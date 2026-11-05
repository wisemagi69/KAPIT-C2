"""Quiet local WSGI host. No production or remote deployment is authorized."""
from concurrent.futures import ThreadPoolExecutor
import os
import socket
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import ServerHandler, WSGIRequestHandler, WSGIServer, make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from config.middleware import SECURITY_HEADERS
from config.runtime_boundary import boundary


class LocalServer(WSGIServer):
    # A fixed set of long-lived worker threads lets each keep one reusable
    # database connection (Django connections are per thread). Accepting waits
    # while every worker is busy, so concurrency and connections stay bounded.
    workers = 8
    # One request per connection: a client trickling bytes under the idle timeout
    # still loses its socket at this total deadline, freeing the worker.
    request_deadline = 120
    # Connections wait in the OS backlog while every worker is busy; the default
    # of 5 refused clients outright once more than workers + 5 were connecting.
    request_queue_size = 64

    def server_activate(self):
        super().server_activate()
        self._slots = threading.BoundedSemaphore(self.workers)
        self._pool = ThreadPoolExecutor(self.workers, thread_name_prefix="kapit-web")

    def process_request(self, request, client_address):
        self._slots.acquire()
        try:
            self._pool.submit(self._process, request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def _process(self, request, client_address):
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = threading.Timer(self.request_deadline, expire)
        deadline.daemon = True
        deadline.start()
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            deadline.cancel()
            try:
                self.shutdown_request(request)
            finally:
                self._slots.release()

    def server_close(self):
        super().server_close()
        pool = getattr(self, "_pool", None)
        if pool is not None:
            pool.shutdown(wait=True)

    def handle_error(self, request, client_address):
        # Do not serialize exception values, request content or traceback locals.
        print("A local web request could not be completed.", file=sys.stderr)


class QuietHandler(WSGIRequestHandler):
    # A stalled client must not hold one of the fixed workers indefinitely.
    timeout = 30

    def send_error(self, code, message=None, explain=None):
        # Errors rejected by the HTTP parser occur before Django middleware.
        # Never reflect the request line or query in these responses.
        body = b'{"code":"INVALID_HTTP_REQUEST","message":"This request could not be accepted."}'
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def handle(self):
        self.raw_requestline = self.rfile.readline(65537)
        if len(self.raw_requestline) > 65536:
            self.requestline = self.request_version = self.command = ""
            self.send_error(414)
            return
        if not self.parse_request():
            return
        handler = SafeServerHandler(self.rfile, self.wfile, self.get_stderr(), self.get_environ(), multithread=True)
        handler.request_handler = self
        handler.run(self.server.get_app())

    def get_stderr(self):
        # The WSGI implementation otherwise dumps unexpected application
        # exception values and tracebacks to the host's standard error.
        return NullErrorLog()

    def log_message(self, format, *args):
        # Standard request logs include the URL/query; private identifiers and
        # untrusted strings must not reach developer logs.
        pass


class NullErrorLog:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


class SafeServerHandler(ServerHandler):
    error_status = "500 Internal Server Error"
    error_headers = [("Content-Type", "application/json; charset=utf-8"), *SECURITY_HEADERS.items()]
    error_body = b'{"code":"SERVER_UNAVAILABLE","message":"The request could not be completed. Please try again."}'

    def cleanup_headers(self):
        super().cleanup_headers()
        # QuietHandler serves one request per connection. Explicitly tell
        # pooled clients to retire it; applications still cannot set this header.
        self.headers["Connection"] = "close"


def main():
    # Imported HTTP test helpers do not load Django. Actual website startup
    # always selects the reviewed application settings, regardless of parent env.
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
    selected = boundary()
    if getattr(selected, "context", None) == "recovery-drill":
        raise SystemExit("A restored recovery drill child is never served as the website.")
    from config.wsgi import application
    from config.hosted_preflight import enforce_hosted_preflight
    enforce_hosted_preflight()

    # Container bind is internal; compose publishes only the loopback port.
    port = 8000
    if getattr(selected, "context", None) == "hosted-demo":
        # The hosting platform assigns the listening port; TLS terminates at its proxy.
        port = int(os.environ.get("PORT", "8000"))
        if not 1024 <= port <= 65535:
            raise SystemExit("The hosted listening port is invalid.")
    with make_server(selected.bind_host, port, application, server_class=LocalServer, handler_class=QuietHandler) as server:
        print("KAPIT-C2 synthetic website ready" + (" (hosted demonstration)" if port != 8000 or selected.context == "hosted-demo" else " at http://127.0.0.1:8000"), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
