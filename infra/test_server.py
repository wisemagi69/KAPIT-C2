"""Real loopback HTTP parser/WSGI error tests, without a Django/DB claim."""
import socket
import threading
import unittest
from unittest.mock import patch
from wsgiref.simple_server import make_server

from infra.server import LocalServer, QuietHandler
import infra.server as runtime_server


class QuietErrorTests(unittest.TestCase):
    def test_direct_server_pins_settings_before_any_django_import(self):
        with patch.dict(runtime_server.os.environ, {"DJANGO_SETTINGS_MODULE": "config.test_settings"}), patch.object(runtime_server, "boundary", side_effect=RuntimeError("dry context stop")):
            with self.assertRaisesRegex(RuntimeError, "dry context stop"):
                runtime_server.main()
            self.assertEqual(runtime_server.os.environ["DJANGO_SETTINGS_MODULE"], "config.settings")

    def request(self, line, application):
        with make_server("127.0.0.1", 0, application, server_class=LocalServer, handler_class=QuietHandler) as server:
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(line)
                client.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    data = client.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            return b"".join(chunks)

    def test_malformed_http_never_reflects_private_canary(self):
        def must_not_run(environ, start_response):
            raise AssertionError("Malformed input reached the application")

        result = self.request(b"GET /?private-canary-parser EXTRA HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", must_not_run)
        self.assertIn(b"400 Bad Request", result)
        self.assertNotIn(b"private-canary-parser", result)
        self.assertIn(b"no-store", result)
        self.assertIn(b"Content-Security-Policy:", result)
        self.assertIn(b"application/json", result)

    def test_unhandled_wsgi_error_stays_generic_with_security_headers(self):
        def broken(environ, start_response):
            raise RuntimeError("private-canary-exception")

        result = self.request(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", broken)
        self.assertIn(b"500 Internal Server Error", result)
        self.assertNotIn(b"private-canary-exception", result)
        self.assertIn(b"SERVER_UNAVAILABLE", result)
        self.assertIn(b"no-store", result)
        self.assertIn(b"application/json", result)


class ConnectionClosureTests(unittest.TestCase):
    def request_without_client_close(self, application, request=None):
        # Keep the client write side open: only the server can produce EOF.
        workers = []

        class ObservedHandler(QuietHandler):
            def finish(self):
                try:
                    super().finish()
                finally:
                    workers.append(threading.current_thread())

        with make_server("127.0.0.1", 0, application, server_class=LocalServer,
                         handler_class=ObservedHandler) as server:
            server.timeout = 3
            acceptor = threading.Thread(target=server.handle_request)
            acceptor.start()
            try:
                with socket.create_connection(server.server_address, timeout=3) as client:
                    client.sendall(request or b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
                    raw = bytearray()
                    while True:
                        data = client.recv(4096)
                        if not data:
                            break
                        raw.extend(data)
                        self.assertLessEqual(len(raw), 65536)
            finally:
                acceptor.join(timeout=3)
                self.assertFalse(acceptor.is_alive())
        # Closing the server retires its fixed workers after the request finished.
        for worker in workers:
            worker.join(timeout=3)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(len(workers), 1)
        head, separator, body = bytes(raw).partition(b"\r\n\r\n")
        self.assertEqual(separator, b"\r\n\r\n")
        lines = head.split(b"\r\n")
        self.assertTrue(lines[0].startswith(b"HTTP/1.0 "))
        headers = {}
        for line in lines[1:]:
            name, colon, value = line.partition(b":")
            self.assertEqual(colon, b":")
            headers.setdefault(name.lower(), []).append(value.strip())
        self.assertEqual(headers.get(b"connection"), [b"close"])
        self.assertNotIn(b"transfer-encoding", headers)
        if b"content-length" in headers:
            self.assertEqual(headers[b"content-length"], [str(len(body)).encode("ascii")])
        return lines[0], headers, body

    def test_normal_response_announces_close_and_reaches_eof_with_client_open(self):
        calls = []

        def application(environ, start_response):
            calls.append(environ["REQUEST_METHOD"])
            start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", "2")])
            return [b"ok"]

        status, headers, body = self.request_without_client_close(application)
        self.assertEqual(status, b"HTTP/1.0 200 OK")
        self.assertEqual(headers[b"content-length"], [b"2"])
        self.assertEqual(body, b"ok")
        self.assertEqual(calls, ["GET"])

    def test_empty_response_keeps_inferred_zero_length(self):
        def application(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b""]

        _, headers, body = self.request_without_client_close(application)
        self.assertEqual(headers[b"content-length"], [b"0"])
        self.assertEqual(body, b"")

    def test_streamed_response_closes_without_inventing_content_length(self):
        def application(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return iter((b"one", b"two"))

        _, headers, body = self.request_without_client_close(application)
        self.assertNotIn(b"content-length", headers)
        self.assertEqual(body, b"onetwo")

    def test_application_exception_announces_close_and_keeps_safe_error(self):
        def application(environ, start_response):
            raise RuntimeError("private-closure-exception")

        status, headers, body = self.request_without_client_close(application)
        self.assertEqual(status, b"HTTP/1.0 500 Internal Server Error")
        self.assertEqual(body, runtime_server.SafeServerHandler.error_body)
        self.assertNotIn(b"private-closure-exception", body)
        self.assertIn(b"no-store", headers[b"cache-control"][0])
        self.assertIn(b"content-security-policy", headers)

    def test_parser_error_already_closes_before_application(self):
        calls = []

        def application(environ, start_response):
            calls.append(True)
            raise AssertionError("Invalid request reached the application")

        status, headers, body = self.request_without_client_close(application,
            b"GET /?private-closure-query EXTRA HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
        self.assertEqual(status, b"HTTP/1.0 400 Bad Request")
        self.assertIn(b"INVALID_HTTP_REQUEST", body)
        self.assertNotIn(b"private-closure-query", body)
        self.assertIn(b"no-store", headers[b"cache-control"][0])
        self.assertEqual(calls, [])

    def test_application_cannot_set_hop_by_hop_connection_header(self):
        def application(environ, start_response):
            start_response("200 OK", [("Connection", "keep-alive"), ("Content-Type", "text/plain")])
            return [b"private-application-body"]

        status, _, body = self.request_without_client_close(application)
        self.assertEqual(status, b"HTTP/1.0 500 Internal Server Error")
        self.assertEqual(body, runtime_server.SafeServerHandler.error_body)
        self.assertNotIn(b"private-application-body", body)


class WorkerPoolTests(unittest.TestCase):
    def serve(self, application, requests, workers=2):
        class SmallServer(LocalServer):
            pass
        SmallServer.workers = workers
        server = make_server("127.0.0.1", 0, application, server_class=SmallServer, handler_class=QuietHandler)
        loop = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        loop.start()
        try:
            def call():
                with socket.create_connection(server.server_address, timeout=5) as client:
                    client.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    while client.recv(4096):
                        pass
            callers = [threading.Thread(target=call) for _ in range(requests)]
            for caller in callers:
                caller.start()
            for caller in callers:
                caller.join(timeout=10)
                self.assertFalse(caller.is_alive())
        finally:
            server.shutdown()
            loop.join(timeout=3)
            server.server_close()

    def test_requests_reuse_a_fixed_bounded_set_of_worker_threads(self):
        lock, names, active, peak = threading.Lock(), set(), [0], [0]

        def application(environ, start_response):
            with lock:
                names.add(threading.current_thread().name)
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            threading.Event().wait(0.05)
            with lock:
                active[0] -= 1
            start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", "2")])
            return [b"ok"]

        self.serve(application, requests=8, workers=2)
        self.assertLessEqual(len(names), 2)
        self.assertTrue(all(name.startswith("kapit-web") for name in names))
        self.assertLessEqual(peak[0], 2)

    def test_trickling_client_loses_its_worker_at_the_total_deadline(self):
        class QuickDeadline(LocalServer):
            workers, request_deadline = 1, 0.5
        server = make_server("127.0.0.1", 0, lambda e, s: [], server_class=QuickDeadline, handler_class=QuietHandler)
        loop = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        loop.start()
        try:
            with socket.create_connection(server.server_address, timeout=5) as client:
                client.sendall(b"GET / HT")  # never completes the request line
                self.assertEqual(b"", client.recv(4096))  # server closed it at the deadline
            self.assertTrue(server._slots.acquire(timeout=2)); server._slots.release()
        finally:
            server.shutdown(); loop.join(timeout=3); server.server_close()

    def test_application_exception_releases_its_worker(self):
        def broken(environ, start_response):
            raise RuntimeError("private-pool-exception")

        self.serve(broken, requests=4, workers=1)


if __name__ == "__main__":
    unittest.main()
