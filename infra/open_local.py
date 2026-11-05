"""Open the verified local application or its retained compiled preview."""
import argparse
from dataclasses import dataclass
from html.parser import HTMLParser
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "web/dist"
APPLICATION_PORT = 8000
PREVIEW_PORT = 18081


class OpenError(RuntimeError):
    pass


@dataclass
class Target:
    url: str
    mode: str
    process: object = None


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        name = values.get("src") if tag == "script" else values.get("href") if tag == "link" and values.get("rel") == "stylesheet" else None
        if name:
            if not re.fullmatch(r"/assets/[A-Za-z0-9_-]+\.(?:js|css)", name):
                raise OpenError("BUILD_INVALID: the compiled page has an unsupported asset path; rebuild the website.")
            self.assets.add(name)


def expected_build():
    try:
        index = (DIST / "index.html").read_bytes()
        if not 1 <= len(index) <= 128 * 1024:
            raise ValueError
        parser = AssetParser()
        parser.feed(index.decode("utf-8"))
        if not any(name.endswith(".js") for name in parser.assets) or not any(name.endswith(".css") for name in parser.assets):
            raise ValueError
        build = {"/": index}
        for name in parser.assets:
            path = DIST / name.lstrip("/")
            if not path.resolve().is_relative_to(DIST.resolve()):
                raise ValueError
            data = path.read_bytes()
            if not 1 <= len(data) <= 8 * 1024 * 1024:
                raise ValueError
            build[name] = data
        return build
    except (OSError, UnicodeError, ValueError):
        raise OpenError("BUILD_MISSING: run npm.cmd --prefix web run build, then open the launcher again.") from None


def check_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise OpenError("INVALID_PORT: a local numeric port is required.")


def get(port, path, limit):
    check_port(port)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request("GET", path, headers={"Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            return None
        body = response.read(limit + 1)
        return body if len(body) <= limit else None
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def verify_site(port, build):
    return all(get(port, path, len(data)) == data for path, data in build.items())


def api_ready(port):
    body = get(port, "/api/v1/auth/csrf/", 4096)
    try:
        value = json.loads(body) if body is not None else None
        return isinstance(value, dict) and set(value) == {"csrf_token"} and isinstance(value["csrf_token"], str) and 32 <= len(value["csrf_token"]) <= 128
    except (ValueError, UnicodeError):
        return False


def port_available(port):
    check_port(port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def preview_command(port):
    check_port(port)
    node = shutil.which("node")
    vite = ROOT / "web/node_modules/vite/bin/vite.js"
    if not node or not vite.is_file():
        raise OpenError("PREVIEW_TOOLS_MISSING: installed Node and the project's Vite package are required; use the documented local setup.")
    return [node, str(vite), "preview", "--host", "127.0.0.1", "--port", str(port), "--strictPort", "--config", str(ROOT / "web/vite.config.ts")]


def stop_owned(child):
    prior = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    finally:
        signal.signal(signal.SIGINT, prior)


def start_preview(port, build, timeout=15):
    if not port_available(port):
        raise OpenError("PREVIEW_PORT_BUSY: port 18081 belongs to a different or stale server; no process was changed.")
    command = preview_command(port)
    environment = {key: value for key, value in os.environ.items() if key.upper() not in {"NODE_OPTIONS", "NODE_PATH"}}
    child = None
    ready = False
    try:
        prior = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            child = subprocess.Popen(command, cwd=ROOT / "web", env=environment, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                                     start_new_session=os.name != "nt")
        finally:
            signal.signal(signal.SIGINT, prior)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise OpenError("PREVIEW_START_FAILED: the installed preview server stopped before readiness.")
            if verify_site(port, build) and child.poll() is None:
                ready = True
                return child
            time.sleep(0.15)
        raise OpenError("PREVIEW_TIMEOUT: the preview did not serve the matching website in time.")
    finally:
        if child is not None and not ready:
            stop_owned(child)


def select_target(build, *, application_port=APPLICATION_PORT, preview_port=PREVIEW_PORT):
    if verify_site(application_port, build) and api_ready(application_port):
        return Target(f"http://127.0.0.1:{application_port}/", "application")
    if verify_site(preview_port, build):
        return Target(f"http://127.0.0.1:{preview_port}/", "preview")
    if not port_available(preview_port):
        raise OpenError("PREVIEW_PORT_BUSY: port 18081 serves a different or stale website; no process was changed.")
    child = start_preview(preview_port, build)
    return Target(f"http://127.0.0.1:{preview_port}/", "preview", child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true", help="Verify/start the local website and print its URL without opening a browser.")
    args = parser.parse_args()
    target = select_target(expected_build())
    if target.mode == "application":
        print(f"Full local application ready: {target.url}", flush=True)
    else:
        print(f"Website preview ready: {target.url}\nSign-in requires the backend. Run python infra/start_local.py for full local setup.", flush=True)
        print("The preview stays available after this opener closes. After a restart, run Open KAPIT.cmd again.", flush=True)
    if not args.no_browser:
        try:
            if not webbrowser.open(target.url, new=2):
                print("The browser did not open automatically. Use the verified link above.", flush=True)
        except (OSError, webbrowser.Error):
            print("The browser could not open automatically. Use the verified link above.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("OPEN_CANCELLED: opening was cancelled; existing services were preserved.", file=sys.stderr)
        raise SystemExit(2) from None
    except OpenError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except (OSError, ValueError, subprocess.SubprocessError):
        print("OPEN_FAILED: the local website could not be verified. Existing services were preserved.", file=sys.stderr)
        raise SystemExit(2) from None
