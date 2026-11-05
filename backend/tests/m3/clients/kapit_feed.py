"""Standard-library loopback reference reader. Never prints the bearer key."""
import ipaddress
import json
import os
import sys
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirects are unavailable.")


def local_base(value):
    parts = urlsplit(value)
    if parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Use a loopback HTTP base URL.")
    host = parts.hostname
    if host == "localhost":
        host = "127.0.0.1"
    if host is None or not ipaddress.ip_address(host).is_loopback:
        raise ValueError("Use a loopback HTTP base URL.")
    address = "[" + host + "]" if ":" in host else host
    if parts.port is not None:
        address += ":" + str(parts.port)
    if parts.path not in {"/api/integration/v1", "/api/integration/v1/"}:
        raise ValueError("Use the integration API base path.")
    return urlunsplit(("http", address, "/api/integration/v1/", "", ""))


def read(base, key):
    base = local_base(base)
    # Deliberately bypass environment proxies and forbid redirects with a secret.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    cursor, count = None, 0
    for _ in range(1000):
        url = base + "publications/" + ("?" + urlencode({"cursor": cursor}) if cursor else "")
        request = Request(url, headers={"Authorization": "Bearer " + key, "Accept": "application/json"})
        with opener.open(request, timeout=10) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Response exceeded the local reader limit.")
        body = json.loads(raw)
        if not isinstance(body, dict) or not isinstance(body.get("results"), list):
            raise ValueError("Invalid integration response.")
        count += len(body["results"])
        cursor = body.get("next_cursor")
        if cursor is None:
            return {"received": count}
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
            raise ValueError("Invalid integration cursor.")
    raise ValueError("Local reader page limit exceeded.")


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError
        key = os.environ["KAPIT_INTEGRATION_KEY"]
        result = read(sys.argv[1], key)
    except (KeyError, ValueError, TypeError, HTTPError, URLError, OSError, HTTPException):
        print("Integration read failed.", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
