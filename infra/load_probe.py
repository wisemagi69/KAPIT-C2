"""Declared read-only load step against the local website (docs/m4-load-profile.md).

Loopback only; the two operator check accounts from the private operator-accounts file;
GET requests after one sign-in per virtual user. Prints latency percentiles and status
counts only, never response bodies or passwords.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.cookiejar
import json
import re
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000/api/v1/"
OPERATOR_FILE = Path(__file__).resolve().parents[1] / ".cache/m1-runtime/operator-accounts.json"
SUBMITTER, RECIPIENT = "ops-submitter", "ops-recipient"
TARGETS = {5: 0.5, 20: 1.5}


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))] if ordered else None


class VirtualUser:
    def __init__(self, username, password):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.username, self.password = username, password

    def request(self, path, body=None, csrf=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if csrf:
            headers["X-CSRFToken"] = csrf
        request = urllib.request.Request(BASE + path, data=data, headers=headers)
        start = time.perf_counter()
        try:
            with self.opener.open(request, timeout=10) as response:
                payload = response.read(1 << 20)
                status = response.status
        except urllib.error.HTTPError as error:
            payload, status = b"", error.code
        except (urllib.error.URLError, TimeoutError, OSError):
            payload, status = b"", 0
        return status, time.perf_counter() - start, payload

    def sign_in(self):
        status, _, payload = self.request("auth/csrf/")
        csrf = json.loads(payload)["csrf_token"] if status == 200 else None
        status, _, payload = self.request("auth/login/", {"username": self.username, "password": self.password}, csrf)
        if status != 200:
            raise RuntimeError("LOGIN_UNAVAILABLE")
        user = json.loads(payload)["user"]
        self.paths = ["me/", f"channels/{user['channel']['id']}/feed/"] if self.username == RECIPIENT else ["me/", "reports/"]


def operator_password():
    try:
        value = json.loads(OPERATOR_FILE.read_text(encoding="utf-8"))["operator"]["password"]
        # Same shape local.operator_accounts() generates; anything else is unusable.
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{20,128}", value) is None:
            raise ValueError
        return value
    except (OSError, ValueError, KeyError, TypeError):
        raise RuntimeError("OPERATOR_ACCOUNTS_UNAVAILABLE") from None


def step(users, seconds):
    password = operator_password()
    actors = [VirtualUser(RECIPIENT if index % 2 == 0 else SUBMITTER, password) for index in range(users)]
    for actor in actors:
        actor.sign_in()
    latencies, statuses, lock = [], {}, threading.Lock()
    deadline = time.monotonic() + seconds

    def run(actor):
        index = 0
        while time.monotonic() < deadline:
            status, elapsed, _ = actor.request(actor.paths[index % 2])
            index += 1
            with lock:
                latencies.append(elapsed)
                statuses[status] = statuses.get(status, 0) + 1

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=users) as pool:
        list(pool.map(run, actors))
    elapsed = time.monotonic() - started
    errors = sum(count for status, count in statuses.items() if not 200 <= status < 300)
    p95 = percentile(latencies, 0.95)
    return {"users": users, "seconds": round(elapsed, 1), "requests": len(latencies), "throughput_rps": round(len(latencies) / elapsed, 1),
            "p50_ms": round(percentile(latencies, 0.50) * 1000, 1), "p95_ms": round(p95 * 1000, 1), "p99_ms": round(percentile(latencies, 0.99) * 1000, 1),
            "statuses": {str(key): value for key, value in sorted(statuses.items())}, "error_rate": round(errors / max(1, len(latencies)), 4),
            "target_p95_ms": TARGETS[users] * 1000, "passed": errors == 0 and p95 <= TARGETS[users]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args(argv)
    steps = [step(users, args.seconds) for users in sorted(TARGETS)]
    print(json.dumps({"schema": 1, "profile": "docs/m4-load-profile.md", "steps": steps, "passed": all(item["passed"] for item in steps)}, indent=2))
    return 0 if all(item["passed"] for item in steps) else 2


if __name__ == "__main__":
    raise SystemExit(main())
