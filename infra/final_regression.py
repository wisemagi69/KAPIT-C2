"""Automated portion of C19: one serialized run of every local regression step, one dated record.

Steps run strictly one after another; a failing step is recorded and the run continues,
so the record shows every result. Full outputs stay in the ignored .cache folder; the
record keeps commands, exit codes, timings, summary lines and log digests only.
This is evidence for human review (C20/G8), not an acceptance decision.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".cache/m1-runtime/venv/Scripts/python.exe"
PY = sys.executable
NPX = "npx.cmd" if os.name == "nt" else "npx"
# Every spec reads this; some otherwise default to an M3 preview port that is not running.
PREVIEW = "http://127.0.0.1:18081"

STEPS = [
    # The project venv carries cryptography/psycopg; system Python skips or refuses those steps.
    ("tools_unittest", [str(VENV), "-B", "-m", "unittest", "discover", "-s", "tools/tests"], ROOT, 1800),
    ("validate_skills", [PY, "-B", "tools/skills/validate_skills.py"], ROOT, 600),
    ("validate_agents", [PY, "-B", "tools/agents/validate_agents.py"], ROOT, 600),
    ("validate_project", [PY, "-B", "tools/validate_project.py"], ROOT, 1800),
    ("infra_unittest", [str(VENV), "-B", "-m", "unittest", "discover", "-s", "infra", "-p", "test_*.py"], ROOT, 1800),
    ("backend_postgres_suite", [PY, "-B", "infra/local.py", "test-native"], ROOT, 3600),
    ("browser_acceptance", [PY, "-B", "infra/local.py", "browser-native"], ROOT, 3600),
    ("web_browser_specs", [NPX, "playwright", "test", "--reporter=line"], ROOT / "web", 3600),
    ("recovery_drill", [str(VENV), "-B", "infra/application_recovery_drill.py", "--execute"], ROOT, 3600),
    ("load_probe", [PY, "-B", "infra/load_probe.py"], ROOT, 900),
    # Last and alone: the owned emulator is sensitive to concurrent host load.
    ("android_emulator_suite", [PY, "-B", "android/tools/emulator_storage.py"], ROOT, 7200),
]
SUMMARY = re.compile(r"^(Ran \d+ tests?.*|OK.*|FAILED.*|\s*\d+ (passed|failed|flaky|skipped).*|.*validat\w* (passed|failed).*|.*(PASSED|FAILED).*gates.*|.*Actual instrumentation passed=False.*)$", re.I)
SOURCE_TREES = ["backend/apps", "backend/config", "backend/tests", "infra", "web/src", "web/tests", "android/app/src", "android/tools", "tools"]


def source_digest():
    digest = hashlib.sha256()
    count = 0
    for tree in SOURCE_TREES:
        for path in sorted((ROOT / tree).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
                count += 1
    return {"trees": SOURCE_TREES, "files": count, "sha256": digest.hexdigest()}


def last_json(text):
    """Final top-level JSON object printed on a step's stdout (drill/load results), if any."""
    text = text.rstrip()
    starts = [0] + [match.start() + 1 for match in re.finditer(r"\n(?=\{)", text)]
    for start in reversed(starts):
        try:
            return json.loads(text[start:])
        except ValueError:
            continue
    return None


def kill_tree(process):
    """Stop the step and every process it started, so nothing runs into the next step."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True, check=False)
    else:
        process.kill()
    process.wait(timeout=60)


def run_step(index, name, command, cwd, timeout, folder):
    started = datetime.now(timezone.utc)
    clock = time.monotonic()
    log = folder / f"{index:02d}-{name}.log"
    stdout_path = folder / f"{index:02d}-{name}.stdout"
    environment = {**os.environ, "KAPIT_UI_QA_URL": PREVIEW}
    # Files, not pipes: a surviving grandchild can never block collection, and a crash keeps the log.
    with open(stdout_path, "wb") as out, open(log, "wb") as err:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_tree(process)
            code = "TIMEOUT"
    stdout = stdout_path.read_bytes()
    with open(log, "ab") as err:
        err.write(b"\n--- stdout ---\n" + stdout)
    stdout_path.unlink()
    output = log.read_bytes()
    text = output.decode("utf-8", "replace")
    step = {"step": name, "command": [Path(part).name if part in (PY, str(VENV)) else part for part in command],
            "cwd": cwd.relative_to(ROOT).as_posix() or ".", "started_utc": started.isoformat(timespec="seconds"),
            "elapsed_seconds": round(time.monotonic() - clock, 1), "exit": code, "passed": code == 0,
            "summary": [line.strip() for line in text.splitlines() if SUMMARY.match(line)][-6:],
            "log": log.relative_to(ROOT).as_posix(), "log_sha256": hashlib.sha256(output).hexdigest()}
    if name in ("recovery_drill", "load_probe"):
        step["result"] = last_json(stdout.decode("utf-8", "replace"))
    return step


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True, help="New evidence record to write (ai/reports/...json)")
    parser.add_argument("--skip", action="append", default=[], choices=[name for name, *_ in STEPS])
    args = parser.parse_args(argv)
    if args.record.exists():
        raise SystemExit("RECORD_EXISTS: evidence records are retained; choose a new record path.")
    stamp = datetime.now(timezone.utc)
    folder = ROOT / ".cache/final-regression" / stamp.strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=False)
    record = {"schema": 1, "package": "C19 automated portion", "started_utc": stamp.isoformat(timespec="seconds"),
              "source_before": source_digest(), "serialized": True, "skipped": args.skip, "steps": []}
    for index, (name, command, cwd, timeout) in enumerate(STEPS, 1):
        if name in args.skip:
            continue
        print(f"C19: {name} started", flush=True)
        step = run_step(index, name, command, cwd, timeout, folder)
        record["steps"].append(step)
        print(f"C19: {name} exit {step['exit']} ({step['elapsed_seconds']} s)", flush=True)
        args.record.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    record["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    record["source_after"] = source_digest()
    record["source_unchanged_during_run"] = record["source_before"]["sha256"] == record["source_after"]["sha256"]
    record["complete"] = not args.skip
    record["all_steps_passed"] = bool(record["steps"]) and all(step["passed"] for step in record["steps"])
    args.record.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    return 0 if record["all_steps_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
