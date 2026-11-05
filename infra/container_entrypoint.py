"""Trusted entry for the reviewed local compose image only."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from config.runtime_boundary import boundary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=["backend", "worker"])
    args = parser.parse_args()
    env = dict(os.environ)
    env["KAPIT_RUNTIME_CONTEXT"] = "compose-m1"
    env["DJANGO_SETTINGS_MODULE"] = "config.settings"
    env.pop("KAPIT_LOCAL_CONTAINER", None)
    selected = boundary(env)
    if selected.context != "compose-m1":
        raise RuntimeError("The local compose image context is required.")
    if args.service == "worker":
        os.execve(sys.executable, [sys.executable, str(ROOT / "backend/manage.py"), "process_jobs"], env)
    result = subprocess.run([sys.executable, str(ROOT / "backend/manage.py"), "migrate", "--noinput"], env=env, check=False)
    if result.returncode:
        raise RuntimeError("Local container initialization failed. No website was started.")
    os.execve(sys.executable, [sys.executable, str(ROOT / "infra/server.py")], env)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
