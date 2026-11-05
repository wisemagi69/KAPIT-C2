"""Bounded local checks. No installation, server startup, DB or remote CI.

Run ``python infra/quality.py`` for pure checks; ``--stage web`` uses already
installed local tools directly (no npm lifecycle hooks). Required external
acceptance gates remain incomplete. Child output is intentionally discarded.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Check:
    name: str
    stage: str
    command: tuple[str, ...]
    files: tuple[str, ...] = ()
    tool: str | None = None


CHECKS = (
    Check("tools-unit", "pure", (sys.executable, "-m", "unittest", "discover", "-s", "tools/tests", "-q")),
    Check("skills-structure", "pure", (sys.executable, "tools/skills/validate_skills.py")),
    Check("agents-structure", "pure", (sys.executable, "tools/agents/validate_agents.py")),
    Check("project-structure", "pure", (sys.executable, "tools/validate_project.py")),
    Check("quality-unit", "pure", (sys.executable, "-m", "unittest", "infra.test_quality", "-q")),
    Check("recovery-unit", "pure", (sys.executable, "-m", "unittest", "infra.test_recovery", "-q")),
    Check("retention-unit", "pure", (sys.executable, "-m", "unittest", "backend.tests.test_m4_retention", "-q"), ("backend/tests/test_m4_retention.py",)),
    Check("evidence-unit", "pure", (sys.executable, "-m", "unittest", "backend.tests.test_m4_evidence_validation", "-q"), ("backend/tests/test_m4_evidence_validation.py",)),
    Check("sanitizer-unit", "pure", (sys.executable, "-m", "unittest", "backend.tests.sanitization.test_evaluation", "-q"), ("backend/tests/sanitization/test_evaluation.py",)),
    Check("retention-policy-unit", "pure", (sys.executable, "-m", "unittest", "backend.tests.test_m4_retention_policy", "-q"), ("backend/tests/test_m4_retention_policy.py",)),
    Check("restore-rehearsal-unit", "pure", (sys.executable, "-m", "unittest", "infra.test_restore_rehearsal", "infra.test_restore_failures", "-q"), ("infra/test_restore_rehearsal.py", "infra/test_restore_failures.py")),
    Check("live-recovery-guards", "pure", (sys.executable, "-m", "unittest", "infra.test_live_recovery_drill", "-q"), ("infra/test_live_recovery_drill.py",)),
    Check("native-ownership-unit", "pure", (sys.executable, "-m", "unittest", "infra.test_native_postgres", "infra.test_local", "infra.test_start_local", "infra.test_browser_native", "-q")),
    Check("web-protocol-unit", "pure", ("node", "--test", "web/tests/domain.test.mjs", "web/tests/live-journey.test.mjs", "web/tests/m3-domain.test.mjs", "web/tests/m3-live-journey.test.mjs"), ("web/tests/domain.test.mjs", "web/tests/live-journey.test.mjs", "web/tests/m3-domain.test.mjs", "web/tests/m3-live-journey.test.mjs"), "node"),
    Check("detector-runner-unit", "pure", (sys.executable, "-m", "unittest", "infra.test_detector_evaluation", "-q"), ("infra/test_detector_evaluation.py",)),
    Check("web-typecheck", "web", ("node", "web/node_modules/typescript/bin/tsc", "--noEmit", "--project", "web/tsconfig.json"), ("web/node_modules/typescript/bin/tsc",), "node"),
    Check("web-build", "web", ("node", "web/node_modules/vite/bin/vite.js", "build", "web"), ("web/node_modules/vite/bin/vite.js",), "node"),
)
EXTERNAL_GATES = (
    "web-protocol-browser", "android-jvm-build-device", "isolated-postgresql",
    "serialized-live-browser", "restore-reconciliation", "synthetic-load-faults",
    "dependency-license-secret-config-review", "independent-security-review", "human-acceptance",
)


def run_checks(stage="pure", *, root=ROOT, timeout=300):
    """Return only allowlisted metadata, never exceptions or child output."""
    if stage not in {"pure", "web", "all"}:
        raise ValueError("INVALID_STAGE")
    root = Path(root).resolve()
    if root != ROOT:
        raise ValueError("INVALID_WORKSPACE")
    if type(timeout) is not int or not 1 <= timeout <= 1800:
        raise ValueError("INVALID_TIMEOUT")
    results = []
    for check in CHECKS:
        if stage != "all" and check.stage != stage:
            results.append({"check": check.name, "status": "NOT_RUN"})
            continue
        if any(not (root / path).is_file() for path in check.files) or (check.tool and not shutil.which(check.tool)):
            results.append({"check": check.name, "status": "UNAVAILABLE"})
            continue
        try:
            completed = subprocess.run(check.command, cwd=root, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       shell=False, timeout=timeout, check=False)
            status = "PASSED" if completed.returncode == 0 else "FAILED"
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
        except OSError:
            status = "UNAVAILABLE"
        results.append({"check": check.name, "status": status})
    results.extend({"check": name, "status": "NOT_RUN"} for name in EXTERNAL_GATES)
    failed = any(item["status"] in {"FAILED", "TIMEOUT"} for item in results)
    return {"schema": 1, "stage": stage, "status": "FAILED" if failed else "INCOMPLETE",
            "checks": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("pure", "web", "all"), default="pure")
    args = parser.parse_args(argv)
    result = run_checks(args.stage)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
