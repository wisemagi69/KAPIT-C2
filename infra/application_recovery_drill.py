"""Whole-application recovery drill with measured RPO/RTO (M4 C12). Opt-in only.

Reuses the reviewed isolated restore runtime (fresh verified backup, exclusive new
child cluster, full-table snapshot equality and private-source decryption), then
reconstructs the real application against that child through recovery_app_probe.
The retained database, keys and running website are only read; the child is stopped.
Private evidence, photos and coordinates are encrypted rows inside the database,
so the database archive plus the source key is the complete application state.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import restore_rehearsal as rehearsal

RPO_TARGET_HOURS = 24
RTO_TARGET_HOURS = 4


class ApplicationRuntime(rehearsal.LocalRuntime):
    """The restored child carries the application's own database/role names, never its port."""
    def reserve(self):
        super().reserve()
        self.user = self.database = "kapit_m1"
        (self.target / "pgpass").unlink()
        self.local.write_private(self.target / "pgpass", f"127.0.0.1:{self.port}:*:{self.user}:{self.password}\n")
        # Keys reach the probe child only through its environment; no key copy is written to disk.
        self.child_secrets = {"KAPIT_SECRET_KEY": self.values["KAPIT_SECRET_KEY"], "KAPIT_SOURCE_KEY": self.values["KAPIT_SOURCE_KEY"],
                              "KAPIT_DB_PASSWORD": self.password}
        self.local.validate_secrets(self.child_secrets)

    def probe_application(self, fault=False):
        if not fault:
            self.verify_child()
        env = {key: value for key, value in self.native.clean_environment().items()
               if not key.startswith(("KAPIT_", "PG")) and key not in {"DATABASE_URL", "DB_URL", "DJANGO_SETTINGS_MODULE"}}
        env.update(KAPIT_RUNTIME_CONTEXT="recovery-drill", KAPIT_DB_HOST="127.0.0.1", KAPIT_DB_PORT=str(self.port),
                   KAPIT_RECOVERY_TARGET=self.token, KAPIT_SECRETS_FILE=str(self.target / "no-secrets-file"), KAPIT_LOCAL_CONTAINER="0",
                   **self.child_secrets)
        result = subprocess.run([self.local.python_path(), "-B", str(ROOT / "infra/recovery_app_probe.py"), *(["--database-stopped"] if fault else [])], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=300)
        try:
            outcome = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            outcome = {"ok": False, "code": "PROBE_OUTPUT_INVALID"}
        if not isinstance(outcome, dict) or set(outcome) - {"ok", "code", "pending_migrations", "accounts"}:
            outcome = {"ok": False, "code": "PROBE_OUTPUT_INVALID"}
        if not fault:
            self.verify_child()
        return outcome


def drill(*, execute=False, runtime=None):
    if execute is not True:
        return {"schema": 1, "status": "PREPARED_NOT_EXECUTED"}
    clock = time.monotonic
    started = clock()
    phases, timings, outcome, fault, code, cleanup = [], {}, None, None, None, "NOT_STARTED"
    runtime = runtime or ApplicationRuntime(secrets.token_hex(16))
    reserved = False
    previous_backup = None
    try:
        previous_backup = runtime.local.latest_verified_backup()
        runtime.preflight()
        before = runtime.source_snapshot()
        mark = clock()
        runtime.fresh_backup()
        if runtime.source_snapshot() != before:
            rehearsal._fail("SOURCE_CHANGED_DURING_BACKUP")
        timings["backup_seconds"] = round(clock() - mark, 3)
        phases.append("FRESH_VERIFIED_BACKUP")
        # RTO clock: from a verified archive and key to a working application.
        recovery = clock()
        reserved = True
        runtime.reserve()
        runtime.initialize()
        runtime.start()
        runtime.restore()
        phases.append("ISOLATED_CHILD_RESTORED")
        if runtime.restored_snapshot() != before:
            rehearsal._fail("RESTORED_SNAPSHOT_MISMATCH")
        runtime.verify_decryption()
        phases.append("DATA_AND_PRIVATE_SOURCE_VERIFIED")
        timings["restore_and_verify_seconds"] = round(clock() - recovery, 3)
        mark = clock()
        outcome = runtime.probe_application()
        timings["application_probe_seconds"] = round(clock() - mark, 3)
        if outcome.get("ok") is not True:
            rehearsal._fail("APPLICATION_RECONSTRUCTION_FAILED")
        phases.append("APPLICATION_RECONSTRUCTED")
        timings["rto_seconds"] = round(clock() - recovery, 3)
        if runtime.source_snapshot() != before:
            rehearsal._fail("CURRENT_AUTHORIZATION_CHANGED")
        # Fault check (C17): stop the owned child, then the real application must fail closed.
        cleanup = runtime.stop_owned()
        reserved = False
        if cleanup != "STOPPED_VERIFIED":
            rehearsal._fail("STOP_UNCONFIRMED")
        fault = runtime.probe_application(fault=True)
        if fault.get("ok") is not True:
            rehearsal._fail("DATABASE_FAULT_EXPOSED")
        phases.append("DATABASE_FAULT_CONTAINED")
    except rehearsal.RehearsalError as error:
        code = str(error)
    except Exception:
        code = "DRILL_UNAVAILABLE"
    finally:
        if reserved:
            try:
                cleanup = runtime.stop_owned()
            except Exception:
                cleanup = "STOP_UNCONFIRMED"
    success = code is None and cleanup == "STOPPED_VERIFIED"
    if code is None and not success:
        code = "STOP_UNCONFIRMED"
    rpo = None
    if previous_backup is not None:
        rpo = round((datetime.now(timezone.utc).timestamp() - previous_backup["created_epoch"]) / 3600, 2)
    return {"schema": 1, "status": "APPLICATION_RECOVERY_PASSED" if success else "FAILED", "code": code or "APPLICATION_RECONSTRUCTED",
            "phases": phases, "timings": timings, "application": outcome, "database_fault": fault, "cleanup": cleanup,
            "targets_hours": {"rpo": RPO_TARGET_HOURS, "rto": RTO_TARGET_HOURS},
            "measured": {"rto_hours": round(timings["rto_seconds"] / 3600, 4) if "rto_seconds" in timings else None,
                         "rto_met": "rto_seconds" in timings and timings["rto_seconds"] <= RTO_TARGET_HOURS * 3600,
                         "backup_age_before_drill_hours": rpo,
                         "rpo_met_by_existing_backups": rpo is not None and rpo <= RPO_TARGET_HOURS},
            "recovery_id": getattr(runtime, "token", None), "elapsed_seconds": round(clock() - started, 3)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    result = drill(execute=args.execute)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"APPLICATION_RECOVERY_PASSED", "PREPARED_NOT_EXECUTED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
