import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from config import runtime_boundary
from infra import application_recovery_drill as drill_module
from infra import restore_rehearsal

TOKEN = "0123456789abcdef0123456789abcdef"


class RecoveryBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / TOKEN).mkdir()
        self.marker = {"schema": 1, "owner": runtime_boundary.RECOVERY_CHILD_OWNER, "target": TOKEN, "port": 56123}
        (self.root / TOKEN / "owner.json").write_text(json.dumps(self.marker), encoding="utf-8")
        patcher = mock.patch.object(runtime_boundary, "RECOVERY_ROOT", self.root)
        patcher.start(); self.addCleanup(patcher.stop)

    def env(self, **changes):
        value = {"KAPIT_RUNTIME_CONTEXT": "recovery-drill", "KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "56123", "KAPIT_RECOVERY_TARGET": TOKEN}
        value.update(changes)
        return value

    def test_owned_marker_port_selects_child(self):
        selected = runtime_boundary.boundary(self.env())
        self.assertEqual(("recovery-drill", "127.0.0.1", "56123", "127.0.0.1"),
                         (selected.context, selected.db_host, selected.db_port, selected.bind_host))

    def test_refuses_retained_port_other_ports_hosts_tokens_and_foreign_markers(self):
        for changes in ({"KAPIT_DB_PORT": "55436"}, {"KAPIT_DB_PORT": "56124"}, {"KAPIT_DB_PORT": "57000"},
                        {"KAPIT_DB_HOST": "localhost"}, {"KAPIT_DB_HOST": "10.0.0.5"}, {"KAPIT_RECOVERY_TARGET": "f" * 32},
                        {"KAPIT_RECOVERY_TARGET": "../" + TOKEN[3:]}, {"KAPIT_RECOVERY_TARGET": ""}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                runtime_boundary.boundary(self.env(**changes))
        for marker in (dict(self.marker, owner="other"), dict(self.marker, target="f" * 32), dict(self.marker, port="56123"), []):
            (self.root / TOKEN / "owner.json").write_text(json.dumps(marker), encoding="utf-8")
            with self.subTest(marker=marker), self.assertRaises(RuntimeError):
                runtime_boundary.boundary(self.env())

    def test_native_boundary_is_unchanged(self):
        with self.assertRaises(RuntimeError):
            runtime_boundary.boundary({"KAPIT_DB_PORT": "56123", "KAPIT_RECOVERY_TARGET": TOKEN})
        self.assertEqual("55436", runtime_boundary.boundary({}).db_port)

    def test_website_never_serves_a_recovery_child(self):
        from infra import server
        selected = runtime_boundary.Boundary("recovery-drill", "127.0.0.1", "56123", "127.0.0.1")
        with mock.patch.object(server, "boundary", return_value=selected), mock.patch.object(server, "make_server") as make:
            with self.assertRaises(SystemExit):
                server.main()
        make.assert_not_called()

    def test_probe_refuses_outside_recovery_context(self):
        from infra import recovery_app_probe
        with mock.patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native"}):
            self.assertEqual("CONTEXT_REFUSED", recovery_app_probe.probe()["code"])


class FakeRuntime:
    def __init__(self, probe=None, change_source=False, stop="STOPPED_VERIFIED", fail=None, fault=None):
        self.calls, self.token = [], TOKEN
        self.probe, self.change_source, self.stop, self.fail = probe or {"ok": True, "code": "APPLICATION_RECONSTRUCTED"}, change_source, stop, fail
        self.fault = fault or {"ok": True, "code": "DATABASE_FAULT_CONTAINED"}
        self.local = mock.Mock(latest_verified_backup=mock.Mock(return_value={"created_epoch": 0}))
        self.snapshots = 0

    def __getattr__(self, name):
        def call(*_):
            self.calls.append(name)
            if name == self.fail:
                restore_rehearsal._fail("RESTORE_KEYS_UNAVAILABLE")
            return {"ok": True}
        return call

    def source_snapshot(self):
        self.calls.append("source_snapshot"); self.snapshots += 1
        return {"v": 2 if self.change_source and self.snapshots > 2 else 1}

    def restored_snapshot(self):
        self.calls.append("restored_snapshot"); return {"v": 1}

    def probe_application(self, fault=False):
        if fault:
            self.calls.append("fault_probe"); return self.fault
        self.calls.append("probe_application"); return self.probe

    def stop_owned(self):
        self.calls.append("stop_owned"); return self.stop


class DrillTest(unittest.TestCase):
    def test_default_is_preparation_only(self):
        self.assertEqual("PREPARED_NOT_EXECUTED", drill_module.drill()["status"])

    def test_success_measures_rto_and_stops_child(self):
        runtime = FakeRuntime()
        result = drill_module.drill(execute=True, runtime=runtime)
        self.assertEqual("APPLICATION_RECOVERY_PASSED", result["status"])
        self.assertEqual(["FRESH_VERIFIED_BACKUP", "ISOLATED_CHILD_RESTORED", "DATA_AND_PRIVATE_SOURCE_VERIFIED", "APPLICATION_RECONSTRUCTED",
                          "DATABASE_FAULT_CONTAINED"], result["phases"])
        self.assertTrue(result["measured"]["rto_met"])
        # The fault probe runs only after the verified stop, and the child is stopped exactly once.
        self.assertEqual(["stop_owned", "fault_probe"], runtime.calls[-2:]); self.assertEqual(1, runtime.calls.count("stop_owned"))
        self.assertFalse(result["measured"]["rpo_met_by_existing_backups"])  # epoch-0 backup is far older than 24h

    def test_failed_probe_or_source_change_or_unconfirmed_stop_fail(self):
        for runtime, code in ((FakeRuntime(probe={"ok": False, "code": "APPLICATION_CHECK_FAILED"}), "APPLICATION_RECONSTRUCTION_FAILED"),
                              (FakeRuntime(change_source=True), "CURRENT_AUTHORIZATION_CHANGED"),
                              (FakeRuntime(stop="STOP_UNCONFIRMED"), "STOP_UNCONFIRMED"),
                              (FakeRuntime(fail="restore"), "RESTORE_KEYS_UNAVAILABLE"),
                              (FakeRuntime(fault={"ok": False, "code": "DATABASE_FAULT_EXPOSED"}), "DATABASE_FAULT_EXPOSED")):
            with self.subTest(code=code):
                result = drill_module.drill(execute=True, runtime=runtime)
                self.assertEqual("FAILED", result["status"]); self.assertEqual(code, result["code"])
                self.assertIn("stop_owned", runtime.calls)

    def test_preflight_failure_never_reserves(self):
        runtime = FakeRuntime(fail="preflight")
        result = drill_module.drill(execute=True, runtime=runtime)
        self.assertEqual("FAILED", result["status"]); self.assertNotIn("reserve", runtime.calls); self.assertNotIn("stop_owned", runtime.calls)


if __name__ == "__main__":
    unittest.main()
