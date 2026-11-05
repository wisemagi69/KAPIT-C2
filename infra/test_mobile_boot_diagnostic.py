"""Pure boot diagnostic guards; no emulator, ADB or database is launched."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, MagicMock, patch

from infra import mobile_boot_diagnostic as boot


class ParserTests(unittest.TestCase):
    def test_fixed_property_schema_preserves_only_expected_enums(self):
        value = boot.fixed_properties("\n0\nrunning\nrestarting\nstopped\nPRIVATE_CANARY\n")
        self.assertEqual(value, dict(zip(boot.PROPERTIES,
            ("unset", "not_complete", "running", "restarting", "stopped", "unexpected"))))
        self.assertNotIn("CANARY", json.dumps(value))
        self.assertEqual(boot.fixed_properties("1\n1\n\n\n\n\n")["sys.boot_completed"], "complete")

    def test_malformed_or_oversized_property_output_fails_closed(self):
        for raw in ("", "1\n" * 5, "1\n" * 7, "x" * 513):
            with self.subTest(raw=raw[:10]), self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_PROPERTY_FORMAT"):
                boot.fixed_properties(raw)

    def test_failure_codes_are_allowlisted_not_messages_or_unknown_codes(self):
        self.assertEqual(boot.failure_code(boot.base.EmulatorError("EMULATOR_BOOT_TIMEOUT")), "EMULATOR_BOOT_TIMEOUT")
        self.assertEqual(boot.failure_code(boot.base.DeviceError("DEVICE_COMMAND_FAILED")), "DEVICE_COMMAND_FAILED")
        for error in (ValueError("EMULATOR_BOOT_TIMEOUT"), RuntimeError("PRIVATE_CANARY"),
                      boot.base.EmulatorError("EMULATOR_PRIVATE_CANARY")):
            self.assertEqual(boot.failure_code(error), "BOOT_OTHER_FAILURE")

    def test_cpu_interval_requires_valid_independent_counters(self):
        before = {"cpu_observed": True, "cpu_idle_ticks": 10, "cpu_total_ticks": 100}
        after = {"cpu_observed": True, "cpu_idle_ticks": 35, "cpu_total_ticks": 200}
        self.assertEqual(boot.cpu_interval(before, after), 75.0)
        for actual in ({"cpu_observed": False}, before,
                       {**after, "cpu_idle_ticks": 200}, {**after, "cpu_total_ticks": 50}):
            self.assertIsNone(boot.cpu_interval(before, actual))

    def test_changed_frozen_dependency_refuses_before_runtime(self):
        with patch.object(boot.base, "digest", return_value="different"), patch.object(boot.base, "AndroidTools") as tools:
            with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_SOURCE_CHANGED"):
                boot.execute()
            tools.assert_not_called()


class OwnedBootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / ".cache/m1-runtime/mobile-boot" / ("a" * 24)
        self.run.parent.mkdir(parents=True)
        for item in (patch.object(boot, "ROOT", self.root), patch.object(boot.base, "ROOT", self.root)):
            item.start()
            self.addCleanup(item.stop)
        self.lease = boot.BootLease(self.run)
        self.lease.__enter__()
        self.addCleanup(self.lease.__exit__, None, None, None)
        self.tools = Mock()
        self.tools.adb = "adb.exe"
        self.emulator = boot.BootEmulator(self.tools, self.lease, self.run)

    def test_lease_refuses_adoption_or_different_parent(self):
        with self.assertRaisesRegex(boot.base.EmulatorError, "A11Y_RUN_PREEXISTING"):
            boot.BootLease(self.run).__enter__()
        with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_RUN_PATH_DENIED"):
            boot.BootLease(self.root / ".cache/m1-runtime/mobile-emulator" / ("b" * 24))

    def test_held_lease_rejects_changed_marker(self):
        self.lease.path.write_bytes(b"changed")
        with self.assertRaisesRegex(boot.base.EmulatorError, "A11Y_RUN_OWNERSHIP_LOST"):
            self.lease.assert_owned()

    def test_original_boot_loop_and_identity_methods_are_inherited(self):
        self.assertIs(boot.BootEmulator.__enter__, boot.base.OwnedEmulator.__enter__)
        self.assertIs(boot.BootEmulator.identity, boot.base.OwnedEmulator.identity)
        self.assertEqual(self.emulator.diagnostic["boot_deadline_seconds"], 240)

    def test_result_binds_host_and_test_sources_without_services(self):
        self.check_source_evidence(changed=False)

    def test_changed_diagnostic_source_invalidates_otherwise_successful_boot(self):
        self.check_source_evidence(changed=True)

    def check_source_evidence(self, *, changed):
        fake = MagicMock()
        fake.closed = True
        fake.evidence = {"owned_emulator_stopped": True, "owned_emulator_ports_closed": True}
        fake.diagnostic = {}
        calls = {}

        def digest(path):
            name = path.relative_to(self.root).as_posix()
            if name in boot.FROZEN:
                return boot.FROZEN[name]
            calls[name] = calls.get(name, 0) + 1
            return "b" * 64 if changed and calls[name] > 1 else "a" * 64

        with patch.object(boot.base, "digest", side_effect=digest), \
                patch.object(boot.base, "AndroidTools"), patch.object(boot, "BootEmulator", return_value=fake), \
                patch.object(boot, "host_sample", return_value={"workspace_disk_free_bytes": 20 * 1024**3}), \
                patch.object(boot.secrets, "token_hex", side_effect=lambda size: "b" * (size * 2)), \
                patch.object(boot.base.integration, "MobileHarness") as harness, patch("builtins.print"):
            if changed:
                with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_SOURCE_CHANGED"):
                    boot.execute()
            else:
                self.assertTrue(boot.execute()["ok"])
            harness.assert_not_called()
        result = json.loads((self.run.parent / ("b" * 24) / "result.json").read_text())
        self.assertEqual(result["diagnostic_sources_sha256"], {
            "infra/mobile_boot_diagnostic.py": "a" * 64,
            "infra/test_mobile_boot_diagnostic.py": "a" * 64})
        self.assertEqual(result["diagnostic_sources_unchanged"], not changed)
        self.assertEqual(result["ok"], not changed)
        self.assertEqual(result.get("code"), "BOOT_SOURCE_CHANGED" if changed else None)
        self.assertFalse(result["database_started"])
        fake.install.assert_not_called()
        fake.unlock.assert_not_called()
        fake.instrument.assert_not_called()

    def test_only_fixed_boot_commands_can_reach_inherited_transport(self):
        with patch.object(boot.base.OwnedEmulator, "command", return_value="0\n") as command:
            self.assertEqual(self.emulator.command("shell", "getprop", "sys.boot_completed"), "0\n")
            for args, kwargs in ((("shell", "input", "text", "123456"), {}),
                                 (("install", "fixture.apk"), {}),
                                 (("shell", "getprop", "sys.boot_completed"), {"stdin": b"anything"}),
                                 (("reverse", "tcp:18082", "tcp:18082"), {})):
                with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_COMMAND_DENIED"):
                    self.emulator.command(*args, **kwargs)
            self.assertEqual(command.call_count, 1)
        result = self.emulator.diagnostic["commands"]["boot_completed"]
        self.assertEqual((result["attempts"], result["succeeded"], result["last_value"]), (1, 1, "not_complete"))

    def test_probe_errors_are_counted_without_raw_message(self):
        with patch.object(boot.base.OwnedEmulator, "command", side_effect=boot.base.DeviceError("PRIVATE_CANARY")):
            with self.assertRaises(boot.base.DeviceError):
                self.emulator.command("shell", "getprop", "sys.boot_completed")
        result = self.emulator.diagnostic["commands"]["boot_completed"]
        self.assertEqual((result["attempts"], result["errors"], result["last_code"]), (1, 1, "BOOT_OTHER_FAILURE"))
        self.assertNotIn("CANARY", str(result))

    def test_probe_counter_is_bounded_before_command(self):
        self.emulator.diagnostic["commands"]["boot_completed"] = {"attempts": 1000}
        with patch.object(boot.base.OwnedEmulator, "command") as command:
            with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_PROBE_BOUND"):
                self.emulator.command("shell", "getprop", "sys.boot_completed")
            command.assert_not_called()

    def test_install_unlock_and_instrumentation_cannot_start(self):
        with patch.object(boot.base.OwnedEmulator, "command") as command:
            for method in (lambda: self.emulator.install([], []), self.emulator.unlock,
                           lambda: self.emulator.instrument(boot.base.PHASES[0][0])):
                with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_COMMAND_DENIED"):
                    method()
            command.assert_not_called()

    def test_final_probe_is_fixed_bounded_and_cannot_turn_boot_failure_into_pass(self):
        with patch.object(boot.base.OwnedEmulator, "command", return_value="1\n1\nrunning\nrunning\nrunning\nrunning\n") as command:
            self.emulator.final_probe()
        self.assertEqual(command.call_args.args[1:], ("shell", "-T", "sh"))
        self.assertEqual(command.call_args.kwargs, {"stdin": boot.PROPERTY_INPUT, "timeout": 5, "maximum": 512})
        self.assertEqual(self.emulator.diagnostic["final_properties"]["sys.boot_completed"], "complete")
        self.assertNotIn("ok", self.emulator.evidence)
        self.assertNotIn("boot_gate_passed", self.emulator.evidence)

    def test_final_probe_passes_only_six_fixed_property_commands_through_stdin(self):
        with patch.object(self.emulator, "identity") as identity, \
                patch.object(boot.base, "run_bounded", return_value="1\n1\nstopped\nrunning\nrunning\nrunning\n") as command:
            self.emulator.target = {"transport": "7"}
            self.emulator.final_probe()
        identity.assert_called_once_with()
        self.assertEqual(command.call_args.args[0], [self.tools.adb, "-t", "7", "shell", "-T", "sh"])
        self.assertEqual(command.call_args.kwargs, {"stdin": (
            b"getprop sys.boot_completed\ngetprop dev.bootcomplete\ngetprop init.svc.bootanim\n"
            b"getprop init.svc.zygote\ngetprop init.svc.surfaceflinger\ngetprop init.svc.servicemanager\n"),
            "timeout": 5, "maximum": 512})

    def test_final_probe_failure_does_not_prevent_owned_cleanup(self):
        self.emulator.owner = Mock()
        self.emulator.child = Mock()
        self.emulator.child.poll.side_effect = [None, 0]
        sock = MagicMock()
        sock.__enter__.return_value.connect_ex.return_value = 1
        with patch.object(boot.base.OwnedEmulator, "command", side_effect=boot.base.EmulatorError("EMULATOR_COMMAND_TIMEOUT")), patch.object(boot.socket, "socket", return_value=sock):
            self.emulator.__exit__(None, None, None)
        self.emulator.owner.close.assert_called_once()
        self.assertTrue(self.emulator.evidence["owned_emulator_stopped"])
        self.assertTrue(self.emulator.evidence["owned_emulator_ports_closed"])
        self.assertEqual(self.emulator.diagnostic["final_probe_code"], "EMULATOR_COMMAND_TIMEOUT")

    def test_cleanup_uncertainty_does_not_import_or_call_database_harness(self):
        self.emulator.owner = Mock()
        self.emulator.owner.close.side_effect = RuntimeError("PRIVATE_CANARY")
        self.emulator.child = Mock()
        self.emulator.child.poll.return_value = 0
        with patch.object(boot.base.integration, "MobileHarness") as harness:
            with self.assertRaisesRegex(boot.base.EmulatorError, "BOOT_CLEANUP_UNCERTAIN"):
                self.emulator.__exit__(None, None, None)
            harness.assert_not_called()
        self.assertNotIn("CANARY", str(self.emulator.evidence))
        self.assertNotIn("owned_emulator_ports_closed", self.emulator.evidence)

    def test_no_owned_process_preflight_does_not_claim_global_ports_closed(self):
        with patch.object(boot.socket, "socket") as socket:
            self.emulator.__exit__(None, None, None)
        socket.assert_not_called()
        self.assertTrue(self.emulator.evidence["owned_process_never_started"])
        self.assertNotIn("owned_emulator_ports_closed", self.emulator.evidence)

    def test_inherited_identity_still_refuses_phone_and_changed_transport(self):
        self.emulator.child = Mock()
        self.emulator.child.poll.return_value = None
        self.tools.discover.return_value = [{"serial": "synthetic-phone", "state": "device", "transport": "7"}]
        with patch.object(boot.base, "run_bounded") as command:
            with self.assertRaisesRegex(boot.base.EmulatorError, "EMULATOR_TRANSPORT_UNAVAILABLE"):
                self.emulator.command("shell", "getprop", "sys.boot_completed")
            command.assert_not_called()
        self.emulator.target = {"serial": boot.base.SERIAL, "state": "device", "transport": "7"}
        self.tools.discover.return_value = [{**self.emulator.target, "transport": "8"}]
        with patch.object(boot.base, "run_bounded") as command:
            with self.assertRaisesRegex(boot.base.EmulatorError, "EMULATOR_TRANSPORT_CHANGED"):
                self.emulator.command("shell", "getprop", "sys.boot_completed")
            command.assert_not_called()

    def test_inherited_entry_failure_keeps_original_error_and_closes_owned_job(self):
        self.check_entry_failure(cleanup_failed=False)

    def test_entry_and_cleanup_failures_are_retained_separately_without_db_hook(self):
        self.check_entry_failure(cleanup_failed=True)

    def check_entry_failure(self, *, cleanup_failed):
        self.tools.sdk = self.root / "sdk"
        for name in ("system-images/android-36/google_apis/x86_64/system.img", "emulator/emulator.exe"):
            path = self.tools.sdk / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic")
        self.tools.discover.return_value = []
        child, owner, sock = Mock(), Mock(), MagicMock()
        child.poll.side_effect = [None, None, 0]
        sock.__enter__.return_value.connect_ex.return_value = 1
        if cleanup_failed:
            owner.close.side_effect = RuntimeError("PRIVATE_CLEANUP_CANARY")
        with patch.object(boot.base, "ports_available"), patch.object(boot.base, "OwnedProcessTree", return_value=owner), \
                patch.object(boot.base.subprocess, "Popen", return_value=child), \
                patch.object(boot.base.OwnedEmulator, "command", side_effect=boot.base.EmulatorError("EMULATOR_AVD_IDENTITY")), \
                patch.object(boot.socket, "socket", return_value=sock), \
                patch.object(boot.base.integration, "MobileHarness") as harness:
            expected = "BOOT_CLEANUP_UNCERTAIN" if cleanup_failed else "EMULATOR_AVD_IDENTITY"
            with self.assertRaisesRegex(boot.base.EmulatorError, expected):
                self.emulator.__enter__()
            harness.assert_not_called()
        owner.attach_and_resume.assert_called_once_with(child)
        owner.close.assert_called_once()
        self.assertTrue(self.emulator.closed)
        self.assertEqual(self.emulator.evidence["body_failure"]["code"], "EMULATOR_AVD_IDENTITY")
        self.assertEqual("cleanup_failure" in self.emulator.evidence, cleanup_failed)
        self.assertNotIn("CANARY", str(self.emulator.evidence))


if __name__ == "__main__":
    unittest.main()
