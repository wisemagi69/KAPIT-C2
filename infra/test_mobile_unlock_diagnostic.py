"""Pure TASK100 metadata/ownership guards. No actual ADB or service starts."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from infra import mobile_unlock_diagnostic as diag

POLICY = ("  KeyguardServiceDelegate\n    showing=true\n    secure=true\n    occluded=false\n"
          "    currentUser=-10000\n    KeyguardStateMonitor\n      mCurrentUserId=0\n"
          "      mIsShowing=true\n      mInputRestricted=true\n  OtherSection\n")
WINDOWS = ("  mCurrentFocus=Window{a1 u0 PRIVATE_CANARY}\n"
           "  Window #0 Window{a1 u0 PRIVATE_CANARY}:\n"
           "    mOwnerUid=10050 showForAllUsers=true package=com.android.systemui appop=NONE\n")
CAPTURE = {"packages": "package:com.android.systemui uid:10050\npackage:other.PRIVATE_CANARY uid:10051\n",
    "trust": 'User "PRIVATE_CANARY" (id=0, flags=0xc13) (current): deviceLocked=1\n',
    "policy": POLICY, "windows": WINDOWS, "current_user": "0\n"}


class MetadataTests(unittest.TestCase):
    def test_package_substring_rows_are_counts_not_inventory_or_authorization(self):
        summary, candidate = diag.package_summary(CAPTURE["packages"])
        self.assertEqual(candidate, 10050)
        self.assertEqual(summary["exact_package_rows"], 1)
        self.assertEqual(summary["other_package_rows"], 1)
        self.assertEqual(summary["candidate_category"], "owner0")
        # Historical field name is frozen; it now calls the current exact-package parser.
        # This observation cannot authorize the obsolete captured-window replay below.
        self.assertTrue(summary["old_single_row_parser_accepts"])
        self.assertNotIn("CANARY", json.dumps(summary))
        self.assertNotIn("10050", json.dumps(summary))

    def test_absent_duplicate_invalid_and_other_user_candidates_are_not_identity(self):
        for raw, category in (("", "absent"), ("package:com.android.systemui uid:10050\n" * 2, "ambiguous"),
                ("package:com.android.systemui uid:PRIVATE_CANARY\n", "invalid"),
                ("package:com.android.systemui uid:0\n", "invalid"),
                ("package:com.android.systemui uid:110050\n", "other_user")):
            with self.subTest(category=category):
                summary, candidate = diag.package_summary(raw)
                self.assertEqual(summary["candidate_category"], category)
                self.assertIsNone(candidate)
                self.assertNotIn("CANARY", json.dumps(summary))

    def test_delegate_and_nested_monitor_values_remain_distinct(self):
        result = diag.policy_summary(POLICY)
        self.assertEqual(result["delegate_current_user"], {"count": 1, "category": "user_null"})
        self.assertEqual(result["monitor_current_user_id"], {"count": 1, "category": "zero"})
        self.assertFalse(result["old_delegate_conditions"]["keyguard_owner_user"])
        self.assertEqual(result["monitor_showing"]["category"], "true")

    def test_user_field_categories_reject_duplicate_and_malformed_values(self):
        for values, expected in (([], "absent"), (["id=0", "id=1"], "ambiguous"),
                (["id=PRIVATE_CANARY"], "invalid"), (["id=-2"], "negative"), (["id=10"], "positive")):
            self.assertEqual(diag.scalar(values, "id")["category"], expected)
        self.assertEqual(diag.scalar(["id=TRUE"], "id", boolean=True)["category"], "invalid")

    def test_duplicate_or_absent_sections_do_not_adopt_nested_user(self):
        result = diag.policy_summary(POLICY + POLICY)
        self.assertEqual(result["delegate_sections"], 2)
        self.assertEqual(result["monitor_current_user_id"]["category"], "absent")
        self.assertFalse(result["old_delegate_conditions"]["keyguard_owner_user"])

    def test_focus_requires_actual_matching_record_and_only_emits_fixed_identity(self):
        result = diag.focus_summary(WINDOWS, 10050)
        self.assertEqual(result["matching_window_records"], 1)
        self.assertEqual(result["owner_package"], "systemui")
        self.assertEqual(result["candidate_uid_match"], "equal")
        self.assertTrue(result["old_focus_parser_with_exact_candidate"])
        self.assertNotIn("CANARY", json.dumps(result))
        self.assertNotIn("10050", json.dumps(result))

    def test_wrong_owner_candidate_and_missing_focus_do_not_match(self):
        for raw, candidate in ((WINDOWS.replace("mOwnerUid=10050", "mOwnerUid=10051"), 10050),
                (WINDOWS.replace("package=com.android.systemui", "package=other.PRIVATE_CANARY"), 10050),
                (WINDOWS.replace("Window #0 Window{a1", "Window #0 Window{b2"), 10050),
                (WINDOWS + "  mCurrentFocus=null\n", 10050), (WINDOWS, None), ("", 10050)):
            with self.subTest(candidate=candidate):
                result = diag.focus_summary(raw, candidate)
                self.assertFalse(result["old_focus_parser_with_exact_candidate"])
                self.assertNotIn("CANARY", json.dumps(result))

    def test_frozen_snapshot_rejects_current_full_window_query(self):
        self.assertEqual(diag.READS['windows'], ('shell', 'dumpsys', 'window', 'windows'))
        self.assertEqual(diag.base.WINDOW_SNAPSHOT, ('shell', 'dumpsys', 'window', '-a'))
        with self.assertRaisesRegex(diag.base.EmulatorError, "UNLOCK_SNAPSHOT_COMMAND_DENIED"):
            diag.ReadSnapshot(CAPTURE).command(*diag.base.WINDOW_SNAPSHOT, timeout=5)
        with self.assertRaisesRegex(diag.base.EmulatorError, "UNLOCK_SNAPSHOT_COMMAND_DENIED"):
            diag.summarize(CAPTURE)

    def test_historical_diagnostics_refuse_current_dependencies_before_tools(self):
        # Use actual dependency bytes, not mocked digests. Completed diagnostics must
        # refuse the changed guards even if an old in-memory fixture looked acceptable.
        for module, code in ((diag.boot, 'BOOT_SOURCE_CHANGED'), (diag, 'UNLOCK_SOURCE_CHANGED')):
            with self.subTest(module=module.__name__):
                self.assertNotEqual(module.base.digest(module.ROOT / 'infra/mobile_emulator.py'),
                                    module.FROZEN['infra/mobile_emulator.py'])
                with patch.object(module.os, 'name', 'nt'), \
                        patch.object(module.base, 'AndroidTools') as tools, \
                        patch.object(module.shutil, 'disk_usage') as disk:
                    with self.assertRaisesRegex(diag.base.EmulatorError, code):
                        module.execute()
                    tools.assert_not_called()
                    disk.assert_not_called()

    def test_snapshot_allows_only_fixed_read_tuples_and_timeout(self):
        snapshot = diag.ReadSnapshot(CAPTURE)
        for args, kwargs in ((('shell', 'input', 'text', '123456'), {}), (diag.READS['trust'], {}),
                             (diag.READS['trust'], {'timeout': 5, 'stdin': b'anything'})):
            with self.assertRaisesRegex(diag.base.EmulatorError, "UNLOCK_SNAPSHOT_COMMAND_DENIED"):
                snapshot.command(*args, **kwargs)

    def test_capture_bounds_and_required_fields_fail_closed(self):
        for raw in ("x" * 262145, "\n" * 4097):
            with self.assertRaisesRegex(diag.base.EmulatorError, "UNLOCK_METADATA_BOUND"):
                diag.lines(raw)
        with self.assertRaisesRegex(diag.base.EmulatorError, "UNLOCK_SNAPSHOT_COMMAND_DENIED"):
            diag.summarize({"packages": ""})

    def test_error_messages_never_cross_allowlist(self):
        for error in (ValueError("UNLOCK_SOURCE_CHANGED"), RuntimeError("PRIVATE_CANARY"),
                      diag.base.EmulatorError("PRIVATE_CANARY")):
            self.assertEqual(diag.error_code(error), "BOOT_OTHER_FAILURE")


class OwnedDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for module in (diag, diag.base):
            target = patch.object(module, "ROOT", self.root)
            target.start()
            self.addCleanup(target.stop)
        self.run = self.root / '.cache/m1-runtime/mobile-unlock' / ('a' * 24)
        self.run.parent.mkdir(parents=True)
        self.lease = diag.UnlockLease(self.run).__enter__()
        self.addCleanup(self.lease.__exit__, None, None, None)
        self.emulator = diag.UnlockDiagnostic(Mock(), self.lease, self.run)

    def test_boot_identity_and_database_free_cleanup_are_inherited(self):
        self.assertIs(diag.UnlockDiagnostic.__enter__, diag.base.OwnedEmulator.__enter__)
        self.assertIs(diag.UnlockDiagnostic.identity, diag.base.OwnedEmulator.identity)
        self.assertIs(diag.UnlockDiagnostic.__exit__, diag.boot.BootEmulator.__exit__)
        self.assertEqual(self.emulator.diagnostic['boot_deadline_seconds'], 240)

    def test_lease_rejects_existing_run_wrong_parent_and_changed_marker(self):
        with self.assertRaisesRegex(diag.base.EmulatorError, "A11Y_RUN_PREEXISTING"):
            diag.UnlockLease(self.run).__enter__()
        with self.assertRaisesRegex(diag.base.EmulatorError, "UNLOCK_RUN_PATH_DENIED"):
            diag.UnlockLease(self.root / '.cache/m1-runtime/mobile-boot' / ('b' * 24))
        self.lease.path.write_bytes(b'changed')
        with self.assertRaisesRegex(diag.base.EmulatorError, "A11Y_RUN_OWNERSHIP_LOST"):
            self.lease.assert_owned()

    def test_pin_only_uses_stdin_once_then_fixed_preparation_without_ui_entry(self):
        with patch.object(diag.base.OwnedEmulator, 'command', return_value='Pin set to PRIVATE_CANARY') as command, \
                patch.object(diag.secrets, 'randbelow', return_value=234567), patch.object(diag.time, 'sleep') as sleep:
            self.emulator.prepare()
            with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_ALREADY_PREPARED'):
                self.emulator.prepare()
        self.assertEqual(command.call_args_list[0], call(self.emulator, 'shell',
            stdin=b'locksettings set-pin 334567\n', timeout=20, maximum=1024))
        self.assertEqual([entry.args[1:] for entry in command.call_args_list[1:]], [
            ('shell', 'input', 'keyevent', 'KEYCODE_SLEEP'), ('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'),
            ('shell', 'input', 'swipe', '360', '1100', '360', '300', '400')])
        self.assertEqual(sleep.call_args_list, [call(2), call(3), call(3)])
        self.assertIsNone(self.emulator.pin)
        self.assertNotIn('334567', json.dumps(self.emulator.evidence))
        self.assertNotIn('CANARY', json.dumps(self.emulator.evidence))
        self.assertFalse(self.emulator.evidence['ui_pin_entered'])

    def test_failed_pin_setup_stops_before_swipe_or_capture(self):
        with patch.object(diag.base.OwnedEmulator, 'command', return_value='PRIVATE_CANARY') as command:
            with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_PIN_SETUP_FAILED'):
                self.emulator.prepare()
            self.assertEqual(command.call_count, 1)
            with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_NOT_PREPARED'):
                self.emulator.collect()
        self.assertNotIn('CANARY', json.dumps(self.emulator.evidence))

    def test_collect_five_frozen_reads_cannot_authorize_current_guard_replay(self):
        self.emulator.prepared = True
        with patch.object(diag.base.OwnedEmulator, 'command', side_effect=lambda _, *parts, **kw:
                CAPTURE[next(name for name, command in diag.READS.items() if command == parts)]) as command:
            with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_SNAPSHOT_COMMAND_DENIED'):
                self.emulator.collect()
            with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_ALREADY_COLLECTED'):
                self.emulator.collect()
            self.emulator.final_probe()
        self.assertEqual(command.call_count, 5)
        self.assertEqual([entry.args[1:] for entry in command.call_args_list], list(diag.READS.values()))
        self.assertTrue(all(entry.kwargs == {'timeout': 5, 'maximum': 262144} for entry in command.call_args_list))
        self.assertNotIn('lock_metadata', self.emulator.evidence)
        self.assertEqual(self.emulator.evidence['stage'], 'lock_metadata_capture')
        self.assertNotIn('CANARY', json.dumps(self.emulator.evidence))

    def test_install_unlock_instrument_and_arbitrary_commands_remain_denied(self):
        with patch.object(diag.base.OwnedEmulator, 'command') as command:
            for operation in (lambda: self.emulator.install([], []), self.emulator.unlock,
                    lambda: self.emulator.instrument(diag.base.PHASES[0][0]),
                    lambda: self.emulator.command('shell', stdin=b'input text 123456\n')):
                with self.assertRaisesRegex(diag.base.EmulatorError, 'BOOT_COMMAND_DENIED'):
                    operation()
            command.assert_not_called()

    def test_inherited_cleanup_stops_owned_job_without_database_hook(self):
        self.emulator.owner, self.emulator.child = Mock(), Mock()
        self.emulator.child.poll.side_effect = [None, 0]
        sock = MagicMock()
        sock.__enter__.return_value.connect_ex.return_value = 1
        with patch.object(diag.boot.socket, 'socket', return_value=sock), \
                patch.object(diag.base.integration, 'MobileHarness') as harness, \
                patch.object(diag.base.OwnedEmulator, 'command') as command:
            self.emulator.__exit__(None, None, None)
            command.assert_not_called()
            harness.assert_not_called()
        self.emulator.owner.close.assert_called_once()
        self.assertTrue(self.emulator.evidence['owned_emulator_stopped'])
        self.assertTrue(self.emulator.evidence['owned_emulator_ports_closed'])

    def test_cleanup_failure_preserves_body_failure_without_raw_details(self):
        self.emulator.owner, self.emulator.child = Mock(), Mock()
        self.emulator.child.poll.return_value = 0
        self.emulator.owner.close.side_effect = RuntimeError('PRIVATE_CANARY')
        with patch.object(diag.base.integration, 'MobileHarness') as harness:
            with self.assertRaisesRegex(diag.base.EmulatorError, 'BOOT_CLEANUP_UNCERTAIN'):
                self.emulator.__exit__(ValueError, ValueError('PRIVATE_CANARY'), None)
            harness.assert_not_called()
        self.assertIn('body_failure', self.emulator.evidence)
        self.assertIn('cleanup_failure', self.emulator.evidence)
        self.assertNotIn('CANARY', json.dumps(self.emulator.evidence))

    def test_changed_dependency_refuses_before_tool_creation(self):
        with patch.object(diag.base, 'digest', return_value='different'), \
                patch.object(diag.base, 'AndroidTools') as tools:
            with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_SOURCE_CHANGED'):
                diag.execute()
            tools.assert_not_called()

    def test_lost_lease_prevents_even_pin_setup_command(self):
        self.lease.path.write_bytes(b'changed')
        with patch.object(diag.base, 'run_bounded') as command:
            with self.assertRaisesRegex(diag.base.EmulatorError, 'A11Y_RUN_OWNERSHIP_LOST'):
                self.emulator.prepare()
            command.assert_not_called()

    def test_recorded_guard_denial_can_be_successful_diagnosis_with_bound_source_hashes(self):
        self.check_execute_evidence(changed=False)

    def test_changed_own_source_invalidates_successful_diagnosis(self):
        self.check_execute_evidence(changed=True)

    def check_execute_evidence(self, *, changed):
        fake = MagicMock()
        fake.closed = True
        fake.evidence = {'owned_emulator_stopped': True, 'owned_emulator_ports_closed': True,
                         'lock_metadata': {'existing_guard_result': 'denied'}}
        fake.diagnostic = {}
        counts = {}
        def digest(path):
            name = path.relative_to(self.root).as_posix()
            if name in diag.FROZEN:
                return diag.FROZEN[name]
            counts[name] = counts.get(name, 0) + 1
            return 'b' * 64 if changed and counts[name] > 1 else 'a' * 64
        with patch.object(diag.base, 'digest', side_effect=digest), patch.object(diag.base, 'AndroidTools'), \
                patch.object(diag, 'UnlockDiagnostic', return_value=fake), \
                patch.object(diag.shutil, 'disk_usage', return_value=Mock(free=20 * 1024**3)), \
                patch.object(diag.secrets, 'token_hex', side_effect=lambda size: 'b' * (size * 2)), \
                patch.object(diag.base.integration, 'MobileHarness') as harness, patch('builtins.print'):
            if changed:
                with self.assertRaisesRegex(diag.base.EmulatorError, 'UNLOCK_SOURCE_CHANGED'):
                    diag.execute()
            else:
                self.assertTrue(diag.execute()['ok'])
            harness.assert_not_called()
        fake.prepare.assert_called_once_with()
        fake.collect.assert_called_once_with()
        fake.install.assert_not_called()
        fake.unlock.assert_not_called()
        fake.instrument.assert_not_called()
        result = json.loads((self.run.parent / ('b' * 24) / 'result.json').read_text())
        self.assertEqual(result['diagnostic_sources_sha256'], {
            'infra/mobile_unlock_diagnostic.py': 'a' * 64,
            'infra/test_mobile_unlock_diagnostic.py': 'a' * 64})
        self.assertEqual(result['ok'], not changed)
        self.assertEqual(result['diagnostic_sources_unchanged'], not changed)
        self.assertEqual(result['emulator']['lock_metadata']['existing_guard_result'], 'denied')
        self.assertFalse(result['database_started'])
        self.assertFalse(result['packages_installed'])
        self.assertFalse(result['ui_pin_entered'])


if __name__ == '__main__':
    unittest.main()
