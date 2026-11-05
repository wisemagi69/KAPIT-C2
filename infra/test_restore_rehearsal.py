"""Pure coordination/guard tests. No DB, PostgreSQL executable or real listener runs."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from infra import restore_rehearsal as restore


class StubRuntime:
    def __init__(self):
        self.events = []
        self.snapshots = [{"current": 1}, {"current": 1}, {"current": 1}]
        self.restored = {"current": 1}
        self.failure = None
        self.cleanup = "STOPPED_VERIFIED"

    def phase(self, name):
        self.events.append(name)
        if self.failure == name:
            raise RuntimeError("PRIVATE_DATABASE_KEY_CANARY")

    def preflight(self): self.phase("preflight")
    def source_snapshot(self):
        self.phase("source_snapshot")
        return self.snapshots.pop(0)
    def fresh_backup(self): self.phase("backup")
    def reserve(self): self.phase("reserve")
    def initialize(self): self.phase("initialize")
    def start(self): self.phase("start")
    def restore(self): self.phase("restore")
    def restored_snapshot(self):
        self.phase("restored_snapshot")
        return self.restored
    def verify_decryption(self): self.phase("decryption")
    def stop_owned(self):
        self.phase("stop_owned")
        return self.cleanup


class CoordinationTests(unittest.TestCase):
    def execute(self, driver):
        return restore.rehearse(execute=True, reservation="a" * 32, driver=driver)

    def test_default_preparation_has_no_runtime_construction_or_key_read(self):
        with patch.object(restore, "LocalRuntime", side_effect=AssertionError("runtime constructed")):
            result = restore.rehearse()
        self.assertEqual(result["status"], "PREPARED_NOT_EXECUTED")
        self.assertEqual(result["restore"], "NOT_RUN")
        self.assertEqual(result["application"], "CLOSED")

    def test_execute_requires_explicit_parent_reservation_token(self):
        for token in (None, True, "", "a" * 31, "A" * 32, "../target"):
            with self.subTest(token=token), patch.object(restore, "LocalRuntime") as driver:
                result = restore.rehearse(execute=True, reservation=token)
                driver.assert_not_called()
                self.assertEqual(result["code"], "RESERVATION_REQUIRED")

    def test_complete_stub_sequence_always_stops_and_keeps_application_closed(self):
        driver = StubRuntime()
        result = self.execute(driver)
        self.assertEqual(result["status"], "DATABASE_REHEARSAL_PASSED_CLOSED")
        self.assertEqual(result["application"], "CLOSED")
        self.assertEqual(result["file_storage"], "NOT_REHEARSED")
        self.assertEqual(driver.events, ["preflight", "source_snapshot", "backup", "source_snapshot", "reserve", "initialize",
            "start", "restore", "restored_snapshot", "decryption", "source_snapshot", "stop_owned"])

    def test_backup_drift_never_creates_cluster(self):
        driver = StubRuntime()
        driver.snapshots[1] = {"current": 2}
        result = self.execute(driver)
        self.assertEqual(result["code"], "SOURCE_CHANGED_DURING_BACKUP")
        self.assertNotIn("reserve", driver.events)
        self.assertEqual(result["cleanup"], "NOT_STARTED")

    def test_current_revocation_drift_refuses_success_and_stops_only_child(self):
        driver = StubRuntime()
        driver.snapshots[-1] = {"current": "revoked"}
        result = self.execute(driver)
        self.assertEqual(result["code"], "CURRENT_AUTHORIZATION_CHANGED")
        self.assertEqual(driver.events[-1], "stop_owned")
        self.assertEqual(result["application"], "CLOSED")

    def test_restored_mismatch_prevents_decryption_success(self):
        driver = StubRuntime()
        driver.restored = {"current": 2}
        result = self.execute(driver)
        self.assertEqual(result["code"], "RESTORED_SNAPSHOT_MISMATCH")
        self.assertNotIn("decryption", driver.events)
        self.assertEqual(driver.events[-1], "stop_owned")

    def test_failure_at_every_mutating_phase_attempts_owned_cleanup_no_secret_output(self):
        for phase in ("reserve", "initialize", "start", "restore", "restored_snapshot", "decryption"):
            driver = StubRuntime()
            driver.failure = phase
            result = self.execute(driver)
            self.assertEqual(driver.events[-1], "stop_owned")
            self.assertEqual(result["status"], "UNAVAILABLE")
            self.assertNotIn("PRIVATE_", json.dumps(result))

    def test_unconfirmed_stop_cannot_report_rehearsal_success(self):
        driver = StubRuntime()
        driver.cleanup = "UNKNOWN"
        self.assertEqual(self.execute(driver)["code"], "STOP_UNCONFIRMED")
        driver = StubRuntime()
        driver.failure = "stop_owned"
        self.assertEqual(self.execute(driver)["status"], "UNAVAILABLE")

    def test_even_custom_error_cannot_reflect_unrecognized_secret_code(self):
        driver = StubRuntime()
        driver.preflight = Mock(side_effect=restore.RehearsalError("PRIVATE_SECRET_CANARY"))
        result = self.execute(driver)
        self.assertEqual(result["code"], "REHEARSAL_UNAVAILABLE")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_cli_default_is_incomplete_exit_two(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = restore.main([])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "PREPARED_NOT_EXECUTED")


class FakeSocket:
    def __init__(self): self.closed = False
    def setsockopt(self, *args): pass
    def bind(self, endpoint): self.endpoint = endpoint
    def getsockname(self): return self.endpoint
    def close(self): self.closed = True


class SandboxGuardsTests(unittest.TestCase):
    def setUp(self):
        from infra import native_postgres
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / ".cache").mkdir()
        self.native = native_postgres
        for target, name, value in ((restore, "ROOT", self.root), (self.native, "ROOT", self.root)):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.driver = restore.LocalRuntime("a" * 32)
        self.socket = FakeSocket()
        for target, name, value in ((restore.socket, "socket", Mock(return_value=self.socket)),
                                     (restore.secrets, "token_hex", Mock(return_value="b" * 32)),
                                     (restore.secrets, "randbelow", Mock(return_value=400))):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_exclusive_reservation_isolated_name_port_and_private_credentials(self):
        self.driver.reserve()
        self.assertEqual(self.driver.port, 56400)
        self.assertNotEqual(self.driver.port, self.native.PORT)
        self.assertEqual(self.driver.database, "kapit_recovery_" + "b" * 32)
        self.assertNotEqual(self.driver.user, "kapit_m1")
        marker = json.loads((self.driver.target / "owner.json").read_text())
        self.assertNotIn(self.driver.password, json.dumps(marker))
        self.assertNotIn("a" * 32, json.dumps(marker))
        self.driver.check_owner()
        self.assertEqual(self.driver.stop_owned(), "NOT_STARTED")
        self.assertTrue(self.socket.closed)

    def test_existing_target_refused_without_overwrite(self):
        self.driver.reserve()
        marker = (self.driver.target / "owner.json").read_bytes()
        with self.assertRaises(FileExistsError):
            restore.LocalRuntime("a" * 32).reserve()
        self.assertEqual((self.driver.target / "owner.json").read_bytes(), marker)
        self.driver.stop_owned()

    def test_unowned_root_and_bool_owner_schema_refused(self):
        root = self.root / ".cache/m4-recovery"
        root.mkdir()
        with self.assertRaisesRegex(restore.RehearsalError, "RECOVERY_ROOT_OWNER_INVALID"):
            self.driver.reserve()
        (root / "owner.json").write_text(json.dumps({"schema": True, "owner": restore.OWNER, "workspace": str(self.root)}))
        with self.assertRaisesRegex(restore.RehearsalError, "RECOVERY_ROOT_OWNER_INVALID"):
            self.driver.reserve()

    def test_marker_changed_or_unknown_cannot_stop_any_server(self):
        self.driver.reserve()
        (self.driver.target / "owner.json").write_text(json.dumps({**self.driver.marker, "target": "c" * 32}))
        with patch.object(self.driver, "command") as command:
            with self.assertRaisesRegex(restore.RehearsalError, "CHILD_OWNER_CHANGED"):
                self.driver.stop_owned()
            command.assert_not_called()

    def test_existing_data_is_not_initialized_or_cleaned(self):
        self.driver.reserve()
        self.driver.data.mkdir()
        sentinel = self.driver.data / "preserve"
        sentinel.write_text("synthetic retained sentinel")
        with patch.object(self.driver, "command") as command:
            with self.assertRaisesRegex(restore.RehearsalError, "CHILD_DATA_PREEXISTS"):
                self.driver.initialize()
            command.assert_not_called()
        self.assertTrue(sentinel.is_file())
        self.driver.stop_owned()

    def test_symlink_or_junction_path_guard_runs_before_creation(self):
        with patch.object(self.native, "checked_path", side_effect=RuntimeError("NATIVE_PATH")):
            with self.assertRaises(RuntimeError):
                self.driver.reserve()
        self.assertFalse((self.root / ".cache/m4-recovery").exists())

    def test_stop_requires_pid_config_os_identity_and_authenticated_connection(self):
        self.driver.reserve()
        self.driver.data.mkdir()
        (self.driver.data / "postmaster.pid").write_text("synthetic process marker")
        with patch.object(self.driver, "verify_child", side_effect=restore.RehearsalError("CHILD_PROCESS_MISMATCH")), patch.object(self.driver, "command") as command:
            with self.assertRaisesRegex(restore.RehearsalError, "CHILD_PROCESS_MISMATCH"):
                self.driver.stop_owned()
            command.assert_not_called()

    def test_restore_uses_fail_fast_without_owner_acl_or_secret_arguments(self):
        self.driver.reserve()
        self.driver.archive = self.root / ".cache/backup.dump"
        self.driver.archive.write_bytes(b"synthetic dump")
        self.driver.archive_hash = self.native.digest(self.driver.archive)
        with patch.object(self.driver, "verify_child"), patch.object(self.driver, "command") as command:
            self.driver.restore()
        name, args = command.call_args.args
        self.assertEqual(name, "pg_restore")
        self.assertTrue({"--exit-on-error", "--no-owner", "--no-acl"}.issubset(args))
        self.assertNotIn(self.driver.password, " ".join(args))
        self.assertNotIn("kapit_m1", args)
        self.driver.stop_owned()

    def test_corrupt_archive_refused_before_restore_command(self):
        self.driver.reserve()
        self.driver.archive = self.root / ".cache/backup.dump"
        self.driver.archive.write_bytes(b"synthetic dump")
        self.driver.archive_hash = "0" * 64
        with patch.object(self.driver, "verify_child"), patch.object(self.driver, "command") as command:
            with self.assertRaisesRegex(restore.RehearsalError, "BACKUP_CHANGED"):
                self.driver.restore()
            command.assert_not_called()
        self.driver.stop_owned()

    def test_binary_bytes_rechecked_before_any_command(self):
        path = self.root / "synthetic-pg_ctl.exe"
        path.write_bytes(b"changed executable")
        self.driver.tools = {"pg_ctl": (str(path), "0" * 64)}
        with patch.object(self.native, "execute") as execute:
            with self.assertRaisesRegex(restore.RehearsalError, "RESTORE_BINARY_CHANGED"):
                self.driver.command("pg_ctl", ["stop"])
            execute.assert_not_called()

    def test_inherited_pg_environment_refused_before_dependency_or_owner_probe(self):
        with patch.dict(restore.os.environ, {"PGSERVICE": "unrelated-database"}), patch.object(self.native, "ownership") as owner:
            with self.assertRaisesRegex(restore.RehearsalError, "LIBPQ_ENVIRONMENT_UNSAFE"):
                self.driver.preflight()
            owner.assert_not_called()

    def test_redirected_backup_directory_is_checked_before_helper_writes(self):
        path = self.root / ".cache/m1-runtime/backups"
        with patch.object(self.driver.local, "BACKUP_DIR", path), patch.object(self.driver, "checked", side_effect=RuntimeError("NATIVE_PATH")) as checked, patch.object(self.driver.local, "native_backup") as backup:
            with self.assertRaises(RuntimeError):
                self.driver.fresh_backup()
            checked.assert_called_once_with(path)
            backup.assert_not_called()

    def test_wrong_backup_parent_or_file_type_refuses_before_helper(self):
        wrong = self.root / ".cache/other-backups"
        expected = self.root / ".cache/m1-runtime/backups"
        expected.parent.mkdir()
        expected.write_text("preserve non-directory artifact")
        for path in (wrong, expected):
            with patch.object(self.driver.local, "BACKUP_DIR", path), patch.object(self.driver.local, "native_backup") as backup:
                with self.assertRaisesRegex(restore.RehearsalError, "BACKUP_DIRECTORY_INVALID"):
                    self.driver.fresh_backup()
                backup.assert_not_called()

    def configuration_fixture(self):
        self.driver.reserve()
        self.driver.data.mkdir()
        self.driver.major = 17
        for name in ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"):
            (self.driver.data / name).write_text("17\n" if name == "PG_VERSION" else "# synthetic config\n")
        self.driver.config_hashes = {name: self.native.digest(self.driver.data / name) for name in
            ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")}

    def test_changed_configuration_refuses_before_socket_release_or_pg_ctl(self):
        self.configuration_fixture()
        (self.driver.data / "postgresql.conf").write_text("listen_addresses='*'\n")
        with patch.object(self.driver, "command") as command, patch.object(self.driver, "verify_child") as verify:
            with self.assertRaisesRegex(restore.RehearsalError, "CHILD_CONFIG_CHANGED"):
                self.driver.start()
            command.assert_not_called()
            verify.assert_not_called()
            self.assertFalse(self.socket.closed)
        self.driver.stop_owned()

    def test_postgres_major_checked_before_launch_even_with_recorded_hash(self):
        self.configuration_fixture()
        version = self.driver.data / "PG_VERSION"
        version.write_text("18\n")
        self.driver.config_hashes["PG_VERSION"] = self.native.digest(version)
        with patch.object(self.driver, "command") as command:
            with self.assertRaisesRegex(restore.RehearsalError, "CHILD_CONFIG_CHANGED"):
                self.driver.start()
            command.assert_not_called()
            self.assertFalse(self.socket.closed)
        self.driver.stop_owned()


class StubCursor:
    def __init__(self, batches):
        self.batches = list(batches)
        self.rows = []
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, query): self.rows = list(self.batches.pop(0))
    def fetchall(self):
        result, self.rows = self.rows, []
        return result
    def fetchmany(self, size):
        result, self.rows = self.rows[:size], self.rows[size:]
        return result


class SnapshotAndDecryptionTests(unittest.TestCase):
    def connection(self, batches):
        cursor = StubCursor(batches)
        connection = Mock()
        connection.cursor.return_value = cursor
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        return connection

    def snapshot_batches(self, *, private="PRIVATE_SNAPSHOT_CANARY", validated=True, enabled="O"):
        return [[("scopes_organization",)], [(json.dumps({"private": private}),)], [("scopes", "0004_m3_scope_profiles")],
                [("synthetic", "nonnegative", "c", validated, "CHECK (epoch >= 0)")],
                [(name, "synthetic guard definition") for name in sorted(restore.REQUIRED_FUNCTIONS)],
                [("synthetic", "guard-" + str(i), enabled, "synthetic trigger") for i in range(20)],
                [("synthetic", "partial_unique", "CREATE UNIQUE INDEX synthetic WHERE active")],
                [("synthetic_id_seq", 1, 1, 1, 1, 1000, False, 1)]]

    def test_snapshot_hashes_private_rows_without_returning_them(self):
        result = restore.database_snapshot(self.connection(self.snapshot_batches()))
        self.assertNotIn("PRIVATE_SNAPSHOT_CANARY", json.dumps(result))
        self.assertEqual(result["tables"]["scopes_organization"]["rows"], 1)
        changed = restore.database_snapshot(self.connection(self.snapshot_batches(private="changed")))
        self.assertNotEqual(changed, result)

    def test_invalid_constraints_disabled_guards_and_missing_functions_refuse(self):
        for batches, code in ((self.snapshot_batches(validated=False), "DATABASE_UNVALIDATED_CONSTRAINT"),
                              (self.snapshot_batches(enabled="D"), "DATABASE_GUARDS_MISSING")):
            with self.assertRaisesRegex(restore.RehearsalError, code):
                restore.database_snapshot(self.connection(batches))
        batches = self.snapshot_batches()
        batches[4] = []
        with self.assertRaisesRegex(restore.RehearsalError, "DATABASE_GUARDS_MISSING"):
            restore.database_snapshot(self.connection(batches))

    def test_snapshot_size_and_unsafe_table_names_are_bounded(self):
        with patch.object(restore, "MAX_SNAPSHOT_BYTES", 1):
            with self.assertRaisesRegex(restore.RehearsalError, "DATABASE_SNAPSHOT_LIMIT"):
                restore.database_snapshot(self.connection(self.snapshot_batches()))
        with self.assertRaisesRegex(restore.RehearsalError, "DATABASE_SCHEMA_UNSUPPORTED"):
            restore.database_snapshot(self.connection([[('unsafe";SQL',)]]))

    def driver(self, rows, payload=b'{"synthetic":"PRIVATE_SOURCE_CANARY"}'):
        driver = object.__new__(restore.LocalRuntime)
        driver.verify_child = Mock()
        driver.connection = Mock(return_value=self.connection([rows]))
        driver.source_key = SimpleNamespace(decrypt=Mock(return_value=payload))
        return driver

    def test_source_hash_checked_after_private_decryption(self):
        expected = restore._hash({"synthetic": "PRIVATE_SOURCE_CANARY"})
        driver = self.driver([(b"encrypted synthetic bytes", expected, None)])
        self.assertIsNone(driver.verify_decryption())
        driver.source_key.decrypt.assert_called_once_with(b"encrypted synthetic bytes")

    def test_wrong_key_hash_corruption_and_empty_source_cannot_claim_decryption_pass(self):
        driver = self.driver([(b"encrypted", "0" * 64, None)])
        with self.assertRaisesRegex(restore.RehearsalError, "RESTORED_SOURCE_INTEGRITY"):
            driver.verify_decryption()
        driver = self.driver([])
        with self.assertRaisesRegex(restore.RehearsalError, "RESTORED_NO_SOURCE_ROWS"):
            driver.verify_decryption()
        driver = self.driver([(b"encrypted", "0" * 64, None)])
        driver.source_key.decrypt.side_effect = ValueError("PRIVATE_WRONG_KEY_CANARY")
        with self.assertRaises(ValueError):
            driver.verify_decryption()
        # Coordinator catches adapter/driver failures without reflecting their text.
        driver = self.driver([(b"encrypted", "0" * 64, None)])
        driver.source_key.decrypt.side_effect = ValueError("PRIVATE_WRONG_KEY_CANARY")
        coordinated = StubRuntime()
        coordinated.verify_decryption = driver.verify_decryption
        self.assertNotIn("PRIVATE", json.dumps(restore.rehearse(execute=True, reservation="a" * 32, driver=coordinated)))


if __name__ == "__main__":
    unittest.main()


# Captured PostgreSQL18 source/dump/reparse schema DDL; no database row data.
OBSERVED_ENUM_CHECKS = [['scopes_adminauthority',
  'authority_kind_valid',
  "CHECK (((kind)::text = ANY ((ARRAY['POLICY'::character varying, 'INTEGRATION'::character "
  'varying])::text[])))',
  "CHECK (((kind)::text = ANY (ARRAY[('POLICY'::character varying)::text, ('INTEGRATION'::character "
  'varying)::text])))'],
 ['review_decisionbatch',
  'batch_action_valid',
  "CHECK (((action)::text = ANY ((ARRAY['APPROVE'::character varying, 'RETURN'::character varying, "
  "'REJECT'::character varying])::text[])))",
  "CHECK (((action)::text = ANY (ARRAY[('APPROVE'::character varying)::text, ('RETURN'::character "
  "varying)::text, ('REJECT'::character varying)::text])))"],
 ['scopes_sharingchannel',
  'channel_max_profile_valid',
  "CHECK (((max_profile IS NULL) OR ((max_profile)::text = ANY ((ARRAY['DEMO-FULL'::character varying, "
  "'DEMO-REDUCED'::character varying, 'DEMO-SUMMARY'::character varying])::text[]))))",
  "CHECK (((max_profile IS NULL) OR ((max_profile)::text = ANY (ARRAY[('DEMO-FULL'::character "
  "varying)::text, ('DEMO-REDUCED'::character varying)::text, ('DEMO-SUMMARY'::character "
  'varying)::text]))))'],
 ['accounts_integrationclient',
  'client_profile_valid',
  "CHECK (((profile_ceiling)::text = ANY ((ARRAY['DEMO-FULL'::character varying, 'DEMO-REDUCED'::character "
  "varying, 'DEMO-SUMMARY'::character varying])::text[])))",
  "CHECK (((profile_ceiling)::text = ANY (ARRAY[('DEMO-FULL'::character varying)::text, "
  "('DEMO-REDUCED'::character varying)::text, ('DEMO-SUMMARY'::character varying)::text])))"],
 ['accounts_integrationclientrequest',
  'client_request_profile_valid',
  "CHECK (((profile_ceiling)::text = ANY ((ARRAY['DEMO-FULL'::character varying, 'DEMO-REDUCED'::character "
  "varying, 'DEMO-SUMMARY'::character varying])::text[])))",
  "CHECK (((profile_ceiling)::text = ANY (ARRAY[('DEMO-FULL'::character varying)::text, "
  "('DEMO-REDUCED'::character varying)::text, ('DEMO-SUMMARY'::character varying)::text])))"],
 ['review_reviewdecision',
  'decision_action_valid',
  "CHECK (((action)::text = ANY ((ARRAY['APPROVE'::character varying, 'RETURN'::character varying, "
  "'REJECT'::character varying])::text[])))",
  "CHECK (((action)::text = ANY (ARRAY[('APPROVE'::character varying)::text, ('RETURN'::character "
  "varying)::text, ('REJECT'::character varying)::text])))"],
 ['publications_publicationdelivery',
  'delivery_profile_valid',
  "CHECK (((profile)::text = ANY ((ARRAY['DEMO-FULL'::character varying, 'DEMO-REDUCED'::character varying, "
  "'DEMO-SUMMARY'::character varying])::text[])))",
  "CHECK (((profile)::text = ANY (ARRAY[('DEMO-FULL'::character varying)::text, ('DEMO-REDUCED'::character "
  "varying)::text, ('DEMO-SUMMARY'::character varying)::text])))"],
 ['operations_privateevidence',
  'evidence_media_valid',
  "CHECK (((media_type)::text = ANY ((ARRAY['image/jpeg'::character varying, 'image/png'::character "
  'varying])::text[])))',
  "CHECK (((media_type)::text = ANY (ARRAY[('image/jpeg'::character varying)::text, ('image/png'::character "
  'varying)::text])))'],
 ['scopes_channelmember',
  'member_profile_ceiling_valid',
  "CHECK (((profile_ceiling)::text = ANY ((ARRAY['DEMO-FULL'::character varying, 'DEMO-REDUCED'::character "
  "varying, 'DEMO-SUMMARY'::character varying])::text[])))",
  "CHECK (((profile_ceiling)::text = ANY (ARRAY[('DEMO-FULL'::character varying)::text, "
  "('DEMO-REDUCED'::character varying)::text, ('DEMO-SUMMARY'::character varying)::text])))"],
 ['scopes_unitmembership',
  'membership_role_valid',
  "CHECK (((role)::text = ANY ((ARRAY['submitter'::character varying, 'reviewer'::character "
  'varying])::text[])))',
  "CHECK (((role)::text = ANY (ARRAY[('submitter'::character varying)::text, ('reviewer'::character "
  'varying)::text])))'],
 ['scopes_policyproposal',
  'proposal_kind_valid',
  "CHECK (((kind)::text = ANY ((ARRAY['ACTIVATE'::character varying, 'DEACTIVATE'::character "
  'varying])::text[])))',
  "CHECK (((kind)::text = ANY (ARRAY[('ACTIVATE'::character varying)::text, ('DEACTIVATE'::character "
  'varying)::text])))'],
 ['publications_publication',
  'publication_profile_valid',
  "CHECK (((profile)::text = ANY ((ARRAY['DEMO-FULL'::character varying, 'DEMO-REDUCED'::character varying, "
  "'DEMO-SUMMARY'::character varying])::text[])))",
  "CHECK (((profile)::text = ANY (ARRAY[('DEMO-FULL'::character varying)::text, ('DEMO-REDUCED'::character "
  "varying)::text, ('DEMO-SUMMARY'::character varying)::text])))"],
 ['publications_publicationremoval',
  'removal_cause_valid',
  "CHECK (((cause)::text = ANY ((ARRAY['WITHDRAWAL'::character varying, 'CORRECTION'::character varying, "
  "'POLICY'::character varying, 'SCOPE'::character varying, 'REAPPROVAL'::character varying])::text[])))",
  "CHECK (((cause)::text = ANY (ARRAY[('WITHDRAWAL'::character varying)::text, ('CORRECTION'::character "
  "varying)::text, ('POLICY'::character varying)::text, ('SCOPE'::character varying)::text, "
  "('REAPPROVAL'::character varying)::text])))"],
 ['publications_publicationremoval',
  'removal_kind_valid',
  "CHECK (((kind)::text = ANY ((ARRAY['WITHDRAWN'::character varying, 'SUPERSEDED'::character "
  'varying])::text[])))',
  "CHECK (((kind)::text = ANY (ARRAY[('WITHDRAWN'::character varying)::text, ('SUPERSEDED'::character "
  'varying)::text])))'],
 ['scopes_channelsource',
  'source_max_profile_valid',
  "CHECK (((max_profile IS NULL) OR ((max_profile)::text = ANY ((ARRAY['DEMO-FULL'::character varying, "
  "'DEMO-REDUCED'::character varying, 'DEMO-SUMMARY'::character varying])::text[]))))",
  "CHECK (((max_profile IS NULL) OR ((max_profile)::text = ANY (ARRAY[('DEMO-FULL'::character "
  "varying)::text, ('DEMO-REDUCED'::character varying)::text, ('DEMO-SUMMARY'::character "
  'varying)::text]))))'],
 ['accounts_user',
  'user_business_role',
  "CHECK (((role)::text = ANY ((ARRAY['submitter'::character varying, 'reviewer'::character varying, "
  "'recipient'::character varying, 'administrator'::character varying])::text[])))",
  "CHECK (((role)::text = ANY (ARRAY[('submitter'::character varying)::text, ('reviewer'::character "
  "varying)::text, ('recipient'::character varying)::text, ('administrator'::character varying)::text])))"],
 ['reports_reportvariant',
  'variant_profile_valid',
  "CHECK (((profile)::text = ANY ((ARRAY['DEMO-FULL'::character varying, 'DEMO-REDUCED'::character varying, "
  "'DEMO-SUMMARY'::character varying])::text[])))",
  "CHECK (((profile)::text = ANY (ARRAY[('DEMO-FULL'::character varying)::text, ('DEMO-REDUCED'::character "
  "varying)::text, ('DEMO-SUMMARY'::character varying)::text])))"]]

class EnumConstraintEquivalenceTests(unittest.TestCase):
    def test_all_observed_postgresql18_spellings_match(self):
        self.assertEqual(len(OBSERVED_ENUM_CHECKS), 17)
        for relation, name, before, after in OBSERVED_ENUM_CHECKS:
            with self.subTest(name=name):
                source = (relation, name, "c", True, before)
                restored = (relation, name, "c", True, after)
                self.assertEqual(restore.canonical_constraint(source), restore.canonical_constraint(restored))

    def test_changed_semantics_and_unrecognized_spelling_remain_exact(self):
        for relation, name, before, after in OBSERVED_ENUM_CHECKS:
            baseline = restore.canonical_constraint((relation, name, "c", True, before))
            for definition in (before, after):
                changes = [definition.replace("ANY", "ALL"), definition.replace(" = ", " <> "),
                           definition.replace("character varying", "character varying(12)"),
                           definition.replace("::text", "::varchar"), definition + " ",
                           definition.replace("ARRAY[", "ARRAY['EXTRA'::character varying, "),
                           definition.replace("CHECK (", "CHECK (false AND "),
                           definition.replace("::text =", "::text COLLATE \"C\" ="),
                           definition.replace("'", "'CHANGED", 1),
                           definition.replace("CHECK", "CHECK /* comment */", 1)]
                if " OR " in definition:
                    changes += [definition.replace(" OR ", " AND "), definition.replace("IS NULL", "IS NOT NULL")]
                for changed in changes:
                    with self.subTest(name=name, changed=changed):
                        row = (relation, name, "c", True, changed)
                        self.assertEqual(restore.canonical_constraint(row), row)
                        self.assertNotEqual(restore.canonical_constraint(row), baseline)

    def test_identity_and_validation_are_never_discarded(self):
        for relation, name, before, after in OBSERVED_ENUM_CHECKS:
            for identity in [("other", name, "c", True), (relation, "other", "c", True),
                             (relation, name, "f", True), (relation, name, "c", False)]:
                row = (*identity, after)
                self.assertEqual(restore.canonical_constraint(row), row)
                self.assertNotEqual(restore.canonical_constraint((*identity, before)), row)
