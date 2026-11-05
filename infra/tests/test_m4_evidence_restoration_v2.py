"""TASK-612 fixtures only: no actual public destination/report is opened."""
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HELPER = Path(__file__).resolve().parents[2] / ".cache/m1-runtime/m4-restore-public-results-v2.py"
spec = importlib.util.spec_from_file_location("restoration_v2_fixture", HELPER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)  # Defines functions only; main/run not called here.


def facts(*, ctime=20, birth=10, inode=2**100 + 17, size=3, **changes):
    value = dict(st_dev=2**55 + 3, st_ino=inode, st_mode=stat.S_IFREG | 0o600,
                 st_nlink=1, st_size=size, st_mtime_ns=12, st_ctime_ns=ctime,
                 st_file_attributes=0, st_birthtime_ns=birth)
    value.update(changes)
    return SimpleNamespace(**value)


class SnapshotTests(unittest.TestCase):
    def test_separate_stable_ctimes_keep_every_other_common_fact(self):
        pathname, descriptor = m.file_facts(facts(ctime=20)), m.file_facts(facts(ctime=21))
        self.assertNotEqual(pathname, descriptor)
        self.assertEqual(m.common(pathname), m.common(descriptor))
        self.assertEqual(pathname[6], 20)
        self.assertEqual(descriptor[6], 21)
        self.assertEqual(pathname[1], 2**100 + 17)

    def test_each_api_clock_change_refuses(self):
        original = (m.file_facts(facts(ctime=20)), m.file_facts(facts(ctime=21)))
        path = SimpleNamespace(lstat=lambda: facts(ctime=20))
        stream = SimpleNamespace(fileno=lambda: 99)
        with patch.object(m.os, "fstat", return_value=facts(ctime=21)):
            m.recheck_pair(path, stream, original)
        for pathname_clock, fd_clock in ((22, 21), (20, 22)):
            path = SimpleNamespace(lstat=lambda: facts(ctime=pathname_clock))
            with self.subTest(path=pathname_clock, fd=fd_clock), patch.object(m.os, "fstat", return_value=facts(ctime=fd_clock)), self.assertRaises(m.Refused):
                m.recheck_pair(path, stream, original)

    def test_birthtime_required_integer_and_never_normalized(self):
        for birth in (None, True, 1.0, -1):
            with self.subTest(birth=birth), self.assertRaises(m.Refused):
                m.file_facts(facts(birth=birth))
        value = facts(); del value.st_birthtime_ns
        with self.assertRaises(m.Refused):
            m.file_facts(value)
        path = SimpleNamespace(lstat=lambda: facts(birth=10))
        with patch.object(m.os, "fstat", return_value=facts(birth=11)), self.assertRaises(m.Refused):
            m.snapshot_pair(path, SimpleNamespace(fileno=lambda: 99))

    def test_cross_api_identity_content_mutations_refuse(self):
        for field, value in (("st_dev", 5), ("st_ino", 99), ("st_mode", stat.S_IFREG | 0o400),
                             ("st_size", 4), ("st_mtime_ns", 13), ("st_file_attributes", 2)):
            pathname = SimpleNamespace(lstat=lambda: facts())
            with self.subTest(field=field), patch.object(m.os, "fstat", return_value=facts(**{field: value})), self.assertRaises(m.Refused):
                m.snapshot_pair(pathname, SimpleNamespace(fileno=lambda: 99))

    def test_reparse_multilink_nonregular_and_oversize_refuse(self):
        for changes in ({"st_file_attributes": 0x400}, {"st_nlink": 2}, {"st_mode": stat.S_IFDIR | 0o700},
                        {"st_size": m.BOUND + 1}, {"st_ino": 0}):
            with self.subTest(changes=changes), self.assertRaises(m.Refused):
                m.file_facts(facts(**changes))

    def test_write_short_flush_and_fsync_failures_not_accepted(self):
        class Stream:
            def write(self, value): return len(value) - 1
            def flush(self): raise AssertionError("must not flush short write")
        with self.assertRaises(m.Refused):
            m.write_all(Stream(), b"fixture")
        stream = SimpleNamespace(write=lambda raw: len(raw), flush=lambda: None, fileno=lambda: 99)
        with patch.object(m.os, "fsync", side_effect=OSError("fixture")), self.assertRaises(OSError):
            m.write_all(stream, b"fixture")


class FixtureOperationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(m, "ROOT", self.root))
        self.stack.enter_context(patch.object(m, "__file__", str(self.root / ".cache/m1-runtime/m4-restore-public-results-v2.py")))
        # Ordinary temporary files with synthetic complete stat records. Force
        # distinct API ctimes without dropping any clock from its own rechecks.
        original_lstat, original_fstat = Path.lstat, os.fstat
        def convert(st, offset):
            keys = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            result = {key: getattr(st, key) for key in keys}
            result["st_ctime_ns"] += offset
            result["st_file_attributes"] = getattr(st, "st_file_attributes", 0)
            result["st_birthtime_ns"] = getattr(st, "st_birthtime_ns", 7)
            return SimpleNamespace(**result)
        self.stack.enter_context(patch.object(Path, "lstat", lambda path: convert(original_lstat(path), 0)))
        self.stack.enter_context(patch.object(m.os, "fstat", lambda fd: convert(original_fstat(fd), 1000)))
        self.write(m.OLD_HELPER, b"immutable old helper fixture")
        old_sha = m.digest((self.root / m.OLD_HELPER).read_bytes())
        self.stack.enter_context(patch.object(m, "OLD_HELPER_SHA", old_sha))
        failure = dict(schema_version=1, task="TASK-597", status="FAILED_BEFORE_REPORT_RESERVATION_NO_RETRY",
                       helper_sha256=old_sha, tool_exit=1, report_created=False, fixed_eight_targets_absent=True,
                       historical_missing_count=10, retry_performed=False, cause="UNCONFIRMED", actual_runtime_operations=0)
        failure_raw = json.dumps(failure).encode("ascii")
        self.write(m.OLD_FAILURE, failure_raw)
        self.stack.enter_context(patch.object(m, "OLD_FAILURE_SHA", m.digest(failure_raw)))
        rows, attempts = [], []
        self.payloads = {}
        for run_id, number, _, _ in m.ROWS:
            raw = json.dumps({"ok": False, "fixture": number}).encode("ascii")
            source = f"ai/reports/devops-m2-unlock-state-before-result-{number}.json"
            destination = f".cache/m1-runtime/mobile-emulator/{run_id}/result.json"
            self.write(source, raw); self.payloads[destination] = raw
            rows.append((run_id, number, m.digest(raw), len(raw)))
            attempts.append(dict(run=run_id, result=destination, result_sha256=m.digest(raw), exit=1))
        self.stack.enter_context(patch.object(m, "ROWS", tuple(rows)))
        history = json.dumps(dict(task="TASK-088", recorded_at_utc="2026-10-19T09:04:41.762615+00:00", attempts=attempts)).encode("ascii")
        self.write(m.HASH_SOURCE, history)
        self.stack.enter_context(patch.object(m, "HASH_SOURCE_SHA", m.digest(history)))
        self.stdout = io.StringIO()
        self.stack.enter_context(redirect_stdout(self.stdout))

    def write(self, relative, raw):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def run_fixture(self):
        return m.run()

    def report(self):
        return json.loads((self.root / m.REPORT).read_bytes())

    def test_eight_fixture_copies_keep_failed_bytes_and_two_absent(self):
        self.assertEqual(self.run_fixture(), 0)
        for destination, raw in self.payloads.items():
            self.assertEqual((self.root / destination).read_bytes(), raw)
        self.assertTrue(all(not (self.root / path).exists() for path in m.UNRESOLVED))
        report = self.report()
        self.assertEqual(report["files_copied"], 8)
        self.assertEqual(report["unresolved"], 2)
        self.assertTrue(report["source_handles_closed"])
        self.assertFalse(report["protected_os_qualification"])
        self.assertFalse((self.root / m.OLD_REPORT).exists())

    def test_equal_existing_result_refuses_before_report(self):
        destination, raw = next(iter(self.payloads.items()))
        self.write(destination, raw)
        self.assertEqual(self.run_fixture(), 1)
        self.assertFalse((self.root / m.REPORT).exists())
        self.assertEqual((self.root / destination).read_bytes(), raw)

    def test_last_source_corruption_prevents_all_copies_and_report(self):
        _, number, _, _ = m.ROWS[-1]
        self.write(f"ai/reports/devops-m2-unlock-state-before-result-{number}.json", b"corrupt")
        self.assertEqual(self.run_fixture(), 1)
        self.assertFalse((self.root / m.REPORT).exists())
        self.assertTrue(all(not (self.root / path).exists() for path in self.payloads))

    def test_old_helper_and_failed_metadata_checked_before_reservation(self):
        for path in (m.OLD_HELPER, m.OLD_FAILURE):
            original = (self.root / path).read_bytes()
            self.write(path, b"changed")
            self.assertEqual(self.run_fixture(), 1)
            self.assertFalse((self.root / m.REPORT).exists())
            self.write(path, original)

    def test_old_or_new_report_existing_is_not_adopted(self):
        for path in (m.OLD_REPORT, m.REPORT):
            self.write(path, b"immutable fixture report")
            self.assertEqual(self.run_fixture(), 1)
            self.assertEqual((self.root / path).read_bytes(), b"immutable fixture report")
            # Fresh temp fixture cleanup only, never a runtime/helper deletion.
            (self.root / path).unlink()

    def test_destination_creation_race_retains_competing_file(self):
        actual_copy = m.copy_one
        def raced(source, destination, guards, expected):
            destination.write_bytes(b"competing fixture")
            return actual_copy(source, destination, guards, expected)
        with patch.object(m, "copy_one", raced):
            self.assertEqual(self.run_fixture(), 1)
        first = next(iter(self.payloads))
        self.assertEqual((self.root / first).read_bytes(), b"competing fixture")
        self.assertEqual(self.report()["status"], "FAILED_PARTIAL_ARTIFACTS_RETAINED_NO_RETRY")

    def test_partial_copy_retained_and_report_failure_persisted(self):
        actual_copy = m.copy_one
        count = 0
        def interrupted(source, destination, guards, expected):
            nonlocal count
            count += 1
            if count == 2:
                destination.write_bytes(b"partial fixture")
                raise OSError("untrusted exception token never emitted")
            return actual_copy(source, destination, guards, expected)
        with patch.object(m, "copy_one", interrupted):
            self.assertEqual(self.run_fixture(), 1)
        paths = list(self.payloads)
        self.assertEqual((self.root / paths[0]).read_bytes(), self.payloads[paths[0]])
        self.assertEqual((self.root / paths[1]).read_bytes(), b"partial fixture")
        report = self.report()
        self.assertEqual(report["files_copied"], 1)
        self.assertEqual(report["status"], "FAILED_PARTIAL_ARTIFACTS_RETAINED_NO_RETRY")
        self.assertNotIn("untrusted", json.dumps(report) + self.stdout.getvalue())

    def test_consumed_v2_report_refuses_second_fixture_operation(self):
        self.assertEqual(self.run_fixture(), 0)
        before = (self.root / m.REPORT).read_bytes()
        self.assertEqual(self.run_fixture(), 1)
        self.assertEqual((self.root / m.REPORT).read_bytes(), before)

    def test_late_destination_mutation_caught_by_final_rehash(self):
        actual_copy = m.copy_one
        count = 0
        def changed(source, destination, guards, expected):
            nonlocal count
            result = actual_copy(source, destination, guards, expected)
            count += 1
            if count == 8:
                (self.root / next(iter(self.payloads))).write_bytes(b"changed after earlier copy")
            return result
        with patch.object(m, "copy_one", changed):
            self.assertEqual(self.run_fixture(), 1)
        self.assertEqual(self.report()["status"], "FAILED_PARTIAL_ARTIFACTS_RETAINED_NO_RETRY")

    def test_report_fsync_failure_retains_consumed_partial_report(self):
        with patch.object(m.os, "fsync", side_effect=OSError("fixture fsync failure")):
            self.assertEqual(self.run_fixture(), 1)
        self.assertTrue((self.root / m.REPORT).exists())
        self.assertTrue(all(not (self.root / path).exists() for path in self.payloads))
        self.assertEqual(self.stdout.getvalue().strip(), "PUBLIC_RESULT_RESTORATION_FAILED_NO_RETRY")

    def test_source_mutation_after_capture_refuses_and_closes_original(self):
        relative = "ai/reports/devops-m2-unlock-state-before-result-1.json"
        raw = (self.root / relative).read_bytes()
        held = m.HeldSource(m.Guards(), relative, m.digest(raw))
        try:
            self.write(relative, b"changed held source")
            with self.assertRaises(m.Refused):
                held.recheck()
        finally:
            held.close(); held.close()
        self.assertTrue(held.stream.closed)

    def test_cli_refuses_original_flag_without_run(self):
        with patch.object(m.sys, "argv", [str(HELPER), "--restore-eight-public-failures"]), patch.object(m, "run", side_effect=AssertionError("must not run")):
            self.assertEqual(m.main(), 1)


if __name__ == "__main__":
    unittest.main()
