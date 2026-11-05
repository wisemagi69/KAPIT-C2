"""Pure fixed-input runner tests; no browser, Django, model or database."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infra import detector_evaluation as runner


class DetectorEvaluationTests(unittest.TestCase):
    def test_actual_generated_evaluation_is_all_manual_without_quality_claims(self):
        with patch("subprocess.Popen", side_effect=AssertionError("NO_CHILD")), patch("socket.socket", side_effect=AssertionError("NO_NETWORK")):
            result = runner.run()
        self.assertEqual(result["case_count"], 75)
        self.assertEqual(result["outcomes"], {"READY_FOR_HUMAN_REVIEW": 0, "MANUAL_REQUIRED": 75, "FAILED_PRIVATE": 0})
        self.assertEqual(result["failure_codes"], {"DETECTOR_UNAVAILABLE": 57, "UNSUPPORTED_LANGUAGE": 18})
        self.assertIsNone(result["metrics_completed_cases_only"]["precision"])
        self.assertIsNone(result["metrics_completed_cases_only"]["recall"])
        self.assertEqual(result["publication_authority"], "NONE")
        self.assertEqual(result["model_quality"], "NOT_INDEPENDENTLY_EVALUATED")

    def test_aggregate_has_no_case_ids_fingerprint_text_or_spans(self):
        result = runner.run()
        text = json.dumps(result)
        self.assertEqual(set(result), {"schema_version", "mode", "split", "corpus_status", "case_count", "adapter_status", "outcomes", "failure_codes", "metrics_completed_cases_only", "model_quality", "review_burden", "publication_authority"})
        for prohibited in ("case-000", "noncompleted_case_ids", "corpus_sha256", '"text"', '"spans"', '"score"', '"start"', '"end"'):
            self.assertNotIn(prohibited, text)

    def test_duplicate_nonfinite_invalid_utf8_and_nonobject_json_are_fixed_errors(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}', b'\xff', b'[]', b'PRIVATE_INPUT_CANARY'):
            with self.subTest(raw_kind=type(raw).__name__), self.assertRaises(runner.EvaluationError) as caught:
                runner.parse_json(raw, 1000)
            self.assertEqual(str(caught.exception), "DETECTOR_EVALUATION_INVALID_INPUT")

    def test_json_bytes_depth_and_nodes_are_bounded(self):
        for raw, limit in ((b'{}', 1), (b'"bad"', 100), (b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}', 1000)):
            with self.assertRaises(runner.EvaluationError):
                runner.parse_json(raw, limit)
        with patch.object(runner, "MAX_NODES", 3):
            with self.assertRaises(runner.EvaluationError):
                runner.parse_json(b'{"x":[1,2,3]}', 100)
        self.assertEqual(runner.parse_json(b'{}', 2), {})

    def test_missing_path_and_directory_refuse_without_raw_path(self):
        with TemporaryDirectory() as directory, patch.object(runner, "ROOT", Path(directory)):
            for target in (Path(directory) / "PRIVATE_PATH_CANARY.json", Path(directory)):
                with self.assertRaises(runner.EvaluationError) as caught:
                    runner._checked(target)
                self.assertEqual(str(caught.exception), "DETECTOR_EVALUATION_UNAVAILABLE")

    def test_escaping_regular_file_refuses(self):
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            root = Path(directory)
            source = Path(outside) / "outside.json"
            source.write_bytes(b'{}')
            with patch.object(runner, "ROOT", root):
                with self.assertRaises(runner.EvaluationError):
                    runner._checked(source)

    def test_hardlink_alias_refuses_when_host_supports_it(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_bytes(b'{}')
            try:
                os.link(source, root / "hard.json")
            except OSError:
                self.skipTest("HARDLINK_UNAVAILABLE")
            with patch.object(runner, "ROOT", root), self.assertRaises(runner.EvaluationError):
                runner._checked(root / "hard.json")

    def test_symlink_alias_refuses_when_host_supports_it(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_bytes(b'{}')
            try:
                (root / "link.json").symlink_to(source)
            except OSError:
                self.skipTest("SYMLINK_UNAVAILABLE")
            with patch.object(runner, "ROOT", root), self.assertRaises(runner.EvaluationError):
                runner._checked(root / "link.json")

    def test_windows_reparse_component_refuses_before_open(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "proposal.json"
            candidate.write_bytes(b'{}')
            original = Path.lstat
            def redirected(path):
                info = original(path)
                if path == root:
                    return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
                return info
            with patch.object(runner, "ROOT", root), patch.object(Path, "lstat", redirected), patch.object(Path, "open") as opened:
                with self.assertRaises(runner.EvaluationError):
                    runner._read(Path("proposal.json"), 100)
                opened.assert_not_called()

    def test_oversized_file_refuses_before_open_and_read_is_bounded(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "large.json"
            path.write_bytes(b' ' * 101)
            with patch.object(runner, "ROOT", root), patch.object(Path, "open") as opened:
                with self.assertRaises(runner.EvaluationError):
                    runner._read(Path("large.json"), 100)
                opened.assert_not_called()

    def test_file_identity_change_after_open_refuses(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "draft.json"
            path.write_bytes(b'{}')
            info = path.stat()
            changed = SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1, st_size=info.st_size, st_mtime_ns=info.st_mtime_ns)
            with patch.object(runner, "ROOT", root), patch.object(runner, "_checked", side_effect=[info, changed]):
                with self.assertRaises(runner.EvaluationError) as caught:
                    runner._read(Path("draft.json"), 100)
                self.assertEqual(str(caught.exception), "DETECTOR_EVALUATION_UNAVAILABLE")

    def test_split_fingerprint_tampering_and_unknown_corpus_fields_fail(self):
        corpus = runner._read(runner.CORPUS, runner.MAX_CORPUS_BYTES)
        manifest = runner._read(runner.MANIFEST, runner.MAX_MANIFEST_BYTES)
        for altered_corpus, altered_manifest in (({**corpus, "PRIVATE_INPUT_CANARY": True}, manifest), (corpus, {**manifest, "corpus_sha256": "0" * 64})):
            with patch.object(runner, "_read", side_effect=[altered_corpus, altered_manifest]):
                with self.assertRaises(runner.EvaluationError) as caught:
                    runner.run()
                self.assertEqual(str(caught.exception), "DETECTOR_EVALUATION_INVALID_INPUT")

    def test_no_adapter_is_explicit_and_accidental_completed_success_is_refused(self):
        from backend.apps.sanitization import detector
        real = detector.detect
        calls = []
        def observe(text, language, **kwargs):
            calls.append(kwargs)
            return real(text, language, **kwargs)
        with patch.object(detector, "detect", observe):
            runner.run()
        self.assertEqual(calls, [{"adapter": None, "manifest": None}] * 75)
        forged = {"outcome": "READY_FOR_HUMAN_REVIEW", "code": "DETECTOR_COMPLETED", "manifest": {"engine": "fixture", "recognizer_version": "1", "model_version": "1"}, "spans": []}
        with patch.object(detector, "detect", return_value=forged):
            with self.assertRaises(runner.EvaluationError):
                runner.run()

    def test_cli_rejects_arguments_and_never_echoes_exceptions(self):
        for arguments, failure in ((["PRIVATE_ARGUMENT_CANARY"], None), ([], OSError("PRIVATE_EXCEPTION_CANARY")), ([], runner.EvaluationError("PRIVATE_ERROR_CANARY"))):
            output = io.StringIO()
            with patch.object(runner, "run", side_effect=failure) as execute, redirect_stdout(output):
                self.assertEqual(runner.main(arguments), 1)
            if arguments:
                execute.assert_not_called()
            parsed = json.loads(output.getvalue())
            self.assertEqual(set(parsed), {"ok", "code"})
            self.assertFalse(parsed["ok"])
            self.assertIn(parsed["code"], runner.ERRORS)
            self.assertNotIn("PRIVATE", output.getvalue())


if __name__ == "__main__":
    unittest.main()
