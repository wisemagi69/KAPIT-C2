"""Fixed-input synthetic detector evaluation; no model, database or live hook."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).absolute().parents[1]
CORPUS = Path("contracts/fixtures/sanitization/m4-corpus.json")
MANIFEST = Path("contracts/fixtures/sanitization/m4-split-manifest.json")
MAX_CORPUS_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_NODES = 20000
ERRORS = frozenset({"DETECTOR_EVALUATION_INVALID_INPUT", "DETECTOR_EVALUATION_UNAVAILABLE"})


class EvaluationError(ValueError):
    def __init__(self, code="DETECTOR_EVALUATION_INVALID_INPUT"):
        super().__init__(code if code in ERRORS else "DETECTOR_EVALUATION_UNAVAILABLE")


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _checked(path):
    root = ROOT.absolute()
    path = path.absolute()
    try:
        path.relative_to(root)
        for component in (*reversed(path.parents), path):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE")
            if component != path and not stat.S_ISDIR(info.st_mode):
                raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE")
        if not path.resolve().is_relative_to(root.resolve()) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE")
        return info
    except (OSError, ValueError):
        raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE") from None


def _read(relative, limit):
    # Only callers in this module select the two fixed relative paths.
    path = ROOT / relative
    before = _checked(path)
    if before.st_size > limit:
        raise EvaluationError()
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _identity(opened) != _identity(before):
                raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE")
            raw = stream.read(limit + 1)
            if _identity(os.fstat(stream.fileno())) != _identity(opened):
                raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE")
        if _identity(_checked(path)) != _identity(opened):
            raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE")
    except OSError:
        raise EvaluationError("DETECTOR_EVALUATION_UNAVAILABLE") from None
    if len(raw) > limit:
        raise EvaluationError()
    return parse_json(raw, limit)


def parse_json(raw, limit):
    if type(raw) is not bytes or len(raw) > limit:
        raise EvaluationError()
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise EvaluationError()
            value[key] = item
        return value
    def nonfinite(_):
        raise EvaluationError()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
        pending, nodes = [(value, 1)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if nodes > MAX_NODES or depth > MAX_DEPTH:
                raise EvaluationError()
            if type(item) is float and not math.isfinite(item):
                raise EvaluationError()
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
                nodes += len(item)  # Keys also consume the tree budget.
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
        if type(value) is not dict:
            raise EvaluationError()
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise EvaluationError() from None


def run():
    corpus = _read(CORPUS, MAX_CORPUS_BYTES)
    manifest = _read(MANIFEST, MAX_MANIFEST_BYTES)
    # The selected module imports only standard-library helpers. No runtime
    # settings, adapter lookup, installed-model probe or configuration is used.
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from backend.apps.sanitization.detector import detect
    from backend.apps.sanitization.evaluation import evaluate, validate_split_manifest
    try:
        validate_split_manifest(corpus, manifest)
        if len(corpus["cases"]) != 300 or {name: len(ids) for name, ids in manifest["splits"].items()} != {"development": 150, "calibration": 75, "evaluation": 75}:
            raise EvaluationError()
        cases = [case for case in corpus["cases"] if case["split"] == "evaluation"]
        observations = {case["id"]: detect(case["text"], case["language"], adapter=None, manifest=None) for case in cases}
        result = evaluate(corpus, manifest, observations)
        outcomes = result["outcomes"]
        counts = result["failure_codes"]
        if outcomes != {"READY_FOR_HUMAN_REVIEW": 0, "MANUAL_REQUIRED": 75, "FAILED_PRIVATE": 0} or set(counts) - {"DETECTOR_UNAVAILABLE", "UNSUPPORTED_LANGUAGE"} or any(type(number) is not int or not 0 <= number <= 75 for number in counts.values()) or sum(counts.values()) != 75:
            raise EvaluationError()
        metrics = result["metrics_completed_cases_only"]
        expected = {"true_positive": 0, "false_positive": 0, "false_negative": 0, "precision": None, "recall": None}
        if metrics != expected:
            raise EvaluationError()
        # Fresh fixed-key output deliberately excludes case IDs, fingerprints,
        # engine metadata, source strings, spans, scores and exception text.
        return {"schema_version": 1, "mode": "LOCAL_SYNTHETIC_EVALUATION", "split": "evaluation",
                "corpus_status": "GENERATED_PREPARATION_NOT_INDEPENDENTLY_REVIEWED", "case_count": 75,
                "adapter_status": "UNAVAILABLE", "outcomes": dict(outcomes), "failure_codes": dict(sorted(counts.items())),
                "metrics_completed_cases_only": dict(expected), "model_quality": "NOT_INDEPENDENTLY_EVALUATED",
                "review_burden": "NOT_MEASURED", "publication_authority": "NONE"}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise EvaluationError() from None


def main(argv=None):
    try:
        if (sys.argv[1:] if argv is None else argv):
            raise EvaluationError()
        result = run()
    except EvaluationError as error:
        print(json.dumps({"ok": False, "code": str(error)}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"ok": False, "code": "DETECTOR_EVALUATION_UNAVAILABLE"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
