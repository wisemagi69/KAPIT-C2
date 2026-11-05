"""Strict synthetic corpus evaluation. Aggregate artifacts exclude text and matched spans."""
import hashlib
import json
import re

from .detector import ENTITIES, validate_result, validate_spans, valid_text

MAX_CASES = 1000
SPLITS = frozenset({"development", "calibration", "evaluation"})
LANGUAGES = frozenset({"en", "mixed", "other"})
GROUPS = frozenset({"english", "mixed_other", "adversarial"})
SAFE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def validate_corpus(corpus):
    if (not isinstance(corpus, dict) or set(corpus) != {"schema_version", "status", "cases"}
            or type(corpus["schema_version"]) is not int or corpus["schema_version"] != 1
            or corpus["status"] != "GENERATED_PREPARATION_NOT_INDEPENDENTLY_REVIEWED"
            or not isinstance(corpus["cases"], list) or not 1 <= len(corpus["cases"]) <= MAX_CASES):
        raise ValueError("INVALID_CORPUS")
    seen, families, texts = set(), {}, {}
    for case in corpus["cases"]:
        if not isinstance(case, dict) or set(case) != {"id", "family", "split", "language", "group", "text", "spans"}:
            raise ValueError("INVALID_CASE")
        for key in ("id", "family"):
            if not isinstance(case[key], str) or not SAFE_ID.fullmatch(case[key]):
                raise ValueError("INVALID_CASE_ID")
        if (not isinstance(case["split"], str) or case["split"] not in SPLITS
                or not isinstance(case["language"], str) or case["language"] not in LANGUAGES
                or not isinstance(case["group"], str) or case["group"] not in GROUPS or not valid_text(case["text"])):
            raise ValueError("INVALID_CASE")
        if case["id"] in seen:
            raise ValueError("DUPLICATE_CASE_ID")
        seen.add(case["id"])
        previous = families.setdefault(case["family"], case["split"])
        if previous != case["split"]:
            raise ValueError("FAMILY_SPLIT_OVERLAP")
        previous = texts.setdefault(case["text"], case["split"])
        if previous != case["split"]:
            raise ValueError("TEXT_SPLIT_OVERLAP")
        validate_spans(case["spans"], len(case["text"]), scores=False)
    return corpus


def validate_split_manifest(corpus, manifest):
    validate_corpus(corpus)
    if (not isinstance(manifest, dict) or set(manifest) != {"schema_version", "corpus_sha256", "splits"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["corpus_sha256"] != fingerprint(corpus)
            or not isinstance(manifest["splits"], dict) or set(manifest["splits"]) != SPLITS):
        raise ValueError("INVALID_SPLIT_MANIFEST")
    for split in SPLITS:
        expected = sorted(case["id"] for case in corpus["cases"] if case["split"] == split)
        if manifest["splits"][split] != expected:
            raise ValueError("INVALID_SPLIT_MEMBERSHIP")
    return manifest


def _counts():
    return {"true_positive": 0, "false_positive": 0, "false_negative": 0}


def _metrics(counts):
    tp, fp, fn = (counts[key] for key in ("true_positive", "false_positive", "false_negative"))
    return {**counts, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def evaluate(corpus, manifest, observations, *, split="evaluation", projected_text=None):
    """Exact (entity,start,end) match; overlapping wrong boundaries count FP + FN.

    Metrics are only for completed detector cases. Manual/failed cases are reported
    separately and never treated as empty successful detections. Optional projected
    strings are synthetic test outputs only, checked for exact forbidden span text.
    This leakage probe is incomplete and never authorizes publication.
    """
    validate_split_manifest(corpus, manifest)
    if not isinstance(split, str) or split not in SPLITS or not isinstance(observations, dict):
        raise ValueError("INVALID_EVALUATION_INPUT")
    cases = [case for case in corpus["cases"] if case["split"] == split]
    expected_ids = {case["id"] for case in cases}
    if set(observations) != expected_ids:
        raise ValueError("OBSERVATION_IDS_MISMATCH")
    if projected_text is not None and (not isinstance(projected_text, dict) or set(projected_text) != expected_ids):
        raise ValueError("PROJECTION_IDS_MISMATCH")
    totals, by_entity, by_language = _counts(), {entity: _counts() for entity in sorted(ENTITIES)}, {}
    outcomes = {key: 0 for key in ("READY_FOR_HUMAN_REVIEW", "MANUAL_REQUIRED", "FAILED_PRIVATE")}
    codes, engine_manifests, noncompleted, leakage_ids = {}, {}, [], []
    for case in cases:
        result = validate_result(observations[case["id"]], len(case["text"]))
        outcomes[result["outcome"]] += 1
        codes[result["code"]] = codes.get(result["code"], 0) + 1
        if result["manifest"] is not None:
            engine_manifests[fingerprint(result["manifest"])] = result["manifest"]
        if result["outcome"] != "READY_FOR_HUMAN_REVIEW":
            noncompleted.append(case["id"])
        else:
            if case["language"] != "en":
                raise ValueError("UNSUPPORTED_LANGUAGE_COMPLETED")
            labels = {(item["entity"], item["start"], item["end"]) for item in case["spans"]}
            predictions = {(item["entity"], item["start"], item["end"]) for item in result["spans"]}
            language_counts = by_language.setdefault(case["language"], _counts())
            for key, entries in (("true_positive", labels & predictions), ("false_positive", predictions - labels),
                                 ("false_negative", labels - predictions)):
                totals[key] += len(entries)
                language_counts[key] += len(entries)
                for entity, _, _ in entries:
                    by_entity[entity][key] += 1
        if projected_text is not None:
            output = projected_text[case["id"]]
            if not valid_text(output):
                raise ValueError("INVALID_PROJECTED_TEXT")
            if any(case["text"][span["start"]:span["end"]] in output for span in case["spans"]):
                leakage_ids.append(case["id"])
    return {"schema_version": 1, "corpus_sha256": fingerprint(corpus), "split": split,
            "corpus_status": corpus["status"], "case_count": len(cases), "outcomes": outcomes,
            "failure_codes": codes, "metrics_completed_cases_only": _metrics(totals),
            "by_entity": {key: _metrics(value) for key, value in by_entity.items()},
            "by_language": {key: _metrics(value) for key, value in by_language.items()},
            "engine_manifests": list(engine_manifests.values()), "noncompleted_case_ids": sorted(noncompleted),
            "exact_text_leakage_probe": {"executed": projected_text is not None, "case_count": len(leakage_ids),
                                         "case_ids": sorted(leakage_ids)},
            "review_burden": "NOT_MEASURED", "model_quality": "NOT_INDEPENDENTLY_EVALUATED",
            "publication_authority": "NONE"}
