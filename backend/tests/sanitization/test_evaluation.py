import copy
import json
from pathlib import Path
import unittest

try:
    from apps.sanitization.detector import detect, MAX_SPANS, MAX_TEXT_BYTES
    from apps.sanitization.evaluation import evaluate, fingerprint, validate_corpus, validate_split_manifest
except ModuleNotFoundError:
    from backend.apps.sanitization.detector import detect, MAX_SPANS, MAX_TEXT_BYTES
    from backend.apps.sanitization.evaluation import evaluate, fingerprint, validate_corpus, validate_split_manifest

ROOT = Path(__file__).resolve().parents[3]
ENGINE = {"engine": "synthetic-test-double-v1", "recognizer_version": "1.0.0", "model_version": "fixture-1"}


def corpus_fixture():
    return {"schema_version": 1, "status": "GENERATED_PREPARATION_NOT_INDEPENDENTLY_REVIEWED", "cases": [
        {"id": "case-a", "family": "family-a", "split": "evaluation", "language": "en", "group": "english",
         "text": "Alice at SiteA", "spans": [{"entity": "PERSON", "start": 0, "end": 5}, {"entity": "LOCATION", "start": 9, "end": 14}]}]}


def manifest_for(corpus):
    return {"schema_version": 1, "corpus_sha256": fingerprint(corpus), "splits": {
        split: sorted(case["id"] for case in corpus["cases"] if case["split"] == split)
        for split in ("development", "calibration", "evaluation")}}


class DetectorTests(unittest.TestCase):
    def test_absent_adapter_is_manual_not_empty_success(self):
        result = detect("A synthetic report")
        self.assertEqual((result["outcome"], result["code"]), ("MANUAL_REQUIRED", "DETECTOR_UNAVAILABLE"))

    def test_unknown_language_does_not_call_adapter(self):
        def forbidden(*args):
            self.fail("Unsupported language invoked adapter")
        for language in ("mixed", "other", "unknown", None):
            self.assertEqual(detect("Synthetic", language, adapter=forbidden)["code"], "UNSUPPORTED_LANGUAGE")

    def test_bounded_source(self):
        for text in (None, {}, "", "x" * (MAX_TEXT_BYTES + 1), "é" * MAX_TEXT_BYTES, "\ud800"):
            with self.subTest(text_type=type(text).__name__):
                self.assertEqual(detect(text)["code"], "INVALID_INPUT")
        self.assertEqual(detect("x" * MAX_TEXT_BYTES)["code"], "DETECTOR_UNAVAILABLE")

    def test_exception_text_is_discarded(self):
        def broken(*args):
            raise RuntimeError("PRIVATE-CANARY-TOKEN")
        result = detect("PRIVATE-SOURCE", adapter=broken, manifest=ENGINE)
        self.assertEqual(result["code"], "DETECTOR_ERROR")
        self.assertNotIn("PRIVATE", json.dumps(result).replace("FAILED_PRIVATE", ""))

    def test_malformed_spans_fail_private(self):
        valid = {"entity": "PERSON", "start": 0, "end": 2, "score": None}
        malformed = [None, {}, [valid] * (MAX_SPANS + 1), [valid, valid],
                     [{**valid, "start": -1}], [{**valid, "start": 2, "end": 1}],
                     [{**valid, "end": 100}], [{**valid, "start": True}],
                     [{**valid, "entity": "UNKNOWN"}], [{**valid, "entity": []}],
                     [{**valid, "matched_text": "PRIVATE"}], [{**valid, "score": float("nan")}],
                     [{**valid, "score": float("inf")}], [{**valid, "score": True}], [{**valid, "score": -0.1}]]
        for spans in malformed:
            with self.subTest(spans=spans):
                result = detect("Example", adapter=lambda *_: spans, manifest=ENGINE)
                self.assertEqual(result["code"], "INVALID_RESULT")
                self.assertEqual(result["spans"], [])

    def test_manifest_is_required_and_bounded(self):
        for manifest in (None, {}, {**ENGINE, "model_version": "latest"}, {**ENGINE, "engine": "unknown"},
                         {**ENGINE, "model_version": "x" * 81}, {**ENGINE, "source": "private"}):
            with self.subTest(manifest=manifest):
                self.assertEqual(detect("Example", adapter=lambda *_: [], manifest=manifest)["code"], "INVALID_RESULT")

    def test_unicode_offsets_nullable_scores_and_overlap(self):
        spans = [{"entity": "PERSON", "start": 0, "end": 1, "score": None},
                 {"entity": "LOCATION", "start": 0, "end": 2, "score": 0.9}]
        result = detect("éx", adapter=lambda *_: spans, manifest=ENGINE)
        self.assertEqual(result["outcome"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(result["spans"], spans)
        self.assertNotIn("approved", result)


class EvaluationTests(unittest.TestCase):
    def evaluate_one(self, result, corpus=None, **kwargs):
        corpus = corpus or corpus_fixture()
        return evaluate(corpus, manifest_for(corpus), {"case-a": result}, **kwargs)

    def test_exact_matching_wrong_boundary_is_fp_and_fn(self):
        spans = [{"entity": "PERSON", "start": 0, "end": 5, "score": None},
                 {"entity": "LOCATION", "start": 9, "end": 13, "score": 1}]
        result = self.evaluate_one(detect("Alice at SiteA", adapter=lambda *_: spans, manifest=ENGINE))
        self.assertEqual(result["metrics_completed_cases_only"], {"true_positive": 1, "false_positive": 1,
                                                                 "false_negative": 1, "precision": 0.5, "recall": 0.5})

    def test_manual_and_failed_are_separate_from_metrics(self):
        for observation in (detect("Alice at SiteA"), detect("")):
            result = self.evaluate_one(observation)
            self.assertIsNone(result["metrics_completed_cases_only"]["recall"])
            self.assertEqual(result["noncompleted_case_ids"], ["case-a"])
            self.assertEqual(result["outcomes"]["READY_FOR_HUMAN_REVIEW"], 0)

    def test_successful_empty_predictions_count_misses(self):
        result = self.evaluate_one(detect("Alice at SiteA", adapter=lambda *_: [], manifest=ENGINE))
        self.assertEqual(result["metrics_completed_cases_only"]["false_negative"], 2)
        self.assertEqual(result["metrics_completed_cases_only"]["recall"], 0)
        self.assertIsNone(result["metrics_completed_cases_only"]["precision"])

    def test_no_gold_entities_has_null_recall(self):
        corpus = corpus_fixture()
        corpus["cases"][0]["spans"] = []
        result = self.evaluate_one(detect("Alice at SiteA", adapter=lambda *_: [], manifest=ENGINE), corpus)
        self.assertIsNone(result["metrics_completed_cases_only"]["recall"])

    def test_aggregate_leakage_report_has_only_ids_not_source(self):
        result = self.evaluate_one(detect("Alice at SiteA"), projected_text={"case-a": "SiteA is visible"})
        self.assertEqual(result["exact_text_leakage_probe"]["case_ids"], ["case-a"])
        self.assertNotIn("Alice", json.dumps(result))
        self.assertNotIn("SiteA", json.dumps(result))
        self.assertEqual(result["publication_authority"], "NONE")
        self.assertEqual(result["review_burden"], "NOT_MEASURED")

    def test_duplicate_ids_and_cross_split_family_or_text_rejected(self):
        for mutation, code in ((lambda c: None, "DUPLICATE_CASE_ID"),
                               (lambda c: c.update(id="case-b", split="development", text="Different"), "FAMILY_SPLIT_OVERLAP"),
                               (lambda c: c.update(id="case-b", family="family-b", split="development"), "TEXT_SPLIT_OVERLAP")):
            corpus = corpus_fixture()
            added = copy.deepcopy(corpus["cases"][0])
            mutation(added)
            corpus["cases"].append(added)
            with self.assertRaisesRegex(ValueError, code):
                validate_corpus(corpus)

    def test_unknown_schema_labels_and_bad_ids_rejected(self):
        mutations = [lambda c: c.update(schema_version=2), lambda c: c.update(schema_version=True),
                     lambda c: c["cases"][0].update(id="private text with spaces"),
                     lambda c: c["cases"][0].update(language="unknown"),
                     lambda c: c["cases"][0].update(split="test"),
                     lambda c: c["cases"][0]["spans"][0].update(entity="UNKNOWN"),
                     lambda c: c["cases"][0].update(text="x" * (MAX_TEXT_BYTES + 1))]
        for mutate in mutations:
            corpus = corpus_fixture()
            mutate(corpus)
            with self.assertRaises(ValueError):
                validate_corpus(corpus)

    def test_manifest_digest_and_membership_are_checked(self):
        corpus = corpus_fixture()
        manifest = manifest_for(corpus)
        manifest["corpus_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "INVALID_SPLIT_MANIFEST"):
            validate_split_manifest(corpus, manifest)
        manifest = manifest_for(corpus)
        manifest["splits"]["development"] = ["case-a"]
        with self.assertRaisesRegex(ValueError, "INVALID_SPLIT_MEMBERSHIP"):
            validate_split_manifest(corpus, manifest)

    def test_observations_must_cover_exact_selected_split(self):
        corpus = corpus_fixture()
        for observations in ({}, {"other-case": detect("Example")}):
            with self.assertRaisesRegex(ValueError, "OBSERVATION_IDS_MISMATCH"):
                evaluate(corpus, manifest_for(corpus), observations)

    def test_forged_success_unknown_outcomes_and_private_findings_rejected(self):
        result = detect("Example")
        for bad in ({**result, "outcome": "SAFE"}, {**result, "outcome": []},
                    {**result, "spans": [{"entity": "PERSON", "start": 0, "end": 1, "score": None}]},
                    {**result, "outcome": "READY_FOR_HUMAN_REVIEW", "code": "DETECTOR_COMPLETED"}):
            with self.assertRaises(ValueError):
                self.evaluate_one(bad)

    def test_unsupported_language_cannot_be_forged_completed(self):
        corpus = corpus_fixture()
        corpus["cases"][0]["language"] = "mixed"
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_LANGUAGE_COMPLETED"):
            self.evaluate_one(detect("Alice at SiteA", adapter=lambda *_: [], manifest=ENGINE), corpus)

    def test_generated_corpus_split_and_unavailable_run(self):
        corpus = json.loads((ROOT / "contracts/fixtures/sanitization/m4-corpus.json").read_text())
        manifest = json.loads((ROOT / "contracts/fixtures/sanitization/m4-split-manifest.json").read_text())
        validate_split_manifest(corpus, manifest)
        self.assertEqual(len(corpus["cases"]), 300)
        self.assertEqual({key: len(value) for key, value in manifest["splits"].items()},
                         {"development": 150, "calibration": 75, "evaluation": 75})
        self.assertEqual({group: sum(case["group"] == group for case in corpus["cases"])
                          for group in ("english", "mixed_other", "adversarial")},
                         {"english": 150, "mixed_other": 75, "adversarial": 75})
        observations = {case["id"]: detect(case["text"], case["language"])
                        for case in corpus["cases"] if case["split"] == "evaluation"}
        result = evaluate(corpus, manifest, observations)
        self.assertEqual(result["outcomes"]["MANUAL_REQUIRED"], 75)
        self.assertEqual(result["outcomes"]["READY_FOR_HUMAN_REVIEW"], 0)
        self.assertIsNone(result["metrics_completed_cases_only"]["recall"])


if __name__ == "__main__":
    unittest.main()
