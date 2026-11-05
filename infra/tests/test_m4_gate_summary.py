"""Synthetic C16 aggregation faults; no execution or collector invocation."""
from copy import deepcopy
import json
import unittest

from infra.m4_gate_summary import CHECK_KINDS, REQUIRED_CHECKS, InvalidEvidence, summarize_required, summarize_health


SOURCE = "a" * 64


def record(name="tools-unit", **updates):
    result = {"id": name, "mode": "ACTUAL", "status": "PASSED", "exit_code": 0,
              "counts": {"total": 5, "passed": 5, "failed": 0, "errors": 0, "skipped": 0},
              "observed_at": 100, "source_sha256": SOURCE}
    if CHECK_KINDS[name] == "COMMAND":
        result["counts"] = None
    result.update(updates)
    return result


def summarize(records, **updates):
    args = {"evaluated_at": 120, "expected_source_sha256": SOURCE, "max_age_seconds": 30}
    args.update(updates)
    return summarize_required(records, **args)


def health():
    return {"schema_version": 1, "completeness": "COMPLETE", "status": "AGGREGATE_ONLY",
            "job_status_counts": {"PENDING": 0, "PROCESSING": 0, "DONE": 4, "FAILED": 0},
            "unknown_status_count": 0, "expired_lease_count": 0, "missing_lease_count": 0,
            "oldest_pending_age_seconds": None, "pending_creation_age_status": "NO_PENDING",
            "oldest_pending_available_age_seconds": None, "available_age_basis": "AVAILABLE_AT_NOT_CREATION_TIME",
            "poison_code_counts": {"RULE_PROCESSING_FAILED": 0, "ATTEMPTS_EXHAUSTED": 0, "STALE_CONTEXT": 0},
            "unclassified_failure_count": 0}


def summarize_job(payload, **updates):
    args = {"observed_at": 100, "evaluated_at": 120, "max_age_seconds": 30, "mode": "ACTUAL"}
    args.update(updates)
    return summarize_health(payload, **args)


class RequiredCheckTests(unittest.TestCase):
    def state(self, item, **updates):
        return summarize([item], **updates)["checks"][0]["state"]

    def test_complete_claimed_checks_leave_human_authority_closed(self):
        result = summarize([record(name) for name in REQUIRED_CHECKS])
        self.assertEqual(result["status"], "CHECK_EVIDENCE_COMPLETE")
        self.assertEqual(result["authority"], "NONE")
        self.assertEqual(result["m4_acceptance"], "NOT_GRANTED")
        self.assertEqual(result["native_execution"], "NOT_GRANTED")
        self.assertEqual(result["checks"][-1]["state"], "HUMAN_REVIEW_REQUIRED")
        self.assertEqual(result["checks"][-2]["state"], "REVIEW_UNADMITTED")
        self.assertEqual(result["provenance"], "UNAUTHENTICATED_CALLER_METADATA")

    def test_missing_required_ids_cannot_be_omitted(self):
        result = summarize([])
        self.assertEqual(len(result["checks"]), 26)
        self.assertTrue(all(item["state"] == "MISSING" for item in result["checks"]))
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_one_missing_test_blocks_other_successful_checks(self):
        records = [record(name) for name in REQUIRED_CHECKS if name != "isolated-postgresql"]
        self.assertEqual(summarize(records)["status"], "INCOMPLETE")

    def test_nonzero_exit_overrides_claimed_success_and_model(self):
        result = summarize([record(mode="MODEL", exit_code=1)])
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["checks"][0]["state"], "FAILED")

    def test_reported_failure_and_timeout_stay_failed(self):
        for status in ("FAILED", "TIMEOUT"):
            with self.subTest(status=status):
                self.assertEqual(self.state(record(status=status)), "FAILED")

    def test_unavailable_and_notrun_are_not_hidden(self):
        for status in ("UNAVAILABLE", "NOT_RUN"):
            with self.subTest(status=status):
                self.assertEqual(self.state(record(status=status, counts=None, exit_code=None)), status)

    def test_all_skips_never_pass(self):
        counts = {"total": 9, "passed": 0, "failed": 0, "errors": 0, "skipped": 9}
        self.assertEqual(self.state(record(counts=counts)), "SKIPPED_REQUIRED")

    def test_partial_skips_never_pass(self):
        counts = {"total": 9, "passed": 8, "failed": 0, "errors": 0, "skipped": 1}
        self.assertEqual(self.state(record(counts=counts)), "SKIPPED_REQUIRED")

    def test_zero_tests_and_unknown_counts_exit_are_distinct(self):
        counts = dict.fromkeys(("total", "passed", "failed", "errors", "skipped"), 0)
        self.assertEqual(self.state(record(counts=counts)), "NO_EXECUTED_TESTS")
        self.assertEqual(self.state(record(counts=None)), "UNKNOWN_COUNTS")
        self.assertEqual(self.state(record(exit_code=None)), "UNKNOWN_EXIT")

    def test_failures_and_errors_override_zero_exit(self):
        for key in ("failed", "errors"):
            counts = {"total": 5, "passed": 4, "failed": 0, "errors": 0, "skipped": 0}
            counts[key] = 1
            with self.subTest(key=key):
                self.assertEqual(self.state(record(counts=counts)), "FAILED")

    def test_model_never_becomes_actual(self):
        self.assertEqual(self.state(record(mode="MODEL")), "MODEL_ONLY")

    def test_freshness_boundaries_future_and_source_change(self):
        self.assertEqual(self.state(record(observed_at=90)), "REPORTED_TEST_PASS")
        self.assertEqual(self.state(record(observed_at=89)), "STALE")
        self.assertEqual(self.state(record(observed_at=121)), "FUTURE")
        self.assertEqual(self.state(record(source_sha256="b" * 64)), "SOURCE_MISMATCH")

    def test_commands_require_no_invented_counts(self):
        result = summarize([record("web-build")])
        item = next(item for item in result["checks"] if item["id"] == "web-build")
        self.assertEqual(item["state"], "REPORTED_COMMAND_COMPLETION")
        with self.assertRaisesRegex(InvalidEvidence, "^INVALID_EVIDENCE$"):
            summarize([record("web-build", counts=record()["counts"])])

    def test_required_boolean_unknown_label_and_duplicate_rejected(self):
        bad = record(); bad["required"] = False
        for records in ([bad], [record(id="private/canary-token")], [record(), record()]):
            with self.subTest(records=records), self.assertRaisesRegex(InvalidEvidence, "^INVALID_EVIDENCE$"):
                summarize(records)

    def test_malformed_counts_cannot_hide_failure(self):
        for counts in ({"total": 0}, {"total": 6, "passed": 5, "failed": 0, "errors": 0, "skipped": 0},
                       {"total": True, "passed": 1, "failed": 0, "errors": 0, "skipped": 0},
                       {"total": -1, "passed": -1, "failed": 0, "errors": 0, "skipped": 0}):
            with self.subTest(counts=counts), self.assertRaises(InvalidEvidence):
                summarize([record(counts=counts)])

    def test_metadata_types_and_bounds(self):
        for mutation in ({"mode": "actual"}, {"exit_code": False}, {"observed_at": True},
                         {"source_sha256": "A" * 64}, {"status": "canary"}):
            with self.subTest(mutation=mutation), self.assertRaises(InvalidEvidence):
                summarize([record(**mutation)])
        for mutation in ({"max_age_seconds": 0}, {"max_age_seconds": True}, {"max_age_seconds": 31_536_001},
                         {"evaluated_at": -1}, {"expected_source_sha256": "canary"}):
            with self.subTest(mutation=mutation), self.assertRaises(InvalidEvidence):
                summarize([], **mutation)

    def test_output_does_not_echo_hashes_or_mutate_input(self):
        records = [record()]; saved = deepcopy(records)
        result = summarize(records)
        self.assertEqual(records, saved)
        self.assertNotIn(SOURCE, json.dumps(result))
        result["checks"][0]["counts"]["passed"] = 9
        self.assertEqual(records, saved)


class HealthSummaryTests(unittest.TestCase):
    def test_zero_jobs_is_observation_not_liveness_or_sla(self):
        item = health(); item["job_status_counts"]["DONE"] = 0
        result = summarize_job(item)
        self.assertEqual(result["status"], "AGGREGATE_OBSERVED")
        self.assertEqual(result["worker_liveness"], "UNVERIFIED")
        self.assertEqual(result["latency_sla"], "UNVERIFIED")
        self.assertEqual(result["authority"], "NONE")

    def test_pending_creation_age_unavailable_not_available_at(self):
        item = health(); item["job_status_counts"]["PENDING"] = 3
        item.update(completeness="PARTIAL", pending_creation_age_status="CREATION_TIME_UNAVAILABLE",
                    oldest_pending_available_age_seconds=86400)
        result = summarize_job(item)
        self.assertIsNone(result["oldest_pending_age_seconds"])
        self.assertEqual(result["oldest_pending_available_age_seconds"], 86400)
        self.assertEqual(result["status"], "ATTENTION_REQUIRED")
        item["oldest_pending_age_seconds"] = 86400
        with self.assertRaises(InvalidEvidence):
            summarize_job(item)

    def test_expired_and_missing_leases_bounded_by_processing(self):
        item = health(); item["job_status_counts"]["PROCESSING"] = 2
        item.update(expired_lease_count=1, missing_lease_count=1, completeness="PARTIAL")
        self.assertIn("EXPIRED_LEASE", summarize_job(item)["issues"])
        item["missing_lease_count"] = 2
        with self.assertRaises(InvalidEvidence):
            summarize_job(item)

    def test_failed_classification_reconciles_exactly(self):
        item = health(); item["job_status_counts"]["FAILED"] = 3
        item["poison_code_counts"]["STALE_CONTEXT"] = 2
        item.update(unclassified_failure_count=1, completeness="PARTIAL")
        self.assertIn("FAILED_JOBS", summarize_job(item)["issues"])
        item["unclassified_failure_count"] = 0
        with self.assertRaises(InvalidEvidence):
            summarize_job(item)

    def test_unknown_status_never_disappears(self):
        item = health(); item.update(unknown_status_count=1, completeness="PARTIAL")
        self.assertIn("UNKNOWN_JOB_STATUS", summarize_job(item)["issues"])
        item["job_status_counts"]["CANARY_PRIVATE_LABEL"] = 1
        with self.assertRaises(InvalidEvidence):
            summarize_job(item)

    def test_complete_claim_cannot_hide_partial(self):
        item = health(); item["missing_lease_count"] = 1
        item["job_status_counts"]["PROCESSING"] = 1
        with self.assertRaises(InvalidEvidence):
            summarize_job(item)

    def test_schema_unavailable_explicit_not_empty_healthy(self):
        item = {"schema_version": 1, "completeness": "PARTIAL", "status": "SCHEMA_UNAVAILABLE"}
        self.assertEqual(summarize_job(item)["status"], "UNAVAILABLE")
        item["completeness"] = "COMPLETE"
        with self.assertRaises(InvalidEvidence):
            summarize_job(item)

    def test_model_stale_future_not_health_pass(self):
        self.assertEqual(summarize_job(health(), mode="MODEL")["status"], "MODEL_ONLY")
        self.assertEqual(summarize_job(health(), observed_at=89)["status"], "STALE")
        self.assertEqual(summarize_job(health(), observed_at=121)["status"], "FUTURE")

    def test_lease_and_age_bad_types_rejected(self):
        for key, value in (("expired_lease_count", True), ("missing_lease_count", -1),
                           ("unknown_status_count", 1.0), ("schema_version", True),
                           ("oldest_pending_available_age_seconds", 0)):
            item = health(); item[key] = value
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                summarize_job(item)

    def test_private_extra_fields_rejected_with_fixed_error(self):
        item = health(); item["raw_token_canary"] = "private/path/password"
        with self.assertRaises(InvalidEvidence) as caught:
            summarize_job(item)
        self.assertEqual(str(caught.exception), "INVALID_EVIDENCE")
        self.assertIsNone(caught.exception.__context__)

    def test_health_output_copies_counts(self):
        item = health(); original = deepcopy(item)
        result = summarize_job(item)
        result["job_status_counts"]["DONE"] = 100
        self.assertEqual(item, original)


if __name__ == "__main__":
    unittest.main()
