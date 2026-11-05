"""Independent C16 supplied-metadata faults; no runner or collector invocation."""
from copy import deepcopy
import json
import unittest
from infra import m4_gate_summary as summary


class GateSummaryIndependentQA(unittest.TestCase):
    def record(self,name="tools-unit",**changes):
        row=dict(id=name,mode="ACTUAL",status="PASSED",exit_code=0,counts=dict(total=3,passed=3,failed=0,errors=0,skipped=0),observed_at=950,source_sha256="b"*64)
        if summary.CHECK_KINDS[name]=="COMMAND":row["counts"]=None
        row.update(changes);return row

    def evaluate(self,rows,**changes):
        args=dict(evaluated_at=1000,expected_source_sha256="b"*64,max_age_seconds=50);args.update(changes)
        return summary.summarize_required(rows,**args)

    def state(self,row,**changes):return next(x for x in self.evaluate([row],**changes)["checks"] if x["id"]==row["id"])["state"]

    def test_complete_metadata_never_admits_review_or_human(self):
        rows=[self.record(name) for name in summary.REQUIRED_CHECKS]
        result=self.evaluate(rows)
        self.assertEqual(len(result["checks"]),26)
        self.assertEqual(result["status"],"CHECK_EVIDENCE_COMPLETE")
        self.assertEqual(result["authority"],"NONE")
        self.assertEqual(result["m4_acceptance"],"NOT_GRANTED")
        self.assertEqual(result["native_execution"],"NOT_GRANTED")
        states={x["id"]:x["state"] for x in result["checks"]}
        self.assertEqual(states["human-acceptance"],"HUMAN_REVIEW_REQUIRED")
        self.assertEqual(states["independent-security-review"],"REVIEW_UNADMITTED")

    def test_fixed_required_set_missing_checks_stay_visible(self):
        result=self.evaluate([])
        self.assertEqual(tuple(x["id"] for x in result["checks"]),summary.REQUIRED_CHECKS)
        self.assertTrue(all(x["state"]=="MISSING" for x in result["checks"]))
        self.assertEqual(result["status"],"INCOMPLETE")
        with self.assertRaises(TypeError):summary.CHECK_KINDS["tools-unit"]="COMMAND"

    def test_one_missing_required_test_blocks_complete(self):
        rows=[self.record(name) for name in summary.REQUIRED_CHECKS if name!="isolated-postgresql"]
        self.assertEqual(self.evaluate(rows)["status"],"INCOMPLETE")

    def test_zero_exit_failure_and_timeout_override_claimed_actual(self):
        for status in ("FAILED","TIMEOUT"):
            self.assertEqual(self.state(self.record(status=status)),"FAILED")
        self.assertEqual(self.state(self.record(mode="MODEL",exit_code=-1)),"FAILED")

    def test_failed_or_error_counts_override_pass(self):
        for field in ("failed","errors"):
            counts=dict(total=3,passed=2,failed=0,errors=0,skipped=0);counts[field]=1
            self.assertEqual(self.state(self.record(counts=counts)),"FAILED")

    def test_all_and_partial_skips_prevent_pass(self):
        for passed,skipped in ((0,3),(2,1)):
            row=self.record(counts=dict(total=3,passed=passed,failed=0,errors=0,skipped=skipped))
            self.assertEqual(self.state(row),"SKIPPED_REQUIRED")

    def test_unknown_and_zero_execution_are_distinct(self):
        self.assertEqual(self.state(self.record(counts=None)),"UNKNOWN_COUNTS")
        self.assertEqual(self.state(self.record(exit_code=None)),"UNKNOWN_EXIT")
        self.assertEqual(self.state(self.record(counts=dict(total=0,passed=0,failed=0,errors=0,skipped=0))),"NO_EXECUTED_TESTS")

    def test_declared_age_edges_future_source_and_model(self):
        for changes,expected in ((dict(observed_at=949),"STALE"),(dict(observed_at=1001),"FUTURE"),
            (dict(source_sha256="c"*64),"SOURCE_MISMATCH"),(dict(mode="MODEL"),"MODEL_ONLY")):
            self.assertEqual(self.state(self.record(**changes)),expected)
        self.assertEqual(self.state(self.record()),"REPORTED_TEST_PASS")

    def test_unavailable_and_notrun_never_admitted(self):
        for status in ("UNAVAILABLE","NOT_RUN"):
            self.assertEqual(self.state(self.record(status=status,counts=None,exit_code=None)),status)

    def test_command_only_completion_counts_forbidden(self):
        self.assertEqual(self.state(self.record("web-build")),"REPORTED_COMMAND_COMPLETION")
        with self.assertRaises(summary.InvalidEvidence):self.evaluate([self.record("web-build",counts=dict(total=3,passed=3,failed=0,errors=0,skipped=0))])

    def test_unknown_duplicate_and_unexpected_fields_refuse(self):
        row=self.record();row["required"]=False
        for rows in ([row],[dict(self.record(),id="synthetic-secret-canary")],[self.record(),self.record()]):
            with self.assertRaises(summary.InvalidEvidence) as caught:self.evaluate(rows)
            self.assertEqual(str(caught.exception),"INVALID_EVIDENCE")
            self.assertIsNone(caught.exception.__context__)

    def test_wrong_metadata_builtin_types_and_bounds_refuse(self):
        for changes in (dict(mode=True),dict(exit_code=False),dict(observed_at=950.0),dict(source_sha256="B"*64),dict(status="SAFE"),dict(exit_code=2**31)):
            with self.assertRaises(summary.InvalidEvidence):self.evaluate([self.record(**changes)])
        for changes in (dict(evaluated_at=True),dict(evaluated_at=2**53),dict(max_age_seconds=0),dict(max_age_seconds=31536001),dict(expected_source_sha256="canary")):
            with self.assertRaises(summary.InvalidEvidence):self.evaluate([],**changes)

    def test_inconsistent_counts_and_bool_values_refuse(self):
        for counts in (dict(total=1,passed=2,failed=0,errors=0,skipped=0),dict(total=True,passed=1,failed=0,errors=0,skipped=0),dict(total=-1,passed=-1,failed=0,errors=0,skipped=0),dict(total=1,passed=1)):
            with self.assertRaises(summary.InvalidEvidence):self.evaluate([self.record(counts=counts)])

    def test_input_immutability_and_output_copies(self):
        rows=[self.record()];original=deepcopy(rows);out=self.evaluate(rows)
        out["checks"][0]["counts"]["passed"]=999
        self.assertEqual(rows,original)
        self.assertNotIn("b"*64,json.dumps(out))

    def health(self):
        return dict(schema_version=1,completeness="COMPLETE",status="AGGREGATE_ONLY",job_status_counts=dict(PENDING=0,PROCESSING=0,DONE=2,FAILED=0),unknown_status_count=0,expired_lease_count=0,missing_lease_count=0,oldest_pending_age_seconds=None,pending_creation_age_status="NO_PENDING",oldest_pending_available_age_seconds=None,available_age_basis="AVAILABLE_AT_NOT_CREATION_TIME",poison_code_counts=dict(RULE_PROCESSING_FAILED=0,ATTEMPTS_EXHAUSTED=0,STALE_CONTEXT=0),unclassified_failure_count=0)

    def health_summary(self,payload,**changes):
        args=dict(observed_at=950,evaluated_at=1000,max_age_seconds=50,mode="ACTUAL");args.update(changes)
        return summary.summarize_health(payload,**args)

    def test_empty_health_is_observed_not_liveness_or_latency(self):
        payload=self.health();payload["job_status_counts"]["DONE"]=0
        out=self.health_summary(payload)
        self.assertEqual(out["status"],"AGGREGATE_OBSERVED")
        self.assertEqual(out["worker_liveness"],"UNVERIFIED")
        self.assertEqual(out["latency_sla"],"UNVERIFIED")
        self.assertEqual(out["authority"],"NONE")

    def test_pending_creation_age_never_inferred_from_retry_schedule(self):
        p=self.health();p["job_status_counts"]["PENDING"]=1;p.update(completeness="PARTIAL",pending_creation_age_status="CREATION_TIME_UNAVAILABLE",oldest_pending_available_age_seconds=86400)
        out=self.health_summary(p)
        self.assertIsNone(out["oldest_pending_age_seconds"])
        self.assertEqual(out["oldest_pending_available_age_seconds"],86400)
        self.assertIn("PENDING_CREATION_AGE_UNAVAILABLE",out["issues"])
        p["oldest_pending_age_seconds"]=86400
        with self.assertRaises(summary.InvalidEvidence):self.health_summary(p)

    def test_expired_and_missing_leases_disjoint_sum_bound(self):
        p=self.health();p["job_status_counts"]["PROCESSING"]=2;p.update(expired_lease_count=1,missing_lease_count=1,completeness="PARTIAL")
        self.assertIn("EXPIRED_LEASE",self.health_summary(p)["issues"])
        p["missing_lease_count"]=2
        with self.assertRaises(summary.InvalidEvidence):self.health_summary(p)

    def test_poison_totals_exactly_reconcile_failures(self):
        p=self.health();p["job_status_counts"]["FAILED"]=2;p["poison_code_counts"]["STALE_CONTEXT"]=1;p.update(unclassified_failure_count=1,completeness="PARTIAL")
        self.assertIn("FAILED_JOBS",self.health_summary(p)["issues"])
        p["unclassified_failure_count"]=0
        with self.assertRaises(summary.InvalidEvidence):self.health_summary(p)

    def test_unknown_job_status_requires_partial_and_attention(self):
        p=self.health();p.update(unknown_status_count=1,completeness="PARTIAL")
        self.assertIn("UNKNOWN_JOB_STATUS",self.health_summary(p)["issues"])
        p["completeness"]="COMPLETE"
        with self.assertRaises(summary.InvalidEvidence):self.health_summary(p)

    def test_health_model_stale_future_remain_visible(self):
        for changes,expected in ((dict(mode="MODEL"),"MODEL_ONLY"),(dict(observed_at=949),"STALE"),(dict(observed_at=1001),"FUTURE")):
            self.assertEqual(self.health_summary(self.health(),**changes)["status"],expected)

    def test_schema_unavailable_has_no_health_success(self):
        p=dict(schema_version=1,completeness="PARTIAL",status="SCHEMA_UNAVAILABLE")
        self.assertEqual(self.health_summary(p)["status"],"UNAVAILABLE")
        p["schema_version"]=True
        with self.assertRaises(summary.InvalidEvidence):self.health_summary(p)

    def test_health_extra_raw_fields_labels_and_bool_counts_refuse(self):
        for mode in ("raw","joblabel","poisonlabel","bool"):
            p=self.health()
            if mode=="raw":p["raw_report"]="synthetic-secret-canary"
            elif mode=="joblabel":p["job_status_counts"]["PRIVATE_JOB_ID"]=1
            elif mode=="poisonlabel":p["poison_code_counts"]["CANARY_TOKEN"]=1
            else:p["unknown_status_count"]=False
            with self.assertRaises(summary.InvalidEvidence) as caught:self.health_summary(p)
            self.assertEqual(str(caught.exception),"INVALID_EVIDENCE")
            self.assertNotIn("canary",str(caught.exception))

    def test_health_output_independent_copy_and_declared_provenance(self):
        p=self.health();before=deepcopy(p);out=self.health_summary(p)
        out["job_status_counts"]["DONE"]=999
        self.assertEqual(p,before)
        self.assertEqual(out["provenance"],"UNAUTHENTICATED_CALLER_METADATA")
        self.assertEqual(out["freshness_basis"],"DECLARED_WINDOW_NOT_LIVE_CURRENTNESS")
