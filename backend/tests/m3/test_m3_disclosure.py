"""Independent T09/T19: inspect real responses and persisted safe metadata."""
import copy
import json
import logging
import uuid
from datetime import datetime
from io import StringIO
from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.operations.worker import process_one
from apps.publications.models import Publication
from apps.reports.models import ReportRevision
from apps.reports.services import accept_operation
from apps.review.services import decide_batch
from .test_m3_isolation import QAMatrixFixture, WEB, INTEGRATION
from .test_m3_review import SETTINGS
from tests.test_workflow import operation


CANARIES = ("QA_PRIVATE_SITE_175", "QA_PRIVATE_REPORTER_175", "QA_PRIVATE_NARRATIVE_175",
            "QA_PRIVATE_CORRECTION_175", "QA_PRIVATE_DECISION_175", "QA_PRIVATE_WITHDRAWAL_175",
            "QA_PRIVATE_PROPOSAL_175")


@override_settings(**SETTINGS)
class IndependentDisclosureTests(QAMatrixFixture, TestCase):
    def assert_no_private(self, value):
        encoded = json.dumps(value, default=str)
        for canary in CANARIES:
            self.assertNotIn(canary, encoded)
        for field in ("payload_ciphertext", "correction_reason", "reason_ciphertext", "source_payload", "candidate_hash", "revision_id", "site_label", "reporter_label", "narrative"):
            self.assertNotIn(field, encoded)

    def canary_source(self):
        raw = operation()
        raw["payload"].update(site_label=CANARIES[0], reporter_label=CANARIES[1], narrative=CANARIES[2])
        receipt, _ = accept_operation(self.author, raw, raw)
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.assertTrue(process_one())
        data, body = self.decision_data(revision, reason=CANARIES[4])
        decide_batch(self.reviewer, revision.id, data, body)
        return revision, raw

    def inspect_outputs(self, readers):
        for name, channel in (("recipient-full", 2), ("recipient-limited", 2), ("recipient-summary", 3), ("recipient-multi", 3)):
            for surface in ("feed", "map", "removed"):
                response = self.read_as(name, f"channels/{self.channels[channel].id}/{surface}/")
                self.assertEqual(response.status_code, 200)
                self.assert_no_private(response.json())
            feed = self.read_as(name, f"channels/{self.channels[channel].id}/feed/").json()
            for row in feed["results"]:
                self.assert_no_private(self.read_as(name, f"publications/{row['id']}/").json())
                served = datetime.fromisoformat(row["published_at"])
                self.assertEqual((served.minute, served.second, served.microsecond), (0, 0, 0))
                if row["projection"]["profile"] != "DEMO-FULL":
                    self.assertEqual(served.hour, 0)
                if row["projection"]["profile"] == "DEMO-SUMMARY":
                    self.assertEqual(served.weekday(), 0)
                projection = row["projection"]
                if projection["profile"] == "DEMO-SUMMARY":
                    self.assertNotIn("area_label", projection)
                    self.assertNotIn("originating_unit", projection)
            hostile = self.read_as(name, f"channels/{self.channels[channel].id}/feed/", {"category": CANARIES[2]})
            self.assertEqual(hostile.status_code, 400)
            self.assert_no_private(hostile.json())
        for reader in readers:
            for suffix in ("publications/", "removed/", f"publications/{uuid.uuid4()}/"):
                response = reader.get(INTEGRATION + suffix)
                self.assertIn("no-store", response["Cache-Control"])
                self.assert_no_private(response.json())
        for row in AuditEvent.objects.values("action", "safe_metadata"):
            self.assert_no_private(row)

    def test_source_decision_correction_withdrawal_canaries_never_reach_sharing(self):
        revision, raw = self.canary_source()
        readers = [self.issue_key(profile, channel)[1] for profile, channel in (("DEMO-FULL", 2), ("DEMO-REDUCED", 2), ("DEMO-SUMMARY", 3))]
        self.inspect_outputs(readers)
        correction = copy.deepcopy(raw)
        correction.update(operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason=CANARIES[3])
        receipt, _ = accept_operation(self.author, correction, correction)
        next_revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.assertTrue(process_one())
        data, body = self.decision_data(next_revision, reason=CANARIES[4])
        decide_batch(self.reviewer, next_revision.id, data, body)
        # The private web DTO carries the explicit reason to authorized source readers only.
        private = self.read_as("submitter2", f"reports/{revision.report_id}/revisions/2/")
        self.assertEqual(private.json()["correction_reason"], CANARIES[3])
        self.inspect_outputs(readers)
        data = {"operation_id": uuid.uuid4(), "expected_revision_no": 2, "reason": CANARIES[5]}
        from apps.publications.services import withdraw_report
        withdraw_report(self.reviewer, revision.report_id, data, {**data, "operation_id": str(data["operation_id"])})
        self.inspect_outputs(readers)
        self.assertFalse(Publication.objects.filter(report_id=revision.report_id, revoked_at__isnull=True).exists())

    def test_policy_proposal_has_no_reason_contract_and_rejects_hostile_extra_field(self):
        self.org.refresh_from_db()
        from apps.scopes.models import PolicyVersion
        target = PolicyVersion.objects.get(organization=self.org, version="demo-policy-v2")
        body = {"operation_id": str(uuid.uuid4()), "kind": "ACTIVATE", "target_policy_id": str(target.id),
                "target_rules_hash": target.rules_hash, "expected_active_policy_id": str(self.org.active_policy_id), "reason": CANARIES[6]}
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(WEB + "administration/policy/proposals/", body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(response.status_code, 422)
        self.assert_no_private(response.json())
        for row in AuditEvent.objects.values("safe_metadata"):
            self.assert_no_private(row)

    def test_unknown_profile_and_cross_scope_errors_do_not_echo_private_query_values(self):
        self.canary_source()
        captured = StringIO()
        handler = logging.StreamHandler(captured)
        logger = logging.getLogger("django.request")
        logger.addHandler(handler)
        try:
            for surface in ("feed", "map"):
                response = self.read_as("recipient-summary", f"channels/{self.channels[2].id}/{surface}/", {"q": CANARIES[2]})
                self.assertEqual(response.status_code, 404)
                self.assert_no_private(response.json())
            # RemovedView rejects all query strings before selecting a channel.
            malformed = self.read_as("recipient-summary", f"channels/{self.channels[2].id}/removed/", {"q": CANARIES[2]})
            self.assertEqual(malformed.status_code, 400)
            self.assert_no_private(malformed.json())
            for surface in ("map", "removed"):
                inaccessible = self.read_as("recipient-summary", f"channels/{self.channels[2].id}/{surface}/")
                self.assertEqual(inaccessible.status_code, 404)
                self.assert_no_private(inaccessible.json())
            for params in ({"profile": CANARIES[0]}, {"page_size": CANARIES[1]}, {"category": CANARIES[2]}, {"urgency": CANARIES[3]}):
                response = self.read_as("recipient-full", f"channels/{self.channels[2].id}/feed/", params)
                self.assertEqual(response.status_code, 400)
                self.assert_no_private(response.json())
        finally:
            logger.removeHandler(handler)
        for value in CANARIES:
            self.assertNotIn(value, captured.getvalue())

    def test_unknown_integration_denials_have_identity_free_fixed_audit_and_fail_closed(self):
        # TASK-178's source-frozen journal contract, not a new application model here.
        from apps.audit.models import AnonymousIntegrationFailure
        reader = APIClient()
        expected = {"code": "AUTHENTICATION_REQUIRED", "message": "Use a valid integration key."}
        for header, prefix in ((None, None), ("Basic " + CANARIES[0], None), ("Bearer invalid", None), ("Bearer kapit_ic_abcd1234_" + "x" * 43, "abcd1234")):
            reader.credentials(**({"HTTP_AUTHORIZATION": header} if header else {}))
            before, scoped = AnonymousIntegrationFailure.objects.count(), AuditEvent.objects.count()
            response = reader.get(INTEGRATION + "publications/")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json(), expected)
            self.assertIn("no-store", response["Cache-Control"])
            self.assertEqual(AnonymousIntegrationFailure.objects.count(), before + 1)
            self.assertEqual(AuditEvent.objects.count(), scoped)
            row = AnonymousIntegrationFailure.objects.order_by("-recorded_at").first()
            self.assertEqual((row.event, row.outcome, row.code, row.prefix), ("INTEGRATION_AUTH_FAILED", "DENIED", "AUTHENTICATION_REQUIRED", prefix))
        self.assertEqual({field.name for field in AnonymousIntegrationFailure._meta.fields}, {"id", "event", "outcome", "code", "prefix", "recorded_at"})
        before = AnonymousIntegrationFailure.objects.count()
        with patch("apps.audit.service.anonymous_integration_failure", side_effect=RuntimeError("synthetic audit failure")):
            response = reader.get(INTEGRATION + "publications/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(AnonymousIntegrationFailure.objects.count(), before)
        self.assert_no_private(response.json())
        for method in ("post", "put", "delete", "patch", "head", "options"):
            self.assertEqual(getattr(reader, method)(INTEGRATION + "publications/").status_code, 405)
        self.assertEqual(AnonymousIntegrationFailure.objects.count(), before)
