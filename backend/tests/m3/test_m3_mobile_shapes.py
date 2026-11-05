"""TASK-125: actual mobile HTTP body preservation amid multi-unit processing."""
import json
import uuid

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import transaction
from django.test import TestCase, override_settings

from apps.operations.mobile_serializers import MobileOperationSerializer
from apps.operations.serializers import DecisionSerializer, OperationSerializer
from apps.operations.worker import binding_for, process_one
from apps.reports.models import ReportRevision
from apps.reports.regeneration import invalidate_policy, latest_job
from apps.reports.services import accept_operation
from apps.review.services import decide
from apps.scopes.models import Organization, PolicyVersion, SharingChannel, Unit
from apps.scopes.services import update_source
from tests.mobile.helpers import MOBILE, MOBILE_SETTINGS, MobileFixtures
from tests.test_workflow import operation


@override_settings(**MOBILE_SETTINGS)
class M3MobileShapeTests(MobileFixtures, TestCase):
    def setUp(self):
        super().setUp()
        call_command("seed_m3_demo", verbosity=0)
        self.session = self.enroll()
        self.admin = get_user_model().objects.get(username="administrator")

    def post(self, body):
        return self.client.post(MOBILE + "sync/operations/", body, format="json",
            HTTP_AUTHORIZATION="Bearer " + self.session["access_token"], HTTP_IDEMPOTENCY_KEY=body["operation_id"])

    def read(self, path):
        return self.client.get(MOBILE + path, HTTP_AUTHORIZATION="Bearer " + self.session["access_token"])

    def mobile_source(self):
        body = operation()
        response = self.post(body)
        self.assertEqual(response.status_code, 201, response.content)
        return body, response.json()

    def m3_source(self):
        body = operation()
        data = OperationSerializer(data=body)
        data.is_valid(raise_exception=True)
        result, created = accept_operation(get_user_model().objects.get(username="submitter2"), data.validated_data, body)
        self.assertTrue(created)
        return ReportRevision.objects.get(pk=result["revision_id"])

    def detail(self, body):
        response = self.read("reports/" + body["report_id"] + "/revisions/1/")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def assert_shapes(self, detail, receipt):
        self.assertEqual(set(detail), {"report", "payload", "receipt", "can_correct", "history", "workflow"})
        self.assertEqual(set(detail["report"]), {"id", "reference", "category", "urgency", "area_label", "created_at",
            "observed_date", "revision_no", "status", "variant_id", "feedback"})
        self.assertEqual(set(receipt), {"operation_id", "report_id", "revision_id", "revision_no", "delivery_status", "processing_status", "shared"})
        self.assertEqual(detail["receipt"], receipt)
        for row in detail["history"]:
            self.assertEqual(set(row), {"revision_no", "received_at", "status"})
        workflow = detail["workflow"]
        self.assertEqual(set(workflow), {"revision_no", "is_current", "received_at", "processing", "review", "sharing"})
        self.assertEqual(set(workflow["processing"]), {"state", "attempts"})
        self.assertEqual(set(workflow["review"]), {"state", "prepared_at", "decided_at"})
        self.assertEqual(set(workflow["sharing"]), {"state", "published_at"})
        for field in ("scope_context", "scope_context_hash", "policy_epoch", "scope_epoch", "candidates", "channel_ids"):
            self.assertNotIn(field, json.dumps(detail))

    def test_multivariant_other_unit_does_not_expand_mobile_summary_history_workflow_or_receipt(self):
        body, receipt = self.mobile_source()
        other = self.m3_source()
        self.assertTrue(process_one())
        self.assertTrue(process_one())
        self.assertEqual(other.variants.count(), 3)
        self.assertIsNotNone(latest_job(other).scope_context_hash)
        detail = self.detail(body)
        self.assert_shapes(detail, receipt)
        self.assertEqual(self.read("reports/").json()["count"], 1)
        foreign = self.read("reports/" + str(other.report_id) + "/revisions/1/")
        self.assertEqual(foreign.status_code, 404)
        self.assertNotIn(str(other.report_id), json.dumps(self.read("reports/").json()))

    def test_unrelated_scope_epoch_keeps_identical_mobile_bodies_and_legacy_decidability(self):
        body, receipt = self.mobile_source()
        self.assertTrue(process_one())
        before_detail = self.detail(body)
        before_list = self.read("reports/").json()
        unit2 = Unit.objects.get(code="SIM-UNIT-02")
        channel2 = SharingChannel.objects.get(code="CH-DEMO-02")
        update_source(self.admin, unit2.id, channel2.id, max_profile="DEMO-REDUCED")
        self.assertEqual(self.detail(body), before_detail)
        self.assertEqual(self.read("reports/").json(), before_list)
        self.assert_shapes(self.detail(body), receipt)
        variant = ReportRevision.objects.get(report_id=body["report_id"]).variants.get()
        raw = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        serializer = DecisionSerializer(data=raw)
        serializer.is_valid(raise_exception=True)
        result = decide(get_user_model().objects.get(username="reviewer"), variant.id, serializer.validated_data, raw)
        self.assertEqual(result["report_status"], "APPROVED")

    def test_policy_change_regenerates_unit01_as_one_legacy_variant_with_frozen_mobile_keys(self):
        body, receipt = self.mobile_source()
        self.assertTrue(process_one())
        revision = ReportRevision.objects.get(report_id=body["report_id"])
        old = latest_job(revision)
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.pk)
            PolicyVersion.objects.filter(organization=org, active=True).update(active=False)
            policy = PolicyVersion.objects.get(organization=org, version="demo-policy-v2")
            policy.active = True
            policy.save(update_fields=["active"])
            org.active_policy = policy
            org.save(update_fields=["active_policy"])
            invalidate_policy(org)
        current = latest_job(revision)
        self.assertNotEqual(current.id, old.id)
        self.assertIsNone(current.scope_context)
        self.assertEqual(current.policy_epoch, 1)
        self.assert_shapes(self.detail(body), receipt)
        self.assertEqual(self.detail(body)["report"]["status"], "PENDING")
        self.assertTrue(process_one())
        self.assertEqual(current.variants.count(), 1)
        self.assertEqual(current.variants.get().profile, "DEMO-REDUCED")
        self.assert_shapes(self.detail(body), receipt)
        replay = self.post(body)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), receipt)

    def test_mobile_correction_remains_returned_only_and_rejects_new_web_reason_field(self):
        body, _ = self.mobile_source()
        self.assertTrue(process_one())
        variant = ReportRevision.objects.get(report_id=body["report_id"]).variants.get()
        self.assertFalse(self.detail(body)["can_correct"])
        raw = {"operation_id": str(uuid.uuid4()), "action": "RETURN", "expected": binding_for(variant), "reason": "Synthetic correction requested."}
        serializer = DecisionSerializer(data=raw)
        serializer.is_valid(raise_exception=True)
        decide(get_user_model().objects.get(username="reviewer"), variant.id, serializer.validated_data, raw)
        self.assertTrue(self.detail(body)["can_correct"])
        data = MobileOperationSerializer(data={**operation(), "correction_reason": "Web-only reason"})
        self.assertFalse(data.is_valid())
