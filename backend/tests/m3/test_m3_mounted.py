"""Mounted HTTP journeys. Authored here; PostgreSQL execution is parent-reserved."""
import copy
import json
import uuid

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.operations.models import ProcessingJob
from apps.operations.worker import process_one
from apps.publications.models import PublicationDelivery, PublicationRemoval
from apps.reports.models import ReportRevision
from apps.scopes.models import AdminAuthority, Organization, PolicyActivation, PolicyProposal, SharingChannel
from tests import test_workflow as workflow
from tests.mobile import helpers as mobile


@override_settings(ROOT_URLCONF="config.urls", KAPIT_SOURCE_KEY=Fernet.generate_key(),
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3MountedAPITests(TestCase):
    # Import the module, not its TestCase class: no accidental duplicate discovery.
    sign_in = workflow.WorkflowTests.sign_in

    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql", "Requires actual PostgreSQL.")
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        self.org = Organization.objects.get(code="SIM-ORG-01")
        self.channel = SharingChannel.objects.get(code="CH-DEMO-02")
        self.summary_channel = SharingChannel.objects.get(code="CH-DEMO-03")
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.raise_request_exception = False

    def post(self, route, body, *, csrf=True):
        headers = {"HTTP_X_CSRFTOKEN": self.token} if csrf else {}
        if "operation_id" in body:
            headers["HTTP_IDEMPOTENCY_KEY"] = body["operation_id"]
        return self.client.post("/api/v1/" + route, body, format="json", **headers)

    def get_ok(self, route):
        response = self.client.get("/api/v1/" + route)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def assert_private_absent(self, value):
        encoded = json.dumps(value)
        for forbidden in ("PRIVATE_", "correction_reason", "reporter_label", "site_label", "narrative",
                          "candidate_hash", "policy_hash", "scope_context", "payload_ciphertext",
                          "revision_id", "replacement", "removed_at", "cause"):
            self.assertNotIn(forbidden, encoded)

    def source(self):
        self.sign_in("submitter2")
        body = workflow.operation()
        response = self.post("sync/operations/", body)
        self.assertEqual(response.status_code, 201, response.content)
        receipt = response.json()
        self.assertEqual(set(receipt), {"operation_id", "report_id", "revision_id", "revision_no",
                                       "delivery_status", "processing_status", "shared"})
        self.assertFalse(receipt["shared"])
        self.assertTrue(process_one())
        self.sign_in("reviewer2")
        candidates = self.get_ok(f"revisions/{receipt['revision_id']}/candidates/")
        self.assertEqual({row["profile"] for row in candidates["candidates"]},
                         {"DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"})
        self.assertNotIn("correction_reason", candidates)
        return body, receipt, candidates

    def decide(self, receipt, candidates, *, action="APPROVE", profiles=None):
        body = {"operation_id": str(uuid.uuid4()), "action": action,
                "approve_profiles": profiles if profiles is not None else ["DEMO-REDUCED", "DEMO-SUMMARY"],
                "expected": copy.deepcopy(candidates["binding"]),
                "reason": "PRIVATE_RETURN_REASON_CANARY" if action != "APPROVE" else None}
        response = self.post(f"revisions/{receipt['revision_id']}/decisions/", body)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def published(self):
        body, receipt, candidates = self.source()
        result = self.decide(receipt, candidates)
        self.assertEqual(result["approved_profiles"], ["DEMO-REDUCED", "DEMO-SUMMARY"])
        self.assertEqual(result["withheld_profiles"], ["DEMO-FULL"])
        self.assertEqual(len(result["publication_ids"]), 3)
        return body, receipt

    def test_mounted_subset_feed_map_delivery_withdrawal_and_private_denials(self):
        body, receipt = self.published()
        self.sign_in("recipient-full")
        identity = self.get_ok("me/")
        self.assertEqual(identity["user"]["grants"][0]["profile_ceiling"], "DEMO-FULL")
        mapping = self.get_ok(f"channels/{self.channel.id}/map/")
        self.assertEqual(mapping, {"areas": [{"area_id": "area-c", "count": 1}], "unmapped": 0})
        self.assertEqual(PublicationDelivery.objects.count(), 0, "Counts are not delivery.")
        feed = self.get_ok(f"channels/{self.channel.id}/feed/")
        self.assertEqual((feed["count"], len(feed["results"])), (1, 1))
        publication = feed["results"][0]
        self.assertEqual(publication["projection"]["profile"], "DEMO-REDUCED")
        self.assertEqual(feed["summary"]["by_area"], {"Area C": 1})
        self.assertEqual(sum(row["count"] for row in mapping["areas"]) + mapping["unmapped"], feed["count"])
        detail = self.get_ok(f"publications/{publication['id']}/")
        self.assertEqual(detail, publication)
        recipient = get_user_model().objects.get(username="recipient-full")
        self.assertEqual(list(PublicationDelivery.objects.filter(user=recipient).values_list("publication_id", flat=True)),
                         [uuid.UUID(publication["id"])])
        for query in ("PRIVATE_NARRATIVE_CANARY", "PRIVATE_SITE_CANARY", "PRIVATE_REPORTER_CANARY"):
            self.assertEqual(self.get_ok(f"channels/{self.channel.id}/feed/?q={query}")["count"], 0)
        self.assert_private_absent(feed)
        self.assert_private_absent(detail)
        self.assertEqual(self.client.get(f"/api/v1/reports/{body['report_id']}/revisions/1/").status_code, 404)

        self.sign_in("recipient-summary")
        summary = self.get_ok(f"channels/{self.summary_channel.id}/feed/")
        self.assertEqual(summary["count"], 1)
        summary_publication = summary["results"][0]
        self.assertEqual(summary_publication["projection"]["profile"], "DEMO-SUMMARY")
        self.assertNotIn("area_label", summary_publication["projection"])
        self.assertEqual(summary["summary"]["by_area"], {})
        self.assertEqual(self.get_ok(f"channels/{self.summary_channel.id}/map/"), {"areas": [], "unmapped": 1})
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.summary_channel.id}/feed/?area=Area%20C").status_code, 400)
        self.assert_private_absent(summary)

        self.sign_in("reviewer2")
        withdrawal = {"operation_id": str(uuid.uuid4()), "expected_revision_no": 1,
                      "reason": "PRIVATE_WITHDRAWAL_REASON_CANARY"}
        response = self.post(f"reports/{body['report_id']}/withdrawal/", withdrawal)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(PublicationRemoval.objects.filter(publication__report_id=body["report_id"]).count(), 3)
        for name, channel, delivered_id in (("recipient-full", self.channel, publication["id"]),
                ("recipient-summary", self.summary_channel, summary_publication["id"])):
            self.sign_in(name)
            self.assertEqual(self.get_ok(f"channels/{channel.id}/feed/")["count"], 0)
            self.assertEqual(self.get_ok(f"channels/{channel.id}/map/"), {"areas": [], "unmapped": 0})
            tombstones = self.get_ok(f"channels/{channel.id}/removed/")
            self.assertEqual(tombstones, {"results": [{"publication_id": delivered_id, "state": "WITHDRAWN"}]})
            self.assert_private_absent(tombstones)
            self.assertEqual(self.client.get(f"/api/v1/publications/{delivered_id}/").status_code, 404)
        self.sign_in("recipient-limited")
        self.assertEqual(self.get_ok(f"channels/{self.channel.id}/removed/"), {"results": []})

    def test_policy_http_two_person_transition_closes_old_outputs_and_regenerates(self):
        _, receipt = self.published()
        self.sign_in("recipient-full")
        old_id = self.get_ok(f"channels/{self.channel.id}/feed/")["results"][0]["id"]
        self.sign_in("administrator")
        state = self.get_ok("administration/policy/")
        target = next(row for row in state["policies"] if row["version"] == "demo-policy-v2")
        body = {"operation_id": str(uuid.uuid4()), "kind": "ACTIVATE", "target_policy_id": target["id"],
                "target_rules_hash": target["rules_hash"], "expected_active_policy_id": state["active_policy_id"]}
        response = self.post("administration/policy/proposals/", body)
        self.assertEqual(response.status_code, 201, response.content)
        proposal = response.json()
        route = f"administration/policy/proposals/{proposal['id']}/apply/"
        denied = self.post(route, {})
        self.assertEqual(denied.status_code, 403, denied.content)
        self.assertEqual(denied.json()["code"], "SELF_APPROVAL_DENIED")
        self.assertFalse(PolicyActivation.objects.exists())
        self.sign_in("administrator2")
        applied = self.post(route, {})
        self.assertEqual(applied.status_code, 201, applied.content)
        self.org.refresh_from_db()
        self.assertEqual((str(self.org.active_policy_id), self.org.policy_epoch), (target["id"], state["policy_epoch"] + 1))
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        job = ProcessingJob.objects.get(revision=revision, policy_id=target["id"], policy_epoch=self.org.policy_epoch)
        self.assertEqual(job.status, "PENDING")
        self.assertEqual(job.scope_epoch, revision.report.unit.scope_epoch)
        self.assertTrue(PublicationRemoval.objects.filter(publication_id=old_id, cause="POLICY").exists())
        replay = self.post(route, {})
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), applied.json())
        self.org.refresh_from_db()
        self.assertEqual(self.org.policy_epoch, state["policy_epoch"] + 1)
        self.sign_in("recipient-full")
        self.assertEqual(self.get_ok(f"channels/{self.channel.id}/feed/")["count"], 0)
        self.assertEqual(self.client.get(f"/api/v1/publications/{old_id}/").status_code, 404)
        removed = self.get_ok(f"channels/{self.channel.id}/removed/")
        self.assertEqual(removed, {"results": [{"publication_id": old_id, "state": "WITHDRAWN"}]})
        self.assert_private_absent(removed)
        self.assertTrue(process_one())
        self.assertEqual(self.get_ok(f"channels/{self.channel.id}/feed/")["count"], 0, "Regeneration cannot publish.")
        self.sign_in("reviewer2")
        current = self.get_ok(f"revisions/{receipt['revision_id']}/candidates/")
        self.assertEqual(current["binding"]["policy_version"], "demo-policy-v2")
        self.assertEqual({row["state"] for row in current["candidates"]}, {"CANDIDATE"})

    def test_policy_authority_and_missing_csrf_deny_without_mutation(self):
        self.sign_in("administrator")
        state = self.get_ok("administration/policy/")
        target = next(row for row in state["policies"] if row["version"] == "demo-policy-v2")
        body = {"operation_id": str(uuid.uuid4()), "kind": "ACTIVATE", "target_policy_id": target["id"],
                "target_rules_hash": target["rules_hash"], "expected_active_policy_id": state["active_policy_id"]}
        denied = self.post("administration/policy/proposals/", body, csrf=False)
        self.assertEqual(denied.status_code, 403, denied.content)
        self.assertFalse(PolicyProposal.objects.exists())
        self.sign_in("reviewer2")
        self.assertEqual(self.client.get("/api/v1/administration/policy/").status_code, 403)
        self.assertEqual(self.post("administration/policy/proposals/", body).status_code, 403)
        self.sign_in("administrator2")
        AdminAuthority.objects.filter(user__username="administrator2", kind="POLICY").update(active=False)
        self.assertEqual(self.client.get("/api/v1/administration/policy/").status_code, 403)
        self.assertEqual(self.post("administration/policy/proposals/", body).status_code, 403)
        self.assertFalse(PolicyProposal.objects.exists())
        self.assertFalse(PolicyActivation.objects.exists())

    def test_private_correction_reason_visible_only_on_authorized_source_and_candidate(self):
        original, receipt, candidates = self.source()
        self.decide(receipt, candidates, action="RETURN", profiles=[])
        self.sign_in("submitter2")
        corrected = copy.deepcopy(original)
        reason = "PRIVATE_CORRECTION_REASON_CANARY"
        corrected.update(operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason=reason)
        corrected["payload"]["category"] = "INFRASTRUCTURE"
        response = self.post("sync/operations/", corrected)
        self.assertEqual(response.status_code, 201, response.content)
        corrected_receipt = response.json()
        source_route = f"reports/{original['report_id']}/revisions/2/"
        current = self.get_ok(source_route)
        self.assertEqual(current["correction_reason"], reason)
        self.assertNotIn("correction_reason", self.get_ok(f"reports/{original['report_id']}/revisions/1/"))
        self.assertTrue(process_one())
        candidate_route = f"revisions/{corrected_receipt['revision_id']}/candidates/"
        self.sign_in("reviewer2")
        candidates = self.get_ok(candidate_route)
        self.assertEqual(candidates["correction_reason"], reason)
        self.decide(corrected_receipt, candidates)
        for actor, expected in (("submitter3", 404), ("reviewer3", 404), ("recipient-full", 404)):
            self.sign_in(actor)
            denied = self.client.get("/api/v1/" + source_route)
            self.assertEqual(denied.status_code, expected, denied.content)
            self.assertNotIn(reason, denied.content.decode())
            denied_candidate = self.client.get("/api/v1/" + candidate_route)
            self.assertEqual(denied_candidate.status_code, 404 if actor == "reviewer3" else 403,
                             denied_candidate.content)
            self.assertNotIn(reason, denied_candidate.content.decode())
        feed = self.get_ok(f"channels/{self.channel.id}/feed/")
        self.assertEqual(feed["count"], 1)
        self.assert_private_absent(feed)


@override_settings(**{**mobile.MOBILE_SETTINGS, "ROOT_URLCONF": "config.mobile_integration_urls"})
class M3MountedMobileWireTests(mobile.MobileFixtures, TestCase):
    def test_existing_m2_runtime_auth_and_wire_stay_frozen_with_expanded_report(self):
        # Actual product M2 URL profile includes actual config.urls; no test URL shim.
        call_command("seed_m3_demo", verbosity=0)
        session = self.enroll()
        body = workflow.operation()
        authorization = {"HTTP_AUTHORIZATION": "Bearer " + session["access_token"]}
        response = self.client.post(mobile.MOBILE + "sync/operations/", body, format="json",
                                    HTTP_IDEMPOTENCY_KEY=body["operation_id"], **authorization)
        self.assertEqual(response.status_code, 201, response.content)
        receipt = response.json()
        self.assertEqual(set(receipt), {"operation_id", "report_id", "revision_id", "revision_no",
                                       "delivery_status", "processing_status", "shared"})
        web, csrf = self.web("submitter2")
        expanded = workflow.operation()
        response = web.post("/api/v1/sync/operations/", expanded, format="json",
                            HTTP_X_CSRFTOKEN=csrf, HTTP_IDEMPOTENCY_KEY=expanded["operation_id"])
        self.assertEqual(response.status_code, 201, response.content)
        self.assertTrue(process_one())
        self.assertTrue(process_one())
        self.assertEqual(ReportRevision.objects.get(report_id=expanded["report_id"]).variants.count(), 3)
        response = self.client.get(mobile.MOBILE + f"reports/{body['report_id']}/revisions/1/", **authorization)
        self.assertEqual(response.status_code, 200, response.content)
        detail = response.json()
        self.assertEqual(set(detail), {"report", "payload", "receipt", "can_correct", "history", "workflow"})
        self.assertEqual(set(detail["report"]), {"id", "reference", "category", "urgency", "area_label", "created_at",
            "observed_date", "revision_no", "status", "variant_id", "feedback"})
        self.assertEqual(detail["receipt"], receipt)
        self.assertEqual(set(detail["workflow"]), {"revision_no", "is_current", "received_at", "processing", "review", "sharing"})
        self.assertEqual(set(detail["workflow"]["processing"]), {"state", "attempts"})
        self.assertEqual(set(detail["workflow"]["review"]), {"state", "prepared_at", "decided_at"})
        self.assertEqual(set(detail["workflow"]["sharing"]), {"state", "published_at"})
        self.assertEqual(set(detail["history"][0]), {"revision_no", "received_at", "status"})
        for forbidden in ("scope_context", "scope_epoch", "policy_epoch", "candidates", "correction_reason"):
            self.assertNotIn(forbidden, json.dumps(detail))
        self.assertEqual(self.client.get(mobile.MOBILE + "reports/", **authorization).json()["count"], 1)
        foreign = self.client.get(mobile.MOBILE + f"reports/{expanded['report_id']}/revisions/1/", **authorization)
        self.assertEqual(foreign.status_code, 404)
