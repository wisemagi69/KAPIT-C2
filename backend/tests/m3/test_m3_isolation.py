"""Independent T02 mounted-route scope matrix. Parent executes PostgreSQL gate."""
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.integration_services import request_client, approve_client, collect_client
from apps.accounts.models import IntegrationClient
from apps.operations.serializers import BatchDecisionSerializer
from apps.operations.worker import binding_for
from apps.publications.models import Publication, PublicationDelivery
from apps.publications.services import withdraw_report
from apps.review.services import candidate_set, decide, decide_batch
from apps.scopes import policy
from apps.scopes.models import AdminAuthority, ChannelMember, Organization, PolicyVersion, SharingChannel, Unit, UnitMembership
from .test_m3_review import ReviewFixture, SETTINGS

WEB = "/api/v1/"
INTEGRATION = "/api/integration/v1/"


class QAMatrixFixture(ReviewFixture):
    """Reuse provisioning helpers only; no imported implementer TestCase classes."""
    def setUp(self):
        super().setUp()
        self.users = {row.username: row for row in get_user_model().objects.all()}
        self.admin, self.second = self.users["administrator"], self.users["administrator2"]
        self.channels = {n: SharingChannel.objects.get(code=f"CH-DEMO-0{n}") for n in (1, 2, 3)}
        self.units = {n: Unit.objects.get(code=f"SIM-UNIT-0{n}") for n in (1, 2, 3)}

    def prepared(self, unit=2):
        return self.submit_source(self.users["submitter" if unit == 1 else f"submitter{unit}"])

    def decision_data(self, revision, reviewer=None, profiles=None, action="APPROVE", reason=None):
        reviewer = reviewer or self.reviewer
        binding = candidate_set(reviewer, revision.id)["binding"]
        body = {"operation_id": str(uuid.uuid4()), "action": action, "expected": binding,
                "approve_profiles": ([row["profile"] for row in binding["candidates"]] if profiles is None else profiles) if action == "APPROVE" else [],
                "reason": reason if reason is not None else (None if action == "APPROVE" else "QA_PRIVATE_DECISION")}
        serializer = BatchDecisionSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data, body

    def publish_unit(self, unit=2, profiles=None):
        revision, body = self.prepared(unit)
        reviewer = self.users["reviewer" if unit == 1 else f"reviewer{unit}"]
        if unit == 1:
            variant = revision.variants.get()
            data = {"operation_id": uuid.uuid4(), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
            decide(reviewer, variant.id, data, {**data, "operation_id": str(data["operation_id"])})
        else:
            data, raw = self.decision_data(revision, reviewer, profiles)
            decide_batch(reviewer, revision.id, data, raw)
        return revision, body

    def proposal(self, target="demo-policy-v2", kind="ACTIVATE"):
        self.org.refresh_from_db()
        row = PolicyVersion.objects.get(organization=self.org, version=target)
        data = {"operation_id": uuid.uuid4(), "kind": kind, "target_policy_id": row.id,
                "target_rules_hash": row.rules_hash, "expected_active_policy_id": self.org.active_policy_id}
        raw = {key: str(value) if value is not None else None for key, value in data.items()}
        result, _ = policy.propose(self.admin, data, raw)
        return result["id"]

    def issue_key(self, profile="DEMO-REDUCED", channel=2, admin=None):
        actor = admin or self.admin
        data = {"operation_id": uuid.uuid4(), "channel_id": self.channels[channel].id, "profile_ceiling": profile,
                "label": "Synthetic QA reader", "expires_at": timezone.now() + timedelta(days=2)}
        result, _ = request_client(actor, data, {key: str(value) for key, value in data.items()})
        if profile == "DEMO-FULL":
            approve_client(self.second, result["request"]["id"])
            result, _ = collect_client(actor, result["request"]["id"])
        reader = APIClient()
        reader.credentials(HTTP_AUTHORIZATION="Bearer " + result["key"])
        return IntegrationClient.objects.get(pk=result["client"]["id"]), reader

    def read_as(self, name, path, params=None):
        client = APIClient()
        client.force_authenticate(user=self.users[name])
        response = client.get(WEB + path, params or {})
        self.assertIn("no-store", response["Cache-Control"])
        return response

    def withdraw_revision(self, revision):
        data = {"operation_id": uuid.uuid4(), "expected_revision_no": revision.revision_no, "reason": "QA_PRIVATE_WITHDRAWAL"}
        return withdraw_report(self.reviewer, revision.report_id, data, {**data, "operation_id": str(data["operation_id"])})


@override_settings(**SETTINGS)
class IndependentIsolationTests(QAMatrixFixture, TestCase):
    def test_three_units_three_channels_roles_and_every_recipient_surface(self):
        revisions = {n: self.publish_unit(n)[0] for n in (1, 2, 3)}
        # Topology is independently specified, not obtained from the selector under test.
        units_by_channel = {1: {1, 3}, 2: {2}, 3: {2, 3}}
        grants = {"recipient": {1}, "recipient-full": {2}, "recipient-limited": {2},
                  "recipient-summary": {3}, "recipient-multi": {1, 3},
                  "submitter2": set(), "reviewer2": set(), "administrator": set()}
        for name, allowed in grants.items():
            for number, channel in self.channels.items():
                with self.subTest(principal=name, channel=number):
                    response = self.read_as(name, f"channels/{channel.id}/feed/")
                    mapping = self.read_as(name, f"channels/{channel.id}/map/")
                    removal = self.read_as(name, f"channels/{channel.id}/removed/")
                    if number not in allowed:
                        self.assertEqual((response.status_code, mapping.status_code, removal.status_code), (404, 404, 404) if name.startswith("recipient") else (403, 403, 403))
                        continue
                    self.assertEqual(response.status_code, 200)
                    result = response.json()
                    self.assertEqual(result["count"], len(units_by_channel[number]))
                    expected_reports = {revisions[n].report_id for n in units_by_channel[number]}
                    ids = {row["id"] for row in result["results"]}
                    self.assertEqual(set(Publication.objects.filter(id__in=ids).values_list("report_id", flat=True)), expected_reports)
                    self.assertEqual(sum(row["count"] for row in mapping.json()["areas"]) + mapping.json()["unmapped"], result["count"])
                    self.assertEqual(removal.json(), {"results": []})
                    for row in result["results"]:
                        self.assertEqual(self.read_as(name, f"publications/{row['id']}/").json(), row)
                    if "summary" in result:
                        self.assertEqual(sum(result["summary"]["by_category"].values()), result["count"])

    def test_source_queue_candidate_receipt_and_uniform_missing_matrix(self):
        for unit in (1, 2, 3):
            revision, body = self.prepared(unit)
            owner = "submitter" if unit == 1 else f"submitter{unit}"
            reviewer = "reviewer" if unit == 1 else f"reviewer{unit}"
            for name in ("submitter", "submitter2", "submitter3", "reviewer", "reviewer2", "reviewer3", "recipient-full", "administrator"):
                with self.subTest(unit=unit, principal=name):
                    actual = self.read_as(name, f"reports/{revision.report_id}/revisions/1/")
                    missing = self.read_as(name, f"reports/{uuid.uuid4()}/revisions/1/")
                    if name in {owner, reviewer}:
                        self.assertEqual(actual.status_code, 200)
                    else:
                        self.assertEqual(actual.status_code, 404)
                        self.assertEqual(actual.json(), missing.json())
                    receipt = self.read_as(name, f"sync/receipts/{body['operation_id']}/")
                    self.assertEqual(receipt.status_code, 200 if name == owner else (404 if name.startswith("submitter") else 403))
                    candidates = self.read_as(name, f"revisions/{revision.id}/candidates/")
                    self.assertEqual(candidates.status_code, 200 if name == reviewer else (404 if name.startswith("reviewer") else 403))
            queue = self.read_as(reviewer, "review/queue/", {"status": "ALL"})
            self.assertIn(str(revision.report_id), {row["id"] for row in queue.json()["results"]})
            own = self.read_as(owner, "reports/")
            self.assertEqual({row["id"] for row in own.json()["results"]}, {str(revision.report_id)})

    def test_other_organization_and_channel_key_cannot_probe_publications_or_removals(self):
        revision, _ = self.publish_unit()
        full = Publication.objects.get(report=revision.report, channel=self.channels[2], profile="DEMO-FULL")
        other = Organization.objects.create(code="QA-OTHER", name="Synthetic other organization")
        outsider = get_user_model().objects.create_user(username="qa-outsider", organization=other, role="recipient", display_name="Synthetic outsider")
        foreign_channel = SharingChannel.objects.create(organization=other, code="QA-OTHER", name="Synthetic other channel", max_profile="DEMO-SUMMARY")
        ChannelMember.objects.create(organization=other, user=outsider, channel=foreign_channel, profile_ceiling="DEMO-SUMMARY")
        self.users[outsider.username] = outsider
        for name in (outsider.username, "recipient-summary"):
            response = self.read_as(name, f"publications/{full.id}/")
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json(), self.read_as(name, f"publications/{uuid.uuid4()}/").json())
        _, reader = self.issue_key("DEMO-SUMMARY", 3)
        hidden = reader.get(INTEGRATION + f"publications/{full.id}/")
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(hidden.json(), reader.get(INTEGRATION + f"publications/{uuid.uuid4()}/").json())
        self.withdraw_revision(revision)
        self.assertEqual(reader.get(INTEGRATION + "removed/").json()["results"], [])

    def test_tombstones_require_actual_delivery_and_current_sufficient_ceiling(self):
        revision, _ = self.publish_unit()
        delivered = self.read_as("recipient-full", f"channels/{self.channels[2].id}/feed/").json()["results"][0]
        self.assertTrue(PublicationDelivery.objects.filter(user=self.users["recipient-full"], publication_id=delivered["id"]).exists())
        self.withdraw_revision(revision)
        self.assertEqual(self.read_as("recipient-limited", f"channels/{self.channels[2].id}/removed/").json(), {"results": []})
        rows = self.read_as("recipient-full", f"channels/{self.channels[2].id}/removed/").json()["results"]
        self.assertEqual(rows, [{"publication_id": delivered["id"], "state": "WITHDRAWN"}])
        ChannelMember.objects.filter(user=self.users["recipient-full"], channel=self.channels[2]).update(profile_ceiling="DEMO-SUMMARY")
        self.assertEqual(self.read_as("recipient-full", f"channels/{self.channels[2].id}/removed/").json(), {"results": []})

    def test_unapproved_lower_profile_never_fabricated_and_summary_area_refused(self):
        self.publish_unit(profiles=["DEMO-FULL"])
        self.assertEqual(self.read_as("recipient-limited", f"channels/{self.channels[2].id}/feed/").json()["count"], 0)
        for path in ("feed", "map"):
            response = self.read_as("recipient-summary", f"channels/{self.channels[3].id}/{path}/", {"area": "Area A"})
            self.assertEqual(response.status_code, 400)
        denied = self.read_as("recipient-limited", f"channels/{self.channels[2].id}/feed/", {"profile": "DEMO-FULL"})
        self.assertEqual(denied.status_code, 400)

    def test_foreign_organization_key_and_cross_client_cursor_are_bound_to_principal(self):
        for _ in range(2):
            self.publish_unit()
        _, first = self.issue_key()
        cursor = first.get(INTEGRATION + "publications/", {"limit": 1}).json()["next_cursor"]
        _, second = self.issue_key()
        for reader, params in ((second, {"limit": 1, "cursor": cursor}), (first, {"limit": 1, "cursor": cursor + "x"}), (first, {"limit": 2, "cursor": cursor})):
            response = reader.get(INTEGRATION + "publications/", params)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["code"], "INVALID_CURSOR")
            self.assertIn("no-store", response["Cache-Control"])
        other = Organization.objects.create(code="QA-FOREIGN-KEY", name="Synthetic other organization")
        source_policy = PolicyVersion.objects.get(organization=self.org, version="demo-policy-v1")
        target = PolicyVersion.objects.create(organization=other, version=source_policy.version, rules=source_policy.rules, rules_hash=source_policy.rules_hash, active=True)
        other.active_policy = target
        other.save(update_fields=["active_policy"])
        channel = SharingChannel.objects.create(organization=other, code="QA-FOREIGN", name="Synthetic foreign channel", max_profile="DEMO-REDUCED")
        actor = get_user_model().objects.create_user(username="qa-foreign-admin", organization=other, role="administrator", display_name="Synthetic foreign administrator")
        AdminAuthority.objects.create(organization=other, user=actor, kind="INTEGRATION")
        data = {"operation_id": uuid.uuid4(), "channel_id": channel.id, "profile_ceiling": "DEMO-REDUCED", "label": "Synthetic foreign reader", "expires_at": timezone.now() + timedelta(days=2)}
        issued, _ = request_client(actor, data, {key: str(value) for key, value in data.items()})
        reader = APIClient()
        reader.credentials(HTTP_AUTHORIZATION="Bearer " + issued["key"])
        self.assertEqual(reader.get(INTEGRATION + "publications/").json()["results"], [])
        hidden = Publication.objects.filter(organization=self.org).first()
        response = reader.get(INTEGRATION + f"publications/{hidden.id}/")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), reader.get(INTEGRATION + f"publications/{uuid.uuid4()}/").json())
        self.assertEqual(reader.get(INTEGRATION + "removed/").json()["results"], [])

    def test_current_scope_precedes_historical_batch_and_withdrawal_replays(self):
        revision, raw = self.prepared()
        data, body = self.decision_data(revision)
        decide_batch(self.reviewer, revision.id, data, body)
        UnitMembership.objects.filter(user=self.reviewer, unit=self.units[2]).update(active=False)
        from apps.operations.errors import ApiError
        with self.assertRaises(ApiError) as caught:
            decide_batch(self.reviewer, revision.id, data, body)
        self.assertEqual(caught.exception.status_code, 404)
        UnitMembership.objects.filter(user=self.reviewer, unit=self.units[2]).update(active=True)
        withdrawal = {"operation_id": uuid.uuid4(), "expected_revision_no": 1, "reason": "Synthetic private withdrawal"}
        wire = {**withdrawal, "operation_id": str(withdrawal["operation_id"])}
        withdraw_report(self.reviewer, revision.report_id, withdrawal, wire)
        UnitMembership.objects.filter(user=self.reviewer, unit=self.units[2]).update(active=False)
        with self.assertRaises(ApiError) as caught:
            withdraw_report(self.reviewer, revision.report_id, withdrawal, wire)
        self.assertEqual(caught.exception.status_code, 404)

    def test_policy_deactivation_closes_all_live_outputs_and_aba_never_revives(self):
        revision, _ = self.publish_unit()
        _, reader = self.issue_key()
        delivered = self.read_as("recipient-full", f"channels/{self.channels[2].id}/feed/").json()["results"][0]
        policy.apply(self.second, self.proposal("demo-policy-v1", "DEACTIVATE"))
        result = self.read_as("recipient-full", f"channels/{self.channels[2].id}/feed/")
        self.assertEqual(result.json()["count"], 0)
        self.assertEqual(result.json()["summary"]["by_category"], {})
        self.assertEqual(self.read_as("recipient-full", f"channels/{self.channels[2].id}/map/").json(), {"areas": [], "unmapped": 0})
        self.assertEqual(self.read_as("recipient-full", f"publications/{delivered['id']}/").status_code, 404)
        self.assertEqual(reader.get(INTEGRATION + "publications/").status_code, 401)
        policy.apply(self.second, self.proposal("demo-policy-v1"))
        self.assertEqual(self.read_as("recipient-full", f"channels/{self.channels[2].id}/feed/").json()["count"], 0)
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())

    def test_current_submitter_scope_precedes_accepted_correction_replay(self):
        from apps.operations.errors import ApiError
        from apps.reports.services import accept_operation
        revision, raw = self.publish_unit()
        correction = {**raw, "operation_id": str(uuid.uuid4()), "expected_revision": 1,
                      "correction_reason": "Synthetic private correction"}
        result, created = accept_operation(self.author, correction, correction)
        self.assertTrue(created)
        self.assertEqual(result["revision_no"], 2)
        UnitMembership.objects.filter(user=self.author, unit=self.units[2]).update(active=False)
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, correction, correction)
        self.assertEqual(caught.exception.status_code, 403)
