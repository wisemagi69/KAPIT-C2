"""Actual PostgreSQL recipient/profile/delivery cases; parent owns serialized execution."""
import copy
from datetime import datetime, timedelta
import json
import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.http import QueryDict
from django.test import TestCase, override_settings
from django.urls import path
from django.utils import timezone
from rest_framework.test import APIClient

from apps.operations.errors import ApiError
from apps.operations.serializers import BatchDecisionSerializer, DecisionSerializer, OperationSerializer, WebOperationSerializer
from apps.operations.worker import binding_for, process_one
from apps.publications.models import Publication, PublicationDelivery, PublicationRemoval
from apps.publications.selectors import detail, feed, map_counts, removed, valid_publication
from apps.publications.services import withdraw_report
from apps.publications.views import FeedView, MapView, PublicationView, RemovedView
from apps.reports.models import ReportRevision
from apps.reports.services import accept_operation
from apps.review.services import candidate_set, decide, decide_batch
from apps.reports.workflow import revision_workflow
from apps.scopes.models import ChannelMember, Organization, SharingChannel, Unit
from tests.test_workflow import operation


# Test-only routes: the application operations URL file is deliberately not edited.
urlpatterns = [path("channels/<uuid:channel_id>/feed/", FeedView.as_view()),
               path("channels/<uuid:channel_id>/map/", MapView.as_view()),
               path("channels/<uuid:channel_id>/removed/", RemovedView.as_view()),
               path("publications/<uuid:publication_id>/", PublicationView.as_view())]


@override_settings(ROOT_URLCONF=__name__, KAPIT_SOURCE_KEY=Fernet.generate_key(),
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3RecipientViewsTests(TestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        self.users = {user.username: user for user in get_user_model().objects.all()}
        self.org = Organization.objects.get(code="SIM-ORG-01")
        self.channel = SharingChannel.objects.get(code="CH-DEMO-02")
        self.summary_channel = SharingChannel.objects.get(code="CH-DEMO-03")
        self.client = APIClient()
        self.client.raise_request_exception = False

    def publish(self, profiles=None):
        body = operation()
        serializer = OperationSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        receipt, _ = accept_operation(self.users["submitter2"], serializer.validated_data, body)
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.approve_revision(revision, profiles)
        return revision, body

    def approve_revision(self, revision, profiles=None):
        for _ in range(20):
            if revision.variants.exists():
                break
            self.assertTrue(process_one())
        binding = candidate_set(self.users["reviewer2"], revision.id)["binding"]
        body = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "approve_profiles":
            list(profiles) if profiles is not None else [value["profile"] for value in binding["candidates"]],
            "expected": binding, "reason": None}
        serializer = BatchDecisionSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        return decide_batch(self.users["reviewer2"], revision.id, serializer.validated_data, body)

    def as_user(self, name):
        self.client.force_authenticate(user=self.users[name])

    def get_feed(self, name="recipient-full", query="", channel=None):
        self.as_user(name)
        return self.client.get(f"/channels/{(channel or self.channel).id}/feed/" + query)

    def withdraw(self, revision):
        body = {"operation_id": uuid.uuid4(), "expected_revision_no": revision.revision_no,
                "reason": "PRIVATE_WITHDRAWAL_REASON_CANARY"}
        return withdraw_report(self.users["reviewer2"], revision.report_id, body,
            {**body, "operation_id": str(body["operation_id"])})

    def assert_safe(self, result):
        encoded = json.dumps(result)
        for value in ("PRIVATE_", "reporter_label", "site_label", "narrative", "candidate_hash", "revision_id",
                      "scope_context", "policy_epoch", "scope_epoch", "content_digest", "payload_ciphertext", "deliveries"):
            self.assertNotIn(value, encoded)

    def test_default_highest_profile_before_search_count_summary_and_map(self):
        self.publish()
        response = self.get_feed()
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual((result["count"], len(result["results"])), (1, 1))
        self.assertEqual(result["results"][0]["projection"]["profile"], "DEMO-FULL")
        self.assertEqual(result["summary"]["by_area"], {"Area C": 1})
        self.assert_safe(result)
        # This phrase matches REDUCED but not FULL. Never fall back after filtering.
        filtered = self.get_feed(query="?q=A%20support%20unit")
        self.assertEqual(filtered.json()["count"], 0)
        mapping = self.client.get(f"/channels/{self.channel.id}/map/?q=A%20support%20unit")
        self.assertEqual(mapping.json(), {"areas": [], "unmapped": 0})

    def test_explicit_lower_profile_detail_allowed_without_instant_tombstone(self):
        self.publish()
        result = self.get_feed(query="?profile=DEMO-REDUCED").json()
        publication = result["results"][0]
        self.assertEqual(publication["projection"]["profile"], "DEMO-REDUCED")
        response = self.client.get(f"/publications/{publication['id']}/")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json(), publication)
        self.assertEqual(self.client.get(f"/channels/{self.channel.id}/removed/").json(), {"results": []})
        self.assertEqual(PublicationDelivery.objects.filter(user=self.users["recipient-full"]).count(), 1)

    def test_live_ceiling_cannot_fabricate_unapproved_lower_projection(self):
        self.publish(profiles=["DEMO-FULL"])
        result = self.get_feed(name="recipient-limited")
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(result.json()["count"], 0)
        full = Publication.objects.get(channel=self.channel)
        response = self.client.get(f"/publications/{full.id}/")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(PublicationDelivery.objects.filter(user=self.users["recipient-limited"]).exists())

    def test_summary_has_no_area_filters_geometry_or_private_search(self):
        self.publish()
        result = self.get_feed("recipient-summary", channel=self.summary_channel).json()
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["summary"]["by_area"], {})
        self.assertEqual(result["summary"]["unmapped"], 1)
        self.assertEqual(self.client.get(f"/channels/{self.summary_channel.id}/map/").json(), {"areas": [], "unmapped": 1})
        self.assertEqual(self.client.get(f"/channels/{self.summary_channel.id}/feed/?area=Area%20C").status_code, 400)
        for query in ("Area%20C", "PRIVATE_NARRATIVE_CANARY", "PRIVATE_SITE_CANARY", "Repair%20assistance"):
            self.assertEqual(self.client.get(f"/channels/{self.summary_channel.id}/feed/?q={query}").json()["count"], 0)
        self.assertNotIn("area_label", result["results"][0]["projection"])
        self.assert_safe(result)

    def test_above_ceiling_unknown_and_duplicate_profile_filters_are_uniform(self):
        self.publish()
        for query in ("?profile=DEMO-FULL", "?profile=UNKNOWN", "?profile=DEMO-REDUCED&profile=DEMO-SUMMARY"):
            response = self.get_feed("recipient-limited", query=query)
            self.assertEqual(response.status_code, 400, response.content)
            self.assertEqual(response.json()["code"], "INVALID_FILTER")
            self.assert_safe(response.json())

    def test_scope_denial_precedes_bad_filter_and_wrong_role_has_no_known_id_probe(self):
        self.publish()
        response = self.get_feed("recipient-summary", query="?profile=UNKNOWN&page=bad")
        self.assertEqual(response.status_code, 404)
        publication = Publication.objects.filter(channel=self.channel).first()
        self.as_user("reviewer2")
        for identifier in (publication.id, uuid.uuid4()):
            response = self.client.get(f"/publications/{identifier}/")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()["code"], "ACCESS_DENIED")

    def test_delivery_insert_failure_rolls_back_all_page_records_and_body(self):
        self.publish()
        self.publish()
        real_create = PublicationDelivery.objects.get_or_create
        calls = []
        def fail_second(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise DatabaseError("PRIVATE_DELIVERY_CANARY")
            return real_create(*args, **kwargs)
        with patch("apps.publications.delivery.PublicationDelivery.objects.get_or_create", side_effect=fail_second):
            response = self.get_feed()
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.json()["code"], "SERVER_ERROR")
        self.assertNotIn("PRIVATE_", response.content.decode())
        self.assertNotIn("results", response.json())
        self.assertEqual(PublicationDelivery.objects.count(), 0)

    def test_only_actual_feed_page_and_detail_are_delivered_not_counts_or_map(self):
        self.publish()
        self.publish()
        first = self.get_feed(query="?page_size=1").json()
        self.assertEqual(first["count"], 2)
        self.assertEqual(PublicationDelivery.objects.count(), 1)
        self.client.get(f"/channels/{self.channel.id}/map/")
        self.assertEqual(PublicationDelivery.objects.count(), 1)
        self.client.get(f"/publications/{first['results'][0]['id']}/")
        self.assertEqual(PublicationDelivery.objects.count(), 1)

    def test_malformed_existing_delivery_record_fails_closed(self):
        self.publish()
        publication = Publication.objects.get(channel=self.channel, profile="DEMO-FULL")
        PublicationDelivery.objects.create(organization=self.org, publication=publication,
            user=self.users["recipient-full"], channel=self.channel, profile="DEMO-SUMMARY",
            first_delivered_at=timezone.now())
        response = self.get_feed()
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.json()["code"], "SERVER_ERROR")
        self.assertNotIn("results", response.json())

    def test_removed_only_same_principal_and_delivered_ids_with_uniform_shape(self):
        first, _ = self.publish()
        second, _ = self.publish()
        page = self.get_feed(query="?page_size=1").json()
        seen = page["results"][0]["id"]
        self.withdraw(first)
        self.withdraw(second)
        self.assertEqual(self.client.get(f"/channels/{self.channel.id}/removed/").json(),
            {"results": [{"publication_id": seen, "state": "WITHDRAWN"}]})
        self.as_user("recipient-limited")
        self.assertEqual(self.client.get(f"/channels/{self.channel.id}/removed/").json(), {"results": []})

    def test_downgraded_or_revoked_grant_cannot_get_full_tombstone(self):
        revision, _ = self.publish()
        self.get_feed()
        self.withdraw(revision)
        ChannelMember.objects.filter(user=self.users["recipient-full"], channel=self.channel).update(profile_ceiling="DEMO-REDUCED")
        self.assertEqual(self.client.get(f"/channels/{self.channel.id}/removed/").json(), {"results": []})
        ChannelMember.objects.filter(user=self.users["recipient-full"], channel=self.channel).update(active=False, revoked_at=timezone.now())
        response = self.client.get(f"/channels/{self.channel.id}/removed/")
        self.assertEqual(response.status_code, 404)

    def test_superseded_lower_id_tombstone_never_links_visible_replacement(self):
        revision, original = self.publish(profiles=["DEMO-REDUCED"])
        seen = self.get_feed().json()["results"][0]["id"]
        correction = copy.deepcopy(original)
        correction.update(operation_id=str(uuid.uuid4()), expected_revision=1,
            correction_reason="PRIVATE_CORRECTION_REASON_CANARY")
        correction["payload"]["category"] = "EQUIPMENT"
        serializer = WebOperationSerializer(data=correction)
        serializer.is_valid(raise_exception=True)
        receipt, _ = accept_operation(self.users["submitter2"], serializer.validated_data, correction)
        replacement = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.approve_revision(replacement, ["DEMO-FULL"])
        result = self.get_feed().json()
        self.assertEqual(result["count"], 1)
        new_id = result["results"][0]["id"]
        tombstone = self.client.get(f"/channels/{self.channel.id}/removed/").json()
        self.assertEqual(tombstone, {"results": [{"publication_id": seen, "state": "WITHDRAWN"}]})
        self.assertNotIn(new_id, json.dumps(tombstone))
        self.assertTrue(PublicationRemoval.objects.filter(publication_id=seen).exists())

    def test_direct_scope_epoch_change_invalidates_all_recipient_surfaces_before_regeneration(self):
        revision, _ = self.publish()
        result = self.get_feed().json()
        seen = result["results"][0]["id"]
        unit = Unit.objects.get(pk=revision.report.unit_id)
        unit.scope_epoch += 1
        unit.save(update_fields=["scope_epoch"])
        self.assertEqual(self.get_feed().json()["count"], 0)
        self.assertEqual(self.client.get(f"/channels/{self.channel.id}/map/").json(), {"areas": [], "unmapped": 0})
        self.assertEqual(self.client.get(f"/publications/{seen}/").status_code, 404)
        self.assertEqual(self.client.get(f"/channels/{self.channel.id}/removed/").json(),
                         {"results": [{"publication_id": seen, "state": "WITHDRAWN"}]})

    def test_publication_own_job_policy_context_projection_and_digest_are_rechecked(self):
        revision, _ = self.publish()
        publication = Publication.objects.filter(variant__revision=revision, profile="DEMO-FULL").select_related(
            "channel", "report__unit", "variant__revision__report__unit", "variant__policy", "variant__job", "decision__batch").get()
        self.assertTrue(valid_publication(publication, self.org))
        for mutate in (lambda p: setattr(p.variant.job, "status", "FAILED"),
                       lambda p: setattr(p.variant, "candidate_hash", "0" * 64),
                       lambda p: setattr(p.variant, "scope_context_hash", "f" * 64),
                       lambda p: setattr(p.decision, "binding", {}),
                       lambda p: p.projection.update(narrative="PRIVATE_INVALID_PROJECTION"),
                       lambda p: p.projection["originating_unit"].update(name="Altered unit snapshot")):
            changed = copy.deepcopy(publication)
            mutate(changed)
            self.assertFalse(valid_publication(changed, self.org))

    def test_publication_timestamp_truncates_by_served_profile(self):
        self.publish()
        for name, profile in (("recipient-full", "DEMO-FULL"), ("recipient-limited", "DEMO-REDUCED"), ("recipient-summary", "DEMO-SUMMARY")):
            channel = self.summary_channel if profile == "DEMO-SUMMARY" else self.channel
            item = self.get_feed(name, channel=channel).json()["results"][0]
            stamp = datetime.fromisoformat(item["published_at"])
            self.assertEqual((stamp.minute, stamp.second, stamp.microsecond), (0, 0, 0))
            if profile != "DEMO-FULL":
                self.assertEqual(stamp.hour, 0)
            if profile == "DEMO-SUMMARY":
                self.assertEqual(stamp.weekday(), 0)

    def test_legacy_feed_detail_shape_and_private_workflow_availability_remain(self):
        body = operation()
        initial = OperationSerializer(data=body)
        initial.is_valid(raise_exception=True)
        receipt, _ = accept_operation(self.users["submitter"], initial.validated_data, body)
        self.assertTrue(process_one())
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        variant = revision.variants.get()
        decision = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        serializer = DecisionSerializer(data=decision)
        serializer.is_valid(raise_exception=True)
        decide(self.users["reviewer"], variant.id, serializer.validated_data, decision)
        channel = SharingChannel.objects.get(code="CH-DEMO-01")
        response = self.get_feed("recipient", channel=channel)
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual(set(result), {"results", "count", "page", "page_size", "total_pages", "refreshed_at"})
        publication = result["results"][0]
        self.assertEqual(set(publication), {"id", "published_at", "channel", "projection"})
        self.assertEqual(self.client.get(f"/publications/{publication['id']}/").json(), publication)
        self.assertEqual(revision_workflow(revision.report, revision, self.org)["sharing"]["state"], "AVAILABLE")

    def test_expired_grant_denies_feed_and_known_unknown_details_without_delivery(self):
        self.publish()
        publication = Publication.objects.get(channel=self.channel, profile="DEMO-FULL")
        ChannelMember.objects.filter(user=self.users["recipient-full"], channel=self.channel).update(
            valid_until=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.get_feed().status_code, 404)
        for identifier in (publication.id, uuid.uuid4()):
            response = self.client.get(f"/publications/{identifier}/")
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json()["code"], "NOT_FOUND")
        self.assertFalse(PublicationDelivery.objects.exists())
