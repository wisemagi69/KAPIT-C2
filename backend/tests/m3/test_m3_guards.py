"""TASK-122: real PostgreSQL checks of the M3 guard triggers (operations 0005_m3_guards); never SQLite or a mocked DB."""
from datetime import timedelta
import json
import random
import uuid

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError, connection, transaction
from django.db.models import F
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.accounts.models import IntegrationClient, IntegrationClientApproval, IntegrationClientRequest
from apps.operations.models import ProcessingJob
from apps.publications.models import Publication, RevisionWithdrawal
from apps.reports.canonical import digest
from apps.reports.crypto import source_payload
from apps.reports.models import ReportVariant
from apps.reports.projection import RULES_V2, project
from apps.reports.scope_context import build_context, context_hash
from apps.review.models import DecisionBatch, ReviewDecision
from apps.scopes.models import (AdminAuthority, ChannelSource, Organization, PolicyActivation, PolicyProposal, PolicyVersion,
                                SharingChannel, Unit)
from tests.test_workflow import WorkflowTests


def rejected(test):
    return test.assertRaises(DatabaseError)


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3GuardTests(TestCase):
    setUp = WorkflowTests.setUp
    sign_in = WorkflowTests.sign_in
    submit = WorkflowTests.submit
    candidate = WorkflowTests.candidate

    def administrators(self):
        users = get_user_model()
        first = users.objects.get(username="administrator")
        second = users.objects.create(organization=self.org, username="administrator-2", display_name="Second administrator",
                                      role="administrator", is_active=True)
        return first, second

    def sql_context(self, unit):
        with connection.cursor() as cursor:
            cursor.execute("SELECT kapit_scope_context(%s)", [unit.id])
            value = cursor.fetchone()[0]
        return json.loads(value) if isinstance(value, str) else value

    def python_context(self, unit):
        unit.refresh_from_db()
        sources = [{"channel_id": str(s.channel_id), "channel_max": s.channel.max_profile, "source_max": s.max_profile}
                   for s in ChannelSource.objects.select_related("channel").filter(unit=unit, active=True, channel__active=True, unit__active=True)]
        if not sources:
            return None
        return build_context(unit.id, Organization.objects.get(pk=unit.organization_id).policy_epoch, unit.scope_epoch, sources)

    def m3_sources(self):
        SharingChannel.objects.filter(pk=self.channel.pk).update(max_profile="DEMO-FULL")
        ChannelSource.objects.filter(channel=self.channel, unit=self.unit).update(max_profile="DEMO-FULL")

    def test_epochs_reject_negative_initial_values(self):
        with rejected(self), transaction.atomic():
            Organization.objects.create(code="NEGATIVE-EPOCH", name="Synthetic", policy_epoch=-1)
        with rejected(self), transaction.atomic():
            Unit.objects.create(organization=self.org, code="NEGATIVE-EPOCH", name="Synthetic", scope_epoch=-1)
        _, _, variant, _ = self.candidate()
        for field in ("policy_epoch", "scope_epoch"):
            with self.subTest(field=field), rejected(self), transaction.atomic():
                ProcessingJob.objects.create(organization=self.org, revision=variant.revision, policy=variant.policy,
                    channel_ids=variant.channel_ids, available_at=timezone.now(), **{field: -1})

    def test_context_and_hash_must_be_a_complete_pair(self):
        _, _, variant, _ = self.candidate()
        for context, context_digest in (({}, None), (None, "a" * 64), ({}, "invalid")):
            with self.subTest(context=context, digest=context_digest), rejected(self), transaction.atomic():
                ProcessingJob.objects.create(organization=self.org, revision=variant.revision, policy=variant.policy,
                    channel_ids=variant.channel_ids, available_at=timezone.now(), scope_context=context,
                    scope_context_hash=context_digest, policy_epoch=1)

    def test_epochs_only_advance_by_one(self):
        for model, pk, field in [(Organization, self.org.pk, "policy_epoch"), (Unit, self.unit.pk, "scope_epoch")]:
            with self.subTest(field=field):
                model.objects.filter(pk=pk).update(**{field: F(field) + 1})
                for value in (F(field) + 2, F(field) - 1, 0):
                    with rejected(self), transaction.atomic():
                        model.objects.filter(pk=pk).update(**{field: value})
                self.assertEqual(getattr(model.objects.get(pk=pk), field), 1)

    def test_sql_scope_context_matches_python_build_context(self):
        self.assertIsNone(self.sql_context(self.unit))  # seeded single source, both maxima NULL: legacy
        self.assertIsNone(self.python_context(self.unit))
        extra = SharingChannel.objects.create(organization=self.org, code="CH-M3-SUMMARY", name="Synthetic summary channel", max_profile="DEMO-SUMMARY")
        ChannelSource.objects.create(organization=self.org, channel=extra, unit=self.unit)
        steps = [
            lambda: None,
            lambda: SharingChannel.objects.filter(pk=self.channel.pk).update(max_profile="DEMO-FULL"),
            lambda: ChannelSource.objects.filter(channel=self.channel).update(max_profile="DEMO-FULL"),
            lambda: Organization.objects.filter(pk=self.org.pk).update(policy_epoch=F("policy_epoch") + 1),
            lambda: Unit.objects.filter(pk=self.unit.pk).update(scope_epoch=F("scope_epoch") + 1),
            lambda: ChannelSource.objects.filter(channel=extra).update(active=False),
        ]
        hashes = []
        for number, step in enumerate(steps):
            step()
            with self.subTest(step=number):
                expected = self.python_context(self.unit)
                self.assertEqual(self.sql_context(self.unit), expected)
                hashes.append(context_hash(expected))
        # A channel maximum above a NULL source maximum (counted as REDUCED) leaves the ceiling unchanged; every other step changes it.
        self.assertEqual(hashes[0], hashes[1])
        self.assertEqual(len(set(hashes)), len(steps) - 1)

    def test_randomized_scope_context_sql_python_parity(self):
        generator = random.Random(120122)
        profiles = [None, "DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"]
        channels = [self.channel] + [SharingChannel.objects.create(organization=self.org,
            code=f"CH-PARITY-{index}", name="Synthetic parity channel") for index in range(3)]
        for channel in channels[1:]:
            ChannelSource.objects.create(organization=self.org, channel=channel, unit=self.unit)
        for index in range(40):
            for channel in channels:
                SharingChannel.objects.filter(pk=channel.id).update(max_profile=generator.choice(profiles),
                    active=generator.choice([True, True, False]))
                ChannelSource.objects.filter(channel=channel, unit=self.unit).update(
                    max_profile=generator.choice(profiles), active=generator.choice([True, True, False]))
            Unit.objects.filter(pk=self.unit.id).update(scope_epoch=F("scope_epoch") + 1)
            Organization.objects.filter(pk=self.org.id).update(policy_epoch=F("policy_epoch") + 1)
            with self.subTest(topology=index):
                self.assertEqual(self.sql_context(self.unit), self.python_context(self.unit))

    def m3_variant(self, profile="DEMO-SUMMARY"):
        body, _, legacy, _ = self.candidate()
        self.m3_sources()
        context = self.python_context(self.unit)
        job = ProcessingJob.objects.create(organization=self.org, revision=legacy.revision, policy=legacy.policy, channel_ids=[str(self.channel.id)],
                                           available_at=timezone.now(), scope_context=context, scope_context_hash=context_hash(context))
        payload = source_payload(legacy.revision)
        projection = project(payload, profile, {"code": self.unit.code, "name": self.unit.name} if profile == "DEMO-FULL" else None)
        fields = dict(organization=self.org, revision=legacy.revision, policy=legacy.policy, job=job, profile=profile, projection=projection,
                      candidate_hash=digest(projection), channel_ids=[str(self.channel.id)], scope_context_hash=job.scope_context_hash)
        return body, legacy, job, fields

    def test_variant_source_link_legacy_and_m3_contexts(self):
        _, legacy, job, fields = self.m3_variant()
        for bad in ({"channel_ids": []}, {"scope_context_hash": None}, {"scope_context_hash": "e" * 64}, {"channel_ids": [str(uuid.uuid4())]}):
            with self.subTest(bad=bad), rejected(self), transaction.atomic():
                ReportVariant.objects.create(**{**fields, **bad})
        ReportVariant.objects.create(**fields)
        # A legacy (NULL-context) job keeps the exact M1 rule and refuses any context hash.
        with rejected(self), transaction.atomic():
            ReportVariant.objects.create(**{**fields, "job": legacy.job, "profile": "DEMO-REDUCED", "projection": legacy.projection})

    def binding(self, variant):
        revision = variant.revision
        return {"revision_id": str(revision.id), "revision_no": revision.revision_no, "candidate_hash": variant.candidate_hash,
                "profile": variant.profile, "channel_ids": variant.channel_ids, "policy_version": variant.policy.version,
                "policy_hash": variant.policy.rules_hash, "scope_context_hash": variant.scope_context_hash}

    def test_m3_decision_and_publication_bind_batch_context_epochs_and_withdrawal(self):
        _, legacy, job, fields = self.m3_variant()
        variant = ReportVariant.objects.create(**fields)
        ReportVariant.objects.filter(pk=variant.pk).update(state="APPROVED")
        variant.refresh_from_db()
        batch = DecisionBatch.objects.create(organization=self.org, reviewer=self.reviewer, revision=variant.revision, operation_id=uuid.uuid4(),
                                             request_hash="a" * 64, action="APPROVE", binding={}, response_body={})
        decision = dict(organization=self.org, variant=variant, reviewer=self.reviewer, operation_id=uuid.uuid4(), request_hash="b" * 64,
                        action="APPROVE", binding=self.binding(variant), response_body={}, batch=batch)
        for label, change in [("no batch", lambda: decision.update(batch=None)),
                              ("binding hash", lambda: decision.update(binding={**self.binding(variant), "scope_context_hash": "f" * 64})),
                              ("stale scope epoch", lambda: Unit.objects.filter(pk=self.unit.pk).update(scope_epoch=F("scope_epoch") + 1)),
                              ("stale policy epoch", lambda: Organization.objects.filter(pk=self.org.pk).update(policy_epoch=F("policy_epoch") + 1)),
                              ("changed sources", lambda: ChannelSource.objects.filter(channel=self.channel).update(max_profile="DEMO-REDUCED")),
                              ("withdrawn", lambda: RevisionWithdrawal.objects.create(
                                  organization=self.org, revision=variant.revision, report=variant.revision.report, reviewer=self.reviewer,
                                  operation_id=uuid.uuid4(), request_hash="c" * 64, expected_revision_no=1, reason_ciphertext=b"synthetic",
                                  publication_ids=[], response_body={}, withdrawn_at=timezone.now()))]:
            saved = dict(decision)
            with self.subTest(label), rejected(self), transaction.atomic():
                change()
                ReviewDecision.objects.create(**decision)
            decision.clear()
            decision.update(saved)
        recorded = ReviewDecision.objects.create(**decision)
        publication = dict(organization=self.org, variant=variant, decision=recorded, channel=self.channel, report=variant.revision.report,
                           profile=variant.profile, projection=variant.projection)
        with rejected(self), transaction.atomic():
            Unit.objects.filter(pk=self.unit.pk).update(scope_epoch=F("scope_epoch") + 1)
            Publication.objects.create(**publication)
        Publication.objects.create(**publication)

    def test_new_records_are_frozen_and_authority_only_toggles_active(self):
        first, _ = self.administrators()
        authority = AdminAuthority.objects.create(organization=self.org, user=first, kind="POLICY")
        AdminAuthority.objects.filter(pk=authority.pk).update(active=False)
        with rejected(self), transaction.atomic():
            AdminAuthority.objects.filter(pk=authority.pk).update(kind="INTEGRATION")
        with rejected(self), transaction.atomic():
            AdminAuthority.objects.filter(pk=authority.pk).delete()
        other = SharingChannel.objects.create(organization=Organization.objects.create(code="SIM-ORG-M3", name="Other synthetic org"),
                                              code="CH-OTHER", name="Other synthetic channel")
        with rejected(self), transaction.atomic():
            IntegrationClientRequest.objects.create(organization=self.org, requester=first, channel=other, profile_ceiling="DEMO-REDUCED", label="x",
                                                    created_at=timezone.now(), collect_deadline=timezone.now() + timedelta(hours=1),
                                                    expires_at=timezone.now() + timedelta(days=1), operation_id=uuid.uuid4(), request_hash="a" * 64)

    def test_policy_activation_needs_two_current_policy_administrators(self):
        first, second = self.administrators()
        for person in (first, second):
            AdminAuthority.objects.create(organization=self.org, user=person, kind="POLICY")
        target = PolicyVersion.objects.create(organization=self.org, version="demo-policy-v2", rules=RULES_V2, rules_hash=digest(RULES_V2))
        now = timezone.now()
        proposal = PolicyProposal.objects.create(organization=self.org, kind="ACTIVATE", target_policy=target, target_rules_hash=target.rules_hash,
                                                 expected_active_policy=self.org.active_policy, proposer=first,
                                                 proposer_permission_version=first.permission_version, operation_id=uuid.uuid4(),
                                                 request_hash="a" * 64, proposed_at=now, expires_at=now + timedelta(hours=24))
        with self.subTest("same person"), rejected(self), transaction.atomic():
            PolicyActivation.objects.create(organization=self.org, proposal=proposal, activator=first, activated_at=timezone.now())
        for label, change in [("proposer permissions changed", lambda: get_user_model().objects.filter(pk=first.pk).update(permission_version=F("permission_version") + 1)),
                              ("activator lacks authority", lambda: AdminAuthority.objects.filter(user=second).update(active=False)),
                              ("pointer moved", lambda: Organization.objects.filter(pk=self.org.pk).update(active_policy=target))]:
            with self.subTest(label), rejected(self), transaction.atomic():
                change()
                PolicyActivation.objects.create(organization=self.org, proposal=proposal, activator=second, activated_at=timezone.now())
        PolicyActivation.objects.create(organization=self.org, proposal=proposal, activator=second, activated_at=timezone.now())
        with rejected(self), transaction.atomic():
            PolicyProposal.objects.filter(pk=proposal.pk).update(target_rules_hash="f" * 64)

    def client_request(self, requester, ceiling):
        now = timezone.now()
        return IntegrationClientRequest.objects.create(organization=self.org, requester=requester, channel=self.channel, profile_ceiling=ceiling,
                                                       label="Synthetic client", created_at=now, collect_deadline=now + timedelta(hours=1),
                                                       expires_at=now + timedelta(days=30), operation_id=uuid.uuid4(), request_hash="a" * 64)

    def issue(self, request, prefix):
        return IntegrationClient.objects.create(organization=self.org, request=request, channel=request.channel, profile_ceiling=request.profile_ceiling,
                                                label=request.label, key_prefix=prefix, key_digest=uuid.uuid4().hex * 2, created_at=timezone.now(),
                                                expires_at=request.expires_at)

    def test_integration_clients_respect_ceiling_two_person_full_and_one_way_revocation(self):
        first, second = self.administrators()
        for person in (first, second):
            AdminAuthority.objects.create(organization=self.org, user=person, kind="INTEGRATION")
        full = self.client_request(first, "DEMO-FULL")
        with self.subTest("channel maximum NULL counts as REDUCED"), rejected(self), transaction.atomic():
            IntegrationClientApproval.objects.create(organization=self.org, request=full, approver=second, approved_at=timezone.now())
            self.issue(full, "aaaaaaaa")
        SharingChannel.objects.filter(pk=self.channel.pk).update(max_profile="DEMO-FULL")
        with self.subTest("FULL needs an approval"), rejected(self), transaction.atomic():
            self.issue(full, "aaaaaaaa")
        with self.subTest("requester cannot approve"), rejected(self), transaction.atomic():
            IntegrationClientApproval.objects.create(organization=self.org, request=full, approver=first, approved_at=timezone.now())
        reduced = self.client_request(first, "DEMO-REDUCED")
        with self.subTest("only FULL requests take approvals"), rejected(self), transaction.atomic():
            IntegrationClientApproval.objects.create(organization=self.org, request=reduced, approver=second, approved_at=timezone.now())
        self.issue(reduced, "bbbbbbbb")
        IntegrationClientApproval.objects.create(organization=self.org, request=full, approver=second, approved_at=timezone.now())
        client = self.issue(full, "aaaaaaaa")
        IntegrationClient.objects.filter(pk=client.pk).update(revoked_at=timezone.now(), revoked_by=second)
        for change in ({"revoked_at": None, "revoked_by": None}, {"revoked_at": timezone.now() + timedelta(minutes=1)}, {"label": "Renamed"}):
            with self.subTest(change=change), rejected(self), transaction.atomic():
                IntegrationClient.objects.filter(pk=client.pk).update(**change)
