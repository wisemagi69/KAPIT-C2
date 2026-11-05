from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.reports.crypto import digest
from apps.reports.projection import RULES
from apps.scopes.models import ChannelMember, ChannelSource, Organization, PolicyVersion, SharingChannel, Unit, UnitMembership, PolicyActivation


class Command(BaseCommand):
    help = "Create fictional local M1 accounts and scope. Never creates decisions or publications."

    @transaction.atomic
    def handle(self, *args, **options):
        org, _ = Organization.objects.get_or_create(code="SIM-ORG-01", defaults={"name": "KAPIT Demonstration Organization"})
        org = Organization.objects.select_for_update().get(pk=org.pk)
        unit, _ = Unit.objects.get_or_create(organization=org, code="SIM-UNIT-01", defaults={"name": "Simulated Support Unit"})
        channel, _ = SharingChannel.objects.get_or_create(organization=org, code="CH-DEMO-01", defaults={"name": "Maintenance Coordination"})
        source, _ = ChannelSource.objects.get_or_create(organization=org, channel=channel, unit=unit)
        if not (org.active and unit.active and channel.active and source.active):
            raise CommandError("The existing fictional scope is inactive. Review it before proceeding.")
        if not PolicyActivation.objects.filter(organization=org).exists():
            policy, _ = PolicyVersion.objects.get_or_create(organization=org, version="demo-policy-v1", defaults={"rules": RULES, "rules_hash": digest(RULES), "active": True})
            if policy.rules != RULES or policy.rules_hash != digest(RULES) or not policy.active:
                raise CommandError("The existing demonstration policy differs. Review it before proceeding.")
            if org.active_policy_id not in {None, policy.id}:
                raise CommandError("A different policy is active. Review it before proceeding.")
            org.active_policy = policy
            org.save(update_fields=["active_policy"])
        user_model = get_user_model()
        for name, display in [("submitter", "Demo Submitter"), ("reviewer", "Originating Reviewer"), ("recipient", "Channel Recipient"), ("administrator", "Demo Administrator")]:
            user, created = user_model.objects.get_or_create(username=name, defaults={"organization": org, "display_name": display, "role": name})
            if user.organization_id != org.id:
                raise CommandError("An existing demonstration username has another scope. No changes were made.")
            # Explicit provisioning is idempotent after business administration:
            # existing accounts, passwords and historical grants are untouched.
            if not created:
                continue
            user.set_password("DemoMaintenance!2026")
            user.save(update_fields=["password"])
            if name in {"submitter", "reviewer"}:
                membership, _ = UnitMembership.objects.get_or_create(organization=org, user=user, unit=unit, role=name)
                if not membership.active or membership.valid_until is not None:
                    raise CommandError("An existing fictional membership differs. Review it before proceeding.")
            elif name == "recipient":
                grant, _ = ChannelMember.objects.get_or_create(organization=org, user=user, channel=channel, defaults={"profile_ceiling": "DEMO-REDUCED"})
                if not grant.active or grant.revoked_at is not None or grant.valid_until is not None or grant.profile_ceiling != "DEMO-REDUCED":
                    raise CommandError("An existing fictional recipient grant differs. Review it before proceeding.")
        self.stdout.write(self.style.SUCCESS("Fictional accounts and local scope are ready. No reports were approved or published."))
