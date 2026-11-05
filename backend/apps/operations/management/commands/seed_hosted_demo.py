"""Provision the fictional scope for the public hosted demonstration. Never creates reports.

Unlike seed_demo (published fixed password, loopback only), every account password arrives
through the environment from infra/hosted/hosted.py's private file and is never printed.
"""
import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.reports.crypto import digest
from apps.reports.projection import RULES
from apps.scopes.models import ChannelMember, ChannelSource, Organization, PolicyActivation, PolicyVersion, SharingChannel, Unit, UnitMembership

ACCOUNTS = [
    ("submitter", "Demo Submitter", "submitter", "KAPIT_HOSTED_SUBMITTER_PASSWORD"),
    ("reviewer", "Originating Reviewer", "reviewer", "KAPIT_HOSTED_REVIEWER_PASSWORD"),
    ("recipient", "Channel Recipient", "recipient", "KAPIT_HOSTED_RECIPIENT_PASSWORD"),
    ("administrator", "Demo Administrator", "administrator", "KAPIT_HOSTED_ADMINISTRATOR_PASSWORD"),
]


class Command(BaseCommand):
    help = "Create fictional hosted-demo accounts and scope with private random passwords."

    @transaction.atomic
    def handle(self, *args, **options):
        if os.environ.get("KAPIT_RUNTIME_CONTEXT") != "hosted-demo":
            raise CommandError("This command only provisions the hosted demonstration database.")
        passwords = {}
        for _, _, _, variable in ACCOUNTS:
            value = os.environ.get(variable, "")
            try:
                validate_password(value)
            except ValidationError:
                raise CommandError("Provisioning passwords are missing or too weak; nothing was changed.") from None
            if value == "DemoMaintenance!2026":
                raise CommandError("The published local demo password is not permitted online; nothing was changed.")
            passwords[variable] = value
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
        for name, display, role, variable in ACCOUNTS:
            user, created = user_model.objects.get_or_create(username=name, defaults={"organization": org, "display_name": display, "role": role})
            if user.organization_id != org.id:
                raise CommandError("An existing demonstration username has another scope. No changes were made.")
            if not created:
                continue  # Existing accounts, passwords and grants are untouched.
            user.set_password(passwords[variable])
            user.save(update_fields=["password"])
            if role in {"submitter", "reviewer"}:
                membership, _ = UnitMembership.objects.get_or_create(organization=org, user=user, unit=unit, role=role)
                if not membership.active or membership.valid_until is not None:
                    raise CommandError("An existing fictional membership differs. Review it before proceeding.")
            elif role == "recipient":
                grant, _ = ChannelMember.objects.get_or_create(organization=org, user=user, channel=channel, defaults={"profile_ceiling": "DEMO-REDUCED"})
                if not grant.active or grant.revoked_at is not None or grant.valid_until is not None or grant.profile_ceiling != "DEMO-REDUCED":
                    raise CommandError("An existing fictional recipient grant differs. Review it before proceeding.")
        self.stdout.write(self.style.SUCCESS("Fictional hosted accounts and scope are ready. No reports were approved or published."))
