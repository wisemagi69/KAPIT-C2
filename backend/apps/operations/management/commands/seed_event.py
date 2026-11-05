"""Provision the exercise organization, Los Baños scope and operator accounts. Never creates reports.

Passwords arrive only through the environment from the private operator-accounts file
(infra/local.py); they are never printed, logged or accepted on the command line.
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

ORGANIZATION = ("KAPIT-TRN-01", "KAPIT-C2 Training Organization")
UNIT = ("LB-MAINT-01", "Los Baños Maintenance Unit")
CHANNEL = ("CH-LB-01", "Maintenance Coordination")
# Stable policy identifier from apps.reports.projection.POLICIES (shown to people as "Policy v1").
POLICY_VERSION = "demo-policy-v1"
MAX_PROFILE = "DEMO-FULL"
EARLIER_EXAMPLE_ORGANIZATION = "SIM-ORG-01"
ACCOUNTS = [
    ("admin", "Exercise Administrator", "administrator", "KAPIT_EVENT_ADMIN_PASSWORD"),
    ("ops-submitter", "Operator Check (Submitter)", "submitter", "KAPIT_OPERATOR_PASSWORD"),
    ("ops-recipient", "Operator Check (Recipient)", "recipient", "KAPIT_OPERATOR_PASSWORD"),
]


class Command(BaseCommand):
    help = "Create the exercise organization, scope and operator accounts. Existing accounts and passwords are untouched."

    @transaction.atomic
    def handle(self, *args, **options):
        if Organization.objects.filter(code=EARLIER_EXAMPLE_ORGANIZATION).exists():
            raise CommandError("This database holds the earlier example data. Archive it before event provisioning; nothing was changed.")
        passwords = {}
        for _, _, _, variable in ACCOUNTS:
            value = os.environ.get(variable, "")
            try:
                validate_password(value)
            except ValidationError:
                raise CommandError("Provisioning passwords are missing or too weak; nothing was changed.") from None
            passwords[variable] = value
        org, _ = Organization.objects.get_or_create(code=ORGANIZATION[0], defaults={"name": ORGANIZATION[1]})
        org = Organization.objects.select_for_update().get(pk=org.pk)
        unit, _ = Unit.objects.get_or_create(organization=org, code=UNIT[0], defaults={"name": UNIT[1]})
        # A maximum profile on the channel and its source selects the multi-view workflow:
        # reviewers approve Full / Reduced / Summary views separately, and recipients get the area map.
        channel, _ = SharingChannel.objects.get_or_create(organization=org, code=CHANNEL[0], defaults={"name": CHANNEL[1], "max_profile": MAX_PROFILE})
        source, _ = ChannelSource.objects.get_or_create(organization=org, channel=channel, unit=unit, defaults={"max_profile": MAX_PROFILE})
        if not (org.active and unit.active and channel.active and source.active):
            raise CommandError("The existing exercise scope is inactive. Review it before proceeding.")
        if channel.max_profile != MAX_PROFILE or source.max_profile != MAX_PROFILE:
            raise CommandError("The existing exercise scope differs. Review it before proceeding.")
        if not PolicyActivation.objects.filter(organization=org).exists():
            policy, _ = PolicyVersion.objects.get_or_create(organization=org, version=POLICY_VERSION,
                                                            defaults={"rules": RULES, "rules_hash": digest(RULES), "active": True})
            if policy.rules != RULES or policy.rules_hash != digest(RULES) or not policy.active:
                raise CommandError("The existing exercise policy differs. Review it before proceeding.")
            if org.active_policy_id not in {None, policy.id}:
                raise CommandError("A different policy is active. Review it before proceeding.")
            org.active_policy = policy
            org.save(update_fields=["active_policy"])
        user_model = get_user_model()
        notices = []
        for username, display, role, variable in ACCOUNTS:
            user, created = user_model.objects.get_or_create(username=username, defaults={"organization": org, "display_name": display, "role": role})
            if user.organization_id != org.id or user.role != role:
                raise CommandError("An existing operator username has another scope or role. No changes were made.")
            if not created:
                # Existing accounts, passwords and grants are never changed here; say so without any secret.
                notices.append(f"{username}: existing account retained; the private file's password was not applied.")
                if not user.is_active:
                    notices.append(f"{username}: account is inactive.")
                if role == "submitter" and not UnitMembership.objects.filter(user=user, unit=unit, role=role, active=True).exists():
                    notices.append(f"{username}: no active membership in the exercise unit.")
                if role == "recipient" and not ChannelMember.objects.filter(user=user, channel=channel, active=True, revoked_at__isnull=True).exists():
                    notices.append(f"{username}: no active grant on the exercise channel.")
                continue
            user.set_password(passwords[variable])
            user.save(update_fields=["password"])
            if role == "submitter":
                UnitMembership.objects.get_or_create(organization=org, user=user, unit=unit, role=role)
            elif role == "recipient":
                ChannelMember.objects.get_or_create(organization=org, user=user, channel=channel, defaults={"profile_ceiling": "DEMO-REDUCED"})
        for notice in notices:
            self.stdout.write(self.style.WARNING(notice))
        self.stdout.write(self.style.SUCCESS("Exercise organization, Los Baños scope and operator accounts are ready. No reports were created."))
