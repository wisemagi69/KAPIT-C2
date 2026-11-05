"""Manual, atomic, refusal-only fictional topology provisioning."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.core.exceptions import MultipleObjectsReturned

from apps.reports.canonical import digest
from apps.reports.models import Report
from apps.reports.projection import RULES_V2
from apps.scopes.models import (AdminAuthority, ChannelMember, ChannelSource, Organization,
    PolicyVersion, SharingChannel, Unit, UnitMembership)

PASSWORD = "DemoMaintenance!2026"  # Local synthetic accounts only, same documented M1 password.


def ensure(model, lookup, values):
    try:
        row, created = model.objects.get_or_create(**lookup, defaults=values)
    except MultipleObjectsReturned:
        raise CommandError("M3_SEED_DIFFERENCE: historical configuration differs; no changes were made.") from None
    if not created and any(getattr(row, key) != value for key, value in values.items()):
        raise CommandError("M3_SEED_DIFFERENCE: existing synthetic configuration differs; no changes were made.")
    return row


class Command(BaseCommand):
    help = "Manually provision fictional M3 topology; refuses differences and never revives access."

    @transaction.atomic
    def handle(self, *args, **options):
        org = Organization.objects.select_for_update().filter(code="SIM-ORG-01", active=True).first()
        if org is None:
            raise CommandError("M3_SEED_BASE_MISSING: provision M1 first.")
        unit1 = Unit.objects.filter(organization=org, code="SIM-UNIT-01", active=True).first()
        channel1 = SharingChannel.objects.filter(organization=org, code="CH-DEMO-01", active=True, max_profile__isnull=True).first()
        if unit1 is None or channel1 is None or not ChannelSource.objects.filter(
            organization=org, unit=unit1, channel=channel1, active=True, max_profile__isnull=True).exists():
            raise CommandError("M3_SEED_BASE_DIFFERENCE: M1 topology must remain unchanged.")
        if ChannelSource.objects.filter(unit=unit1).exclude(organization=org, channel=channel1).exists():
            raise CommandError("M3_SEED_BASE_DIFFERENCE: M1 topology must remain unchanged.")
        if Report.objects.filter(organization=org, unit__code__in=["SIM-UNIT-02", "SIM-UNIT-03"]).exists():
            raise CommandError("M3_SEED_REPORTS_EXIST: use reviewed topology services after reporting starts.")
        units = {n: ensure(Unit, {"organization": org, "code": f"SIM-UNIT-0{n}"},
            {"name": name, "active": True, "scope_epoch": 0}) for n, name in (
                (2, "Simulated Water Supply Section"), (3, "Simulated Equipment Workshop"))}
        channels = {1: channel1}
        for n, name, ceiling in ((2, "Water Supply Coordination", "DEMO-FULL"), (3, "Regional Summary", "DEMO-SUMMARY")):
            channels[n] = ensure(SharingChannel, {"organization": org, "code": f"CH-DEMO-0{n}"},
                {"name": name, "active": True, "max_profile": ceiling})
        for unit_no, channel_no, ceiling in ((2, 2, "DEMO-FULL"), (2, 3, "DEMO-SUMMARY"),
                (3, 1, "DEMO-REDUCED"), (3, 3, "DEMO-SUMMARY")):
            ensure(ChannelSource, {"organization": org, "unit": units[unit_no], "channel": channels[channel_no]},
                {"active": True, "max_profile": ceiling})
        for n, allowed in ((2, [channels[2].id, channels[3].id]), (3, [channel1.id, channels[3].id])):
            if ChannelSource.objects.filter(unit=units[n]).exclude(organization=org, channel_id__in=allowed).exists():
                raise CommandError("M3_SEED_SOURCE_DIFFERENCE: existing source set differs.")
        user_model = get_user_model()

        def account(name, role, display):
            row, created = user_model.objects.get_or_create(username=name, defaults={
                "organization": org, "role": role, "display_name": display})
            if created:
                row.set_password(PASSWORD)
                row.save(update_fields=["password"])
            if (row.organization_id != org.id or row.role != role or not row.is_active or
                    row.display_name != display or not row.check_password(PASSWORD)):
                raise CommandError("M3_SEED_ACCOUNT_DIFFERENCE: existing account differs; no changes were made.")
            return row

        for n in (2, 3):
            for role in ("submitter", "reviewer"):
                user = account(f"{role}{n}", role, f"Synthetic {role} {n}")
                ensure(UnitMembership, {"organization": org, "user": user, "unit": units[n], "role": role},
                    {"active": True, "valid_until": None})
                if UnitMembership.objects.filter(user=user).exclude(unit=units[n], role=role).exists() or ChannelMember.objects.filter(user=user).exists():
                    raise CommandError("M3_SEED_ASSIGNMENT_DIFFERENCE: existing assignment differs.")
        recipients = {
            "recipient-full": [(2, "DEMO-FULL")], "recipient-limited": [(2, "DEMO-REDUCED")],
            "recipient-summary": [(3, "DEMO-SUMMARY")],
            "recipient-multi": [(1, "DEMO-REDUCED"), (3, "DEMO-SUMMARY")],
        }
        for name, assignments in recipients.items():
            user = account(name, "recipient", f"Synthetic {name}")
            expected = []
            for n, ceiling in assignments:
                expected.append(ensure(ChannelMember, {"organization": org, "user": user, "channel": channels[n]},
                    {"profile_ceiling": ceiling, "active": True, "revoked_at": None, "valid_until": None}).id)
            if ChannelMember.objects.filter(user=user).exclude(id__in=expected).exists() or UnitMembership.objects.filter(user=user).exists():
                raise CommandError("M3_SEED_ASSIGNMENT_DIFFERENCE: existing assignment differs.")
        first = user_model.objects.filter(username="administrator", organization=org, role="administrator", is_active=True).first()
        if first is None or not first.check_password(PASSWORD):
            raise CommandError("M3_SEED_ADMIN_DIFFERENCE: existing administrator differs.")
        second = account("administrator2", "administrator", "Synthetic administrator 2")
        for user in (first, second):
            for kind in ("POLICY", "INTEGRATION"):
                ensure(AdminAuthority, {"organization": org, "user": user, "kind": kind}, {"active": True})
        ensure(PolicyVersion, {"organization": org, "version": "demo-policy-v2"},
            {"rules": RULES_V2, "rules_hash": digest(RULES_V2), "active": False})
        self.stdout.write("M3 synthetic topology ready. No reports, decisions, publications or keys created.")
