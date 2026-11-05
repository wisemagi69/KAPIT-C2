"""Local aggregate worker diagnostics; never expose caller-controlled labels."""
import json

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, DatabaseError, transaction
from django.utils import timezone

from apps.operations.health import job_summary
from .retention_inventory import require_native


def collect_health():
    require_native()
    # Defer model access until the native-only boundary has passed.
    from apps.operations.models import ProcessingJob
    now = timezone.now()
    try:
        with transaction.atomic():
            if ProcessingJob._meta.db_table not in connection.introspection.table_names():
                return {"schema_version": 1, "completeness": "PARTIAL", "status": "SCHEMA_UNAVAILABLE"}
            summary = job_summary(ProcessingJob.objects.all(), now)
    except DatabaseError:
        raise CommandError("HEALTH_UNAVAILABLE") from None
    statuses, unknown = summary["by_status"], summary["unknown_status"]
    missing_lease, unknown_error = summary["missing_leases"], summary["unclassified_failures"]
    return {"schema_version": 1, "completeness": "PARTIAL" if unknown or missing_lease or unknown_error or statuses["PENDING"] else "COMPLETE",
        "status": "AGGREGATE_ONLY", "job_status_counts": statuses, "unknown_status_count": unknown,
        "expired_lease_count": summary["expired_leases"], "missing_lease_count": missing_lease,
        "oldest_pending_age_seconds": None,
        "pending_creation_age_status": "CREATION_TIME_UNAVAILABLE" if statuses["PENDING"] else "NO_PENDING",
        "oldest_pending_available_age_seconds": summary["oldest_pending_available_age_seconds"],
        "available_age_basis": "AVAILABLE_AT_NOT_CREATION_TIME",
        "poison_code_counts": summary["failures_by_code"], "unclassified_failure_count": unknown_error}


class Command(BaseCommand):
    help = "Native operator-only aggregate worker health, without object/content labels."
    requires_system_checks = []
    requires_migrations_checks = False

    def handle(self, *args, **options):
        self.stdout.write(json.dumps(collect_health(), sort_keys=True))
