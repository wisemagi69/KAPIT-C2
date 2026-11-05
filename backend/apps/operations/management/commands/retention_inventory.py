"""Local metadata inventory only. No retention duration, purge or mutation switch."""
import json
import os
from pathlib import Path
import sys

from django.apps import apps
from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, DatabaseError, transaction
from django.utils import timezone

from config.runtime_boundary import native_boundary
from apps.operations.retention import InventoryItem, inventory


def verify_owned_runtime():
    """Read-only existing ownership/process/connection proof, imported lazily."""
    root = str(Path(__file__).resolve().parents[5])
    if root not in sys.path:
        sys.path.insert(0, root)
    from infra import native_postgres
    return native_postgres.status(require_running=True)


def require_native():
    """Refuse hosted/unowned settings before opening a connection or querying ORM."""
    if os.environ.get("KAPIT_RUNTIME_CONTEXT", "native") != "native":
        raise CommandError("NATIVE_ONLY")
    # Existing native proof sanitizes its subprocess environment; the Django
    # connection must not inherit a separate libpq redirect/schema configuration.
    if any(name in os.environ for name in ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS")):
        raise CommandError("NATIVE_ONLY")
    try:
        native_boundary(os.environ)
    except RuntimeError:
        raise CommandError("NATIVE_ONLY") from None
    database = settings.DATABASES["default"]
    if (database.get("ENGINE") != "django.db.backends.postgresql"
            or database.get("HOST") != "127.0.0.1"
            or str(database.get("PORT")) != "55436"
            or database.get("USER") != "kapit_m1"
            or database.get("NAME") not in {"kapit_m1", "test_kapit_m1"}
            or database.get("OPTIONS") != {"connect_timeout": 5}):
        raise CommandError("NATIVE_ONLY")
    try:
        proof = verify_owned_runtime()
        if (not isinstance(proof, dict) or proof.get("state") != "running"
                or proof.get("owned") is not True or proof.get("port") != 55436):
            raise ValueError
    except Exception:
        raise CommandError("NATIVE_ONLY") from None


# One metadata timestamp per row; no ciphertext, payload, original, response,
# reason, finding, session_data, operation digest or key field is selected.
SOURCES = (
    ("SOURCE", "reports.ReportRevision", "received_at"),
    ("CANDIDATE", "reports.ReportVariant", "created_at"),
    ("EVIDENCE", "operations.PrivateEvidence", "created_at"),
    ("EVIDENCE", "operations.PrivateEvidenceValidation", "created_at"),
    ("PUBLICATION", "publications.Publication", "published_at"),
    ("DELIVERY", "publications.PublicationDelivery", "first_delivered_at"),
    ("TOMBSTONE", "publications.PublicationRemoval", "removed_at"),
    ("AUDIT", "audit.AuditEvent", "recorded_at"),
    ("AUDIT", "audit.AnonymousIntegrationFailure", "recorded_at"),
    ("RESPONSE_BODY", "operations.SyncReceipt", "received_at"),
    ("RESPONSE_BODY", "review.ReviewDecision", "recorded_at"),
    ("RESPONSE_BODY", "review.DecisionBatch", "recorded_at"),
    ("OPERATION_IDENTITY", "operations.SyncReceipt", "received_at"),
    ("OPERATION_IDENTITY", "operations.PrivateEvidence", "created_at"),
    ("OPERATION_IDENTITY", "operations.PrivateEvidenceValidation", "created_at"),
    ("OPERATION_IDENTITY", "reports.ReportRevision", "received_at"),
    ("OPERATION_IDENTITY", "review.ReviewDecision", "recorded_at"),
    ("OPERATION_IDENTITY", "review.DecisionBatch", "recorded_at"),
    ("OPERATION_IDENTITY", "publications.RevisionWithdrawal", "withdrawn_at"),
    ("OPERATION_IDENTITY", "scopes.PolicyProposal", "proposed_at"),
    ("OPERATION_IDENTITY", "accounts.IntegrationClientRequest", "created_at"),
)
UNOBSERVABLE = ("MOBILE_OUTBOX", "ACKNOWLEDGED_LOCAL_ORIGINAL", "FINDING", "BACKUP", "ENCRYPTION_KEY")


def collect_inventory():
    require_native()
    now = timezone.now()
    counts, unavailable, sources = {}, [], []
    try:
        with transaction.atomic():
            tables = set(connection.introspection.table_names())
            for category, label, timestamp in SOURCES:
                try:
                    model = apps.get_model(label)
                    model._meta.get_field(timestamp)
                except (LookupError, FieldDoesNotExist):
                    unavailable.append({"category": category, "code": "SCHEMA_UNAVAILABLE"})
                    continue
                if model._meta.db_table not in tables:
                    unavailable.append({"category": category, "code": "SCHEMA_UNAVAILABLE"})
                    continue
                rows = model.objects.values_list(timestamp, flat=True).iterator(chunk_size=200)
                # Hold and recovery knowledge is absent, explicitly retained rather
                # than assuming "no holds" or a made-up creation/acknowledgment age.
                result = inventory((InventoryItem(category, "UNCONFIRMED", created,
                    confirmed=False, recovery_complete=False, holds=("UNKNOWN",)) for created in rows),
                    now=now, proposed_windows={})
                for row in result["counts"]:
                    key = (row["category"], row["disposition"], row["code"])
                    counts[key] = counts.get(key, 0) + row["count"]
                sources.append({"category": category, "status": "COUNTED_METADATA", "count": result["total"]})
            session = apps.get_model("sessions.Session")
            if session._meta.db_table in tables:
                sources.append({"category": "SESSION", "status": "COUNTED_METADATA", "count": session.objects.count()})
                unavailable.append({"category": "SESSION", "code": "CREATION_TIME_UNAVAILABLE"})
            else:
                unavailable.append({"category": "SESSION", "code": "SCHEMA_UNAVAILABLE"})
    except DatabaseError:
        raise CommandError("INVENTORY_UNAVAILABLE") from None
    # A category can span several immutable tables. An available subset is not
    # a complete category count, even when that subset contains zero rows.
    incomplete = {row["category"] for row in unavailable if row["code"] == "SCHEMA_UNAVAILABLE"}
    sources = [row for row in sources if row["category"] not in incomplete]
    counts = {key: count for key, count in counts.items() if key[0] not in incomplete}
    unavailable.extend({"category": category, "code": "SOURCE_UNAVAILABLE"} for category in UNOBSERVABLE)
    unavailable.append({"category": "ALL", "code": "HOLDS_RECOVERY_UNAVAILABLE"})
    return {"schema_version": 1, "mode": "DRY_RUN", "completeness": "PARTIAL",
        "policy_status": "NO_ACTIVE_WINDOWS", "disposition": "RETAIN_ALL",
        "counts": [{"category": category, "disposition": disposition, "code": code, "count": count}
                   for (category, disposition, code), count in sorted(counts.items())],
        "sources": sources, "unavailable": unavailable,
        "count_basis": "CATEGORY_MEMBERSHIP_NOT_UNIQUE_OBJECTS"}


class Command(BaseCommand):
    help = "Native operator-only metadata retention inventory; always dry-run/retain-all."
    requires_system_checks = []
    requires_migrations_checks = False

    def handle(self, *args, **options):
        self.stdout.write(json.dumps(collect_inventory(), sort_keys=True))
