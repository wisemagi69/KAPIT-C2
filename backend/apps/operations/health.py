"""Content-free worker and backup health: counts, ages and fixed codes only.

Shared by the native `workflow_health` command and the administrator health panel.
Never returns report content, identifiers, caller-controlled labels or file names.
"""
import json
import os
import re
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from django.db.models import Count, Min


STATUSES = ("PENDING", "PROCESSING", "DONE", "FAILED")
POISON_CODES = ("RULE_PROCESSING_FAILED", "ATTEMPTS_EXHAUSTED", "STALE_CONTEXT")

# Same folder and cadence as infra/local.py native_backup and infra/start_local.py BackupScheduler.
BACKUP_DIR = Path(__file__).resolve().parents[3] / ".cache/m1-runtime/backups"
BACKUP_INTERVAL_SECONDS = 20 * 3600
# Approved RPO (ai/reports/M4-completion-user-decisions.json).
BACKUP_RPO_SECONDS = 24 * 3600
_RECORD_NAME = re.compile(r"kapit_m1-\d{8}T\d{12}Z\.json")
_DUMP_NAME = re.compile(r"kapit_m1-\d{8}T\d{12}Z\.dump")
_CLOCK_TOLERANCE_SECONDS = 300


def job_summary(jobs, now):
    """Aggregate a ProcessingJob queryset; the caller chooses its scope."""
    statuses = dict.fromkeys(STATUSES, 0)
    unknown = 0
    for row in jobs.values("status").annotate(count=Count("*")):
        if row["status"] in statuses:
            statuses[row["status"]] += row["count"]
        else:
            unknown += row["count"]
    pending = jobs.filter(status="PENDING").aggregate(oldest=Min("available_at"))["oldest"]
    poison = dict.fromkeys(POISON_CODES, 0)
    for row in jobs.filter(status="FAILED", error_code__in=POISON_CODES).values("error_code").annotate(count=Count("*")):
        poison[row["error_code"]] = row["count"]
    return {
        "by_status": statuses,
        "unknown_status": unknown,
        "expired_leases": jobs.filter(status="PROCESSING", lease_until__lte=now).count(),
        "missing_leases": jobs.filter(status="PROCESSING", lease_until__isnull=True).count(),
        "oldest_pending_available_age_seconds": max(0, int((now - pending).total_seconds())) if pending else None,
        "failures_by_code": poison,
        "unclassified_failures": jobs.filter(status="FAILED").exclude(error_code__in=POISON_CODES).count(),
    }


def _record_epoch(record, now_epoch):
    """created_epoch of a well-formed verified record whose dump is still present, else None."""
    if not _RECORD_NAME.fullmatch(record.name) or record.is_symlink() or not record.is_file() or record.stat().st_size > 16384:
        return None
    value = json.loads(record.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("verified") is not True:
        return None
    name, size, epoch = value.get("file"), value.get("bytes"), value.get("created_epoch")
    if (not isinstance(name, str) or not _DUMP_NAME.fullmatch(name) or name[:-5] != record.name[:-5]
            or type(size) is not int or size <= 0 or type(epoch) not in (int, float) or not 0 < epoch <= now_epoch + _CLOCK_TOLERANCE_SECONDS):
        return None
    dump = record.parent / name
    if dump.is_symlink() or not dump.is_file() or dump.stat().st_size != size:
        return None
    return float(epoch)


def backup_status(now, directory=None):
    """Newest backup recorded as verified at creation (pg_restore --list and digest).

    Reads only small record files and dump sizes; the supervisor re-checks digests
    before relying on a backup. File names and digests are never returned.
    """
    base = {"interval_hours": BACKUP_INTERVAL_SECONDS // 3600, "rpo_hours": BACKUP_RPO_SECONDS // 3600,
            "basis": "RECORDED_VERIFIED_AT_CREATION", "last_verified_utc": None, "age_seconds": None}
    if os.environ.get("KAPIT_RUNTIME_CONTEXT", "native") != "native":
        return {**base, "status": "UNAVAILABLE"}
    directory = BACKUP_DIR if directory is None else directory
    now_epoch = now.timestamp()
    newest = None
    try:
        if directory.is_symlink() or not directory.is_dir():
            return {**base, "status": "NONE"}
        for record in directory.glob("kapit_m1-*.json"):
            try:
                epoch = _record_epoch(record, now_epoch)
            except (OSError, ValueError, UnicodeError, ArithmeticError, RecursionError):
                continue
            if epoch is not None and (newest is None or epoch > newest):
                newest = epoch
    except OSError:
        return {**base, "status": "UNAVAILABLE"}
    if newest is None:
        return {**base, "status": "NONE"}
    age = max(0, int(now_epoch - newest))
    status = "CURRENT" if age < BACKUP_INTERVAL_SECONDS else "DUE" if age < BACKUP_RPO_SECONDS else "OVERDUE"
    stamp = datetime.fromtimestamp(newest, dt_timezone.utc).replace(microsecond=0)
    return {**base, "status": status, "last_verified_utc": stamp.isoformat().replace("+00:00", "Z"), "age_seconds": age}


def organization_health(organization_id, now):
    from .models import ProcessingJob
    return {
        "schema_version": 1,
        "scope": "ORGANIZATION",
        "generated_utc": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "jobs": job_summary(ProcessingJob.objects.filter(organization_id=organization_id), now),
        "backup": backup_status(now),
    }
