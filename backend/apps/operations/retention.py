"""Pure dry-run retention inventory. No database access, identifiers or purge API.

Explicit caller-supplied proposed windows classify review candidates only. Nothing
returned by this module authorizes deleting bytes, identities, rows or keys.
"""
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta


CATEGORIES = frozenset({"MOBILE_OUTBOX", "ACKNOWLEDGED_LOCAL_ORIGINAL", "SOURCE", "CANDIDATE",
                        "FINDING", "EVIDENCE", "PUBLICATION", "DELIVERY", "TOMBSTONE", "RESPONSE_BODY",
                        "OPERATION_IDENTITY", "AUDIT", "SESSION", "BACKUP", "ENCRYPTION_KEY"})
STATES = frozenset({"PENDING", "UNCONFIRMED", "CONFIRMED", "FAILED", "REVOKED", "EXPIRED", "ACTIVE", "COMPLETE"})
HOLDS = frozenset({"LEGAL", "EVALUATION", "CORRECTION", "RECOVERY", "DEPENDENCY"})
PROTECTED = frozenset({"MOBILE_OUTBOX", "OPERATION_IDENTITY", "AUDIT", "SOURCE", "PUBLICATION", "DELIVERY",
                       "TOMBSTONE", "ENCRYPTION_KEY"})


@dataclass(frozen=True)
class InventoryItem:
    category: str
    state: str
    created_at: datetime
    confirmed: bool = False
    recovery_complete: bool = False
    holds: tuple[str, ...] = ()


def _aware(value):
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _windows(proposed_windows):
    if not isinstance(proposed_windows, dict):
        raise ValueError("INVALID_WINDOWS")
    for category, duration in proposed_windows.items():
        if category not in CATEGORIES or not isinstance(duration, timedelta) or duration <= timedelta(0):
            raise ValueError("INVALID_WINDOWS")
    return dict(proposed_windows)


def _classification(item, now, windows):
    if type(item) is not InventoryItem:
        return "UNKNOWN", "RETAIN", "UNKNOWN_RECORD"
    category = item.category if isinstance(item.category, str) and item.category in CATEGORIES else "UNKNOWN"
    if category == "UNKNOWN":
        return category, "RETAIN", "UNKNOWN_CATEGORY"
    if not isinstance(item.state, str) or item.state not in STATES:
        return category, "RETAIN", "UNKNOWN_STATE"
    if type(item.holds) is not tuple or any(not isinstance(hold, str) or hold not in HOLDS for hold in item.holds):
        return category, "RETAIN", "UNKNOWN_HOLD"
    if item.holds:
        return category, "RETAIN", "EXPLICIT_HOLD"
    if category in PROTECTED:
        return category, "RETAIN", "PROTECTED_CATEGORY"
    if item.state in {"PENDING", "UNCONFIRMED", "FAILED", "REVOKED", "ACTIVE"}:
        return category, "RETAIN", "STATE_HOLD"
    if type(item.confirmed) is not bool or not item.confirmed:
        return category, "RETAIN", "UNCONFIRMED"
    if type(item.recovery_complete) is not bool or not item.recovery_complete:
        return category, "RETAIN", "RECOVERY_INCOMPLETE"
    if not _aware(item.created_at) or item.created_at > now:
        return category, "RETAIN", "INVALID_CLOCK"
    if category not in windows:
        return category, "RETAIN", "NO_PROPOSED_WINDOW"
    if now - item.created_at < windows[category]:
        return category, "RETAIN", "WITHIN_WINDOW"
    return category, "REVIEW_CANDIDATE", "WINDOW_ELAPSED"


def inventory(items, *, now, proposed_windows):
    """Return only aggregate fixed-code counts; no IDs, free text or source fields.

    `now` is required to make fake-clock evaluation reproducible. Review candidates
    still need a separately approved category policy and runtime implementation.
    Unknown and protected items remain retained regardless of elapsed windows.
    """
    if not _aware(now):
        raise ValueError("INVALID_CLOCK")
    windows = _windows(proposed_windows)
    counts = Counter(_classification(item, now, windows) for item in items)
    return {"mode": "DRY_RUN", "total": sum(counts.values()), "counts": [
        {"category": category, "disposition": disposition, "code": code, "count": count}
        for (category, disposition, code), count in sorted(counts.items())]}
