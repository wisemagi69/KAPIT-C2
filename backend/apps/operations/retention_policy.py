"""Unapproved retention declarations. No runtime, filesystem or deletion capability."""
from collections import Counter
from dataclasses import dataclass
import json
import re

from .retention import CATEGORIES, HOLDS, PROTECTED

MAX_BYTES = 65536
MAX_SECONDS = 2147483647
CLOCKS = frozenset({"CREATED_AT_UTC", "RECEIVED_AT_UTC", "ACKNOWLEDGED_AT_UTC", "COMPLETED_AT_UTC",
    "RECORDED_AT_UTC", "PUBLISHED_AT_UTC", "FIRST_DELIVERED_AT_UTC", "REMOVED_AT_UTC", "EXPIRES_AT_UTC"})
SCALARS = {"custodian_ref": "CUSTODIAN_UNSET", "duration_seconds": "DURATION_UNSET", "clock": "CLOCK_UNSET",
    "backup_expiry_seconds": "BACKUP_EXPIRY_UNSET", "key_expiry_seconds": "KEY_EXPIRY_UNSET",
    "disposition": "DISPOSITION_UNSET", "reviewer_ref": "REVIEWER_UNSET", "review_interval_seconds": "REVIEW_INTERVAL_UNSET"}
SECONDS = frozenset({"duration_seconds", "backup_expiry_seconds", "key_expiry_seconds", "review_interval_seconds"})


def invalid():
    return ValueError("INVALID_POLICY_DRAFT")


def _bounded_tree(document):
    stack, nodes = [(document, 1)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 2048 or depth > 8:
            raise invalid()
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise invalid()
            stack.extend((child, depth + 1) for child in value.values())
        elif type(value) is list:
            stack.extend((child, depth + 1) for child in value)
        elif value is not None and type(value) not in {str, int}:
            raise invalid()
    try:
        if len(json.dumps(document, ensure_ascii=False).encode("utf-8")) > MAX_BYTES:
            raise invalid()
    except (TypeError, ValueError, UnicodeError, OverflowError):
        raise invalid() from None


def _token(value):
    return value is None or type(value) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value, re.ASCII) is not None


@dataclass(frozen=True)
class CategoryProposal:
    category: str
    status: str
    declarations: tuple
    hold_sources: tuple


@dataclass(frozen=True)
class PolicyDraft:
    categories: tuple


def validate_policy_draft(document):
    _bounded_tree(document)
    if (type(document) is not dict or set(document) != {"schema_version", "status", "categories"}
            or type(document["schema_version"]) is not int or document["schema_version"] != 1
            or document["status"] != "PROPOSED" or type(document["categories"]) is not list
            or len(document["categories"]) != 15):
        raise invalid()
    rows, seen = [], set()
    for row in document["categories"]:
        if type(row) is not dict or set(row) != set(SCALARS) | {"category", "status", "hold_sources"}:
            raise invalid()
        category = row["category"]
        if (type(category) is not str or category not in CATEGORIES or category in seen
                or type(row["status"]) is not str or row["status"] not in {"UNSET", "PROPOSED"}):
            raise invalid()
        seen.add(category)
        holds = row["hold_sources"]
        if type(holds) is not dict or set(holds) != HOLDS or any(not _token(value) for value in holds.values()):
            raise invalid()
        for name in SCALARS:
            value = row[name]
            if value is None:
                continue
            if name in SECONDS:
                if type(value) is not int or not 1 <= value <= MAX_SECONDS:
                    raise invalid()
            elif name in {"custodian_ref", "reviewer_ref"}:
                if not _token(value):
                    raise invalid()
            elif name == "clock":
                if type(value) is not str or value not in CLOCKS:
                    raise invalid()
            elif type(value) is not str or value not in {"RETAIN", "REVIEW_ONLY"}:
                raise invalid()
        populated = any(row[name] is not None for name in SCALARS) or any(value is not None for value in holds.values())
        if (row["status"] == "PROPOSED") != populated:
            raise invalid()
        rows.append(CategoryProposal(category, row["status"], tuple((name, row[name]) for name in sorted(SCALARS)), tuple(sorted(holds.items()))))
    if seen != CATEGORIES:
        raise invalid()
    return PolicyDraft(tuple(sorted(rows, key=lambda row: row.category)))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise invalid()
        result[key] = value
    return result


def parse_policy_draft(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise invalid()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(invalid()))
        return validate_policy_draft(document)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise invalid() from None


def summarize_policy_gaps(proposal, *, observed_categories):
    if (type(observed_categories) is not frozenset or len(observed_categories) > 15
            or any(type(value) is not str or value not in CATEGORIES for value in observed_categories)):
        raise ValueError("INVALID_POLICY_OBSERVATION")
    if type(proposal) is not PolicyDraft or type(proposal.categories) is not tuple:
        raise invalid()
    try:
        document = {"schema_version": 1, "status": "PROPOSED", "categories": []}
        for row in proposal.categories:
            if type(row) is not CategoryProposal or type(row.declarations) is not tuple or type(row.hold_sources) is not tuple:
                raise invalid()
            document["categories"].append({"category": row.category, "status": row.status,
                **_pairs(row.declarations), "hold_sources": _pairs(row.hold_sources)})
        proposal = validate_policy_draft(document)
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise invalid() from None
    counts = Counter()
    for row in proposal.categories:
        def add(code, count=1):
            if count:
                counts[row.category, code] += count
        for code in ("APPROVAL_REQUIRED", "HOLD_KNOWLEDGE_UNCONFIRMED", "RECOVERY_UNCONFIRMED"):
            add(code)
        if row.category not in observed_categories:
            add("NATIVE_COVERAGE_UNAVAILABLE")
        if row.category in PROTECTED:
            add("PROTECTED_CATEGORY")
        if row.status == "UNSET":
            add("CATEGORY_UNSET")
        for name, value in row.declarations:
            if value is None:
                add(SCALARS[name])
        add("HOLD_SOURCE_UNSET", sum(value is None for _, value in row.hold_sources))
    return {"schema_version": 1, "mode": "DRY_RUN", "policy_status": "PROPOSED_ONLY", "disposition": "RETAIN_ALL",
        "category_count": 15, "counts": [{"category": category, "code": code, "count": count}
            for (category, code), count in sorted(counts.items())]}
