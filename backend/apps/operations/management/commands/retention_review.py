"""Native operator-only proposal gap report. Never activates retention decisions."""
import json
import os
from pathlib import Path
import stat

from django.core.management.base import BaseCommand, CommandError

from apps.operations.retention import CATEGORIES
from apps.operations.retention_policy import MAX_BYTES, parse_policy_draft, summarize_policy_gaps, validate_policy_draft

ROOT = Path(__file__).resolve().parents[5]


def read_workspace_json(path, *, root=ROOT):
    try:
        root = root.resolve(strict=True)
        candidate = Path(path)
        if ".." in candidate.parts:
            raise ValueError
        candidate = candidate if candidate.is_absolute() else root / candidate
        relative = candidate.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
                raise ValueError
        info = candidate.stat()
        if not stat.S_ISREG(info.st_mode) or candidate.suffix.lower() != ".json" or info.st_size > MAX_BYTES:
            raise ValueError
        with candidate.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(opened.st_mode):
                raise ValueError
            # Recheck components after opening; refuse a path redirected between checks.
            current = root
            for part in relative.parts:
                current = current / part
                checked = current.lstat()
                if stat.S_ISLNK(checked.st_mode) or getattr(checked, "st_file_attributes", 0) & 1024:
                    raise ValueError
            raw = stream.read(MAX_BYTES + 1)
        if not 1 <= len(raw) <= MAX_BYTES:
            raise ValueError
        return raw
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ValueError("POLICY_DRAFT_UNAVAILABLE") from None


def proposal_for(path):
    if path is not None:
        return parse_policy_draft(read_workspace_json(path))
    try:
        contract = json.loads(read_workspace_json(ROOT / "contracts/m4/retention-policy-draft.json").decode("utf-8"))
        return validate_policy_draft(contract["default_draft"])
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError("POLICY_DRAFT_UNAVAILABLE") from None


def observations(snapshot):
    if (type(snapshot) is not dict or snapshot.get("mode") != "DRY_RUN" or snapshot.get("disposition") != "RETAIN_ALL"
            or type(snapshot.get("sources")) is not list or len(snapshot["sources"]) > 64):
        raise ValueError("INVALID_POLICY_OBSERVATION")
    result = set()
    for row in snapshot["sources"]:
        if (type(row) is not dict or set(row) != {"category", "status", "count"}
                or type(row["category"]) is not str or row["category"] not in CATEGORIES
                or row["status"] != "COUNTED_METADATA" or type(row["count"]) is not int or row["count"] < 0):
            raise ValueError("INVALID_POLICY_OBSERVATION")
        result.add(row["category"])
    return frozenset(result)


def review(path=None):
    proposal = proposal_for(path)
    # Collector enforces native settings/libpq/ownership proof before its ORM.
    from .retention_inventory import collect_inventory
    return summarize_policy_gaps(proposal, observed_categories=observations(collect_inventory()))


class Command(BaseCommand):
    help = "Native read-only retention proposal gaps; always retain all."
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser):
        parser.add_argument("--proposal-file", default=None)

    def handle(self, *args, **options):
        try:
            result = review(options.get("proposal_file"))
        except ValueError as error:
            code = str(error)
            if code not in {"INVALID_POLICY_DRAFT", "INVALID_POLICY_OBSERVATION", "POLICY_DRAFT_UNAVAILABLE"}:
                code = "POLICY_DRAFT_UNAVAILABLE"
            raise CommandError(code) from None
        self.stdout.write(json.dumps(result, sort_keys=True))
