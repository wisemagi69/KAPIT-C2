"""Standard-library selector logic checks; PostgreSQL view cases live in test_m3_views.

AST extraction supplies controlled query/identity capabilities, not database evidence.
"""
import ast
from collections import Counter
import copy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as Object
import unittest
import uuid
from unittest.mock import Mock

try:
    from apps.reports.canonical import digest
    from apps.reports.projection import POLICIES, PROFILE_KEYS, PROFILE_RANK, project, served_published_at, valid_projection
except ModuleNotFoundError:
    from backend.apps.reports.canonical import digest
    from backend.apps.reports.projection import POLICIES, PROFILE_KEYS, PROFILE_RANK, project, served_published_at, valid_projection

ROOT = Path(__file__).resolve().parents[3]


class Denial(Exception):
    pass


class Rows(list):
    def iterator(self, chunk_size):
        return iter(self)


class Params(dict):
    def getlist(self, key):
        return self[key] if isinstance(self[key], list) else [self[key]]
    def dict(self):
        return dict(self)


def extract(path, names, scope):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8-sig"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != set(names):
        raise AssertionError("Required selector functions missing")
    for node in functions:
        node.decorator_list = []
    exec(compile(ast.Module(body=functions, type_ignores=[]), path, "exec"), scope)


def functions():
    scope = {"Counter": Counter, "ApiError": Denial, "digest": digest, "POLICIES": POLICIES,
             "PROFILE_KEYS": PROFILE_KEYS, "PROFILE_RANK": PROFILE_RANK,
             "served_published_at": served_published_at, "valid_projection": valid_projection}
    extract("backend/apps/operations/pagination.py", {"query_values", "pagination_values"}, scope)
    # pagination's fixed regex is a deliberate pure dependency.
    import re
    scope["re"] = re
    extract("backend/apps/publications/selectors.py", {"feed_filters", "matches_projection", "filtered_publications",
        "selected_publications", "serialize_publication", "summarize", "supported_policy", "valid_publication", "_valid_publication"}, scope)
    extract("backend/apps/operations/worker.py", {"binding_for", "candidate_digest"}, scope)
    return scope


class M3PureProfileTests(unittest.TestCase):
    def setUp(self):
        self.scope = functions()
        self.full_scope = Object(ceiling="DEMO-FULL")

    def row(self, profile, text, *, report="report", stamp=None):
        return Object(id=uuid.uuid4(), report_id=report, channel_id="channel", profile=profile,
            published_at=stamp or datetime(2026, 10, 21, 10, 47, 59, tzinfo=timezone.utc),
            projection={"title": "Maintenance", "text": text, "category": "WATER_SUPPLY", "urgency": "ROUTINE"})

    def select(self, rows, *, profile=None, ceiling="DEMO-FULL"):
        self.scope["current_publications"] = lambda *args, **kwargs: (Object(ceiling=ceiling), Rows(rows))
        self.scope["valid_publication"] = lambda value, org: getattr(value, "valid", True)
        return self.scope["selected_publications"](None, None, "channel", profile)[1]

    def test_highest_selection_precedes_filters_without_lower_profile_fallback(self):
        full = self.row("DEMO-FULL", "full-only")
        reduced = self.row("DEMO-REDUCED", "lower-only")
        selected = self.select([reduced, full])
        self.assertEqual(selected, [full])
        options = {"q": "lower-only", "category": "ALL", "urgency": "ALL", "area": "ALL"}
        self.assertEqual(self.scope["filtered_publications"](self.full_scope, selected, options), [])

    def test_only_valid_approved_lower_profile_can_fill_a_lower_ceiling(self):
        full = self.row("DEMO-FULL", "full")
        summary = self.row("DEMO-SUMMARY", "summary")
        self.assertEqual(self.select([full], ceiling="DEMO-REDUCED"), [])
        self.assertEqual(self.select([full, summary], ceiling="DEMO-REDUCED"), [summary])
        summary.valid = False
        self.assertEqual(self.select([full, summary], ceiling="DEMO-REDUCED"), [])

    def test_unknown_or_above_ceiling_profile_rejected_before_iteration(self):
        class ForbiddenRows:
            def iterator(self, **kwargs):
                raise AssertionError("dataset iterated before denied profile")
        self.scope["current_publications"] = lambda *args, **kwargs: (Object(ceiling="DEMO-SUMMARY"), ForbiddenRows())
        for profile in ("DEMO-FULL", "UNKNOWN", []):
            with self.assertRaises(Denial):
                self.scope["selected_publications"](None, None, "channel", profile)

    def test_summary_area_rejected_independent_of_result_existence(self):
        for values in ([], [self.row("DEMO-SUMMARY", "summary")]):
            with self.assertRaises(Denial):
                self.scope["filtered_publications"](Object(ceiling="DEMO-SUMMARY"), values,
                    {"q": "", "category": "ALL", "urgency": "ALL", "area": "Area C"})

    def test_search_uses_only_present_allowlisted_projection_keys(self):
        projection = self.row("DEMO-SUMMARY", "A water supply issue").projection
        projection["private_internal"] = "PRIVATE_SEARCH_CANARY"
        options = {"q": "PRIVATE_SEARCH_CANARY", "category": "ALL", "urgency": "ALL", "area": "ALL"}
        self.assertFalse(self.scope["matches_projection"](projection, options))
        options["q"] = "water supply"
        self.assertTrue(self.scope["matches_projection"](projection, options))
        options.update(q="", area="Area C")
        self.assertFalse(self.scope["matches_projection"](projection, options))

    def test_summary_and_map_inputs_have_no_summary_area_inference(self):
        row = self.row("DEMO-SUMMARY", "summary")
        self.assertEqual(self.scope["summarize"]([row]), {"by_category": {"WATER_SUPPLY": 1},
            "by_urgency": {"ROUTINE": 1}, "by_area": {}, "unmapped": 1})

    def test_one_per_report_channel_and_server_order_are_stable(self):
        first = self.row("DEMO-FULL", "first", report="first", stamp=datetime(2026, 10, 21, 12, tzinfo=timezone.utc))
        low = self.row("DEMO-REDUCED", "lower", report="first")
        second = self.row("DEMO-FULL", "second", report="second", stamp=datetime(2026, 10, 21, 10, tzinfo=timezone.utc))
        self.assertEqual(self.select([second, low, first]), [first, second])

    def test_bounded_duplicate_and_unknown_filters_rejected(self):
        for params in (Params(q=["a", "b"]), Params(profile="UNKNOWN"), Params(area="PRIVATE_CANARY"),
                       Params(narrative="private"), Params(page_size="51"), Params(q="x" * 121)):
            with self.assertRaises(Denial):
                self.scope["feed_filters"](params)
        self.assertEqual(self.scope["feed_filters"](Params(profile="DEMO-SUMMARY"))["profile"], "DEMO-SUMMARY")

    def test_all_profiles_use_frozen_key_allowlists_and_truncate_publication_time(self):
        payload = {"category": "WATER_SUPPLY", "urgency": "ROUTINE", "area_label": "Area C",
            "assistance_requested": "Repair assistance", "observed_at": "2026-10-21T09:47:29Z"}
        for profile in PROFILE_RANK:
            row = self.row(profile, "unused")
            row.channel = Object(id="channel", code="CH", name="Synthetic channel")
            row.projection = project(payload, profile, {"code": "SIM-UNIT-02", "name": "Synthetic unit"} if profile == "DEMO-FULL" else None)
            row.projection["private_unapproved"] = "PRIVATE_SERIALIZER_CANARY"
            result = self.scope["serialize_publication"](row)
            self.assertEqual(set(result), {"id", "published_at", "channel", "projection"})
            self.assertEqual(set(result["projection"]), set(PROFILE_KEYS[profile]))
            self.assertNotIn("PRIVATE", str(result))
            self.assertEqual(result["published_at"], served_published_at(row.published_at, profile))


if __name__ == "__main__":
    unittest.main()
