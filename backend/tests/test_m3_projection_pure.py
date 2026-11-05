"""Executed without Django: TASK-123 checks the pure M3 projections against the frozen TASK-120 fixtures."""
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

try:
    # Django management starts with backend/ on its import path.
    from apps.reports import projection as rules
    from apps.reports import scope_context
    from apps.reports.canonical import canonical, digest
except ModuleNotFoundError:
    # Standalone standard-library execution from the project root.
    from backend.apps.reports import projection as rules
    from backend.apps.reports import scope_context
    from backend.apps.reports.canonical import canonical, digest

FIXTURES = Path(__file__).resolve().parents[2] / "contracts/m3"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FrozenProfileTests(unittest.TestCase):
    def setUp(self):
        self.profiles = fixture("profiles.json")
        self.source = self.profiles["source_payload"]
        self.unit = self.profiles["originating_unit_snapshot"]

    def project(self, profile, policy):
        return rules.project(self.source, profile, self.unit if profile == "DEMO-FULL" else None, rules.POLICIES[policy])

    def test_every_profile_and_policy_matches_the_frozen_fixture_exactly(self):
        for policy, outputs in self.profiles["expected"].items():
            for profile, expected in outputs.items():
                with self.subTest(policy=policy, profile=profile):
                    actual = self.project(profile, policy)
                    self.assertEqual(actual, expected)
                    self.assertEqual(list(actual), self.profiles["keys"][profile])
                    self.assertTrue(rules.valid_projection(actual, profile, self.unit if profile == "DEMO-FULL" else None, rules.POLICIES[policy]))

    def test_default_one_argument_calls_are_byte_identical_to_m1(self):
        reduced = rules.project(self.source)
        self.assertEqual(canonical(reduced), canonical(self.profiles["expected"]["demo-policy-v1"]["DEMO-REDUCED"]))
        self.assertEqual(rules.project(self.source), rules._project_m1(self.source))
        self.assertTrue(rules.valid_projection(reduced))
        self.assertIs(rules.RULES_V1, rules.RULES)

    def test_private_fields_never_reach_any_profile(self):
        for policy in rules.POLICIES:
            for profile in rules.PROFILE_KEYS:
                text = json.dumps(self.project(profile, policy))
                for field in rules.RULES["private_fields"]:
                    with self.subTest(policy=policy, profile=profile, field=field):
                        self.assertNotIn(self.source[field], text)

    def test_v2_keeps_every_key_set_and_enum_and_only_changes_wording(self):
        for key in ("categories", "urgencies", "areas", "assistance", "private_fields", "template"):
            self.assertEqual(rules.RULES_V2[key], rules.RULES_V1[key])
        for profile in rules.PROFILE_KEYS:
            v1, v2 = self.project(profile, "demo-policy-v1"), self.project(profile, "demo-policy-v2")
            self.assertEqual(list(v1), list(v2))
            self.assertEqual({k: v for k, v in v1.items() if k != "text"}, {k: v for k, v in v2.items() if k != "text"})
            self.assertNotEqual(v1["text"], v2["text"])
        frozen = fixture("rules-v2.json")
        self.assertEqual(digest(rules.RULES_V1), frozen["rules_v1_hash"])
        self.assertEqual(digest(rules.RULES_V2), frozen["rules_v2_hash"])

    def test_tampered_or_mismatched_projections_fail_closed(self):
        full = self.project("DEMO-FULL", "demo-policy-v1")
        cases = [
            ({**full, "text": "Changed text"}, "DEMO-FULL", self.unit),
            ({**full, "originating_unit": {"code": "OTHER", "name": "Other unit"}}, "DEMO-FULL", self.unit),
            (full, "DEMO-FULL", {"code": "SIM-UNIT-02", "name": "Renamed unit"}),
            ({**full, "narrative": "x"}, "DEMO-FULL", self.unit),
            (self.project("DEMO-SUMMARY", "demo-policy-v1"), "DEMO-REDUCED", None),
            ({**self.project("DEMO-SUMMARY", "demo-policy-v1"), "area_label": "Area B"}, "DEMO-SUMMARY", None),
        ]
        for projection, profile, unit in cases:
            with self.subTest(profile=profile):
                self.assertFalse(rules.valid_projection(projection, profile, unit))
        with self.assertRaises(ValueError):
            rules.project(self.source, "DEMO-FULL")  # FULL needs a unit snapshot
        with self.assertRaises(ValueError):
            rules.project(self.source, "DEMO-SUMMARY", self.unit)  # only FULL carries the unit
        with self.assertRaises(ValueError):
            rules.project(self.source, "DEMO-SECRET")

    def test_published_time_is_served_at_profile_precision(self):
        precision = self.profiles["published_at_precision"]
        stored = datetime.fromisoformat(precision["stored"])
        for profile in rules.PROFILE_KEYS:
            with self.subTest(profile=profile):
                self.assertEqual(rules.served_published_at(stored, profile), precision[profile])
        self.assertEqual(rules.served_published_at(datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc), "DEMO-SUMMARY"),
                         "2026-10-26T00:00:00+00:00")


class ScopeContextTests(unittest.TestCase):
    def test_frozen_example_context_and_hash(self):
        frozen = fixture("scope-context.json")
        example = frozen["example_context"]
        sources = [{"channel_id": example["channels"][1]["id"], "channel_max": "DEMO-SUMMARY", "source_max": None},
                   {"channel_id": example["channels"][0]["id"], "channel_max": "DEMO-FULL", "source_max": "DEMO-FULL"}]
        context = scope_context.build_context(example["unit_id"], example["policy_epoch"], example["scope_epoch"], sources)
        self.assertEqual(context, example)
        self.assertEqual(canonical(context).decode("utf-8"), frozen["canonical_bytes"])
        self.assertEqual(scope_context.context_hash(context), frozen["scope_context_hash"])

    def test_legacy_rule_and_ceiling_derivation(self):
        legacy = [{"channel_id": "c1", "channel_max": None, "source_max": None}]
        self.assertIsNone(scope_context.build_context("u1", 0, 0, legacy))
        self.assertIsNone(scope_context.context_hash(None))
        capped = scope_context.build_context("u1", 0, 0, [{"channel_id": "c1", "channel_max": "DEMO-FULL", "source_max": None}])
        self.assertEqual(capped["channels"], [{"id": "c1", "profiles": ["DEMO-REDUCED", "DEMO-SUMMARY"]}])
        two = scope_context.build_context("u1", 0, 0, [{"channel_id": "c2", "channel_max": None, "source_max": None},
                                                       {"channel_id": "c1", "channel_max": None, "source_max": None}])
        self.assertEqual([item["id"] for item in two["channels"]], ["c1", "c2"])
        for bad in ([], [{"channel_id": "c1", "channel_max": "DEMO-X", "source_max": None}],
                    [{"channel_id": "c1", "channel_max": None, "source_max": None}] * 2):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                scope_context.build_context("u1", 0, 0, bad)
        with self.assertRaises(ValueError):
            scope_context.build_context("u1", -1, 0, legacy)

    def test_any_epoch_change_changes_the_hash_and_cursor_digest(self):
        sources = [{"channel_id": "c1", "channel_max": "DEMO-FULL", "source_max": "DEMO-FULL"}]
        base = scope_context.context_hash(scope_context.build_context("u1", 1, 1, sources))
        self.assertNotEqual(base, scope_context.context_hash(scope_context.build_context("u1", 2, 1, sources)))
        self.assertNotEqual(base, scope_context.context_hash(scope_context.build_context("u1", 1, 2, sources)))
        self.assertEqual(scope_context.scope_epochs_digest([("u2", 1), ("u1", 3)]), scope_context.scope_epochs_digest([("u1", 3), ("u2", 1)]))
        self.assertNotEqual(scope_context.scope_epochs_digest([("u1", 3)]), scope_context.scope_epochs_digest([("u1", 4)]))


if __name__ == "__main__":
    unittest.main()
