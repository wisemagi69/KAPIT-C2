"""Fake-clock inventory tests; never access a database or delete a record."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest

try:
    from apps.operations.retention import CATEGORIES, InventoryItem, PROTECTED, inventory
except ModuleNotFoundError:
    from backend.apps.operations.retention import CATEGORIES, InventoryItem, PROTECTED, inventory


class RetentionInventoryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 21, tzinfo=timezone.utc)
        self.item = InventoryItem("EVIDENCE", "COMPLETE", self.now - timedelta(days=10), True, True)
        self.windows = {category: timedelta(days=7) for category in CATEGORIES}

    def run_inventory(self, items, now=None, windows=None):
        return inventory(items, now=self.now if now is None else now,
                         proposed_windows=self.windows if windows is None else windows)

    def row(self, item):
        return self.run_inventory([item])["counts"][0]

    def test_elapsed_window_only_creates_review_candidate_and_never_mutates(self):
        items = [self.item]
        result = self.run_inventory(items)
        self.assertEqual(result["mode"], "DRY_RUN")
        self.assertEqual(result["counts"], [{"category": "EVIDENCE", "disposition": "REVIEW_CANDIDATE",
                                            "code": "WINDOW_ELAPSED", "count": 1}])
        self.assertEqual(items, [self.item])
        self.assertFalse(hasattr(self.item, "delete"))

    def test_all_protected_categories_remain_retained_even_when_expired_confirmed_or_revoked(self):
        for category in PROTECTED:
            for state in ("CONFIRMED", "EXPIRED", "REVOKED", "PENDING"):
                with self.subTest(category=category, state=state):
                    self.assertEqual(self.row(replace(self.item, category=category, state=state))["disposition"], "RETAIN")

    def test_pending_unconfirmed_active_failed_and_revoked_are_held(self):
        for state in ("PENDING", "UNCONFIRMED", "ACTIVE", "FAILED", "REVOKED"):
            with self.subTest(state=state):
                self.assertEqual(self.row(replace(self.item, state=state))["code"], "STATE_HOLD")
        self.assertEqual(self.row(replace(self.item, confirmed=False))["code"], "UNCONFIRMED")
        self.assertEqual(self.row(replace(self.item, confirmed=1))["code"], "UNCONFIRMED")

    def test_holds_and_incomplete_recovery_override_elapsed_windows(self):
        for hold in ("LEGAL", "EVALUATION", "CORRECTION", "RECOVERY", "DEPENDENCY"):
            self.assertEqual(self.row(replace(self.item, holds=(hold,)))["code"], "EXPLICIT_HOLD")
        self.assertEqual(self.row(replace(self.item, recovery_complete=False))["code"], "RECOVERY_INCOMPLETE")

    def test_unknown_fields_and_records_fail_closed_and_never_echo_content(self):
        private = "PRIVATE_RETENTION_CANARY"
        items = [replace(self.item, category=private), replace(self.item, category=[]),
                 replace(self.item, state=private), replace(self.item, holds=(private,)),
                 {"source_text": private}, None]
        result = self.run_inventory(items)
        self.assertEqual(result["total"], 6)
        self.assertNotIn(private, json.dumps(result))
        self.assertTrue(all(row["disposition"] == "RETAIN" for row in result["counts"]))

    def test_fake_clock_boundaries_future_and_naive_timestamps(self):
        boundary = self.item.created_at + timedelta(days=7)
        before = self.run_inventory([self.item], now=boundary - timedelta(microseconds=1))
        at = self.run_inventory([self.item], now=boundary)
        self.assertEqual(before["counts"][0]["code"], "WITHIN_WINDOW")
        self.assertEqual(at["counts"][0]["code"], "WINDOW_ELAPSED")
        self.assertEqual(self.row(replace(self.item, created_at=self.now + timedelta(seconds=1)))["code"], "INVALID_CLOCK")
        self.assertEqual(self.row(replace(self.item, created_at=datetime(2020, 1, 1)))["code"], "INVALID_CLOCK")
        with self.assertRaisesRegex(ValueError, "INVALID_CLOCK"):
            self.run_inventory([], now=datetime(2026, 1, 1))

    def test_absent_policy_holds_and_invalid_windows_refuse(self):
        self.assertEqual(self.run_inventory([self.item], windows={})["counts"][0]["code"], "NO_PROPOSED_WINDOW")
        for windows in ({"UNKNOWN": timedelta(days=1)}, {"EVIDENCE": timedelta(0)}, {"EVIDENCE": 7}, None):
            with self.subTest(windows=windows), self.assertRaisesRegex(ValueError, "INVALID_WINDOWS"):
                inventory([], now=self.now, proposed_windows=windows)

    def test_aggregate_counts_are_deterministic_with_no_per_object_fields(self):
        held = replace(self.item, category="MOBILE_OUTBOX")
        result = self.run_inventory([self.item, held, self.item])
        self.assertEqual(result, self.run_inventory([held, self.item, self.item]))
        self.assertEqual(result["total"], 3)
        self.assertEqual(sorted(row["count"] for row in result["counts"]), [1, 2])
        self.assertTrue(all(set(row) == {"category", "disposition", "code", "count"} for row in result["counts"]))
        self.assertEqual(self.run_inventory([]), {"mode": "DRY_RUN", "total": 0, "counts": []})


if __name__ == "__main__":
    unittest.main()
