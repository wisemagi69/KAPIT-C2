"""Meaningful proposal/parser/command guard checks; standard library, no Django/DB."""
import ast
import copy
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

try:
    from apps.operations import retention_policy as policy
except ModuleNotFoundError:
    from backend.apps.operations import retention_policy as policy

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / "contracts/m4/retention-policy-draft.json").read_text())


def command_namespace():
    path = ROOT / "backend/apps/operations/management/commands/retention_review.py"
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    class BaseCommand:
        pass
    namespace = dict(Path=Path, stat=stat, json=json, os=os, ROOT=ROOT, MAX_BYTES=policy.MAX_BYTES,
        CATEGORIES=policy.CATEGORIES, parse_policy_draft=policy.parse_policy_draft,
        validate_policy_draft=policy.validate_policy_draft, summarize_policy_gaps=policy.summarize_policy_gaps,
        BaseCommand=BaseCommand, CommandError=RuntimeError, __package__="review_commands")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


class RetentionPolicyTests(unittest.TestCase):
    def draft(self):
        return copy.deepcopy(CONTRACT["default_draft"])

    def summary(self, draft=None, observed=frozenset()):
        return policy.summarize_policy_gaps(policy.validate_policy_draft(self.draft() if draft is None else draft), observed_categories=observed)

    def rejected(self, draft):
        with self.assertRaisesRegex(ValueError, "^INVALID_POLICY_DRAFT$"):
            policy.validate_policy_draft(draft)

    def test_default_accounts_for_every_category_and_five_unknown_hold_sources(self):
        result = self.summary()
        self.assertEqual({row["category"] for row in result["counts"]}, policy.CATEGORIES)
        self.assertEqual(sum(row["count"] for row in result["counts"] if row["code"] == "HOLD_SOURCE_UNSET"), 75)
        self.assertEqual(result["disposition"], "RETAIN_ALL")
        self.assertEqual(result["category_count"], 15)
        self.assertEqual(set(result), set(CONTRACT["api"]["result_exact_keys"]))
        self.assertEqual(result["counts"], sorted(result["counts"], key=lambda row: (row["category"], row["code"])))

    def test_complete_proposal_cannot_clear_unknown_holds_recovery_or_approval(self):
        draft = self.draft()
        for row in draft["categories"]:
            row.update(status="PROPOSED", custodian_ref="PRIVATE_CUSTODIAN_CANARY", duration_seconds=1,
                clock="CREATED_AT_UTC", backup_expiry_seconds=1, key_expiry_seconds=policy.MAX_SECONDS,
                disposition="REVIEW_ONLY", reviewer_ref="PRIVATE_REVIEWER_CANARY", review_interval_seconds=1)
            row["hold_sources"] = {kind: "PRIVATE_HOLD_CANARY" for kind in policy.HOLDS}
        result = self.summary(draft, policy.CATEGORIES)
        self.assertEqual({row["code"] for row in result["counts"]},
            {"APPROVAL_REQUIRED", "HOLD_KNOWLEDGE_UNCONFIRMED", "RECOVERY_UNCONFIRMED", "PROTECTED_CATEGORY"})
        self.assertEqual(sum(row["count"] for row in result["counts"]), 53)
        self.assertNotIn("PRIVATE_", json.dumps(result))
        self.assertEqual(result["policy_status"], "PROPOSED_ONLY")

    def test_partial_declarations_and_observed_metadata_never_establish_item_eligibility(self):
        draft = self.draft()
        draft["categories"][0].update(status="PROPOSED", custodian_ref="LOCAL_REVIEW")
        result = self.summary(draft, frozenset({"SOURCE"}))
        coverage = [row for row in result["counts"] if row["code"] == "NATIVE_COVERAGE_UNAVAILABLE"]
        self.assertEqual(len(coverage), 14)
        self.assertNotIn("SOURCE", {row["category"] for row in coverage})
        self.assertEqual(result["disposition"], "RETAIN_ALL")

    def test_input_copy_and_frozen_representation(self):
        draft = self.draft()
        frozen = policy.validate_policy_draft(draft)
        before = policy.summarize_policy_gaps(frozen, observed_categories=frozenset())
        draft["categories"][0]["hold_sources"]["LEGAL"] = "CHANGED"
        self.assertEqual(policy.summarize_policy_gaps(frozen, observed_categories=frozenset()), before)
        with self.assertRaises(FrozenInstanceError):
            frozen.categories = ()
        with self.assertRaisesRegex(ValueError, "INVALID_POLICY_DRAFT"):
            policy.summarize_policy_gaps(policy.PolicyDraft(("bad",)), observed_categories=frozenset())

    def test_categories_fields_and_status_are_closed(self):
        for change in (lambda d: d.update(schema_version=True), lambda d: d.update(status="APPROVED"),
            lambda d: d.update(purge=True), lambda d: d["categories"].pop(),
            lambda d: d["categories"].__setitem__(0, copy.deepcopy(d["categories"][1])),
            lambda d: d["categories"][0].update(category="PRIVATE_UNKNOWN"),
            lambda d: d["categories"][0].update(status=[]),
            lambda d: d["categories"][0].update(status="PROPOSED"),
            lambda d: d["categories"][0].update(custodian_ref="FILLED_BUT_UNSET")):
            draft = self.draft(); change(draft); self.rejected(draft)

    def test_seconds_reference_clock_and_disposition_boundaries(self):
        for field in policy.SECONDS:
            for value in (True, 0, -1, 1.5, "7", policy.MAX_SECONDS + 1):
                draft = self.draft(); draft["categories"][0].update(status="PROPOSED", **{field: value}); self.rejected(draft)
            for value in (1, policy.MAX_SECONDS):
                draft = self.draft(); draft["categories"][0].update(status="PROPOSED", **{field: value}); policy.validate_policy_draft(draft)
        for field, values in (("custodian_ref", ("lower", "A" * 65, "UPPER\n", "ÉTOKEN", 42)),
                              ("clock", ("LOCAL_TIME", [], 1)), ("disposition", ("DELETE", "APPROVED", {}))):
            for value in values:
                draft = self.draft(); draft["categories"][0].update(status="PROPOSED", **{field: value}); self.rejected(draft)
        draft = self.draft(); draft["categories"][0].update(status="PROPOSED", custodian_ref="A" * 64)
        policy.validate_policy_draft(draft)

    def test_hold_sources_exact_known_keys_and_safe_references(self):
        for holds in ({}, {"LEGAL": "ANY"}, {**{h: None for h in policy.HOLDS}, "UNKNOWN": None},
                      {**{h: None for h in policy.HOLDS}, "LEGAL": "PRIVATE_\n"}, []):
            draft = self.draft(); draft["categories"][0].update(status="PROPOSED", hold_sources=holds); self.rejected(draft)

    def test_json_resource_duplicate_nonfinite_and_unicode_fail_closed(self):
        valid = json.dumps(self.draft()).encode()
        self.assertIsInstance(policy.parse_policy_draft(valid), policy.PolicyDraft)
        for raw in (valid.decode(), b"", b"x" * 65537, b'\xff', b'{"schema_version":1,"schema_version":1}',
                    b'{"x":NaN}', b'{"x":Infinity}', b'[' * 1000 + b'0' + b']' * 1000,
                    json.dumps([None] * 2049).encode(), json.dumps([[[[[[[[None]]]]]]]]).encode()):
            with self.assertRaisesRegex(ValueError, "^INVALID_POLICY_DRAFT$"):
                policy.parse_policy_draft(raw)
        draft = self.draft(); draft["categories"][0]["custodian_ref"] = "X" * 65536
        self.rejected(draft)

    def test_observations_reject_unknown_or_coerced_values(self):
        for observed in (set(), [], frozenset({"PRIVATE_UNKNOWN"}), frozenset({1})):
            with self.assertRaisesRegex(ValueError, "^INVALID_POLICY_OBSERVATION$"):
                self.summary(observed=observed)


class RetentionCommandGuardTests(unittest.TestCase):
    def test_file_guard_accepts_only_bounded_regular_workspace_json(self):
        command = command_namespace()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "proposal.json"; valid.write_bytes(b"{}")
            self.assertEqual(command["read_workspace_json"](valid, root=root), b"{}")
            with patch.object(os, "fstat", return_value=Mock(st_dev=-1, st_ino=-1, st_mode=stat.S_IFREG)), self.assertRaisesRegex(ValueError, "POLICY_DRAFT_UNAVAILABLE"):
                command["read_workspace_json"](valid, root=root)
            huge = root / "huge.json"; huge.write_bytes(b"x" * 65537)
            for value in (huge, root, root / "missing.json", root / "../escape.json", root / "bad.txt"):
                with self.assertRaisesRegex(ValueError, "^POLICY_DRAFT_UNAVAILABLE$"):
                    command["read_workspace_json"](value, root=root)
            link = root / "redirect.json"
            try:
                link.symlink_to(valid)
            except OSError:
                # Windows without symlink permission: emulate the lstat reparse bit.
                info = valid.stat()
                fake = Mock(st_mode=info.st_mode, st_file_attributes=1024)
                with patch.object(Path, "lstat", return_value=fake), self.assertRaisesRegex(ValueError, "POLICY_DRAFT_UNAVAILABLE"):
                    command["read_workspace_json"](valid, root=root)
            else:
                with self.assertRaisesRegex(ValueError, "POLICY_DRAFT_UNAVAILABLE"):
                    command["read_workspace_json"](link, root=root)

    def test_native_refusal_precedes_observation_and_no_mutation_argument(self):
        command = command_namespace()
        module = ModuleType("review_commands.retention_inventory")
        module.collect_inventory = Mock(side_effect=RuntimeError("NATIVE_ONLY"))
        proposal = policy.validate_policy_draft(copy.deepcopy(CONTRACT["default_draft"]))
        command["proposal_for"] = Mock(return_value=proposal)
        command["observations"] = Mock(side_effect=AssertionError("must not process unguarded data"))
        with patch.dict(sys.modules, {"review_commands.retention_inventory": module}), self.assertRaisesRegex(RuntimeError, "^NATIVE_ONLY$"):
            command["review"]()
        command["observations"].assert_not_called()
        parser = Mock(); command["Command"]().add_arguments(parser)
        self.assertEqual(parser.add_argument.call_args.args, ("--proposal-file",))
        self.assertEqual(command["Command"].requires_system_checks, [])
        self.assertFalse(command["Command"].requires_migrations_checks)

    def test_observation_allowlist_and_final_output_suppress_all_source_counts_and_labels(self):
        command = command_namespace()
        snapshot = {"mode": "DRY_RUN", "disposition": "RETAIN_ALL", "sources": [
            {"category": "AUDIT", "status": "COUNTED_METADATA", "count": 999999}], "unavailable": []}
        self.assertEqual(command["observations"](snapshot), frozenset({"AUDIT"}))
        for change in (lambda s: s.update(mode="APPLY"), lambda s: s["sources"][0].update(category="PRIVATE_CANARY"),
                       lambda s: s["sources"][0].update(count=True), lambda s: s["sources"][0].update(raw="PRIVATE_CANARY")):
            bad = copy.deepcopy(snapshot); change(bad)
            with self.assertRaisesRegex(ValueError, "^INVALID_POLICY_OBSERVATION$"):
                command["observations"](bad)
        module = ModuleType("review_commands.retention_inventory"); module.collect_inventory = Mock(return_value=snapshot)
        with patch.dict(sys.modules, {"review_commands.retention_inventory": module}):
            result = command["review"]()
        self.assertNotIn("999999", json.dumps(result))
        self.assertNotIn("sources", result)
        self.assertEqual(result["disposition"], "RETAIN_ALL")


if __name__ == "__main__":
    unittest.main()
