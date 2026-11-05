"""Limited stdlib checks: actual function bodies, explicit ORM/framework stand-ins.

These do not execute Django, authentication, transactions, SQL or session storage.
The genuine API/session/race checks remain in test_integration_sprint/concurrency.
"""
import ast
import copy
import re
import sys
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as Object

# Support both root-qualified tests and Django's backend-directory discovery.
# Derive this path from this file, never the caller's current working directory.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from backend.apps.reports.canonical import digest
from backend.apps.reports.projection import POLICIES, PROFILE_KEYS, PROFILE_RANK, RULES, project, served_published_at, valid_projection


ROOT = Path(__file__).resolve().parents[1]


class Denial(Exception):
    def __init__(self, *args):
        self.args = args


class Params(dict):
    def getlist(self, key):
        value = self[key]
        return value if isinstance(value, list) else [value]

    def dict(self):
        return dict(self)


class Rows(list):
    def exists(self):
        return bool(self)

    def filter(self, **kwargs):
        return Rows(row for row in self if all(getattr(row, key) == value for key, value in kwargs.items()))

    def order_by(self, *args):
        return self

    def select_related(self, *args):
        return self

    def first(self):
        return self[0] if self else None

    def iterator(self, chunk_size):
        self.last_chunk_size = chunk_size
        return iter(self)


def extract(path, names, context):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8-sig"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != set(names):
        raise AssertionError("Requested implementation functions are missing")
    for node in functions:
        node.decorator_list = []
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), context)


def functions():
    context = {"re": re, "ApiError": Denial, "digest": digest, "RULES": RULES,
               "valid_projection": valid_projection, "PROFILE": "DEMO-REDUCED",
               "POLICIES": POLICIES, "PROFILE_KEYS": PROFILE_KEYS, "PROFILE_RANK": PROFILE_RANK,
               "served_published_at": served_published_at, "Counter": Counter}
    # Controlled external capabilities only. SQL/locks/durable delivery are separate PG gates.
    context["PublicationRemoval"] = Object(objects=Rows())
    context["RevisionWithdrawal"] = Object(objects=Rows())
    context["job_is_current"] = lambda job, org: (job.revision.revision_no == job.revision.report.current_revision_no
        and job.engine_manifest == org.active_policy.rules["engine"]
        and job.policy_epoch == org.policy_epoch and job.scope_epoch == job.revision.report.unit.scope_epoch)
    context["_read_identity"] = lambda actor, org: (actor, org)
    context["recipient_scope"] = lambda *args: Object(ceiling="DEMO-REDUCED", expanded=False)
    context["record_deliveries"] = lambda *args: None
    extract("apps/operations/pagination.py", ["query_values", "pagination_values"], context)
    extract("apps/operations/worker.py", ["binding_for", "candidate_digest"], context)
    extract("apps/publications/selectors.py", ["feed_filters", "matches_projection", "feed", "valid_publication", "_valid_publication", "serialize_publication", "supported_policy", "selected_publications", "filtered_publications", "summarize"], context)
    return context


def publication(context):
    stamp = datetime(2026, 10, 14, tzinfo=timezone.utc)
    policy = Object(id="policy", organization_id="org", active=True, version="demo-policy-v1", rules=copy.deepcopy(RULES), rules_hash=digest(RULES))
    org = Object(id="org", active=True, active_policy=policy, policy_epoch=0)
    report = Object(id="report", organization_id="org", unit_id="unit", current_revision_no=1,
                    unit=Object(active=True, organization_id="org", scope_epoch=0))
    revision = Object(id="revision", organization_id="org", report_id="report", report=report, revision_no=1,
                      content_digest="source-hash", processing_state="AWAITING_REVIEW", received_at=stamp)
    job = Object(id="job", organization_id="org", revision_id="revision", policy_id="policy", channel_ids=["channel"],
                 engine_manifest="demo-rules-v1", status="DONE", attempts=1, revision=revision,
                 scope_context=None, scope_context_hash=None, policy_epoch=0, scope_epoch=0)
    projection = project({"category": "WATER_SUPPLY", "urgency": "ROUTINE", "area_label": "Area C",
                          "assistance_requested": "Repair assistance", "observed_at": stamp.isoformat()})
    variant = Object(id="variant", revision=revision, revision_id=revision.id, job=job, policy=policy, policy_id=policy.id,
                     organization_id="org", profile="DEMO-REDUCED", projection=projection, channel_ids=["channel"],
                     state="APPROVED", created_at=stamp, scope_context_hash=None)
    variant.candidate_hash = context["candidate_digest"](projection, revision.id, 1, revision.content_digest, policy.id, policy.rules_hash, variant.profile, variant.channel_ids)
    decision = Object(id="decision", variant_id=variant.id, organization_id="org", action="APPROVE",
                      binding=context["binding_for"](variant), recorded_at=stamp)
    variant.decision = decision
    revision.variants = Rows([variant]); revision.jobs = Rows([job])
    result = Object(id="publication", organization_id="org", report=report, report_id=report.id,
                    channel=Object(id="channel", organization_id="org", active=True, code="CH-DEMO", name="Fictional channel"),
                    channel_id="channel", variant=variant, variant_id=variant.id, decision=decision, decision_id=decision.id,
                    profile="DEMO-REDUCED", projection=projection, published_at=stamp, revoked_at=None)
    context["eligible_channels"] = lambda org_id, unit_id: ["channel"]
    return result, org


class LimitedIntegrationSprintTests(unittest.TestCase):
    def setUp(self):
        self.context = functions()

    def test_feed_query_is_bounded_and_rejects_duplicate_unknown_and_coerced_values(self):
        parse = self.context["feed_filters"]
        self.assertEqual(parse(Params(q="  Repair  "))["q"], "Repair")
        for params in [Params(page="0"), Params(page_size="51"), Params(page=["1", "2"]), Params(page="01"),
                       Params(category="hidden"), Params(urgency="hidden"), Params(q="x" * 121), Params(narrative="private")]:
            with self.subTest(params=params), self.assertRaises(Denial):
                parse(params)

    def test_feed_iterates_past_100_keeps_only_requested_page_and_counts_valid_rows(self):
        publication_, org = publication(self.context)
        rows = Rows()
        for index in range(105):
            row = copy.deepcopy(publication_); row.id = f"{index:03}"
            row.report_id = row.report.id = row.variant.revision.report_id = f"report-{index}"
            if index in (1, 8, 22, 30):
                row.variant.candidate_hash = "invalid"
            rows.append(row)
        scope = Object(ceiling="DEMO-REDUCED", expanded=False)
        self.context["current_publications"] = lambda *args, **kwargs: (scope, rows)
        delivered = []
        self.context["record_deliveries"] = lambda actor, org, values: delivered.extend(value.id for value in values)
        serialized = []
        serialize = self.context["serialize_publication"]
        self.context["serialize_publication"] = lambda value: (serialized.append(value.id), serialize(value))[1]
        page = self.context["feed"](None, org, "channel", Params(page="11", page_size="10"))
        self.assertEqual((page["count"], page["total_pages"], len(page["results"])), (101, 11, 1))
        self.assertEqual(serialized, ["000"])
        self.assertEqual(delivered, serialized)
        self.assertEqual(rows.last_chunk_size, 100)

    def test_projection_search_never_reads_unapproved_fields_and_applies_both_enums(self):
        publication_, _ = publication(self.context)
        projection = {**publication_.projection, "narrative": "PRIVATE_CANARY", "site_label": "PRIVATE_CANARY"}
        match = self.context["matches_projection"]
        base = {"q": "repair", "category": "WATER_SUPPLY", "urgency": "ROUTINE"}
        self.assertTrue(match(projection, base))
        for options in [{**base, "q": "PRIVATE_CANARY"}, {**base, "category": "EQUIPMENT"}, {**base, "urgency": "PRIORITY"}]:
            self.assertFalse(match(projection, options))

    def test_scope_denial_precedes_filter_validation_or_dataset_iteration(self):
        def deny(*args):
            raise Denial("scope")
        self.context["recipient_scope"] = deny
        with self.assertRaises(Denial) as failure:
            self.context["feed"](None, None, "channel", Params(page="bad"))
        self.assertEqual(failure.exception.args, ("scope",))

    def test_highest_profile_is_selected_before_search_without_lower_profile_fallback(self):
        # Currentness/SQL are controlled; execute the actual rank/filter functions.
        rows = Rows([
            Object(id="lower", report_id="same-report", channel_id="channel", profile="DEMO-REDUCED",
                   published_at=1, projection={"title": "lower-only", "text": "maintenance", "category": "WATER_SUPPLY", "urgency": "ROUTINE"}),
            Object(id="higher", report_id="same-report", channel_id="channel", profile="DEMO-FULL",
                   published_at=2, projection={"title": "higher-only", "text": "maintenance", "category": "WATER_SUPPLY", "urgency": "ROUTINE"}),
        ])
        scope = Object(ceiling="DEMO-FULL", expanded=True)
        self.context["current_publications"] = lambda *args, **kwargs: (scope, rows)
        self.context["valid_publication"] = lambda value, org: True
        _, chosen = self.context["selected_publications"](None, None, "channel")
        self.assertEqual([value.id for value in chosen], ["higher"])
        filtered = self.context["filtered_publications"](scope, chosen,
            {"q": "lower-only", "category": "ALL", "urgency": "ALL"})
        self.assertEqual(filtered, [])
        _, lower = self.context["selected_publications"](None, None, "channel", "DEMO-REDUCED")
        self.assertEqual([value.id for value in lower], ["lower"])

    def test_actual_availability_predicate_fails_closed_on_every_mutable_currentness_dimension(self):
        source, original_org = publication(self.context)
        valid = self.context["valid_publication"]
        self.assertTrue(valid(source, original_org))
        mutations = [lambda p, o: setattr(o, "active", False), lambda p, o: setattr(o.active_policy, "active", False),
                     lambda p, o: setattr(p, "revoked_at", p.published_at), lambda p, o: setattr(p.channel, "active", False),
                     lambda p, o: setattr(p.report, "current_revision_no", 2), lambda p, o: setattr(p.report.unit, "active", False),
                     lambda p, o: setattr(p.variant.job, "status", "FAILED"), lambda p, o: setattr(p.variant.revision, "processing_state", "FAILED"),
                     lambda p, o: setattr(p.variant.job, "revision_id", "other"), lambda p, o: setattr(p.variant.job, "channel_ids", ["other"]),
                     lambda p, o: setattr(p, "organization_id", "other"), lambda p, o: setattr(p.decision, "action", "RETURN"),
                     lambda p, o: setattr(p.variant, "candidate_hash", "invalid"), lambda p, o: setattr(p.decision, "binding", {}),
                     lambda p, o: setattr(p, "projection", {"narrative": "PRIVATE_CANARY"})]
        for index, mutate in enumerate(mutations):
            with self.subTest(dimension=index):
                item, org = copy.deepcopy((source, original_org)); mutate(item, org)
                self.assertFalse(valid(item, org))

    def test_workflow_keeps_historical_timestamps_and_reports_current_availability_separately(self):
        item, org = publication(self.context)
        self.context["Publication"] = Object(objects=Rows([item]))
        # This source-extraction test supplies controlled selection dependencies;
        # real current-context selection is tested against PostgreSQL in tests/m3.
        self.context["representative_variant"] = lambda revision: item.variant
        self.context["current_job"] = lambda revision: item.variant.job
        extract("apps/reports/workflow.py", ["revision_workflow"], self.context)
        detail = lambda: self.context["revision_workflow"](item.report, item.variant.revision, org)
        original = detail()
        self.assertEqual(original["sharing"]["state"], "AVAILABLE")
        item.variant.job.status = "FAILED"
        failed = detail()
        self.assertEqual(failed["processing"], {"state": "FAILED", "attempts": 1})
        self.assertEqual(failed["sharing"]["state"], "UNAVAILABLE")
        self.assertEqual(failed["review"], original["review"])
        item.variant.job.status = "DONE"; item.report.current_revision_no = 2
        self.assertEqual(detail()["sharing"]["state"], "SUPERSEDED")
        item.report.current_revision_no = 1; item.revoked_at = item.published_at
        self.assertEqual(detail()["sharing"]["state"], "WITHDRAWN")
        self.assertEqual(detail()["sharing"]["published_at"], original["sharing"]["published_at"])

    def test_password_function_reauthenticates_validates_and_audits_only_actor(self):
        calls = []
        actor = Object(id="actor", permission_version=4)
        actor.check_password = lambda value: calls.append(("check", value)) or value == "current"
        actor.set_password = lambda value: calls.append(("set", value))
        actor.save = lambda **kwargs: calls.append(("save", kwargs))
        context = {"lock_identity": lambda user: (calls.append(("lock", user)), (actor, Object(id="org")))[1],
                   "user_object": lambda user: calls.append(("context", user.id)), "ApiError": Denial,
                   "serializers": Object(ValidationError=Denial), "validate_new_password": lambda *args: calls.append(("validate", args[2])),
                   "audit": Object(record=lambda *args: calls.append(("audit", args[2], args[3])))}
        extract("apps/accounts/services.py", ["change_password"], context)
        result = context["change_password"]("request-actor", {"current_password": "current", "new_password": "new"})
        self.assertEqual(result, {"changed": True, "reauthenticate": True})
        self.assertEqual(actor.permission_version, 5)
        self.assertEqual([entry[0] for entry in calls], ["lock", "context", "check", "check", "validate", "set", "save", "audit"])
        self.assertEqual(calls[-1], ("audit", "ACCOUNT_PASSWORD_CHANGED", "actor"))
        calls.clear()
        with self.assertRaises(Denial):
            context["change_password"]("request-actor", {"current_password": "wrong", "new_password": "new"})
        self.assertEqual([entry[0] for entry in calls], ["lock", "context", "check"])
        self.assertEqual(actor.permission_version, 5)


if __name__ == "__main__":
    unittest.main()
