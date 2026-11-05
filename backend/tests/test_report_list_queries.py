"""Real PostgreSQL checks that the per-page scope memo changes query counts, never list results."""
from contextlib import nullcontext
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.db import connection
from django.db.models import F
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.reports import regeneration
from apps.scopes.models import ChannelSource, Unit

from . import test_workflow as workflow


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ReportListMemoTests(TestCase):
    setUp = workflow.WorkflowTests.setUp
    sign_in = workflow.WorkflowTests.sign_in
    submit = workflow.WorkflowTests.submit
    candidate = workflow.WorkflowTests.candidate
    decision = workflow.WorkflowTests.decision

    def mixed_reports(self):
        for action in ("APPROVE", "RETURN", "REJECT"):
            _, _, variant, review = self.candidate()
            _, decided = self.decision(variant, review, action, "Synthetic review reason")
            self.assertEqual(decided.status_code, 200, decided.content)
        self.candidate()  # AWAITING_REVIEW
        self.sign_in("submitter")
        for _ in range(2):
            _, response = self.submit()  # PENDING
            self.assertEqual(response.status_code, 201, response.content)

    def listing(self, url, memo=True):
        disabled = nullcontext() if memo else patch("apps.reports.activity.scope_memo", new=nullcontext)
        with disabled, CaptureQueriesContext(connection) as queries:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(regeneration._scope_memo.get())
        return response.json(), len(queries)

    def assert_same_with_fewer_queries(self, url):
        unmemoized, before = self.listing(url, memo=False)
        memoized, after = self.listing(url)
        self.assertEqual(memoized, unmemoized)
        self.assertLess(after, before)
        return memoized

    def test_submitter_list_is_identical_with_fewer_queries(self):
        self.mixed_reports()
        self.sign_in("submitter")
        result = self.assert_same_with_fewer_queries("/api/v1/reports/?status=ALL&page_size=25")
        self.assertEqual(sorted(row["status"] for row in result["results"]),
                         ["APPROVED", "AWAITING_REVIEW", "PENDING", "PENDING", "REJECTED", "RETURNED"])

    def test_reviewer_queue_is_identical_with_fewer_queries(self):
        self.mixed_reports()
        self.sign_in("reviewer")
        result = self.assert_same_with_fewer_queries("/api/v1/review/queue/?status=ALL&page_size=25")
        self.assertEqual(result["count"], 6)

    def test_scope_changes_between_requests_are_never_served_from_an_earlier_memo(self):
        self.mixed_reports()
        self.sign_in("submitter")
        first, _ = self.listing("/api/v1/reports/?status=ALL&page_size=25")
        self.assertIn("AWAITING_REVIEW", [row["status"] for row in first["results"]])
        for change in (lambda: Unit.objects.filter(pk=self.unit.pk).update(scope_epoch=F("scope_epoch") + 1),
                       lambda: ChannelSource.objects.filter(unit=self.unit).update(active=False)):
            change()
            with self.subTest(change=change):
                result = self.assert_same_with_fewer_queries("/api/v1/reports/?status=ALL&page_size=25")
                statuses = sorted(row["status"] for row in result["results"])
                # Stale open work leaves the current queue; terminal decisions stay historical.
                self.assertEqual(statuses, ["FAILED", "FAILED", "FAILED", "FAILED", "REJECTED", "RETURNED"])

    def test_memo_is_inactive_outside_list_pages(self):
        self.assertIsNone(regeneration._scope_memo.get())
        calls = []
        self.assertEqual(regeneration._memoized("key", lambda: calls.append(1) or len(calls)), 1)
        self.assertEqual(regeneration._memoized("key", lambda: calls.append(1) or len(calls)), 2)
        with regeneration.scope_memo():
            self.assertEqual(regeneration._memoized("key", lambda: calls.append(1) or len(calls)), 3)
            self.assertEqual(regeneration._memoized("key", lambda: calls.append(1) or len(calls)), 3)
        self.assertIsNone(regeneration._scope_memo.get())
