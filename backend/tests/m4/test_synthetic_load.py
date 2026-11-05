"""Declared serial synthetic measurement, only inside the owned disposable DB runner."""
import json
import math
import statistics
import time

from django.contrib.auth import get_user_model
from django.db import connection
from django.http import QueryDict
from django.test import TestCase, override_settings

from apps.publications.models import Publication, PublicationDelivery
from apps.publications.selectors import feed, map_counts
from apps.reports.models import ReportVariant
from apps.scopes.models import SharingChannel
from tests import browser_runner
from tests.m3.test_m3_review import ReviewFixture, SETTINGS


@override_settings(**SETTINGS)
class SyntheticWorkflowLoadTests(ReviewFixture, TestCase):
    def setUp(self):
        lease = browser_runner.ACTIVE_DATABASE_LEASE
        self.assertTrue(lease is not None and lease.locked, "Guarded disposable runner required")
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(),oid FROM pg_database WHERE datname=current_database()")
            identity = cursor.fetchone()
        self.assertEqual(identity, ("test_kapit_m1", lease.owned_oid), "Guarded disposable identity required")
        super().setUp()

    def test_fifty_sequential_reports_keep_profile_map_and_delivery_consistent(self):
        latencies = []
        started = time.perf_counter()
        for _ in range(50):
            tick = time.perf_counter()
            revision, _ = self.submit_source()
            self.batch(revision)
            latencies.append((time.perf_counter() - tick) * 1000)
        workflow_ms = (time.perf_counter() - started) * 1000
        self.assertEqual(ReportVariant.objects.count(), 150)
        self.assertEqual(Publication.objects.count(), 200)
        recipient = get_user_model().objects.get(username="recipient-full")
        channel = SharingChannel.objects.get(code="CH-DEMO-02")
        tick = time.perf_counter()
        first = feed(recipient, self.org, channel.id, QueryDict("page_size=50"))
        feed_ms = (time.perf_counter() - tick) * 1000
        self.assertEqual((first["count"], len(first["results"]), first["total_pages"]), (50, 50, 1))
        self.assertEqual({item["projection"]["profile"] for item in first["results"]}, {"DEMO-FULL"})
        self.assertEqual(sum(first["summary"]["by_area"].values()), 50)
        tick = time.perf_counter()
        mapped = map_counts(recipient, self.org, channel.id, QueryDict())
        map_ms = (time.perf_counter() - tick) * 1000
        self.assertEqual(sum(area["count"] for area in mapped["areas"]) + mapped["unmapped"], first["count"])
        self.assertEqual(PublicationDelivery.objects.filter(user=recipient).count(), 50)
        repeated = feed(recipient, self.org, channel.id, QueryDict("page_size=50"))
        self.assertEqual([item["id"] for item in repeated["results"]], [item["id"] for item in first["results"]])
        self.assertEqual(PublicationDelivery.objects.filter(user=recipient).count(), 50)
        ordered = sorted(latencies)
        result = {"status": "PASSED", "reports": 50, "candidates": 150, "publication_rows": 200,
            "visible_reports": 50, "delivery_rows": 50, "sample_count": len(latencies),
            "workflow_total_ms": round(workflow_ms, 3), "workflow_median_ms": round(statistics.median(latencies), 3),
            "workflow_p95_ms": round(ordered[math.ceil(len(ordered) * .95) - 1], 3),
            "feed_ms": round(feed_ms, 3), "map_ms": round(map_ms, 3),
            "mode": "Sequential internal services in a disposable TestCase transaction",
            "limits": ["No network/device or commit latency", "No concurrency or production SLA", "Test fixture password hasher only"]}
        # Aggregate synthetic observations only; no report/publication IDs or source data.
        print("KAPIT_SYNTHETIC_LOAD " + json.dumps(result, sort_keys=True))
