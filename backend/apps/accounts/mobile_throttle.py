"""Small, persistent, serialized pre-authentication counters; no identity locks."""
from datetime import timedelta
import hashlib
import hmac

from django.db import connection, transaction

from .mobile_protocol import MobileError, config, now
from .models import MobileThrottle


THROTTLE_LOCK = 746397320


def consume(kind, value, limit):
    policy = config()
    key = hmac.new(policy.signing_key, ("kapit-mobile-throttle-v1\0" + kind + "\0" + value).encode("utf-8"), hashlib.sha256).hexdigest()
    instant = now()
    window = int(instant.timestamp()) // 300 * 300
    retry = window + 300 - int(instant.timestamp())
    denied = False
    try:
        with transaction.atomic():
            # One bounded table; the lock also covers absent-row creation/capacity.
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", [THROTTLE_LOCK])
            old = list(MobileThrottle.objects.filter(updated_at__lt=instant - timedelta(hours=24)).order_by("updated_at", "key").values_list("key", flat=True)[:100])
            if old:
                MobileThrottle.objects.filter(key__in=old).delete()
            counter = MobileThrottle.objects.filter(pk=key).first()
            if counter is None:
                if MobileThrottle.objects.count() >= 4096:
                    raise MobileError("MOBILE_UNAVAILABLE", 503)
                counter = MobileThrottle(key=key, attempts=0, window_start=window)
            if counter.window_start != window:
                counter.window_start, counter.attempts = window, 0
            # Saturate after denial so hostile traffic cannot overflow the field.
            counter.attempts = min(counter.attempts + 1, limit + 1)
            counter.updated_at = instant
            counter.save()
            denied = counter.attempts > limit
    except MobileError:
        raise
    except Exception:
        raise MobileError("MOBILE_UNAVAILABLE", 503) from None
    if denied:
        raise MobileError("THROTTLED", 429, retry_after=retry)
