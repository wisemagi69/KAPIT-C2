"""Bounded integration bearer authentication, independent of mobile/session auth."""
import hashlib
import hmac
import re
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.operations.errors import ApiError
from apps.publications.selectors import recipient_scope, supported_policy
from apps.scopes.models import Organization
from .integration_services import key_digest
from .mobile_throttle import THROTTLE_LOCK
from .models import IntegrationClient, MobileThrottle

KEY = re.compile(r"kapit_ic_([a-z0-9]{8})_[A-Za-z0-9_-]{43}", re.ASCII)


def unauthorized():
    return ApiError("AUTHENTICATION_REQUIRED", "Use a valid integration key.", 401)


def consume(kind, value, limit):
    # Existing column is 64 characters: namespace + 208-bit keyed digest.
    material = ("kapit-integration-throttle-v1\0" + kind + "\0" + value).encode("utf-8")
    key = "integration:" + hmac.new(settings.SECRET_KEY.encode(), material, hashlib.sha256).hexdigest()[:52]
    instant = timezone.now()
    window = int(instant.timestamp()) // 300 * 300
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [THROTTLE_LOCK])
        old = list(MobileThrottle.objects.filter(updated_at__lt=instant - timedelta(hours=24)).order_by("updated_at", "key").values_list("key", flat=True)[:100])
        MobileThrottle.objects.filter(key__in=old).delete()
        counter = MobileThrottle.objects.filter(pk=key).first()
        if counter is None:
            if MobileThrottle.objects.count() >= 4096:
                raise ApiError("SERVER_ERROR", "The service is unavailable. Retry later.", 503)
            counter = MobileThrottle(key=key, window_start=window, attempts=0)
        if counter.window_start != window:
            counter.window_start, counter.attempts = window, 0
        counter.attempts = min(counter.attempts + 1, limit + 1)
        counter.updated_at = instant
        counter.save()
        denied = counter.attempts > limit
    if denied:
        raise ApiError("THROTTLED", "Wait before trying again.", 429)


def candidate(request):
    # REMOTE_ADDR only; caller-controlled forwarding headers are ignored.
    consume("address", str(request.META.get("REMOTE_ADDR", ""))[:128], 120)
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not isinstance(header, str) or len(header) > 80 or not header.startswith("Bearer "):
        raise unauthorized()
    key = header[7:]
    match = KEY.fullmatch(key)
    if match is None or any(name.lower() in {"key", "token", "access_token", "api_key", "authorization"} for name in request.query_params):
        raise unauthorized()
    expected = key_digest(key)
    request.integration_failure_prefix = match.group(1)
    client = IntegrationClient.objects.filter(key_digest=expected).first()
    # Constant-time verification also runs when the digest is unknown.
    valid = hmac.compare_digest(expected, client.key_digest if client else "0" * 64)
    if client is None or not valid:
        raise unauthorized()
    request.integration_client = client
    consume("client", str(client.pk), 300)
    return client


def lock_client(client):
    org = Organization.objects.select_for_update(of=("self",)).filter(pk=client.organization_id).select_related("active_policy").first()
    current = IntegrationClient.objects.select_for_update().filter(pk=client.pk, organization=org).first()
    if org is None or current is None or not supported_policy(org):
        raise unauthorized()
    try:
        scope = recipient_scope(None, org, current.channel_id, client=current)
    except ApiError:
        raise unauthorized() from None
    return current, org, scope


def record_failure(request):
    client = getattr(request, "integration_client", None)
    try:
        with transaction.atomic():
            if client is not None:
                audit.record(client.organization_id, None, "INTEGRATION_AUTH_FAILED", outcome="DENIED", prefix=client.key_prefix)
            else:
                audit.anonymous_integration_failure(getattr(request, "integration_failure_prefix", None))
    except Exception:
        # This boundary contains only the denial write, never a successful read.
        raise ApiError("SERVER_ERROR", "The service is unavailable. Retry later.", 503) from None
