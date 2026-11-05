"""Private synthetic integration key lifecycle. Plaintext exists only at first collect."""
import hashlib
import hmac
import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.http import QueryDict

from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.operations.pagination import query_values
from apps.reports.crypto import digest
from apps.reports.projection import PROFILE_RANK
from apps.scopes.access import lock_identity
from apps.scopes.authority import has_authority, require_authority
from apps.scopes.models import SharingChannel
from .models import IntegrationClient, IntegrationClientApproval, IntegrationClientRequest


def key_digest(key):
    derived = hmac.new(settings.SECRET_KEY.encode("utf-8"), b"kapit-integration-key-v1", hashlib.sha256).digest()
    return hmac.new(derived, key.encode("ascii"), hashlib.sha256).hexdigest()


def request_metadata(row):
    return {"id": str(row.id), "requester_id": str(row.requester_id), "channel_id": str(row.channel_id),
            "profile_ceiling": row.profile_ceiling, "label": row.label, "expires_at": row.expires_at.isoformat(),
            "collect_deadline": row.collect_deadline.isoformat(), "created_at": row.created_at.isoformat()}


def client_metadata(row):
    return {"id": str(row.id), "request_id": str(row.request_id), "channel_id": str(row.channel_id),
            "profile_ceiling": row.profile_ceiling, "label": row.label, "key_prefix": row.key_prefix,
            "created_at": row.created_at.isoformat(), "expires_at": row.expires_at.isoformat(),
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None}


def unavailable():
    return missing()


def _channel(org, channel_id, profile):
    channel = SharingChannel.objects.select_for_update().filter(organization=org, pk=channel_id, active=True).first()
    if channel is None:
        raise missing()
    if profile not in PROFILE_RANK or PROFILE_RANK[profile] > PROFILE_RANK.get(channel.max_profile or "DEMO-REDUCED", 0):
        raise unavailable()
    return channel


def _collect_locked(actor, org, request):
    if request.requester_id != actor.id:
        raise missing()
    prior = IntegrationClient.objects.filter(organization=org, request=request).first()
    if prior:
        # Lost-response retries never reproduce the secret, even if still active.
        return {"request": request_metadata(request), "client": client_metadata(prior)}, False
    now = timezone.now()
    if now >= request.collect_deadline or now >= request.expires_at:
        raise unavailable()
    _channel(org, request.channel_id, request.profile_ceiling)
    if request.profile_ceiling == "DEMO-FULL":
        approval = IntegrationClientApproval.objects.filter(organization=org, request=request).first()
        if approval is None or approval.approver_id == actor.id:
            raise unavailable()
        approver = get_user_model().objects.select_for_update().filter(pk=approval.approver_id, organization=org).first()
        if approver is None or not has_authority(approver, "INTEGRATION"):
            raise unavailable()
    alphabet = string.ascii_lowercase + string.digits
    prefix = "".join(secrets.choice(alphabet) for _ in range(8))
    key = "kapit_ic_" + prefix + "_" + secrets.token_urlsafe(32)
    client = IntegrationClient.objects.create(organization=org, request=request, channel_id=request.channel_id,
        profile_ceiling=request.profile_ceiling, label=request.label, key_prefix=prefix,
        key_digest=key_digest(key), created_at=now, expires_at=request.expires_at)
    audit.record(org.id, actor, "INTEGRATION_COLLECTED", client.id)
    return {"request": request_metadata(request), "client": client_metadata(client), "key": key}, True


@transaction.atomic
def request_client(user, data, raw_body):
    actor, org = lock_identity(user)
    require_authority(actor, "INTEGRATION")
    request_hash = digest({"route": "POST /administration/integration/requests/", "body": raw_body})
    prior = IntegrationClientRequest.objects.filter(organization=org, requester=actor, operation_id=data["operation_id"]).first()
    if prior:
        if prior.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This integration operation has a different request.", 409)
        client = IntegrationClient.objects.filter(organization=org, request=prior).first()
        return {"request": request_metadata(prior), "client": client_metadata(client) if client else None}, False
    now = timezone.now()
    expires = data["expires_at"]
    if (not isinstance(data["label"], str) or not data["label"].strip() or len(data["label"]) > 80
            or not hasattr(expires, "tzinfo") or timezone.is_naive(expires)
            or not now < expires <= now + timedelta(days=90)):
        raise unavailable()
    channel = _channel(org, data["channel_id"], data["profile_ceiling"])
    request = IntegrationClientRequest.objects.create(organization=org, requester=actor, channel=channel,
        profile_ceiling=data["profile_ceiling"], label=data["label"], expires_at=expires,
        collect_deadline=min(expires, now + timedelta(hours=24)), operation_id=data["operation_id"],
        request_hash=request_hash, created_at=now)
    audit.record(org.id, actor, "INTEGRATION_REQUESTED", request.id, operation_id=str(data["operation_id"]))
    if request.profile_ceiling != "DEMO-FULL":
        return _collect_locked(actor, org, request)
    return {"request": request_metadata(request), "client": None}, True


@transaction.atomic
def approve_client(user, request_id):
    actor, org = lock_identity(user)
    require_authority(actor, "INTEGRATION")
    request = IntegrationClientRequest.objects.select_for_update().filter(organization=org, pk=request_id).first()
    if request is None:
        raise missing()
    if request.requester_id == actor.id:
        raise ApiError("SELF_APPROVAL_DENIED", "A different integration authority holder must approve this request.", 403)
    requester = get_user_model().objects.select_for_update().filter(pk=request.requester_id, organization=org).first()
    if requester is None or not has_authority(requester, "INTEGRATION"):
        raise unavailable()
    prior = IntegrationClientApproval.objects.filter(organization=org, request=request).first()
    if prior:
        if prior.approver_id != actor.id:
            raise unavailable()
        return {"request_id": str(request.id), "approval_id": str(prior.id)}, False
    now = timezone.now()
    if request.profile_ceiling != "DEMO-FULL" or now >= request.collect_deadline or now >= request.expires_at:
        raise unavailable()
    _channel(org, request.channel_id, request.profile_ceiling)
    approval = IntegrationClientApproval.objects.create(organization=org, request=request, approver=actor, approved_at=now)
    audit.record(org.id, actor, "INTEGRATION_APPROVED", approval.id)
    return {"request_id": str(request.id), "approval_id": str(approval.id)}, True


@transaction.atomic
def collect_client(user, request_id):
    actor, org = lock_identity(user)
    require_authority(actor, "INTEGRATION")
    request = IntegrationClientRequest.objects.select_for_update().filter(organization=org, pk=request_id).first()
    if request is None:
        raise missing()
    return _collect_locked(actor, org, request)


@transaction.atomic
def revoke_client(user, client_id):
    actor, org = lock_identity(user)
    require_authority(actor, "INTEGRATION")
    client = IntegrationClient.objects.select_for_update().filter(organization=org, pk=client_id).first()
    if client is None:
        raise missing()
    if client.revoked_at is None:
        client.revoked_at, client.revoked_by = timezone.now(), actor
        client.save(update_fields=["revoked_at", "revoked_by"])
        audit.record(org.id, actor, "INTEGRATION_REVOKED", client.id)
    return client_metadata(client)


@transaction.atomic
def administration_state(user, params=None):
    actor, org = lock_identity(user)
    require_authority(actor, "INTEGRATION")
    values = query_values(params if params is not None else QueryDict(), {"page", "page_size"})
    def integer(name, default, maximum):
        value = values.get(name, str(default))
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or not 1 <= len(value) <= 6 or not 1 <= int(value) <= maximum:
            raise ApiError("INVALID_FILTER", "Use supported pagination values.")
        return int(value)
    page, size = integer("page", 1, 100000), integer("page_size", 25, 100)
    clients = IntegrationClient.objects.filter(organization=org).order_by("-created_at", "-id")
    requests = IntegrationClientRequest.objects.filter(organization=org).select_related("integrationclientapproval").order_by("-created_at", "-id")
    offset = (page - 1) * size
    client_count, request_count = clients.count(), requests.count()
    return {"clients": [client_metadata(row) for row in clients[offset:offset + size]],
            "requests": [{**request_metadata(row), "approved": hasattr(row, "integrationclientapproval")}
                         for row in requests[offset:offset + size]],
            "page": page, "page_size": size, "client_count": client_count, "request_count": request_count,
            "clients_more": offset + size < client_count, "requests_more": offset + size < request_count}
