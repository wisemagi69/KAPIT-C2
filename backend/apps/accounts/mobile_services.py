"""Mobile authority and committed security transitions, separate from web auth."""
from datetime import timedelta
import secrets
import uuid

from django.contrib.auth import authenticate
from django.db import connection, transaction
from django.db.models import Q
import jwt

from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.scopes.access import lock_identity, user_object
from apps.scopes.models import Organization

from .models import User, DeviceEnrollment, DeviceFamily, MobileChallenge, RefreshCredential
from .mobile_protocol import (MobileError, canonical_uuid, config, decode64, digest, encode64,
    now, proof_message, timestamp, verify_proof)
from .mobile_throttle import consume


def _actor(org_id, user_id):
    org = Organization.objects.select_for_update().filter(pk=org_id, active=True).first()
    actor = User.objects.select_for_update().filter(pk=user_id, organization_id=org_id, is_active=True).first()
    if org is None or actor is None:
        raise MobileError()
    return actor, org


def _submitter_context(actor):
    if actor.role != "submitter":
        raise MobileError("ACCESS_DENIED", 403)
    from apps.scopes.access import submitter_unit
    from apps.scopes.models import ChannelSource
    from apps.reports.scope_context import is_legacy
    unit = submitter_unit(actor)
    sources = list(ChannelSource.objects.filter(organization_id=actor.organization_id, unit=unit,
        active=True, channel__active=True, channel__organization_id=actor.organization_id)
        .values("max_profile", "channel__max_profile"))
    if not is_legacy([{"source_max": row["max_profile"], "channel_max": row["channel__max_profile"]} for row in sources]):
        raise MobileError("ACCESS_DENIED", 403)
    return user_object(actor)


def lock_mobile_identity(claims):
    """Caller must own a transaction extending through its protected operation."""
    config()
    actor, org = _actor(claims.organization_id, claims.user_id)
    enrollment = DeviceEnrollment.objects.select_for_update().filter(pk=claims.enrollment_id).first()
    family = DeviceFamily.objects.select_for_update().filter(pk=claims.family_id).first()
    instant = now()
    if (enrollment is None or family is None or actor.role != "submitter"
        or actor.permission_version != claims.permission_version
        or enrollment.owner_id != actor.id or enrollment.organization_id != org.id or enrollment.revoked_at is not None
        or family.owner_id != actor.id or family.organization_id != org.id or family.enrollment_id != enrollment.id
        or family.revoked_at is not None or family.absolute_expires_at <= instant
        or family.permission_version != claims.permission_version
        or not secrets.compare_digest(family.auth_stamp, actor.get_session_auth_hash())
        or claims.issued_at < int(family.issued_at.timestamp())
        or claims.expires_at != min(claims.issued_at + config().access_lifetime_seconds, int(family.absolute_expires_at.timestamp()))
        or not claims.issued_at <= int(instant.timestamp()) < claims.expires_at):
        raise MobileError()
    _submitter_context(actor)
    return actor, org, enrollment, family


def context(actor, org, enrollment, family, instant):
    duration = min(config().offline_lease_seconds, int((family.absolute_expires_at - instant).total_seconds()))
    if duration <= 0:
        raise MobileError()
    return {"protocol": config().protocol, "user": _submitter_context(actor), "organization_id": str(org.id),
        "enrollment_id": str(enrollment.id), "family_id": str(family.id), "permission_version": actor.permission_version,
        "template_version": "demo-maintenance-v1", "server_time": timestamp(instant),
        "family_expires_at": timestamp(family.absolute_expires_at),
        "offline_lease_expires_at": timestamp(instant + timedelta(seconds=duration)), "offline_lease_seconds": duration}


def _session(actor, org, enrollment, family, instant, generation=0):
    policy = config()
    expiry = min(int(instant.timestamp()) + policy.access_lifetime_seconds, int(family.absolute_expires_at.timestamp()))
    if expiry <= int(instant.timestamp()):
        raise MobileError()
    claims = {"iss": policy.issuer, "aud": policy.audience, "sub": str(actor.id), "org": str(org.id),
        "did": str(enrollment.id), "sid": str(family.id), "pv": actor.permission_version, "role": "submitter",
        "iat": int(instant.timestamp()), "nbf": int(instant.timestamp()), "exp": expiry, "jti": str(uuid.uuid4()), "token_type": "access"}
    access = jwt.encode(claims, policy.signing_key, algorithm=policy.algorithm, headers={"typ": "JWT"})
    credential_id = uuid.uuid4()
    refresh = str(credential_id) + "." + encode64(secrets.token_bytes(32))
    RefreshCredential.objects.create(id=credential_id, organization=org, family=family,
        digest=digest(refresh.encode("ascii")), generation=generation, issued_at=instant)
    return {"token_type": "Bearer", "access_token": access,
        "access_expires_at": timestamp(instant + timedelta(seconds=expiry-int(instant.timestamp()))),
        "refresh_token": refresh, "refresh_expires_at": timestamp(family.absolute_expires_at),
        "context": context(actor, org, enrollment, family, instant)}


def issue_challenge(data):
    policy = config()
    actor = authenticate(username=data["username"], password=data["password"])
    if actor is None:
        raise MobileError("LOGIN_FAILED")
    stamp, version = actor.get_session_auth_hash(), actor.permission_version
    # Separate counter transaction finishes before authority locks. Conservatively
    # reserve an issuance slot even if a subsequent scope race denies issuance.
    consume("issuance", str(actor.id), 5)
    with transaction.atomic():
        actor, org = _actor(actor.organization_id, actor.id)
        if actor.permission_version != version or not secrets.compare_digest(stamp, actor.get_session_auth_hash()):
            raise MobileError()
        _submitter_context(actor)
        enrollment = None
        if data["enrollment_id"] is not None:
            enrollment = DeviceEnrollment.objects.select_for_update().filter(pk=data["enrollment_id"], owner=actor, organization=org).first()
            # A hint cannot reveal another owner's binding. Same-owner mismatches
            # also fail generically; revoked state is disclosed only after proof.
            if enrollment is None or enrollment.installation_id != data["installation_id"] or enrollment.key_fingerprint != digest(data["public_key_spki"]):
                raise MobileError()
        instant = now()
        obsolete = list(MobileChallenge.objects.filter(owner=actor, created_at__lt=instant-timedelta(hours=24))
            .filter(Q(consumed_at__isnull=False) | Q(expires_at__lte=instant)).order_by("created_at", "id").values_list("id", flat=True)[:100])
        if obsolete:
            MobileChallenge.objects.filter(id__in=obsolete).delete()
        outstanding = list(MobileChallenge.objects.filter(owner=actor, consumed_at__isnull=True).order_by("created_at", "id"))
        for previous in outstanding[:max(0, len(outstanding)-2)]:
            previous.consumed_at = instant
            previous.save(update_fields=["consumed_at"])
        nonce = secrets.token_bytes(32)
        challenge = MobileChallenge.objects.create(organization=org, owner=actor, enrollment=enrollment,
            action="REAUTHENTICATE" if enrollment else "NEW_ENROLLMENT", installation_id=data["installation_id"],
            public_key_spki=data["public_key_spki"], key_fingerprint=digest(data["public_key_spki"]), label=data["label"],
            permission_version=version, auth_stamp=stamp, nonce_digest=digest(nonce), created_at=instant,
            expires_at=instant+timedelta(seconds=policy.challenge_lifetime_seconds))
        audit.record(org.id, actor, "MOBILE_CHALLENGE_ISSUED", challenge.id)
        encoded_nonce = encode64(nonce)
        return {"protocol": policy.protocol, "challenge_id": str(challenge.id), "action": challenge.action,
            "user_id": str(actor.id), "organization_id": str(org.id),
            "enrollment_id": str(enrollment.id) if enrollment else None, "installation_id": str(challenge.installation_id),
            "key_fingerprint": challenge.key_fingerprint, "nonce": encoded_nonce, "server_time": timestamp(instant),
            "expires_at": timestamp(challenge.expires_at), "proof_message": proof_message(challenge, encoded_nonce)}


def _proof_transition(data):
    """Return denials instead of raising so one-use state survives the response."""
    hint = MobileChallenge.objects.filter(pk=data["challenge_id"]).values("owner_id", "organization_id").first()
    if hint is None:
        return MobileError()
    with transaction.atomic():
        # Even disabled/changed actors must not leave an attempted challenge reusable.
        org = Organization.objects.select_for_update().filter(pk=hint["organization_id"]).first()
        actor = User.objects.select_for_update().filter(pk=hint["owner_id"], organization_id=hint["organization_id"]).first()
        if org is None or actor is None:
            return MobileError()
        preliminary = MobileChallenge.objects.get(pk=data["challenge_id"])
        # Globally unique public keys can race across different organizations.
        # Serialize the absent-row creation namespace after org/user locks and
        # before any enrollment rows. A hash collision only adds serialization.
        key_lock = int(preliminary.key_fingerprint[:8], 16)
        if key_lock >= 2**31:
            key_lock -= 2**32
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s, %s)", [746397321, key_lock])
        # Lock all matching identities before families/challenge, including NEW
        # collisions, to serialize global key/installation binding inspection.
        matches = list(DeviceEnrollment.objects.select_for_update().filter(
            Q(key_fingerprint=preliminary.key_fingerprint) | Q(owner=actor, installation_id=preliminary.installation_id)
            | Q(pk=preliminary.enrollment_id)).order_by("id"))
        families = list(DeviceFamily.objects.select_for_update().filter(enrollment_id__in=[e.id for e in matches], owner=actor).order_by("id"))
        challenge = MobileChallenge.objects.select_for_update().get(pk=data["challenge_id"])
        if challenge.consumed_at is not None:
            return MobileError()
        instant = now()
        challenge.consumed_at = instant
        challenge.save(update_fields=["consumed_at"])
        valid = (org.active and actor.is_active and actor.role == "submitter" and actor.permission_version == challenge.permission_version
            and secrets.compare_digest(actor.get_session_auth_hash(), challenge.auth_stamp)
            and challenge.expires_at > instant and verify_proof(challenge, data["nonce"], data["signature"]))
        if valid:
            try:
                _submitter_context(actor)
            except ApiError:
                valid = False
        if not valid:
            audit.record(org.id, actor, "MOBILE_PROOF_DENIED", challenge.id, outcome="DENIED", error_code="AUTH_REQUIRED")
            return MobileError()
        enrollment = next((e for e in matches if e.owner_id == actor.id and e.organization_id == org.id
            and e.installation_id == challenge.installation_id and e.key_fingerprint == challenge.key_fingerprint), None)
        denial = None
        if challenge.action == "NEW_ENROLLMENT":
            if enrollment:
                denial = MobileError("ENROLLMENT_REVOKED", 409) if enrollment.revoked_at else MobileError("ENROLLMENT_EXISTS", 409, enrollment_id=enrollment.id)
            elif matches:
                denial = MobileError("ACCESS_DENIED", 403)
            elif DeviceEnrollment.objects.filter(owner=actor).count() >= 100 or DeviceEnrollment.objects.filter(owner=actor, revoked_at__isnull=True).count() >= 20:
                denial = MobileError("ENROLLMENT_LIMIT", 409)
            else:
                enrollment = DeviceEnrollment.objects.create(organization=org, owner=actor, installation_id=challenge.installation_id,
                    public_key_spki=bytes(challenge.public_key_spki), key_fingerprint=challenge.key_fingerprint, label=challenge.label,
                    created_at=instant, last_authenticated_at=instant)
        elif enrollment is None or enrollment.id != challenge.enrollment_id:
            denial = MobileError("ACCESS_DENIED", 403)
        elif enrollment.revoked_at is not None:
            denial = MobileError("ENROLLMENT_REVOKED", 409)
        if denial:
            audit.record(org.id, actor, "MOBILE_PROOF_DENIED", challenge.id, outcome="DENIED", error_code=denial.safe_body["code"])
            return denial
        for family in families:
            if family.enrollment_id == enrollment.id and family.revoked_at is None:
                family.revoked_at = instant
                family.save(update_fields=["revoked_at"])
        family = DeviceFamily.objects.create(organization=org, owner=actor, enrollment=enrollment,
            permission_version=actor.permission_version, auth_stamp=actor.get_session_auth_hash(), issued_at=instant,
            absolute_expires_at=instant+timedelta(seconds=config().family_lifetime_seconds))
        enrollment.last_authenticated_at = instant
        enrollment.save(update_fields=["last_authenticated_at"])
        result = _session(actor, org, enrollment, family, instant)
        audit.record(org.id, actor, "MOBILE_AUTHENTICATED", enrollment.id)
        return result


def complete_proof(data):
    config()
    result = _proof_transition(data)
    if isinstance(result, MobileError):
        raise result
    return result


def _refresh_transition(value):
    try:
        handle, secret = value.split(".")
        credential_id = canonical_uuid(handle)
        decode64(secret, 43, size=32)
    except (ValueError, TypeError):
        return MobileError()
    hint = RefreshCredential.objects.filter(pk=credential_id).values("family__owner_id", "family__enrollment_id", "family_id", "organization_id").first()
    if hint is None:
        return MobileError()
    with transaction.atomic():
        # A verified consumed credential must permanently revoke its family
        # even during temporary identity inactivity. Preserve authority lock
        # order, but defer active-issuance checks until after digest/reuse.
        org = Organization.objects.select_for_update().filter(pk=hint["organization_id"]).first()
        actor = User.objects.select_for_update().filter(pk=hint["family__owner_id"], organization_id=hint["organization_id"]).first()
        if org is None or actor is None:
            return MobileError()
        enrollment = DeviceEnrollment.objects.select_for_update().get(pk=hint["family__enrollment_id"])
        family = DeviceFamily.objects.select_for_update().get(pk=hint["family_id"])
        credential = RefreshCredential.objects.select_for_update().get(pk=credential_id)
        if not secrets.compare_digest(credential.digest, digest(value.encode("ascii"))):
            return MobileError()
        instant = now()
        if credential.consumed_at is not None:
            if family.revoked_at is None:
                family.revoked_at = instant
                family.save(update_fields=["revoked_at"])
                audit.record(org.id, actor, "MOBILE_REFRESH_REUSED", family.id, outcome="DENIED", error_code="REFRESH_REUSED")
            return MobileError("REFRESH_REUSED")
        if (not org.active or not actor.is_active
            or credential.revoked_at is not None or enrollment.revoked_at is not None or family.revoked_at is not None
            or family.absolute_expires_at <= instant or family.owner_id != actor.id or enrollment.owner_id != actor.id
            or family.organization_id != org.id or enrollment.organization_id != org.id
            or actor.role != "submitter" or family.permission_version != actor.permission_version
            or not secrets.compare_digest(family.auth_stamp, actor.get_session_auth_hash())):
            return MobileError()
        try:
            _submitter_context(actor)
        except ApiError:
            return MobileError("ACCESS_DENIED", 403)
        credential.consumed_at = instant
        credential.save(update_fields=["consumed_at"])
        result = _session(actor, org, enrollment, family, instant, credential.generation+1)
        audit.record(org.id, actor, "MOBILE_REFRESH_ROTATED", family.id)
        return result


def rotate_refresh(value):
    config()
    result = _refresh_transition(value)
    if isinstance(result, MobileError):
        raise result
    return result


@transaction.atomic
def mobile_context(claims):
    return context(*lock_mobile_identity(claims), now())


@transaction.atomic
def logout_mobile(claims):
    actor, org, _, family = lock_mobile_identity(claims)
    family.revoked_at = now()
    family.save(update_fields=["revoked_at"])
    audit.record(org.id, actor, "MOBILE_LOGGED_OUT", family.id)
    return {"logged_out": True}


@transaction.atomic
def list_devices(user):
    actor, _ = lock_identity(user)
    rows = DeviceEnrollment.objects.filter(owner=actor, organization_id=actor.organization_id).order_by("-created_at", "-id")
    count = rows.count()
    if count > 100:
        raise MobileError("SERVER_ERROR", 503)
    return {"results": [{"id": str(row.id), "label": row.label, "created_at": timestamp(row.created_at),
        "last_authenticated_at": timestamp(row.last_authenticated_at), "revoked_at": timestamp(row.revoked_at) if row.revoked_at else None}
        for row in rows], "count": count}


@transaction.atomic
def revoke_device(user, enrollment_id):
    actor, org = lock_identity(user)
    enrollment = DeviceEnrollment.objects.select_for_update().filter(pk=enrollment_id, owner=actor, organization=org).first()
    if enrollment is None:
        raise missing()
    families = list(DeviceFamily.objects.select_for_update().filter(enrollment=enrollment).order_by("id"))
    if enrollment.revoked_at is None:
        instant = now()
        enrollment.revoked_at = instant
        enrollment.save(update_fields=["revoked_at"])
        for family in families:
            if family.revoked_at is None:
                family.revoked_at = instant
                family.save(update_fields=["revoked_at"])
        audit.record(org.id, actor, "MOBILE_DEVICE_REVOKED", enrollment.id)
    return {"id": str(enrollment.id), "revoked": True, "revoked_at": timestamp(enrollment.revoked_at)}
