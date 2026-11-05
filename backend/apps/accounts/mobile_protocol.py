"""Bounded wire primitives for the frozen synthetic mobile contract."""
import base64
from dataclasses import dataclass
import hashlib
import json
import re
import unicodedata
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import UnsupportedAlgorithm
from django.conf import settings
from django.utils import timezone
import jwt
from rest_framework import serializers

from apps.operations.errors import ApiError
from apps.operations.parsers import BoundedJSONParser
from apps.operations.parsers import unique_object
from apps.operations.serializers import StrictSerializer
from config.mobile import MobileConfigurationUnavailable


AUTH_HEADER = 'Bearer realm="kapit-mobile"'
CLAIMS = {"iss", "aud", "sub", "org", "did", "sid", "pv", "role", "iat", "nbf", "exp", "jti", "token_type"}
MESSAGES = {
    "AUTH_REQUIRED": "Sign in again to continue.",
    "LOGIN_FAILED": "The username or password was not accepted.",
    "REFRESH_REUSED": "Sign in again to continue.",
    "ACCESS_DENIED": "This action is unavailable.",
    "ENROLLMENT_EXISTS": "Resume the existing enrollment with a new proof.",
    "ENROLLMENT_REVOKED": "This enrollment is revoked.",
    "ENROLLMENT_LIMIT": "The enrollment limit has been reached.",
    "THROTTLED": "Wait before trying again.",
    "MOBILE_UNAVAILABLE": "Mobile authentication is unavailable.",
    "SERVER_ERROR": "The service is unavailable. Try again later.",
}


class MobileError(ApiError):
    def __init__(self, code="AUTH_REQUIRED", status=401, *, enrollment_id=None, retry_after=None):
        super().__init__(code, MESSAGES[code], status)
        self.headers = {"WWW-Authenticate": AUTH_HEADER} if status == 401 else {}
        if enrollment_id is not None and code == "ENROLLMENT_EXISTS":
            self.safe_body["enrollment_id"] = str(enrollment_id)
        if retry_after is not None:
            self.headers["Retry-After"] = str(retry_after)


def config():
    try:
        return settings.KAPIT_MOBILE_AUTH.require_available()
    except (AttributeError, MobileConfigurationUnavailable):
        raise MobileError("MOBILE_UNAVAILABLE", 503) from None


def now():
    return timezone.now().replace(microsecond=0)


def timestamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def encode64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode64(value, maximum, *, size=None):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if encode64(raw) != value or (size is not None and len(raw) != size):
        raise ValueError
    return raw


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError
    return uuid.UUID(value)


def scalar_text(value):
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, dict):
        for key, child in value.items():
            scalar_text(key); scalar_text(child)
    elif isinstance(value, list):
        for child in value:
            scalar_text(child)


class MobileJSONParser(BoundedJSONParser):
    def parse(self, *args, **kwargs):
        result = super().parse(*args, **kwargs)
        try:
            scalar_text(result)
        except (UnicodeError, RecursionError):
            raise ApiError("INVALID_JSON", "Send one valid JSON object.") from None
        return result


class CanonicalUUIDField(serializers.Field):
    def to_internal_value(self, value):
        try:
            return canonical_uuid(value)
        except (ValueError, TypeError, AttributeError):
            raise serializers.ValidationError("Use a canonical identifier.") from None


def public_key(value):
    raw = decode64(value, 200)
    key = serialization.load_der_public_key(raw)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError
    if key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != raw:
        raise ValueError
    return raw


class ChallengeSerializer(StrictSerializer):
    username = serializers.CharField(max_length=150, trim_whitespace=False)
    password = serializers.CharField(max_length=128, trim_whitespace=False, write_only=True)
    installation_id = CanonicalUUIDField()
    enrollment_id = CanonicalUUIDField(allow_null=True)
    public_key_spki = serializers.CharField(max_length=200, trim_whitespace=False)
    label = serializers.CharField(min_length=1, max_length=80, trim_whitespace=False)

    def validate_label(self, value):
        if not value.strip() or any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in value):
            raise serializers.ValidationError("Use a short display label without control characters.")
        return value

    def validate(self, attrs):
        # Size checks precede the maintained curve parser. No key values escape.
        try:
            attrs["public_key_spki"] = public_key(attrs["public_key_spki"])
        except (ValueError, TypeError, UnicodeError, UnsupportedAlgorithm):
            raise serializers.ValidationError({"public_key_spki": ["Use a supported enrollment public key."]}) from None
        return attrs


class TokenSerializer(StrictSerializer):
    challenge_id = CanonicalUUIDField()
    nonce = serializers.CharField(max_length=43, trim_whitespace=False)
    signature = serializers.CharField(max_length=100, trim_whitespace=False)


class RefreshSerializer(StrictSerializer):
    refresh_token = serializers.CharField(max_length=80, trim_whitespace=False, write_only=True)


class EmptySerializer(StrictSerializer):
    pass


def proof_message(challenge, nonce):
    return "\n".join([
        "KAPIT-C2-MOBILE-PROOF-V1", challenge.action, str(challenge.id), str(challenge.owner_id),
        str(challenge.organization_id), str(challenge.enrollment_id) if challenge.enrollment_id else "-",
        str(challenge.installation_id), challenge.key_fingerprint, nonce, str(int(challenge.expires_at.timestamp())),
    ]) + "\n"


def digest(value):
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class MobileClaims:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    enrollment_id: uuid.UUID
    family_id: uuid.UUID
    permission_version: int
    issued_at: int
    expires_at: int


def decode_access(token):
    policy = config()
    try:
        if not isinstance(token, str) or len(token) > 2048:
            raise ValueError
        pieces = token.split(".")
        if len(pieces) != 3:
            raise ValueError
        for piece in pieces[:2]:
            part = json.loads(decode64(piece, 2048).decode("utf-8"), object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(part, dict):
                raise ValueError
            scalar_text(part)
        decoded = jwt.decode_complete(token, policy.signing_key, algorithms=[policy.algorithm],
            issuer=policy.issuer, audience=policy.audience, leeway=0,
            options={"require": sorted(CLAIMS), "strict_aud": True})
        header, body = decoded["header"], decoded["payload"]
        if header != {"alg": "HS256", "typ": "JWT"} or set(body) != CLAIMS:
            raise ValueError
        if body["iss"] != policy.issuer or body["aud"] != policy.audience or body["role"] != "submitter" or body["token_type"] != "access":
            raise ValueError
        if any(type(body[key]) is not int for key in ["pv", "iat", "nbf", "exp"]) or body["pv"] < 0:
            raise ValueError
        instant = int(now().timestamp())
        if not (0 <= body["iat"] == body["nbf"] <= instant < body["exp"] <= body["iat"] + policy.access_lifetime_seconds):
            raise ValueError
        canonical_uuid(body["jti"])
        return MobileClaims(canonical_uuid(body["sub"]), canonical_uuid(body["org"]), canonical_uuid(body["did"]),
            canonical_uuid(body["sid"]), body["pv"], body["iat"], body["exp"])
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, jwt.PyJWTError):
        raise MobileError() from None


def verify_proof(challenge, nonce, signature):
    try:
        raw_nonce = decode64(nonce, 43, size=32)
        import secrets
        if not secrets.compare_digest(digest(raw_nonce), challenge.nonce_digest):
            return False
        key = serialization.load_der_public_key(bytes(challenge.public_key_spki))
        key.verify(decode64(signature, 100), proof_message(challenge, nonce).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        # Verification is deliberately opaque; no crypto exception text escapes.
        return False
