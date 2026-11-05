import copy
from datetime import timedelta
import hashlib
import json
import secrets
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings
import jwt

from apps.accounts.models import User, DeviceEnrollment, DeviceFamily, MobileChallenge, RefreshCredential, MobileThrottle
from apps.accounts.mobile_protocol import encode64, now
from apps.accounts.mobile_services import revoke_device
from apps.accounts.mobile_throttle import consume
from apps.audit.models import AuditEvent
from apps.scopes.models import UnitMembership, ChannelSource
from config.mobile import MobileAuthConfig
from .helpers import MOBILE, MOBILE_SETTINGS, MobileFixtures


@override_settings(**MOBILE_SETTINGS)
class MobileAuthTests(MobileFixtures, TestCase):
    def test_enrollment_context_fixed_claims_and_hashed_refresh(self):
        session = self.enroll()
        self.assertEqual(set(session), {"token_type", "access_token", "access_expires_at", "refresh_token", "refresh_expires_at", "context"})
        response = self.me(session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"], session["context"]["user"])
        self.assertEqual(response.json()["family_id"], session["context"]["family_id"])
        self.assertEqual(session["context"]["offline_lease_seconds"], 86400)
        self.assertTrue(session["access_expires_at"].endswith(".000000Z"))
        decoded = jwt.decode_complete(session["access_token"], settings.KAPIT_MOBILE_AUTH.signing_key,
            algorithms=["HS256"], audience="kapit-android", issuer="kapit-local-mobile")
        self.assertEqual(decoded["header"], {"alg": "HS256", "typ": "JWT"})
        body = decoded["payload"]
        self.assertEqual(set(body), {"iss", "aud", "sub", "org", "did", "sid", "pv", "role", "iat", "nbf", "exp", "jti", "token_type"})
        self.assertEqual(body["exp"]-body["iat"], 600)
        credential = RefreshCredential.objects.get()
        self.assertEqual(credential.digest, hashlib.sha256(session["refresh_token"].encode("ascii")).hexdigest())
        self.assertEqual(credential.generation, 0)
        self.assertNotIn(session["refresh_token"], json.dumps(list(AuditEvent.objects.values("safe_metadata"))))

    def test_invalid_proof_is_consumed_and_audited_before_denial(self):
        challenge = self.challenge()
        body = self.proof_body(challenge)
        invalid = dict(body, signature=encode64(b"invalid"))
        self.assert_auth_denied(self.client.post(MOBILE+"auth/token/", invalid, format="json"))
        self.assertIsNotNone(MobileChallenge.objects.get().consumed_at)
        self.assertEqual(AuditEvent.objects.filter(action="MOBILE_PROOF_DENIED").count(), 1)
        self.assert_auth_denied(self.client.post(MOBILE+"auth/token/", body, format="json"))
        self.assertEqual(DeviceFamily.objects.count(), 0)

    def test_nonce_mismatch_consumes_challenge(self):
        challenge = self.challenge()
        body = dict(self.proof_body(challenge), nonce=encode64(secrets.token_bytes(32)))
        self.assert_auth_denied(self.client.post(MOBILE+"auth/token/", body, format="json"))
        self.assertIsNotNone(MobileChallenge.objects.get().consumed_at)

    def test_expired_and_permission_changed_challenges_are_consumed(self):
        with patch("apps.accounts.mobile_services.now", return_value=now()-timedelta(seconds=121)):
            old = self.challenge()
        self.assert_auth_denied(self.client.post(MOBILE+"auth/token/", self.proof_body(old), format="json"))
        challenge = self.challenge()
        User.objects.filter(pk=self.owner.pk).update(permission_version=1)
        self.assert_auth_denied(self.client.post(MOBILE+"auth/token/", self.proof_body(challenge), format="json"))
        self.assertEqual(MobileChallenge.objects.filter(consumed_at__isnull=False).count(), 2)

    def test_duplicate_binding_discloses_only_own_verified_enrollment(self):
        session = self.enroll()
        challenge = self.challenge()
        response = self.client.post(MOBILE+"auth/token/", self.proof_body(challenge), format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "ENROLLMENT_EXISTS")
        self.assertEqual(response.json()["enrollment_id"], session["context"]["enrollment_id"])
        challenge = self.challenge(installation=str(uuid.uuid4()))
        response = self.client.post(MOBILE+"auth/token/", self.proof_body(challenge), format="json")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("enrollment_id", response.json())
        self.assertEqual(DeviceEnrollment.objects.count(), 1)

    def test_revoked_key_tombstone_cannot_be_reactivated_or_rebound(self):
        session = self.enroll()
        revoke_device(self.owner, session["context"]["enrollment_id"])
        for installation, expected in [(self.installation, 409), (str(uuid.uuid4()), 403)]:
            challenge = self.challenge(installation=installation)
            response = self.client.post(MOBILE+"auth/token/", self.proof_body(challenge), format="json")
            self.assertEqual(response.status_code, expected)
            self.assertNotIn("enrollment_id", response.json())
        self.assertEqual(DeviceEnrollment.objects.count(), 1)
        fresh = self.enroll(key=ec.generate_private_key(ec.SECP256R1()), installation=str(uuid.uuid4()))
        self.assertNotEqual(fresh["context"]["enrollment_id"], session["context"]["enrollment_id"])

    def test_reauthentication_preserves_enrollment_and_replaces_only_its_family(self):
        web, _ = self.web()
        session = self.enroll()
        other = self.enroll(key=ec.generate_private_key(ec.SECP256R1()), installation=str(uuid.uuid4()))
        recovered = self.enroll(enrollment=session["context"]["enrollment_id"])
        self.assertEqual(recovered["context"]["enrollment_id"], session["context"]["enrollment_id"])
        self.assertNotEqual(recovered["context"]["family_id"], session["context"]["family_id"])
        self.assert_auth_denied(self.me(session))
        self.assertEqual(self.me(recovered).status_code, 200)
        self.assertEqual(self.me(other).status_code, 200)
        self.assertEqual(web.get("/api/v1/account/devices/").status_code, 200)

    def test_refresh_rotation_replay_revokes_family_before_denial(self):
        session = self.enroll()
        response = self.refresh(session)
        self.assertEqual(response.status_code, 200)
        successor = response.json()
        self.assertEqual(successor["refresh_expires_at"], session["refresh_expires_at"])
        self.assert_auth_denied(self.refresh(session), "REFRESH_REUSED")
        family = DeviceFamily.objects.get()
        self.assertIsNotNone(family.revoked_at)
        self.assertEqual(RefreshCredential.objects.count(), 2)
        self.assert_auth_denied(self.me(successor))
        self.assert_auth_denied(self.refresh(successor))

    def test_unknown_secret_does_not_revoke_guessed_family(self):
        session = self.enroll()
        wrong = dict(session, refresh_token=session["refresh_token"].split(".")[0]+"."+encode64(secrets.token_bytes(32)))
        self.assert_auth_denied(self.refresh(wrong))
        self.assertIsNone(DeviceFamily.objects.get().revoked_at)
        self.assertEqual(self.me(session).status_code, 200)

    def test_lost_refresh_reply_recovers_same_enrollment_with_password_proof(self):
        session = self.enroll()
        self.assertEqual(self.refresh(session).status_code, 200)  # Response deliberately discarded.
        recovered = self.enroll(enrollment=session["context"]["enrollment_id"])
        self.assertEqual(session["context"]["enrollment_id"], recovered["context"]["enrollment_id"])
        self.assertEqual(self.me(recovered).status_code, 200)
        self.assertEqual(DeviceFamily.objects.filter(revoked_at__isnull=True).count(), 1)

    def test_password_permission_role_and_account_changes_invalidate_access(self):
        for field, value in [("password", "unusable"), ("permission_version", 9), ("role", "reviewer"), ("is_active", False)]:
            with self.subTest(field=field):
                session = self.enroll(key=ec.generate_private_key(ec.SECP256R1()), installation=str(uuid.uuid4()))
                original = getattr(self.owner, field)
                User.objects.filter(pk=self.owner.pk).update(**{field: value})
                self.assert_auth_denied(self.me(session))
                self.assert_auth_denied(self.refresh(session))
                User.objects.filter(pk=self.owner.pk).update(**{field: original})

    def test_live_scope_failure_is_403_and_org_deactivation_is_401(self):
        session = self.enroll()
        memberships = UnitMembership.objects.filter(user=self.owner)
        memberships.update(active=False)
        response = self.me(session)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "ACCESS_DENIED")
        self.org.active = False
        self.org.save(update_fields=["active"])
        self.assert_auth_denied(self.me(session))

    def test_logout_is_one_family_only_and_repeated_bearer_is_denied(self):
        session = self.enroll()
        other = self.enroll(key=ec.generate_private_key(ec.SECP256R1()), installation=str(uuid.uuid4()))
        response = self.client.post(MOBILE+"auth/logout/", {}, format="json", HTTP_AUTHORIZATION="Bearer "+session["access_token"])
        self.assertEqual(response.json(), {"logged_out": True})
        self.assert_auth_denied(self.me(session))
        self.assertEqual(self.me(other).status_code, 200)

    def test_web_cookie_and_mobile_bearer_remain_separate(self):
        web, csrf = self.web()
        session = self.enroll()
        self.assert_auth_denied(web.get(MOBILE+"me/"))
        bearer_only = self.client.get("/api/v1/account/devices/", HTTP_AUTHORIZATION="Bearer "+session["access_token"])
        self.assertEqual(bearer_only.status_code, 403)
        url = "/api/v1/account/devices/"+session["context"]["enrollment_id"]+"/revoke/"
        response = web.post(url, {}, format="json", HTTP_AUTHORIZATION="Bearer "+session["access_token"])
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "CSRF_FAILED")
        self.assertIsNone(DeviceEnrollment.objects.get().revoked_at)
        self.assertEqual(web.post(url, {}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code, 200)

    def test_owner_revoke_is_idempotent_and_foreign_ids_are_hidden(self):
        session = self.enroll()
        web, csrf = self.web()
        url = "/api/v1/account/devices/"+session["context"]["enrollment_id"]+"/revoke/"
        first = web.post(url, {}, format="json", HTTP_X_CSRFTOKEN=csrf)
        second = web.post(url, {}, format="json", HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), second.json())
        self.assertEqual(AuditEvent.objects.filter(action="MOBILE_DEVICE_REVOKED").count(), 1)
        self.assert_auth_denied(self.me(session))
        foreign, foreign_csrf = self.web("reviewer")
        self.assertEqual(foreign.get("/api/v1/account/devices/").json(), {"count": 0, "results": []})
        denied = foreign.post(url, {}, format="json", HTTP_X_CSRFTOKEN=foreign_csrf)
        unknown = foreign.post("/api/v1/account/devices/"+str(uuid.uuid4())+"/revoke/", {}, format="json", HTTP_X_CSRFTOKEN=foreign_csrf)
        self.assertEqual(denied.status_code, 404)
        self.assertEqual(denied.json(), unknown.json())

    def test_role_changed_owner_can_manage_historical_devices(self):
        session = self.enroll()
        User.objects.filter(pk=self.owner.pk).update(role="administrator", permission_version=1)
        web, csrf = self.web()
        self.assertEqual(web.get("/api/v1/account/devices/").json()["count"], 1)
        response = web.post("/api/v1/account/devices/"+session["context"]["enrollment_id"]+"/revoke/", {}, format="json", HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(response.status_code, 200)

    def test_audit_failure_cannot_issue_family_or_consume_proof_success(self):
        challenge = self.challenge()
        with patch("apps.accounts.mobile_services.audit.record", side_effect=RuntimeError("SENSITIVE_FAILURE_CANARY")):
            response = self.client.post(MOBILE+"auth/token/", self.proof_body(challenge), format="json")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("SENSITIVE_FAILURE_CANARY", response.content.decode())
        self.assertEqual(DeviceFamily.objects.count(), 0)
        self.assertEqual(RefreshCredential.objects.count(), 0)
        self.assertIsNone(MobileChallenge.objects.get().consumed_at)

    def test_inactive_config_fails_closed_without_breaking_web(self):
        with override_settings(KAPIT_MOBILE_AUTH=MobileAuthConfig(False, "MOBILE_DISABLED")):
            response = self.client.get(MOBILE+"me/")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["code"], "MOBILE_UNAVAILABLE")
            self.assertEqual(self.client.get("/api/v1/auth/csrf/").status_code, 200)

    def test_bad_password_unknown_user_and_non_submitter_authority(self):
        body = self.challenge_body()
        body["password"] = "incorrect"
        first = self.client.post(MOBILE+"auth/challenge/", body, format="json")
        body["username"] = "unknown-synthetic-user"
        second = self.client.post(MOBILE+"auth/challenge/", body, format="json")
        self.assert_auth_denied(first, "LOGIN_FAILED")
        self.assertEqual(first.json(), second.json())
        body = self.challenge_body(owner=User.objects.get(username="reviewer"))
        response = self.client.post(MOBILE+"auth/challenge/", body, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(MobileChallenge.objects.count(), 0)

    def test_malformed_signed_jwt_containers_unicode_and_numeric_types(self):
        session = self.enroll()
        original = jwt.decode(session["access_token"], options={"verify_signature": False})
        cases = [("aud", ["kapit-android"]), ("iss", {}), ("sub", []), ("sub", "\ud800"),
            ("did", str(uuid.uuid4()).upper()), ("pv", True), ("pv", -1), ("iat", "2"),
            ("nbf", []), ("exp", {}), ("exp", float("inf")), ("role", ["submitter"]), ("jti", 1)]
        for field, value in cases:
            with self.subTest(field=field, kind=type(value).__name__):
                payload = dict(original, **{field: value})
                # The high-level encoder validates some claim types before
                # signing. Use maintained JWS over bounded JSON so malformed
                # but correctly signed claims actually reach our decoder.
                token = jwt.api_jws.encode(json.dumps(payload, separators=(",", ":")).encode("ascii"),
                    settings.KAPIT_MOBILE_AUTH.signing_key, algorithm="HS256")
                response = self.me(dict(session, access_token=token))
                self.assert_auth_denied(response)
                self.assertNotIn(session["refresh_token"], response.content.decode())
        for headers in [{"kid": "UNTRUSTED_KEY_CANARY"}, {"jwk": {}}, {"typ": "OTHER"}]:
            token = jwt.encode(original, settings.KAPIT_MOBILE_AUTH.signing_key, algorithm="HS256", headers=headers)
            response = self.me(dict(session, access_token=token))
            self.assert_auth_denied(response)
            self.assertNotIn("UNTRUSTED_KEY_CANARY", response.content.decode())

    def test_bounded_json_and_schema_fail_without_reflecting_input(self):
        cases = [(b'{"username":"a","username":"b"}', 400), (b'[]', 400),
            (b'{"username":"\\ud800"}', 400), (b'{"x":NaN}', 400), (b"x"*20481, 413)]
        for body, expected in cases:
            response = self.client.post(MOBILE+"auth/challenge/", body, content_type="application/json")
            self.assertEqual(response.status_code, expected)
        response = self.client.post(MOBILE+"auth/challenge/", "username=canary", content_type="application/x-www-form-urlencoded")
        self.assertEqual(response.status_code, 415)
        body = self.challenge_body()
        body["SENSITIVE_UNKNOWN_FIELD"] = "SENSITIVE_VALUE"
        response = self.client.post(MOBILE+"auth/challenge/", body, format="json")
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("SENSITIVE_", response.content.decode())

    def test_invalid_curve_canonical_uuid_label_and_query_are_rejected(self):
        bodies = [self.challenge_body(key=ec.generate_private_key(ec.SECP384R1())),
            dict(self.challenge_body(), installation_id=self.installation.upper()),
            dict(self.challenge_body(), label="\nBAD"), dict(self.challenge_body(), public_key_spki="CANARY_NOT_A_KEY")]
        for body in bodies:
            response = self.client.post(MOBILE+"auth/challenge/", body, format="json")
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("CANARY_NOT_A_KEY", response.content.decode())
        response = self.client.post(MOBILE+"auth/challenge/?extra=private", self.challenge_body(), format="json")
        self.assertEqual(response.status_code, 400)

    def test_peer_username_issuance_throttles_and_outstanding_bound(self):
        for _ in range(5):
            self.challenge()
        self.assertEqual(MobileChallenge.objects.filter(consumed_at__isnull=True).count(), 3)
        response = self.client.post(MOBILE+"auth/challenge/", self.challenge_body(), format="json")
        self.assertEqual(response.status_code, 429)
        self.assertTrue(1 <= int(response["Retry-After"]) <= 300)
        self.assertEqual(MobileChallenge.objects.count(), 5)
        for _ in range(5):
            response = self.client.post(MOBILE+"auth/challenge/", dict(self.challenge_body(), password="wrong"), format="json")
        self.assertEqual(response.status_code, 429)
        for index in range(20):
            response = self.client.post(MOBILE+"auth/refresh/", {"refresh_token": "invalid"}, format="json", HTTP_X_FORWARDED_FOR=str(index))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(MobileThrottle.objects.count(), 3)
        self.assertTrue(all(len(key) == 64 for key in MobileThrottle.objects.values_list("key", flat=True)))

    def test_throttle_storage_capacity_cleanup_window_and_failure(self):
        instant = now()
        MobileThrottle.objects.bulk_create([MobileThrottle(key=f"{index:064x}", window_start=0, attempts=1, updated_at=instant) for index in range(4096)])
        response = self.client.post(MOBILE+"auth/refresh/", {"refresh_token": "invalid"}, format="json")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(MobileThrottle.objects.count(), 4096)
        MobileThrottle.objects.all().update(updated_at=instant-timedelta(hours=25))
        consume("unit", "synthetic", 1)
        self.assertEqual(MobileThrottle.objects.count(), 3997)
        with self.assertRaises(Exception) as caught:
            consume("unit", "synthetic", 1)
        self.assertEqual(caught.exception.status_code, 429)
        with patch("apps.accounts.mobile_throttle.now", return_value=instant+timedelta(seconds=301)):
            consume("unit", "synthetic", 1)
        with patch("apps.accounts.mobile_throttle.MobileThrottle.objects.filter", side_effect=DatabaseError("CANARY")):
            response = self.client.post(MOBILE+"auth/refresh/", {"refresh_token": "invalid"}, format="json")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("CANARY", response.content.decode())

    def test_database_guards_prevent_binding_rewrites_and_tombstone_reset(self):
        session = self.enroll()
        enrollment = DeviceEnrollment.objects.get()
        other = self.another_owner(same_org=True)
        for changes in [{"installation_id": uuid.uuid4()}, {"owner": other}, {"key_fingerprint": "f"*64}]:
            with self.assertRaises(DatabaseError), transaction.atomic():
                DeviceEnrollment.objects.filter(pk=enrollment.pk).update(**changes)
        family = DeviceFamily.objects.get()
        with self.assertRaises(DatabaseError), transaction.atomic():
            DeviceFamily.objects.create(organization=self.org, owner=other, enrollment=enrollment,
                permission_version=0, auth_stamp=other.get_session_auth_hash(), issued_at=now(),
                absolute_expires_at=now()+timedelta(days=7), revoked_at=now())
        revoke_device(self.owner, enrollment.pk)
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("UPDATE accounts_deviceenrollment SET revoked_at = NULL WHERE id = %s", [enrollment.id])
        with self.assertRaises(DatabaseError), transaction.atomic():
            DeviceFamily.objects.filter(pk=family.pk).update(revoked_at=None)
        challenge = MobileChallenge.objects.get()
        with self.assertRaises(DatabaseError), transaction.atomic():
            MobileChallenge.objects.filter(pk=challenge.pk).update(consumed_at=None)
        with self.assertRaises(DatabaseError), transaction.atomic():
            MobileChallenge.objects.filter(pk=challenge.pk).delete()
        self.assertEqual(DeviceEnrollment.objects.count(), 1)
        self.assertEqual(DeviceFamily.objects.count(), 1)
        self.assertEqual(RefreshCredential.objects.count(), 1)

    def test_cross_org_family_and_refresh_references_fail_direct_sql_guards(self):
        self.enroll()
        other = self.another_owner()
        family = DeviceFamily.objects.get()
        with self.assertRaises(DatabaseError), transaction.atomic():
            RefreshCredential.objects.create(organization=other.organization, family=family, generation=1,
                digest="f"*64, issued_at=now(), revoked_at=now())
        with self.assertRaises(DatabaseError), transaction.atomic():
            DeviceFamily.objects.create(organization=other.organization, owner=other, enrollment=family.enrollment,
                permission_version=0, auth_stamp=other.get_session_auth_hash(), issued_at=now(),
                absolute_expires_at=now()+timedelta(days=7), revoked_at=now())
        self.assertEqual(DeviceFamily.objects.count(), 1)

    def test_active_and_lifetime_enrollment_caps_do_not_create_extra_families(self):
        stamp = now()
        for index in range(100):
            public = ("synthetic-test-binding-"+str(index)).encode("ascii")
            DeviceEnrollment.objects.create(organization=self.org, owner=self.owner, installation_id=uuid.uuid4(),
                public_key_spki=public, key_fingerprint=hashlib.sha256(public).hexdigest(), label="Synthetic retained binding",
                created_at=stamp, last_authenticated_at=stamp, revoked_at=stamp if index >= 20 else None)
        challenge = self.challenge()
        response = self.client.post(MOBILE+"auth/token/", self.proof_body(challenge), format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "ENROLLMENT_LIMIT")
        self.assertEqual(DeviceEnrollment.objects.count(), 100)
        self.assertEqual(DeviceFamily.objects.count(), 0)
        self.assertIsNotNone(MobileChallenge.objects.get().consumed_at)

    def test_family_expiry_and_incorrect_access_lifetime_are_denied(self):
        session = self.enroll()
        payload = jwt.decode(session["access_token"], options={"verify_signature": False})
        payload["exp"] -= 1
        malformed = jwt.encode(payload, settings.KAPIT_MOBILE_AUTH.signing_key, algorithm="HS256")
        self.assert_auth_denied(self.me(dict(session, access_token=malformed)))
        family = DeviceFamily.objects.get()
        with patch("apps.accounts.mobile_services.now", return_value=family.absolute_expires_at):
            self.assert_auth_denied(self.refresh(session))

    def test_refresh_consume_tombstone_and_binding_are_immutable(self):
        session = self.enroll()
        original = RefreshCredential.objects.get()
        self.assertEqual(self.refresh(session).status_code, 200)
        for changes in [{"consumed_at": None}, {"digest": "f"*64}, {"generation": 9}]:
            with self.assertRaises(DatabaseError), transaction.atomic():
                RefreshCredential.objects.filter(pk=original.id).update(**changes)
        self.assertEqual(RefreshCredential.objects.count(), 2)
