import secrets
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management import call_command
from django.db import connection
from django.test import override_settings
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.accounts.mobile_protocol import encode64
from apps.scopes.models import Organization, Unit, UnitMembership, SharingChannel, ChannelSource
from config.mobile import MobileAuthConfig


MOBILE = "/api/v1/mobile/"
PASSWORD = "DemoMaintenance!2026"
MOBILE_SETTINGS = dict(ROOT_URLCONF="tests.mobile.urls",
    KAPIT_SOURCE_KEY=Fernet.generate_key(),
    KAPIT_MOBILE_AUTH=MobileAuthConfig(True, None, secrets.token_bytes(32)),
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])


class MobileFixtures:
    def setUp(self):
        super().setUp()
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        self.owner = User.objects.get(username="submitter")
        self.org = self.owner.organization
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.installation = str(uuid.uuid4())
        self.client = self.api()

    @staticmethod
    def api():
        client = APIClient(enforce_csrf_checks=True)
        client.raise_request_exception = False
        return client

    def challenge_body(self, *, key=None, owner=None, installation=None, enrollment=None, **changes):
        key, owner = key or self.key, owner or self.owner
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return dict(username=owner.username, password=PASSWORD, installation_id=installation or self.installation,
            enrollment_id=enrollment, public_key_spki=encode64(public), label="Synthetic Android", **changes)

    def challenge(self, **kwargs):
        response = self.client.post(MOBILE+"auth/challenge/", self.challenge_body(**kwargs), format="json")
        self.assertEqual(response.status_code, 200, "Challenge issuance failed.")
        return response.json()

    def proof_body(self, challenge, key=None):
        signature = (key or self.key).sign(challenge["proof_message"].encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return dict(challenge_id=challenge["challenge_id"], nonce=challenge["nonce"], signature=encode64(signature))

    def enroll(self, **kwargs):
        challenge = self.challenge(**kwargs)
        response = self.client.post(MOBILE+"auth/token/", self.proof_body(challenge, kwargs.get("key")), format="json")
        self.assertEqual(response.status_code, 200, "Enrollment failed.")
        return response.json()

    def me(self, session, *, client=None):
        return (client or self.client).get(MOBILE+"me/", HTTP_AUTHORIZATION="Bearer "+session["access_token"])

    def refresh(self, session):
        return self.client.post(MOBILE+"auth/refresh/", {"refresh_token": session["refresh_token"]}, format="json")

    def web(self, username="submitter"):
        client = self.api()
        csrf = client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        response = client.post("/api/v1/auth/login/", {"username": username, "password": PASSWORD}, format="json", HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(response.status_code, 200, "Web login failed.")
        csrf = client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        return client, csrf

    def another_owner(self, suffix="two", *, same_org=False):
        org = self.org if same_org else Organization.objects.create(code="MOBILE-"+suffix, name="Synthetic organization")
        unit = Unit.objects.create(organization=org, code="MOBILE-"+suffix, name="Synthetic unit")
        channel = SharingChannel.objects.create(organization=org, code="MOBILE-"+suffix, name="Synthetic channel")
        owner = User.objects.create_user(username="mobile-"+suffix, password=PASSWORD,
            organization=org, display_name="Synthetic submitter", role="submitter")
        UnitMembership.objects.create(organization=org, user=owner, unit=unit, role="submitter")
        ChannelSource.objects.create(organization=org, channel=channel, unit=unit)
        return owner

    def assert_auth_denied(self, response, code="AUTH_REQUIRED"):
        self.assertEqual(response.status_code, 401, "Expected safe mobile authentication denial.")
        self.assertEqual(response.json()["code"], code)
        self.assertEqual(response.get("WWW-Authenticate"), 'Bearer realm="kapit-mobile"')
        self.assertIn("no-store", response.get("Cache-Control", ""))
