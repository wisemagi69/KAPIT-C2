import json

from cryptography.fernet import Fernet
from django.conf import settings

from .canonical import canonical, digest


def encrypt(value):
    key = settings.KAPIT_SOURCE_KEY
    return Fernet(key.encode("ascii") if isinstance(key, str) else key).encrypt(canonical(value))


def decrypt(ciphertext):
    key = settings.KAPIT_SOURCE_KEY
    return json.loads(Fernet(key.encode("ascii") if isinstance(key, str) else key).decrypt(bytes(ciphertext)))


def source_payload(revision):
    payload = decrypt(revision.payload_ciphertext)
    if digest(payload) != revision.content_digest:
        raise ValueError("source integrity")
    return payload
