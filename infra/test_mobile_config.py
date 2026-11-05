"""Pure configuration boundaries; no database, mobile mounts or retained keys."""
import base64
from dataclasses import FrozenInstanceError
from importlib import metadata
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from config.mobile import (MobileConfigurationUnavailable, JWT_PACKAGE_VERSION,
                          load_mobile_config)


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class MobileConfigTests(unittest.TestCase):
    def setUp(self):
        # Deterministic synthetic bytes only; never used by a running server.
        self.key = bytes(range(32))
        self.secrets = {"django_secret": "SyntheticDjangoSigningKey!" * 3,
                        "source_key": base64.urlsafe_b64encode(bytes(range(32, 64))).decode("ascii"),
                        "database_password": "SyntheticDatabasePassword!" * 2}

    def load(self, env=None, **overrides):
        settings = {"KAPIT_MOBILE_ENABLED": "1", "KAPIT_MOBILE_SIGNING_KEY": encoded(self.key)}
        if env is not None:
            settings.update(env)
        with patch("config.mobile.metadata.version", return_value=JWT_PACKAGE_VERSION):
            return load_mobile_config(settings, **{**self.secrets, **overrides})

    def test_default_disabled_does_not_inspect_key_or_require_dependency(self):
        with patch("config.mobile.metadata.version") as package:
            config = load_mobile_config({}, **self.secrets)
        self.assertFalse(config.enabled)
        self.assertFalse(config.available)
        self.assertIsNone(config.signing_key)
        package.assert_not_called()
        with self.assertRaises(MobileConfigurationUnavailable):
            config.require_available()

    def test_noncanonical_flags_never_enable_auth(self):
        for flag in ["true", "yes", " 1", "1 ", "", "01"]:
            config = self.load({"KAPIT_MOBILE_ENABLED": flag})
            self.assertFalse(config.available)
            self.assertIsNone(config.signing_key)

    def test_explicitly_disabled_ignores_invalid_inherited_key(self):
        config = self.load({"KAPIT_MOBILE_ENABLED": "0", "KAPIT_MOBILE_SIGNING_KEY": "bad"})
        self.assertFalse(config.available)
        self.assertIsNone(config.signing_key)

    def test_enabled_missing_key_is_unavailable_without_an_import_exception(self):
        for value in [None, ""]:
            config = self.load({"KAPIT_MOBILE_SIGNING_KEY": value})
            self.assertTrue(config.enabled)
            self.assertFalse(config.available)
            self.assertEqual(config.unavailable_reason, "MOBILE_KEY_MISSING")

    def test_key_length_and_canonical_encoding_are_enforced(self):
        for value in [encoded(bytes(range(31))), encoded(bytes(range(65))), encoded(self.key) + "=",
                      " " + encoded(self.key), encoded(self.key) + "\n", "not-a-key", "é" * 43]:
            config = self.load({"KAPIT_MOBILE_SIGNING_KEY": value})
            self.assertFalse(config.available)
            self.assertIsNone(config.signing_key)
        for key in [self.key, bytes(range(64))]:
            self.assertTrue(self.load({"KAPIT_MOBILE_SIGNING_KEY": encoded(key)}).available)

    def test_noncanonical_trailing_pad_bits_and_repeated_material_are_rejected(self):
        value = encoded(self.key)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        alias = value[:-1] + alphabet[alphabet.index(value[-1]) + 1]
        for invalid in [alias, encoded(b"a" * 32), encoded(b"abcd" * 8)]:
            self.assertFalse(self.load({"KAPIT_MOBILE_SIGNING_KEY": invalid}).available)

    def test_source_key_reuse_cannot_hide_by_dropping_fernet_padding(self):
        config = self.load({"KAPIT_MOBILE_SIGNING_KEY": self.secrets["source_key"].rstrip("=")})
        self.assertEqual(config.unavailable_reason, "MOBILE_KEY_REUSED")
        self.assertIsNone(config.signing_key)

    def test_django_and_database_key_reuse_rejects_raw_and_base64_forms(self):
        for setting in ["django_secret", "database_password"]:
            for existing in [self.key.decode("ascii"), encoded(self.key), encoded(self.key) + "="]:
                config = self.load(**{setting: existing})
                self.assertEqual(config.unavailable_reason, "MOBILE_KEY_REUSED")
                self.assertIsNone(config.signing_key)

    def test_missing_or_unreviewed_dependency_disables_mobile_only(self):
        env = {"KAPIT_MOBILE_ENABLED": "1", "KAPIT_MOBILE_SIGNING_KEY": encoded(self.key)}
        for version in ["2.0.0", "2.15.2"]:
            with patch("config.mobile.metadata.version", return_value=version):
                self.assertFalse(load_mobile_config(env, **self.secrets).available)
        with patch("config.mobile.metadata.version", side_effect=metadata.PackageNotFoundError):
            self.assertFalse(load_mobile_config(env, **self.secrets).available)

    def test_policy_is_fixed_and_not_derived_from_environment_overrides(self):
        config = self.load({"KAPIT_MOBILE_ALGORITHM": "none", "KAPIT_MOBILE_ISSUER": "untrusted",
                            "KAPIT_MOBILE_AUDIENCE": "untrusted", "KAPIT_MOBILE_ACCESS_SECONDS": "999999"})
        self.assertIs(config.require_available(), config)
        self.assertEqual((config.protocol, config.algorithm, config.issuer, config.audience),
                         ("kapit-mobile-v1", "HS256", "kapit-local-mobile", "kapit-android"))
        self.assertEqual((config.access_lifetime_seconds, config.family_lifetime_seconds,
                          config.offline_lease_seconds, config.challenge_lifetime_seconds, config.leeway_seconds),
                         (600, 604800, 86400, 120, 0))
        with self.assertRaises(FrozenInstanceError):
            config.algorithm = "none"

    def test_repr_and_unavailable_exceptions_exclude_key_material(self):
        config = self.load()
        self.assertTrue(encoded(self.key) not in repr(config) and repr(self.key) not in repr(config))
        bad = self.load({"KAPIT_MOBILE_SIGNING_KEY": "PRIVATE_KEY_CANARY"})
        try:
            bad.require_available()
        except MobileConfigurationUnavailable as error:
            self.assertEqual(str(error), "Mobile authentication configuration is unavailable.")
            self.assertNotIn("PRIVATE_KEY_CANARY", repr(bad) + str(error))
        else:
            self.fail("Invalid mobile configuration must refuse issuance.")


if __name__ == "__main__":
    unittest.main()
