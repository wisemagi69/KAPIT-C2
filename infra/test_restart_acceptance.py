"""Ownership guards for the explicit process-restart acceptance harness."""
import unittest
import socket
import struct
from unittest.mock import Mock, patch

from infra.restart_acceptance import AcceptanceError, Client, NoRedirect, reconnect_lease
from infra.start_local import parse_listener_owners


class RestartLeaseTests(unittest.TestCase):
    def lease(self, lock_result=True):
        lease = Mock(owned_oid=1234, assert_owned=Mock())
        lease.connection.cursor.return_value.__enter__ = Mock(return_value=lease.connection.cursor.return_value)
        lease.connection.cursor.return_value.__exit__ = Mock(return_value=False)
        lease.connection.cursor.return_value.fetchone.return_value = (lock_result,)
        return lease

    def test_restart_never_adopts_a_database_without_prior_creation_identity(self):
        lease = self.lease(); lease.owned_oid = None
        with self.assertRaises(AcceptanceError):
            reconnect_lease(lease, 746397301)
        lease.connection.ensure_connection.assert_not_called()

    def test_restart_refuses_a_lock_held_by_another_process(self):
        lease = self.lease(False)
        with self.assertRaises(AcceptanceError):
            reconnect_lease(lease, 746397301)
        self.assertFalse(lease.locked)
        lease.assert_owned.assert_not_called()

    def test_restart_checks_retained_oid_after_reacquiring_lock(self):
        lease = self.lease()
        lease.assert_owned.side_effect = RuntimeError("BROWSER_DATABASE_OWNERSHIP")
        with self.assertRaisesRegex(RuntimeError, "BROWSER_DATABASE_OWNERSHIP"):
            reconnect_lease(lease, 746397301)
        self.assertTrue(lease.locked)
        self.assertEqual(lease.owned_oid, 1234)

    def test_success_reconnects_and_verifies_without_database_create_or_drop(self):
        lease = self.lease()
        reconnect_lease(lease, 746397301)
        lease.connection.close.assert_called_once()
        lease.connection.ensure_connection.assert_called_once()
        lease.assert_owned.assert_called_once()
        statements = [call.args[0] for call in lease.connection.cursor.return_value.execute.call_args_list]
        self.assertEqual(statements, ["SELECT pg_try_advisory_lock(%s)"])


class RestartHttpBoundaryTests(unittest.TestCase):
    def test_listener_port_selection_does_not_accept_another_owned_port(self):
        row = struct.pack("<6I", 2, int.from_bytes(socket.inet_aton("127.0.0.1"), "little"),
                          socket.htons(18092), 0, 0, 42)
        raw = struct.pack("<I", 1) + row
        self.assertEqual(parse_listener_owners(raw), set())
        self.assertEqual(parse_listener_owners(raw, 18092), {42})

    def test_unowned_listener_cannot_receive_http_request(self):
        client = Client()
        client.opener = Mock()
        with patch("infra.restart_acceptance.server_owned", return_value=False):
            with self.assertRaises(AcceptanceError):
                client.request("/api/v1/auth/login/", {"username": "fixture", "password": "fixture"})
        client.opener.open.assert_not_called()

    def test_redirects_are_never_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.invalid/"))


if __name__ == "__main__":
    unittest.main()
