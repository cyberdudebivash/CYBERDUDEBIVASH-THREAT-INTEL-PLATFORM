import unittest
from unittest.mock import patch
from agent.global_incidents_collect import collect, CollectionError

class CollectorSecurityTests(unittest.TestCase):
    def test_rejects_http(self):
        with self.assertRaises(CollectionError):
            collect("http://example.org/feed", {"example.org"})
    def test_rejects_unlisted_host(self):
        with self.assertRaises(CollectionError):
            collect("https://other.example/feed", {"example.org"})
    def test_rejects_userinfo(self):
        with self.assertRaises(CollectionError):
            collect("https://user:pass@example.org/feed", {"example.org"})
    def test_rejects_nonstandard_port(self):
        with self.assertRaises(CollectionError):
            collect("https://example.org:8443/feed", {"example.org"})
    def test_rejects_private_resolution(self):
        with patch("agent.global_incidents_collect._public_ips", side_effect=CollectionError("non-public DNS answer")):
            with self.assertRaises(CollectionError):
                collect("https://example.org/feed", {"example.org"})
    def test_no_transport_fails_closed(self):
        with patch("agent.global_incidents_collect._public_ips", return_value=set()):
            with self.assertRaisesRegex(CollectionError, "network adapter not configured"):
                collect("https://example.org/feed", {"example.org"})

    def test_explicit_transport_returns_metadata_without_publishing(self):
        import hashlib
        from unittest.mock import MagicMock
        from agent.global_incidents_collect import MAX_BYTES, TIMEOUT_SECONDS

        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {"Content-Type": "application/json", "Content-Length": "2"}
        response.read.return_value = b"{}"
        opener = MagicMock()
        opener.open.return_value = response

        with patch("agent.global_incidents_collect._public_ips", return_value=set()):
            result = collect("https://example.org/feed", {"example.org"}, opener=opener)

        self.assertEqual(result["content_type"], "application/json")
        self.assertEqual(result["size_bytes"], 2)
        self.assertEqual(result["sha256"], hashlib.sha256(b"{}").hexdigest())
        self.assertEqual(result["verification_state"], "unreviewed")
        self.assertNotIn("incident", result)
        response.read.assert_called_once_with(MAX_BYTES + 1)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], TIMEOUT_SECONDS)

    def test_injected_transport_failure_is_not_silently_accepted(self):
        from unittest.mock import MagicMock

        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 503
        opener = MagicMock()
        opener.open.return_value = response

        with patch("agent.global_incidents_collect._public_ips", return_value=set()):
            with self.assertRaises(CollectionError):
                collect("https://example.org/feed", {"example.org"}, opener=opener)

if __name__ == "__main__":
    unittest.main()
