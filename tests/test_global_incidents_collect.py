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

if __name__ == "__main__":
    unittest.main()
