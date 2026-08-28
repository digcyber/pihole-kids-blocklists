import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.build_ut1_policy_lists import (
    BuildError,
    apply_suffix_exceptions,
    normalize_hostname,
    parse_ut1_category_archive,
    suffix_excluded,
)


class PolicyNormalizeTests(unittest.TestCase):
    def test_url_to_hostname(self):
        self.assertEqual(normalize_hostname("HTTPS://WWW.Example.COM:443/path?q=1"), "www.example.com")

    def test_rejects_ip_and_local(self):
        self.assertIsNone(normalize_hostname("192.0.2.1"))
        self.assertIsNone(normalize_hostname("localhost"))


class ExceptionTests(unittest.TestCase):
    def test_suffix_exception_matches_root_and_subdomains(self):
        roots = {"nordvpn.com"}
        self.assertTrue(suffix_excluded("nordvpn.com", roots))
        self.assertTrue(suffix_excluded("us123.nordvpn.com", roots))
        self.assertFalse(suffix_excluded("notnordvpn.com", roots))

    def test_apply_suffix_exceptions(self):
        domains = {"nordvpn.com", "api.nordvpn.com", "other-vpn.example"}
        kept, removed = apply_suffix_exceptions(domains, {"nordvpn.com"})
        self.assertEqual(kept, {"other-vpn.example"})
        self.assertEqual(removed, 2)


class UT1CategoryParserTests(unittest.TestCase):
    def test_parses_domains_and_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "chat.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                for name, payload in (
                    ("chat/domains", b"chat.example\nWWW.CHAT.EXAMPLE\n"),
                    ("chat/urls", b"rooms.example/path\nhttps://talk.example/a?q=1\n"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
            self.assertEqual(
                parse_ut1_category_archive(archive, "chat"),
                {"chat.example", "www.chat.example", "rooms.example", "talk.example"},
            )

    def test_requires_domains_and_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "chat.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                payload = b"chat.example\n"
                info = tarfile.TarInfo("chat/domains")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            with self.assertRaises(BuildError):
                parse_ut1_category_archive(archive, "chat")


if __name__ == "__main__":
    unittest.main()
