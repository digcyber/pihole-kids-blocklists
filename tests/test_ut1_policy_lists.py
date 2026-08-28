import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.build_ut1_policy_lists import BuildError, normalize_hostname, parse_ut1_category_archive
from scripts.shared_exceptions import Exceptions, apply_exceptions, is_excluded, read_exceptions


class PolicyNormalizeTests(unittest.TestCase):
    def test_url_to_hostname(self):
        self.assertEqual(normalize_hostname("HTTPS://WWW.Example.COM:443/path?q=1"), "www.example.com")

    def test_rejects_ip_and_local(self):
        self.assertIsNone(normalize_hostname("192.0.2.1"))
        self.assertIsNone(normalize_hostname("localhost"))


class ExceptionTests(unittest.TestCase):
    def test_exact_exception_matches_only_exact_hostname(self):
        rules = Exceptions(frozenset({"google.com"}), frozenset())
        self.assertTrue(is_excluded("google.com", rules))
        self.assertFalse(is_excluded("dns.google.com", rules))

    def test_suffix_exception_matches_root_and_subdomains(self):
        rules = Exceptions(frozenset(), frozenset({"nordvpn.com"}))
        self.assertTrue(is_excluded("nordvpn.com", rules))
        self.assertTrue(is_excluded("us123.nordvpn.com", rules))
        self.assertFalse(is_excluded("notnordvpn.com", rules))

    def test_apply_mixed_exceptions(self):
        domains = {"google.com", "dns.google.com", "nordvpn.com", "api.nordvpn.com", "other.example"}
        rules = Exceptions(frozenset({"google.com"}), frozenset({"nordvpn.com"}))
        kept, removed = apply_exceptions(domains, rules)
        self.assertEqual(kept, {"dns.google.com", "other.example"})
        self.assertEqual(removed, 3)

    def test_parser_requires_mode_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exceptions.txt"
            path.write_text("google.com\n", encoding="utf-8")
            with self.assertRaises(BuildError):
                read_exceptions(path, normalize_hostname, BuildError)

    def test_parser_reads_exact_and_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exceptions.txt"
            path.write_text("exact:google.com\nsuffix:nordvpn.com\n", encoding="utf-8")
            rules = read_exceptions(path, normalize_hostname, BuildError)
            self.assertEqual(rules.exact, frozenset({"google.com"}))
            self.assertEqual(rules.suffix, frozenset({"nordvpn.com"}))


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

    def test_accepts_domains_only_category(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "vpn.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                payload = b"vpn.example\nnode.vpn.example\n"
                info = tarfile.TarInfo("vpn/domains")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            self.assertEqual(parse_ut1_category_archive(archive, "vpn"), {"vpn.example", "node.vpn.example"})

    def test_rejects_archive_without_category_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "chat.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                payload = b"metadata\n"
                info = tarfile.TarInfo("chat/README")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            with self.assertRaises(BuildError):
                parse_ut1_category_archive(archive, "chat")


if __name__ == "__main__":
    unittest.main()
