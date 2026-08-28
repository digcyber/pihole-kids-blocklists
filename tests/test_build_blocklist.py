import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.build_blocklist import (
    BuildError,
    guard_drop,
    normalize_hostname,
    parse_curlie_archive,
    parse_domain_lines,
    validate_domains,
)


class NormalizeTests(unittest.TestCase):
    def test_url_cleanup_and_lowercase(self):
        self.assertEqual(normalize_hostname("HTTPS://User:Pass@WWW.Example.COM:8443/path?q=1#x"), "www.example.com")

    def test_bare_domain_and_port(self):
        self.assertEqual(normalize_hostname("Shop.Example.COM:443/path"), "shop.example.com")

    def test_idn_to_punycode(self):
        self.assertEqual(normalize_hostname("https://münich.example/"), "xn--mnich-kva.example")

    def test_preserves_hosted_subdomain(self):
        self.assertEqual(normalize_hostname("https://merchant.hosting.example/path"), "merchant.hosting.example")

    def test_preserves_www_as_exact_hostname(self):
        self.assertEqual(normalize_hostname("https://www.example.com"), "www.example.com")

    def test_rejects_ip_and_localhost(self):
        self.assertIsNone(normalize_hostname("192.0.2.1"))
        self.assertIsNone(normalize_hostname("https://[2001:db8::1]/"))
        self.assertIsNone(normalize_hostname("localhost"))
        self.assertIsNone(normalize_hostname("printer"))

    def test_rejects_bad_labels(self):
        self.assertIsNone(normalize_hostname("-bad.example"))
        self.assertIsNone(normalize_hostname("bad_.example"))
        self.assertIsNone(normalize_hostname("example.123"))


class MergeTests(unittest.TestCase):
    def test_deduplication(self):
        self.assertEqual(parse_domain_lines(["EXAMPLE.com", "example.com", "www.example.com"]), {"example.com", "www.example.com"})

    def test_exact_exception_semantics(self):
        merged = {"example.com", "www.example.com", "shop.example.com"}
        self.assertEqual(merged - {"example.com"}, {"www.example.com", "shop.example.com"})

    def test_sorted_unique_validation(self):
        self.assertEqual(validate_domains(["a.example", "b.example"]), ["a.example", "b.example"])
        with self.assertRaises(BuildError):
            validate_domains(["b.example", "a.example"])

    def test_drop_guard(self):
        previous = {f"d{i}.example" for i in range(100)}
        guard_drop("test", previous, {f"d{i}.example" for i in range(75)})
        with self.assertRaises(BuildError):
            guard_drop("test", previous, {f"d{i}.example" for i in range(60)})


class CurlieParserTests(unittest.TestCase):
    def test_selects_recursive_category_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "curlie.tar.gz"
            categories = ("1\tShopping\t2\troot\t\t\n" "2\tShopping/Books\t1\tbooks\t\t\n" "3\tOther\t1\tother\t\t\n").encode()
            sites = ("https://www.shop.example/\tShop\tdesc\t1\n" "https://books.example/path\tBooks\tdesc\t2\n" "https://other.example/\tOther\tdesc\t3\n").encode()
            with tarfile.open(archive, "w:gz") as tf:
                for name, payload in (("curlie-rdf/rdf-Test-s.tsv", categories), ("curlie-rdf/rdf-Test-c.tsv", sites)):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
            domains, matches = parse_curlie_archive(archive, roots=("Shopping",))
            self.assertEqual(domains, {"www.shop.example", "books.example"})
            self.assertEqual(matches["Shopping"], 2)


if __name__ == "__main__":
    unittest.main()
