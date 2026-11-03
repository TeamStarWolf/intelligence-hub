import unittest

import support  # noqa: F401  (puts the repository root on sys.path)
from intelligence_hub.collect import safe_url


class SafeUrlTest(unittest.TestCase):
    def test_accepts_canonical_https(self):
        self.assertEqual(safe_url("https://www.cisa.gov/news"), "https://www.cisa.gov/news")

    def test_adds_root_path_and_drops_fragment(self):
        self.assertEqual(safe_url("https://www.cisa.gov"), "https://www.cisa.gov/")
        self.assertEqual(safe_url("https://www.cisa.gov/a#section"), "https://www.cisa.gov/a")

    def test_accepts_explicit_default_port(self):
        self.assertEqual(safe_url("https://www.cisa.gov:443/a"), "https://www.cisa.gov/a")

    def test_rejects_plain_http(self):
        self.assertIsNone(safe_url("http://www.cisa.gov/news"))

    def test_rejects_other_schemes(self):
        for value in ("ftp://www.cisa.gov/a", "javascript:alert(1)", "data:text/html,x", "//www.cisa.gov/a", "www.cisa.gov/a"):
            with self.subTest(value=value):
                self.assertIsNone(safe_url(value))

    def test_rejects_credentials_and_other_ports(self):
        for value in ("https://user:pass@www.cisa.gov/", "https://user@www.cisa.gov/", "https://www.cisa.gov:8443/"):
            with self.subTest(value=value):
                self.assertIsNone(safe_url(value))

    def test_rejects_ip_literals_and_private_suffixes(self):
        for value in ("https://127.0.0.1/", "https://10.0.0.1/", "https://[::1]/", "https://printer.local/",
                      "https://intranet.internal/", "https://router.home.arpa/", "https://site.example/"):
            with self.subTest(value=value):
                self.assertIsNone(safe_url(value))

    def test_rejects_unsafe_characters_and_shapes(self):
        for value in ("https://www.cisa.gov/a b", "https://www.cisa.gov/\x00", "https://www.cisa.gov\\a",
                      "https://www.cisa.gov./", "https://www.cïsa.gov/", "https://localhost/", None, 42,
                      "https://www.cisa.gov/" + "a" * 4000):
            with self.subTest(value=value):
                self.assertIsNone(safe_url(value))

    def test_host_allowlist(self):
        self.assertEqual(safe_url("https://cisa.gov/a", {"cisa.gov"}), "https://cisa.gov/a")
        self.assertIsNone(safe_url("https://evil.org/a", {"cisa.gov"}))

    def test_strips_tracking_parameters(self):
        self.assertEqual(safe_url("https://www.cisa.gov/a?id=7&utm_source=x&UTM_medium=y&fbclid=z&gclid=q"),
                         "https://www.cisa.gov/a?id=7")


if __name__ == "__main__":
    unittest.main()
