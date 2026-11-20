"""The platform menu copy check: shape, the one-level and 14-entry caps, and the address allow-list
(https, and a TeamStarWolf host, with github.com only under /TeamStarWolf). check_platform_nav.py
runs as a script in the pull-request check; these exercise its validation directly."""
import json
import unittest

import check_platform_nav as check


def base():
    """A minimal valid menu to mutate in each case."""
    return {
        "version": 1,
        "home": {"label": "TeamStarWolf", "href": "https://teamstarwolf.com/"},
        "items": [
            {"id": "home", "label": "Home", "href": "https://teamstarwolf.com/",
             "menu": [{"label": "Front page", "href": "https://teamstarwolf.com/"}]},
            {"id": "github", "label": "GitHub", "href": "https://github.com/TeamStarWolf",
             "menu": [{"label": "Repo", "href": "https://github.com/TeamStarWolf/intelligence-hub"}]},
        ],
    }


def run(menu):
    return check.problems(json.dumps(menu).encode("ascii"))


class PlatformNavTest(unittest.TestCase):
    def test_the_vendored_copy_is_valid(self):
        self.assertEqual(check.problems(check.COPY.read_bytes()), [])

    def test_a_minimal_menu_is_valid(self):
        self.assertEqual(run(base()), [])

    def test_a_host_outside_the_allow_list_fails(self):
        menu = base()
        menu["items"][0]["menu"][0]["href"] = "https://evil.example.com/phish"
        self.assertTrue(any("not a TeamStarWolf property" in line for line in run(menu)), run(menu))

    def test_a_non_https_address_fails(self):
        menu = base()
        menu["items"][0]["menu"][0]["href"] = "http://teamstarwolf.com/insecure"
        self.assertTrue(any("not an https address" in line for line in run(menu)), run(menu))

    def test_a_github_address_outside_teamstarwolf_fails(self):
        menu = base()
        menu["items"][1]["href"] = "https://github.com/SomeoneElse/repo"
        self.assertTrue(any("outside /TeamStarWolf" in line for line in run(menu)), run(menu))

    def test_a_dot_dot_path_segment_fails(self):
        menu = base()
        menu["items"][1]["href"] = "https://github.com/TeamStarWolf/../someone/repo"
        self.assertTrue(any("dot path segment" in line for line in run(menu)), run(menu))

    def test_a_percent_encoded_dot_dot_segment_fails(self):
        menu = base()
        menu["items"][1]["href"] = "https://github.com/TeamStarWolf/%2e%2e/someone/repo"
        self.assertTrue(any("dot path segment" in line for line in run(menu)), run(menu))

    def test_a_single_dot_segment_fails(self):
        menu = base()
        menu["items"][1]["href"] = "https://github.com/TeamStarWolf/./repo"
        self.assertTrue(any("dot path segment" in line for line in run(menu)), run(menu))

    def test_a_backslash_address_fails(self):
        menu = base()
        menu["items"][1]["href"] = "https://github.com/TeamStarWolf\\..\\someone/repo"
        self.assertTrue(any("backslash" in line for line in run(menu)), run(menu))

    def test_an_explicit_port_fails(self):
        menu = base()
        menu["items"][0]["href"] = "https://teamstarwolf.com:8443/"
        self.assertTrue(any("explicit port" in line for line in run(menu)), run(menu))

    def test_userinfo_before_an_allowed_host_fails(self):
        menu = base()
        menu["items"][0]["href"] = "https://user:pw@teamstarwolf.com/"
        self.assertTrue(any("userinfo" in line for line in run(menu)), run(menu))

    def test_the_home_brand_target_is_checked(self):
        menu = base()
        menu["home"]["href"] = "https://example.org/"
        self.assertTrue(any(line.startswith("home ") for line in run(menu)), run(menu))

    def test_a_pending_entry_address_is_still_checked(self):
        menu = base()
        menu["items"][0]["menu"].append({"label": "Later", "href": "https://elsewhere.net/x", "pending": "not live"})
        self.assertTrue(any("not a TeamStarWolf property" in line for line in run(menu)), run(menu))

    def test_a_menu_over_fourteen_entries_fails(self):
        menu = base()
        menu["items"][0]["menu"] = [{"label": "E" + str(i), "href": "https://teamstarwolf.com/" + str(i)} for i in range(15)]
        self.assertTrue(any("cap" in line for line in run(menu)), run(menu))


if __name__ == "__main__":
    unittest.main()
