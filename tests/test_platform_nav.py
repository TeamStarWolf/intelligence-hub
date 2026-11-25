"""The platform menu copy check. Two address rules are exercised directly: the TeamStarWolf https
rule (every address that is not an external Bookmarks leaf: https, a TeamStarWolf host, github.com
only under /TeamStarWolf, no port, userinfo, backslash or dot segment) and the stricter external-leaf
rule (inside Bookmarks, on a leaf flagged external: a real DNS host off the four hosts, no port,
userinfo, IP literal, punycode, dot segment or encoded slash, at most 512 characters, and never an
address the TeamStarWolf rule would accept). Also the Bookmarks nesting and the entry caps.
check_platform_nav.py runs as a script in the pull-request check; these exercise its validation."""
import json
import unittest

import check_platform_nav as check


def base():
    """A minimal valid menu of plain (one-level) items to mutate in each case."""
    return {
        "version": 6,
        "home": {"label": "TeamStarWolf", "href": "https://teamstarwolf.com/"},
        "items": [
            {"id": "home", "label": "Home", "href": "https://teamstarwolf.com/",
             "menu": [{"label": "Front page", "href": "https://teamstarwolf.com/"}]},
            {"id": "github", "label": "GitHub", "href": "https://github.com/TeamStarWolf",
             "menu": [{"label": "Repo", "href": "https://github.com/TeamStarWolf/intelligence-hub"}]},
        ],
    }


def leaf(href, **extra):
    entry = {"label": "A link", "href": href, "external": True}
    entry.update(extra)
    return entry


def bookmarks(entries, source=None):
    """A menu whose Bookmarks item carries the given category list."""
    return {
        "version": 6,
        "home": {"label": "TeamStarWolf", "href": "https://teamstarwolf.com/"},
        "items": [
            {"id": "home", "label": "Home", "href": "https://teamstarwolf.com/"},
            {"id": "bookmarks", "label": "Bookmarks",
             "href": "https://github.com/TeamStarWolf/cybersecurity-resources/blob/main/LINKS.md",
             "source": source or {"repo": "TeamStarWolf/cybersecurity-resources", "path": "LINKS.md", "commit": "abc123"},
             "menu": entries},
        ],
    }


def category(label, children):
    return {"label": label, "href": "https://github.com/TeamStarWolf/cybersecurity-resources/blob/main/LINKS.md#" + label.lower(), "menu": children}


def run(menu):
    return check.problems(json.dumps(menu).encode("ascii"))


class PlatformNavTest(unittest.TestCase):
    def test_the_vendored_copy_is_valid(self):
        self.assertEqual(check.problems(check.COPY.read_bytes()), [])

    def test_a_minimal_menu_is_valid(self):
        self.assertEqual(run(base()), [])

    def test_a_valid_bookmarks_tree_passes(self):
        menu = bookmarks([
            category("Daily", [leaf("https://nvd.nist.gov/")]),
            category("Cloud", [{"label": "Subsection", "href": "https://github.com/TeamStarWolf/cybersecurity-resources/blob/main/LINKS.md#sub",
                                "menu": [leaf("https://attack.mitre.org/")]}]),
        ])
        self.assertEqual(run(menu), [])

    # --- the TeamStarWolf https rule (unchanged from every version) ---
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

    def test_a_plain_menu_over_fourteen_entries_fails(self):
        menu = base()
        menu["items"][0]["menu"] = [{"label": "E" + str(i), "href": "https://teamstarwolf.com/" + str(i)} for i in range(15)]
        self.assertTrue(any("cap" in line for line in run(menu)), run(menu))

    def test_an_external_flag_outside_bookmarks_fails(self):
        menu = base()
        menu["items"][0]["menu"][0]["external"] = True
        self.assertTrue(any("external flag outside the Bookmarks item" in line for line in run(menu)), run(menu))

    def test_an_outside_address_outside_bookmarks_fails(self):
        menu = base()
        menu["items"][0]["menu"][0]["href"] = "https://nvd.nist.gov/"
        self.assertTrue(any("not a TeamStarWolf property" in line for line in run(menu)), run(menu))

    def test_a_source_field_outside_bookmarks_fails(self):
        menu = base()
        menu["items"][0]["source"] = {"repo": "x", "path": "y", "commit": "z"}
        self.assertTrue(any("source field outside the Bookmarks item" in line for line in run(menu)), run(menu))

    # --- the external-leaf rule (Bookmarks only) ---
    def test_an_outside_leaf_without_the_flag_fails(self):
        menu = bookmarks([category("Daily", [{"label": "No flag", "href": "https://nvd.nist.gov/"}])])
        self.assertTrue(any("not a TeamStarWolf property" in line for line in run(menu)), run(menu))

    def test_a_flagged_leaf_on_our_own_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://teamstarwolf.com/x")])])
        self.assertTrue(any("internal TeamStarWolf address wearing the external flag" in line for line in run(menu)), run(menu))

    def test_a_flagged_entry_with_children_fails(self):
        menu = bookmarks([category("Daily", [{"label": "Bad", "href": "https://nvd.nist.gov/", "external": True,
                                               "menu": [leaf("https://attack.mitre.org/")]}])])
        self.assertTrue(any("flagged external but has a menu" in line for line in run(menu)), run(menu))

    def test_an_external_dot_dot_path_segment_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/a/..?x=1")])])
        self.assertTrue(any("dot path segment" in line for line in run(menu)), run(menu))

    def test_an_external_explicit_port_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov:8443/")])])
        self.assertTrue(any("explicit port" in line for line in run(menu)), run(menu))

    def test_external_userinfo_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://user@nvd.nist.gov/")])])
        self.assertTrue(any("userinfo" in line for line in run(menu)), run(menu))

    def test_an_external_ip_literal_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://93.184.216.34/")])])
        self.assertTrue(any("IP literal" in line for line in run(menu)), run(menu))

    def test_an_external_punycode_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://xn--80ak6aa92e.com/")])])
        self.assertTrue(any("punycode" in line for line in run(menu)), run(menu))

    def test_an_external_shorthand_ip_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://127.1/")])])
        self.assertTrue(any("looks like an IP address" in line for line in run(menu)), run(menu))

    def test_an_external_hex_ip_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://0x7f.0.0.1/")])])
        self.assertTrue(any("looks like an IP address" in line for line in run(menu)), run(menu))

    def test_an_external_three_part_numeric_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://1.2.3/")])])
        self.assertTrue(any("looks like an IP address" in line for line in run(menu)), run(menu))

    def test_an_external_hex_final_part_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://1.2.3.0x7f/")])])
        self.assertTrue(any("looks like an IP address" in line for line in run(menu)), run(menu))

    def test_an_external_non_ascii_character_fails(self):
        # The file carries the non-ASCII character as a \uXXXX escape, so the raw-byte ASCII test
        # passes and only the parsed address is non-ASCII.
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/café")])])
        self.assertTrue(any("non-printable or non-ASCII" in line for line in run(menu)), run(menu))

    def test_an_external_encoded_slash_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/a%2fb")])])
        self.assertTrue(any("encoded slash or backslash" in line for line in run(menu)), run(menu))

    def test_an_external_backslash_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/a\\b")])])
        self.assertTrue(any("backslash" in line for line in run(menu)), run(menu))

    def test_an_external_single_label_host_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://localhost/x")])])
        self.assertTrue(any("single label" in line for line in run(menu)), run(menu))

    def test_an_external_over_512_characters_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/" + "a" * 520)])])
        self.assertTrue(any("longer than 512" in line for line in run(menu)), run(menu))

    def test_an_external_flag_that_is_not_true_fails(self):
        menu = bookmarks([category("Daily", [{"label": "Odd", "href": "https://nvd.nist.gov/", "external": "yes"}])])
        self.assertTrue(any("external flag that is not true" in line for line in run(menu)), run(menu))

    # --- Bookmarks nesting and caps ---
    def test_a_bookmarks_list_over_sixteen_entries_fails(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/" + str(i)) for i in range(17)])])
        self.assertTrue(any("16 cap" in line or "than the 16 cap" in line for line in run(menu)), run(menu))

    def test_sixteen_bookmarks_entries_are_allowed(self):
        menu = bookmarks([category("Daily", [leaf("https://nvd.nist.gov/" + str(i)) for i in range(16)])])
        self.assertEqual(run(menu), [])

    def test_bookmarks_nesting_past_the_third_level_fails(self):
        deep = {"label": "Sub", "href": "https://github.com/TeamStarWolf/cybersecurity-resources/blob/main/LINKS.md#s",
                "menu": [{"label": "Deeper", "href": "https://github.com/TeamStarWolf/cybersecurity-resources/blob/main/LINKS.md#d",
                          "menu": [leaf("https://nvd.nist.gov/")]}]}
        menu = bookmarks([category("Daily", [deep])])
        self.assertTrue(any("nests deeper than the Bookmarks item allows" in line for line in run(menu)), run(menu))


if __name__ == "__main__":
    unittest.main()
