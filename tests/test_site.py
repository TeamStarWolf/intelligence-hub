"""The page files: site/files.json, the layout revision, publish-time stamping, the generated
labels module, script syntax, the contrast check and the 12 px type floor."""
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import support
from intelligence_hub import site

sys.path.insert(0, str(support.ROOT / "tests"))
import check_contrast  # noqa: E402
import check_font_size  # noqa: E402

SITE = support.ROOT / "site"
NODE = shutil.which("node")


def copy_site(directory):
    target = Path(directory) / "site"
    for name in support.site_files():
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SITE / name, target / name)
    return target


class FilesListTest(unittest.TestCase):
    def test_every_page_file_is_listed_and_every_listed_file_exists(self):
        listed = set(site.site_files(SITE))
        on_disk = {path.relative_to(SITE).as_posix() for path in SITE.rglob("*") if path.is_file() and
                   not path.relative_to(SITE).as_posix().startswith("data/") and path.name != "files.json"}
        self.assertEqual(on_disk, listed)

    def test_bad_lists_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = copy_site(directory)
            good = json.loads((target / "files.json").read_text(encoding="utf-8"))
            for bad in ("../secret.js", "data/feed.json", "js/Main.js", "notes.txt", "files.json"):
                value = {**good, "files": good["files"] + [bad]}
                (target / "files.json").write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(site.SiteError, msg=bad):
                    site.site_files(target)
            value = {**good, "files": [name for name in good["files"] if name != "js/main.js"]}
            (target / "files.json").write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(site.SiteError, "js/main.js"):
                site.site_files(target)


class StampTest(unittest.TestCase):
    def test_check_stamps_a_copy_and_leaves_the_repository_unchanged(self):
        before = {name: (SITE / name).read_bytes() for name in support.site_files()}
        revision = site.check(SITE, out=io.StringIO())
        self.assertEqual(revision, site.layout_revision(SITE)[:16])
        self.assertEqual(before, {name: (SITE / name).read_bytes() for name in support.site_files()})

    def test_every_module_url_carries_the_revision_after_stamping(self):
        with tempfile.TemporaryDirectory() as directory:
            target = copy_site(directory)
            expected = site.layout_revision(target)[:16]
            revision = site.stamp(target, out=io.StringIO())
            self.assertEqual(revision, expected)
            page = (target / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="./styles.css?v=' + revision + '"', page)
            self.assertIn('src="./js/main.js?v=' + revision + '"', page)
            main = (target / "js" / "main.js").read_text(encoding="utf-8")
            self.assertIn('from "./router.js?v=' + revision + '"', main)
            self.assertIn('import("./labels.js?v=' + revision + '")', main)
            for name in support.site_files():
                if name.endswith(".js"):
                    text = (target / name).read_text(encoding="utf-8")
                    self.assertIsNone(re.search(r"""(?:from|import)\s*\(?\s*["']\.{1,2}/[^"'?]+\.js["']""", text), name)
            site.verify_stamped(target, revision)

    def test_an_import_of_an_unlisted_module_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = copy_site(directory)
            path = target / "js" / "util.js"
            path.write_text('import { x } from "./extra.js";\n' + path.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(site.SiteError, "extra.js"):
                site.stamp(target, out=io.StringIO())

    def test_the_layout_revision_follows_every_listed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = copy_site(directory)
            first = site.layout_revision(target)
            path = target / "js" / "views" / "today.js"
            path.write_bytes(path.read_bytes() + b"\n")
            self.assertNotEqual(site.layout_revision(target), first)

    def test_the_collector_records_the_same_layout_revision(self):
        from test_publication import Workspace
        workspace = Workspace()
        try:
            workspace.build()
            index = json.loads((workspace.root / "site" / "data" / "v7" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["layout_revision"], site.layout_revision(workspace.root / "site"))
            self.assertEqual(workspace.json("feed.json")["layout_revision"], index["layout_revision"])
        finally:
            workspace.close()

    def test_publish_stamps_before_packaging(self):
        workflow = (support.ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        stamp, package = workflow.index("python3 -m intelligence_hub.site stamp site"), workflow.index("python3 -m intelligence_hub.shards package site")
        upload = workflow.index("actions/upload-pages-artifact")
        self.assertLess(stamp, package)
        self.assertLess(package, upload)


class PageTest(unittest.TestCase):
    def test_the_content_security_policy_is_the_one_pull_request_6_set(self):
        page = (SITE / "index.html").read_text(encoding="utf-8")
        policy = re.search(r'Content-Security-Policy" content="([^"]+)"', page)[1]
        self.assertEqual(policy, "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
                                 "font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'")

    def test_no_inline_script_or_style_and_no_markup_sinks(self):
        page = (SITE / "index.html").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)", page))
        self.assertNotIn(" style=", page)
        self.assertIsNone(re.search(r"<[^>]*\son[a-z]+=", page), "no inline event handler attribute")
        for name in support.site_files():
            if name.endswith(".js"):
                text = (SITE / name).read_text(encoding="utf-8")
                for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
                    self.assertNotIn(sink, text, name)

    def test_the_brand_is_one_word(self):
        for name in support.site_files():
            if name.endswith((".html", ".js")) and name != "js/labels.js":
                self.assertIsNone(re.search(r"Team Star Wolf|TEAM STAR WOLF", (SITE / name).read_text(encoding="utf-8")), name)


class LabelsTest(unittest.TestCase):
    def test_labels_module_is_current(self):
        self.assertEqual((SITE / "js" / "labels.js").read_text(encoding="utf-8").replace("\r\n", "\n"), site.build_labels())

    def test_labels_cover_the_vocabularies(self):
        text = site.build_labels()
        for key in ('"vendor:fortinet"', '"actor:G0016"', '"class:vendor-primary"', '"event:exploitation"', '"region:US"', '"kind:kev"'):
            self.assertIn(key, text)


@unittest.skipIf(NODE is None, "Node is not installed; the pull-request check runs node --check itself")
class ScriptSyntaxTest(unittest.TestCase):
    def test_every_listed_script_parses(self):
        for name in support.site_files():
            if name.endswith(".js"):
                completed = subprocess.run([NODE, "--check", str(SITE / name)], capture_output=True, text=True, timeout=60)
                self.assertEqual(completed.returncode, 0, name + ": " + completed.stderr)


class ThemeTest(unittest.TestCase):
    def test_every_text_pair_meets_aa_in_both_themes(self):
        self.assertEqual(check_contrast.failures(), [])

    def test_a_low_contrast_token_is_caught(self):
        css = (SITE / "styles.css").read_text(encoding="utf-8")
        light = re.search(r'^:root\[data-theme="light"\]\s*\{(.*?)
\}', css, re.S | re.M).group(1)
        muted = re.search(r"--tsw-text-muted:\s*#[0-9a-fA-F]{6};", light).group(0)
        planted = css.replace(muted, "--tsw-text-muted:        def test_the_system_light_block_matches_the_light_theme(self):
        css = (SITE / "styles.css").read_text(encoding="utf-8")
        system = re.search(r'@media \(prefers-color-scheme: light\)\s*\{\s*:root:not\(\[data-theme="dark"\]\)\s*\{(.*?)
\s*\}', css, re.S)
        link = re.search(r"--tsw-link:\s*#([0-9a-fA-F]{6});", system.group(1))
        value = link.group(1)
        nudged = value[:-1] + ("8" if value[-1].lower() != "8" else "9")
        start = css.index(system.group(1))
        planted = css[:start] + system.group(1).replace(link.group(0), link.group(0).replace(value, nudged), 1) + css[start + len(system.group(1)):]
        self.assertNotEqual(planted, css)
        self.assertIn("differs", " ".join(check_contrast.failures(planted)))


assertNotEqual(planted, css.replace("\r\n", "\n") if "\r\n" in css else css)
        self.assertIn("differs", " ".join(check_contrast.failures(planted)))


class FontFloorTest(unittest.TestCase):
    def test_no_font_size_under_12_px(self):
        self.assertEqual(check_font_size.problems(), [])

    def test_a_small_size_is_caught(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for value in ("font-size: 11px", "font-size: .7rem", "font: 600 0.6875rem/1 x", "font-size: x-small", "--text-tiny: 10px"):
                (target / "styles.css").write_text(".a { " + value + "; }\n", encoding="utf-8")
                self.assertTrue(check_font_size.problems(target), value)
            (target / "styles.css").write_text(".a { font-size: 12px; } .b { font-size: .75rem; }\n", encoding="utf-8")
            self.assertEqual(check_font_size.problems(target), [])


if __name__ == "__main__":
    unittest.main()
