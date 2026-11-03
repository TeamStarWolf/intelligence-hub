"""The static site in site/: its file list, its layout revision, publish-time stamping and the
generated labels module.

site/files.json lists every page file the Pages artifact may carry (the data files are listed
by data/v7/index.json instead). The collector hashes those files into layout_revision, and the
publish workflow stamps the same revision into the page before packaging it:

    python -m intelligence_hub.site stamp site    # publish.yml, on the checked-out copy only
    python -m intelligence_hub.site check site    # check.yml: stamp a temporary copy and verify it
    python -m intelligence_hub.site labels         # rewrite site/js/labels.js from config/
    python -m intelligence_hub.site labels --check # fail when site/js/labels.js is out of date

Stamping appends ?v=<first 16 hex of layout_revision> to the stylesheet and module URLs in
index.html and to every relative import between modules, so a browser never pairs a new page
with a module it cached from an earlier deploy. The committed files stay unstamped.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
FILES_JSON = "files.json"
FILE_NAME = re.compile(r"(?:js/(?:[a-z0-9-]+/)?)?[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:html|css|js|svg)")
MAX_FILES = 200
REQUIRED = ("index.html", "styles.css", "js/main.js")
# Relative import specifiers in a module: static imports and exports, and dynamic import().
IMPORT = re.compile(r"""(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(["'])(\.{1,2}/[A-Za-z0-9_./-]+?\.js)\2""")
# The two references in index.html that load page code.
PAGE_REF = re.compile(r"""(\b(?:href|src)=)(["'])\./([A-Za-z0-9_./-]+?\.(?:css|js))\2""")
STAMPED = re.compile(r"\?v=[a-f0-9]{16}$")
LABELS = "js/labels.js"


class SiteError(SystemExit):
    """Raised when site/files.json or a stamped page does not meet its rules."""


def _refuse(condition, message):
    if not condition:
        raise SiteError(message)


def site_files(site):
    """The page files listed in site/files.json, in their listed order."""
    path = Path(site) / FILES_JSON
    raw = path.read_bytes()
    _refuse(len(raw) <= 65536, "site/files.json exceeds 65,536 bytes.")
    value = json.loads(raw.decode("utf-8"))
    _refuse(isinstance(value, dict) and set(value) == {"schema_version", "comment", "files"} and value["schema_version"] == 1,
            "site/files.json must hold schema_version 1, a comment and a files list.")
    files = value["files"]
    _refuse(isinstance(files, list) and 0 < len(files) <= MAX_FILES and all(isinstance(name, str) for name in files),
            "site/files.json must list between 1 and " + str(MAX_FILES) + " files.")
    _refuse(len(set(files)) == len(files), "site/files.json lists a file twice.")
    for name in files:
        _refuse(FILE_NAME.fullmatch(name) is not None and ".." not in name and name != FILES_JSON,
                "site/files.json lists a name outside the page-file pattern: " + name)
    for name in REQUIRED:
        _refuse(name in files, "site/files.json must list " + name + ".")
    return tuple(files)


def page_directories(files):
    """Every directory that holds a listed file, such as js and js/views."""
    found = set()
    for name in files:
        parts = name.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            found.add("/".join(parts[:depth]))
    return found


def layout_revision(site):
    """sha256 over files.json and every listed file (path and content sha256, in path order)."""
    site = Path(site)
    names = [FILES_JSON] + sorted(site_files(site))
    lines = "".join(name + " " + hashlib.sha256((site / name).read_bytes()).hexdigest() + "\n" for name in names)
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _resolve(module, specifier):
    """The site-relative path an import specifier in module names, or None when it leaves the site."""
    parts = module.split("/")[:-1]
    for piece in specifier.split("/"):
        if piece == "..":
            if not parts:
                return None
            parts.pop()
        elif piece not in ("", "."):
            parts.append(piece)
    return "/".join(parts)


def stamp(site, out=None):
    """Stamp the page files in place with the layout revision. Returns the revision used."""
    out = out or sys.stdout
    site = Path(site)
    files = site_files(site)
    revision = layout_revision(site)[:16]
    listed = set(files)
    changed = 0
    for name in files:
        path = site / name
        if name.endswith(".js"):
            text = path.read_text(encoding="utf-8")

            def module_ref(match, name=name):
                target = _resolve(name, match[3])
                _refuse(target in listed, name + " imports " + match[3] + ", which site/files.json does not list.")
                return match[1] + match[2] + match[3] + "?v=" + revision + match[2]
            stamped, count = IMPORT.subn(module_ref, text)
            if count:
                path.write_text(stamped, encoding="utf-8", newline="\n")
                changed += count
        elif name == "index.html":
            text = path.read_text(encoding="utf-8")

            def page_ref(match):
                _refuse(match[3] in listed, "index.html loads ./" + match[3] + ", which site/files.json does not list.")
                return match[1] + match[2] + "./" + match[3] + "?v=" + revision + match[2]
            stamped, count = PAGE_REF.subn(page_ref, text)
            _refuse(count >= 2, "index.html must load its stylesheet and js/main.js by relative URL.")
            path.write_text(stamped, encoding="utf-8", newline="\n")
            changed += count
    print("Stamped " + str(changed) + " page and module URLs with ?v=" + revision, file=out)
    return revision


def verify_stamped(site, revision):
    """Every page and module reference in a stamped site carries ?v=revision and names a listed file."""
    site = Path(site)
    files = site_files(site)
    listed = set(files)
    unversioned = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}/[^"'?]+?\.js)["']""")
    for name in files:
        text = (site / name).read_text(encoding="utf-8") if name.endswith((".js", ".html")) else ""
        if name.endswith(".js"):
            _refuse(not unversioned.search(text), name + " still has an unversioned import after stamping.")
            for match in re.finditer(r"""(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}/[^"']+?)\?v=([a-f0-9]{16})["']""", text):
                _refuse(match[2] == revision and _resolve(name, match[1]) in listed, name + " has a stale or unlisted import: " + match[1])
        if name == "index.html":
            refs = re.findall(r"""\b(?:href|src)=["']\./([^"']+?\.(?:css|js))(\?v=[a-f0-9]{16})?["']""", text)
            _refuse(refs and all(version == "?v=" + revision for _, version in refs), "index.html has an unversioned stylesheet or script URL.")


def check(site, out=None):
    """Stamp a temporary copy of the site and verify it; the real files are not changed."""
    out = out or sys.stdout
    site = Path(site)
    files = site_files(site)
    for name in files:
        _refuse((site / name).is_file(), "site/files.json lists a missing file: " + name)
    with tempfile.TemporaryDirectory(prefix="hub-site-") as directory:
        copy = Path(directory)
        shutil.copyfile(site / FILES_JSON, copy / FILES_JSON)
        for name in files:
            (copy / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(site / name, copy / name)
        revision = stamp(copy, out=out)
        verify_stamped(copy, revision)
    print("site/files.json: " + str(len(files)) + " page files; stamping verified", file=out)
    return revision


def build_labels(root=ROOT):
    """site/js/labels.js: display labels for every vocabulary value the site can show."""
    root = Path(root)
    labels = {}
    vocabulary = json.loads((root / "config" / "vocabulary.json").read_text(encoding="utf-8"))
    for entity in vocabulary["entities"]:
        labels[entity["id"]] = entity["label"]
    prefixes = {"kind": "kind", "source_class": "class", "event_type": "event", "exploitation": "exp", "region": "region"}
    for name, prefix in prefixes.items():
        vocab = json.loads((root / "config" / "vocab" / (name + ".json")).read_text(encoding="utf-8"))
        for value in vocab["values"]:
            labels[prefix + ":" + value["value"]] = value["label"]
    lines = ["// Generated by python -m intelligence_hub.site labels from config/vocabulary.json and",
             "// config/vocab/*.json. Do not edit by hand; the pull-request check runs it with --check.",
             "export default {"]
    for key in sorted(labels):
        lines.append("  " + json.dumps(key) + ": " + json.dumps(labels[key]) + ",")
    lines[-1] = lines[-1].rstrip(",")
    lines.append("};")
    return "\n".join(lines) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["stamp"] and len(argv) <= 2:
        stamp(argv[1] if len(argv) == 2 else "site")
    elif argv[:1] == ["check"] and len(argv) <= 2:
        check(argv[1] if len(argv) == 2 else "site")
    elif argv[:1] == ["labels"] and argv[1:] in ([], ["--check"]):
        text = build_labels()
        path = ROOT / "site" / LABELS
        if argv[1:] == ["--check"]:
            current = path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else ""
            _refuse(current == text, "site/js/labels.js is out of date; run python -m intelligence_hub.site labels")
            print("site/js/labels.js is current (" + str(text.count("\n") - 4) + " labels)")
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
            print("Wrote site/js/labels.js")
    else:
        raise SystemExit("usage: python -m intelligence_hub.site stamp [site] | check [site] | labels [--check]")


if __name__ == "__main__":
    main()
