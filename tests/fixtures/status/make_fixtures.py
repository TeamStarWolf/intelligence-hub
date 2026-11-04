"""Trim real status-source responses into the committed fixtures under tests/fixtures/status/documents/.

    python -I tests/fixtures/status/make_fixtures.py SAMPLES_DIRECTORY

SAMPLES_DIRECTORY holds the untrimmed responses as read on 2026-11-04 (not committed). Each
fixture keeps the response's own shape and only drops rows and long text, so the normalizers in
intelligence_hub/status.py are tested against what the vendors actually return. README.md lists
every document and names the two inputs the tests build themselves.
After a change here, rebuild tests/fixtures/status-cache.json with build_cache.py.
"""
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
OUT = HERE / "documents"


def load(name):
    raw = (Path(sys.argv[1]) / name).read_bytes()
    return json.loads(raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8"))


def write(name, value, encoding="utf-8"):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, indent=1) + "\n"
    path.write_bytes(("﻿" + text).encode("utf-16-le") if encoding == "utf-16" else text.encode("utf-8"))


def write_text(name, text):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def cut(value, size=400):
    return value[:size] if isinstance(value, str) else value


def statuspage():
    summary = load("cp-summary.json")
    keep_open = {"ctxpqx5z4nb4", "dnncywl1n491"}
    summary["components"] = summary["components"][:3]
    summary["incidents"] = [item for item in summary["incidents"] if item["id"] in keep_open]
    summary["scheduled_maintenances"] = []
    incidents = load("cp-incidents.json")
    keep = ["lng6p1wpj7l2", "bfdjj7v1z8fx", "h2cvvr768kn1", "bqhbqv8pf8gw", "ctxpqx5z4nb4", "dnncywl1n491"]
    rows = [item for item in incidents["incidents"] if item["id"] in keep]
    for item in rows + summary["incidents"]:
        item["incident_updates"] = item["incident_updates"][:2]
        for update in item["incident_updates"]:
            update["body"] = cut(update["body"])
    incidents["incidents"] = rows
    write("statuspage/summary.json", summary)
    write("statuspage/incidents.json", incidents)


def google():
    items = load("gcp-incidents.json")[:3]
    for item in items:
        item["updates"] = item["updates"][:1]
        for update in item["updates"] + [item["most_recent_update"]]:
            update["text"] = cut(update["text"], 600)
        item["affected_products"] = item["affected_products"][:4]
        item["currently_affected_locations"] = item["currently_affected_locations"][:2]
        item["previously_affected_locations"] = item["previously_affected_locations"][:2]
    write("google/incidents.json", items)


def aws():
    items = load("aws-current.json")[:1]
    for item in items:
        item["event_log"] = item["event_log"][:2]
        for entry in item["event_log"]:
            entry["message"] = cut(entry["message"])
        item["impacted_services"] = dict(sorted(item["impacted_services"].items())[:3])
        item["impacted_service_status_changes"] = item.get("impacted_service_status_changes", [])[:2]
    write("aws/currentevents.json", items, encoding="utf-16")


def ioda():
    value = load("ioda-events.json")
    value["data"] = value["data"][:4]
    write("ioda/events.json", value)


def small():
    write("slack/current.json", load("slack-current.json"))
    history = load("slack-history.json")[:3]
    for item in history:
        for note in item["notes"]:
            note["body"] = cut(note["body"])
    write("slack/history.json", history)
    heroku = load("heroku.json")
    heroku["scheduled"] = heroku["scheduled"][:1]
    write("heroku/current-status.json", heroku)
    salesforce = load("sfdc-active.json")[:1]
    for item in salesforce:
        item["instanceKeys"] = item["instanceKeys"][:5]
        item["IncidentEvents"] = item["IncidentEvents"][:1]
        for event in item["IncidentEvents"]:
            event["message"] = cut(event["message"])
        item["timeline"] = item.get("timeline", [])[:1] if isinstance(item.get("timeline"), list) else item.get("timeline")
    write("salesforce/active.json", salesforce)
    gitlab = load("gitlab.json")
    gitlab["result"]["status"] = gitlab["result"]["status"][:2]
    write("statusio/status.json", gitlab)
    azdo = load("azdo.json")
    azdo["services"] = azdo["services"][:2]
    write("azure-devops/health.json", azdo)
    page = load("chainguard-index.json")
    reports = [item for item in page["included"] if item["type"] == "status_report"][:2]
    wanted = {link["id"] for report in reports for link in report["relationships"]["status_updates"]["data"]}
    resources = {entry["status_page_resource_id"] for report in reports for entry in report["attributes"]["affected_resources"]}
    page["included"] = [item for item in page["included"] if item in reports or (item["type"] == "status_update" and item["id"] in wanted) or
                        (item["type"] == "status_page_resource" and item["id"] in resources)]
    for item in page["included"]:
        if item["type"] == "status_update":
            item["attributes"]["message"] = cut(item["attributes"]["message"])
    write("betterstack/index.json", page)


def rss():
    source = (Path(sys.argv[1]) / "zscaler.rss").read_text(encoding="utf-8")
    head = source[:source.index("<item>")]
    items = re.findall(r"<item>.*?</item>", source, re.S)
    chosen = [item for item in items if re.search(r"<category[^>]*>Recent incident</category>", item)][:2]
    chosen += [item for item in items if re.search(r"<category[^>]*>Scheduled maintenance</category>", item)][:1]
    chosen = [re.sub(r"<description>.*?</description>", "<description></description>", item, flags=re.S) for item in chosen]
    write_text("zscaler/rss-feed.xml", head + "\n".join(chosen) + "\n</channel>\n</rss>\n")
    source = (Path(sys.argv[1]) / "oci-history.rss").read_text(encoding="utf-8")
    head = source[:source.index("<item>")]
    items = re.findall(r"<item>.*?</item>", source, re.S)[:2]
    write_text("statuspage-rss/history.rss", head + "\n".join(items) + "\n</channel></rss>\n")
    write("statuspage-rss/status.json", load("oci-status.json"))
    write_text("azure/feed.xml", (Path(sys.argv[1]) / "azure.rss").read_text(encoding="utf-8"))


if __name__ == "__main__":
    statuspage()
    google()
    aws()
    ioda()
    small()
    rss()
    print("Wrote", OUT)
