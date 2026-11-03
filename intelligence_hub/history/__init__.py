"""History adapters: public archives back to 1998, built locally, committed, and merged at publish.

ADAPTERS is also the build order. ubuntu-usn and nvd-cve keep only rows whose CVE ids
other adapters cite, so they run after the adapters they read. STATIC_SOURCES are the
sources with no adapter: unreachable ones (refused, JavaScript-only or behind a login
when checked) and ones whose adapter is not built yet. coverage.json states every
source and year from 1998 either way.
"""
from .adapters import (certcc_ca, certcc_vu, cisa_alerts, cisa_ics_csaf, mozilla_mfsa, msrc_bulletins, msrc_cvrf,
                       nvd_cve, oracle_cpu, ubuntu_usn)

ADAPTERS = {module.ID: module for module in (
    msrc_bulletins, msrc_cvrf, certcc_vu, certcc_ca, cisa_ics_csaf, cisa_alerts, mozilla_mfsa, oracle_cpu,
    ubuntu_usn, nvd_cve)}

CHECKED = "2026-11-03"
UNREACHABLE = "unreachable"
NOT_BUILT = "adapter not built yet"

STATIC_SOURCES = [
    {"source_id": "adobe-psirt", "name": "Adobe Security Bulletins", "home": "https://helpx.adobe.com/security/security-bulletin.html",
     "status": UNREACHABLE, "reason": "the bulletin index returned HTTP 403 to automated reads (" + CHECKED + ")"},
    {"source_id": "vmware-vmsa", "name": "VMware Security Advisories (Broadcom)", "home": "https://support.broadcom.com/",
     "status": UNREACHABLE, "reason": "the advisory pages are a JavaScript application with no static VMSA index (" + CHECKED + ")"},
    {"source_id": "juniper-jsa", "name": "Juniper Security Advisories", "home": "https://supportportal.juniper.net/",
     "status": UNREACHABLE, "reason": "the support portal is a JavaScript application and no public CSAF host resolved (" + CHECKED + ")"},
    {"source_id": "citrix-bulletins", "name": "Citrix Security Bulletins", "home": "https://support.citrix.com/securitybulletins",
     "status": UNREACHABLE, "reason": "the bulletin page is a JavaScript shell with no static index (" + CHECKED + ")"},
    {"source_id": "sap-security-notes", "name": "SAP Security Notes", "home": "https://support.sap.com/",
     "status": UNREACHABLE, "reason": "note details need an SAP login; only patch-day summaries are public (" + CHECKED + ")"},
    {"source_id": "schneider-electric-psirt", "name": "Schneider Electric Security Notifications", "home": "https://www.se.com/",
     "status": UNREACHABLE, "reason": "the notification page and its CSAF provider metadata returned HTTP 403; its ICS advisories also arrive through CISA ICS CSAF (" + CHECKED + ")"},
    {"source_id": "redhat-csaf", "name": "Red Hat Security Advisories (CSAF)", "home": "https://security.access.redhat.com/data/csaf/v2/advisories/",
     "status": "gap", "reason": NOT_BUILT + "; it waits for the owner's reading of the Red Hat data licence"},
    {"source_id": "siemens-productcert", "name": "Siemens ProductCERT (CSAF)", "home": "https://cert-portal.siemens.com/productcert/",
     "status": "gap", "reason": NOT_BUILT},
    {"source_id": "paloalto-psirt", "name": "Palo Alto Networks Security Advisories", "home": "https://security.paloaltonetworks.com/",
     "status": "gap", "reason": NOT_BUILT},
    {"source_id": "google-project-zero", "name": "Google Project Zero", "home": "https://googleprojectzero.blogspot.com/",
     "status": "gap", "reason": NOT_BUILT},
    {"source_id": "talos-reports", "name": "Cisco Talos Vulnerability Reports", "home": "https://talosintelligence.com/vulnerability_reports",
     "status": "gap", "reason": NOT_BUILT},
    {"source_id": "cisco-openvuln", "name": "Cisco PSIRT openVuln", "home": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
     "status": "gap", "reason": NOT_BUILT + "; the openVuln API needs an owner-registered key"},
    {"source_id": "research-blog-backfill", "name": "Research blog archives (Securelist, Unit 42, Microsoft Security blog)",
     "home": "https://securelist.com/", "status": "gap", "reason": NOT_BUILT},
]


def registry():
    """Source entries for the tagging context, one per adapter."""
    return [{"id": module.SOURCE_ID, "source_class": module.SOURCE_CLASS, "publisher_vendor": module.PUBLISHER_VENDOR,
             "country": module.COUNTRY} for module in ADAPTERS.values()]
