import asyncio
import copy
import io
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import httpx
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from capabilities import CapabilityManager, CapabilityRegistry  # noqa: E402
from capabilities.rag import indexer as indexer_module  # noqa: E402
from capabilities.rag.indexer import ArtifactSourceIndexer  # noqa: E402
from config_manager import ConfigManager  # noqa: E402
from discovery.environment_profile import detect_deployment_type, normalize_installed_app_rows, splunk_version_line  # noqa: E402
from knowledge_library import docs as docs_module  # noqa: E402
from knowledge_library import sources as sources_module  # noqa: E402
from knowledge_library.catalog import build_catalog, choose_doc_version, match_addon_doc  # noqa: E402
from knowledge_library.docs import (  # noqa: E402
    CHUNK_MAX_CHARS,
    DocIndex,
    _parse_and_chunk,
    build_doc_plan,
    chunk_page,
    extract_doc_page,
    fts5_available,
    needs_fetch,
    plan_coverage,
    plan_signature,
    rank_doc_results,
    sanitize_docs_payload,
    sync_docs,
)
from knowledge_library.ranking import BM25, EnvironmentTerms, query_terms, reciprocal_rank_fusion  # noqa: E402
from knowledge_library.profile import build_environment_profile  # noqa: E402
from knowledge_library.scorecard import build_scorecard  # noqa: E402
from knowledge_library.service import KnowledgeLibraryService, LibraryBusyError  # noqa: E402
from knowledge_library.sources import (  # noqa: E402
    LibraryPackError,
    LibrarySourceError,
    LibraryStore,
    build_docs_product_index,
    create_library_http_client,
    export_pack,
    fetch_help_docs,
    fetch_security_content,
    fetch_splunkbase,
    import_pack,
    normalize_splunkbase_app,
    parse_data_source_yaml,
    parse_sitemap,
    utc_now_iso,
)
from security_manager import SecurityManager  # noqa: E402
import web_app  # noqa: E402


_NO_REQUEST_SPACING = mock.patch.object(docs_module, "DOC_REQUEST_INTERVAL", 0)


def setUpModule():
    _NO_REQUEST_SPACING.start()


def tearDownModule():
    _NO_REQUEST_SPACING.stop()


DATA_SOURCE_FILES = {
    "windows_event_log_security_4624.yml": """
name: Windows Event Log Security 4624
id: 11111111-2222-3333-4444-555555555555
version: 3
description: Successful logons.
source: XmlWinEventLog:Security
sourcetype: xmlwineventlog
separator: EventCode
separator_value: '4624'
supported_TA:
- name: Splunk Add-on for Microsoft Windows
  url: https://splunkbase.splunk.com/app/742
  version: 9.0.1
fields:
- _time
- EventCode
- dest
output_fields:
- dest
mitre_components:
- Logon Session Creation
""",
    "aws_cloudtrail.yml": """
name: AWS CloudTrail
id: 22222222-3333-4444-5555-666666666666
source: aws_cloudtrail
sourcetype: aws:cloudtrail
supported_TA:
- name: Splunk Add-on for AWS
  url: https://splunkbase.splunk.com/app/1876
  version: 7.9.0
fields:
- eventName
""",
    "palo_alto_network_traffic.yml": """
name: Palo Alto Network Traffic
id: 33333333-4444-5555-6666-777777777777
source: screenconnect
sourcetype: pan:traffic
supported_TA:
- name: Palo Alto Networks Add-on
  url: https://splunkbase.splunk.com/app/2757
  version: 8.1.0
""",
    "broken.yml": "name: [unclosed",
}

SPLUNKBASE_RECORDS = {
    742: {
        "uid": 742, "appid": "Splunk_TA_windows", "title": "Splunk Add-on for Microsoft Windows", "type": "addon",
        "cloud_compatible": True, "archive_status": "live",
        "releases": [
            {"title": "9.1.0", "published_time": "2026-01-10T00:00:00Z", "product_compatibility": ["Splunk Enterprise"]},
            {"title": "9.0.1", "published_time": "2025-11-01T00:00:00Z", "product_compatibility": ["Splunk Enterprise", "Splunk Cloud"]},
        ],
    },
    1876: {
        "uid": 1876, "appid": "Splunk_TA_aws", "title": "Splunk Add-on for AWS", "type": "addon", "archive_status": "live",
        "releases": [{"title": "8.0.0", "product_compatibility": ["Splunk Enterprise", "Splunk Cloud"]}],
    },
    2757: {
        "uid": 2757, "appid": "Splunk_TA_paloalto", "title": "Palo Alto Networks Add-on", "type": "addon", "archive_status": "archived",
        "releases": [{"title": "8.1.0", "product_compatibility": ["Splunk Enterprise"]}],
    },
    1621: {
        "uid": 1621, "appid": "Splunk_SA_CIM", "title": "Splunk Common Information Model (CIM)", "type": "addon",
        "cloud_compatible": False, "archive_status": "live",
        "releases": [{"title": "6.0.0", "product_compatibility": ["Splunk Enterprise"]}],
    },
}
SPLUNKBASE_BY_APPID = {record["appid"].lower(): record for record in SPLUNKBASE_RECORDS.values()}

HELP = "https://help.splunk.com/en/"
ENTERPRISE_PAGES = [
    "splunk-enterprise/search/spl-search-reference/9.4/introduction/welcome",
    "splunk-enterprise/search/spl-search-reference/9.3/introduction/welcome",
    "splunk-enterprise/administer/admin-manual/9.4/configuration-files/about",
    "splunk-enterprise/administer/admin-manual/9.4/configuration-files/list",
    "splunk-enterprise/administer/admin-manual/9.3/configuration-files/about",
    "splunk-enterprise/administer/distributed-search/9.4/overview/about",
    "splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.4/overview/about",
    "splunk-enterprise/common-information-model/6.0/introduction/overview",
    "splunk-enterprise/get-started/overview",
    "splunk-enterprise/bad segment/9.4/page",
    "splunk-cloud-platform/search/spl-search-reference/10.1.2507/introduction/welcome",
]
CLOUD_PAGES = [
    "splunk-cloud-platform/search/spl-search-reference/10.1.2507/introduction/welcome",
    "splunk-cloud-platform/administer/admin-manual/10.1.2507/configuration-files/about",
    "splunk-cloud-platform/administer/admin-manual/10.0.2503/configuration-files/about",
]
ADDON_PAGES = ["supported-add-ons/splunk-supported-add-ons/microsoft-windows/install"]


DOC_PAGE_TEXT = {
    "splunk-enterprise/search/spl-search-reference/9.4/introduction/welcome": (
        "Welcome to the Search Reference",
        [("Search commands", "The stats command calculates aggregate statistics such as count, sum, and average over the search results.")],
    ),
    "splunk-enterprise/administer/admin-manual/9.4/configuration-files/about": (
        "About configuration files",
        [
            ("Where settings live", "Splunk Enterprise stores settings in configuration files such as inputs.conf and props.conf."),
            ("Change parsing", "Edit props.conf to change how the WinEventLog:Security sourcetype is parsed at index time."),
        ],
    ),
    "splunk-enterprise/administer/admin-manual/9.4/configuration-files/list": (
        "List of configuration files",
        [("Forwarding", "outputs.conf holds forwarding settings and indexes.conf defines index paths and retention.")],
    ),
    "splunk-enterprise/administer/distributed-search/9.4/overview/about": (
        "About distributed search",
        [("Search heads", "A search head distributes searches to search peers and merges the results.")],
    ),
    "splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.4/overview/about": (
        "About indexer clusters",
        [("Replication", "An indexer cluster replicates data across peer nodes. The manager node enforces the replication factor and search factor.")],
    ),
    "splunk-enterprise/common-information-model/6.0/introduction/overview": (
        "Overview of the Common Information Model",
        [("Data models", "The CIM normalizes fields such as src and dest so the Authentication data model works across sources.")],
    ),
    "supported-add-ons/splunk-supported-add-ons/microsoft-windows/install": (
        "Install the Splunk Add-on for Microsoft Windows",
        [("Forwarders", "Deploy the add-on to universal forwarders to collect WinEventLog data from Windows hosts.")],
    ),
}


def doc_html(title, sections, lastmod="2026-02-01T00:00:00Z"):
    body = "".join(f"<h2>{heading}</h2><p>{text}</p>" for heading, text in sections)
    return (
        f'<html><head><title>{title} | Splunk Docs</title><meta name="lastModifiedISO" content="{lastmod}">'
        f"<script>var tracking = 1;</script></head><body><nav>Menu Products Search</nav>"
        f"<main><article><h1>{title}</h1>{body}</article></main><footer>Copyright Splunk</footer></body></html>"
    )


def doc_page_html(page):
    title, sections = DOC_PAGE_TEXT.get(page, (page.rsplit("/", 1)[-1].replace("-", " ").capitalize() or "Overview", [("Details", f"Reference text for {page}.")]))
    return doc_html(title, sections)


def sitemap(pages):
    blocks = "".join(f"<url><loc>{HELP}{page}</loc><lastmod>2026-02-0{index % 9 + 1}</lastmod></url>" for index, page in enumerate(pages))
    return f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{blocks}</urlset>'


SITEMAPS = {
    "splunk-enterprise": sitemap(ENTERPRISE_PAGES),
    "splunk-cloud-platform": sitemap(CLOUD_PAGES),
    "supported-add-ons": sitemap(ADDON_PAGES),
}


class FakeSourceServer:
    """Answers the GitHub, Splunkbase, and help.splunk.com requests the library makes."""

    def __init__(self, release_tag="v9.9.0", sitemaps=None, gate=None, github_status=None, missing_pages=(), pdf_pages=(), refuse_after=None):
        self.release_tag = release_tag
        self.sitemaps = SITEMAPS if sitemaps is None else sitemaps
        self.gate = gate
        self.github_status = github_status
        self.missing_pages = set(missing_pages)
        self.pdf_pages = set(pdf_pages)
        self.refuse_after = refuse_after
        self.refused_pages = []
        self.calls = []
        self.page_fetches = []

    def transport(self):
        return httpx.MockTransport(self.handle)

    async def handle(self, request):
        if self.gate is not None:
            await self.gate.wait()
        self.calls.append(str(request.url))
        host, path = request.url.host, request.url.path
        if host == "api.github.com":
            if self.github_status:
                return httpx.Response(self.github_status, json={"message": "limited"})
            if path.endswith("/releases/latest"):
                return httpx.Response(200, json={"tag_name": self.release_tag}) if self.release_tag else httpx.Response(404, json={})
            if path.endswith("/contents/data_sources"):
                listing = [{"name": name, "type": "file"} for name in [*DATA_SOURCE_FILES, "missing.yml"]]
                listing += [{"name": "deprecated", "type": "dir"}, {"name": "README.md", "type": "file"}]
                return httpx.Response(200, json=listing)
        if host == "raw.githubusercontent.com":
            name = path.rsplit("/", 1)[-1]
            if name in DATA_SOURCE_FILES:
                return httpx.Response(200, text=DATA_SOURCE_FILES[name])
            return httpx.Response(404, text="not found")
        if host == "splunkbase.splunk.com":
            if path == "/api/v1/app/":
                record = SPLUNKBASE_BY_APPID.get(str(request.url.params.get("appid") or "").lower())
                return httpx.Response(200, json={"results": [record] if record else []})
            match = re.fullmatch(r"/api/v1/app/(\d+)/", path)
            if match and int(match.group(1)) in SPLUNKBASE_RECORDS:
                return httpx.Response(200, json=SPLUNKBASE_RECORDS[int(match.group(1))])
            return httpx.Response(404, json={})
        if host == "help.splunk.com":
            if path.endswith("/sitemap.xml"):
                product = path.split("/")[2]
                if product in self.sitemaps:
                    return httpx.Response(200, text=self.sitemaps[product])
                return httpx.Response(404, text="")
            page = path[len("/en/"):]
            if page in self.missing_pages:
                return httpx.Response(404, text="")
            # Like the real site, page requests that ask for text/html are refused; the default Accept header is served.
            refuse_html = "text/html" in request.headers.get("accept", "")
            if refuse_html or (self.refuse_after is not None and len(self.page_fetches) >= self.refuse_after):
                self.refused_pages.append(page)
                return httpx.Response(403, html="<html><head><title>Error</title></head><body><main><h1>You don't have access to this page.</h1></main></body></html>")
            self.page_fetches.append(page)
            if page in self.pdf_pages:
                return httpx.Response(200, content=b"%PDF-1.7 binary", headers={"Content-Type": "application/pdf"})
            return httpx.Response(200, html=doc_page_html(page))
        return httpx.Response(500)


def library_sources(now_iso=None):
    """Source payloads as the fetchers produce them, built from the fixtures above."""
    stamp = now_iso or utc_now_iso()
    data_sources = [entry for entry in (parse_data_source_yaml(text, name) for name, text in DATA_SOURCE_FILES.items()) if entry]
    apps = {record["appid"].lower(): normalize_splunkbase_app(record) for record in SPLUNKBASE_RECORDS.values()}
    products = {
        product: {**build_docs_product_index(product, [(HELP + page, "2026-02-01") for page in pages]), "fetched_at": stamp}
        for product, pages in (("splunk-enterprise", ENTERPRISE_PAGES), ("splunk-cloud-platform", CLOUD_PAGES), ("supported-add-ons", ADDON_PAGES))
    }
    return {
        "security_content": {"source": "security_content", "fetched_at": stamp, "origin": "online", "ref": "v9.9.0", "version": "v9.9.0", "data_sources": data_sources},
        "splunkbase": {"source": "splunkbase", "fetched_at": stamp, "origin": "online", "apps": apps, "not_found": ["ta-custom-thing"]},
        "help_docs": {"source": "help_docs", "fetched_at": stamp, "origin": "online", "products": products},
    }


DEFAULT_APPS = [
    {"name": "search", "label": "Search & Reporting", "version": "9.4.2", "disabled": "0"},
    {"name": "Splunk_TA_windows", "label": "Splunk Add-on for Microsoft Windows", "version": "9.0.1", "disabled": "0"},
    {"name": "Splunk_TA_paloalto", "label": "Palo Alto Networks Add-on", "version": "8.1.0", "disabled": "0"},
    {"name": "Splunk_SA_CIM", "label": "Splunk Common Information Model", "version": "6.0.0", "disabled": "0"},
    {"name": "TA-custom-thing", "label": "Custom thing", "version": "1.0", "disabled": "0"},
]
DEFAULT_SOURCETYPES = [
    {"name": "splunkd", "events": 9000},
    {"name": "WinEventLog:Security", "events": 5000},
    {"name": "aws:cloudtrail", "events": 3000},
    {"name": "pan:traffic", "events": 2000},
    {"name": "custom:app", "events": 1000},
]


def make_blueprint(version="9.4.2", deployment="enterprise", apps_status="ok", apps=None, sourcetypes=None, roles=("search_head",), env=True):
    blueprint = {
        "generated_at": "2026-05-01T12:00:00+00:00",
        "overview": {"splunk_version": version, "server_roles": list(roles)},
        "discovered_inventory": {"indexes": ["main", "firewall"], "sourcetypes": [row["name"] for row in (sourcetypes or DEFAULT_SOURCETYPES)]},
    }
    if env:
        blueprint["environment_profile"] = {
            "schema_version": 1,
            "splunk_version": version,
            "deployment_type": deployment,
            "server_roles": list(roles),
            "installed_apps": {"status": apps_status, "error": "" if apps_status == "ok" else "Insufficient permissions", "items": DEFAULT_APPS if apps is None else apps},
            "sourcetypes": sourcetypes or DEFAULT_SOURCETYPES,
        }
    return blueprint


def doc_page_path(manual, page):
    return "/".join(part for part in (manual["product"], manual["manual"], manual["version"], page) if part)


def default_doc_plan(blueprint=None):
    return build_doc_plan(build_environment_profile(blueprint or make_blueprint()), library_sources()["help_docs"])


def fill_doc_index(index, plan=None):
    """Store every planned page the way a sync would, without the network."""
    plan = plan or default_doc_plan()
    for manual in plan["manuals"]:
        pages = []
        for page in manual["pages"]:
            parsed, chunks = _parse_and_chunk(doc_page_html(doc_page_path(manual, page)))
            url = sources_module.help_doc_url(manual["product"], manual["manual"], manual["version"], page)
            pages.append({"page": page, "url": url, "title": parsed["title"], "lastmod": parsed["lastmod"], "chunks": chunks})
        index.replace_manual(manual, pages, failed=0, complete=True)
    return plan


def loaded_summary(stamp=None):
    stamp = stamp or utc_now_iso()
    return {name: {"name": name, "available": True, "fetched_at": stamp} for name in ("security_content", "splunkbase", "help_docs")}


class EnvironmentProfileHelperTests(unittest.TestCase):
    def test_deployment_type_detection(self):
        self.assertEqual(detect_deployment_type({"instance_type": "cloud", "version": "9.4.2"})[0], "cloud")
        self.assertEqual(detect_deployment_type({"version": "9.4.2"}, "https://acme.splunkcloud.com:8089/services/mcp")[0], "cloud")
        self.assertEqual(detect_deployment_type({"version": "9.4.2"}, "https://acme.splunkcloudgc.com/services/mcp")[0], "cloud")
        self.assertEqual(detect_deployment_type({"version": "10.1.2507.3"}, "https://10.0.0.5:8089/mcp")[0], "cloud")
        self.assertEqual(detect_deployment_type({"version": "9.4.2"}, "https://splunk.example.test:8089/mcp")[0], "enterprise")
        self.assertEqual(detect_deployment_type({}, "")[0], "unknown")
        self.assertEqual(detect_deployment_type({"version": "unknown"}, "")[0], "unknown")

    def test_version_line_keeps_the_cloud_release_component(self):
        self.assertEqual(splunk_version_line("9.4.2"), "9.4")
        self.assertEqual(splunk_version_line("10.1.2507.3"), "10.1.2507")
        self.assertEqual(splunk_version_line(""), "")
        self.assertEqual(splunk_version_line("unknown"), "")

    def test_app_rows_from_either_collector_are_flattened(self):
        rows = [
            {"title": "Splunk_TA_windows", "label": "Windows", "version": "9.0.1", "disabled": "0", "details": "https://splunkbase.splunk.com/app/742"},
            {"name": "splunk_ta_windows", "label": "Duplicate"},
            {"id": "https://sh:8089/servicesNS/nobody/system/apps/local/TA-from-id", "content": {"version": "2.0", "disabled": True}},
            {"name": "100-cloudworks-wlm", "version": "1"},
            {"name": "my_app", "core": "1"},
            {"label": "No name"},
            "not a row",
        ]
        apps = {app["name"]: app for app in normalize_installed_app_rows(rows)}
        self.assertEqual(sorted(apps, key=str.lower), ["100-cloudworks-wlm", "my_app", "Splunk_TA_windows", "TA-from-id"])
        self.assertEqual(apps["Splunk_TA_windows"]["label"], "Windows")
        self.assertFalse(apps["Splunk_TA_windows"]["builtin"])
        self.assertTrue(apps["TA-from-id"]["disabled"])
        self.assertEqual(apps["TA-from-id"]["version"], "2.0")
        self.assertTrue(apps["100-cloudworks-wlm"]["builtin"])
        self.assertTrue(apps["my_app"]["builtin"])

    def test_profile_from_a_blueprint_without_the_new_section_uses_older_fields(self):
        blueprint = make_blueprint(version="10.1.2507.3", env=False)
        blueprint["finding_ledger"] = [{"kind": "sourcetype", "data": {"sourcetype": "pan:traffic", "totalCount": "12"}}]
        profile = build_environment_profile(blueprint)
        self.assertTrue(profile["available"])
        self.assertEqual(profile["splunk"]["deployment_type"], "cloud")
        self.assertEqual(profile["splunk"]["version_line"], "10.1.2507")
        self.assertFalse(profile["apps"]["collected"])
        self.assertEqual(profile["apps"]["status"], "not_collected")
        self.assertEqual(profile["sourcetypes"], [{"name": "pan:traffic", "events": 12, "last_seen_utc": None}])
        self.assertFalse(build_environment_profile(None)["available"])


class SourceFetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_security_content_reads_the_latest_release_and_skips_unreadable_files(self):
        server = FakeSourceServer()
        progress = []
        async with create_library_http_client(server.transport()) as client:
            payload = await fetch_security_content(client, lambda stage, done, total: progress.append((stage, done, total)))
        self.assertEqual(payload["ref"], "v9.9.0")
        self.assertEqual(payload["version"], "v9.9.0")
        self.assertEqual([entry["name"] for entry in payload["data_sources"]], ["AWS CloudTrail", "Palo Alto Network Traffic", "Windows Event Log Security 4624"])
        self.assertEqual(payload["failed_files"], 1)
        windows = payload["data_sources"][2]
        self.assertEqual(windows["supported_tas"], [{"name": "Splunk Add-on for Microsoft Windows", "splunkbase_uid": 742, "version": "9.0.1"}])
        self.assertEqual(windows["fields_count"], 3)
        self.assertEqual(windows["file"], "windows_event_log_security_4624.yml")
        self.assertFalse(any("README.md" in url for url in server.calls))
        self.assertTrue(all("/v9.9.0/" in url for url in server.calls if "raw.githubusercontent.com" in url))
        self.assertEqual(progress[-1], ("security_content", 5, 5))

    async def test_security_content_uses_the_default_branch_without_a_release(self):
        server = FakeSourceServer(release_tag="")
        async with create_library_http_client(server.transport()) as client:
            payload = await fetch_security_content(client)
        self.assertEqual(payload["ref"], "develop")
        self.assertIn("ref=develop", next(url for url in server.calls if "contents/data_sources" in url))

    async def test_github_rate_limit_is_explained(self):
        async with create_library_http_client(FakeSourceServer(github_status=403).transport()) as client:
            with self.assertRaisesRegex(LibrarySourceError, "hourly limit"):
                await fetch_security_content(client)

    async def test_requests_outside_the_source_hosts_are_blocked(self):
        hits = []

        def handler(request):
            hits.append(str(request.url))
            if request.url.host == "help.splunk.com":
                return httpx.Response(302, headers={"Location": "https://attacker.example/steal"})
            return httpx.Response(200, text="ok")

        async with create_library_http_client(httpx.MockTransport(handler)) as client:
            with self.assertRaises(LibrarySourceError):
                await client.get("https://attacker.example/")
            with self.assertRaises(LibrarySourceError):
                await client.get("http://help.splunk.com/en/splunk-enterprise/sitemap.xml")
            with self.assertRaises(LibrarySourceError):
                await client.get("https://help.splunk.com/en/splunk-enterprise/sitemap.xml")
        self.assertEqual(hits, ["https://help.splunk.com/en/splunk-enterprise/sitemap.xml"])

    async def test_splunkbase_lookups_record_latest_and_cloud_releases(self):
        server = FakeSourceServer()
        existing = {"apps": {}, "not_found": ["splunk_ta_aws"]}
        async with create_library_http_client(server.transport()) as client:
            payload = await fetch_splunkbase(client, uids=[742, 2757, 9999], appids=["Splunk_TA_aws", "TA-custom-thing"], existing=existing)
        windows = payload["apps"]["splunk_ta_windows"]
        self.assertEqual((windows["latest_version"], windows["latest_cloud_version"]), ("9.1.0", "9.0.1"))
        self.assertTrue(windows["cloud_compatible"])
        self.assertFalse(windows["archived"])
        self.assertTrue(payload["apps"]["splunk_ta_paloalto"]["archived"])
        self.assertIn("splunk_ta_aws", payload["apps"])
        self.assertEqual(payload["not_found"], ["ta-custom-thing"])
        self.assertEqual(payload["failed_lookups"], 1)

    async def test_splunkbase_needs_something_to_look_up(self):
        async with create_library_http_client(FakeSourceServer().transport()) as client:
            with self.assertRaises(LibrarySourceError):
                await fetch_splunkbase(client, uids=[], appids=[])

    async def test_help_docs_group_pages_by_manual_and_version(self):
        server = FakeSourceServer()
        async with create_library_http_client(server.transport()) as client:
            payload = await fetch_help_docs(client)
        products = payload["products"]
        self.assertEqual(sorted(products), ["splunk-cloud-platform", "splunk-enterprise", "supported-add-ons"])
        enterprise = products["splunk-enterprise"]
        self.assertEqual(enterprise["page_count"], 9)
        self.assertEqual(sorted(enterprise["manuals"]["administer/admin-manual"]), ["9.3", "9.4"])
        self.assertEqual(enterprise["manuals"]["administer/admin-manual"]["9.4"]["pages"], ["configuration-files/about", "configuration-files/list"])
        self.assertEqual(enterprise["manuals"]["get-started/overview"][""]["pages"], [""])
        self.assertNotIn("bad segment", json.dumps(enterprise))
        self.assertIn("splunk-supported-add-ons/microsoft-windows", products["supported-add-ons"]["manuals"])
        self.assertEqual(len(payload["errors"]), 3)

    async def test_help_docs_fail_when_no_product_answers(self):
        async with create_library_http_client(FakeSourceServer(sitemaps={}).transport()) as client:
            with self.assertRaises(LibrarySourceError):
                await fetch_help_docs(client)

    def test_sitemap_parser_ignores_entries_without_a_location(self):
        entries = parse_sitemap("<urlset><url><lastmod>2026</lastmod></url><url><loc> https://help.splunk.com/en/a </loc></url></urlset>")
        self.assertEqual(entries, [("https://help.splunk.com/en/a", "")])


class LibraryPackTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = LibraryStore(self.root / "source")
        for name, payload in library_sources().items():
            self.store.save_source(name, payload)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _zip(self, members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content if isinstance(content, str) else json.dumps(content))
        return buffer.getvalue()

    def test_pack_round_trip_marks_sources_as_imported(self):
        data = export_pack(self.store)
        target = LibraryStore(self.root / "target")
        result = import_pack(target, data)
        self.assertEqual(result["imported"], ["help_docs", "security_content", "splunkbase"])
        summary = target.summary()
        self.assertTrue(all(entry["available"] for entry in summary.values()))
        self.assertEqual(summary["security_content"]["origin"], "pack")
        self.assertEqual(summary["security_content"]["count"], 3)
        self.assertEqual(summary["splunkbase"]["count"], 4)
        self.assertTrue(summary["help_docs"]["pack_created_at"])
        original = self.store.load_source("help_docs")["products"]["splunk-enterprise"]["manuals"]
        self.assertEqual(target.load_source("help_docs")["products"]["splunk-enterprise"]["manuals"], original)

    def test_export_needs_at_least_one_source(self):
        with self.assertRaises(LibraryPackError):
            export_pack(LibraryStore(self.root / "empty"))

    def test_unusable_uploads_are_rejected(self):
        target = LibraryStore(self.root / "target")
        manifest = {"format": sources_module.PACK_FORMAT, "format_version": 1}
        cases = {
            "empty": b"",
            "not a zip": b"plain text",
            "no manifest": self._zip({"sources/splunkbase.json": {}}),
            "newer format": self._zip({sources_module.PACK_MANIFEST_NAME: {**manifest, "format_version": 99}}),
            "no sources": self._zip({sources_module.PACK_MANIFEST_NAME: manifest}),
            "bad json": self._zip({sources_module.PACK_MANIFEST_NAME: manifest, "sources/splunkbase.json": "{oops"}),
        }
        for label, data in cases.items():
            with self.subTest(label):
                with self.assertRaises(LibraryPackError):
                    import_pack(target, data)
        self.assertFalse(any(entry["available"] for entry in target.summary().values()))
        with mock.patch.object(sources_module, "MAX_PACK_BYTES", 10):
            with self.assertRaises(LibraryPackError):
                import_pack(target, export_pack(self.store))

    def test_imported_sources_are_rebuilt_from_known_fields(self):
        manifest = {"format": sources_module.PACK_FORMAT, "format_version": 1, "created_at": "2026-04-01T00:00:00+00:00"}
        security = {
            "ref": "../../etc",
            "script": "<script>alert(1)</script>",
            "data_sources": [{"name": "Good", "sourcetype": "x", "file": "../evil.yml", "extra": "dropped"}, {"description": "no name"}],
        }
        docs = {"products": {
            "splunk-enterprise": {"manuals": {"../escape": {"9.4": {"pages": ["a"]}}, "search/ok": {"9.4": {"pages": ["fine", "../bad"]}, "javascript:": {"pages": ["x"]}}}},
            "unknown-product": {"manuals": {"a/b": {"": {"pages": ["c"]}}}},
        }}
        splunkbase = {"apps": {"x": {"appid": "no_uid"}, "y": {"uid": 5, "appid": "Good_App", "releases": [{"title": "1.2"}]}}}
        data = self._zip({
            sources_module.PACK_MANIFEST_NAME: manifest,
            "sources/security_content.json": security,
            "sources/help_docs.json": docs,
            "sources/splunkbase.json": splunkbase,
            "sources/../../outside.json": {"x": 1},
        })
        target = LibraryStore(self.root / "target")
        import_pack(target, data)
        loaded = target.load_sources()
        self.assertEqual(loaded["security_content"]["ref"], "develop")
        self.assertNotIn("script", loaded["security_content"])
        self.assertEqual([entry["name"] for entry in loaded["security_content"]["data_sources"]], ["Good"])
        self.assertEqual(loaded["security_content"]["data_sources"][0]["file"], "")
        self.assertNotIn("extra", loaded["security_content"]["data_sources"][0])
        self.assertEqual(list(loaded["help_docs"]["products"]), ["splunk-enterprise"])
        self.assertEqual(loaded["help_docs"]["products"]["splunk-enterprise"]["manuals"], {"search/ok": {"9.4": {"lastmod": "", "pages": ["fine"]}}})
        self.assertEqual(list(loaded["splunkbase"]["apps"]), ["good_app"])
        self.assertFalse((self.root / "outside.json").exists())


class CatalogTests(unittest.TestCase):
    def test_sourcetypes_map_to_data_sources_add_ons_and_docs(self):
        catalog = build_catalog(build_environment_profile(make_blueprint()), library_sources())
        by_name = {entry["name"]: entry for entry in catalog["sourcetypes"]}

        windows = by_name["WinEventLog:Security"]
        self.assertEqual(windows["match"], "source")
        self.assertEqual(windows["addon_status"], "outdated")
        addon = windows["add_ons"][0]
        self.assertEqual((addon["installed_app"], addon["installed_version"], addon["latest_version"]), ("Splunk_TA_windows", "9.0.1", "9.1.0"))
        self.assertEqual(addon["splunkbase_url"], "https://splunkbase.splunk.com/app/742/")
        self.assertEqual(addon["doc_url"], "https://help.splunk.com/en/supported-add-ons/splunk-supported-add-ons/microsoft-windows")
        self.assertEqual(windows["data_sources"][0]["url"], "https://github.com/splunk/security_content/blob/v9.9.0/data_sources/windows_event_log_security_4624.yml")
        self.assertEqual(by_name["aws:cloudtrail"]["addon_status"], "missing")
        self.assertEqual(by_name["pan:traffic"]["addon_status"], "current")
        self.assertEqual(by_name["custom:app"]["match"], "")

        apps = {entry["name"]: entry for entry in catalog["apps"]}
        self.assertEqual(apps["search"]["status"], "builtin")
        self.assertEqual(apps["TA-custom-thing"]["status"], "not_on_splunkbase")
        self.assertEqual(apps["Splunk_TA_windows"]["supports_sourcetypes"], ["WinEventLog:Security"])
        self.assertEqual(catalog["pending_splunkbase_lookups"], [])
        self.assertEqual(catalog["splunkbase_uids"], [742, 1876, 2757])

        docs = catalog["platform_docs"]
        self.assertEqual((docs["product"], docs["doc_version"], docs["version_match"]), ("splunk-enterprise", "9.4", "exact"))
        self.assertEqual([entry["title"] for entry in docs["manuals"]], ["SPL Search Reference", "Admin Manual", "Distributed Search"])
        self.assertEqual(docs["manuals"][1]["url"], "https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-files/about")
        self.assertEqual(docs["manuals"][1]["page_count"], 2)
        self.assertEqual([(entry["title"], entry["version"]) for entry in catalog["app_docs"]], [("Common Information Model", "6.0")])

    def test_cloud_stacks_use_cloud_releases_and_cloud_docs(self):
        catalog = build_catalog(build_environment_profile(make_blueprint(version="10.1.2507.3", deployment="cloud")), library_sources())
        windows = next(entry for entry in catalog["apps"] if entry["name"] == "Splunk_TA_windows")
        self.assertEqual((windows["latest_version"], windows["status"]), ("9.0.1", "current"))
        docs = catalog["platform_docs"]
        self.assertEqual((docs["product"], docs["doc_version"], docs["version_match"]), ("splunk-cloud-platform", "10.1.2507", "exact"))

    def test_app_documentation_uses_the_installed_version_only(self):
        product = "splunk-enterprise-security-8"
        pages = [
            "administer/8.1/overview/about",
            "administer/8.1/overview/roles",
            "administer/8.2/overview/about",
            "user-guide/8.1/start/welcome",
            *[f"ai-toolkit/ai-toolkit-user-guide/6.2.0/chapter/page-{number}" for number in range(5)],
            "splunk-app-for-pci-compliance/user-manual/6.4/start/welcome",
            "splunk-app-for-pci-compliance/user-manual/8.8/start/welcome",
        ]
        sources = library_sources()
        sources["help_docs"]["products"][product] = build_docs_product_index(product, [(f"{HELP}{product}/{page}", "2026-02-01") for page in pages])
        apps = [*DEFAULT_APPS, {"name": "SplunkEnterpriseSecuritySuite", "label": "Enterprise Security", "version": "8.1.0", "disabled": "0"}]
        profile = build_environment_profile(make_blueprint(apps=apps))
        catalog = build_catalog(profile, sources)
        es_docs = [(entry["manual"], entry["version"]) for entry in catalog["app_docs"] if entry["app"] == "SplunkEnterpriseSecuritySuite"]
        self.assertEqual(es_docs, [("administer", "8.1"), ("user-guide", "8.1")])
        plan = build_doc_plan(profile, sources["help_docs"])
        self.assertEqual([manual["key"] for manual in plan["manuals"] if manual["product"] == product], [f"{product}/administer/8.1", f"{product}/user-guide/8.1"])

    def test_unknown_apps_wait_for_a_splunkbase_lookup(self):
        apps = [*DEFAULT_APPS, {"name": "TA-brand-new", "version": "1.0"}]
        catalog = build_catalog(build_environment_profile(make_blueprint(apps=apps)), library_sources())
        self.assertEqual(catalog["pending_splunkbase_lookups"], ["TA-brand-new"])

    def test_doc_version_choice(self):
        available = ["9.2", "9.3", "9.4", "10.0"]
        self.assertEqual(choose_doc_version(available, "9.4"), ("9.4", "exact"))
        self.assertEqual(choose_doc_version(available, "9.4.2"), ("9.4", "same_line"))
        self.assertEqual(choose_doc_version(available, "9.5"), ("9.4", "nearest_lower"))
        self.assertEqual(choose_doc_version(available, "8.2"), ("9.2", "nearest_higher"))
        self.assertEqual(choose_doc_version(available, ""), ("10.0", "latest"))
        self.assertEqual(choose_doc_version([], "9.4"), ("", "none"))

    def test_add_on_doc_matching(self):
        slugs = {"microsoft-windows": "w", "amazon-web-services-aws": "a", "cisco-asa": "c"}
        self.assertEqual(match_addon_doc(["Splunk Add-on for Microsoft Windows"], slugs)["slug"], "microsoft-windows")
        self.assertEqual(match_addon_doc(["Splunk Add-on for Cisco ASA"], slugs)["slug"], "cisco-asa")
        self.assertIsNone(match_addon_doc(["Custom thing"], slugs))


class ScorecardTests(unittest.TestCase):
    def _scorecard(self, blueprint=None, sources=None, summary=None, assets=()):
        profile = build_environment_profile(blueprint if blueprint is not None else make_blueprint())
        loaded = library_sources() if sources is None else sources
        catalog = build_catalog(profile, loaded) if profile.get("available") else None
        return build_scorecard(profile, catalog, list(assets) if assets is not None else None, loaded_summary() if summary is None else summary)

    def test_full_scorecard(self):
        assets = [
            {"title": "Notes on pan:traffic fields", "library_status": "checked_in"},
            {"title": "custom:app runbook", "library_status": "checked_out"},
            {"title": "Windows notes", "attributes": {"library_entry_ids": ["app:Splunk_TA_windows"]}},
        ]
        scorecard = self._scorecard(assets=assets)
        scores = {entry["key"]: entry["score"] for entry in scorecard["dimensions"]}
        # 10,000 of 11,000 customer events have a reference; splunkd is internal and not counted.
        self.assertEqual(scores, {
            "environment": 100,
            "reference_coverage": 91,
            "addon_coverage": 67,
            "addon_currency": 67,
            "documentation": 100,
            "knowledge_base": 25,
        })
        self.assertEqual(scorecard["overall_score"], 75)
        self.assertEqual([gap["id"] for gap in scorecard["gaps"]], [
            "addon_missing:Splunk Add-on for AWS",
            "no_reference:custom:app",
            "addon_outdated:Splunk_TA_windows",
            "app_archived:Splunk_TA_paloalto",
            "kb_uncovered",
        ])
        self.assertEqual(scorecard["gap_counts"], {"high": 1, "medium": 3, "low": 1})
        missing = scorecard["gaps"][0]
        self.assertEqual(missing["priority"], "high")
        self.assertIn("8.0.0", missing["action"])
        self.assertTrue(missing["detail"].startswith("1 sourcetype depends on it (aws:cloudtrail, 3,000 events"))
        self.assertEqual(missing["url"], "https://splunkbase.splunk.com/app/1876/")
        self.assertNotIn("splunkd", json.dumps(scorecard["gaps"]))

    def test_without_sources(self):
        empty = {name: {"available": False} for name in ("security_content", "splunkbase", "help_docs")}
        scorecard = self._scorecard(sources={}, summary=empty)
        self.assertIsNone(scorecard["overall_score"])
        self.assertEqual(scorecard["gaps"][0]["id"], "sources_missing")
        statuses = {entry["key"]: entry["status"] for entry in scorecard["dimensions"]}
        for key in ("reference_coverage", "addon_coverage", "addon_currency", "documentation"):
            self.assertEqual(statuses[key], "needs_sources", key)

    def test_without_discovery(self):
        empty = {name: {"available": False} for name in ("security_content", "splunkbase", "help_docs")}
        for blueprint in ({}, {"_artifact": {"name": "v2_intelligence_blueprint_x.json"}}):
            with self.subTest(blueprint=blueprint):
                scorecard = self._scorecard(blueprint=blueprint, sources={}, summary=empty)
                self.assertIsNone(scorecard["overall_score"])
                self.assertEqual(scorecard["dimensions"], [])
                self.assertEqual([gap["id"] for gap in scorecard["gaps"]], ["no_discovery", "sources_missing"])

    def test_discovery_from_an_older_version_asks_for_a_new_run(self):
        scorecard = self._scorecard(blueprint=make_blueprint(env=False))
        dimensions = {entry["key"]: entry for entry in scorecard["dimensions"]}
        self.assertEqual(dimensions["addon_coverage"]["status"], "needs_discovery")
        self.assertEqual(dimensions["addon_currency"]["status"], "needs_discovery")
        self.assertEqual(scorecard["gaps"][0]["id"], "apps_not_collected")

    def test_blocked_app_collection_explains_the_permission(self):
        scorecard = self._scorecard(blueprint=make_blueprint(apps_status="error", apps=[]))
        gap = scorecard["gaps"][0]
        self.assertEqual(gap["id"], "apps_failed")
        self.assertIn("permission", gap["action"])

    def test_missing_and_stale_sources_and_version_gaps(self):
        old = (datetime.now(timezone.utc) - timedelta(days=45)).replace(microsecond=0).isoformat()
        sources = library_sources()
        del sources["splunkbase"]
        summary = loaded_summary()
        summary["splunkbase"] = {"available": False}
        summary["help_docs"]["fetched_at"] = old
        scorecard = self._scorecard(blueprint=make_blueprint(version="9.6.0"), sources=sources, summary=summary)
        ids = [gap["id"] for gap in scorecard["gaps"]]
        self.assertIn("source_missing:splunkbase", ids)
        self.assertIn("source_stale:help_docs", ids)
        self.assertIn("docs_version", ids)
        dimensions = {entry["key"]: entry for entry in scorecard["dimensions"]}
        self.assertEqual(dimensions["addon_currency"]["status"], "needs_sources")
        self.assertEqual(dimensions["documentation"]["score"], 70)

    def test_cloud_stack_flags_apps_not_marked_cloud_compatible(self):
        scorecard = self._scorecard(blueprint=make_blueprint(version="10.1.2507.3", deployment="cloud"))
        self.assertIn("app_not_cloud:Splunk_SA_CIM", [gap["id"] for gap in scorecard["gaps"]])

    def test_knowledge_base_unavailable(self):
        scorecard = self._scorecard(assets=None)
        dimension = next(entry for entry in scorecard["dimensions"] if entry["key"] == "knowledge_base")
        self.assertEqual((dimension["score"], dimension["status"]), (None, "unavailable"))


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name) / "knowledge_library"
        self.service = KnowledgeLibraryService(self.root)
        self.profile = build_environment_profile(make_blueprint())

    def tearDown(self):
        self.temp_dir.cleanup()

    async def test_refresh_downloads_every_source_and_records_the_result(self):
        server = FakeSourceServer()
        snapshot = self.service.start_refresh(self.profile, transport=server.transport())
        self.assertEqual(snapshot["state"], "running")
        self.assertTrue(self.service.is_refreshing())
        self.assertEqual(self.service.start_refresh(self.profile, transport=server.transport())["started_at"], snapshot["started_at"])
        result = await self.service.wait_for_refresh()

        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["results"]["security_content"]["count"], 3)
        self.assertEqual(result["results"]["splunkbase"]["count"], 4)
        self.assertGreater(result["results"]["help_docs"]["count"], 0)
        lookups = [url for url in server.calls if "splunkbase" in url]
        self.assertTrue(any("/app/742/" in url for url in lookups))
        self.assertTrue(any("appid=TA-custom-thing" in url for url in lookups))
        self.assertFalse(any("appid=search" in url for url in lookups))

        reloaded = KnowledgeLibraryService(self.root)
        previous = reloaded.job_snapshot()
        self.assertEqual((previous["state"], previous["previous"]), ("completed", True))
        status = reloaded.build_status(make_blueprint(), [], allow_online=False, can_manage=True)
        self.assertEqual(status["scorecard"]["dimensions"][0]["key"], "environment")
        self.assertTrue(all(source["available"] for source in status["sources"]))
        self.assertEqual(status["catalog"]["app_total"], 5)

    async def test_partial_refresh_keeps_what_worked(self):
        result_snapshot = self.service.start_refresh(self.profile, transport=FakeSourceServer(sitemaps={}).transport())
        self.assertEqual(result_snapshot["state"], "running")
        result = await self.service.wait_for_refresh()
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["results"]["help_docs"]["status"], "error")
        self.assertIsNotNone(self.service.store.load_source("security_content"))
        self.assertIsNone(self.service.store.load_source("help_docs"))

    async def test_pack_import_waits_for_a_running_refresh(self):
        gate = asyncio.Event()
        self.service.start_refresh(self.profile, transport=FakeSourceServer(gate=gate).transport())
        await asyncio.sleep(0)
        with self.assertRaises(LibraryBusyError):
            self.service.import_pack(b"anything")
        gate.set()
        await self.service.wait_for_refresh()

    async def test_automatic_refresh_rules(self):
        now = datetime.now(timezone.utc)
        with mock.patch.object(self.service, "start_refresh") as start:
            self.assertIsNone(self.service.maybe_auto_refresh(self.profile, False, [], now=now))
            self.assertEqual(self.service.maybe_auto_refresh(self.profile, True, [], now=now), "scheduled")
            self.assertEqual(start.call_args.kwargs, {"sources": None, "reason": "scheduled"})
            # A failed attempt is not retried for an hour.
            self.assertIsNone(self.service.maybe_auto_refresh(self.profile, True, [], now=now + timedelta(minutes=30)))

            for name, payload in library_sources(now.replace(microsecond=0).isoformat()).items():
                self.service.store.save_source(name, payload)
            later = now + timedelta(minutes=61)
            self.assertIsNone(self.service.maybe_auto_refresh(self.profile, True, [], now=later))
            self.assertEqual(self.service.maybe_auto_refresh(self.profile, True, ["TA-brand-new"], now=later), "apps")
            self.assertEqual(start.call_args.kwargs, {"sources": ["splunkbase"], "reason": "apps"})
            self.assertEqual(self.service.maybe_auto_refresh(self.profile, True, [], now=later + timedelta(days=8)), "scheduled")

    async def test_app_lookup_refresh_only_asks_about_new_apps(self):
        for name, payload in library_sources().items():
            self.service.store.save_source(name, payload)
        server = FakeSourceServer()
        profile = build_environment_profile(make_blueprint(apps=[*DEFAULT_APPS, {"name": "TA-brand-new", "version": "1.0"}]))
        self.service.start_refresh(profile, sources=["splunkbase"], reason="apps", transport=server.transport())
        result = await self.service.wait_for_refresh()
        self.assertEqual(result["state"], "completed")
        self.assertEqual([url for url in server.calls], ["https://splunkbase.splunk.com/api/v1/app/?appid=TA-brand-new&include=releases"])
        self.assertIn("ta-brand-new", self.service.store.load_source("splunkbase")["not_found"])
        self.assertIn("splunk_ta_windows", self.service.store.load_source("splunkbase")["apps"])


class LibrarySettingsTests(unittest.TestCase):
    def test_online_sources_are_off_until_turned_on(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = str(Path(temp_dir) / "config.encrypted")
            manager = ConfigManager(path)
            self.assertFalse(manager.get().library.allow_online_sources)
            self.assertTrue(manager.update_library(allow_online_sources=True))
            self.assertTrue(ConfigManager(path).get().library.allow_online_sources)


class LibraryIndexerTests(unittest.TestCase):
    def test_library_sources_are_not_indexed_as_discovery_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_dir = temp_path / "output"
            (output_dir / "knowledge_library" / "sources").mkdir(parents=True)
            (output_dir / "knowledge_library" / "sources" / "help_docs.json").write_text(json.dumps({"marker": "library-source-marker"}), encoding="utf-8")
            (output_dir / "v2_operator_runbook_test.md").write_text(
                "## Queue Pressure\n\nOperators should validate queue pressure and ingestion delays in _internal before escalating.",
                encoding="utf-8",
            )
            original_cwd = Path.cwd()
            try:
                os.chdir(temp_path)
                manager = CapabilityManager(ConfigManager(str(temp_path / "config.encrypted")), registry=CapabilityRegistry())
                manager.update_capability_config("rag_chromadb", {"source_dir": str(output_dir), "storage_dir": str(output_dir / "rag" / "chromadb")})
                indexer = ArtifactSourceIndexer(
                    config=manager.config_manager.get_capability("rag_chromadb"),
                    definition=manager.registry.get_definition("rag_chromadb"),
                )
                documents = indexer.collect_documents()
                with mock.patch.object(indexer_module, "LIBRARY_DIR_NAME", "not-the-library-folder"):
                    unfiltered = indexer.collect_documents()
            finally:
                os.chdir(original_cwd)
        self.assertTrue(documents)
        self.assertFalse(any("library-source-marker" in document.content for document in documents))
        self.assertTrue(any("library-source-marker" in document.content for document in unfiltered))


class KnowledgeLibraryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.temp_path = Path(self.temp_dir.name)
        self.original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.security_manager = SecurityManager(str(self.temp_path / "security.db"))
        self.originals = (web_app.config_manager, web_app.capability_manager, web_app.security_manager, web_app.knowledge_library_service)
        web_app.config_manager = self.config_manager
        web_app.capability_manager = CapabilityManager(self.config_manager, registry=web_app.capability_registry)
        web_app.security_manager = self.security_manager
        web_app.knowledge_library_service = KnowledgeLibraryService(self.temp_path / "output" / "knowledge_library")
        self.client = TestClient(web_app.app)

    def tearDown(self):
        self.client.close()
        web_app.config_manager, web_app.capability_manager, web_app.security_manager, web_app.knowledge_library_service = self.originals
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def _pack(self):
        store = LibraryStore(self.temp_path / "pack-source")
        for name, payload in library_sources().items():
            store.save_source(name, payload)
        return export_pack(store)

    def _write_discovery(self, blueprint):
        timestamp = "20260501_120000"
        name = f"v2_intelligence_blueprint_{timestamp}.json"
        (web_app._discovery_scope_output_dir(None) / name).write_text(json.dumps(blueprint), encoding="utf-8")
        web_app.register_discovery_session(
            timestamp=timestamp,
            overview=mock.Mock(total_indexes=2, total_sourcetypes=5, total_hosts=1, total_users=1, data_volume_24h="1 GB", splunk_version="9.4.2"),
            report_paths=[name],
            mcp_capabilities={},
            classifications={},
            recommendations=[],
            suggested_use_cases=[],
            discovery_step_count=0,
        )

    def test_status_before_discovery_and_sources(self):
        response = self.client.get("/api/knowledge-library/status")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body["profile"]["available"])
        self.assertFalse(body["settings"]["allow_online_sources"])
        self.assertIn("help.splunk.com", body["settings"]["online_hosts"])
        self.assertTrue(body["can_manage"])
        self.assertEqual([gap["id"] for gap in body["scorecard"]["gaps"]], ["no_discovery", "sources_missing"])
        self.assertEqual([source["available"] for source in body["sources"]], [False, False, False])
        self.assertIsNone(body["refresh"]["auto_started"])
        self.assertIsNone(body["catalog"])

    def test_refresh_is_refused_while_online_sources_are_off(self):
        response = self.client.post("/api/knowledge-library/refresh")
        self.assertEqual(response.status_code, 409)
        self.assertIn("turned off", response.json()["detail"])

    def test_turning_on_online_sources_saves_and_starts_the_first_download(self):
        with mock.patch.object(web_app.knowledge_library_service, "start_refresh", return_value={}) as start:
            response = self.client.post("/api/knowledge-library/settings", json={"allow_online_sources": True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["settings"]["allow_online_sources"])
        self.assertEqual(response.json()["refresh"]["auto_started"], "scheduled")
        self.assertTrue(ConfigManager(str(self.temp_path / "config.encrypted")).get().library.allow_online_sources)
        start.assert_called_once()

        with mock.patch.object(web_app.knowledge_library_service, "start_refresh", return_value={}) as start:
            response = self.client.post("/api/knowledge-library/refresh")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(start.call_args.kwargs, {"sources": None, "reason": "manual"})

        with mock.patch.object(web_app.knowledge_library_service, "start_refresh", return_value={}) as start:
            response = self.client.post("/api/knowledge-library/refresh", json={"sources": ["docs"]})
        self.assertEqual(response.status_code, 200, response.text)
        # The help.splunk.com page list is not loaded yet, so downloading documentation loads it first.
        self.assertEqual(start.call_args.kwargs, {"sources": ["help_docs", "docs"], "reason": "manual"})

        with mock.patch.object(web_app.knowledge_library_service, "start_refresh", return_value={}) as start:
            response = self.client.post("/api/knowledge-library/refresh", json={"sources": ["everything"]})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("Choose at least one", response.json()["detail"])
        start.assert_not_called()
    def test_pack_import_scores_the_latest_discovery_and_exports_again(self):
        self._write_discovery(make_blueprint())
        self.assertEqual(self.client.get("/api/knowledge-library/pack/export").status_code, 404)

        response = self.client.post(
            "/api/knowledge-library/pack/import",
            files={"file": ("library.zip", self._pack(), "application/zip")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["import_result"]["imported"], ["help_docs", "security_content", "splunkbase"])
        self.assertTrue(body["profile"]["available"])
        self.assertEqual(body["profile"]["apps"], {"collected": True, "status": "ok", "error": "", "total": 5, "addons": 4})
        self.assertEqual(body["profile"]["splunk"]["deployment_type"], "enterprise")
        self.assertEqual(body["scorecard"]["gaps"][0]["id"], "addon_missing:Splunk Add-on for AWS")
        self.assertEqual({source["origin"] for source in body["sources"]}, {"pack"})
        self.assertEqual(body["catalog"]["platform_docs"]["doc_version"], "9.4")

        export = self.client.get("/api/knowledge-library/pack/export")
        self.assertEqual(export.status_code, 200)
        self.assertEqual(export.headers["content-type"], "application/zip")
        self.assertIn("dt4sms_library_pack_", export.headers["content-disposition"])
        with zipfile.ZipFile(io.BytesIO(export.content)) as archive:
            self.assertIn(sources_module.PACK_MANIFEST_NAME, archive.namelist())

    def test_bad_pack_upload_is_rejected(self):
        response = self.client.post("/api/knowledge-library/pack/import", files={"file": ("notes.zip", b"not a zip", "application/zip")})
        self.assertEqual(response.status_code, 400)
        self.assertIn("not a library pack", response.json()["detail"])

    def test_only_admins_can_change_library_sources(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))
        password = "Analyst-Library-Check-2026"
        self.security_manager.create_user(username="analyst-one", password=password, role="analyst", require_password_reset=False)
        login = self.client.post("/api/auth/login", json={"username": "analyst-one", "password": password})
        self.assertEqual(login.status_code, 200, login.text)

        status = self.client.get("/api/knowledge-library/status")
        self.assertEqual(status.status_code, 200, status.text)
        self.assertFalse(status.json()["can_manage"])
        self.assertEqual(self.client.post("/api/knowledge-library/settings", json={"allow_online_sources": True}).status_code, 403)
        self.assertEqual(self.client.post("/api/knowledge-library/refresh").status_code, 403)
        upload = self.client.post("/api/knowledge-library/pack/import", files={"file": ("library.zip", self._pack(), "application/zip")})
        self.assertEqual(upload.status_code, 403)
        self.assertFalse(self.config_manager.get().library.allow_online_sources)


    def _pack_with_docs(self):
        service = KnowledgeLibraryService(self.temp_path / "pack-source-docs")
        for name, payload in library_sources().items():
            service.store.save_source(name, payload)
        fill_doc_index(service.docs)
        return service.export_pack()

    def test_pack_with_documentation_fills_the_searchable_library(self):
        self._write_discovery(make_blueprint())
        response = self.client.post(
            "/api/knowledge-library/pack/import",
            files={"file": ("library.zip", self._pack_with_docs(), "application/zip")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["import_result"]["imported"], ["help_docs", "security_content", "splunkbase", "docs"])
        self.assertEqual(body["import_result"]["docs_pages"], 7)
        self.assertEqual(body["docs"]["coverage"]["pct"], 100)
        self.assertEqual(body["docs"]["summary"]["groups"][0]["origin"], "pack")
        dimension = next(entry for entry in body["scorecard"]["dimensions"] if entry["key"] == "doc_text")
        self.assertEqual(dimension["score"], 100)

    def test_documentation_search_endpoint(self):
        self.assertEqual(self.client.post("/api/knowledge-library/search", json={"query": "   "}).status_code, 400)
        empty = self.client.post("/api/knowledge-library/search", json={"query": "replication factor"})
        self.assertEqual(empty.status_code, 200, empty.text)
        self.assertEqual((empty.json()["results"], empty.json()["docs_available"]), ([], False))

        self._write_discovery(make_blueprint())
        fill_doc_index(web_app.knowledge_library_service.docs)
        response = self.client.post("/api/knowledge-library/search", json={"query": "How does the manager node enforce the replication factor?", "limit": 3})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["docs_available"])
        top = body["results"][0]
        self.assertEqual(top["url"], HELP + "splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.4/overview/about")
        self.assertEqual(top["group"], "Splunk Enterprise 9.4")
        self.assertIn("replication", top["matched_terms"])
        self.assertNotIn("context", top)
        self.assertTrue(top["why"])
        self.assertLessEqual(len(body["results"]), 3)

    def test_context_preview_shows_documentation_while_the_knowledge_base_is_not_ready(self):
        fill_doc_index(web_app.knowledge_library_service.docs)
        response = self.client.post("/api/capabilities/rag/context/build", json={"query": "where do props.conf settings live", "limit": 4})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["ok"])
        matches = body["details"]["library_matches"]
        self.assertEqual(matches[0]["url"], HELP + "splunk-enterprise/administer/admin-manual/9.4/configuration-files/about")
        self.assertNotIn("context", matches[0])
        self.assertIn("not ready", body["details"]["message"])

    def test_chat_context_adds_matching_documentation_only(self):
        self._write_discovery(make_blueprint())
        fill_doc_index(web_app.knowledge_library_service.docs)
        with mock.patch.object(web_app.capability_manager, "get_rag_context", return_value={}):
            context_text, usage = web_app.get_optional_rag_context("How do I change parsing for the WinEventLog:Security sourcetype in props.conf?")
            unrelated_text, unrelated_usage = web_app.get_optional_rag_context("Show failed logins for user bob over the last hour")
        self.assertIn("SPLUNK DOCUMENTATION", context_text)
        self.assertIn(HELP + "splunk-enterprise/administer/admin-manual/9.4/configuration-files/about", context_text)
        self.assertIn("Edit props.conf", context_text)
        self.assertEqual([entry["name"] for entry in usage], ["knowledge_library_docs"])
        chunk = usage[0]["chunks"][0]
        self.assertEqual(chunk["source_type"], "splunk_docs")
        self.assertTrue(chunk["url"].startswith(HELP))
        self.assertIn("Mentions your sourcetype wineventlog:security", chunk["why"])
        self.assertEqual((unrelated_text, unrelated_usage), ("", []))


class DocTextTests(unittest.TestCase):
    def test_page_text_comes_from_the_article_only(self):
        html = (
            '<html><head><title>Configure inputs | Splunk Docs</title><meta name="lastModifiedISO" content="2026-03-04T05:06:07Z">'
            "<style>.hidden{}</style></head><body><header>Header links</header><nav>Product menu</nav>"
            "<main><article><h1>Configure inputs</h1><p>Inputs bring data into Splunk.</p>"
            "<h2>Monitor files</h2><p>Use the <code>monitor</code> stanza.</p>"
            "<pre>[monitor:///var/log]\nindex = main\n</pre>"
            "<ul><li>First item</li><li>Second item</li></ul>"
            "<table><tr><th>Setting</th><th>Default</th></tr><tr><td>index</td><td>default</td></tr></table>"
            "<aside>Related topics</aside><button>Copy code</button><script>track()</script>"
            "</article></main><footer>Legal notice</footer></body></html>"
        )
        parsed = extract_doc_page(html)
        self.assertEqual((parsed["title"], parsed["lastmod"]), ("Configure inputs", "2026-03-04T05:06:07Z"))
        self.assertEqual([(section["heading"], section["lines"]) for section in parsed["sections"]], [
            ("Configure inputs", ["Inputs bring data into Splunk."]),
            ("Monitor files", [
                "Use the monitor stanza.",
                "```\n[monitor:///var/log]\nindex = main\n```",
                "- First item",
                "- Second item",
                "Setting | Default",
                "index | default",
            ]),
        ])
        flat = json.dumps(parsed)
        for hidden in ("Header links", "Product menu", "Related topics", "Copy code", "track()", "Legal notice", ".hidden"):
            self.assertNotIn(hidden, flat)

    def test_pages_without_a_main_element_use_the_body(self):
        parsed = extract_doc_page("<html><head><title>Plain page | Splunk Docs</title></head><body><nav>Skip</nav><p>Body text only.</p></body></html>")
        self.assertEqual(parsed["title"], "Plain page")
        self.assertEqual([(section["heading"], section["lines"]) for section in parsed["sections"]], [("", ["Body text only."])])

    def test_long_sections_split_under_their_heading(self):
        long_text = " ".join(f"Sentence {number} explains the setting." for number in range(400))
        chunks = chunk_page("Guide", [{"heading": "Details", "lines": [long_text]}])
        self.assertGreater(len(chunks), 3)
        self.assertTrue(all(heading == "Details" for heading, _ in chunks))
        self.assertTrue(all(len(body) <= CHUNK_MAX_CHARS for _, body in chunks))
        self.assertTrue(chunks[0][1].startswith("Sentence 0 "))
        self.assertTrue(chunks[-1][1].endswith("Sentence 399 explains the setting."))

    def test_small_sections_join_the_previous_chunk_and_the_title_heading_is_dropped(self):
        chunks = chunk_page("Guide", [
            {"heading": "Guide", "lines": ["A" * 300]},
            {"heading": "Note", "lines": ["Short note."]},
        ])
        self.assertEqual(chunks, [("", "A" * 300 + "\nNote\nShort note.")])


class DocPlanTests(unittest.TestCase):
    def test_plan_follows_the_platform_version_and_installed_apps(self):
        plan = default_doc_plan()
        self.assertEqual(plan["status"], "ok")
        self.assertEqual([manual["key"] for manual in plan["manuals"]], [
            "splunk-enterprise/administer/admin-manual/9.4",
            "splunk-enterprise/administer/distributed-search/9.4",
            "splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.4",
            "splunk-enterprise/search/spl-search-reference/9.4",
            "splunk-enterprise/common-information-model/6.0",
            "supported-add-ons/splunk-supported-add-ons/microsoft-windows/current",
        ])
        self.assertEqual(plan["page_total"], 7)
        self.assertEqual([(group["label"], group["manuals"], group["pages"]) for group in plan["groups"]], [
            ("Splunk Enterprise 9.4", 4, 5),
            ("Common Information Model 6.0", 1, 1),
            ("Supported add-on overviews", 1, 1),
        ])
        self.assertEqual(plan["platform"]["doc_version"], "9.4")

    def test_cloud_stacks_get_cloud_manuals(self):
        plan = default_doc_plan(make_blueprint(version="10.1.2507.3", deployment="cloud"))
        self.assertEqual([manual["key"] for manual in plan["manuals"]][:2], [
            "splunk-cloud-platform/administer/admin-manual/10.1.2507",
            "splunk-cloud-platform/search/spl-search-reference/10.1.2507",
        ])

    def test_duplicate_manual_paths_and_pdf_exports_are_skipped(self):
        pages = [
            "splunk-enterprise/search/spl-search-reference/9.4/introduction/welcome",
            "splunk-enterprise/search/spl-search-reference/9.4/commands/stats",
            "splunk-enterprise/spl-search-reference/9.4/introduction/welcome",
            "splunk-enterprise/spl-search-reference/9.4/commands/stats",
            "splunk-enterprise/administer/install-and-upgrade/9.4/overview/install",
            "splunk-enterprise/administer/install-and-upgrade/9.4/overview/upgrade",
            "splunk-enterprise/administer/install-and-upgrade/9.4/splunk_installation.pdf",
            "splunk-enterprise/get-started/install-and-upgrade/9.4/overview/install",
            "splunk-enterprise/get-started/install-and-upgrade/9.4/overview/upgrade",
            "splunk-enterprise/get-started/install-and-upgrade/9.4/splunk_installation.pdf",
            "splunk-enterprise/get-started/overview/9.4",
            "splunk-enterprise/translated-documentation/9.4",
            "splunk-enterprise/administer/admin_guide.pdf/9.4",
        ]
        help_docs = {"products": {"splunk-enterprise": build_docs_product_index("splunk-enterprise", [(HELP + page, "2026-02-01") for page in pages])}}
        plan = build_doc_plan(build_environment_profile(make_blueprint(apps=[])), help_docs)
        self.assertEqual([manual["key"] for manual in plan["manuals"]], [
            "splunk-enterprise/administer/install-and-upgrade/9.4",
            "splunk-enterprise/get-started/overview/9.4",
            "splunk-enterprise/search/spl-search-reference/9.4",
            "splunk-enterprise/translated-documentation/9.4",
        ])
        self.assertEqual(plan["manuals"][0]["pages"], ["overview/install", "overview/upgrade"])
        self.assertEqual(plan["page_total"], 6)

    def test_plan_needs_discovery_and_the_doc_index(self):
        help_docs = library_sources()["help_docs"]
        self.assertEqual(build_doc_plan(build_environment_profile(None), help_docs)["status"], "needs_discovery")
        self.assertEqual(build_doc_plan(build_environment_profile(make_blueprint()), None)["status"], "needs_source")

    def test_platform_manuals_come_first_within_the_page_budget(self):
        with mock.patch.object(docs_module, "MAX_DOC_PAGES", 3):
            plan = default_doc_plan()
        self.assertEqual([manual["key"] for manual in plan["manuals"]], [
            "splunk-enterprise/administer/admin-manual/9.4",
            "splunk-enterprise/administer/distributed-search/9.4",
        ])
        self.assertEqual(plan["page_total"], 3)

    def test_coverage_and_signature_track_changes(self):
        plan = default_doc_plan()
        empty = plan_coverage(plan, {})
        self.assertEqual((empty["pct"], empty["missing_manuals"], empty["planned_pages"]), (0, 6, 7))
        states = {
            manual["key"]: {"complete": 1, "lastmod": manual["lastmod"], "page_total": len(manual["pages"]), "page_done": len(manual["pages"])}
            for manual in plan["manuals"]
        }
        full = plan_coverage(plan, states)
        self.assertEqual((full["pct"], full["current_manuals"], full["outdated_manuals"]), (100, 6, 0))
        self.assertEqual(full["groups"][0], {"label": "Splunk Enterprise 9.4", "manuals": 4, "pages": 5, "downloaded_pages": 5})
        first = plan["manuals"][0]
        self.assertFalse(needs_fetch(first, states[first["key"]]))
        states[first["key"]]["lastmod"] = "2025-01-01"
        self.assertTrue(needs_fetch(first, states[first["key"]]))
        self.assertEqual(plan_coverage(plan, states)["outdated_manuals"], 1)

        changed = copy.deepcopy(plan)
        self.assertEqual(plan_signature(changed), plan_signature(plan))
        changed["manuals"][0]["lastmod"] = "2026-04-01"
        self.assertNotEqual(plan_signature(changed), plan_signature(plan))

    def test_coverage_lists_each_manual_with_its_download_state(self):
        plan = default_doc_plan()
        first, second, third = plan["manuals"][:3]
        states = {
            first["key"]: {"complete": 1, "lastmod": first["lastmod"], "page_total": len(first["pages"]), "page_done": len(first["pages"])},
            second["key"]: {"complete": 0, "lastmod": second["lastmod"], "page_total": len(second["pages"]), "page_done": 1},
            third["key"]: {"complete": 1, "lastmod": "2025-01-01", "page_total": len(third["pages"]), "page_done": len(third["pages"])},
        }
        manuals = plan_coverage(plan, states)["manuals"]
        self.assertEqual([manual["key"] for manual in manuals], [manual["key"] for manual in plan["manuals"]])
        self.assertEqual([manual["status"] for manual in manuals], ["downloaded", "partial", "changed", "missing", "missing", "missing"])
        self.assertEqual(manuals[0], {
            "key": "splunk-enterprise/administer/admin-manual/9.4",
            "title": first["title"],
            "group": "Splunk Enterprise 9.4",
            "reason": first["reason"],
            "version": "9.4",
            "pages": len(first["pages"]),
            "downloaded_pages": len(first["pages"]),
            "status": "downloaded",
            "url": f"{HELP}splunk-enterprise/administer/admin-manual/9.4/{first['pages'][0]}",
        })
        self.assertEqual((manuals[1]["downloaded_pages"], manuals[3]["downloaded_pages"]), (1, 0))
        # A manual that gained pages on the site after a complete download still has pages to fetch.
        grown = copy.deepcopy(plan)
        grown["manuals"][0]["pages"] = [*first["pages"], "new/page"]
        self.assertEqual(plan_coverage(grown, states)["manuals"][0]["status"], "partial")
        self.assertEqual(manuals[-1]["group"], "Supported add-on overviews")
        with mock.patch.object(docs_module, "MAX_STATUS_MANUALS", 2):
            self.assertEqual(len(plan_coverage(plan, states)["manuals"]), 2)

class DocIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_search_with_and_without_fts5(self):
        engines = [True, False] if fts5_available() else [False]
        for use_fts in engines:
            with self.subTest(use_fts=use_fts):
                index = DocIndex(self.root / f"docs-{use_fts}.sqlite3", use_fts=use_fts)
                fill_doc_index(index)
                summary = index.summary()
                self.assertTrue(summary["available"])
                self.assertEqual((summary["manuals"], summary["pages"], summary["search_engine"]), (6, 7, "fts5" if use_fts else "python"))
                self.assertGreater(summary["size_bytes"], 0)
                query = "where do props.conf settings live"
                results = rank_doc_results(query, index.search_candidates(query_terms(query)))
                top = results[0]
                self.assertEqual(top["url"], HELP + "splunk-enterprise/administer/admin-manual/9.4/configuration-files/about")
                self.assertEqual(top["title"], "About configuration files")
                self.assertEqual(top["kind"], "splunk_docs")
                self.assertEqual(top["matched_terms"], ["props", "conf", "settings", "live"])
                self.assertIn("Title or heading match", top["why"])
                self.assertIn("props.conf", top["context"])
                self.assertTrue(1 <= top["score"] <= 100)
                self.assertEqual(index.search_candidates(["it's"]), [])

    @unittest.skipUnless(fts5_available(), "SQLite was built without FTS5")
    def test_text_saved_without_fts5_is_indexed_when_fts5_is_used(self):
        path = self.root / "docs.sqlite3"
        fill_doc_index(DocIndex(path, use_fts=False))
        rows = DocIndex(path, use_fts=True).search_candidates(["replication"])
        self.assertEqual([row["title"] for row in rows], ["About indexer clusters"])

    def test_removed_manuals_leave_the_index(self):
        index = DocIndex(self.root / "docs.sqlite3")
        plan = fill_doc_index(index)
        self.assertEqual(index.remove_manuals([plan["manuals"][2]["key"]]), 1)
        self.assertEqual(index.search_candidates(["replication"]), [])
        self.assertEqual(index.summary()["pages"], 6)


class DocSyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.index = DocIndex(Path(self.temp_dir.name) / "docs.sqlite3")
        self.plan = default_doc_plan()

    def tearDown(self):
        self.temp_dir.cleanup()

    async def _sync(self, server, plan=None, progress=None):
        async with create_library_http_client(server.transport()) as client:
            return await sync_docs(client, self.index, plan or self.plan, progress)

    async def test_sync_downloads_once_then_only_what_changed(self):
        server = FakeSourceServer()
        progress = []
        first = await self._sync(server, progress=lambda *update: progress.append(update))
        self.assertEqual((first["manuals_updated"], first["pages_fetched"], first["pages_failed"]), (6, 7, 0))
        expected = sorted(doc_page_path(manual, page) for manual in self.plan["manuals"] for page in manual["pages"])
        self.assertEqual(sorted(server.page_fetches), expected)
        self.assertEqual((progress[0], progress[-1]), (("docs", 0, 7), ("docs", 7, 7)))

        server.page_fetches.clear()
        second = await self._sync(server)
        self.assertEqual((second["manuals_updated"], second["manuals_current"], server.page_fetches), (0, 6, []))

        changed = copy.deepcopy(self.plan)
        admin = changed["manuals"][0]
        admin["lastmod"] = "2026-04-01"
        third = await self._sync(server, changed)
        self.assertEqual(third["manuals_updated"], 1)
        self.assertEqual(sorted(server.page_fetches), [doc_page_path(admin, page) for page in admin["pages"]])
        self.assertEqual(self.index.manual_states()[admin["key"]]["lastmod"], "2026-04-01")

        smaller = {**changed, "manuals": changed["manuals"][1:]}
        fourth = await self._sync(server, smaller)
        self.assertEqual(fourth["manuals_removed"], 1)
        self.assertNotIn(admin["key"], self.index.manual_states())
        self.assertEqual(self.index.search_candidates(["props"]), [])

    async def test_missing_and_non_html_pages_are_counted(self):
        admin, cim = self.plan["manuals"][0], self.plan["manuals"][4]
        server = FakeSourceServer(missing_pages={doc_page_path(admin, admin["pages"][1])}, pdf_pages={doc_page_path(cim, cim["pages"][0])})
        result = await self._sync(server)
        self.assertEqual((result["pages_fetched"], result["pages_failed"], result["manuals_updated"]), (5, 2, 5))
        self.assertEqual(len(result["errors"]), 2)
        self.assertTrue(any("not an HTML page (application/pdf)" in error for error in result["errors"]))
        states = self.index.manual_states()
        self.assertEqual((states[admin["key"]]["page_done"], states[admin["key"]]["page_failed"]), (1, 1))
        self.assertNotIn(cim["key"], states)
        self.assertEqual(plan_coverage(self.plan, states)["pct"], 71)

    async def test_a_failed_download_keeps_the_previous_text(self):
        await self._sync(FakeSourceServer())
        changed = copy.deepcopy(self.plan)
        admin = changed["manuals"][0]
        admin["lastmod"] = "2026-04-01"
        server = FakeSourceServer(missing_pages={doc_page_path(admin, page) for page in admin["pages"]})
        with self.assertRaisesRegex(LibrarySourceError, "Could not download documentation pages"):
            await self._sync(server, changed)
        state = self.index.manual_states()[admin["key"]]
        self.assertEqual((state["page_done"], state["lastmod"]), (2, "2026-02-01"))
        self.assertTrue(needs_fetch(admin, state))
        self.assertTrue(self.index.search_candidates(["props"]))

    async def test_downloads_stop_when_the_site_refuses_them(self):
        server = FakeSourceServer(refuse_after=1)
        with self.assertRaisesRegex(LibrarySourceError, r"stopped allowing documentation downloads .*HTTP 403.*1 downloaded page was saved"):
            await self._sync(server)
        self.assertEqual(len(server.page_fetches) + len(server.refused_pages), 1 + docs_module.DOC_REFUSAL_LIMIT)
        states = self.index.manual_states()
        self.assertEqual(list(states), [self.plan["manuals"][0]["key"]])
        self.assertEqual((states[self.plan["manuals"][0]["key"]]["page_done"], states[self.plan["manuals"][0]["key"]]["complete"]), (1, 0))

        later = FakeSourceServer()
        result = await self._sync(later)
        self.assertEqual((result["manuals_updated"], result["pages_fetched"]), (6, 7))

    async def test_an_empty_plan_is_refused(self):
        with self.assertRaises(LibrarySourceError):
            await self._sync(FakeSourceServer(), {"manuals": []})


class RankingTests(unittest.TestCase):
    def test_bm25_and_rank_fusion(self):
        index = BM25([["stats", "count"], ["eval", "field"], ["stats", "stats", "sum"]])
        self.assertEqual([position for position, _ in index.top(["stats"], 5)], [2, 0])
        self.assertEqual(index.scores(["missing"]), {})
        fused = reciprocal_rank_fusion([(["a", "b"], 1.0), (["b", "a"], 2.0)])
        self.assertGreater(fused["b"], fused["a"])

    def test_environment_names_skip_generic_words(self):
        terms = EnvironmentTerms(sourcetypes=["pan:traffic", "csv"], indexes=["main", "firewall"], apps=["Splunk_TA_windows"])
        self.assertEqual([(kind, name) for kind, name, _ in terms.entities], [
            ("sourcetype", "pan:traffic"), ("index", "firewall"), ("app", "splunk_ta_windows"),
        ])
        self.assertEqual(terms.mentioned_in("Parse PAN:traffic in the firewall index"), [("sourcetype", "pan:traffic"), ("index", "firewall")])
        self.assertEqual(terms.mentioned_in("pan:traffic_extra and firewalls"), [])
        self.assertEqual(query_terms("How do I use the stats command?"), ["stats", "command"])

    def _candidate(self, chunk_id, body, lexical):
        return {
            "chunk_id": chunk_id, "page_id": chunk_id, "title": "Props", "heading": "", "body": body, "url": f"{HELP}page-{chunk_id}",
            "product": "splunk-enterprise", "version": "9.4", "manual_title": "Admin Manual", "grp": "Splunk Enterprise 9.4", "lexical": lexical,
        }

    def test_results_about_the_users_data_rank_higher(self):
        candidates = [
            self._candidate(1, "Configure props.conf for the pan:threat sourcetype and traffic logs.", 9.0),
            self._candidate(2, "Configure props.conf for the pan:traffic sourcetype.", 8.0),
        ]
        query = "configure props for pan:traffic"
        plain = rank_doc_results(query, candidates)
        self.assertEqual(plain[0]["url"], f"{HELP}page-1")
        boosted = rank_doc_results(query, candidates, EnvironmentTerms(sourcetypes=["pan:traffic"]))
        self.assertEqual(boosted[0]["url"], f"{HELP}page-2")
        self.assertIn("Mentions your sourcetype pan:traffic", boosted[0]["why"])
        self.assertIn("Splunk Enterprise 9.4 documentation", boosted[0]["why"])

    def test_weak_matches_can_be_filtered_and_pages_are_capped(self):
        candidates = [
            self._candidate(1, "The stats command counts events.", 5.0),
            {**self._candidate(2, "The stats command sums values.", 4.0), "page_id": 1},
            {**self._candidate(3, "The stats command averages values.", 3.0), "page_id": 1},
            self._candidate(4, "Unrelated text about lookups.", 1.0),
        ]
        results = rank_doc_results("stats command lookups", candidates, limit=10, per_page=2)
        self.assertEqual([result["id"] for result in results].count("doc:3"), 0)
        filtered = rank_doc_results("stats command lookups", candidates, limit=10, min_coverage=0.6)
        self.assertEqual({result["id"] for result in filtered}, {"doc:1", "doc:2"})
        self.assertEqual(rank_doc_results("the and of", candidates), [])


class DocPackTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _service(self, name):
        return KnowledgeLibraryService(self.root / name)

    def test_documentation_travels_in_the_pack_and_is_not_downloaded_again(self):
        source = self._service("source")
        for name, payload in library_sources().items():
            source.store.save_source(name, payload)
        plan = fill_doc_index(source.docs)
        data = source.export_pack()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertIn(sources_module.PACK_DOCS_MEMBER, archive.namelist())
            manifest = json.loads(archive.read(sources_module.PACK_MANIFEST_NAME))
        self.assertEqual((manifest["docs"]["manuals"], manifest["docs"]["pages"]), (6, 7))

        target = self._service("target")
        result = target.import_pack(data)
        self.assertEqual(result["imported"], ["help_docs", "security_content", "splunkbase", "docs"])
        self.assertEqual(result["docs_pages"], 7)
        states = target.docs.manual_states()
        self.assertTrue(all(not needs_fetch(manual, states.get(manual["key"])) for manual in plan["manuals"]))
        self.assertEqual({row["origin"] for row in states.values()}, {"pack"})
        top = target.search_docs("indexer cluster replication factor")[0]
        self.assertEqual(top["url"], HELP + "splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.4/overview/about")

    def test_imported_documentation_is_rebuilt_from_known_fields(self):
        key = "splunk-enterprise/administer/admin-manual/9.4"
        payload = {
            "manuals": [
                {"product": "splunk-enterprise", "manual": "administer/admin-manual", "version": "9.4", "title": "Admin Manual", "page_total": 99999, "complete": True},
                {"product": "evil-product", "manual": "x", "version": ""},
                {"product": "splunk-enterprise", "manual": "../escape", "version": "9.4"},
            ],
            "pages": [
                {"manual_key": key, "page": "configuration-files/about", "url": "https://attacker.example/", "title": "About",
                 "chunks": [["Heading", "Body text"], ["only one"], [1, "number heading"], ["Blank", "   "]]},
                {"manual_key": key, "page": "../../etc", "chunks": [["h", "b"]]},
                {"manual_key": "evil-product/x/current", "page": "a", "chunks": [["h", "b"]]},
                "not a page",
            ],
        }
        manuals, pages = sanitize_docs_payload(payload)
        self.assertEqual([manual["manual_key"] for manual in manuals], [key])
        self.assertEqual((manuals[0]["page_total"], manuals[0]["page_failed"]), (1, 0))
        self.assertEqual(pages[key][0]["url"], HELP + "splunk-enterprise/administer/admin-manual/9.4/configuration-files/about")
        self.assertEqual(pages[key][0]["chunks"], [("Heading", "Body text")])
        self.assertIsNone(sanitize_docs_payload({"manuals": "x", "pages": []}))
        self.assertIsNone(sanitize_docs_payload({"manuals": payload["manuals"], "pages": []}))

    def test_unusable_documentation_is_skipped_but_sources_import(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(sources_module.PACK_MANIFEST_NAME, json.dumps({"format": sources_module.PACK_FORMAT, "format_version": 1}))
            archive.writestr("sources/splunkbase.json", json.dumps(library_sources()["splunkbase"]))
            archive.writestr(sources_module.PACK_DOCS_MEMBER, json.dumps({"manuals": [], "pages": []}))
        target = self._service("target")
        result = target.import_pack(buffer.getvalue())
        self.assertEqual((result["imported"], result["skipped"], result["docs_pages"]), (["splunkbase"], ["docs"], 0))
        self.assertFalse(target.docs_available())


class DocServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = KnowledgeLibraryService(Path(self.temp_dir.name) / "knowledge_library")
        self.profile = build_environment_profile(make_blueprint())

    def tearDown(self):
        self.temp_dir.cleanup()

    def _save_sources(self, stamp=None):
        for name, payload in library_sources(stamp).items():
            self.service.store.save_source(name, payload)

    async def test_refresh_downloads_documentation_and_reports_coverage(self):
        server = FakeSourceServer()
        self.service.start_refresh(self.profile, transport=server.transport())
        result = await self.service.wait_for_refresh()
        self.assertEqual(result["state"], "completed")
        docs = result["results"]["docs"]
        self.assertEqual((docs["status"], docs["count"], docs["manuals_updated"]), ("ok", 7, 6))

        status = self.service.build_status(make_blueprint(), [], allow_online=False, can_manage=True)
        self.assertEqual(status["docs"]["plan_status"], "ok")
        self.assertEqual(status["docs"]["coverage"]["pct"], 100)
        self.assertEqual(status["docs"]["summary"]["pages"], 7)
        self.assertEqual(status["docs"]["addon_overviews"], 1)
        dimension = next(entry for entry in status["scorecard"]["dimensions"] if entry["key"] == "doc_text")
        self.assertEqual(dimension["score"], 100)
        self.assertFalse({"docs_not_downloaded", "docs_missing", "docs_outdated"} & {gap["id"] for gap in status["scorecard"]["gaps"]})

        server.page_fetches.clear()
        self.service.start_refresh(self.profile, sources=["docs"], transport=server.transport())
        again = await self.service.wait_for_refresh()
        self.assertEqual((again["results"]["docs"]["manuals_current"], server.page_fetches), (6, []))

    def test_refresh_sources_load_the_doc_index_when_documentation_needs_it(self):
        self.assertIsNone(self.service.resolve_refresh_sources(None))
        self.assertEqual(self.service.resolve_refresh_sources(["docs"]), ["help_docs", "docs"])
        for empty in ([], ["everything"]):
            with self.assertRaises(ValueError):
                self.service.resolve_refresh_sources(empty)
        self._save_sources()
        self.assertEqual(self.service.resolve_refresh_sources(["docs", "docs", "everything"]), ["docs"])
        self.assertEqual(self.service.resolve_refresh_sources(["splunkbase"]), ["splunkbase"])

    async def test_documentation_only_refresh_loads_the_doc_index_and_skips_other_sources(self):
        server = FakeSourceServer()
        self.service.start_refresh(self.profile, sources=self.service.resolve_refresh_sources(["docs"]), transport=server.transport())
        result = await self.service.wait_for_refresh()
        self.assertEqual(result["state"], "completed")
        self.assertEqual(sorted(result["results"]), ["docs", "help_docs"])
        self.assertEqual(result["results"]["docs"]["count"], 7)
        status = self.service.build_status(make_blueprint(), [], allow_online=False, can_manage=True)
        self.assertEqual({manual["status"] for manual in status["docs"]["coverage"]["manuals"]}, {"downloaded"})
        self.assertFalse(self.service.store.load_source("splunkbase"))

    async def test_documentation_waits_for_discovery(self):
        self._save_sources()
        self.service.start_refresh(build_environment_profile(None), sources=["docs"], transport=FakeSourceServer().transport())
        result = await self.service.wait_for_refresh()
        self.assertEqual(result["results"]["docs"]["status"], "skipped")
        self.assertIn("discovery", result["results"]["docs"]["reason"])
        self.assertEqual(result["state"], "completed")

    async def test_documentation_download_starts_automatically_once_per_plan(self):
        now = datetime.now(timezone.utc)
        self._save_sources(now.replace(microsecond=0).isoformat())
        before = self.service.build_status(make_blueprint(), [], allow_online=False, can_manage=True)
        self.assertIn("docs_not_downloaded", [gap["id"] for gap in before["scorecard"]["gaps"]])

        with mock.patch.object(self.service, "start_refresh") as start:
            self.assertEqual(self.service.maybe_auto_refresh(self.profile, True, [], now=now, docs_due=True), "docs")
            self.assertEqual(start.call_args.kwargs, {"sources": ["docs"], "reason": "docs"})
            later = now + timedelta(minutes=61)
            self.assertEqual(self.service.maybe_auto_refresh(self.profile, True, ["TA-brand-new"], now=later, docs_due=True), "apps")
            self.assertEqual(start.call_args.kwargs, {"sources": ["splunkbase", "docs"], "reason": "apps"})

        plan, docs_status = self.service._docs_status(self.profile, self.service.store.load_source("help_docs"))
        self.assertTrue(self.service._docs_due(plan, docs_status["coverage"]))
        self.service._last_auto_attempt = None
        with mock.patch.object(self.service, "start_refresh") as start:
            status = self.service.build_status(make_blueprint(), [], allow_online=True, can_manage=True)
        self.assertEqual(status["refresh"]["auto_started"], "docs")
        # A download that keeps failing is not retried until the plan changes.
        self.service._update_state(docs_plan_attempted=plan_signature(plan))
        self.assertFalse(self.service._docs_due(plan, docs_status["coverage"]))
        fill_doc_index(self.service.docs, plan)
        self.service._update_state(docs_plan_attempted="")
        _plan, filled = self.service._docs_status(self.profile, self.service.store.load_source("help_docs"))
        self.assertFalse(self.service._docs_due(plan, filled["coverage"]))


class DocScorecardTests(unittest.TestCase):
    def _run(self, doc_text, summary=None):
        profile = build_environment_profile(make_blueprint())
        loaded = library_sources()
        scorecard = build_scorecard(profile, build_catalog(profile, loaded), [], summary or loaded_summary(), doc_text=doc_text)
        dimension = next(entry for entry in scorecard["dimensions"] if entry["key"] == "doc_text")
        gaps = [gap["id"] for gap in scorecard["gaps"] if gap["id"] in {"docs_not_downloaded", "docs_missing", "docs_outdated"}]
        return dimension, gaps

    def test_documentation_text_dimension(self):
        coverage = {"planned_pages": 7, "planned_manuals": 6, "downloaded_pages": 0, "pct": 0, "missing_manuals": 6, "outdated_manuals": 0}
        dimension, gaps = self._run({"plan_status": "ok", "coverage": coverage})
        self.assertEqual((dimension["score"], gaps), (0, ["docs_not_downloaded"]))

        partial = {**coverage, "downloaded_pages": 6, "pct": 86, "missing_manuals": 0, "outdated_manuals": 1}
        dimension, gaps = self._run({"plan_status": "ok", "coverage": partial})
        self.assertEqual((dimension["score"], gaps), (86, ["docs_outdated"]))
        self.assertIn("6 of 7 pages", dimension["basis"])

        dimension, _ = self._run({"plan_status": "needs_source", "coverage": {}})
        self.assertEqual(dimension["status"], "needs_sources")
        dimension, _ = self._run({"plan_status": "empty", "coverage": {"planned_pages": 0}})
        self.assertEqual(dimension["status"], "not_applicable")

if __name__ == "__main__":
    unittest.main()
