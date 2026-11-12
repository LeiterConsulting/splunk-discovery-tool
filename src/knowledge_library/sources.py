"""Storage, parsing, online fetching, and offline packs for knowledge library sources.

Three sources feed the catalog:
- security_content: data source definitions from github.com/splunk/security_content (Apache 2.0)
- splunkbase: public app metadata from the Splunkbase API
- help_docs: page listings from the help.splunk.com sitemaps
"""

import asyncio
import io
import json
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

import httpx
import yaml

SOURCE_NAMES = ("security_content", "splunkbase", "help_docs")
SOURCE_TITLES = {
    "security_content": "Splunk Security Content data sources",
    "splunkbase": "Splunkbase app metadata",
    "help_docs": "help.splunk.com documentation index",
}
SOURCE_LICENSES = {
    "security_content": "Apache-2.0",
    "splunkbase": "Splunkbase public API metadata",
    "help_docs": "Splunk documentation, used with Splunk's consent",
}
ALLOWED_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com", "splunkbase.splunk.com", "help.splunk.com"})
ONLINE_SOURCE_HOSTS = sorted(ALLOWED_HOSTS)

SECURITY_CONTENT_REPO = "splunk/security_content"
SECURITY_CONTENT_DEFAULT_REF = "develop"
SPLUNKBASE_API = "https://splunkbase.splunk.com/api/v1/app/"
HELP_DOCS_BASE = "https://help.splunk.com/en/"
DOC_PRODUCTS = {
    "splunk-enterprise": "Splunk Enterprise",
    "splunk-cloud-platform": "Splunk Cloud Platform",
    "supported-add-ons": "Splunk supported add-ons",
    "splunk-enterprise-security-8": "Splunk Enterprise Security 8",
    "splunk-enterprise-security-7": "Splunk Enterprise Security 7",
    "splunk-it-service-intelligence": "Splunk IT Service Intelligence",
}

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_PACK_BYTES = 100 * 1024 * 1024
MAX_PACK_MEMBER_BYTES = 128 * 1024 * 1024
MAX_SPLUNKBASE_LOOKUPS = 400
MAX_DATA_SOURCES = 5000
PACK_FORMAT = "dt4sms-knowledge-library-pack"
PACK_FORMAT_VERSION = 1
PACK_MANIFEST_NAME = "library-pack.json"

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\.ya?ml$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_VERSION = re.compile(r"^\d+(?:\.\d+){1,3}$")
_DOC_VERSION = re.compile(r"^(?:\d+(?:\.\d+){1,3})?$")
_SPLUNKBASE_UID = re.compile(r"splunkbase\.splunk\.com/app/(\d+)")
_SITEMAP_URL = re.compile(r"<url>(.*?)</url>", re.S | re.I)
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_SITEMAP_LASTMOD = re.compile(r"<lastmod>\s*([^<\s]+)\s*</lastmod>", re.I)

ProgressCallback = Callable[[str, int, int], None]


class LibrarySourceError(Exception):
    """A library source could not be fetched or parsed."""


class LibraryPackError(ValueError):
    """An uploaded library pack is not usable."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _clean_text(value: Any, limit: int = 300) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()[:limit]


def _clean_list(values: Any, limit: int, item_limit: int = 120) -> List[str]:
    items: List[str] = []
    for value in values if isinstance(values, list) else []:
        text = _clean_text(value, item_limit)
        if text and text not in items:
            items.append(text)
        if len(items) >= limit:
            break
    return items


def _optional_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def splunkbase_uid(value: Any) -> Optional[int]:
    if isinstance(value, int) and value > 0:
        return value
    text = str(value or "").strip()
    if text.isdigit():
        return int(text) or None
    match = _SPLUNKBASE_UID.search(text)
    return int(match.group(1)) if match else None


def splunkbase_app_url(uid: Any) -> str:
    parsed = splunkbase_uid(uid)
    return f"https://splunkbase.splunk.com/app/{parsed}/" if parsed else ""


def security_content_file_url(ref: str, file_name: str) -> str:
    if not _REF.match(str(ref or "")) or not _FILE_NAME.match(str(file_name or "")):
        return ""
    return f"https://github.com/{SECURITY_CONTENT_REPO}/blob/{ref}/data_sources/{file_name}"


def help_doc_url(product: str, *segments: str) -> str:
    parts = [product, *[segment for segment in segments if segment]]
    if product not in DOC_PRODUCTS or not all(_SEGMENT.match(part) for part in "/".join(parts).split("/")):
        return ""
    return HELP_DOCS_BASE + "/".join(parts)


# ---------------------------------------------------------------------------
# Normalizers (used for fresh downloads and to sanitize imported packs)
# ---------------------------------------------------------------------------

def normalize_data_source(doc: Any, file_name: str = "") -> Optional[Dict[str, Any]]:
    """Reduce a security_content data source YAML document (or an already normalized entry) to catalog fields."""
    if not isinstance(doc, dict):
        return None
    name = _clean_text(doc.get("name"), 200)
    if not name:
        return None
    supported: List[Dict[str, Any]] = []
    raw_tas = doc.get("supported_TA") if isinstance(doc.get("supported_TA"), list) else doc.get("supported_tas")
    for ta in raw_tas if isinstance(raw_tas, list) else []:
        if not isinstance(ta, dict):
            continue
        ta_name = _clean_text(ta.get("name"), 200)
        if not ta_name:
            continue
        supported.append({
            "name": ta_name,
            "splunkbase_uid": splunkbase_uid(ta.get("splunkbase_uid") or ta.get("url")),
            "version": _clean_text(ta.get("version"), 40),
        })
    fields = doc.get("fields")
    fields_count = len(fields) if isinstance(fields, list) else doc.get("fields_count")
    file_name = _clean_text(doc.get("file") or file_name, 160)
    return {
        "id": _clean_text(doc.get("id"), 64),
        "name": name,
        "description": _clean_text(doc.get("description"), 600),
        "source": _clean_text(doc.get("source"), 300),
        "sourcetype": _clean_text(doc.get("sourcetype"), 200),
        "separator": _clean_text(doc.get("separator"), 80),
        "separator_value": _clean_text(doc.get("separator_value"), 80),
        "supported_tas": supported[:10],
        "fields_count": fields_count if isinstance(fields_count, int) and fields_count >= 0 else 0,
        "output_fields": _clean_list(doc.get("output_fields"), 30),
        "mitre_components": _clean_list(doc.get("mitre_components"), 10),
        "file": file_name if _FILE_NAME.match(file_name) else "",
        "modification_date": _clean_text(doc.get("modification_date"), 40),
        "version": _clean_text(doc.get("version"), 20),
    }


def parse_data_source_yaml(text: str, file_name: str) -> Optional[Dict[str, Any]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return normalize_data_source(doc, file_name)


def normalize_splunkbase_app(record: Any) -> Optional[Dict[str, Any]]:
    """Keep the Splunkbase fields the catalog uses; releases are listed newest first by the API."""
    if not isinstance(record, dict):
        return None
    uid = splunkbase_uid(record.get("uid"))
    appid = _clean_text(record.get("appid"), 160)
    if not uid or not appid:
        return None
    releases = [release for release in record.get("releases") or [] if isinstance(release, dict)] if isinstance(record.get("releases"), list) else []
    latest = _clean_text(releases[0].get("title"), 40) if releases else _clean_text(record.get("latest_version"), 40)
    latest_cloud = next(
        (
            _clean_text(release.get("title"), 40)
            for release in releases
            if "splunk cloud" in [str(item).strip().lower() for item in release.get("product_compatibility") or []]
        ),
        "",
    ) if releases else _clean_text(record.get("latest_cloud_version"), 40)
    archived = record.get("archived")
    if not isinstance(archived, bool):
        archived = bool(record.get("is_archived")) or str(record.get("archive_status") or "live").strip().lower() not in {"", "live"}
    return {
        "uid": uid,
        "appid": appid,
        "title": _clean_text(record.get("title"), 200) or appid,
        "type": _clean_text(record.get("type"), 40),
        "cloud_compatible": _optional_bool(record.get("cloud_compatible")),
        "fedramp_validation": _clean_text(record.get("fedramp_validation"), 40),
        "fips_compatible": _optional_bool(record.get("fips_compatible", record.get("fips_compatibility"))),
        "archived": archived,
        "latest_version": latest,
        "latest_cloud_version": latest_cloud,
        "latest_published": _clean_text(releases[0].get("published_time"), 40) if releases else _clean_text(record.get("latest_published"), 40),
        "updated_time": _clean_text(record.get("updated_time"), 40),
    }


def parse_sitemap(xml_text: str) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    for block in _SITEMAP_URL.findall(xml_text or ""):
        loc = _SITEMAP_LOC.search(block)
        if not loc:
            continue
        lastmod = _SITEMAP_LASTMOD.search(block)
        entries.append((loc.group(1).strip(), lastmod.group(1).strip() if lastmod else ""))
    return entries


def build_docs_product_index(product: str, entries: Iterable[Tuple[str, str]]) -> Dict[str, Any]:
    """Group sitemap pages by manual and documentation version."""
    prefix = f"{HELP_DOCS_BASE}{product}/"
    manuals: Dict[str, Dict[str, Dict[str, Any]]] = {}
    page_count = 0
    for loc, lastmod in entries:
        if not loc.startswith(prefix):
            continue
        segments = [segment for segment in loc[len(prefix):].split("/") if segment]
        if not segments or not all(_SEGMENT.match(segment) for segment in segments):
            continue
        version_index = next((index for index, segment in enumerate(segments) if _VERSION.match(segment)), None)
        if version_index is not None and version_index > 0:
            manual = "/".join(segments[:version_index])
            version = segments[version_index]
            page = "/".join(segments[version_index + 1:])
        else:
            manual = "/".join(segments[:2]) if len(segments) > 1 else segments[0]
            version = ""
            page = "/".join(segments[2:]) if len(segments) > 1 else ""
        bucket = manuals.setdefault(manual, {}).setdefault(version, {"lastmod": "", "pages": []})
        bucket["pages"].append(page)
        if lastmod and lastmod > bucket["lastmod"]:
            bucket["lastmod"] = _clean_text(lastmod, 40)
        page_count += 1
    return {"title": DOC_PRODUCTS.get(product, product), "page_count": page_count, "manuals": manuals}


def sanitize_docs_product(product: str, payload: Any) -> Optional[Dict[str, Any]]:
    if product not in DOC_PRODUCTS or not isinstance(payload, dict) or not isinstance(payload.get("manuals"), dict):
        return None
    manuals: Dict[str, Dict[str, Dict[str, Any]]] = {}
    page_count = 0
    for manual, versions in payload["manuals"].items():
        if not isinstance(manual, str) or not all(_SEGMENT.match(part) for part in manual.split("/")) or not isinstance(versions, dict):
            continue
        for version, bucket in versions.items():
            if not isinstance(version, str) or not _DOC_VERSION.match(version) or not isinstance(bucket, dict):
                continue
            pages = [
                page for page in bucket.get("pages") or []
                if isinstance(page, str) and (page == "" or all(_SEGMENT.match(part) for part in page.split("/")))
            ] if isinstance(bucket.get("pages"), list) else []
            if not pages:
                continue
            manuals.setdefault(manual, {})[version] = {"lastmod": _clean_text(bucket.get("lastmod"), 40), "pages": pages}
            page_count += len(pages)
    return {
        "title": DOC_PRODUCTS[product],
        "page_count": page_count,
        "fetched_at": _clean_text(payload.get("fetched_at"), 40),
        "manuals": manuals,
    }


def sanitize_source_payload(name: str, payload: Any) -> Optional[Dict[str, Any]]:
    """Rebuild a source payload from known fields only; anything unexpected is dropped."""
    if not isinstance(payload, dict):
        return None
    base = {
        "source": name,
        "fetched_at": _clean_text(payload.get("fetched_at"), 40),
        "origin": _clean_text(payload.get("origin"), 20) or "online",
        "pack_created_at": _clean_text(payload.get("pack_created_at"), 40),
        "license": SOURCE_LICENSES[name],
    }
    if name == "security_content":
        ref = _clean_text(payload.get("ref"), 100)
        data_sources = [
            entry for entry in (normalize_data_source(item) for item in (payload.get("data_sources") or [])[:MAX_DATA_SOURCES])
            if entry
        ] if isinstance(payload.get("data_sources"), list) else []
        if not data_sources:
            return None
        return {**base, "ref": ref if _REF.match(ref) else SECURITY_CONTENT_DEFAULT_REF, "version": _clean_text(payload.get("version"), 60), "data_sources": data_sources}
    if name == "splunkbase":
        apps: Dict[str, Dict[str, Any]] = {}
        for record in (payload.get("apps") or {}).values() if isinstance(payload.get("apps"), dict) else []:
            normalized = normalize_splunkbase_app(record)
            if normalized:
                apps[normalized["appid"].lower()] = normalized
        if not apps:
            return None
        not_found = _clean_list(payload.get("not_found"), 2000, 160)
        return {**base, "apps": apps, "not_found": not_found}
    if name == "help_docs":
        products = {}
        for product, product_payload in (payload.get("products") or {}).items() if isinstance(payload.get("products"), dict) else []:
            sanitized = sanitize_docs_product(product, product_payload)
            if sanitized and sanitized["page_count"]:
                products[product] = sanitized
        if not products:
            return None
        return {**base, "products": products}
    return None


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class LibraryStore:
    """JSON files under output/knowledge_library. Paths stay relative so they follow the app's working directory."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._cache: Dict[str, Tuple[float, Optional[Dict[str, Any]]]] = {}

    def source_path(self, name: str) -> Path:
        return self.root / "sources" / f"{name}.json"

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    def _read_json(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        key = str(path.resolve())
        cached = self._cache.get(key)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = None
        payload = payload if isinstance(payload, dict) else None
        self._cache[key] = (mtime, payload)
        return payload

    def _write_json(self, path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def load_source(self, name: str) -> Optional[Dict[str, Any]]:
        return self._read_json(self.source_path(name)) if name in SOURCE_NAMES else None

    def load_sources(self) -> Dict[str, Optional[Dict[str, Any]]]:
        return {name: self.load_source(name) for name in SOURCE_NAMES}

    def save_source(self, name: str, payload: Dict[str, Any]) -> None:
        if name not in SOURCE_NAMES:
            raise ValueError(f"Unknown library source {name}")
        self._write_json(self.source_path(name), payload)

    def load_state(self) -> Dict[str, Any]:
        return dict(self._read_json(self.state_path) or {})

    def save_state(self, state: Dict[str, Any]) -> None:
        self._write_json(self.state_path, state)

    def signature(self) -> Tuple[Any, ...]:
        stamps = []
        for name in SOURCE_NAMES:
            try:
                stamps.append(self.source_path(name).stat().st_mtime)
            except OSError:
                stamps.append(None)
        return tuple(stamps)

    def summary(self) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for name, payload in self.load_sources().items():
            entry: Dict[str, Any] = {
                "name": name,
                "title": SOURCE_TITLES[name],
                "license": SOURCE_LICENSES[name],
                "available": bool(payload),
            }
            if payload:
                entry.update({
                    "fetched_at": payload.get("fetched_at") or "",
                    "origin": payload.get("origin") or "online",
                    "pack_created_at": payload.get("pack_created_at") or "",
                })
                if name == "security_content":
                    entry.update({"version": payload.get("version") or payload.get("ref") or "", "count": len(payload.get("data_sources") or [])})
                elif name == "splunkbase":
                    entry["count"] = len(payload.get("apps") or {})
                elif name == "help_docs":
                    products = payload.get("products") or {}
                    entry.update({
                        "count": sum(int(product.get("page_count") or 0) for product in products.values()),
                        "products": sorted(products.keys()),
                    })
            result[name] = entry
        return result


# ---------------------------------------------------------------------------
# Online fetching
# ---------------------------------------------------------------------------

async def _enforce_allowed_host(request: httpx.Request) -> None:
    if request.url.scheme != "https" or request.url.host not in ALLOWED_HOSTS:
        raise LibrarySourceError(f"Blocked request to {request.url.scheme}://{request.url.host}; only the library source hosts are allowed")


def create_library_http_client(transport: Optional[httpx.AsyncBaseTransport] = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(45.0, connect=15.0),
        follow_redirects=True,
        headers={"User-Agent": "DT4SMS-knowledge-library/1"},
        event_hooks={"request": [_enforce_allowed_host]},
        transport=transport,
    )


async def _get(client: httpx.AsyncClient, url: str, *, accept: str = "") -> httpx.Response:
    headers = {"Accept": accept} if accept else None
    try:
        response = await client.get(url, headers=headers)
    except LibrarySourceError:
        raise
    except httpx.HTTPError as exc:
        raise LibrarySourceError(f"Could not reach {httpx.URL(url).host}: {type(exc).__name__}: {exc}") from exc
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise LibrarySourceError(f"Response from {response.url.host} is larger than {MAX_RESPONSE_BYTES // (1024 * 1024)} MB")
    if response.status_code == 403 and response.url.host == "api.github.com":
        raise LibrarySourceError("GitHub refused the request (usually the hourly limit for anonymous requests). Try again later or import a library pack.")
    if response.status_code >= 400:
        raise LibrarySourceError(f"{response.url.host} returned HTTP {response.status_code} for {response.url.path}")
    return response


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        raise LibrarySourceError(f"{response.url.host} returned data that is not JSON") from exc


async def _gather_limited(items: List[Any], worker: Callable[[Any], Awaitable[Any]], limit: int, progress: Optional[Callable[[int], None]] = None) -> List[Any]:
    semaphore = asyncio.Semaphore(limit)
    done = 0

    async def run(item: Any) -> Any:
        nonlocal done
        async with semaphore:
            try:
                return await worker(item)
            finally:
                done += 1
                if progress:
                    progress(done)

    return await asyncio.gather(*(run(item) for item in items), return_exceptions=True)


async def fetch_security_content(client: httpx.AsyncClient, progress: Optional[ProgressCallback] = None) -> Dict[str, Any]:
    ref = SECURITY_CONTENT_DEFAULT_REF
    version = ""
    try:
        release = _json(await _get(client, f"https://api.github.com/repos/{SECURITY_CONTENT_REPO}/releases/latest", accept="application/vnd.github+json"))
        tag = _clean_text(release.get("tag_name"), 100) if isinstance(release, dict) else ""
        if tag and _REF.match(tag):
            ref, version = tag, tag
    except LibrarySourceError:
        pass
    listing = _json(await _get(
        client,
        f"https://api.github.com/repos/{SECURITY_CONTENT_REPO}/contents/data_sources?ref={ref}",
        accept="application/vnd.github+json",
    ))
    if not isinstance(listing, list):
        raise LibrarySourceError("GitHub did not return the data_sources folder listing")
    file_names = [
        str(item.get("name")) for item in listing
        if isinstance(item, dict) and item.get("type") == "file" and _FILE_NAME.match(str(item.get("name") or ""))
    ][:MAX_DATA_SOURCES]
    if not file_names:
        raise LibrarySourceError("The data_sources folder listing was empty")

    async def fetch_one(file_name: str) -> Optional[Dict[str, Any]]:
        response = await _get(client, f"https://raw.githubusercontent.com/{SECURITY_CONTENT_REPO}/{ref}/data_sources/{file_name}")
        return parse_data_source_yaml(response.text, file_name)

    results = await _gather_limited(
        file_names, fetch_one, 8,
        (lambda done: progress("security_content", done, len(file_names))) if progress else None,
    )
    data_sources = [result for result in results if isinstance(result, dict)]
    failures = [result for result in results if isinstance(result, BaseException)]
    if not data_sources:
        raise LibrarySourceError(f"No data source files could be read ({failures[0] if failures else 'empty'})")
    return {
        "source": "security_content",
        "fetched_at": utc_now_iso(),
        "origin": "online",
        "license": SOURCE_LICENSES["security_content"],
        "ref": ref,
        "version": version or ref,
        "data_sources": sorted(data_sources, key=lambda item: item["name"].lower()),
        "failed_files": len(failures),
    }


async def fetch_splunkbase(
    client: httpx.AsyncClient,
    *,
    uids: Iterable[int],
    appids: Iterable[str],
    existing: Optional[Dict[str, Any]] = None,
    progress: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    known_apps: Dict[str, Dict[str, Any]] = dict((existing or {}).get("apps") or {})
    lookups: List[Tuple[str, Any]] = []
    for uid in sorted({uid for uid in uids if uid}):
        lookups.append(("uid", uid))
    for appid in sorted({str(appid).strip() for appid in appids if str(appid or "").strip()}, key=str.lower):
        lookups.append(("appid", appid))
    lookups = lookups[:MAX_SPLUNKBASE_LOOKUPS]
    if not lookups:
        raise LibrarySourceError("There were no apps to look up on Splunkbase")

    async def lookup(item: Tuple[str, Any]) -> Tuple[str, Any, Optional[Dict[str, Any]]]:
        kind, value = item
        if kind == "uid":
            record = _json(await _get(client, f"{SPLUNKBASE_API}{int(value)}/?include=releases"))
        else:
            payload = _json(await _get(client, f"{SPLUNKBASE_API}?{httpx.QueryParams({'appid': value, 'include': 'releases'})}"))
            results = payload.get("results") if isinstance(payload, dict) else None
            record = next((row for row in results or [] if isinstance(row, dict) and str(row.get("appid", "")).lower() == value.lower()), None)
        return kind, value, normalize_splunkbase_app(record)

    results = await _gather_limited(
        lookups, lookup, 4,
        (lambda done: progress("splunkbase", done, len(lookups))) if progress else None,
    )
    not_found = set(str(item) for item in (existing or {}).get("not_found") or [])
    errors = 0
    for result in results:
        if isinstance(result, BaseException):
            errors += 1
            continue
        kind, value, record = result
        if record:
            known_apps[record["appid"].lower()] = record
            not_found.discard(record["appid"].lower())
        elif kind == "appid":
            not_found.add(str(value).lower())
    if errors and errors == len(results):
        raise LibrarySourceError(f"Splunkbase lookups failed ({next(r for r in results if isinstance(r, BaseException))})")
    return {
        "source": "splunkbase",
        "fetched_at": utc_now_iso(),
        "origin": "online",
        "license": SOURCE_LICENSES["splunkbase"],
        "apps": known_apps,
        "not_found": sorted(not_found),
        "failed_lookups": errors,
    }


async def fetch_help_docs(
    client: httpx.AsyncClient,
    products: Iterable[str] = tuple(DOC_PRODUCTS),
    progress: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    product_list = [product for product in products if product in DOC_PRODUCTS]
    indexed: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    for position, product in enumerate(product_list, start=1):
        try:
            response = await _get(client, f"{HELP_DOCS_BASE}{product}/sitemap.xml", accept="application/xml")
            index = build_docs_product_index(product, parse_sitemap(response.text))
            if index["page_count"]:
                indexed[product] = {**index, "fetched_at": utc_now_iso()}
        except LibrarySourceError as exc:
            errors.append(f"{product}: {exc}")
        if progress:
            progress("help_docs", position, len(product_list))
    if not indexed:
        raise LibrarySourceError(errors[0] if errors else "help.splunk.com returned no documentation pages")
    return {
        "source": "help_docs",
        "fetched_at": utc_now_iso(),
        "origin": "online",
        "license": SOURCE_LICENSES["help_docs"],
        "products": indexed,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Offline packs
# ---------------------------------------------------------------------------

def export_pack(store: LibraryStore) -> bytes:
    sources = {name: payload for name, payload in store.load_sources().items() if payload}
    if not sources:
        raise LibraryPackError("There are no library sources to export yet.")
    manifest = {
        "format": PACK_FORMAT,
        "format_version": PACK_FORMAT_VERSION,
        "created_at": utc_now_iso(),
        "sources": {
            name: {
                "fetched_at": payload.get("fetched_at") or "",
                "license": SOURCE_LICENSES[name],
                "version": payload.get("version") or "",
            }
            for name, payload in sources.items()
        },
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(PACK_MANIFEST_NAME, json.dumps(manifest, indent=2))
        for name, payload in sources.items():
            archive.writestr(f"sources/{name}.json", json.dumps(payload, separators=(",", ":")))
    return buffer.getvalue()


def _read_pack_member(archive: zipfile.ZipFile, name: str) -> Optional[Any]:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_PACK_MEMBER_BYTES:
        raise LibraryPackError(f"{name} is larger than the {MAX_PACK_MEMBER_BYTES // (1024 * 1024)} MB limit for one pack file.")
    with archive.open(info) as handle:
        data = handle.read(MAX_PACK_MEMBER_BYTES + 1)
    if len(data) > MAX_PACK_MEMBER_BYTES:
        raise LibraryPackError(f"{name} is larger than the {MAX_PACK_MEMBER_BYTES // (1024 * 1024)} MB limit for one pack file.")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise LibraryPackError(f"{name} is not valid JSON.") from exc


def import_pack(store: LibraryStore, data: bytes) -> Dict[str, Any]:
    if not data:
        raise LibraryPackError("The uploaded file is empty.")
    if len(data) > MAX_PACK_BYTES:
        raise LibraryPackError(f"Library packs can be at most {MAX_PACK_BYTES // (1024 * 1024)} MB.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise LibraryPackError("The uploaded file is not a library pack (.zip).") from exc
    with archive:
        manifest = _read_pack_member(archive, PACK_MANIFEST_NAME)
        if not isinstance(manifest, dict) or manifest.get("format") != PACK_FORMAT:
            raise LibraryPackError("The zip file does not contain a knowledge library pack manifest.")
        if int(manifest.get("format_version") or 0) > PACK_FORMAT_VERSION:
            raise LibraryPackError("This library pack was made by a newer version of the app. Update the app, then import it again.")
        created_at = _clean_text(manifest.get("created_at"), 40)
        accepted: Dict[str, Dict[str, Any]] = {}
        skipped: List[str] = []
        for name in SOURCE_NAMES:
            raw = _read_pack_member(archive, f"sources/{name}.json")
            if raw is None:
                continue
            sanitized = sanitize_source_payload(name, raw)
            if sanitized is None:
                skipped.append(name)
                continue
            sanitized["origin"] = "pack"
            sanitized["pack_created_at"] = created_at
            accepted[name] = sanitized
    if not accepted:
        raise LibraryPackError("The library pack did not contain any usable sources.")
    for name, payload in accepted.items():
        store.save_source(name, payload)
    return {"imported": sorted(accepted), "skipped": skipped, "pack_created_at": created_at}
