"""Download, store, and search the text of the Splunk documentation that matches the environment.

Pages come from help.splunk.com only. The download plan follows the environment profile: every manual of
the platform version, the manuals of installed apps that have their own documentation (Splunk Enterprise
Security, ITSI, CIM, DB Connect, ...), and the overview page of each installed supported add-on. Full add-on
manuals live on docs.splunk.com, which does not allow automated access, so the library links to them instead.
"""

import asyncio
import hashlib
import re
import sqlite3
import threading
from contextlib import closing
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import httpx

from knowledge_library.catalog import (
    ADDON_DOC_PREFIX,
    ADDON_DOC_PRODUCT,
    APP_MANUALS,
    PLATFORM_MANUALS,
    _addon_doc_index,
    _app_product,
    _find_manual,
    choose_doc_version,
    match_addon_doc,
    select_platform_docs,
)
from knowledge_library.ranking import (
    EnvironmentTerms,
    BM25,
    best_possible_fusion,
    cosine,
    coverage_weight,
    hashed_vector,
    matched_terms,
    query_terms,
    reciprocal_rank_fusion,
    tokenize,
)
from knowledge_library.sources import (
    _DOC_VERSION,
    _SEGMENT,
    DOC_PRODUCTS,
    LibraryRefusedError,
    LibrarySourceError,
    _clean_text,
    _get,
    help_doc_url,
    utc_now_iso,
)

DOCS_DIR_NAME = "docs"
DOCS_DB_NAME = "library_docs.sqlite3"
# help.splunk.com refuses a client that requests pages too quickly, so downloads stay slow and stop at the first refusals.
DOC_FETCH_CONCURRENCY = 2
DOC_REQUEST_INTERVAL = 0.25
DOC_REFUSAL_LIMIT = 3
MAX_DOC_PAGES = 8000
MAX_PAGES_PER_MANUAL = 1500
MAX_STATUS_MANUALS = 400
CHUNK_TARGET_CHARS = 1400
CHUNK_MIN_CHARS = 160
CHUNK_MAX_CHARS = 3000
MAX_CHUNKS_PER_PAGE = 60
MAX_PAGE_TEXT_CHARS = 60000
MAX_HEADING_CHARS = 300
SEARCH_CANDIDATES = 60
FALLBACK_CANDIDATE_ROWS = 4000
FUSION_WEIGHTS = (1.0, 0.6, 0.5)
CONTEXT_CHARS = 1200
ProgressCallback = Callable[[str, int, int], None]

_ACRONYMS = {"spl", "spl2", "rest", "cim", "itsi", "http", "hec", "kv", "ui", "api", "db", "sql", "aws", "ot", "ai", "jdbc", "odbc", "es"}
_SKIP_TAGS = frozenset({"script", "style", "noscript", "svg", "nav", "header", "footer", "aside", "button", "form", "template", "iframe", "select"})
_BLOCK_TAGS = frozenset({
    "p", "div", "section", "article", "ul", "ol", "li", "table", "thead", "tbody", "tfoot", "tr", "dl", "dt", "dd",
    "blockquote", "figure", "figcaption", "br", "hr", "caption",
})
_HEADING_TAGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
_WHITESPACE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WHITESPACE.sub(" ", text or "").strip()


def humanize_manual(manual: str) -> str:
    leaf = str(manual or "").rsplit("/", 1)[-1]
    words = [word.upper() if word in _ACRONYMS else word for word in leaf.split("-") if word]
    text = " ".join(words)
    return text[:1].upper() + text[1:] if text else ""


# ---------------------------------------------------------------------------
# Page text
# ---------------------------------------------------------------------------

class _DocPageParser(HTMLParser):
    def __init__(self, main_only: bool):
        super().__init__(convert_charrefs=True)
        self.main_only = main_only
        self.main_depth = 0
        self.in_head = False
        self.in_title = False
        self.title_parts: List[str] = []
        self.h1_title = ""
        self.lastmod = ""
        self.skip_stack: List[str] = []
        self.heading_level = 0
        self.heading_parts: List[str] = []
        self.pre_depth = 0
        self.pre_parts: List[str] = []
        self.buffer: List[str] = []
        self.prefix = ""
        self.cell_count = 0
        self.sections: List[Dict[str, Any]] = []
        self.current: Dict[str, Any] = {"heading": "", "level": 0, "lines": []}

    def _capturing(self) -> bool:
        if self.skip_stack:
            return False
        return self.main_depth > 0 if self.main_only else not self.in_head

    def _flush(self) -> None:
        text = _normalize("".join(self.buffer))
        self.buffer = []
        if text:
            self.current["lines"].append(self.prefix + text)
            self.prefix = ""

    def _start_section(self, heading: str, level: int) -> None:
        self._flush()
        if self.current["lines"]:
            self.sections.append(self.current)
        self.current = {"heading": heading, "level": level, "lines": []}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag == "meta":
            values = {key.lower(): value or "" for key, value in attrs}
            if (values.get("name") or values.get("property") or "").lower() == "lastmodifiediso":
                self.lastmod = _clean_text(values.get("content"), 40)
            return
        if tag == "title" and not self.title_parts:
            self.in_title = True
            return
        if tag == "head":
            self.in_head = True
            return
        if tag == "main":
            self.main_depth += 1
            return
        if tag in _SKIP_TAGS:
            self.skip_stack.append(tag)
            return
        if not self._capturing():
            return
        if tag in _HEADING_TAGS:
            self._flush()
            self.heading_level = int(tag[1])
            self.heading_parts = []
        elif tag == "pre":
            self._flush()
            self.pre_depth += 1
        elif tag in ("td", "th"):
            if self.cell_count:
                self.buffer.append(" | ")
            self.cell_count += 1
        elif tag == "tr":
            self._flush()
            self.cell_count = 0
        elif tag == "li":
            self._flush()
            self.prefix = "- "
        elif tag in _BLOCK_TAGS:
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
            return
        if tag == "head":
            self.in_head = False
            return
        if tag == "main":
            self._flush()
            self.main_depth = max(0, self.main_depth - 1)
            return
        if self.skip_stack:
            if tag in self.skip_stack:
                while self.skip_stack and self.skip_stack.pop() != tag:
                    pass
            return
        if not self._capturing():
            return
        if tag in _HEADING_TAGS and self.heading_level:
            heading = _normalize("".join(self.heading_parts))[:MAX_HEADING_CHARS]
            level = self.heading_level
            self.heading_level = 0
            self.heading_parts = []
            if heading:
                if level == 1 and not self.h1_title:
                    self.h1_title = heading
                self._start_section(heading, level)
        elif tag == "pre" and self.pre_depth:
            self.pre_depth -= 1
            if not self.pre_depth:
                code = "".join(self.pre_parts).strip("\n").rstrip()
                self.pre_parts = []
                if code.strip():
                    self.current["lines"].append("```\n" + code + "\n```")
        elif tag == "tr":
            self._flush()
            self.cell_count = 0
        elif tag in _BLOCK_TAGS:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
            return
        if not self._capturing():
            return
        if self.heading_level:
            self.heading_parts.append(data)
        elif self.pre_depth:
            self.pre_parts.append(data)
        else:
            self.buffer.append(data)

    def finish(self) -> Dict[str, Any]:
        self.close()
        self._start_section("", 0)
        title = self.h1_title
        if not title:
            title = _normalize("".join(self.title_parts)).split(" | ", 1)[0]
        return {"title": title[:MAX_HEADING_CHARS], "lastmod": self.lastmod, "sections": self.sections}


def extract_doc_page(html: str) -> Dict[str, Any]:
    """Title, last-modified time, and heading-delimited sections of a help.splunk.com page."""
    text = str(html or "")
    parser = _DocPageParser(main_only="<main" in text.lower())
    parser.feed(text)
    return parser.finish()


def _split_long_block(block: str, limit: int) -> List[str]:
    if len(block) <= limit:
        return [block]
    pieces: List[str] = []
    current = ""
    for line in block.split("\n"):
        while len(line) > limit:
            cut = line.rfind(" ", 0, limit)
            cut = cut if cut > limit // 2 else limit
            pieces.append((current + "\n" + line[:cut]).strip("\n") if current else line[:cut])
            current = ""
            line = line[cut:].lstrip()
        if current and len(current) + len(line) + 1 > limit:
            pieces.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current.strip():
        pieces.append(current)
    return pieces


def chunk_page(title: str, sections: Sequence[Dict[str, Any]], target: int = CHUNK_TARGET_CHARS) -> List[Tuple[str, str]]:
    """Split a page into (heading, text) chunks of about `target` characters that never cross a heading."""
    chunks: List[Tuple[str, str]] = []
    total = 0
    for section in sections:
        heading = str(section.get("heading") or "")
        if heading == title:
            heading = ""
        blocks: List[str] = []
        for line in section.get("lines") or []:
            if str(line).strip():
                blocks.extend(_split_long_block(str(line), int(target * 1.5)))
        current: List[str] = []
        size = 0
        pending: List[str] = []
        for block in blocks:
            if current and size + len(block) + 1 > target:
                pending.append("\n".join(current))
                current, size = [], 0
            current.append(block)
            size += len(block) + 1
        if current:
            pending.append("\n".join(current))
        for body in pending:
            if chunks and len(body) < CHUNK_MIN_CHARS and len(chunks[-1][1]) + len(body) < target * 1.25:
                previous_heading, previous_body = chunks[-1]
                label = f"{heading}\n" if heading and heading != previous_heading else ""
                chunks[-1] = (previous_heading, f"{previous_body}\n{label}{body}")
            else:
                chunks.append((heading, body))
            total += len(body)
            if total >= MAX_PAGE_TEXT_CHARS or len(chunks) >= MAX_CHUNKS_PER_PAGE:
                return [(h[:MAX_HEADING_CHARS], b[:CHUNK_MAX_CHARS]) for h, b in chunks]
    return [(h[:MAX_HEADING_CHARS], b[:CHUNK_MAX_CHARS]) for h, b in chunks]


def _parse_and_chunk(html: str) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
    parsed = extract_doc_page(html)
    return parsed, chunk_page(parsed["title"], parsed["sections"])


# ---------------------------------------------------------------------------
# Download plan
# ---------------------------------------------------------------------------

def _product_title(product: str) -> str:
    return re.sub(r"\s\d+$", "", DOC_PRODUCTS.get(product, product))


def _is_pdf(path: str) -> bool:
    return str(path or "").lower().endswith(".pdf")


def _html_pages(pages: Optional[Iterable[str]]) -> List[str]:
    """Sitemaps also list PDF exports of some manuals; only HTML pages have text the library can read."""
    return [page for page in dict.fromkeys(pages or []) if not _is_pdf(page)]


def _distinct_manuals(available: Dict[str, Any], version: str, preferred_paths: Iterable[str]) -> List[str]:
    """help.splunk.com publishes some manuals under two paths with the same pages; keep one path for each."""
    preferred = set(preferred_paths)
    candidates = sorted(manual for manual, versions in available.items() if version in versions)
    chosen: Dict[Tuple[str, ...], str] = {}
    for manual in sorted(candidates, key=lambda path: (path not in preferred, -path.count("/"), path)):
        bucket = available[manual][version]
        pages = tuple(_html_pages(bucket.get("pages") if isinstance(bucket, dict) else None))
        # Single-page manuals often share a page name such as the manual root, so only longer page lists identify a copy.
        chosen.setdefault(pages if len(pages) > 1 else (manual,), manual)
    keep = set(chosen.values())
    return [manual for manual in candidates if manual in keep]


def build_doc_plan(profile: Dict[str, Any], help_docs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Pick the manuals to download for this environment, platform first, within MAX_DOC_PAGES."""
    if not profile.get("available"):
        return {"status": "needs_discovery", "manuals": [], "groups": [], "page_total": 0}
    products = (help_docs or {}).get("products") or {}
    if not products:
        return {"status": "needs_source", "manuals": [], "groups": [], "page_total": 0}

    manuals: List[Dict[str, Any]] = []
    seen = set()
    page_total = 0

    def add(product: str, manual: str, version: str, title: str, reason: str, group: str) -> None:
        nonlocal page_total
        bucket = (((products.get(product) or {}).get("manuals") or {}).get(manual) or {}).get(version)
        pages = _html_pages(bucket.get("pages") if isinstance(bucket, dict) else None)[:MAX_PAGES_PER_MANUAL]
        key = f"{product}/{manual}/{version or 'current'}"
        if not pages or _is_pdf(manual) or key in seen or page_total + len(pages) > MAX_DOC_PAGES:
            return
        seen.add(key)
        page_total += len(pages)
        manuals.append({
            "key": key,
            "product": product,
            "manual": manual,
            "version": version,
            "title": title,
            "reason": reason,
            "group": group,
            "lastmod": bucket.get("lastmod") or "",
            "pages": pages,
        })

    platform = select_platform_docs(profile, help_docs)
    if platform.get("status") == "ok" and platform.get("doc_version"):
        product, version = platform["product"], platform["doc_version"]
        group = f"{_product_title(product)} {version}"
        titles = {path: title for path, title, _reason, _roles in PLATFORM_MANUALS}
        for manual in _distinct_manuals(products[product].get("manuals") or {}, version, titles):
            add(product, manual, version, titles.get(manual) or humanize_manual(manual), f"Your platform version ({group})", group)

    deployment = (profile.get("splunk") or {}).get("deployment_type")
    platform_order = ["splunk-cloud-platform", "splunk-enterprise"] if deployment == "cloud" else ["splunk-enterprise", "splunk-cloud-platform"]
    addon_slugs = _addon_doc_index(help_docs)
    matched_addons = False
    for app in (profile.get("apps") or {}).get("items") or []:
        if app.get("disabled"):
            continue
        name = str(app.get("name") or "")
        label = str(app.get("label") or name)
        app_version = str(app.get("version") or "")
        key = name.lower()
        if key in APP_MANUALS:
            manual_path, title = APP_MANUALS[key]
            for product in platform_order:
                available = (products.get(product) or {}).get("manuals") or {}
                manual = _find_manual(available, manual_path)
                if manual:
                    version, _match = choose_doc_version(available[manual].keys(), app_version)
                    version = version if version in available[manual] else ""
                    add(product, manual, version, title, f"Installed app {label}", f"{title} {version}".strip())
                    break
        product = _app_product(key, app_version)
        if product and product in products:
            available = products[product].get("manuals") or {}
            all_versions = {version for versions in available.values() for version in versions if version}
            version, _match = choose_doc_version(all_versions, app_version)
            group = f"{_product_title(product)} {version}".strip()
            for manual, versions in sorted(available.items()):
                if version and version in versions:
                    add(product, manual, version, humanize_manual(manual), f"Installed app {label}", group)
                elif "" in versions:
                    add(product, manual, "", humanize_manual(manual), f"Installed app {label}", group)
        if not app.get("builtin"):
            doc = match_addon_doc([name, label], addon_slugs)
            if doc:
                matched_addons = True
                add(ADDON_DOC_PRODUCT, f"{ADDON_DOC_PREFIX}{doc['slug']}", "", label, f"Installed add-on {label}", "Supported add-on overviews")
    if matched_addons:
        for manual in sorted((products.get(ADDON_DOC_PRODUCT) or {}).get("manuals") or {}):
            if manual.startswith("about-the-splunk-supported-add-ons"):
                add(ADDON_DOC_PRODUCT, manual, "", humanize_manual(manual), "Installing and troubleshooting add-ons", "Supported add-on overviews")

    groups: Dict[str, Dict[str, Any]] = {}
    for manual in manuals:
        entry = groups.setdefault(manual["group"], {"label": manual["group"], "manuals": 0, "pages": 0})
        entry["manuals"] += 1
        entry["pages"] += len(manual["pages"])
    return {
        "status": "ok" if manuals else "empty",
        "manuals": manuals,
        "groups": list(groups.values()),
        "page_total": page_total,
        "platform": {key: platform.get(key) for key in ("product", "product_title", "doc_version", "version_match", "requested_version")},
    }


def needs_fetch(manual: Dict[str, Any], state: Optional[Dict[str, Any]]) -> bool:
    if not state or not state.get("complete"):
        return True
    if (state.get("lastmod") or "") != (manual.get("lastmod") or ""):
        return True
    return int(state.get("page_total") or 0) != len(manual.get("pages") or [])


def plan_coverage(plan: Dict[str, Any], states: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    planned_pages = 0
    downloaded = 0
    missing = 0
    outdated = 0
    for manual in plan.get("manuals") or []:
        pages = len(manual["pages"])
        planned_pages += pages
        state = states.get(manual["key"])
        if not state or not int(state.get("page_done") or 0):
            missing += 1
            continue
        downloaded += min(int(state.get("page_done") or 0), pages)
        if needs_fetch(manual, state):
            outdated += 1
    total = len(plan.get("manuals") or [])
    groups: Dict[str, Dict[str, Any]] = {}
    for manual in plan.get("manuals") or []:
        entry = groups.setdefault(manual["group"], {"label": manual["group"], "manuals": 0, "pages": 0, "downloaded_pages": 0})
        entry["manuals"] += 1
        entry["pages"] += len(manual["pages"])
        entry["downloaded_pages"] += min(int((states.get(manual["key"]) or {}).get("page_done") or 0), len(manual["pages"]))
    return {
        "planned_manuals": total,
        "planned_pages": planned_pages,
        "downloaded_pages": downloaded,
        "missing_manuals": missing,
        "outdated_manuals": outdated,
        "current_manuals": total - missing - outdated,
        "pct": int(round(100 * downloaded / planned_pages)) if planned_pages else None,
        "groups": list(groups.values()),
        "manuals": [manual_status(manual, states.get(manual["key"])) for manual in (plan.get("manuals") or [])[:MAX_STATUS_MANUALS]],
    }


def manual_status(manual: Dict[str, Any], state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """One planned manual's download state: downloaded, missing, partial (pages failed or were added), or changed on the site."""
    pages = len(manual["pages"])
    done = min(int((state or {}).get("page_done") or 0), pages)
    if not state or not done:
        status = "missing"
    elif done < pages or not state.get("complete"):
        status = "partial"
    elif needs_fetch(manual, state):
        status = "changed"
    else:
        status = "downloaded"
    return {
        "key": manual["key"],
        "title": manual["title"],
        "group": manual["group"],
        "reason": manual.get("reason") or "",
        "version": manual.get("version") or "",
        "pages": pages,
        "downloaded_pages": done,
        "status": status,
        "url": help_doc_url(manual["product"], manual["manual"], manual.get("version") or "", manual["pages"][0]) if manual["pages"] else "",
    }


def plan_signature(plan: Dict[str, Any]) -> str:
    """Changes whenever the manuals, their page lists, or their last-modified times change."""
    digest = hashlib.sha1()
    for manual in sorted(plan.get("manuals") or [], key=lambda item: item["key"]):
        digest.update(f"{manual['key']}|{manual.get('lastmod') or ''}|{len(manual['pages'])}\n".encode("utf-8"))
    return digest.hexdigest()[:20]


# ---------------------------------------------------------------------------
# Storage and search
# ---------------------------------------------------------------------------

_FTS5_AVAILABLE: Optional[bool] = None


def fts5_available() -> bool:
    global _FTS5_AVAILABLE
    if _FTS5_AVAILABLE is None:
        try:
            with closing(sqlite3.connect(":memory:")) as conn:
                conn.execute("CREATE VIRTUAL TABLE probe USING fts5(body)")
            _FTS5_AVAILABLE = True
        except sqlite3.Error:
            _FTS5_AVAILABLE = False
    return _FTS5_AVAILABLE


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS manuals (
    manual_key TEXT PRIMARY KEY, product TEXT NOT NULL, manual TEXT NOT NULL, version TEXT NOT NULL,
    title TEXT, reason TEXT, grp TEXT, lastmod TEXT, page_total INTEGER, page_done INTEGER,
    page_failed INTEGER, fetched_at TEXT, origin TEXT, complete INTEGER
);
CREATE TABLE IF NOT EXISTS pages (
    page_id INTEGER PRIMARY KEY, manual_key TEXT NOT NULL, page TEXT NOT NULL, url TEXT NOT NULL,
    title TEXT, lastmod TEXT, chars INTEGER
);
CREATE INDEX IF NOT EXISTS pages_by_manual ON pages(manual_key);
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id INTEGER PRIMARY KEY, page_id INTEGER NOT NULL, manual_key TEXT NOT NULL, ordinal INTEGER,
    title TEXT, heading TEXT, body TEXT
);
CREATE INDEX IF NOT EXISTS chunks_by_page ON chunks(page_id);
CREATE INDEX IF NOT EXISTS chunks_by_manual ON chunks(manual_key);
"""
_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    title, heading, body, content='chunks', content_rowid='chunk_id', tokenize="unicode61 tokenchars '_'"
);
CREATE TRIGGER IF NOT EXISTS chunks_fts_insert AFTER INSERT ON chunks BEGIN
    INSERT INTO chunks_fts(rowid, title, heading, body) VALUES (new.chunk_id, new.title, new.heading, new.body);
END;
CREATE TRIGGER IF NOT EXISTS chunks_fts_delete AFTER DELETE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, title, heading, body) VALUES ('delete', old.chunk_id, old.title, old.heading, old.body);
END;
"""
_DROP_FTS_TRIGGERS = "DROP TRIGGER IF EXISTS chunks_fts_insert; DROP TRIGGER IF EXISTS chunks_fts_delete;"
_CANDIDATE_COLUMNS = (
    "c.chunk_id, c.page_id, c.title, c.heading, c.body, p.url, m.product, m.version, m.title AS manual_title, m.grp"
)
_MANUAL_COLUMNS = (
    "manual_key", "product", "manual", "version", "title", "reason", "grp", "lastmod",
    "page_total", "page_done", "page_failed", "fetched_at", "origin", "complete",
)


class DocIndex:
    """SQLite store of documentation chunks. FTS5 ranks matches when the Python build includes it."""

    def __init__(self, path: Path, *, use_fts: Optional[bool] = None):
        self.path = Path(path)
        self.use_fts = fts5_available() if use_fts is None else bool(use_fts)
        self._ready = False
        self._write_lock = threading.Lock()

    def exists(self) -> bool:
        return self.path.exists()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        if not self._ready:
            self._init_schema(conn)
            self._ready = True
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(_SCHEMA)
        if self.use_fts:
            existed = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'chunks_fts'").fetchone() is not None
            conn.executescript(_FTS_SCHEMA)
            current = conn.execute("SELECT value FROM meta WHERE key = 'fts_current'").fetchone()
            # Chunks written while FTS5 was unavailable are missing from the index until it is rebuilt.
            if (not existed or (current and current[0] != "1")) and conn.execute("SELECT 1 FROM chunks LIMIT 1").fetchone():
                conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('rebuild')")
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('fts_current', '1')")
        else:
            conn.executescript(_DROP_FTS_TRIGGERS)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('fts_current', '0')")
        conn.commit()

    def manual_states(self) -> Dict[str, Dict[str, Any]]:
        if not self.exists():
            return {}
        with closing(self._connect()) as conn:
            return {row["manual_key"]: dict(row) for row in conn.execute("SELECT * FROM manuals")}

    @staticmethod
    def _insert_pages(conn: sqlite3.Connection, manual_key: str, pages: Iterable[Dict[str, Any]]) -> int:
        count = 0
        for page in pages:
            chunks = [(heading, body) for heading, body in page.get("chunks") or [] if str(body or "").strip()]
            if not chunks:
                continue
            cursor = conn.execute(
                "INSERT INTO pages(manual_key, page, url, title, lastmod, chars) VALUES (?, ?, ?, ?, ?, ?)",
                (manual_key, page["page"], page["url"], page.get("title") or "", page.get("lastmod") or "", sum(len(body) for _, body in chunks)),
            )
            page_id = cursor.lastrowid
            conn.executemany(
                "INSERT INTO chunks(page_id, manual_key, ordinal, title, heading, body) VALUES (?, ?, ?, ?, ?, ?)",
                [(page_id, manual_key, ordinal, page.get("title") or "", heading, body) for ordinal, (heading, body) in enumerate(chunks)],
            )
            count += 1
        return count

    @staticmethod
    def _delete_manuals(conn: sqlite3.Connection, keys: Sequence[str]) -> None:
        for key in keys:
            conn.execute("DELETE FROM chunks WHERE manual_key = ?", (key,))
            conn.execute("DELETE FROM pages WHERE manual_key = ?", (key,))
            conn.execute("DELETE FROM manuals WHERE manual_key = ?", (key,))

    @staticmethod
    def _upsert_manual(conn: sqlite3.Connection, record: Dict[str, Any]) -> None:
        conn.execute(
            f"INSERT OR REPLACE INTO manuals({', '.join(_MANUAL_COLUMNS)}) VALUES ({', '.join('?' for _ in _MANUAL_COLUMNS)})",
            tuple(record.get(column) for column in _MANUAL_COLUMNS),
        )

    def replace_manual(self, manual: Dict[str, Any], pages: List[Dict[str, Any]], *, failed: int, complete: bool) -> int:
        with self._write_lock, closing(self._connect()) as conn, conn:
            self._delete_manuals(conn, [manual["key"]])
            stored = self._insert_pages(conn, manual["key"], pages)
            self._upsert_manual(conn, {
                "manual_key": manual["key"],
                "product": manual["product"],
                "manual": manual["manual"],
                "version": manual["version"],
                "title": manual.get("title") or "",
                "reason": manual.get("reason") or "",
                "grp": manual.get("group") or "",
                "lastmod": manual.get("lastmod") or "",
                "page_total": len(manual.get("pages") or []),
                "page_done": stored,
                "page_failed": failed,
                "fetched_at": utc_now_iso(),
                "origin": "online",
                "complete": 1 if complete else 0,
            })
            return stored

    def remove_manuals(self, keys: Sequence[str]) -> int:
        if not keys or not self.exists():
            return 0
        with self._write_lock, closing(self._connect()) as conn, conn:
            self._delete_manuals(conn, list(keys))
        return len(keys)

    def replace_all(self, manuals: List[Dict[str, Any]], pages_by_manual: Dict[str, List[Dict[str, Any]]], *, origin: str) -> int:
        stored = 0
        with self._write_lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM chunks")
            conn.execute("DELETE FROM pages")
            conn.execute("DELETE FROM manuals")
            for manual in manuals:
                count = self._insert_pages(conn, manual["manual_key"], pages_by_manual.get(manual["manual_key"]) or [])
                stored += count
                self._upsert_manual(conn, {**manual, "page_done": count, "origin": origin})
        return stored

    def summary(self) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "available": False,
            "search_engine": "fts5" if self.use_fts else "python",
            "manuals": 0,
            "pages": 0,
            "chunks": 0,
            "groups": [],
            "last_fetched_at": "",
            "size_bytes": 0,
        }
        if not self.exists():
            return base
        with closing(self._connect()) as conn:
            pages = conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
            chunks = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            manuals = conn.execute("SELECT COUNT(*) FROM manuals WHERE page_done > 0").fetchone()[0]
            last = conn.execute("SELECT MAX(fetched_at) FROM manuals").fetchone()[0] or ""
            groups = [
                {"label": row["grp"] or row["product"], "manuals": row["manuals"], "pages": row["pages"] or 0, "origin": row["origin"] or "online"}
                for row in conn.execute(
                    "SELECT grp, product, MAX(origin) AS origin, COUNT(*) AS manuals, SUM(page_done) AS pages "
                    "FROM manuals WHERE page_done > 0 GROUP BY grp, product ORDER BY pages DESC"
                )
            ]
        size = sum(candidate.stat().st_size for candidate in (self.path, Path(f"{self.path}-wal")) if candidate.exists())
        return {**base, "available": pages > 0, "manuals": manuals, "pages": pages, "chunks": chunks, "groups": groups, "last_fetched_at": last, "size_bytes": size}

    def search_candidates(self, terms: Sequence[str], limit: int = SEARCH_CANDIDATES) -> List[Dict[str, Any]]:
        terms = [term for term in terms if re.fullmatch(r"[a-z0-9_]+", term)]
        if not terms or not self.exists():
            return []
        with closing(self._connect()) as conn:
            if self.use_fts:
                rows = conn.execute(
                    f"SELECT {_CANDIDATE_COLUMNS}, bm25(chunks_fts, 6.0, 3.0, 1.0) AS rank "
                    "FROM chunks_fts JOIN chunks c ON c.chunk_id = chunks_fts.rowid "
                    "JOIN pages p ON p.page_id = c.page_id JOIN manuals m ON m.manual_key = c.manual_key "
                    "WHERE chunks_fts MATCH ? ORDER BY rank LIMIT ?",
                    (" OR ".join(f'"{term}"' for term in terms), limit),
                ).fetchall()
                return [{**dict(row), "lexical": -float(row["rank"])} for row in rows]
            clauses = " OR ".join("(c.title LIKE ? OR c.heading LIKE ? OR c.body LIKE ?)" for _ in terms)
            params: List[Any] = [value for term in terms for value in (f"%{term}%",) * 3]
            rows = conn.execute(
                f"SELECT {_CANDIDATE_COLUMNS} FROM chunks c JOIN pages p ON p.page_id = c.page_id "
                f"JOIN manuals m ON m.manual_key = c.manual_key WHERE {clauses} LIMIT ?",
                (*params, FALLBACK_CANDIDATE_ROWS),
            ).fetchall()
        candidates = [dict(row) for row in rows]
        weighted = [tokenize(row["title"]) * 3 + tokenize(row["heading"]) * 2 + tokenize(row["body"]) for row in candidates]
        index = BM25(weighted)
        return [{**candidates[position], "lexical": score} for position, score in index.top(terms, limit)]

    def export_payload(self) -> Optional[Dict[str, Any]]:
        if not self.exists():
            return None
        with closing(self._connect()) as conn:
            manuals = [dict(row) for row in conn.execute("SELECT * FROM manuals WHERE page_done > 0 ORDER BY manual_key")]
            if not manuals:
                return None
            pages: Dict[int, Dict[str, Any]] = {}
            for row in conn.execute("SELECT page_id, manual_key, page, title, lastmod FROM pages ORDER BY page_id"):
                pages[row["page_id"]] = {"manual_key": row["manual_key"], "page": row["page"], "title": row["title"], "lastmod": row["lastmod"], "chunks": []}
            for row in conn.execute("SELECT page_id, heading, body FROM chunks ORDER BY page_id, ordinal"):
                page = pages.get(row["page_id"])
                if page is not None:
                    page["chunks"].append([row["heading"] or "", row["body"] or ""])
        return {
            "manuals": [{column: manual.get(column) for column in _MANUAL_COLUMNS if column not in {"page_done", "origin"}} for manual in manuals],
            "pages": list(pages.values()),
        }


def sanitize_docs_payload(payload: Any) -> Optional[Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]]:
    """Rebuild imported documentation from known fields; links are rebuilt from the validated page path."""
    if not isinstance(payload, dict) or not isinstance(payload.get("manuals"), list) or not isinstance(payload.get("pages"), list):
        return None
    manuals: Dict[str, Dict[str, Any]] = {}
    for raw in payload["manuals"]:
        if not isinstance(raw, dict):
            continue
        product = str(raw.get("product") or "")
        manual = str(raw.get("manual") or "")
        version = str(raw.get("version") or "")
        if product not in DOC_PRODUCTS or not manual or not all(_SEGMENT.match(part) for part in manual.split("/")) or not _DOC_VERSION.match(version):
            continue
        key = f"{product}/{manual}/{version or 'current'}"
        page_total = raw.get("page_total")
        manuals[key] = {
            "manual_key": key,
            "product": product,
            "manual": manual,
            "version": version,
            "title": _clean_text(raw.get("title"), 200) or humanize_manual(manual),
            "reason": _clean_text(raw.get("reason"), 200),
            "grp": _clean_text(raw.get("grp"), 120),
            "lastmod": _clean_text(raw.get("lastmod"), 40),
            "page_total": page_total if isinstance(page_total, int) and 0 <= page_total <= MAX_PAGES_PER_MANUAL else 0,
            "page_failed": 0,
            "fetched_at": _clean_text(raw.get("fetched_at"), 40),
            "complete": 1 if raw.get("complete") else 0,
        }
    pages_by_manual: Dict[str, List[Dict[str, Any]]] = {}
    accepted = 0
    for raw in payload["pages"]:
        if accepted >= MAX_DOC_PAGES:
            break
        if not isinstance(raw, dict):
            continue
        manual = manuals.get(str(raw.get("manual_key") or ""))
        page = str(raw.get("page") or "")
        if manual is None or (page and not all(_SEGMENT.match(part) for part in page.split("/"))):
            continue
        url = help_doc_url(manual["product"], manual["manual"], manual["version"], page)
        chunks = [
            (_clean_text(item[0], MAX_HEADING_CHARS), str(item[1])[:CHUNK_MAX_CHARS])
            for item in (raw.get("chunks") or [])[:MAX_CHUNKS_PER_PAGE]
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], str) and item[1].strip()
        ] if isinstance(raw.get("chunks"), list) else []
        if not url or not chunks:
            continue
        pages_by_manual.setdefault(manual["manual_key"], []).append({
            "page": page,
            "url": url,
            "title": _clean_text(raw.get("title"), MAX_HEADING_CHARS),
            "lastmod": _clean_text(raw.get("lastmod"), 40),
            "chunks": chunks,
        })
        accepted += 1
    kept = []
    for key, manual in manuals.items():
        stored = len(pages_by_manual.get(key) or [])
        if not stored:
            continue
        manual["page_total"] = max(manual["page_total"], stored)
        manual["page_failed"] = manual["page_total"] - stored
        kept.append(manual)
    if not kept:
        return None
    return kept, pages_by_manual


async def sync_docs(
    client: httpx.AsyncClient,
    index: DocIndex,
    plan: Dict[str, Any],
    progress: Optional[ProgressCallback] = None,
    *,
    concurrency: int = DOC_FETCH_CONCURRENCY,
    request_interval: Optional[float] = None,
) -> Dict[str, Any]:
    """Download manuals that are missing or changed since the last sync; manuals left out of the plan are removed."""
    if not plan.get("manuals"):
        raise LibrarySourceError("There is no documentation to download for this environment yet")
    interval = DOC_REQUEST_INTERVAL if request_interval is None else request_interval
    states = await asyncio.to_thread(index.manual_states)
    planned = {manual["key"] for manual in plan["manuals"]}
    removed = await asyncio.to_thread(index.remove_manuals, [key for key in states if key not in planned])
    todo = [manual for manual in plan["manuals"] if needs_fetch(manual, states.get(manual["key"]))]
    total = sum(len(manual["pages"]) for manual in todo)
    counters = {"done": 0, "fetched": 0, "failed": 0}
    errors: List[str] = []
    refusals: List[str] = []
    semaphore = asyncio.Semaphore(max(1, concurrency))
    if progress:
        progress("docs", 0, total)

    def refused() -> bool:
        return len(refusals) >= DOC_REFUSAL_LIMIT

    async def fetch_page(manual: Dict[str, Any], page: str) -> Optional[Dict[str, Any]]:
        url = help_doc_url(manual["product"], manual["manual"], manual["version"], page)
        try:
            if not url:
                raise LibrarySourceError(f"Skipped an invalid page path in {manual['title']}")
            async with semaphore:
                if refused():
                    return None
                try:
                    # help.splunk.com answers HTTP 403 to non-browser requests whose Accept header names text/html.
                    response = await _get(client, url)
                finally:
                    if interval > 0:
                        await asyncio.sleep(interval)
            content_type = response.headers.get("content-type", "").lower()
            if content_type and "html" not in content_type:
                raise LibrarySourceError(f"Skipped {url}: not an HTML page ({content_type.split(';', 1)[0]})")
            try:
                parsed, chunks = await asyncio.to_thread(_parse_and_chunk, response.text)
            except Exception as exc:  # noqa: BLE001 - one unreadable page must not stop the manual
                raise LibrarySourceError(f"Could not read {url}: {type(exc).__name__}") from exc
            if not chunks:
                raise LibrarySourceError(f"No text found on {url}")
            return {"page": page, "url": url, "title": parsed["title"] or manual["title"], "lastmod": parsed["lastmod"], "chunks": chunks}
        except LibraryRefusedError as exc:
            refusals.append(str(exc)[:240])
            return None
        except LibrarySourceError as exc:
            if len(errors) < 5:
                errors.append(str(exc)[:240])
            return None
        finally:
            counters["done"] += 1
            if progress:
                progress("docs", counters["done"], total)

    updated = 0
    for manual in todo:
        if refused():
            break
        refusals_before = len(refusals)
        results = await asyncio.gather(*(fetch_page(manual, page) for page in manual["pages"]))
        pages = [result for result in results if result]
        failed = len(results) - len(pages)
        counters["fetched"] += len(pages)
        counters["failed"] += failed
        if pages:
            # A manual that failed completely keeps its previous text and is retried on the next sync. Refused pages are
            # not broken pages, so a manual with any refusal stays incomplete and is downloaded again.
            complete = len(refusals) == refusals_before and failed <= max(2, len(manual["pages"]) // 10)
            await asyncio.to_thread(index.replace_manual, manual, pages, failed=failed, complete=complete)
            updated += 1
        if refused():
            break
        if not counters["fetched"] and counters["failed"] >= min(20, total):
            raise LibrarySourceError(f"Could not download documentation pages from help.splunk.com ({errors[0] if errors else 'no response'})")
    if refused():
        fetched = counters["fetched"]
        saved = f"{fetched:,} downloaded page{'s were' if fetched != 1 else ' was'} saved. " if fetched else ""
        raise LibrarySourceError(
            f"help.splunk.com stopped allowing documentation downloads ({refusals[0]}). {saved}"
            "The library tries again at the next scheduled refresh, or select Refresh sources later."
        )
    return {
        "status": "ok",
        "manuals_updated": updated,
        "manuals_current": len(plan["manuals"]) - len(todo),
        "manuals_removed": removed,
        "pages_fetched": counters["fetched"],
        "pages_failed": counters["failed"],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

def _snippet(body: str, terms: Sequence[str], size: int = 700) -> str:
    lowered = body.lower()
    positions = [match.start() for term in terms for match in [re.search(r"(?<![a-z0-9_])" + re.escape(term), lowered)] if match]
    start = 0
    if positions:
        start = max(0, min(positions) - 160)
        if start:
            space = body.find(" ", start)
            start = space + 1 if 0 <= space < start + 40 else start
    text = body[start:start + size].strip()
    return ("..." if start else "") + text + ("..." if start + size < len(body) else "")


def rank_doc_results(
    query: str,
    candidates: Sequence[Dict[str, Any]],
    environment: Optional[EnvironmentTerms] = None,
    *,
    limit: int = 5,
    per_page: int = 2,
    min_coverage: float = 0.0,
) -> List[Dict[str, Any]]:
    """Fuse BM25, title and heading matches, and hashed-vector similarity, then favor the user's own data."""
    terms = query_terms(query)
    if not terms or not candidates:
        return []
    query_vector = hashed_vector(query)
    query_entities = environment.mentioned_in(query) if environment else []
    details: Dict[int, Dict[str, Any]] = {}
    for row in candidates:
        heading_tokens = set(tokenize(row["title"]) + tokenize(row["heading"]))
        body_tokens = tokenize(row["body"])
        matched = matched_terms(terms, heading_tokens | set(body_tokens))
        lowered = f"{row['title']}\n{row['heading']}\n{row['body']}".lower()
        entities = [(kind, name) for kind, name in query_entities if name in lowered]
        details[row["chunk_id"]] = {
            "row": row,
            "matched": matched,
            "heading_hits": [term for term in terms if term in heading_tokens],
            "vector": cosine(query_vector, hashed_vector(f"{row['title']} {row['heading']} {row['body']}")),
            "entities": entities,
            "coverage": len(matched) / len(terms),
        }
    lexical_order = [row["chunk_id"] for row in sorted(candidates, key=lambda row: -row["lexical"])]
    lexical_rank = {key: position for position, key in enumerate(lexical_order)}
    heading_order = sorted(details, key=lambda key: (-len(details[key]["heading_hits"]), lexical_rank[key]))
    vector_order = sorted(details, key=lambda key: (-details[key]["vector"], lexical_rank[key]))
    fused = reciprocal_rank_fusion([(lexical_order, FUSION_WEIGHTS[0]), (heading_order, FUSION_WEIGHTS[1]), (vector_order, FUSION_WEIGHTS[2])])
    best = best_possible_fusion(FUSION_WEIGHTS)
    final = {
        key: fused[key] * (1 + min(0.4, 0.2 * len(info["entities"]))) * coverage_weight(info["coverage"])
        for key, info in details.items()
    }
    ranked = sorted(details, key=lambda key: (-final[key], lexical_rank[key]))
    results: List[Dict[str, Any]] = []
    per_page_counts: Dict[int, int] = {}
    for key in ranked:
        info = details[key]
        if info["coverage"] < min_coverage:
            continue
        row = info["row"]
        if per_page_counts.get(row["page_id"], 0) >= per_page:
            continue
        per_page_counts[row["page_id"]] = per_page_counts.get(row["page_id"], 0) + 1
        boosted = final[key]
        why = [f"Matches {', '.join(info['matched'][:6])}"] if info["matched"] else []
        if info["heading_hits"]:
            why.append("Title or heading match")
        why.extend(f"Mentions your {kind} {name}" for kind, name in info["entities"][:2])
        if row.get("grp"):
            why.append(f"{row['grp']} documentation")
        heading = row["heading"] or ""
        results.append({
            "id": f"doc:{row['chunk_id']}",
            "kind": "splunk_docs",
            "title": row["title"],
            "heading": heading,
            "label": f"{row['title']} > {heading}" if heading and heading != row["title"] else row["title"],
            "manual": row["manual_title"],
            "group": row.get("grp") or "",
            "product": row["product"],
            "version": row["version"],
            "url": row["url"],
            "snippet": _snippet(row["body"], info["matched"] or terms),
            "context": _snippet(row["body"], info["matched"] or terms, size=CONTEXT_CHARS),
            "score": max(1, min(100, int(round(100 * boosted / best)))),
            "matched_terms": info["matched"],
            "why": why,
        })
        if len(results) >= limit:
            break
    return results
