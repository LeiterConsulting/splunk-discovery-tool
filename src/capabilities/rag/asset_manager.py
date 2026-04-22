"""Managed knowledge-asset storage for RAG import and context building."""

import hashlib
from io import BytesIO
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SUPPORTED_KNOWLEDGE_ASSET_TYPES = {
    "splunk_documentation",
    "monitored_system_context",
    "connected_system_context",
    "integration_context",
    "runbook_context",
    "reference_document",
}

SUPPORTED_KNOWLEDGE_LIBRARY_STATUSES = {
    "checked_in",
    "checked_out",
}

SUPPORTED_IMPORT_SUFFIXES = {".md", ".txt", ".json", ".log", ".csv", ".pdf", ".docx"}

FOCUS_TERM_STOPWORDS = {
    "and",
    "about",
    "after",
    "are",
    "also",
    "before",
    "because",
    "between",
    "build",
    "can",
    "context",
    "document",
    "even",
    "from",
    "have",
    "into",
    "just",
    "knowledge",
    "must",
    "need",
    "note",
    "notes",
    "only",
    "other",
    "same",
    "should",
    "that",
    "the",
    "their",
    "them",
    "these",
    "this",
    "through",
    "used",
    "using",
    "what",
    "when",
    "with",
    "your",
}

ASSET_TYPE_USAGE_HINTS = {
    "splunk_documentation": [
        "Use for Splunk product behavior, configuration expectations, and platform limits.",
    ],
    "monitored_system_context": [
        "Use when the question depends on the role, behavior, or risks of a monitored system.",
    ],
    "connected_system_context": [
        "Use when upstream, downstream, or dependency context matters to the answer.",
    ],
    "integration_context": [
        "Use for interface, dependency, and data-flow questions involving connected services.",
    ],
    "runbook_context": [
        "Use for procedure, triage, escalation, and operator handoff questions.",
    ],
    "reference_document": [
        "Use as supporting reference context when no more specific asset type applies.",
    ],
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_whitespace(text: Any) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def normalize_knowledge_asset_type(value: Any) -> str:
    candidate = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    if candidate in SUPPORTED_KNOWLEDGE_ASSET_TYPES:
        return candidate
    return "reference_document"


def normalize_knowledge_asset_library_status(value: Any) -> str:
    candidate = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    if candidate in SUPPORTED_KNOWLEDGE_LIBRARY_STATUSES:
        return candidate
    return "checked_in"


def normalize_knowledge_asset_tags(value: Any) -> List[str]:
    raw_tags: List[str]
    if isinstance(value, list):
        raw_tags = [str(item) for item in value]
    else:
        raw_tags = re.split(r"[,\n]", str(value or ""))

    tags: List[str] = []
    seen = set()
    for raw_tag in raw_tags:
        cleaned = re.sub(r"\s+", " ", str(raw_tag or "").strip())
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        tags.append(cleaned)
    return tags[:12]


def _normalize_string_list(value: Any, limit: int = 6) -> List[str]:
    raw_items: List[Any]
    if isinstance(value, list):
        raw_items = list(value)
    elif value is None:
        raw_items = []
    else:
        raw_items = re.split(r"[,\n|]+", str(value))

    items: List[str] = []
    seen = set()
    for raw_item in raw_items:
        cleaned = _normalize_whitespace(raw_item).strip(" -")
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        items.append(cleaned)
        if len(items) >= limit:
            break
    return items


def _slugify(value: Any) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return slug or "knowledge-asset"


def _strip_markdown(text: str) -> str:
    cleaned = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
    cleaned = re.sub(r"^#+\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"^[-*]\s+", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", cleaned)
    return _normalize_whitespace(cleaned)


def _extract_context_body(text: str) -> str:
    raw_text = str(text or "")
    marker = "## Context"
    if marker in raw_text:
        return raw_text.split(marker, 1)[1].strip()
    return raw_text.strip()


def _build_stored_sections(text: str) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    current_title = "Overview"
    current_lines: List[str] = []

    def flush_section(title: str, lines: List[str]) -> None:
        raw_content = "\n".join(line.rstrip() for line in lines).strip()
        if not raw_content:
            return

        items: List[str] = []
        for line in lines:
            bullet_match = re.match(r"^\s*(?:[-*+]\s+|\d+\.\s+)(.+)$", line)
            if not bullet_match:
                continue
            cleaned = _normalize_whitespace(bullet_match.group(1))
            if cleaned:
                items.append(cleaned)

        sections.append(
            {
                "title": title or "Section",
                "content": raw_content,
                "items": items,
                "line_count": len([line for line in lines if str(line).strip()]),
                "character_count": len(raw_content),
            }
        )

    for raw_line in str(text or "").splitlines():
        heading_match = re.match(r"^##\s+(.*?)\s*$", raw_line)
        if raw_line.startswith("# "):
            continue
        if heading_match:
            flush_section(current_title, current_lines)
            current_title = heading_match.group(1).strip() or "Section"
            current_lines = []
            continue
        current_lines.append(raw_line)

    flush_section(current_title, current_lines)
    return sections


def _build_preview(text: str, limit: int = 220) -> str:
    cleaned = _strip_markdown(text)
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: max(40, limit - 3)].rstrip()}..."


def _extract_text_from_pdf_bytes(content_bytes: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError("PDF upload support requires the pypdf package to be installed.") from exc

    try:
        reader = PdfReader(BytesIO(content_bytes or b""))
    except Exception as exc:
        raise ValueError(f"Failed to read uploaded PDF: {exc}") from exc

    pages: List[str] = []
    for index, page in enumerate(reader.pages, start=1):
        try:
            page_text = str(page.extract_text() or "").strip()
        except Exception as exc:
            raise ValueError(f"Failed to extract text from PDF page {index}: {exc}") from exc
        if not page_text:
            continue
        normalized_page_text = re.sub(r"\n{3,}", "\n\n", page_text)
        pages.append(f"## PDF Page {index}\n{normalized_page_text}")

    if not pages:
        raise ValueError("The uploaded PDF did not contain extractable text.")
    return "\n\n".join(pages)


def _extract_text_from_docx_bytes(content_bytes: bytes) -> str:
    try:
        from docx import Document
        from docx.document import Document as DocumentType
        from docx.oxml.table import CT_Tbl
        from docx.oxml.text.paragraph import CT_P
        from docx.table import Table
        from docx.text.paragraph import Paragraph
    except ImportError as exc:
        raise ValueError("DOCX upload support requires the python-docx package to be installed.") from exc

    try:
        document = Document(BytesIO(content_bytes or b""))
    except Exception as exc:
        raise ValueError(f"Failed to read uploaded DOCX: {exc}") from exc

    def iter_blocks(parent: DocumentType) -> Any:
        for child in parent.element.body.iterchildren():
            if isinstance(child, CT_P):
                yield Paragraph(child, parent)
            elif isinstance(child, CT_Tbl):
                yield Table(child, parent)

    parts: List[str] = []
    table_index = 0
    for block in iter_blocks(document):
        if block.__class__.__name__ == "Paragraph":
            paragraph_text = _normalize_whitespace(block.text)
            if not paragraph_text:
                continue
            style_name = str(getattr(getattr(block, "style", None), "name", "") or "").strip().lower()
            if style_name.startswith("heading") or style_name == "title":
                parts.append(f"## {paragraph_text}")
            else:
                parts.append(paragraph_text)
            continue

        rows: List[str] = []
        for row in block.rows:
            cells = [_normalize_whitespace(cell.text) for cell in row.cells]
            cleaned_cells = [cell for cell in cells if cell]
            if cleaned_cells:
                rows.append(" | ".join(cleaned_cells))
        if rows:
            table_index += 1
            parts.append(f"## DOCX Table {table_index}")
            parts.extend(rows)

    if not parts:
        raise ValueError("The uploaded DOCX did not contain extractable text.")
    return "\n\n".join(parts)


def _extract_headings(text: str, limit: int = 6) -> List[str]:
    headings: List[str] = []
    for line in str(text or "").splitlines():
        candidate = None
        heading_match = re.match(r"^\s{0,3}#{1,6}\s+(.*?)\s*$", line)
        if heading_match:
            candidate = heading_match.group(1)
        else:
            stripped = line.strip()
            if stripped.endswith(":") and len(stripped) <= 80 and not stripped.startswith("{"):
                candidate = stripped.rstrip(":")

        if candidate:
            headings.extend(_normalize_string_list([candidate], limit=limit))
            if len(headings) >= limit:
                break
    return _normalize_string_list(headings, limit=limit)


def _extract_key_points(text: str, limit: int = 4) -> List[str]:
    bullet_candidates: List[str] = []
    for line in str(text or "").splitlines():
        bullet_match = re.match(r"^\s*(?:[-*+]\s+|\d+\.\s+)(.+)$", line)
        if not bullet_match:
            continue
        cleaned = _normalize_whitespace(bullet_match.group(1)).strip(".")
        if len(cleaned) >= 25:
            bullet_candidates.append(cleaned)
        if len(bullet_candidates) >= limit:
            break

    if bullet_candidates:
        return _normalize_string_list(bullet_candidates, limit=limit)

    sentences = [
        sentence.strip().rstrip(".")
        for sentence in re.split(r"(?<=[.!?])\s+", _strip_markdown(text))
        if sentence.strip() and len(sentence.strip()) >= 30
    ]
    return _normalize_string_list(sentences, limit=limit)


def _extract_focus_terms(
    title: str,
    description: str,
    source_label: str,
    tags: List[str],
    headings: List[str],
    key_points: List[str],
    content: str,
    limit: int = 8,
) -> List[str]:
    scores: Dict[str, int] = {}
    labels: Dict[str, str] = {}

    def add_phrase(value: Any, weight: int) -> None:
        cleaned = _normalize_whitespace(value).strip(".,:;")
        if not cleaned:
            return
        if len(cleaned.split()) > 4 or len(cleaned) > 32:
            return
        normalized = cleaned.lower()
        if normalized in FOCUS_TERM_STOPWORDS:
            return
        scores[normalized] = scores.get(normalized, 0) + weight
        labels.setdefault(normalized, cleaned)

    def add_tokens(value: Any, weight: int) -> None:
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", str(value or "").lower()):
            if token in FOCUS_TERM_STOPWORDS:
                continue
            scores[token] = scores.get(token, 0) + weight
            labels.setdefault(token, token)

    for tag in tags:
        add_phrase(tag, 6)
        add_tokens(tag, 4)
    for phrase, weight in ((title, 5), (source_label, 4), (description, 2)):
        add_phrase(phrase, weight)
        add_tokens(phrase, weight)
    for heading in headings:
        add_phrase(heading, 4)
        add_tokens(heading, 3)
    for point in key_points[:3]:
        add_tokens(point, 2)
    add_tokens(str(content or "")[:2000], 1)

    ranked = sorted(
        scores.items(),
        key=lambda item: (-item[1], len(labels.get(item[0], item[0])), labels.get(item[0], item[0])),
    )
    return [labels[key] for key, _ in ranked[:limit]]


def _build_usage_guidance(asset_type: str, source_label: str, tags: List[str], content: str, key_points: List[str]) -> List[str]:
    guidance: List[str] = []
    seen = set()

    def add(item: str) -> None:
        cleaned = _normalize_whitespace(item).rstrip(".")
        if not cleaned:
            return
        normalized = cleaned.lower()
        if normalized in seen:
            return
        seen.add(normalized)
        guidance.append(f"{cleaned}.")

    for base_hint in ASSET_TYPE_USAGE_HINTS.get(asset_type, []):
        add(base_hint)

    keyword_text = " ".join([source_label, " ".join(tags), " ".join(key_points[:2]), str(content or "")[:1200]]).lower()
    if any(keyword in keyword_text for keyword in ("dependency", "depends", "integration", "api", "forwarder", "certificate", "queue", "pipeline", "shared service")):
        add("Use when the assistant needs dependency or integration context")
    if any(keyword in keyword_text for keyword in ("owner", "team", "contact", "on-call", "escalat", "support group")):
        add("Use for ownership, escalation, and support-routing questions")
    if any(keyword in keyword_text for keyword in ("index", "sourcetype", "search", "savedsearch", "props", "transforms", "search head", "indexer", "cluster")):
        add("Use for Splunk platform behavior, configuration, and search workflow questions")
    if any(keyword in keyword_text for keyword in ("runbook", "validate", "triage", "procedure", "step", "response", "playbook")):
        add("Use for operator procedures, triage flow, and runbook questions")
    return guidance[:4]


def _format_token(value: Any) -> str:
    cleaned = str(value or "").strip().lower()
    if not cleaned:
        return ""
    return " ".join(part.upper() if part in {"rag", "llm", "mcp"} else part.capitalize() for part in cleaned.split("_"))


def _build_summary(
    title: str,
    asset_type: str,
    source_label: str,
    description: str,
    tags: List[str],
    key_points: List[str],
    content: str,
) -> str:
    title_text = _normalize_whitespace(title)
    description_text = _normalize_whitespace(description)
    body_text = _strip_markdown(content)
    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", body_text)
        if sentence.strip() and len(sentence.strip()) >= 30
    ]

    parts = [f"{title_text}." if title_text else "Knowledge asset."]
    if source_label:
        parts.append(f"{_format_token(asset_type)} for {source_label}.")
    else:
        parts.append(f"{_format_token(asset_type)} context.")

    if description_text:
        parts.append(f"{description_text.rstrip('.')}.")

    if key_points:
        parts.append(key_points[0].rstrip(".") + ".")
        if len(key_points) > 1 and len(" ".join(parts)) < 260:
            parts.append(key_points[1].rstrip(".") + ".")
    elif sentences:
        parts.append(sentences[0].rstrip(".") + ".")
        if len(sentences) > 1 and len(" ".join(parts)) < 260:
            parts.append(sentences[1].rstrip(".") + ".")
    elif body_text:
        parts.append(_build_preview(body_text, limit=180).rstrip(".") + ".")

    if tags:
        parts.append(f"Tags: {', '.join(tags[:5])}.")

    summary = _normalize_whitespace(" ".join(parts))
    return summary[:320].rstrip()


def _derive_asset_enrichment(
    title: str,
    asset_type: str,
    source_label: str,
    description: str,
    tags: List[str],
    content: str,
) -> Dict[str, Any]:
    normalized_content = str(content or "").strip()
    headings = _extract_headings(normalized_content)
    key_points = _extract_key_points(normalized_content)
    focus_terms = _extract_focus_terms(
        title=title,
        description=description,
        source_label=source_label,
        tags=tags,
        headings=headings,
        key_points=key_points,
        content=normalized_content,
    )
    usage_guidance = _build_usage_guidance(
        asset_type=asset_type,
        source_label=source_label,
        tags=tags,
        content=normalized_content,
        key_points=key_points,
    )
    summary = _build_summary(
        title=title,
        asset_type=asset_type,
        source_label=source_label,
        description=description,
        tags=tags,
        key_points=key_points,
        content=normalized_content,
    )
    return {
        "headings": headings,
        "key_points": key_points,
        "focus_terms": focus_terms,
        "usage_guidance": usage_guidance,
        "summary": summary,
        "preview": _build_preview(normalized_content),
    }


@dataclass
class ManagedKnowledgeAsset:
    """User-managed knowledge asset stored for retrieval use."""

    asset_id: str
    title: str
    asset_type: str
    source_label: str
    description: str
    summary: str
    preview: str
    headings: List[str] = field(default_factory=list)
    key_points: List[str] = field(default_factory=list)
    focus_terms: List[str] = field(default_factory=list)
    usage_guidance: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    library_status: str = "checked_in"
    checked_out_at: Optional[str] = None
    last_checked_in_at: Optional[str] = None
    content_path: str = ""
    import_method: str = "text"
    original_filename: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    text_char_count: int = 0
    word_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "title": self.title,
            "asset_type": self.asset_type,
            "source_label": self.source_label,
            "description": self.description,
            "summary": self.summary,
            "preview": self.preview,
            "headings": list(self.headings),
            "key_points": list(self.key_points),
            "focus_terms": list(self.focus_terms),
            "usage_guidance": list(self.usage_guidance),
            "tags": list(self.tags),
            "library_status": self.library_status,
            "checked_out_at": self.checked_out_at,
            "last_checked_in_at": self.last_checked_in_at,
            "content_path": self.content_path,
            "import_method": self.import_method,
            "original_filename": self.original_filename,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "text_char_count": self.text_char_count,
            "word_count": self.word_count,
        }


class KnowledgeAssetManager:
    """Persist and describe user-managed knowledge assets."""

    def __init__(self, asset_dir: Path, manifest_path: Path):
        self.asset_dir = asset_dir
        self.manifest_path = manifest_path

    def list_assets(self) -> Dict[str, Any]:
        assets = self._load_assets()
        asset_type_counts: Dict[str, int] = {}
        library_status_counts: Dict[str, int] = {
            "checked_in": 0,
            "checked_out": 0,
        }
        for asset in assets:
            asset_type_counts[asset.asset_type] = asset_type_counts.get(asset.asset_type, 0) + 1
            library_status_counts[asset.library_status] = library_status_counts.get(asset.library_status, 0) + 1

        return {
            "asset_count": len(assets),
            "checked_in_asset_count": library_status_counts.get("checked_in", 0),
            "checked_out_asset_count": library_status_counts.get("checked_out", 0),
            "library_status_counts": library_status_counts,
            "asset_type_counts": asset_type_counts,
            "assets": [asset.to_dict() for asset in assets],
        }

    def get_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        for asset in self._load_assets():
            if asset.asset_id == asset_id:
                return asset
        return None

    def get_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        asset = self.get_asset(asset_id)
        if asset is None:
            return None

        content_path = self.asset_dir / asset.content_path
        if not content_path.exists() or not content_path.is_file():
            return None

        stored_text = content_path.read_text(encoding="utf-8", errors="ignore")
        context_body = _extract_context_body(stored_text)
        return {
            "asset": asset.to_dict(),
            "stored_path": asset.content_path,
            "stored_sections": _build_stored_sections(stored_text),
            "context_body": context_body,
            "context_character_count": len(context_body),
        }

    def import_text_asset(
        self,
        title: str,
        asset_type: str,
        content: str,
        source_label: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        original_filename: Optional[str] = None,
        import_method: str = "text",
    ) -> ManagedKnowledgeAsset:
        normalized_title = _normalize_whitespace(title)
        normalized_content = str(content or "").strip()
        if not normalized_title:
            raise ValueError("Asset title is required.")
        if not normalized_content:
            raise ValueError("Asset content is required.")

        normalized_type = normalize_knowledge_asset_type(asset_type)
        normalized_source_label = _normalize_whitespace(source_label)
        normalized_description = _normalize_whitespace(description)
        normalized_tags = normalize_knowledge_asset_tags(tags or [])
        created_at = _utc_now_iso()
        asset_id = hashlib.sha1(f"{normalized_title}|{created_at}|{normalized_content[:200]}".encode("utf-8")).hexdigest()
        file_timestamp = created_at.replace(":", "").replace("-", "")[:15]
        filename = f"knowledge_asset_{file_timestamp}_{_slugify(original_filename or normalized_title)}.md"

        self.asset_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        content_path = self.asset_dir / filename
        enrichment = _derive_asset_enrichment(
            title=normalized_title,
            asset_type=normalized_type,
            source_label=normalized_source_label,
            description=normalized_description,
            tags=normalized_tags,
            content=normalized_content,
        )
        summary = enrichment["summary"]
        preview = enrichment["preview"]
        stored_markdown = self._build_asset_markdown(
            title=normalized_title,
            asset_type=normalized_type,
            source_label=normalized_source_label,
            description=normalized_description,
            summary=summary,
            headings=enrichment["headings"],
            key_points=enrichment["key_points"],
            focus_terms=enrichment["focus_terms"],
            usage_guidance=enrichment["usage_guidance"],
            tags=normalized_tags,
            created_at=created_at,
            content=normalized_content,
        )
        content_path.write_text(stored_markdown, encoding="utf-8")

        asset = ManagedKnowledgeAsset(
            asset_id=asset_id,
            title=normalized_title,
            asset_type=normalized_type,
            source_label=normalized_source_label,
            description=normalized_description,
            summary=summary,
            preview=preview,
            headings=enrichment["headings"],
            key_points=enrichment["key_points"],
            focus_terms=enrichment["focus_terms"],
            usage_guidance=enrichment["usage_guidance"],
            tags=normalized_tags,
            content_path=content_path.name,
            import_method=import_method,
            original_filename=original_filename,
            created_at=created_at,
            updated_at=created_at,
            text_char_count=len(normalized_content),
            word_count=len(re.findall(r"\S+", normalized_content)),
            library_status="checked_in",
            checked_out_at=None,
            last_checked_in_at=created_at,
        )

        assets = self._load_assets()
        assets.append(asset)
        self._save_assets(assets)
        return asset

    def import_file_asset(
        self,
        filename: str,
        content_bytes: bytes,
        title: Optional[str] = None,
        asset_type: str = "reference_document",
        source_label: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> ManagedKnowledgeAsset:
        safe_name = Path(str(filename or "")).name
        suffix = Path(safe_name).suffix.lower()
        if suffix and suffix not in SUPPORTED_IMPORT_SUFFIXES:
            raise ValueError("Only markdown, text, JSON, log, CSV, PDF, and DOCX assets are supported in this release.")

        if suffix == ".pdf":
            content_text = _extract_text_from_pdf_bytes(content_bytes)
        elif suffix == ".docx":
            content_text = _extract_text_from_docx_bytes(content_bytes)
        else:
            try:
                content_text = (content_bytes or b"").decode("utf-8", errors="ignore")
            except Exception as exc:
                raise ValueError(f"Failed to decode uploaded asset: {exc}") from exc

        normalized_title = title or Path(safe_name).stem or "Imported Knowledge Asset"
        return self.import_text_asset(
            title=normalized_title,
            asset_type=asset_type,
            content=content_text,
            source_label=source_label,
            description=description,
            tags=tags,
            original_filename=safe_name or None,
            import_method="file_upload",
        )

    def delete_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        assets = self._load_assets()
        remaining: List[ManagedKnowledgeAsset] = []
        deleted: Optional[ManagedKnowledgeAsset] = None

        for asset in assets:
            if asset.asset_id == asset_id and deleted is None:
                deleted = asset
                continue
            remaining.append(asset)

        if deleted is None:
            return None

        asset_path = self.asset_dir / deleted.content_path
        if asset_path.exists() and asset_path.is_file():
            asset_path.unlink()
        self._save_assets(remaining)
        return deleted

    def check_in_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        return self._set_asset_library_status(asset_id, "checked_in")

    def check_out_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        return self._set_asset_library_status(asset_id, "checked_out")

    def _set_asset_library_status(self, asset_id: str, library_status: str) -> Optional[ManagedKnowledgeAsset]:
        normalized_status = normalize_knowledge_asset_library_status(library_status)
        assets = self._load_assets()
        updated_asset: Optional[ManagedKnowledgeAsset] = None
        next_assets: List[ManagedKnowledgeAsset] = []

        for asset in assets:
            if asset.asset_id != asset_id or updated_asset is not None:
                next_assets.append(asset)
                continue

            if asset.library_status == normalized_status:
                updated_asset = asset
                next_assets.append(asset)
                continue

            updated_at = _utc_now_iso()
            payload = asset.to_dict()
            payload.update(
                {
                    "library_status": normalized_status,
                    "updated_at": updated_at,
                    "checked_out_at": updated_at if normalized_status == "checked_out" else None,
                    "last_checked_in_at": updated_at if normalized_status == "checked_in" else asset.last_checked_in_at,
                }
            )
            updated_asset = ManagedKnowledgeAsset(**payload)
            next_assets.append(updated_asset)

        if updated_asset is None:
            return None

        self._save_assets(next_assets)
        return updated_asset

    def _build_asset_markdown(
        self,
        title: str,
        asset_type: str,
        source_label: str,
        description: str,
        summary: str,
        headings: List[str],
        key_points: List[str],
        focus_terms: List[str],
        usage_guidance: List[str],
        tags: List[str],
        created_at: str,
        content: str,
    ) -> str:
        lines = [f"# {title}", ""]
        lines.append(f"Asset Type: {asset_type}")
        if source_label:
            lines.append(f"Source Label: {source_label}")
        if tags:
            lines.append(f"Tags: {', '.join(tags)}")
        lines.append(f"Imported At: {created_at}")
        lines.append("")
        if description:
            lines.extend(["## Description", "", description, ""])
        if focus_terms:
            lines.extend(["## Focus Terms", ""])
            lines.extend([f"- {term}" for term in focus_terms])
            lines.append("")
        if key_points:
            lines.extend(["## Key Points", ""])
            lines.extend([f"- {point}" for point in key_points])
            lines.append("")
        if usage_guidance:
            lines.extend(["## Suggested Use", ""])
            lines.extend([f"- {item}" for item in usage_guidance])
            lines.append("")
        if headings:
            lines.extend(["## Headings", ""])
            lines.extend([f"- {heading}" for heading in headings])
            lines.append("")
        lines.extend(["## Summary", "", summary, "", "## Context", "", content.strip(), ""])
        return "\n".join(lines)

    def _load_assets(self) -> List[ManagedKnowledgeAsset]:
        if not self.manifest_path.exists():
            return []
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return []

        items = payload.get("assets", []) if isinstance(payload, dict) else []
        assets: List[ManagedKnowledgeAsset] = []
        manifest_changed = False
        for item in items:
            if not isinstance(item, dict):
                manifest_changed = True
                continue
            content_path = self.asset_dir / str(item.get("content_path") or "")
            if not content_path.exists() or not content_path.is_file():
                manifest_changed = True
                continue
            try:
                title = str(item.get("title") or "Knowledge Asset")
                asset_type = normalize_knowledge_asset_type(item.get("asset_type"))
                source_label = str(item.get("source_label") or "")
                description = str(item.get("description") or "")
                tags = normalize_knowledge_asset_tags(item.get("tags") or [])
                stored_text = content_path.read_text(encoding="utf-8", errors="ignore")
                asset_content = _extract_context_body(stored_text) or stored_text
                created_at = str(item.get("created_at") or item.get("updated_at") or _utc_now_iso())
                updated_at = str(item.get("updated_at") or created_at)
                raw_library_status = str(item.get("library_status") or "").strip()
                library_status = normalize_knowledge_asset_library_status(raw_library_status)
                checked_out_at = str(item.get("checked_out_at") or "").strip() or None
                last_checked_in_at = str(item.get("last_checked_in_at") or "").strip() or None
                if not raw_library_status or library_status != raw_library_status.replace("-", "_").lower():
                    manifest_changed = True
                if library_status == "checked_out" and checked_out_at is None:
                    checked_out_at = updated_at
                    manifest_changed = True
                if library_status == "checked_in" and last_checked_in_at is None:
                    last_checked_in_at = updated_at
                    manifest_changed = True
                enrichment = _derive_asset_enrichment(
                    title=title,
                    asset_type=asset_type,
                    source_label=source_label,
                    description=description,
                    tags=tags,
                    content=asset_content,
                )
                headings = enrichment["headings"]
                key_points = enrichment["key_points"]
                focus_terms = enrichment["focus_terms"]
                usage_guidance = enrichment["usage_guidance"]
                summary = enrichment["summary"]
                preview = enrichment["preview"]
                rebuilt_markdown = self._build_asset_markdown(
                    title=title,
                    asset_type=asset_type,
                    source_label=source_label,
                    description=description,
                    summary=summary,
                    headings=headings,
                    key_points=key_points,
                    focus_terms=focus_terms,
                    usage_guidance=usage_guidance,
                    tags=tags,
                    created_at=created_at,
                    content=asset_content,
                )
                derived_changed = (
                    _normalize_string_list(item.get("headings"), limit=6) != headings
                    or _normalize_string_list(item.get("key_points"), limit=4) != key_points
                    or _normalize_string_list(item.get("focus_terms"), limit=8) != focus_terms
                    or _normalize_string_list(item.get("usage_guidance"), limit=4) != usage_guidance
                    or _normalize_whitespace(item.get("summary")) != summary
                    or _normalize_whitespace(item.get("preview")) != preview
                    or stored_text != rebuilt_markdown
                )
                if derived_changed:
                    updated_at = _utc_now_iso()
                    content_path.write_text(rebuilt_markdown, encoding="utf-8")
                    manifest_changed = True
                assets.append(ManagedKnowledgeAsset(
                    asset_id=str(item.get("asset_id") or ""),
                    title=title,
                    asset_type=asset_type,
                    source_label=source_label,
                    description=description,
                    summary=summary,
                    preview=preview,
                    headings=headings,
                    key_points=key_points,
                    focus_terms=focus_terms,
                    usage_guidance=usage_guidance,
                    tags=tags,
                    library_status=library_status,
                    checked_out_at=checked_out_at,
                    last_checked_in_at=last_checked_in_at,
                    content_path=content_path.name,
                    import_method=str(item.get("import_method") or "text"),
                    original_filename=item.get("original_filename"),
                    created_at=created_at,
                    updated_at=updated_at,
                    text_char_count=int(item.get("text_char_count") or len(asset_content)),
                    word_count=int(item.get("word_count") or len(re.findall(r"\S+", asset_content))),
                ))
            except Exception:
                manifest_changed = True

        assets.sort(key=lambda asset: asset.updated_at or asset.created_at, reverse=True)
        if manifest_changed:
            self._save_assets(assets)
        return assets

    def _save_assets(self, assets: List[ManagedKnowledgeAsset]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(
            json.dumps({"assets": [asset.to_dict() for asset in assets]}, indent=2),
            encoding="utf-8",
        )