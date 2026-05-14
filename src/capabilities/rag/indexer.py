"""Artifact indexing utilities for the Chroma-backed RAG provider."""

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from capabilities.models import CapabilityConfig, CapabilityDefinition
from capabilities.rag.asset_manager import KnowledgeAssetManager, normalize_knowledge_asset_attributes
from capabilities.rag.base import RetrievalChunk


QUERY_TERM_STOPWORDS = {
    "about",
    "after",
    "against",
    "between",
    "build",
    "does",
    "from",
    "into",
    "need",
    "preview",
    "question",
    "should",
    "that",
    "their",
    "them",
    "these",
    "this",
    "what",
    "when",
    "with",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_timestamp(value: Any) -> Optional[datetime]:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _safe_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _safe_relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        return path.name


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def _artifact_source_type(path: Path) -> str:
    lowered = path.name.lower()
    parent_lowered = [part.lower() for part in path.parts]
    if "chat_memory" in parent_lowered:
        return "chat_memory_derived"
    if "rag" in parent_lowered and "assets" in parent_lowered:
        return "knowledge_asset"
    if lowered.startswith("v2_operator_runbook_"):
        return "runbook"
    if lowered.startswith("v2_developer_handoff_"):
        return "handoff"
    if lowered.startswith("v2_ai_summary_") or lowered.startswith("v2_insights_brief_"):
        return "generated_summary"
    if lowered.startswith("v2_intelligence_blueprint_"):
        return "discovery_artifact"
    if lowered.startswith("discovery_sessions"):
        return "tool_result_snapshot"
    if lowered.endswith(".md") or lowered.endswith(".txt"):
        return "uploaded_document"
    return "discovery_artifact"


def _normalize_preview_text(text: Any) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _split_metadata_list(value: Any, limit: int = 8) -> List[str]:
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
        cleaned = _normalize_preview_text(raw_item).strip(" -")
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


def _split_metadata_lines(value: Any, limit: int = 8) -> List[str]:
    raw_items: List[Any]
    if isinstance(value, list):
        raw_items = list(value)
    elif value is None:
        raw_items = []
    else:
        raw_items = str(value).splitlines()

    items: List[str] = []
    seen = set()
    for raw_item in raw_items:
        cleaned = _normalize_preview_text(raw_item).strip(" -")
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


def _merge_distinct(existing: List[str], additions: List[str], limit: int) -> List[str]:
    merged = list(existing or [])
    seen = {item.lower() for item in merged if item}
    for item in additions or []:
        cleaned = _normalize_preview_text(item).strip(" -")
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        merged.append(cleaned)
        if len(merged) >= limit:
            break
    return merged


def _merge_traceable_chunk_refs(existing: List[Dict[str, Any]], additions: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = [dict(item) for item in existing or [] if isinstance(item, dict)]
    seen = set()

    for item in merged:
        document_id = str(item.get("document_id") or "").strip()
        section = _normalize_preview_text(item.get("section"))
        snippet = _normalize_preview_text(item.get("snippet"))
        key = (document_id or f"{section}|{snippet}").lower()
        if key:
            seen.add(key)

    for item in additions or []:
        if not isinstance(item, dict):
            continue
        document_id = str(item.get("document_id") or "").strip()
        section = _normalize_preview_text(item.get("section"))
        snippet = _normalize_preview_text(item.get("snippet"))
        if not document_id and not snippet:
            continue
        key = (document_id or f"{section}|{snippet}").lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "document_id": document_id,
                "section": section,
                "score": item.get("score"),
                "snippet": snippet,
                "source": _normalize_preview_text(item.get("source")),
            }
        )
        if len(merged) >= limit:
            break

    return merged


def _serialize_retrieval_chunk(chunk: RetrievalChunk) -> Dict[str, Any]:
    payload = chunk.to_dict()
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    payload["document_id"] = str(metadata.get("document_id") or "").strip()
    payload["section"] = str(metadata.get("section") or "").strip()
    payload["asset_id"] = str(metadata.get("asset_id") or "").strip()
    payload["asset_title"] = str(metadata.get("asset_title") or "").strip()
    return payload


def _safe_int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _metadata_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "known_good"}


def _join_metadata_list(items: Any, limit: int = 8) -> str:
    if not isinstance(items, list):
        return ""
    cleaned_items = [str(item).strip() for item in items if str(item).strip()]
    return ", ".join(cleaned_items[:limit])


def _extract_runtime_spl_metadata(asset: Dict[str, Any]) -> Dict[str, Any]:
    attributes = normalize_knowledge_asset_attributes(asset.get("attributes") or {})
    spl_intelligence = attributes.get("spl_intelligence") if isinstance(attributes.get("spl_intelligence"), dict) else {}
    environment_fit = spl_intelligence.get("environment_fit") if isinstance(spl_intelligence.get("environment_fit"), dict) else {}
    validation = spl_intelligence.get("validation") if isinstance(spl_intelligence.get("validation"), dict) else {}
    reuse = spl_intelligence.get("reuse") if isinstance(spl_intelligence.get("reuse"), dict) else {}

    return {
        "asset_spl_query": str(attributes.get("spl_query") or "").strip(),
        "asset_spl_intent": str(spl_intelligence.get("query_intent") or "").strip(),
        "asset_spl_commands": _join_metadata_list(spl_intelligence.get("commands") or [], limit=10),
        "asset_spl_indexes": _join_metadata_list(spl_intelligence.get("indexes") or [], limit=8),
        "asset_spl_sourcetypes": _join_metadata_list(spl_intelligence.get("sourcetypes") or [], limit=8),
        "asset_spl_hosts": _join_metadata_list(spl_intelligence.get("hosts") or [], limit=8),
        "asset_spl_sources": _join_metadata_list(spl_intelligence.get("sources") or [], limit=8),
        "asset_spl_environment_fit_status": str(environment_fit.get("status") or "").strip(),
        "asset_spl_environment_fit_score": _safe_int_value(environment_fit.get("score"), 0),
        "asset_spl_environment_fit_reason": str(environment_fit.get("reason") or "").strip(),
        "asset_spl_validation_status": str(validation.get("status") or "").strip(),
        "asset_spl_execution_count": _safe_int_value(validation.get("execution_count"), 0),
        "asset_spl_success_count": _safe_int_value(validation.get("success_count"), 0),
        "asset_spl_failure_count": _safe_int_value(validation.get("failure_count"), 0),
        "asset_spl_last_status": str(validation.get("last_status") or "").strip(),
        "asset_spl_reuse_tier": str(reuse.get("tier") or "").strip(),
        "asset_spl_reuse_score": _safe_int_value(reuse.get("score"), 0),
        "asset_spl_known_good": bool(reuse.get("known_good")) or str(validation.get("status") or "") == "known_good",
        "asset_spl_reuse_guidance": str(reuse.get("guidance") or "").strip(),
        "asset_app": str(attributes.get("app") or "").strip(),
        "asset_earliest": str(attributes.get("earliest") or "").strip(),
        "asset_latest": str(attributes.get("latest") or "").strip(),
    }


def _query_terms(text: Any) -> List[str]:
    terms: List[str] = []
    seen = set()
    for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", str(text or "").lower()):
        if token in QUERY_TERM_STOPWORDS or token in seen:
            continue
        seen.add(token)
        terms.append(token)
        if len(terms) >= 12:
            break
    return terms


@dataclass
class IndexedArtifactDocument:
    """Single text unit sent into the vector index."""

    document_id: str
    source_name: str
    source_path: str
    source_type: str
    section: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> Dict[str, Any]:
        payload = dict(self.metadata)
        payload.update(
            {
                "document_id": self.document_id,
                "source_name": self.source_name,
                "source_path": self.source_path,
                "source_type": self.source_type,
                "section": self.section,
            }
        )
        return payload


class HashEmbeddingFunction:
    """Deterministic local embedding function that avoids model downloads."""

    def __init__(self, dimensions: int = 192):
        self.dimensions = dimensions

    def __call__(self, input: List[str]) -> List[List[float]]:
        texts = input if isinstance(input, list) else [str(input)]
        return self.embed_documents(texts)

    def embed_documents(self, documents: Optional[List[str]] = None, input: Optional[List[str]] = None, **_: Any) -> List[List[float]]:
        items = documents if documents is not None else input if input is not None else []
        return [self._embed_text(text) for text in items]

    def embed_query(self, query: Optional[str] = None, input: Optional[str] = None, **_: Any) -> List[List[float]]:
        text = query if query is not None else input if input is not None else ""
        return [self._embed_text(text)]

    @staticmethod
    def name() -> str:
        return "dt4sms_hash_embedding"

    @staticmethod
    def build_from_config(config: Dict[str, Any]) -> "HashEmbeddingFunction":
        dimensions = _safe_positive_int((config or {}).get("dimensions"), 192)
        return HashEmbeddingFunction(dimensions=dimensions)

    def get_config(self) -> Dict[str, Any]:
        return {
            "dimensions": self.dimensions,
        }

    def is_legacy(self) -> bool:
        return False

    def default_space(self) -> str:
        return "cosine"

    def supported_spaces(self) -> List[str]:
        return ["cosine", "l2", "ip"]

    def _embed_text(self, text: str) -> List[float]:
        vector = [0.0] * self.dimensions
        tokens = re.findall(r"[a-zA-Z0-9_\-.]{2,}", str(text or "").lower())[:400]
        if not tokens:
            return vector

        for token in tokens:
            digest = hashlib.sha1(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:2], byteorder="big") % self.dimensions
            sign = 1.0 if digest[2] % 2 == 0 else -1.0
            weight = 1.5 if any(char.isdigit() for char in token) or "_" in token or ":" in token else 1.0
            vector[bucket] += sign * weight

        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / norm for value in vector]


class ArtifactSourceIndexer:
    """Collect and index DT4SMS artifacts into a Chroma collection."""

    SUMMARY_FILENAME = "index_summary.json"
    ASSET_MANIFEST_FILENAME = "knowledge_assets_manifest.json"
    INDEX_SCHEMA_VERSION = 2

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition):
        self.config = config
        self.definition = definition
        self._asset_metadata_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._asset_payload_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def _invalidate_asset_caches(self) -> None:
        self._asset_metadata_cache = None
        self._asset_payload_cache = None

    def get_source_dir(self) -> Path:
        return Path(str(self.config.config.get("source_dir") or self.definition.default_config.get("source_dir") or "output"))

    def get_storage_dir(self) -> Path:
        return Path(str(self.config.config.get("storage_dir") or self.definition.default_config.get("storage_dir") or "output/rag/chromadb"))

    def get_asset_dir(self) -> Path:
        configured = str(self.config.config.get("asset_dir") or "").strip()
        if configured:
            return Path(configured)
        return self.get_source_dir() / "rag" / "assets"

    def get_asset_manifest_path(self) -> Path:
        return self.get_storage_dir() / self.ASSET_MANIFEST_FILENAME

    def get_collection_name(self) -> str:
        raw_prefix = str(self.config.config.get("collection_prefix") or self.definition.default_config.get("collection_prefix") or "dt4sms")
        cleaned_prefix = re.sub(r"[^a-z0-9_]+", "_", raw_prefix.lower()).strip("_") or "dt4sms"
        return f"{cleaned_prefix}_artifact_rag"

    def get_summary_path(self) -> Path:
        return self.get_storage_dir() / self.SUMMARY_FILENAME

    def get_asset_manager(self) -> KnowledgeAssetManager:
        return KnowledgeAssetManager(
            asset_dir=self.get_asset_dir(),
            manifest_path=self.get_asset_manifest_path(),
            source_dir=self.get_source_dir(),
        )

    def get_index_summary(self) -> Dict[str, Any]:
        summary_path = self.get_summary_path()
        if not summary_path.exists():
            return {
                "collection_name": self.get_collection_name(),
                "storage_dir": str(self.get_storage_dir()),
                "source_dir": str(self.get_source_dir()),
                "index_schema_version": 0,
                "document_count": 0,
                "source_file_count": 0,
                "source_type_counts": {},
                "sample_sources": [],
                "last_indexed_at": None,
            }

        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {
                "collection_name": self.get_collection_name(),
                "storage_dir": str(self.get_storage_dir()),
                "source_dir": str(self.get_source_dir()),
                "index_schema_version": 0,
                "document_count": 0,
                "source_file_count": 0,
                "source_type_counts": {},
                "sample_sources": [],
                "last_indexed_at": None,
                "error": "Failed to parse stored index summary.",
            }

    def get_knowledge_asset_summary(self) -> Dict[str, Any]:
        summary = self.get_asset_manager().list_assets()
        summary.update(
            {
                "asset_dir": str(self.get_asset_dir()),
                "manifest_path": str(self.get_asset_manifest_path()),
            }
        )
        return summary

    def list_managed_assets(self) -> Dict[str, Any]:
        return self.get_knowledge_asset_summary()

    def get_managed_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        detail = self.get_asset_manager().get_asset_detail(asset_id)
        if detail is None:
            return None

        asset_payload = detail.get("asset") if isinstance(detail.get("asset"), dict) else {}
        content_path = self.get_asset_dir() / str(asset_payload.get("content_path") or "")
        self._invalidate_asset_caches()
        chunk_sections: List[Dict[str, Any]] = []
        if content_path.exists() and content_path.is_file():
            for document in self._documents_from_path(content_path, self.get_source_dir()):
                metadata = document.metadata if isinstance(document.metadata, dict) else {}
                if str(metadata.get("asset_id") or "").strip() != asset_id:
                    continue
                chunk_sections.append(
                    {
                        "document_id": document.document_id,
                        "section": document.section,
                        "content": document.content,
                        "character_count": len(document.content or ""),
                        "source_name": document.source_name,
                        "metadata": {
                            "source_type": metadata.get("source_type") or document.source_type,
                            "asset_type": metadata.get("asset_type") or asset_payload.get("asset_type"),
                            "asset_source_label": metadata.get("asset_source_label") or asset_payload.get("source_label"),
                        },
                    }
                )

        detail["chunk_sections"] = chunk_sections
        detail["chunk_count"] = len(chunk_sections)
        detail["index_summary"] = self.get_index_summary()
        return detail

    def _ensure_asset_index_current(self) -> Dict[str, Any]:
        asset_summary = self.get_knowledge_asset_summary()
        index_summary = self.get_index_summary()
        latest_asset_update = max(
            (
                _parse_iso_timestamp(asset.get("updated_at") or asset.get("created_at"))
                for asset in asset_summary.get("assets", [])
                if isinstance(asset, dict)
            ),
            default=None,
        )
        last_indexed_at = _parse_iso_timestamp(index_summary.get("last_indexed_at"))
        schema_version = int(index_summary.get("index_schema_version") or 0)
        if latest_asset_update and (
            last_indexed_at is None
            or latest_asset_update > last_indexed_at
            or schema_version < self.INDEX_SCHEMA_VERSION
        ):
            return self.reindex()
        return index_summary

    def collect_documents(self) -> List[IndexedArtifactDocument]:
        source_dir = self.get_source_dir()
        storage_dir = self.get_storage_dir()
        if not source_dir.exists():
            return []

        self._invalidate_asset_caches()

        allowed_extensions = {
            str(extension).lower()
            for extension in (self.config.config.get("allowed_extensions") or self.definition.default_config.get("allowed_extensions") or [".md", ".txt", ".json"])
        }
        max_files = _safe_positive_int(self.config.config.get("max_files"), self.definition.default_config.get("max_files", 24))
        max_documents = _safe_positive_int(self.config.config.get("max_documents"), self.definition.default_config.get("max_documents", 80))

        files = []
        for path in sorted(source_dir.rglob("*"), key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
            if not path.is_file():
                continue
            if allowed_extensions and path.suffix.lower() not in allowed_extensions:
                continue
            if _path_is_within(path, storage_dir):
                continue
            files.append(path)
            if len(files) >= max_files:
                break

        documents: List[IndexedArtifactDocument] = []
        for file_path in files:
            if _artifact_source_type(file_path) == "knowledge_asset":
                source_path = _safe_relative_path(file_path, source_dir)
                asset_metadata = self._knowledge_asset_metadata(source_path)
                if asset_metadata.get("asset_library_status") == "checked_out":
                    continue
            documents.extend(self._documents_from_path(file_path, source_dir))
            if len(documents) >= max_documents:
                break

        return documents[:max_documents]

    def reindex(self) -> Dict[str, Any]:
        self._invalidate_asset_caches()
        documents = self.collect_documents()
        storage_dir = self.get_storage_dir()
        storage_dir.mkdir(parents=True, exist_ok=True)

        summary = {
            "collection_name": self.get_collection_name(),
            "storage_dir": str(storage_dir),
            "source_dir": str(self.get_source_dir()),
            "index_schema_version": self.INDEX_SCHEMA_VERSION,
            "document_count": 0,
            "source_file_count": len({document.source_path for document in documents}),
            "source_type_counts": {},
            "sample_sources": sorted({document.source_name for document in documents})[:5],
            "last_indexed_at": _utc_now_iso(),
        }

        for document in documents:
            summary["source_type_counts"][document.source_type] = summary["source_type_counts"].get(document.source_type, 0) + 1

        from chromadb import PersistentClient

        client = PersistentClient(path=str(storage_dir))
        collection_name = self.get_collection_name()

        try:
            client.delete_collection(name=collection_name)
        except Exception:
            pass

        collection = client.get_or_create_collection(
            name=collection_name,
            embedding_function=HashEmbeddingFunction(),
        )

        if documents:
            collection.upsert(
                ids=[document.document_id for document in documents],
                documents=[document.content for document in documents],
                metadatas=[document.to_metadata() for document in documents],
            )

        summary["document_count"] = collection.count() if documents else 0
        self.get_summary_path().write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    def search(self, user_message: str, max_chunks: int = 3) -> Dict[str, Any]:
        summary, chunks = self._query_chunks(user_message=user_message, max_chunks=max_chunks)
        if not chunks:
            return self._empty_result(summary)

        reusable_spl_queries = self._collect_reusable_spl_queries(user_message=user_message, chunks=chunks)
        lines = ["📚 OPTIONAL CHROMADB RAG CONTEXT:"]
        for index, chunk in enumerate(chunks, 1):
            source_type = str(chunk.metadata.get("source_type") or "artifact").replace("_", " ")
            lines.append(f"{index}. [{source_type}] [{chunk.source}] {chunk.snippet}")

        if reusable_spl_queries:
            lines.extend(["", "🔁 REUSABLE SPL QUERY CANDIDATES:"])
            for index, candidate in enumerate(reusable_spl_queries, 1):
                confidence = str(candidate.get("reuse_tier") or "candidate").replace("_", " ")
                fit_status = str(candidate.get("environment_fit_status") or "unknown")
                validation_status = str(candidate.get("validation_status") or "unvalidated").replace("_", " ")
                success_count = _safe_int_value(candidate.get("success_count"), 0)
                failure_count = _safe_int_value(candidate.get("failure_count"), 0)
                lines.append(
                    f"{index}. [{confidence}] [{fit_status} fit] [{validation_status}; {success_count} success / {failure_count} failure] {candidate.get('title') or 'Saved SPL Query'}"
                )
                lines.append(f"   Query: {candidate.get('query')}")
                if candidate.get("why_reuse"):
                    lines.append(f"   Why: {candidate.get('why_reuse')}")

        return {
            "capability": self.definition.name,
            "provider": self.definition.name,
            "context_text": "\n".join(lines),
            "chunks": [_serialize_retrieval_chunk(chunk) for chunk in chunks],
            "reusable_spl_queries": reusable_spl_queries,
            "index_summary": summary,
        }

    def import_knowledge_asset_text(
        self,
        title: str,
        asset_type: str,
        content: str,
        source_label: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        auto_reindex: bool = False,
    ) -> Dict[str, Any]:
        asset = self.get_asset_manager().import_text_asset(
            title=title,
            asset_type=asset_type,
            content=content,
            source_label=source_label,
            description=description,
            tags=tags,
            attributes=attributes,
        )
        self._invalidate_asset_caches()
        index_summary = self.reindex() if auto_reindex else self.get_index_summary()
        return {
            "asset": asset.to_dict(),
            "asset_import_action": getattr(asset, "last_import_action", "created"),
            "asset_summary": self.get_knowledge_asset_summary(),
            "index_summary": index_summary,
            "auto_reindexed": bool(auto_reindex),
        }

    def import_knowledge_asset_file(
        self,
        filename: str,
        content_bytes: bytes,
        title: Optional[str] = None,
        asset_type: str = "reference_document",
        source_label: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        auto_reindex: bool = False,
    ) -> Dict[str, Any]:
        asset = self.get_asset_manager().import_file_asset(
            filename=filename,
            content_bytes=content_bytes,
            title=title,
            asset_type=asset_type,
            source_label=source_label,
            description=description,
            tags=tags,
            attributes=attributes,
        )
        self._invalidate_asset_caches()
        index_summary = self.reindex() if auto_reindex else self.get_index_summary()
        return {
            "asset": asset.to_dict(),
            "asset_import_action": getattr(asset, "last_import_action", "created"),
            "asset_summary": self.get_knowledge_asset_summary(),
            "index_summary": index_summary,
            "auto_reindexed": bool(auto_reindex),
        }

    def delete_knowledge_asset(self, asset_id: str, auto_reindex: bool = False) -> Dict[str, Any]:
        deleted = self.get_asset_manager().delete_asset(asset_id=asset_id)
        self._invalidate_asset_caches()
        if deleted is None:
            return {
                "deleted": False,
                "asset": None,
                "asset_summary": self.get_knowledge_asset_summary(),
                "index_summary": self.get_index_summary(),
                "auto_reindexed": False,
            }

        index_summary = self.reindex() if auto_reindex else self.get_index_summary()
        return {
            "deleted": True,
            "asset": deleted.to_dict(),
            "asset_summary": self.get_knowledge_asset_summary(),
            "index_summary": index_summary,
            "auto_reindexed": bool(auto_reindex),
        }

    def record_spl_query_feedback(self, query: str, status: str, feedback: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        updated_asset = self.get_asset_manager().record_spl_query_feedback(
            query=query,
            status=status,
            feedback=feedback,
        )
        self._invalidate_asset_caches()
        return {
            "found": updated_asset is not None,
            "asset": updated_asset.to_dict() if updated_asset is not None else None,
            "asset_summary": self.get_knowledge_asset_summary(),
            "index_summary": self.get_index_summary(),
            "feedback_recorded": updated_asset is not None,
        }

    def check_in_knowledge_asset(self, asset_id: str, auto_reindex: bool = False) -> Dict[str, Any]:
        return self._set_knowledge_asset_library_status(
            asset_id=asset_id,
            library_status="checked_in",
            auto_reindex=auto_reindex,
        )

    def check_out_knowledge_asset(self, asset_id: str, auto_reindex: bool = False) -> Dict[str, Any]:
        return self._set_knowledge_asset_library_status(
            asset_id=asset_id,
            library_status="checked_out",
            auto_reindex=auto_reindex,
        )

    def _set_knowledge_asset_library_status(
        self,
        asset_id: str,
        library_status: str,
        auto_reindex: bool = False,
    ) -> Dict[str, Any]:
        manager = self.get_asset_manager()
        existing_asset = manager.get_asset(asset_id)
        if existing_asset is None:
            return {
                "found": False,
                "changed": False,
                "asset": None,
                "asset_summary": self.get_knowledge_asset_summary(),
                "index_summary": self.get_index_summary(),
                "auto_reindexed": False,
            }

        if library_status == "checked_in":
            updated_asset = manager.check_in_asset(asset_id)
        else:
            updated_asset = manager.check_out_asset(asset_id)

        self._invalidate_asset_caches()
        if updated_asset is None:
            return {
                "found": False,
                "changed": False,
                "asset": None,
                "asset_summary": self.get_knowledge_asset_summary(),
                "index_summary": self.get_index_summary(),
                "auto_reindexed": False,
            }

        changed = existing_asset.library_status != updated_asset.library_status
        index_summary = self.reindex() if auto_reindex and changed else self.get_index_summary()
        return {
            "found": True,
            "changed": changed,
            "asset": updated_asset.to_dict(),
            "asset_summary": self.get_knowledge_asset_summary(),
            "index_summary": index_summary,
            "auto_reindexed": bool(auto_reindex and changed),
        }

    def build_context_preview(self, query: str, max_chunks: int = 4) -> Dict[str, Any]:
        normalized_query = str(query or "").strip()
        summary, chunks = self._query_chunks(
            user_message=normalized_query,
            max_chunks=max_chunks,
            source_type="knowledge_asset",
        )
        asset_summary = self.get_knowledge_asset_summary()
        reusable_spl_queries = self._collect_reusable_spl_queries(user_message=normalized_query, chunks=chunks)
        if not chunks:
            return {
                "query": normalized_query,
                "context_text": "",
                "operator_brief": "",
                "chunks": [],
                "matched_assets": [],
                "reusable_spl_queries": [],
                "retrieved_key_points": [],
                "recommended_uses": [],
                "coverage_gaps": [],
                "coverage_summary": {"asset_count": 0, "asset_types": [], "source_labels": [], "focus_terms": []},
                "index_summary": summary,
                "asset_summary": asset_summary,
                "message": "No indexed knowledge assets matched this query.",
            }

        query_terms = set(_query_terms(normalized_query))
        matched_assets_by_key: Dict[str, Dict[str, Any]] = {}
        serialized_chunks: List[Dict[str, Any]] = []
        lines = [f"Knowledge asset context preview for: {normalized_query}", ""]
        for index, chunk in enumerate(chunks, 1):
            serialized_chunk = _serialize_retrieval_chunk(chunk)
            serialized_chunks.append(serialized_chunk)
            metadata = serialized_chunk.get("metadata") if isinstance(serialized_chunk.get("metadata"), dict) else {}
            asset_id = str(metadata.get("asset_id") or "").strip()
            title = str(metadata.get("asset_title") or metadata.get("source_name") or chunk.source).strip()
            asset_type = str(metadata.get("asset_type") or "reference_document").strip()
            source_label = str(metadata.get("asset_source_label") or "").strip()
            focus_terms = _split_metadata_list(metadata.get("asset_focus_terms"), limit=8)
            tags = _split_metadata_list(metadata.get("asset_tags"), limit=8)
            key_points = _split_metadata_lines(metadata.get("asset_key_points"), limit=4)
            usage_guidance = _split_metadata_lines(metadata.get("asset_usage_guidance"), limit=4)
            matched_sections = _split_metadata_list(metadata.get("section"), limit=4) or [chunk.source]
            chunk_document_id = str(serialized_chunk.get("document_id") or "").strip()
            chunk_reference = {
                "document_id": chunk_document_id,
                "section": str(serialized_chunk.get("section") or chunk.source).strip(),
                "score": chunk.score,
                "snippet": chunk.snippet.strip(),
                "source": chunk.source,
            }
            overlap_terms = self._match_focus_terms(
                query_terms,
                title,
                source_label,
                focus_terms,
                tags,
                key_points,
                chunk.snippet,
            )
            lines.append(f"{index}. [{asset_type}] {title}: {chunk.snippet}")
            asset_key = asset_id or f"{title}|{asset_type}"
            asset_entry = matched_assets_by_key.get(asset_key)
            if asset_entry is None:
                asset_entry = {
                    "asset_id": asset_id,
                    "title": title,
                    "asset_type": asset_type,
                    "source_label": source_label,
                    "summary": str(metadata.get("asset_summary") or "").strip(),
                    "tags": tags,
                    "focus_terms": focus_terms,
                    "key_points": key_points,
                    "usage_guidance": usage_guidance,
                    "spl_query": str(metadata.get("asset_spl_query") or "").strip() or None,
                    "reuse_tier": str(metadata.get("asset_spl_reuse_tier") or "").strip() or None,
                    "reuse_score": _safe_int_value(metadata.get("asset_spl_reuse_score"), 0),
                    "known_good": _metadata_truthy(metadata.get("asset_spl_known_good")),
                    "validation_status": str(metadata.get("asset_spl_validation_status") or "").strip() or None,
                    "environment_fit_status": str(metadata.get("asset_spl_environment_fit_status") or "").strip() or None,
                    "environment_fit_score": _safe_int_value(metadata.get("asset_spl_environment_fit_score"), 0),
                    "environment_fit_reason": str(metadata.get("asset_spl_environment_fit_reason") or "").strip(),
                    "matched_sections": matched_sections,
                    "matched_chunk_ids": [chunk_document_id] if chunk_document_id else [],
                    "matched_chunks": _merge_traceable_chunk_refs([], [chunk_reference], limit=6),
                    "best_excerpt": chunk.snippet.strip(),
                    "best_chunk_document_id": chunk_document_id or None,
                    "match_score": chunk.score,
                    "_overlap_terms": overlap_terms,
                }
                matched_assets_by_key[asset_key] = asset_entry
            else:
                asset_entry["tags"] = _merge_distinct(asset_entry.get("tags", []), tags, limit=8)
                asset_entry["focus_terms"] = _merge_distinct(asset_entry.get("focus_terms", []), focus_terms, limit=8)
                asset_entry["key_points"] = _merge_distinct(asset_entry.get("key_points", []), key_points, limit=4)
                asset_entry["usage_guidance"] = _merge_distinct(asset_entry.get("usage_guidance", []), usage_guidance, limit=4)
                asset_entry["matched_sections"] = _merge_distinct(asset_entry.get("matched_sections", []), matched_sections, limit=4)
                asset_entry["matched_chunk_ids"] = _merge_distinct(
                    asset_entry.get("matched_chunk_ids", []),
                    [chunk_document_id] if chunk_document_id else [],
                    limit=6,
                )
                asset_entry["matched_chunks"] = _merge_traceable_chunk_refs(
                    asset_entry.get("matched_chunks", []),
                    [chunk_reference],
                    limit=6,
                )
                asset_entry["_overlap_terms"] = _merge_distinct(asset_entry.get("_overlap_terms", []), overlap_terms, limit=5)
                current_score = asset_entry.get("match_score")
                if chunk.score is not None and (current_score is None or chunk.score > current_score):
                    asset_entry["match_score"] = chunk.score
                    asset_entry["best_excerpt"] = chunk.snippet.strip()
                    asset_entry["best_chunk_document_id"] = chunk_document_id or asset_entry.get("best_chunk_document_id")

        matched_assets = sorted(
            matched_assets_by_key.values(),
            key=lambda asset: -(asset.get("match_score") or 0),
        )
        for asset in matched_assets:
            asset["why_matched"] = self._build_match_reason(
                overlap_terms=asset.get("_overlap_terms", []),
                usage_guidance=asset.get("usage_guidance", []),
                score=asset.get("match_score"),
            )
            asset.pop("_overlap_terms", None)

        brief = self._build_operator_brief(query=normalized_query, matched_assets=matched_assets)

        return {
            "query": normalized_query,
            "context_text": "\n".join(lines),
            "operator_brief": brief["text"],
            "chunks": serialized_chunks,
            "matched_assets": matched_assets,
            "reusable_spl_queries": reusable_spl_queries,
            "retrieved_key_points": brief["key_points"],
            "recommended_uses": brief["recommended_uses"],
            "coverage_gaps": brief["coverage_gaps"],
            "coverage_summary": brief["coverage_summary"],
            "index_summary": summary,
            "asset_summary": asset_summary,
            "message": f"Built context preview from {len(chunks)} indexed knowledge chunk(s).",
        }

    def _query_chunks(
        self,
        user_message: str,
        max_chunks: int = 3,
        source_type: Optional[str] = None,
    ) -> Any:
        summary = self._ensure_asset_index_current()
        if int(summary.get("document_count") or 0) <= 0:
            return summary, []

        storage_dir = self.get_storage_dir()
        if not storage_dir.exists():
            return summary, []

        from chromadb import PersistentClient

        client = PersistentClient(path=str(storage_dir))
        try:
            collection = client.get_collection(
                name=self.get_collection_name(),
                embedding_function=HashEmbeddingFunction(),
            )
        except Exception:
            return summary, []

        requested_results = max(1, min(int(max_chunks or 3), 6))
        query_kwargs: Dict[str, Any] = {
            "query_texts": [user_message],
            "n_results": max(requested_results, min(12, requested_results * 3)),
            "include": ["documents", "metadatas", "distances"],
        }
        if source_type:
            query_kwargs["where"] = {"source_type": source_type}

        raw = collection.query(**query_kwargs)

        documents = raw.get("documents", [[]])
        metadatas = raw.get("metadatas", [[]])
        distances = raw.get("distances", [[]])
        result_documents = documents[0] if documents and isinstance(documents[0], list) else []
        result_metadatas = metadatas[0] if metadatas and isinstance(metadatas[0], list) else []
        result_distances = distances[0] if distances and isinstance(distances[0], list) else []

        chunks: List[RetrievalChunk] = []
        for index, snippet in enumerate(result_documents):
            if not isinstance(snippet, str) or not snippet.strip():
                continue
            metadata = result_metadatas[index] if index < len(result_metadatas) and isinstance(result_metadatas[index], dict) else {}
            metadata = self._merge_live_asset_metadata(metadata)
            distance = result_distances[index] if index < len(result_distances) else None
            section = str(metadata.get("section") or "").strip()
            source_name = str(metadata.get("source_name") or metadata.get("source_path") or "artifact").strip() or "artifact"
            source_label = f"{source_name} :: {section}" if section and section != source_name else source_name
            base_score = self._distance_to_score(distance, index)
            reuse_bonus, reuse_reason = self._score_reusable_spl_bonus(user_message=user_message, metadata=metadata)
            if reuse_bonus:
                metadata = dict(metadata)
                metadata["asset_spl_reuse_bonus"] = reuse_bonus
                metadata["asset_spl_reuse_reason"] = reuse_reason
            chunks.append(
                RetrievalChunk(
                    source=source_label,
                    score=max(1, min(100, base_score + reuse_bonus)),
                    snippet=snippet.strip(),
                    metadata=metadata,
                )
            )
        chunks.sort(key=lambda chunk: -(chunk.score or 0))
        return summary, chunks[:requested_results]

    def _documents_from_path(self, file_path: Path, source_root: Path) -> List[IndexedArtifactDocument]:
        if file_path.suffix.lower() == ".json":
            return self._documents_from_json(file_path, source_root)
        return self._documents_from_text(file_path, source_root)

    def _documents_from_text(self, file_path: Path, source_root: Path) -> List[IndexedArtifactDocument]:
        max_scan_chars = _safe_positive_int(self.config.config.get("max_scan_chars"), self.definition.default_config.get("max_scan_chars", 16000))
        max_document_chars = _safe_positive_int(self.config.config.get("max_document_chars"), self.definition.default_config.get("max_document_chars", 1800))
        max_sections = _safe_positive_int(self.config.config.get("max_sections_per_file"), self.definition.default_config.get("max_sections_per_file", 8))

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")[:max_scan_chars]
        except Exception:
            return []

        sections = [section.strip() for section in re.split(r"\n(?=#+\s)", text) if section.strip()]
        if len(sections) <= 1:
            sections = [section.strip() for section in re.split(r"\n\s*\n", text) if section.strip()]

        source_path = _safe_relative_path(file_path, source_root)
        source_type = _artifact_source_type(file_path)
        asset_metadata = self._knowledge_asset_metadata(source_path) if source_type == "knowledge_asset" else {}
        documents: List[IndexedArtifactDocument] = []
        for index, section_text in enumerate(sections[:max_sections]):
            if len(section_text) < 40:
                continue
            lines = [line.strip() for line in section_text.splitlines() if line.strip()]
            title = lines[0].lstrip("# ").strip() if lines else file_path.stem
            content = section_text[:max_document_chars]
            documents.append(
                IndexedArtifactDocument(
                    document_id=self._document_id(source_path, f"text-{index}"),
                    source_name=file_path.name,
                    source_path=source_path,
                    source_type=source_type,
                    section=title or file_path.stem,
                    content=content,
                    metadata={
                        "file_type": file_path.suffix.lower(),
                        **asset_metadata,
                    },
                )
            )
        return documents

    def _documents_from_json(self, file_path: Path, source_root: Path) -> List[IndexedArtifactDocument]:
        max_scan_chars = _safe_positive_int(self.config.config.get("max_scan_chars"), self.definition.default_config.get("max_scan_chars", 16000))
        max_document_chars = _safe_positive_int(self.config.config.get("max_document_chars"), self.definition.default_config.get("max_document_chars", 1800))
        source_path = _safe_relative_path(file_path, source_root)
        source_type = _artifact_source_type(file_path)

        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")[:max_scan_chars]
            payload = json.loads(raw_text)
        except Exception:
            return self._documents_from_text(file_path, source_root)

        documents: List[IndexedArtifactDocument] = []
        lowered = file_path.name.lower()

        if lowered.startswith("v2_intelligence_blueprint_") and isinstance(payload, dict):
            overview = payload.get("overview", {}) if isinstance(payload.get("overview", {}), dict) else {}
            overview_text = (
                f"Splunk environment overview. Readiness score: {payload.get('readiness_score', 0)}. "
                f"Indexes: {overview.get('total_indexes', 0)}. Sourcetypes: {overview.get('total_sourcetypes', 0)}. "
                f"Hosts: {overview.get('total_hosts', 0)}. Sources: {overview.get('total_sources', 0)}. "
                f"Data volume over 24h: {overview.get('data_volume_24h', 'unknown')}. "
                f"Splunk version: {overview.get('splunk_version', 'unknown')}."
            )
            documents.append(
                IndexedArtifactDocument(
                    document_id=self._document_id(source_path, "overview"),
                    source_name=file_path.name,
                    source_path=source_path,
                    source_type=source_type,
                    section="Overview",
                    content=overview_text[:max_document_chars],
                    metadata={"file_type": ".json"},
                )
            )
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("recommendations", []), "Recommendation", ["title", "priority", "description"], max_document_chars, limit=6))
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("coverage_gaps", []), "Coverage Gap", ["gap", "priority", "why_it_matters"], max_document_chars, limit=6))
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("risk_register", []), "Risk", ["risk", "severity", "impact"], max_document_chars, limit=6))
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("suggested_use_cases", []), "Use Case", ["title", "description", "business_value"], max_document_chars, limit=5))
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("finding_ledger", []), "Finding", ["title", "findings"], max_document_chars, limit=8))
            return documents

        if lowered.startswith("v2_ai_summary_") and isinstance(payload, dict):
            ai_summary = str(payload.get("ai_summary") or "").strip()
            if ai_summary:
                documents.append(
                    IndexedArtifactDocument(
                        document_id=self._document_id(source_path, "ai-summary"),
                        source_name=file_path.name,
                        source_path=source_path,
                        source_type=source_type,
                        section="AI Summary",
                        content=ai_summary[:max_document_chars],
                        metadata={"file_type": ".json"},
                    )
                )
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("risk_register", []), "Risk", ["risk", "severity", "impact"], max_document_chars, limit=5))
            documents.extend(self._json_list_documents(source_path, file_path.name, source_type, payload.get("coverage_gaps", []), "Coverage Gap", ["gap", "priority", "why_it_matters"], max_document_chars, limit=5))
            return documents

        if lowered.startswith("discovery_sessions") and isinstance(payload, list):
            for index, session in enumerate(payload[:4]):
                if not isinstance(session, dict):
                    continue
                overview = session.get("overview", {}) if isinstance(session.get("overview", {}), dict) else {}
                session_text = (
                    f"Discovery session {session.get('timestamp', 'unknown')} created at {session.get('created_at', 'unknown')}. "
                    f"Indexes: {overview.get('total_indexes', 0)}. Sourcetypes: {overview.get('total_sourcetypes', 0)}. "
                    f"Hosts: {overview.get('total_hosts', 0)}. Splunk version: {overview.get('splunk_version', 'unknown')}."
                )
                documents.append(
                    IndexedArtifactDocument(
                        document_id=self._document_id(source_path, f"session-{index}"),
                        source_name=file_path.name,
                        source_path=source_path,
                        source_type=source_type,
                        section=f"Session {session.get('timestamp', index)}",
                        content=session_text[:max_document_chars],
                        metadata={"file_type": ".json"},
                    )
                )
            return documents

        serialized = json.dumps(payload, indent=2)[:max_document_chars]
        documents.append(
            IndexedArtifactDocument(
                document_id=self._document_id(source_path, "json-body"),
                source_name=file_path.name,
                source_path=source_path,
                source_type=source_type,
                section=file_path.stem,
                content=serialized,
                metadata={"file_type": ".json"},
            )
        )
        return documents

    def _json_list_documents(
        self,
        source_path: str,
        source_name: str,
        source_type: str,
        items: Any,
        label: str,
        fields: List[str],
        max_document_chars: int,
        limit: int,
    ) -> List[IndexedArtifactDocument]:
        if not isinstance(items, list):
            return []

        documents: List[IndexedArtifactDocument] = []
        for index, item in enumerate(items[:limit]):
            if not isinstance(item, dict):
                continue
            lines = [f"{label} {index + 1}"]
            for field in fields:
                value = item.get(field)
                if isinstance(value, list):
                    joined = "; ".join(str(entry).strip() for entry in value[:4] if str(entry).strip())
                    if joined:
                        lines.append(f"{field}: {joined}")
                elif value not in (None, ""):
                    lines.append(f"{field}: {value}")
            title = str(item.get(fields[0]) or f"{label} {index + 1}").strip()
            content = ". ".join(lines)[:max_document_chars]
            documents.append(
                IndexedArtifactDocument(
                    document_id=self._document_id(source_path, f"{label.lower()}-{index}"),
                    source_name=source_name,
                    source_path=source_path,
                    source_type=source_type,
                    section=title,
                    content=content,
                    metadata={"file_type": ".json"},
                )
            )
        return documents

    def _document_id(self, source_path: str, suffix: str) -> str:
        raw = f"{source_path}:{suffix}".encode("utf-8")
        return hashlib.sha1(raw).hexdigest()

    def _current_asset_payload_by_id(self) -> Dict[str, Dict[str, Any]]:
        if self._asset_payload_cache is None:
            self._asset_payload_cache = {}
            for asset in self.get_asset_manager().list_assets().get("assets", []):
                if not isinstance(asset, dict):
                    continue
                asset_id = str(asset.get("asset_id") or "").strip()
                if not asset_id:
                    continue
                self._asset_payload_cache[asset_id] = dict(asset)
        return self._asset_payload_cache

    def _merge_live_asset_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = str((metadata or {}).get("asset_id") or "").strip()
        if not asset_id:
            return dict(metadata or {})

        asset = self._current_asset_payload_by_id().get(asset_id)
        if not isinstance(asset, dict):
            return dict(metadata or {})

        merged = dict(metadata or {})
        merged.update(
            {
                "asset_title": str(asset.get("title") or merged.get("asset_title") or "").strip(),
                "asset_type": str(asset.get("asset_type") or merged.get("asset_type") or "reference_document").strip(),
                "asset_source_label": str(asset.get("source_label") or merged.get("asset_source_label") or "").strip(),
                "asset_summary": str(asset.get("summary") or merged.get("asset_summary") or "").strip(),
                "asset_tags": ", ".join(asset.get("tags") or []),
                "asset_focus_terms": ", ".join(asset.get("focus_terms") or []),
                "asset_key_points": "\n".join(asset.get("key_points") or []),
                "asset_usage_guidance": "\n".join(asset.get("usage_guidance") or []),
                **_extract_runtime_spl_metadata(asset),
            }
        )
        return merged

    def _score_reusable_spl_bonus(self, user_message: str, metadata: Dict[str, Any]) -> Any:
        if str(metadata.get("asset_type") or "").strip().lower() != "spl_query_library":
            return 0, ""

        query_terms = set(_query_terms(user_message))
        overlap_terms = self._match_focus_terms(
            query_terms,
            metadata.get("asset_title"),
            metadata.get("asset_source_label"),
            _split_metadata_list(metadata.get("asset_focus_terms"), limit=8),
            _split_metadata_list(metadata.get("asset_spl_indexes"), limit=8),
            _split_metadata_list(metadata.get("asset_spl_sourcetypes"), limit=8),
            metadata.get("asset_spl_query"),
            metadata.get("asset_spl_intent"),
        )

        bonus = 4
        reasons: List[str] = []
        reuse_score = _safe_int_value(metadata.get("asset_spl_reuse_score"), 0)
        fit_score = _safe_int_value(metadata.get("asset_spl_environment_fit_score"), 0)
        validation_status = str(metadata.get("asset_spl_validation_status") or "").strip().lower()

        bonus += min(16, reuse_score // 6)
        bonus += min(10, fit_score // 10)

        if _metadata_truthy(metadata.get("asset_spl_known_good")):
            bonus += 18
            reasons.append("known good in this environment")
        elif validation_status == "mixed":
            bonus += 6
            reasons.append("partially validated")
        elif validation_status == "failing":
            bonus -= 10
            reasons.append("recent failures recorded")

        if overlap_terms:
            bonus += min(14, len(overlap_terms) * 4)
            reasons.append(f"matched request terms: {', '.join(overlap_terms[:4])}")

        bonus = max(-10, min(36, bonus))
        return bonus, "; ".join(reasons[:3])

    def _collect_reusable_spl_queries(self, user_message: str, chunks: List[RetrievalChunk]) -> List[Dict[str, Any]]:
        query_terms = set(_query_terms(user_message))
        candidates: List[Dict[str, Any]] = []
        seen = set()

        for chunk in chunks:
            metadata = chunk.metadata if isinstance(chunk.metadata, dict) else {}
            if str(metadata.get("asset_type") or "").strip().lower() != "spl_query_library":
                continue
            spl_query = str(metadata.get("asset_spl_query") or "").strip()
            if not spl_query:
                continue

            asset_id = str(metadata.get("asset_id") or "").strip()
            dedupe_key = asset_id or re.sub(r"\s+", " ", spl_query).strip().lower()
            if not dedupe_key or dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            matched_terms = self._match_focus_terms(
                query_terms,
                metadata.get("asset_title"),
                metadata.get("asset_source_label"),
                _split_metadata_list(metadata.get("asset_focus_terms"), limit=8),
                _split_metadata_list(metadata.get("asset_spl_indexes"), limit=8),
                _split_metadata_list(metadata.get("asset_spl_sourcetypes"), limit=8),
                spl_query,
                metadata.get("asset_spl_intent"),
            )

            reasons: List[str] = []
            reuse_reason = str(metadata.get("asset_spl_reuse_guidance") or metadata.get("asset_spl_reuse_reason") or "").strip()
            if reuse_reason:
                reasons.append(reuse_reason)
            fit_reason = str(metadata.get("asset_spl_environment_fit_reason") or "").strip()
            if fit_reason:
                reasons.append(fit_reason)
            if matched_terms:
                reasons.append(f"Matched request terms: {', '.join(matched_terms[:4])}.")

            candidates.append(
                {
                    "asset_id": asset_id,
                    "title": str(metadata.get("asset_title") or "Saved SPL Query").strip() or "Saved SPL Query",
                    "query": spl_query,
                    "source_label": str(metadata.get("asset_source_label") or "").strip(),
                    "intent": str(metadata.get("asset_spl_intent") or "").strip(),
                    "environment_fit_status": str(metadata.get("asset_spl_environment_fit_status") or "").strip(),
                    "environment_fit_score": _safe_int_value(metadata.get("asset_spl_environment_fit_score"), 0),
                    "validation_status": str(metadata.get("asset_spl_validation_status") or "").strip(),
                    "success_count": _safe_int_value(metadata.get("asset_spl_success_count"), 0),
                    "failure_count": _safe_int_value(metadata.get("asset_spl_failure_count"), 0),
                    "reuse_tier": str(metadata.get("asset_spl_reuse_tier") or "candidate").strip(),
                    "reuse_score": _safe_int_value(metadata.get("asset_spl_reuse_score"), 0),
                    "known_good": _metadata_truthy(metadata.get("asset_spl_known_good")),
                    "why_reuse": " ".join(reasons[:3]).strip(),
                    "app": str(metadata.get("asset_app") or "").strip(),
                    "earliest": str(metadata.get("asset_earliest") or "").strip(),
                    "latest": str(metadata.get("asset_latest") or "").strip(),
                }
            )

        candidates.sort(
            key=lambda candidate: (
                -int(bool(candidate.get("known_good"))),
                -_safe_int_value(candidate.get("reuse_score"), 0),
                -_safe_int_value(candidate.get("environment_fit_score"), 0),
            )
        )
        return candidates[:3]

    def _knowledge_asset_metadata(self, source_path: str) -> Dict[str, Any]:
        if self._asset_metadata_cache is None:
            self._asset_metadata_cache = {}
            for asset in self.get_asset_manager().list_assets().get("assets", []):
                if not isinstance(asset, dict):
                    continue
                content_path = Path(str(asset.get("content_path") or "")).name
                if not content_path:
                    continue
                self._asset_metadata_cache[content_path] = {
                    "asset_id": str(asset.get("asset_id") or "").strip(),
                    "asset_title": str(asset.get("title") or "").strip(),
                    "asset_type": str(asset.get("asset_type") or "reference_document").strip(),
                    "asset_source_label": str(asset.get("source_label") or "").strip(),
                    "asset_summary": str(asset.get("summary") or "").strip(),
                    "asset_library_status": str(asset.get("library_status") or "checked_in").strip(),
                    "asset_tags": ", ".join(asset.get("tags") or []),
                    "asset_focus_terms": ", ".join(asset.get("focus_terms") or []),
                    "asset_key_points": "\n".join(asset.get("key_points") or []),
                    "asset_usage_guidance": "\n".join(asset.get("usage_guidance") or []),
                    "asset_import_method": str(asset.get("import_method") or "text").strip(),
                    "asset_original_filename": str(asset.get("original_filename") or "").strip(),
                    **_extract_runtime_spl_metadata(asset),
                }

        return dict(self._asset_metadata_cache.get(Path(source_path).name, {}))

    def _match_focus_terms(self, query_terms: Any, *candidate_groups: Any) -> List[str]:
        normalized_query_terms = set(query_terms or [])
        if not normalized_query_terms:
            return []

        matches: List[str] = []
        seen = set()
        for group in candidate_groups:
            items = group if isinstance(group, list) else [group]
            for item in items:
                for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", _normalize_preview_text(item).lower()):
                    if token in QUERY_TERM_STOPWORDS or token not in normalized_query_terms or token in seen:
                        continue
                    seen.add(token)
                    matches.append(token)
                    if len(matches) >= 5:
                        return matches
        return matches

    def _build_match_reason(self, overlap_terms: List[str], usage_guidance: List[str], score: Any) -> str:
        parts: List[str] = []
        if overlap_terms:
            parts.append(f"Matched focus terms: {', '.join(overlap_terms[:4])}.")
        if usage_guidance:
            parts.append(str(usage_guidance[0]).rstrip("." ) + ".")
        if score is not None:
            parts.append(f"Best chunk score: {score}.")
        if not parts:
            return "Matched via indexed similarity against the preview question."
        return " ".join(parts)

    def _build_operator_brief(self, query: str, matched_assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        asset_types: List[str] = []
        source_labels: List[str] = []
        focus_terms: List[str] = []
        key_points: List[str] = []
        recommended_uses: List[str] = []

        for asset in matched_assets:
            asset_types = _merge_distinct(asset_types, [str(asset.get("asset_type") or "reference_document")], limit=6)
            if asset.get("source_label"):
                source_labels = _merge_distinct(source_labels, [str(asset.get("source_label") or "")], limit=4)
            focus_terms = _merge_distinct(focus_terms, asset.get("focus_terms") or [], limit=8)
            key_points = _merge_distinct(key_points, asset.get("key_points") or [], limit=4)
            recommended_uses = _merge_distinct(recommended_uses, asset.get("usage_guidance") or [], limit=4)

        coverage_gaps = self._infer_coverage_gaps(query=query, asset_types=asset_types)
        asset_type_label = ", ".join(asset_type.replace("_", " ") for asset_type in asset_types) or "general reference context"

        lines = [
            "Operator context brief",
            "",
            f"Question: {query}",
            f"Coverage: {len(matched_assets)} asset(s) across {asset_type_label}.",
        ]
        if source_labels:
            lines.append(f"Sources: {', '.join(source_labels)}.")
        if recommended_uses:
            lines.extend(["", "How to use this context:"])
            lines.extend([f"- {item}" for item in recommended_uses[:4]])
        if key_points:
            lines.extend(["", "Key points likely to matter:"])
            lines.extend([f"- {item}" for item in key_points[:4]])
        if focus_terms:
            lines.extend(["", f"Focus terms: {', '.join(focus_terms[:8])}"])
        reusable_spl_assets = [asset for asset in matched_assets if asset.get("spl_query")]
        if reusable_spl_assets:
            lines.extend(["", "Reusable SPL candidates:"])
            for asset in reusable_spl_assets[:2]:
                tier = str(asset.get("reuse_tier") or "candidate").replace("_", " ")
                fit_status = str(asset.get("environment_fit_status") or "unknown")
                lines.append(f"- {asset.get('title')}: {tier} reuse, {fit_status} fit.")
        if coverage_gaps:
            lines.extend(["", "Potential gaps:"])
            lines.extend([f"- {item}" for item in coverage_gaps[:3]])

        return {
            "text": "\n".join(lines).strip(),
            "key_points": key_points[:4],
            "recommended_uses": recommended_uses[:4],
            "coverage_gaps": coverage_gaps[:3],
            "coverage_summary": {
                "asset_count": len(matched_assets),
                "asset_types": asset_types,
                "source_labels": source_labels,
                "focus_terms": focus_terms[:8],
            },
        }

    def _infer_coverage_gaps(self, query: str, asset_types: List[str]) -> List[str]:
        lowered_query = str(query or "").lower()
        matched_types = set(asset_types or [])
        gaps: List[str] = []

        if any(keyword in lowered_query for keyword in ("integration", "api", "dependency", "interface", "forwarder", "service")):
            if not matched_types.intersection({"integration_context", "connected_system_context", "monitored_system_context"}):
                gaps.append("No integration or system-context asset matched this question.")
        if any(keyword in lowered_query for keyword in ("runbook", "procedure", "triage", "escalat", "playbook")):
            if "runbook_context" not in matched_types:
                gaps.append("No runbook-context asset matched this question.")
        if any(keyword in lowered_query for keyword in ("splunk", "config", "setting", "feature", "search head", "indexer")):
            if "splunk_documentation" not in matched_types:
                gaps.append("No Splunk-documentation asset matched this question.")
        return _merge_distinct([], gaps, limit=3)

    def _distance_to_score(self, distance: Any, rank: int) -> int:
        try:
            numeric_distance = float(distance)
            return max(1, min(100, int(round(100 - min(numeric_distance, 2.0) * 45))))
        except (TypeError, ValueError):
            return max(1, 100 - (rank * 10))

    def _empty_result(self, summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "capability": self.definition.name,
            "provider": self.definition.name,
            "context_text": "",
            "chunks": [],
            "index_summary": summary or self.get_index_summary(),
        }