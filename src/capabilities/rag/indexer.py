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
from capabilities.rag.base import RetrievalChunk


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    def name(self) -> str:
        return "dt4sms_hash_embedding"

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

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition):
        self.config = config
        self.definition = definition

    def get_source_dir(self) -> Path:
        return Path(str(self.config.config.get("source_dir") or self.definition.default_config.get("source_dir") or "output"))

    def get_storage_dir(self) -> Path:
        return Path(str(self.config.config.get("storage_dir") or self.definition.default_config.get("storage_dir") or "output/rag/chromadb"))

    def get_collection_name(self) -> str:
        raw_prefix = str(self.config.config.get("collection_prefix") or self.definition.default_config.get("collection_prefix") or "dt4sms")
        cleaned_prefix = re.sub(r"[^a-z0-9_]+", "_", raw_prefix.lower()).strip("_") or "dt4sms"
        return f"{cleaned_prefix}_artifact_rag"

    def get_summary_path(self) -> Path:
        return self.get_storage_dir() / self.SUMMARY_FILENAME

    def get_index_summary(self) -> Dict[str, Any]:
        summary_path = self.get_summary_path()
        if not summary_path.exists():
            return {
                "collection_name": self.get_collection_name(),
                "storage_dir": str(self.get_storage_dir()),
                "source_dir": str(self.get_source_dir()),
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
                "document_count": 0,
                "source_file_count": 0,
                "source_type_counts": {},
                "sample_sources": [],
                "last_indexed_at": None,
                "error": "Failed to parse stored index summary.",
            }

    def collect_documents(self) -> List[IndexedArtifactDocument]:
        source_dir = self.get_source_dir()
        storage_dir = self.get_storage_dir()
        if not source_dir.exists():
            return []

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
            documents.extend(self._documents_from_path(file_path, source_dir))
            if len(documents) >= max_documents:
                break

        return documents[:max_documents]

    def reindex(self) -> Dict[str, Any]:
        documents = self.collect_documents()
        storage_dir = self.get_storage_dir()
        storage_dir.mkdir(parents=True, exist_ok=True)

        summary = {
            "collection_name": self.get_collection_name(),
            "storage_dir": str(storage_dir),
            "source_dir": str(self.get_source_dir()),
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
        summary = self.get_index_summary()
        if int(summary.get("document_count") or 0) <= 0:
            return self._empty_result(summary)

        storage_dir = self.get_storage_dir()
        if not storage_dir.exists():
            return self._empty_result(summary)

        from chromadb import PersistentClient

        client = PersistentClient(path=str(storage_dir))
        try:
            collection = client.get_collection(
                name=self.get_collection_name(),
                embedding_function=HashEmbeddingFunction(),
            )
        except Exception:
            return self._empty_result(summary)

        raw = collection.query(
            query_texts=[user_message],
            n_results=max(1, min(int(max_chunks or 3), 6)),
            include=["documents", "metadatas", "distances"],
        )

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
            distance = result_distances[index] if index < len(result_distances) else None
            section = str(metadata.get("section") or "").strip()
            source_name = str(metadata.get("source_name") or metadata.get("source_path") or "artifact").strip() or "artifact"
            source_label = f"{source_name} :: {section}" if section and section != source_name else source_name
            chunks.append(
                RetrievalChunk(
                    source=source_label,
                    score=self._distance_to_score(distance, index),
                    snippet=snippet.strip(),
                    metadata=metadata,
                )
            )

        if not chunks:
            return self._empty_result(summary)

        lines = ["📚 OPTIONAL CHROMADB RAG CONTEXT:"]
        for index, chunk in enumerate(chunks, 1):
            source_type = str(chunk.metadata.get("source_type") or "artifact").replace("_", " ")
            lines.append(f"{index}. [{source_type}] [{chunk.source}] {chunk.snippet}")

        return {
            "capability": self.definition.name,
            "provider": self.definition.name,
            "context_text": "\n".join(lines),
            "chunks": [chunk.to_dict() for chunk in chunks],
            "index_summary": summary,
        }

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
                    metadata={"file_type": file_path.suffix.lower()},
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