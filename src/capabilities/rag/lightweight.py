"""Lightweight local retrieval over DT4SMS artifact output."""

import re
from pathlib import Path
from typing import Any, Dict, List

from capabilities.models import CapabilityConfig, CapabilityDefinition
from capabilities.rag.base import BaseRAGProvider, RetrievalChunk


class LightweightRAGProvider(BaseRAGProvider):
    """Retrieve compact snippets from recent artifact files."""

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition):
        self.config = config
        self.definition = definition

    def get_context(self, user_message: str, max_chunks: int = 3) -> Dict[str, Any]:
        source_dir = Path(str(self.config.config.get("source_dir") or self.definition.default_config.get("source_dir") or "output"))
        if not source_dir.exists():
            return self._empty_result()

        query_terms = self._extract_query_terms(user_message)
        if not query_terms:
            return self._empty_result()

        max_files = self._safe_positive_int(self.config.config.get("max_files"), self.definition.default_config.get("max_files", 8))
        max_scan_chars = self._safe_positive_int(self.config.config.get("max_scan_chars"), self.definition.default_config.get("max_scan_chars", 12000))
        max_block_chars = self._safe_positive_int(self.config.config.get("max_block_chars"), self.definition.default_config.get("max_block_chars", 420))
        allowed_extensions = {
            str(extension).lower()
            for extension in (self.config.config.get("allowed_extensions") or self.definition.default_config.get("allowed_extensions") or [])
        }

        candidate_files = sorted(
            [path for path in source_dir.glob("*") if path.is_file() and (not allowed_extensions or path.suffix.lower() in allowed_extensions)],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:max_files]

        scored_chunks: List[RetrievalChunk] = []
        for file_path in candidate_files:
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")[:max_scan_chars]
            except Exception:
                continue

            blocks = [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]
            for block in blocks:
                lower_block = block.lower()
                hits = sum(1 for term in query_terms if term in lower_block)
                if hits <= 0:
                    continue
                scored_chunks.append(
                    RetrievalChunk(
                        source=file_path.name,
                        score=hits,
                        snippet=block[:max_block_chars],
                    )
                )

        if not scored_chunks:
            return self._empty_result()

        top_chunks = sorted(scored_chunks, key=lambda item: item.score, reverse=True)[:max(1, min(max_chunks, 6))]
        lines = ["📚 OPTIONAL LOCAL RAG CONTEXT:"]
        for index, chunk in enumerate(top_chunks, 1):
            lines.append(f"{index}. [{chunk.source}] {chunk.snippet}")

        return {
            "capability": self.definition.name,
            "provider": self.definition.name,
            "context_text": "\n".join(lines),
            "chunks": [chunk.to_dict() for chunk in top_chunks],
        }

    def _extract_query_terms(self, user_message: str) -> List[str]:
        tokens = re.findall(r"[a-zA-Z0-9_\-\.]{3,}", str(user_message or "").lower())
        stopwords = {
            "what", "when", "where", "which", "that", "this", "with", "from", "have", "used",
            "show", "list", "last", "time", "were", "been", "into", "does", "about", "splunk",
        }
        unique = []
        seen = set()
        for token in tokens:
            if token in stopwords:
                continue
            if token not in seen:
                seen.add(token)
                unique.append(token)
        return unique[:10]

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "capability": self.definition.name,
            "provider": self.definition.name,
            "context_text": "",
            "chunks": [],
        }

    def _safe_positive_int(self, value: Any, default: int) -> int:
        try:
            parsed = int(value)
            return parsed if parsed > 0 else default
        except (TypeError, ValueError):
            return default