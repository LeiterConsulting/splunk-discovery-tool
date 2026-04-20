"""Chroma-backed RAG provider for indexed DT4SMS artifacts."""

from typing import Any, Dict

from capabilities.models import CapabilityConfig, CapabilityDefinition
from capabilities.rag.base import BaseRAGProvider
from capabilities.rag.indexer import ArtifactSourceIndexer


class ChromaRAGProvider(BaseRAGProvider):
    """Retrieve context from a persistent Chroma collection built from DT4SMS artifacts."""

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition):
        self.config = config
        self.definition = definition
        self.indexer = ArtifactSourceIndexer(config=config, definition=definition)

    def get_context(self, user_message: str, max_chunks: int = 3) -> Dict[str, Any]:
        return self.indexer.search(user_message=user_message, max_chunks=max_chunks)

    def reindex(self) -> Dict[str, Any]:
        return self.indexer.reindex()

    def get_index_summary(self) -> Dict[str, Any]:
        return self.indexer.get_index_summary()