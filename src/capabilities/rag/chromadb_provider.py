"""Chroma-backed RAG provider for indexed DT4SMS artifacts."""

from typing import Any, Dict, Optional

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

    def get_knowledge_asset_summary(self) -> Dict[str, Any]:
        return self.indexer.get_knowledge_asset_summary()

    def list_managed_assets(self) -> Dict[str, Any]:
        return self.indexer.list_managed_assets()

    def get_managed_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.indexer.get_managed_asset_detail(asset_id)

    def import_text_asset(self, **kwargs: Any) -> Dict[str, Any]:
        return self.indexer.import_knowledge_asset_text(**kwargs)

    def import_file_asset(self, **kwargs: Any) -> Dict[str, Any]:
        return self.indexer.import_knowledge_asset_file(**kwargs)

    def delete_managed_asset(self, asset_id: str, auto_reindex: bool = False) -> Dict[str, Any]:
        return self.indexer.delete_knowledge_asset(asset_id=asset_id, auto_reindex=auto_reindex)

    def check_in_managed_asset(self, asset_id: str, auto_reindex: bool = False) -> Dict[str, Any]:
        return self.indexer.check_in_knowledge_asset(asset_id=asset_id, auto_reindex=auto_reindex)

    def check_out_managed_asset(self, asset_id: str, auto_reindex: bool = False) -> Dict[str, Any]:
        return self.indexer.check_out_knowledge_asset(asset_id=asset_id, auto_reindex=auto_reindex)

    def build_context_preview(self, query: str, max_chunks: int = 4) -> Dict[str, Any]:
        return self.indexer.build_context_preview(query=query, max_chunks=max_chunks)