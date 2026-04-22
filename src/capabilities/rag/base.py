"""Base interface for RAG capability providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class RetrievalChunk:
    """Single retrieved chunk returned by a RAG provider."""

    source: str
    score: int
    snippet: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "score": self.score,
            "snippet": self.snippet,
            "metadata": dict(self.metadata),
        }


class BaseRAGProvider(ABC):
    """Abstract base for optional retrieval providers."""

    @abstractmethod
    def get_context(self, user_message: str, max_chunks: int = 3) -> Dict[str, Any]:
        raise NotImplementedError
