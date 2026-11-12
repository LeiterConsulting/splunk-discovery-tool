"""Lexical retrieval helpers shared by the documentation index and the Knowledge Base.

Two lexical views of each candidate (BM25 term weighting and a hashed bag-of-words vector) are fused with
reciprocal rank fusion, then nudged by what discovery found in the environment.
"""

import hashlib
import math
import re
from collections import Counter
from typing import Any, Dict, Hashable, Iterable, List, Optional, Sequence, Tuple

# Matches the FTS5 unicode61 tokenizer with tokenchars '_': dots, colons, and dashes split words.
TOKEN_PATTERN = re.compile(r"[a-z0-9_]+")
STOPWORDS = frozenset(
    """
    a about all also an and any are as at be been but by can could do does for from get give had has have how
    i if in into is it its just know like list look many me more most much my need no not of on or our please
    see should show so some tell than that the their them then there these they this to up us use using via vs
    want was we what when where which who why will with would you your
    """.split()
)
MAX_QUERY_TERMS = 12
RRF_K = 60
HASH_DIMENSIONS = 192
_HASH_TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_\-.]{2,}")
# Index names such as main or summary are ordinary words in documentation, so they never count as a match.
_GENERIC_ENTITY_NAMES = frozenset({"main", "summary", "history", "default", "search", "test", "data", "events", "metrics"})


def tokenize(text: Any) -> List[str]:
    return TOKEN_PATTERN.findall(str(text or "").lower())


def query_terms(text: Any, limit: int = MAX_QUERY_TERMS) -> List[str]:
    terms: List[str] = []
    for token in tokenize(text):
        if len(token) < 2 or token in STOPWORDS or token in terms:
            continue
        terms.append(token)
        if len(terms) >= limit:
            break
    return terms


def hashed_vector(text: Any, dimensions: int = HASH_DIMENSIONS) -> List[float]:
    """Deterministic hashed bag-of-words vector; the Knowledge Base stores these in Chroma."""
    vector = [0.0] * dimensions
    tokens = _HASH_TOKEN_PATTERN.findall(str(text or "").lower())[:400]
    if not tokens:
        return vector
    for token in tokens:
        digest = hashlib.sha1(token.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:2], byteorder="big") % dimensions
        sign = 1.0 if digest[2] % 2 == 0 else -1.0
        weight = 1.5 if any(char.isdigit() for char in token) or "_" in token or ":" in token else 1.0
        vector[bucket] += sign * weight
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return [value / norm for value in vector]


def cosine(left: Sequence[float], right: Sequence[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


class BM25:
    """Okapi BM25 over pre-tokenized documents, with postings so a query only touches matching documents."""

    def __init__(self, documents: Sequence[Sequence[str]], k1: float = 1.2, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.size = len(documents)
        self.lengths = [len(doc) for doc in documents]
        self.average_length = (sum(self.lengths) / self.size) if self.size else 0.0
        self.postings: Dict[str, List[Tuple[int, int]]] = {}
        for index, doc in enumerate(documents):
            for term, count in Counter(doc).items():
                self.postings.setdefault(term, []).append((index, count))

    def idf(self, term: str) -> float:
        frequency = len(self.postings.get(term) or ())
        return math.log(1 + (self.size - frequency + 0.5) / (frequency + 0.5)) if frequency else 0.0

    def scores(self, terms: Iterable[str]) -> Dict[int, float]:
        result: Dict[int, float] = {}
        average = self.average_length or 1.0
        for term in set(terms):
            postings = self.postings.get(term)
            if not postings:
                continue
            idf = self.idf(term)
            for index, count in postings:
                denominator = count + self.k1 * (1 - self.b + self.b * self.lengths[index] / average)
                result[index] = result.get(index, 0.0) + idf * count * (self.k1 + 1) / denominator
        return result

    def top(self, terms: Iterable[str], limit: int) -> List[Tuple[int, float]]:
        return sorted(self.scores(terms).items(), key=lambda item: (-item[1], item[0]))[:limit]


def reciprocal_rank_fusion(rankings: Iterable[Tuple[Sequence[Hashable], float]], k: int = RRF_K) -> Dict[Hashable, float]:
    fused: Dict[Hashable, float] = {}
    for ranked, weight in rankings:
        for position, key in enumerate(ranked):
            fused[key] = fused.get(key, 0.0) + weight / (k + position + 1)
    return fused


def best_possible_fusion(weights: Iterable[float], k: int = RRF_K) -> float:
    return sum(weights) / (k + 1)


def coverage_weight(coverage: float) -> float:
    """Fusion only orders candidates against each other; this keeps a match on one of several query terms from scoring high."""
    return 0.2 + 0.8 * max(0.0, min(1.0, coverage))


def _entity_pattern(name: str) -> re.Pattern:
    return re.compile(r"(?<![\w:.-])" + re.escape(name) + r"(?![\w:-])")


class EnvironmentTerms:
    """Sourcetype, index, and app names from discovery, used to favor results about the user's own data."""

    def __init__(self, sourcetypes: Iterable[str] = (), indexes: Iterable[str] = (), apps: Iterable[str] = ()):
        self.entities: List[Tuple[str, str, re.Pattern]] = []
        seen = set()
        for kind, names in (("sourcetype", sourcetypes), ("index", indexes), ("app", apps)):
            for raw in names:
                name = str(raw or "").strip().lower()
                if len(name) < 4 or name in _GENERIC_ENTITY_NAMES or name in STOPWORDS or (kind, name) in seen:
                    continue
                seen.add((kind, name))
                self.entities.append((kind, name, _entity_pattern(name)))

    @classmethod
    def from_profile(cls, profile: Optional[Dict[str, Any]]) -> "EnvironmentTerms":
        profile = profile if isinstance(profile, dict) and profile.get("available") else {}
        apps = []
        for app in (profile.get("apps") or {}).get("items") or []:
            if not app.get("builtin"):
                apps.extend([app.get("name"), app.get("label")])
        return cls(
            sourcetypes=[row.get("name") for row in profile.get("sourcetypes") or [] if isinstance(row, dict)],
            indexes=profile.get("indexes") or [],
            apps=apps,
        )

    def mentioned_in(self, text: Any) -> List[Tuple[str, str]]:
        lowered = str(text or "").lower()
        return [(kind, name) for kind, name, pattern in self.entities if pattern.search(lowered)]


def matched_terms(terms: Sequence[str], text_tokens: Iterable[str]) -> List[str]:
    present = set(text_tokens)
    return [term for term in terms if term in present]
