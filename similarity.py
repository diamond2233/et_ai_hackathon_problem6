"""Layer 2: campaign fingerprinting via TF-IDF cosine similarity.

Why TF-IDF and not a transformer embedding model: the corpus is small and
domain-specific, the vectoriser fits in under 50 ms at boot, it needs no GPU, no
model download and no API call, and — critically for a public-safety tool — the
match is inspectable. We can show an investigator exactly which terms drove the
match. A 90 MB sentence-transformer would score marginally better on paraphrase
and would cost us cold-start time on every free-tier deploy.

The interface is deliberately swappable: replace `_vectorise` and nothing else
changes.
"""
import logging
import threading
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.data.campaigns import CAMPAIGNS

logger = logging.getLogger(__name__)


class CampaignMatcher:
    """Thread-safe, lazily-built matcher over the known campaign corpus."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._matrix = None
        self._campaigns: List[Dict] = []
        self._ready = False

    def build(self, extra_corpus: Optional[List[Dict]] = None) -> None:
        """Fit the vectoriser. Called once at startup, and again after seeding."""
        with self._lock:
            corpus = list(CAMPAIGNS)
            if extra_corpus:
                corpus.extend(extra_corpus)

            texts = [c["text"] for c in corpus]
            self._vectorizer = TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 3),
                sublinear_tf=True,
                min_df=1,
                max_features=20000,
                strip_accents="unicode",
                token_pattern=r"(?u)\b\w[\w']+\b",
            )
            self._matrix = self._vectorizer.fit_transform(texts)
            self._campaigns = corpus
            self._ready = True
            logger.info("Campaign matcher built over %d fingerprints", len(corpus))

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def size(self) -> int:
        return len(self._campaigns)

    def match(self, text: str, top_k: int = 3) -> List[Tuple[Dict, float]]:
        if not self._ready or self._vectorizer is None:
            return []
        vec = self._vectorizer.transform([text])
        sims = cosine_similarity(vec, self._matrix)[0]
        idx = np.argsort(sims)[::-1][:top_k]
        return [(self._campaigns[i], float(sims[i])) for i in idx if sims[i] > 0.01]

    def best(self, text: str) -> Tuple[Optional[Dict], float]:
        results = self.match(text, top_k=1)
        if not results:
            return None, 0.0
        return results[0]

    def explain(self, text: str, campaign_index_text: str, top_terms: int = 6) -> List[str]:
        """Return the shared high-weight terms that drove a match."""
        if not self._ready or self._vectorizer is None:
            return []
        try:
            names = np.array(self._vectorizer.get_feature_names_out())
            a = self._vectorizer.transform([text]).toarray()[0]
            b = self._vectorizer.transform([campaign_index_text]).toarray()[0]
            overlap = a * b
            idx = np.argsort(overlap)[::-1][:top_terms]
            return [str(names[i]) for i in idx if overlap[i] > 0]
        except Exception:  # pragma: no cover - explanation is best-effort
            return []


matcher = CampaignMatcher()
