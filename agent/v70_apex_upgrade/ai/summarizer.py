"""
SENTINEL APEX v70 — AI Threat Summarizer
==========================================
Generates analyst-grade threat summaries using:
1. Transformers pipeline (if available, GPU-accelerated)
2. Extractive summarization fallback (sklearn TF-IDF)
3. Template-based generation (deterministic fallback)

Produces structured, actionable intelligence summaries.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from ..core.models import Advisory, Severity, ThreatType

logger = logging.getLogger("sentinel.ai.summarizer")

# Transformers import with graceful fallback
_TRANSFORMERS_AVAILABLE = False
_summarizer_pipeline = None

try:
    from transformers import pipeline as hf_pipeline
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("transformers not available — using extractive/template summarization")

# sklearn for extractive fallback
_SKLEARN_AVAILABLE = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    pass


def _init_hf_summarizer():
    """Lazy-initialize the HuggingFace summarization pipeline."""
    global _summarizer_pipeline
    if _summarizer_pipeline is not None:
        return _summarizer_pipeline

    if not _TRANSFORMERS_AVAILABLE:
        return None

    try:
        _summarizer_pipeline = hf_pipeline(
            "summarization",
            model="sshleifer/distilbart-cnn-6-6",  # Small, fast model
            device=-1,  # CPU (safe default; GPU = 0)
            framework="pt",
        )
        logger.info("HuggingFace summarizer initialized (distilbart-cnn-6-6)")
        return _summarizer_pipeline
    except Exception as e:
        logger.warning(f"Failed to initialize HF summarizer: {e}")
        return None


class ThreatSummarizer:
    """
    Multi-strategy threat summarizer.
    Produces structured intelligence summaries for advisories.
    """

    def __init__(self, use_transformers: bool = True):
        self.use_transformers = use_transformers
        self._hf_pipeline = None
        if use_transformers:
            self._hf_pipeline = _init_hf_summarizer()

    def summarize(self, advisory: Advisory) -> str:
        """Generate a structured threat summary for an advisory."""
        text = f"{advisory.title}. {advisory.summary}".strip()

        if not text or len(text) < 20:
            return self._template_summary(advisory)

        # Strategy 1: Transformers (if available and text is long enough)
        if self._hf_pipeline and len(text) > 100:
            try:
                result = self._hf_pipeline(
                    text[:1024],  # Model input limit
                    max_length=150,
                    min_length=40,
                    do_sample=False,
                    truncation=True,
                )
                if result and result[0].get("summary_text"):
                    base_summary = result[0]["summary_text"]
                    return self._enrich_summary(base_summary, advisory)
            except Exception as e:
                logger.debug(f"HF summarization failed for {advisory.advisory_id}: {e}")

        # Strategy 2: Extractive (TF-IDF sentence scoring)
        if _SKLEARN_AVAILABLE and len(text) > 200:
            try:
                extractive = self._extractive_summarize(text, n_sentences=3)
                if extractive:
                    return self._enrich_summary(extractive, advisory)
            except Exception as e:
                logger.debug(f"Extractive summarization failed: {e}")

        # Strategy 3: Template-based (always works)
        return self._template_summary(advisory)

    def _extractive_summarize(self, text: str, n_sentences: int = 3) -> str:
        """TF-IDF extractive summarization — select most informative sentences."""
        # Split into sentences
        sentences = re.split(r'(?<=[.!?])\s+', text)
        if len(sentences) <= n_sentences:
            return text

        # TF-IDF score each sentence
        vectorizer = TfidfVectorizer(stop_words="english", sublinear_tf=True)
        tfidf_matrix = vectorizer.fit_transform(sentences)

        # Score = sum of TF-IDF weights in sentence
        scores = np.asarray(tfidf_matrix.sum(axis=1)).flatten()

        # Select top sentences (preserve order)
        top_indices = sorted(
            scores.argsort()[-n_sentences:][::-1]
        )
        return " ".join(sentences[i] for i in top_indices)

    def _template_summary(self, advisory: Advisory) -> str:
        """Template-based summary generation — deterministic fallback."""
        parts = []

        # Opening line based on threat type
        type_openers = {
            ThreatType.VULNERABILITY: "Security vulnerability identified",
            ThreatType.MALWARE: "Malware threat detected",
            ThreatType.CAMPAIGN: "Threat campaign activity observed",
            ThreatType.INTRUSION_SET: "Intrusion set activity identified",
            ThreatType.GENERIC: "Security advisory issued",
        }
        opener = type_openers.get(advisory.threat_type, "Security advisory issued")
        parts.append(f"{opener}: {advisory.title}.")

        # CVE context
        if advisory.cves:
            cve_str = ", ".join(advisory.cves[:5])
            parts.append(f"Tracked as {cve_str}.")

        # Severity and score
        if advisory.threat_score > 0:
            parts.append(
                f"Threat score: {advisory.threat_score}/100 "
                f"(Severity: {advisory.severity.value.upper()})."
            )

        # Actors
        if advisory.actors:
            parts.append(f"Associated actors: {', '.join(advisory.actors[:3])}.")

        # MITRE techniques
        if advisory.mitre_techniques:
            parts.append(f"MITRE ATT&CK: {', '.join(advisory.mitre_techniques[:5])}.")

        # IOC count
        ioc_count = len(advisory.iocs)
        if ioc_count > 0:
            parts.append(f"{ioc_count} indicator(s) of compromise extracted.")

        # Source
        if advisory.source_name:
            parts.append(f"Source: {advisory.source_name}.")

        return " ".join(parts)

    def _enrich_summary(self, base_summary: str, advisory: Advisory) -> str:
        """Append structured intelligence context to ML-generated summary."""
        enrichments = []

        if advisory.cves:
            enrichments.append(f"CVEs: {', '.join(advisory.cves[:5])}")
        if advisory.threat_score > 0:
            enrichments.append(f"Score: {advisory.threat_score}/100")
        if advisory.actors:
            enrichments.append(f"Actors: {', '.join(advisory.actors[:3])}")
        if advisory.mitre_techniques:
            enrichments.append(f"TTPs: {', '.join(advisory.mitre_techniques[:4])}")

        if enrichments:
            return f"{base_summary} [{' | '.join(enrichments)}]"
        return base_summary

    def summarize_batch(self, advisories: List[Advisory]) -> List[Advisory]:
        """Summarize all advisories in batch."""
        for adv in advisories:
            if not adv.ai_summary:
                adv.ai_summary = self.summarize(adv)

        logger.info(f"Summarized {len(advisories)} advisories")
        return advisories
