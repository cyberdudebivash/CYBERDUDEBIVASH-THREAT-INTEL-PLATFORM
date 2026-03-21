"""
SENTINEL APEX v70 — AI Threat Summarizer (PRODUCTION FIX)
===========================================================
Generates analyst-grade threat summaries using:
1. Template-based generation (fast, deterministic — PRIMARY for short texts)
2. Extractive summarization fallback (sklearn TF-IDF — for medium texts)
3. Transformers pipeline (ONLY for genuinely long texts >500 chars on GPU)

PRODUCTION FIX: Most advisories in this platform are short CVE titles
(20-100 tokens). Running HF distilbart on these is wasteful — it takes
2-3s/item on CPU, produces worse output than templates, and floods
logs with max_length warnings. Template summarization is used by default.
HF is ONLY invoked for texts >500 chars where it adds real value.
"""

import logging
import os
import re
import warnings
from typing import Any, Dict, List, Optional

from ..core.models import Advisory, Severity, ThreatType

logger = logging.getLogger("sentinel.ai.summarizer")

# Suppress HF max_length warnings globally
warnings.filterwarnings("ignore", message=".*max_length.*input_length.*")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

# sklearn for extractive fallback
_SKLEARN_AVAILABLE = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    pass

# Transformers — lazy load only when actually needed
_TRANSFORMERS_AVAILABLE = False
_summarizer_pipeline = None

try:
    from transformers import pipeline as hf_pipeline
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    pass


# Minimum character count to even consider HF summarization
# Below this, template is always better and 100x faster
HF_MIN_INPUT_CHARS = 500


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
            model="sshleifer/distilbart-cnn-6-6",
            device=-1,
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
    Template-first approach for production speed.
    HF only for long-form text where it adds value.
    """

    def __init__(self, use_transformers: bool = False):
        """
        Args:
            use_transformers: Enable HF transformers for long texts.
                              Default FALSE for CI/CD speed.
                              Set True only with GPU or for batch offline runs.
        """
        self.use_transformers = use_transformers
        self._hf_pipeline = None
        # Only init HF if explicitly requested
        if use_transformers and _TRANSFORMERS_AVAILABLE:
            self._hf_pipeline = _init_hf_summarizer()

    def summarize(self, advisory: Advisory) -> str:
        """Generate a structured threat summary for an advisory."""
        text = f"{advisory.title}. {advisory.summary}".strip()

        if not text or len(text) < 20:
            return self._template_summary(advisory)

        # Strategy 1: HF Transformers ONLY for genuinely long text
        if (
            self._hf_pipeline
            and self.use_transformers
            and len(text) > HF_MIN_INPUT_CHARS
        ):
            try:
                # Dynamic max_length to avoid warnings
                input_tokens = len(text.split())
                max_len = max(30, min(150, input_tokens - 5))
                min_len = max(10, min(40, input_tokens // 3))

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    result = self._hf_pipeline(
                        text[:1024],
                        max_length=max_len,
                        min_length=min_len,
                        do_sample=False,
                        truncation=True,
                    )
                if result and result[0].get("summary_text"):
                    base_summary = result[0]["summary_text"]
                    return self._enrich_summary(base_summary, advisory)
            except Exception as e:
                logger.debug(f"HF summarization failed: {e}")

        # Strategy 2: Extractive (for medium-length texts, >300 chars)
        if _SKLEARN_AVAILABLE and len(text) > 300:
            try:
                extractive = self._extractive_summarize(text, n_sentences=3)
                if extractive:
                    return self._enrich_summary(extractive, advisory)
            except Exception:
                pass

        # Strategy 3: Template (always works, fast, good for short texts)
        return self._template_summary(advisory)

    def _extractive_summarize(self, text: str, n_sentences: int = 3) -> str:
        """TF-IDF extractive summarization."""
        sentences = re.split(r'(?<=[.!?])\s+', text)
        if len(sentences) <= n_sentences:
            return text

        vectorizer = TfidfVectorizer(stop_words="english", sublinear_tf=True)
        tfidf_matrix = vectorizer.fit_transform(sentences)
        scores = np.asarray(tfidf_matrix.sum(axis=1)).flatten()
        top_indices = sorted(scores.argsort()[-n_sentences:][::-1])
        return " ".join(sentences[i] for i in top_indices)

    def _template_summary(self, advisory: Advisory) -> str:
        """Template-based summary — fast, deterministic, production-grade."""
        parts = []

        # Opening based on threat type
        type_openers = {
            ThreatType.VULNERABILITY: "Security vulnerability identified",
            ThreatType.MALWARE: "Malware threat detected",
            ThreatType.CAMPAIGN: "Threat campaign activity observed",
            ThreatType.INTRUSION_SET: "Intrusion set activity identified",
            ThreatType.GENERIC: "Security advisory issued",
        }
        opener = type_openers.get(advisory.threat_type, "Security advisory issued")
        parts.append(f"{opener}: {advisory.title}.")

        if advisory.cves:
            cve_str = ", ".join(advisory.cves[:5])
            parts.append(f"Tracked as {cve_str}.")

        if advisory.threat_score > 0:
            parts.append(
                f"Threat score: {advisory.threat_score}/100 "
                f"(Severity: {advisory.severity.value.upper()})."
            )

        if advisory.actors:
            parts.append(f"Associated actors: {', '.join(advisory.actors[:3])}.")

        if advisory.mitre_techniques:
            parts.append(f"MITRE ATT&CK: {', '.join(advisory.mitre_techniques[:5])}.")

        ioc_count = len(advisory.iocs)
        if ioc_count > 0:
            parts.append(f"{ioc_count} indicator(s) of compromise extracted.")

        if advisory.source_name:
            parts.append(f"Source: {advisory.source_name}.")

        return " ".join(parts)

    def _enrich_summary(self, base_summary: str, advisory: Advisory) -> str:
        """Append structured context to ML-generated summary."""
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
