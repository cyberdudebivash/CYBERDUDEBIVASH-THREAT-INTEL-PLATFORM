#!/usr/bin/env python3
"""
deduplication.py — CyberDudeBivash v14.0 (SENTINEL APEX ULTRA)
TRIPLE-LAYER Intelligence Deduplication Engine.

v14.0 ROOT CAUSE FIX for duplicate reports:
  Layer 1: Exact hash (title + URL) — catches identical republish
  Layer 2: Title-only hash — catches SAME article from DIFFERENT feeds
  Layer 3: Fuzzy word-overlap — catches near-identical titles (80% threshold)

BUG HISTORY: v13.0 only had Layer 1. Same article from Threatpost AND
BleepingComputer had different URLs → different hashes → published twice.
CDB-NEWS Phase 1 had NO dedup at all → articles repeated 6x.
"""
import hashlib
import json
import os
import re
import logging
from typing import Dict, List

logger = logging.getLogger("CDB-DEDUP")


class DeduplicationEngine:
    """Triple-layer deduplication. Prevents duplicates across all feed sources."""

    def __init__(self, state_file: str = "data/blogger_processed.json",
                 max_state_size: int = 500):
        self.state_file = state_file
        self.max_state_size = max_state_size
        self._state = self._load_state()

    # ── Persistence ──────────────────────────────────────

    def _load_state(self) -> Dict:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return {"processed_hashes": data, "hash_titles": {},
                                "title_hashes": []}
                    if isinstance(data, dict):
                        data.setdefault("title_hashes", [])
                        return data
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"State corrupted, fresh start: {e}")
        return {"processed_hashes": [], "hash_titles": {}, "title_hashes": []}

    def _save_state(self):
        os.makedirs(os.path.dirname(self.state_file) or '.', exist_ok=True)
        for key in ("processed_hashes", "title_hashes"):
            if len(self._state.get(key, [])) > self.max_state_size:
                self._state[key] = self._state[key][-self.max_state_size:]
        with open(self.state_file, 'w') as f:
            json.dump(self._state, f, indent=2)

    # ── Hash generators ──────────────────────────────────

    def _generate_hash(self, title: str, source_url: str = "") -> str:
        """Layer 1: Exact hash from title + URL."""
        content = f"{title.strip().lower()}|{source_url.strip().lower()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _generate_title_hash(self, title: str) -> str:
        """Layer 2: Hash from normalized title only (cross-feed dedup)."""
        normalized = re.sub(r'[^\w\s]', '', title.strip().lower())
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _titles_similar(self, a: str, b: str, threshold: float = 0.80) -> bool:
        """Layer 3: Fuzzy word-overlap similarity."""
        wa = set(re.sub(r'[^\w\s]', '', a.lower()).split())
        wb = set(re.sub(r'[^\w\s]', '', b.lower()).split())
        if not wa or not wb or len(wa) < 3:
            return False
        overlap = len(wa & wb)
        mx = max(len(wa), len(wb))
        return (overlap / mx) >= threshold if mx > 0 else False

    # ── Core API ─────────────────────────────────────────

    def is_duplicate(self, title: str, source_url: str = "") -> bool:
        """Triple-layer duplicate check. Returns True if already processed."""
        # Layer 1: Exact hash match (title + URL)
        if self._generate_hash(title, source_url) in self._state["processed_hashes"]:
            return True
        # Layer 2: Title-only hash (catches cross-feed duplicates)
        if self._generate_title_hash(title) in self._state.get("title_hashes", []):
            logger.info(f"  [DEDUP-L2] Cross-feed dup: {title[:60]}")
            return True
        # Layer 3: Fuzzy word-overlap against recent titles
        for existing in list(self._state.get("hash_titles", {}).values())[-150:]:
            if self._titles_similar(title, existing):
                logger.info(f"  [DEDUP-L3] Similar: {title[:40]}… ≈ {existing[:40]}…")
                return True
        return False

    def mark_processed(self, title: str, source_url: str = ""):
        """Register across all 3 layers."""
        ch = self._generate_hash(title, source_url)
        th = self._generate_title_hash(title)
        if ch not in self._state["processed_hashes"]:
            self._state["processed_hashes"].append(ch)
            self._state["hash_titles"][ch] = title[:100]
        if th not in self._state.get("title_hashes", []):
            self._state.setdefault("title_hashes", []).append(th)
        self._save_state()
        logger.info(f"  [DEDUP] Registered: {title[:60]}…")

    def get_processed_count(self) -> int:
        return len(self._state["processed_hashes"])

    def is_similar_in_manifest(self, title: str, manifest: List[Dict],
                                threshold: float = 0.80) -> bool:
        """Check fuzzy similarity against live STIX manifest titles."""
        tw = set(re.sub(r'[^\w\s]', '', title.lower()).split())
        for entry in manifest:
            ew = set(re.sub(r'[^\w\s]', '', entry.get("title", "").lower()).split())
            if not tw or not ew:
                continue
            overlap = len(tw & ew)
            mx = max(len(tw), len(ew))
            if mx > 0 and (overlap / mx) >= threshold:
                logger.info(f"  [DEDUP] Manifest match: {entry.get('title', '')[:60]}")
                return True
        return False


# Global singleton (backward compatible)
dedup_engine = DeduplicationEngine()
