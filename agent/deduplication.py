#!/usr/bin/env python3
"""
deduplication.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
NEW MODULE: Intelligence Deduplication Engine.
Prevents duplicate campaigns from appearing in the manifest/dashboard.
Uses content hashing for "Known Intelligence" tracking.
"""
import hashlib
import json
import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-DEDUP")


class DeduplicationEngine:
    """
    Tracks processed intelligence to prevent duplicates.
    Uses SHA256 hashing of title + source for unique identification.
    """

    def __init__(self, state_file: str = "data/blogger_processed.json",
                 max_state_size: int = 500):
        self.state_file = state_file
        self.max_state_size = max_state_size
        self._state = self._load_state()

    def _load_state(self) -> Dict:
        """Load processed state from disk."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    # Handle both list and dict formats
                    if isinstance(data, list):
                        return {"processed_hashes": data, "hash_titles": {}}
                    elif isinstance(data, dict):
                        return data
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"State file corrupted, starting fresh: {e}")
        return {"processed_hashes": [], "hash_titles": {}}

    def _save_state(self):
        """Persist state to disk."""
        os.makedirs(os.path.dirname(self.state_file) or '.', exist_ok=True)
        # Trim to max size
        if len(self._state["processed_hashes"]) > self.max_state_size:
            self._state["processed_hashes"] = \
                self._state["processed_hashes"][-self.max_state_size:]
        with open(self.state_file, 'w') as f:
            json.dump(self._state, f, indent=2)

    def _generate_hash(self, title: str, source_url: str = "") -> str:
        """Generate unique content hash from title + source."""
        content = f"{title.strip().lower()}|{source_url.strip().lower()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def is_duplicate(self, title: str, source_url: str = "") -> bool:
        """Check if this intelligence item has already been processed."""
        content_hash = self._generate_hash(title, source_url)
        return content_hash in self._state["processed_hashes"]

    def mark_processed(self, title: str, source_url: str = ""):
        """Mark an intelligence item as processed."""
        content_hash = self._generate_hash(title, source_url)
        if content_hash not in self._state["processed_hashes"]:
            self._state["processed_hashes"].append(content_hash)
            self._state["hash_titles"][content_hash] = title[:100]
            self._save_state()
            logger.info(f"Marked as processed: {title[:60]}...")

    def get_processed_count(self) -> int:
        """Return total number of processed items."""
        return len(self._state["processed_hashes"])

    def is_similar_in_manifest(self, title: str,
                                manifest: List[Dict],
                                threshold: float = 0.85) -> bool:
        """
        Check if a similar title already exists in the manifest.
        Uses simple word overlap for similarity detection.
        """
        title_words = set(title.lower().split())
        for entry in manifest:
            existing_words = set(entry.get("title", "").lower().split())
            if not title_words or not existing_words:
                continue
            overlap = len(title_words & existing_words)
            max_len = max(len(title_words), len(existing_words))
            similarity = overlap / max_len if max_len > 0 else 0
            if similarity >= threshold:
                logger.info(f"Similar entry found in manifest: {entry.get('title', '')[:60]}")
                return True
        return False


# Global singleton
dedup_engine = DeduplicationEngine()
