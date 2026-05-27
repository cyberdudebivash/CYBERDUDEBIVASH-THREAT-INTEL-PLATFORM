#!/usr/bin/env python3
"""
scripts/actor_attribution_enricher.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Actor Attribution Enricher v1.0.0
=====================================================================
ROOT CAUSE FIX (P1.6):
  api/feed.json shows 0/25 actor attribution — no named threat actors
  (APT28, Lazarus, Sandworm, etc.) appear in any feed item even though
  threat_actor_profiler.py has a complete MITRE ATT&CK group database.

  threat_actor_profiler.py only writes to data/actor_profiles.json and
  explicitly "Never modifies feed_manifest.json". This script bridges
  that gap: it reads the actor database, pattern-matches against each
  feed item's text fields, and writes actor_attribution back into the
  live feed items.

WHAT THIS SCRIPT DOES:
  1. Loads actor name/alias lookup table from MITRE ATT&CK group database
     (same data as threat_actor_profiler.py — no external dependency)
  2. Reads api/feed.json
  3. For each item, scans title + description + ai_summary for actor mentions
  4. Writes item["actor_attribution"] = [{"name": ..., "mitre_id": ...,
       "attribution": ..., "confidence": "HIGH/MEDIUM/LOW"}]
  5. Saves atomically
  6. Also invokes threat_actor_profiler.py to build data/actor_profiles.json
     (for the actor registry side of things)

IDEMPOTENT: Existing actor_attribution values are merged, never dropped.

USAGE:
  python3 scripts/actor_attribution_enricher.py
  DRY_RUN=true python3 scripts/actor_attribution_enricher.py
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] ACTOR-ENRICHER %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("actor-enricher")

# ── Config ─────────────────────────────────────────────────────────────────────
REPO      = Path(__file__).resolve().parent.parent
DRY_RUN   = os.environ.get("DRY_RUN", "false").strip().lower() == "true"
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
MANIFEST_PATH = REPO / "data" / "feed_manifest.json"

# ── Actor Database (mirrors threat_actor_profiler.py MITRE data) ───────────────
# Each entry: canonical_name → {mitre_id, aliases, attribution, motivation, confidence_weight}
ACTOR_DB: Dict[str, Dict] = {
    "APT28": {
        "mitre_id":    "G0007",
        "aliases":     ["Fancy Bear", "Pawn Storm", "Sofacy", "Sednit", "STRONTIUM",
                        "Tsar Team", "Forest Blizzard", "Iron Twilight"],
        "attribution": "Russia (GRU)",
        "motivation":  ["espionage", "political"],
    },
    "APT29": {
        "mitre_id":    "G0016",
        "aliases":     ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard",
                        "Dark Halo", "UNC2452"],
        "attribution": "Russia (SVR)",
        "motivation":  ["espionage", "intelligence_gathering"],
    },
    "Lazarus Group": {
        "mitre_id":    "G0032",
        "aliases":     ["Lazarus", "HIDDEN COBRA", "Guardians of Peace", "ATK3",
                        "UNC577", "Diamond Sleet"],
        "attribution": "North Korea (RGB)",
        "motivation":  ["financial_gain", "espionage", "sabotage"],
    },
    "Sandworm": {
        "mitre_id":    "G0034",
        "aliases":     ["Sandworm Team", "BlackEnergy", "Voodoo Bear", "IRIDIUM",
                        "Seashell Blizzard", "TeleBots"],
        "attribution": "Russia (GRU Unit 74455)",
        "motivation":  ["sabotage", "espionage"],
    },
    "Charming Kitten": {
        "mitre_id":    "G0058",
        "aliases":     ["APT35", "Phosphorus", "MINT SANDSTORM", "TA453",
                        "NewsBeef", "Newscaster"],
        "attribution": "Iran (IRGC)",
        "motivation":  ["espionage", "information_operations"],
    },
    "Muddled Libra": {
        "mitre_id":    "G1015",
        "aliases":     ["Scattered Spider", "UNC3944", "0ktapus", "Starfraud"],
        "attribution": "Financially motivated / Western-based",
        "motivation":  ["financial_gain", "ransomware"],
    },
    "Volt Typhoon": {
        "mitre_id":    "G1017",
        "aliases":     ["Bronze Silhouette", "Vanguard Panda", "DEV-0391"],
        "attribution": "China (PLA / MSS)",
        "motivation":  ["espionage", "pre-positioning"],
    },
    "APT41": {
        "mitre_id":    "G0096",
        "aliases":     ["Double Dragon", "Winnti", "Barium", "Bronze Atlas",
                        "Earth Baku", "Wicked Panda"],
        "attribution": "China (MSS)",
        "motivation":  ["espionage", "financial_gain"],
    },
    "BlackCat": {
        "mitre_id":    "G1016",
        "aliases":     ["ALPHV", "Noberus"],
        "attribution": "Criminal (Ransomware-as-a-Service)",
        "motivation":  ["financial_gain", "ransomware"],
    },
    "LockBit": {
        "mitre_id":    "G0139",
        "aliases":     ["LockBit 2.0", "LockBit 3.0", "LockBit Black"],
        "attribution": "Criminal (Ransomware-as-a-Service)",
        "motivation":  ["financial_gain", "ransomware"],
    },
    "Cl0p": {
        "mitre_id":    "G0116",
        "aliases":     ["Clop", "TA505", "FIN11"],
        "attribution": "Criminal (Eastern Europe)",
        "motivation":  ["financial_gain", "data_extortion"],
    },
    "Kimsuky": {
        "mitre_id":    "G0094",
        "aliases":     ["Velvet Chollima", "Black Banshee", "Thallium", "APT43",
                        "Emerald Sleet"],
        "attribution": "North Korea (RGB)",
        "motivation":  ["espionage", "intelligence_gathering"],
    },
    "MuddyWater": {
        "mitre_id":    "G0069",
        "aliases":     ["TEMP.Zagros", "Static Kitten", "Seedworm", "Mercury",
                        "Mango Sandstorm"],
        "attribution": "Iran (MOIS)",
        "motivation":  ["espionage", "surveillance"],
    },
    "REvil": {
        "mitre_id":    "G0115",
        "aliases":     ["Sodinokibi", "GOLD SOUTHFIELD"],
        "attribution": "Criminal",
        "motivation":  ["financial_gain", "ransomware"],
    },
    "DarkSide": {
        "mitre_id":    "G0139",
        "aliases":     ["Carbon Spider", "GOLD CARBON"],
        "attribution": "Criminal",
        "motivation":  ["financial_gain", "ransomware"],
    },
}

# Build flat lookup: every alias → canonical name
_ALIAS_MAP: Dict[str, str] = {}
for _canonical, _data in ACTOR_DB.items():
    _ALIAS_MAP[_canonical.lower()] = _canonical
    for _alias in _data.get("aliases", []):
        _ALIAS_MAP[_alias.lower()] = _canonical


def _build_patterns() -> List[tuple[re.Pattern, str]]:
    """Compile regex patterns for all actor names and aliases, longest first."""
    pairs = sorted(_ALIAS_MAP.items(), key=lambda x: -len(x[0]))
    return [
        (re.compile(r"\b" + re.escape(alias) + r"\b", re.IGNORECASE), canonical)
        for alias, canonical in pairs
    ]


ACTOR_PATTERNS = _build_patterns()


# ── Text scanning ──────────────────────────────────────────────────────────────

def scan_text(text: str) -> List[str]:
    """Return list of canonical actor names found in text, deduplicated."""
    found: list[str] = []
    for pattern, canonical in ACTOR_PATTERNS:
        if pattern.search(text):
            if canonical not in found:
                found.append(canonical)
    return found


def get_item_text(item: Dict[str, Any]) -> str:
    """Concatenate all searchable text fields from an item."""
    parts: list[str] = []
    for field in ("title", "description", "summary", "ai_summary",
                  "executive_summary", "raw_title", "tags"):
        val = item.get(field)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, list):
            parts.extend(str(v) for v in val if v)
    raw = item.get("raw")
    if isinstance(raw, dict):
        for field in ("title", "description", "summary"):
            val = raw.get(field)
            if isinstance(val, str):
                parts.append(val)
    return " ".join(parts)


# ── JSON helpers ───────────────────────────────────────────────────────────────

def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return None


def save_json_atomic(path: Path, data: Any) -> None:
    if DRY_RUN:
        log.info("[DRY_RUN] Would write %s", path)
        return
    tmp = path.with_suffix(".tmp_actor")
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        log.info("Saved: %s", path)
    except Exception as exc:
        log.error("Failed to save %s: %s", path, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ── Enrichment ─────────────────────────────────────────────────────────────────

def enrich_items(items: List[Dict[str, Any]]) -> int:
    """Mutate items in-place with actor_attribution. Returns modified count."""
    modified = 0
    for item in items:
        if not isinstance(item, dict):
            continue

        text = get_item_text(item)
        if not text.strip():
            continue

        found_actors = scan_text(text)
        if not found_actors:
            continue

        # Build structured attribution records
        new_attributions = []
        for canonical in found_actors:
            actor_data = ACTOR_DB.get(canonical, {})
            new_attributions.append({
                "name":        canonical,
                "mitre_id":    actor_data.get("mitre_id", ""),
                "attribution": actor_data.get("attribution", "Unknown"),
                "motivation":  actor_data.get("motivation", []),
                "confidence":  "HIGH",
                "source":      "text_pattern_match",
            })

        # Merge with existing (never drop)
        existing = item.get("actor_attribution") or []
        if isinstance(existing, str):
            existing = [{"name": existing}]
        existing_names = {e.get("name") for e in existing if isinstance(e, dict)}

        added = False
        for attr in new_attributions:
            if attr["name"] not in existing_names:
                existing.append(attr)
                added = True

        if added or (new_attributions and not item.get("actor_attribution")):
            item["actor_attribution"] = existing
            # Also write primary actor as flat string for backward compat
            if new_attributions and not item.get("primary_actor"):
                item["primary_actor"] = new_attributions[0]["name"]
            modified += 1
            log.info("Actor enriched: %s  actors=%s",
                     str(item.get("title", ""))[:70],
                     [a["name"] for a in new_attributions])

    return modified


def process_feed(path: Path) -> int:
    data = load_json(path)
    if data is None:
        log.info("Skipping (not found): %s", path)
        return 0

    if isinstance(data, list):
        modified = enrich_items(data)
        if modified > 0:
            save_json_atomic(path, data)
        return modified

    if isinstance(data, dict):
        # Skip empty lists — feed_manifest.json has "items": [] and "advisories": [482]
        for key in ("items", "advisories", "feed", "data"):
            if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                modified = enrich_items(data[key])
                if modified > 0:
                    save_json_atomic(path, data)
                return modified

    return 0


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    log.info("Actor Attribution Enricher v1.0.0 — DRY_RUN=%s", DRY_RUN)
    log.info("Actor database: %d canonical actors, %d aliases",
             len(ACTOR_DB), len(_ALIAS_MAP))

    total = 0

    # Enrich api/feed.json
    n = process_feed(FEED_PATH)
    log.info("%-40s  enriched=%d", FEED_PATH.name, n)
    total += n

    # Enrich data/feed_manifest.json
    n = process_feed(MANIFEST_PATH)
    log.info("%-40s  enriched=%d", MANIFEST_PATH.name, n)
    total += n

    log.info("=" * 60)
    log.info("Actor attribution enrichment complete: %d item(s) updated", total)

    # Also run threat_actor_profiler.py to build actor_profiles.json registry
    profiler = Path(__file__).parent / "threat_actor_profiler.py"
    if profiler.exists() and not DRY_RUN:
        log.info("Running threat_actor_profiler.py to build actor_profiles.json...")
        try:
            result = subprocess.run(
                [sys.executable, str(profiler), "--list"],
                capture_output=True, text=True, timeout=60,
                cwd=str(REPO)
            )
            if result.returncode == 0:
                log.info("threat_actor_profiler.py: OK")
            else:
                log.warning("threat_actor_profiler.py exited %d — non-fatal",
                            result.returncode)
        except Exception as exc:
            log.warning("threat_actor_profiler.py failed: %s — non-fatal", exc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
ctor_profiler.py failed: %s — non-fatal", exc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
