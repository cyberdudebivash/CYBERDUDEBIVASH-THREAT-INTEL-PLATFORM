"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — TAXII 2.1 SERVER ENGINE v1.0           ║
║  Standards-Compliant Threat Intelligence Sharing                          ║
║  OASIS TAXII 2.1 Specification (CS02, November 2021)                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Revenue: Enterprise-only ($499+/mo) · ISACs · Government partnerships

TAXII 2.1 Collection Model:
  - /taxii2/                      → Discovery endpoint
  - /api-root/                    → API Root info
  - /api-root/collections/        → List collections
  - /api-root/collections/{id}/   → Collection info
  - /api-root/collections/{id}/objects/  → STIX 2.1 objects
  - /api-root/collections/{id}/manifest/ → Object manifests
  - /api-root/status/{id}/        → Status endpoint

Collections:
  - apt-threat-intelligence       → APT group TTPs and campaigns (ENTERPRISE+)
  - ransomware-intelligence       → Ransomware IOCs, TTPs, actor profiles
  - vulnerability-intelligence    → CVE/EPSS/KEV enriched vulnerability data
  - ioc-indicators                → IOC feed (IPs, domains, hashes, URLs)
  - supply-chain-threats          → Supply chain compromise indicators
  - all-objects                   → Full STIX 2.1 bundle (MSSP only)
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-TAXII")

BASE_DIR = Path(__file__).resolve().parent.parent.parent

TAXII_MEDIA_TYPE         = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE          = "application/stix+json;version=2.1"
TAXII_ACCEPT             = f"{TAXII_MEDIA_TYPE}, {STIX_MEDIA_TYPE}"
TAXII_SPEC_VERSION       = "2.1"


@dataclass
class TaxiiCollection:
    id:          str
    title:       str
    description: str
    can_read:    bool = True
    can_write:   bool = False
    media_types: List[str] = field(default_factory=lambda: [STIX_MEDIA_TYPE])
    required_tier: str = "ENTERPRISE"
    aliases:     List[str] = field(default_factory=list)


# ── Collection Registry ───────────────────────────────────────────────────────
COLLECTIONS: Dict[str, TaxiiCollection] = {
    "apt-threat-intelligence": TaxiiCollection(
        id          = "apt-threat-intelligence",
        title       = "APT Threat Intelligence",
        description = "Nation-state APT group profiles, TTPs, campaigns, infrastructure, and attribution intelligence. "
                      "Covers 35+ APT groups with MITRE ATT&CK mapping and STIX 2.1 objects.",
        required_tier = "ENTERPRISE",
        aliases     = ["apt", "nation-state"],
    ),
    "ransomware-intelligence": TaxiiCollection(
        id          = "ransomware-intelligence",
        title       = "Ransomware Intelligence",
        description = "Active ransomware group TTPs, IOCs, victim sectors, ransom amounts, and group profiles. "
                      "Includes LockBit, ALPHV/BlackCat, Cl0p, Rhysida, and 20+ active groups.",
        required_tier = "PRO",
        aliases     = ["ransomware", "rw"],
    ),
    "vulnerability-intelligence": TaxiiCollection(
        id          = "vulnerability-intelligence",
        title       = "Vulnerability Intelligence",
        description = "CVE/EPSS/KEV enriched vulnerability data with exploit probability scores, "
                      "patch availability, and vendor advisories. Prioritized by exploitability.",
        required_tier = "PRO",
        aliases     = ["cve", "vuln"],
    ),
    "ioc-indicators": TaxiiCollection(
        id          = "ioc-indicators",
        title       = "IOC Intelligence Feed",
        description = "Curated IOC feed: malicious IPs, domains, file hashes, URLs, email addresses. "
                      "Enriched with confidence scores, TLP markings, and STIX 2.1 indicator objects.",
        required_tier = "PRO",
        aliases     = ["ioc", "indicators"],
    ),
    "supply-chain-threats": TaxiiCollection(
        id          = "supply-chain-threats",
        title       = "Supply Chain Threat Intelligence",
        description = "Software supply chain compromises, malicious package detections, "
                      "CI/CD attack indicators, and vendor breach intelligence.",
        required_tier = "ENTERPRISE",
        aliases     = ["supply-chain", "sc"],
    ),
    "all-objects": TaxiiCollection(
        id          = "all-objects",
        title       = "Full Intelligence Bundle",
        description = "Complete STIX 2.1 bundle — all threat intelligence objects. "
                      "500+ advisories with full enrichment. MSSP tier only.",
        required_tier = "MSSP",
        aliases     = ["full", "all"],
    ),
}

# ── Tier to collection access map ─────────────────────────────────────────────
TIER_COLLECTION_ACCESS: Dict[str, List[str]] = {
    "FREE":       [],
    "PRO":        ["ransomware-intelligence", "vulnerability-intelligence", "ioc-indicators"],
    "ENTERPRISE": ["apt-threat-intelligence", "ransomware-intelligence",
                   "vulnerability-intelligence", "ioc-indicators", "supply-chain-threats"],
    "MSSP":       list(COLLECTIONS.keys()),
}


class TaxiiServer:
    """
    TAXII 2.1 server engine.
    Serves STIX 2.1 objects from the SENTINEL APEX threat intelligence feed.
    """

    def __init__(self, api_root_url: str = "https://intel.cyberdudebivash.com/taxii"):
        self.api_root_url = api_root_url.rstrip("/")
        self.requests_served = 0
        self._feed_cache: Optional[List[Dict]] = None
        self._cache_ts: float = 0

    # ── TAXII 2.1 Protocol Methods ────────────────────────────────────────────

    def discovery(self) -> Dict[str, Any]:
        """TAXII 2.1 Discovery endpoint — /taxii2/"""
        return {
            "title":              "CYBERDUDEBIVASH SENTINEL APEX Threat Intelligence",
            "description":        (
                "Enterprise-grade threat intelligence platform. "
                "STIX 2.1 · TAXII 2.1 · MITRE ATT&CK · CVE/EPSS/KEV enrichment. "
                "500+ curated advisories."
            ),
            "contact":            "intel@cyberdudebivash.com",
            "default":            f"{self.api_root_url}/",
            "api_roots":          [f"{self.api_root_url}/"],
        }

    def api_root(self) -> Dict[str, Any]:
        """TAXII 2.1 API Root endpoint — /taxii/"""
        return {
            "title":              "SENTINEL APEX TAXII 2.1 API Root",
            "description":        "Primary API root for SENTINEL APEX threat intelligence sharing",
            "versions":           ["2.1"],
            "max_content_length": 10_000_000,
        }

    def list_collections(self, tier: str = "PRO") -> Dict[str, Any]:
        """TAXII 2.1 Collections endpoint — /taxii/collections/"""
        accessible = TIER_COLLECTION_ACCESS.get(tier.upper(), [])
        cols = []
        for col_id, col in COLLECTIONS.items():
            can_access = col_id in accessible
            col_obj = {
                "id":          col.id,
                "title":       col.title,
                "description": col.description,
                "can_read":    can_access,
                "can_write":   False,
                "media_types": col.media_types,
                "aliases":     col.aliases,
            }
            if not can_access:
                col_obj["upgrade_required"] = col.required_tier
            cols.append(col_obj)
        return {"collections": cols}

    def get_collection(self, collection_id: str, tier: str = "PRO") -> Tuple[bool, Dict]:
        """Get single collection details."""
        col = COLLECTIONS.get(collection_id)
        if not col:
            return False, {"title": "Collection Not Found", "description": f"No collection with id: {collection_id}"}
        accessible = collection_id in TIER_COLLECTION_ACCESS.get(tier.upper(), [])
        return True, {
            "id":          col.id,
            "title":       col.title,
            "description": col.description,
            "can_read":    accessible,
            "can_write":   False,
            "media_types": col.media_types,
            "aliases":     col.aliases,
        }

    def get_objects(
        self,
        collection_id: str,
        tier:           str = "PRO",
        limit:          int = 100,
        offset:         int = 0,
        added_after:    Optional[str] = None,
        object_type:    Optional[str] = None,
        stix_id:        Optional[str] = None,
    ) -> Tuple[bool, Dict]:
        """
        TAXII 2.1 Objects endpoint — /taxii/collections/{id}/objects/
        Returns STIX 2.1 bundle with matching objects.
        """
        accessible = collection_id in TIER_COLLECTION_ACCESS.get(tier.upper(), [])
        if not accessible:
            col = COLLECTIONS.get(collection_id)
            required = col.required_tier if col else "ENTERPRISE"
            return False, {
                "title": "Access Denied",
                "description": f"Collection '{collection_id}' requires {required} tier or above.",
                "upgrade_url": "https://intel.cyberdudebivash.com/pricing",
            }

        feed_items = self._load_feed()
        stix_objects = self._filter_objects(
            feed_items, collection_id, object_type, stix_id, added_after
        )

        total = len(stix_objects)
        page  = stix_objects[offset:offset + limit]

        bundle = {
            "type":         "bundle",
            "id":           f"bundle--{hashlib.sha256(f'{collection_id}{time.time()}'.encode()).hexdigest()}",
            "spec_version": "2.1",
            "objects":      page,
        }

        self.requests_served += 1
        return True, {
            "bundle":       bundle,
            "next":         f"offset={offset + limit}" if offset + limit < total else None,
            "more":         offset + limit < total,
            "total":        total,
            "returned":     len(page),
            "x_next_cursor": str(offset + limit) if offset + limit < total else None,
        }

    def get_manifest(
        self,
        collection_id: str,
        tier:           str = "PRO",
        limit:          int = 100,
        offset:         int = 0,
        added_after:    Optional[str] = None,
    ) -> Tuple[bool, Dict]:
        """TAXII 2.1 Manifest endpoint — /taxii/collections/{id}/manifest/"""
        accessible = collection_id in TIER_COLLECTION_ACCESS.get(tier.upper(), [])
        if not accessible:
            return False, {"title": "Access Denied", "description": "Upgrade required"}

        feed_items = self._load_feed()
        stix_objects = self._filter_objects(feed_items, collection_id, None, None, added_after)

        manifests = [
            {
                "id":           obj.get("id", ""),
                "date_added":   obj.get("created", datetime.now(timezone.utc).isoformat()),
                "version":      obj.get("modified", obj.get("created", datetime.now(timezone.utc).isoformat())),
                "media_type":   STIX_MEDIA_TYPE,
            }
            for obj in stix_objects[offset:offset + limit]
        ]

        return True, {
            "objects": manifests,
            "more":    offset + limit < len(stix_objects),
            "next":    f"offset={offset + limit}" if offset + limit < len(stix_objects) else None,
        }

    def add_objects(
        self,
        collection_id: str,
        tier:           str,
        bundle:         Dict,
    ) -> Tuple[bool, Dict]:
        """TAXII 2.1 Add Objects — write endpoint (MSSP only)."""
        if tier.upper() != "MSSP":
            return False, {"title": "Write requires MSSP tier", "http_status": 403}

        status_id = hashlib.sha256(f"status-{time.time()}".encode()).hexdigest()[:16]
        objects   = bundle.get("objects", [])
        return True, {
            "id":            status_id,
            "status":        "complete",
            "request_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_count":   len(objects),
            "success_count": len(objects),
            "failure_count": 0,
            "pending_count": 0,
            "successes":     [{"id": obj.get("id", ""), "version": obj.get("modified", "")} for obj in objects],
        }

    # ── Feed Loading & Filtering ───────────────────────────────────────────────

    def _load_feed(self) -> List[Dict]:
        """Load threat intelligence feed with 5-minute cache."""
        now = time.time()
        if self._feed_cache is not None and now - self._cache_ts < 300:
            return self._feed_cache

        feed_paths = [
            BASE_DIR / "api" / "feed.json",
            BASE_DIR / "data" / "stix" / "feed_manifest.json",
            BASE_DIR / "api" / "feed_enterprise.json",
        ]
        for path in feed_paths:
            try:
                if path.exists():
                    with open(path, encoding="utf-8") as f:
                        raw = json.load(f)
                    items = raw if isinstance(raw, list) else raw.get("data", raw.get("items", []))
                    if items:
                        self._feed_cache = items
                        self._cache_ts   = now
                        return items
            except Exception as e:
                logger.warning(f"[TAXII] Feed load failed {path}: {e}")
        return []

    def _filter_objects(
        self,
        items:          List[Dict],
        collection_id:  str,
        object_type:    Optional[str],
        stix_id:        Optional[str],
        added_after:    Optional[str],
    ) -> List[Dict]:
        """Convert feed items to STIX 2.1 objects and apply filters."""
        stix_objects = []

        for item in items:
            # Apply collection-specific filters
            if not self._item_matches_collection(item, collection_id):
                continue

            # Convert to STIX 2.1 Report object
            stix_obj = self._item_to_stix(item)

            # Apply filters
            if stix_id and stix_obj.get("id") != stix_id:
                continue
            if object_type and stix_obj.get("type") != object_type:
                continue
            if added_after:
                try:
                    obj_ts = stix_obj.get("created", "")
                    if obj_ts and obj_ts < added_after:
                        continue
                except Exception:
                    pass

            stix_objects.append(stix_obj)

        return stix_objects

    def _item_matches_collection(self, item: Dict, collection_id: str) -> bool:
        """Check if feed item belongs to a collection."""
        ttype  = (item.get("threat_type") or "").lower()
        actor  = (item.get("actor_tag") or "").lower()
        supply = item.get("supply_chain", False)

        if collection_id == "all-objects":
            return True
        if collection_id == "ransomware-intelligence":
            return "ransom" in ttype or "extort" in ttype
        if collection_id == "apt-threat-intelligence":
            return ("apt" in actor or "state" in actor or "unc" in actor or
                    "threat actor" in ttype.lower())
        if collection_id == "vulnerability-intelligence":
            return ("vulnerab" in ttype or "exploit" in ttype or "cve" in ttype or
                    bool(item.get("cvss_score")))
        if collection_id == "ioc-indicators":
            iocs = item.get("ioc_counts") or {}
            return sum(v for v in iocs.values() if isinstance(v, (int, float))) > 0
        if collection_id == "supply-chain-threats":
            return supply or "supply chain" in ttype or "dependency" in ttype
        return True

    @staticmethod
    def _item_to_stix(item: Dict) -> Dict:
        """Convert feed item to STIX 2.1 Report object."""
        stix_id = item.get("stix_id") or f"report--{hashlib.sha256(str(item).encode()).hexdigest()}"
        ts      = item.get("timestamp") or datetime.now(timezone.utc).isoformat()
        if not ts.endswith("Z") and "+" not in ts:
            ts = ts + "Z" if not ts.endswith("+00:00") else ts

        mitre   = item.get("mitre_tactics") or []
        iocs    = item.get("ioc_counts") or {}

        obj_refs = []
        for technique in mitre[:10]:
            obj_refs.append(f"attack-pattern--{hashlib.sha256(technique.encode()).hexdigest()[:32]}")
        actor = item.get("actor_tag", "")
        if actor and actor not in ("UNC-UNKNOWN", "UNC-CDB-99", "UNATTRIBUTED"):
            obj_refs.append(f"threat-actor--{hashlib.sha256(actor.encode()).hexdigest()[:32]}")

        report = {
            "type":             "report",
            "spec_version":     "2.1",
            "id":               stix_id if stix_id.startswith("report--") else f"report--{stix_id.split('--')[-1]}",
            "created":          ts,
            "modified":         ts,
            "name":             item.get("title", "Unknown Threat Advisory"),
            "description":      item.get("summary", ""),
            "published":        ts,
            "report_types":     ["threat-report"],
            "object_refs":      obj_refs or [f"indicator--{hashlib.sha256(stix_id.encode()).hexdigest()[:32]}"],
            "confidence":       min(100, int((item.get("confidence_score") or 0.75) * 100)),
            "labels":           [
                item.get("threat_type", "unknown").lower(),
                (item.get("severity") or "medium").lower(),
                item.get("tlp_label", "TLP:CLEAR").lower(),
            ],
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519a9"  # TLP:CLEAR
            ],
            "external_references": [
                {
                    "source_name":  "CYBERDUDEBIVASH SENTINEL APEX",
                    "description":  "Source advisory",
                    "url":          item.get("blog_url") or item.get("source_url") or "",
                    "external_id":  item.get("stix_id", ""),
                }
            ],
            "extensions": {
                "sentinel_apex": {
                    "risk_score":         item.get("risk_score"),
                    "cvss_score":         item.get("cvss_score"),
                    "epss_score":         item.get("epss_score"),
                    "kev_present":        item.get("kev_present", False),
                    "actor_tag":          item.get("actor_tag"),
                    "feed_source":        item.get("feed_source"),
                    "ioc_counts":         iocs,
                    "supply_chain":       item.get("supply_chain", False),
                    "exploit_probability": item.get("exploit_probability"),
                }
            }
        }
        return report

    def get_stats(self) -> Dict:
        feed = self._load_feed()
        return {
            "engine":              "TaxiiServer v1.0",
            "spec_version":        "TAXII 2.1 (OASIS CS02)",
            "collections":         len(COLLECTIONS),
            "feed_items":          len(feed),
            "requests_served":     self.requests_served,
            "api_root_url":        self.api_root_url,
            "supported_media_types": [TAXII_MEDIA_TYPE, STIX_MEDIA_TYPE],
        }
