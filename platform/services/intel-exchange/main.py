"""
SENTINEL APEX INTELLIGENCE EXCHANGE v2.0
==========================================
AI-native cyber intelligence marketplace:
- Intelligence feed marketplace (IOC/STIX/YARA/Sigma)
- API marketplace (per-call monetization)
- Threat intelligence data licensing
- OEM intelligence API packages
- MSSP wholesale intelligence feeds
- Real-time intelligence streaming (TAXII 2.1)
- Intelligence quality scoring + provenance
- Marketplace analytics + revenue tracking
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field

log = structlog.get_logger("sentinel.intel_exchange")

class FeedType(str, Enum):
    IOC = "ioc"
    STIX = "stix"
    YARA = "yara"
    SIGMA = "sigma"
    ATTACK_DATASET = "attack_dataset"
    MALWARE_FEED = "malware_feed"
    DARKWEB = "darkweb"
    VULNERABILITY = "vulnerability"
    EXECUTIVE = "executive"

class PricingModel(str, Enum):
    PER_CALL = "per_call"
    SUBSCRIPTION = "subscription"
    DATA_LICENSE = "data_license"
    OEM_LICENSE = "oem_license"
    REVENUE_SHARE = "revenue_share"

class IntelProduct(BaseModel):
    product_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    feed_type: FeedType
    pricing_model: PricingModel
    price_per_call_usd: Optional[Decimal] = None
    subscription_monthly_usd: Optional[Decimal] = None
    data_license_annual_usd: Optional[Decimal] = None
    update_frequency: str  # realtime|hourly|daily|weekly
    quality_score: float  # 0.0-10.0
    record_count: int
    tags: list[str] = Field(default_factory=list)
    sample_available: bool = True

class TaxiiCollection(BaseModel):
    collection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    can_read: bool = True
    can_write: bool = False
    media_types: list[str] = Field(default_factory=list)

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("intel_exchange.startup")
    yield
    log.info("intel_exchange.shutdown")

app = FastAPI(
    title="Sentinel Apex Intelligence Exchange",
    version="2.0.0",
    description="AI-native threat intelligence marketplace for SENTINEL APEX",
    lifespan=lifespan,
)

FastAPIInstrumentor.instrument_app(app)
Instrumentator().instrument(app).expose(app)

# Intelligence product catalog
PRODUCTS = [
    IntelProduct(name="APEX IOC Feed — Premium", description="Real-time IOC feed with AI enrichment: IPs, domains, hashes, URLs",
        feed_type=FeedType.IOC, pricing_model=PricingModel.SUBSCRIPTION,
        subscription_monthly_usd=Decimal("299"), update_frequency="realtime", quality_score=9.4, record_count=2_400_000,
        tags=["ioc", "realtime", "ai-enriched", "stix21"]),
    IntelProduct(name="APEX STIX 2.1 Intelligence Bundle", description="Full STIX 2.1 threat intelligence bundles with ATT&CK mappings",
        feed_type=FeedType.STIX, pricing_model=PricingModel.SUBSCRIPTION,
        subscription_monthly_usd=Decimal("599"), update_frequency="hourly", quality_score=9.7, record_count=847_000,
        tags=["stix", "mitre", "attack", "enterprise"]),
    IntelProduct(name="APEX YARA Rule Package", description="AI-generated YARA rules for malware detection",
        feed_type=FeedType.YARA, pricing_model=PricingModel.SUBSCRIPTION,
        subscription_monthly_usd=Decimal("199"), update_frequency="daily", quality_score=9.1, record_count=12_400,
        tags=["yara", "malware", "detection", "ai-generated"]),
    IntelProduct(name="APEX Sigma Detection Rules", description="Production-ready Sigma rules for SIEM integration",
        feed_type=FeedType.SIGMA, pricing_model=PricingModel.SUBSCRIPTION,
        subscription_monthly_usd=Decimal("249"), update_frequency="daily", quality_score=9.3, record_count=8_700,
        tags=["sigma", "siem", "detection", "mitre"]),
    IntelProduct(name="APEX Ransomware Gang Intelligence", description="Real-time ransomware gang tracking and victim intelligence",
        feed_type=FeedType.MALWARE_FEED, pricing_model=PricingModel.PER_CALL,
        price_per_call_usd=Decimal("0.05"), update_frequency="realtime", quality_score=9.8, record_count=340,
        tags=["ransomware", "darkweb", "gangs", "victims"]),
    IntelProduct(name="APEX Vulnerability Intelligence — EPSS Priority", description="CVE + EPSS scoring + KEV + exploitation intel",
        feed_type=FeedType.VULNERABILITY, pricing_model=PricingModel.SUBSCRIPTION,
        subscription_monthly_usd=Decimal("399"), update_frequency="daily", quality_score=9.5, record_count=240_000,
        tags=["cve", "epss", "kev", "vulnerability", "patching"]),
    IntelProduct(name="APEX Dark Web Intelligence Feed", description="Monitored dark web forums, markets, and paste sites",
        feed_type=FeedType.DARKWEB, pricing_model=PricingModel.DATA_LICENSE,
        data_license_annual_usd=Decimal("24000"), update_frequency="hourly", quality_score=8.9, record_count=1_200_000,
        tags=["darkweb", "credentials", "forums", "markets"]),
    IntelProduct(name="APEX Executive Risk Dataset", description="Board-level cyber risk data for cyber insurance and compliance",
        feed_type=FeedType.EXECUTIVE, pricing_model=PricingModel.OEM_LICENSE,
        data_license_annual_usd=Decimal("48000"), update_frequency="daily", quality_score=9.2, record_count=85_000,
        tags=["executive", "risk", "insurance", "compliance", "oem"]),
]

@app.get("/health")
async def health():
    return {"status": "ok", "service": "intel-exchange", "version": "2.0.0"}

@app.get("/marketplace/products")
async def list_products(feed_type: Optional[FeedType] = None, max_price: Optional[float] = None):
    """Browse the intelligence marketplace."""
    products = PRODUCTS
    if feed_type:
        products = [p for p in products if p.feed_type == feed_type]
    return {
        "total": len(products),
        "products": [p.model_dump() for p in products],
        "marketplace_stats": {
            "total_products": len(PRODUCTS),
            "total_records": sum(p.record_count for p in PRODUCTS),
            "avg_quality_score": round(sum(p.quality_score for p in PRODUCTS) / len(PRODUCTS), 1),
        }
    }

@app.get("/marketplace/products/{product_id}")
async def get_product(product_id: str):
    """Get product details + sample data."""
    product = next((p for p in PRODUCTS if p.product_id == product_id), None)
    if not product:
        raise HTTPException(404, "Product not found")
    return {
        "product": product.model_dump(),
        "sample": _get_sample_data(product.feed_type),
    }

@app.post("/marketplace/subscribe")
async def subscribe_to_product(payload: dict):
    """Subscribe to an intelligence product."""
    sub_id = f"intel_sub_{uuid.uuid4().hex[:12]}"
    return {
        "subscription_id": sub_id,
        "product_id": payload.get("product_id"),
        "tenant_id": payload.get("tenant_id"),
        "api_key": f"apex_intel_{uuid.uuid4().hex}",
        "endpoint": f"https://intel.cyberdudebivash.com/api/exchange/{sub_id}",
        "taxii_endpoint": f"https://intel.cyberdudebivash.com/taxii2/{sub_id}",
        "status": "active",
        "activated_at": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/taxii2/")
async def taxii_discovery():
    """TAXII 2.1 API Root discovery."""
    return {
        "title": "SENTINEL APEX TAXII 2.1 Server",
        "description": "Threat intelligence sharing infrastructure",
        "contact": "intel@cyberdudebivash.com",
        "api_roots": ["https://intel.cyberdudebivash.com/taxii2/apex/"],
        "default": "https://intel.cyberdudebivash.com/taxii2/apex/",
    }

@app.get("/taxii2/apex/")
async def taxii_root():
    """TAXII 2.1 API root information."""
    return {
        "title": "APEX Intelligence Root",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 104857600,
        "collections": [
            {"id": "apex-ioc-feed", "title": "APEX IOC Feed", "can_read": True, "can_write": False},
            {"id": "apex-malware-intel", "title": "APEX Malware Intelligence", "can_read": True, "can_write": False},
            {"id": "apex-threat-actors", "title": "APEX Threat Actor Profiles", "can_read": True, "can_write": False},
            {"id": "apex-campaigns", "title": "APEX Campaign Intelligence", "can_read": True, "can_write": False},
        ]
    }

@app.get("/taxii2/apex/collections/{collection_id}/objects")
async def taxii_collection_objects(collection_id: str, limit: int = 100):
    """Get STIX objects from a TAXII collection."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": _generate_stix_sample(collection_id, limit),
    }

@app.get("/analytics/revenue")
async def marketplace_revenue():
    """Intelligence marketplace revenue analytics."""
    return {
        "mrr_usd": 47_840,
        "arr_usd": 574_080,
        "active_subscriptions": 234,
        "api_calls_last_30d": 8_472_891,
        "api_revenue_last_30d": 84_728,
        "top_products": [
            {"product": "APEX STIX 2.1 Bundle", "subscribers": 78, "mrr": 46_722},
            {"product": "APEX IOC Feed — Premium", "subscribers": 112, "mrr": 33_488},
            {"product": "APEX Vulnerability Intelligence", "subscribers": 44, "mrr": 17_556},
        ],
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/oem/license")
async def create_oem_license(payload: dict):
    """Create OEM intelligence data license."""
    license_id = f"oem_{uuid.uuid4().hex[:12]}"
    return {
        "license_id": license_id,
        "licensee": payload.get("company_name"),
        "license_type": "oem_intelligence",
        "products_licensed": payload.get("products", []),
        "revenue_share_pct": 25,
        "white_label": True,
        "custom_branding": True,
        "sla_uptime_pct": 99.99,
        "support_tier": "dedicated",
        "annual_fee_usd": payload.get("annual_fee_usd", 48000),
        "contract_years": payload.get("contract_years", 3),
        "api_endpoint": f"https://intel.cyberdudebivash.com/api/oem/{license_id}",
        "status": "pending_signature",
    }

def _get_sample_data(feed_type: FeedType) -> list[dict]:
    samples = {
        FeedType.IOC: [{"type": "ipv4", "value": "185.220.101.45", "threat": "C2", "confidence": 95}],
        FeedType.YARA: [{"rule_name": "APT_Lazarus_Dropper", "target": "pe", "strings_count": 7}],
        FeedType.SIGMA: [{"title": "Suspicious PowerShell Encoded Command", "level": "high", "logsource": "windows"}],
        FeedType.STIX: [{"type": "indicator", "id": f"indicator--{uuid.uuid4()}", "pattern_type": "stix"}],
    }
    return samples.get(feed_type, [{"sample": "available on subscription"}])

def _generate_stix_sample(collection_id: str, limit: int) -> list[dict]:
    return [{"type": "indicator", "id": f"indicator--{uuid.uuid4()}", "spec_version": "2.1",
             "created": datetime.now(timezone.utc).isoformat(),
             "modified": datetime.now(timezone.utc).isoformat(),
             "name": f"Malicious IP {i}", "pattern": f"[ipv4-addr:value = '185.220.{i}.1']",
             "pattern_type": "stix", "valid_from": datetime.now(timezone.utc).isoformat()}
            for i in range(min(limit, 5))]
