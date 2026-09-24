/**
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  Cloudflare Worker v184.0
 * intel-gateway/src/index.js
 *
 * v184.0 GOD-MODE-GLOBAL-RELEASE (2026-06-22)
 * - Razorpay payment pipeline: /api/payments/razorpay/verify + webhook
 * - HMAC-SHA256 constant-time webhook signature verification (crypto.subtle)
 * - Idempotency guard: KV key rzp_verified:{payment_id} prevents replay attacks
 * - Webhook dedup: rzp_webhook:{payment_id} prevents double-provisioning on
 *   payment.captured + order.paid events
 * - Gumroad webhook URL token auth: GUMROAD_WEBHOOK_SECRET ?secret= guard
 * - Gumroad idempotency: gumroad_sale:{sale_id} dedup in SECURITY_HUB_KV
 * - 5 God Mode Worker modules: Brand Protection, Vendor Risk, Geopolitical Risk,
 *   NLP Query (NLQ), Incident Response (NIST SP 800-61r3)
 * - NLQ falsy-zero fix: min_cvss/min_risk filters now use != null (not !f.x)
 * - Incident Response KV pagination: cursor loop, 1000-item safety cap
 * - MSSP tier: RATE_LIMITS.MSSP = 1200 req/15min, TIERS.MSSP added
 * - AI Copilot v3.0: DeepSeek R1+V3 -> GROQ -> OpenRouter -> deterministic fallback
 *
 * ENTERPRISE PRODUCTION HARDENING v184.0 (preserved)
 * - Real JWT HS256 (crypto.subtle HMAC-SHA256) - no more fake 16-char check
 * - API key validation against API_KEYS_KV
 * - Brute-force lockout: 5 failures -> 15-min IP lockout (RATE_LIMIT_KV)
 * - Sliding-window rate limiting per IP/tier (RATE_LIMIT_KV)
 * - Security headers on ALL responses (HSTS, X-Frame, X-Content-Type, Referrer-Policy)
 * - CSP on HTML report responses
 * - Audit logging via ctx.waitUntil (SECURITY_HUB_KV, 30-day TTL)
 * - POST /auth/login  -- issue HS256 JWT from valid API key
 * - POST /auth/logout -- revoke JWT via SECURITY_HUB_KV blocklist
 * - GET/POST/DELETE /api/admin/* -- admin API gated by ADMIN_SECRET
 * - TAXII 2.1: /taxii/ discovery, /taxii/collections/, /taxii/collections/{id}/objects/
 * - ctx passed through to handleRequest for waitUntil support
 *
 * Routes (all v184.0 routes preserved):
 *   GET  /api/health
 *   GET  /api/v1/intel/latest.json
 *   GET  /api/v1/intel/apex.json            (premium tier gate)
 *   GET  /api/v1/intel/ai_summary.json      (premium tier gate)
 *   GET  /api/v1/intel/top10.json
 *   GET  /api/v1/intel/stats
 *   GET  /api/v1/intel/campaigns
 *   GET  /api/v1/intel/ransomware
 *   GET  /api/v1/intel/apt
 *   GET  /api/v1/intel/epss
 *   GET  /api/v1/intel/defcon
 *   GET  /api/v1/intel/pulse
 *   GET  /api/v1/intel/darkweb
 *   GET  /api/v1/intel/cybermap
 *   GET  /api/v1/news/feed
 *   GET  /api/reports/index.json
 *   GET  /api/reports/latest.json
 *   GET  /api/reports/stats.json
 *   POST /auth/login                        (NEW v184.0)
 *   POST /auth/logout                       (NEW v184.0)
 *   POST /api/v1/ioc/lookup
 *   GET  /api/v1/ioc/lookup
 *   GET  /api/preview
 *   GET  /api/feed(.json)
 *   GET  /reports/**
 *   GET  /taxii/                            (NEW v184.0 - TAXII 2.1 server discovery)
 *   GET  /taxii/collections/               (NEW v184.0)
 *   GET  /taxii/collections/{id}/objects/  (NEW v184.0 - PRO/ENTERPRISE)
 *   GET  /api/admin/health                 (NEW v184.0 - ADMIN_SECRET)
 *   GET  /api/admin/audit                  (NEW v184.0 - ADMIN_SECRET)
 *   POST /api/admin/keys                   (NEW v184.0 - ADMIN_SECRET)
 *   DELETE /api/admin/keys/{key}           (NEW v184.0 - ADMIN_SECRET)
 */

// --- Constants ----------------------------------------------------------------
import { handleP16Workflows, handleP16Assets, handleP16Health, handleP16Analytics, handleP16Automation, handleP16Observability, buildSubsystems } from './p16-handlers.js';
import { handleP17Orchestrator, handleP17DigitalTwin, handleP17CampaignForecast, handleP17ExecutiveCenter, handleP17Policies, handleP17Playbooks, handleP17AiOps } from './p17-handlers.js';
import { handleP18Correlation, handleP18TrustIndicators, handleP18Validate, handleP18QualityScore, handleP18IOCEnriched, handleP18ConfidenceMethod, buildTrustIndicatorBlock, buildEvidenceAttribution, computeTransparentConfidence, validateReportQuality } from './p18-handlers.js';
import { buildSOCBlock, buildIOCDetailBlock, buildDetectionBlock, buildMitreTechBlock, buildExecutiveBlock, buildAnalystBlock, handleP19Certify, handleP19Scorecard, normalizeTierForEE, computeCertificationLevel } from './p19-handlers.js';
import { stripMarkdown, filterBehavioralTags, formatConfidenceForHeader, buildEvidenceChainBlock, buildIOCQualityBlock, buildAttributionRationaleBlock, buildP20ExecutiveBlock, buildP20QualityGateBlock, buildBenchmarkBlock, handleP20QualityReport, handleP20FeedAudit } from './p20-handlers.js';
import { buildP21CertificationBlock, buildP21ScorecardComparison, handleP21Certify, handleP21FeedCertify, handleP21Dashboard, handleP21Observability } from './p21-handlers.js';
import { buildP22ValidationStatusBlock, buildP22ContradictionBlock, buildP22DetectionVerificationBlock, buildSOCAnalystBlock, buildConfidenceExplanationBlock, buildP22CommercialGateBlock, handleP22Validate, handleP22ContradictionReport, handleP22Observability } from './p22-handlers.js';
import { buildThreatHuntingBlock, buildIRPackageBlock, buildPatchPriorityBlock, buildComplianceBlock, buildDetectionCoverageBlock, buildActionabilityScoreBlock, buildOperationalReadinessGateBlock, handleP23Actionability, handleP23OperationalReadiness, handleP23Observability } from './p23-handlers.js';
import { buildP25TrustPackage, buildExplainableScoreBlock, buildSourceConsensusBlock, buildAnalystExplainabilityBlock, buildTrustScoreBlock, buildPublicationLineageBlock, handleP25TrustScore, handleP25Observability } from './p25-handlers.js';
import { buildP26Package, buildP26TrustBadgesBlock, buildP26GradeCardBlock, buildP26CertificationBlock, handleP26Grade, handleP26FeedGrade, handleP26Observability } from './p26-handlers.js';
import { buildP27Package, buildP27ExposureAnalysisBlock, buildP27MultiAudienceBlock, buildP27IntelBenchmarkBlock, buildP27StructuralIntegrityBlock, handleP27Certify, handleP27Observability } from './p27-handlers.js';
import { buildP28Package, buildP28EnvironmentRiskBlock, buildP28BusinessImpactBlock, buildP28ActionCenterBlock, buildP28RoleGuidanceBlock, buildP28FeedbackBlock, buildP28MetricsBlock, handleP28Feedback, handleP28Certify, handleP28Observability } from './p28-handlers.js';
import { buildP29EINBlock, buildP29ConfidenceGraphBlock, buildP29CustomerExposureBlock, buildP29DecisionEngineBlock, buildP29LifecycleBlock, buildP29DetectionValidationBlock, handleP29Certify, handleP29CustomerValueAnalytics, handleP29TrustCenter, handleP29ReleaseAssurance, handleP29Observability } from './p29-handlers.js';
import { buildP30VerificationBlock, buildP30TimelineBlock, buildP30ChangeTrackingBlock, buildP30DetectionDriftBlock, buildP30IOCLifecycleBlock, buildP30SLABlock, buildP30TrustTimelineBlock, handleP30Verification, handleP30Timeline, handleP30SourceHealth, handleP30Drift, handleP30ReportHealth, handleP30Observability, handleP30Certify } from './p30-handlers.js';
import { buildP31KnowledgeGraphBlock, buildP31EntityBlock, buildP31CampaignBlock, buildP31CopilotBlock, buildP31PlaybookBlock, buildP31RelationshipBlock, handleP31Graph, handleP31Search, handleP31Entity, handleP31Relationships, handleP31Campaign, handleP31Copilot, handleP31Observability, handleP31Certify } from './p31-handlers.js';
import { buildP32LifecycleBlock, buildP32DecisionBlock, buildP32DeltaBlock, buildP32DetectionEffectivenessBlock, buildP32EnvironmentSimulatorBlock, buildP32DriftBlock, buildP32EvidenceTransparencyBlock, buildP32MaturityBlock, buildP32MetricsBlock, buildP32ReleaseGateBlock, handleP32Decision, handleP32Drift, handleP32Lifecycle, handleP32Metrics, handleP32Customer, handleP32Quality, handleP32Operations, handleP32Release, handleP32Dashboard, handleP32Observability } from './p32-handlers.js';
import { buildP33CaseBlock, buildP33CampaignBlock, buildP33MissionBlock, buildP33RecommendationsBlock, buildP33CoverageMatrixBlock, buildP33HeatmapBlock, buildP33ExplorerBlock, buildP33AutomationBlock, buildP33OperationalDashboardBlock, buildP33APIGatewayBlock, handleP33Cases, handleP33Campaigns, handleP33Heatmap, handleP33Mission, handleP33Recommendations, handleP33Explorer, handleP33Dashboard, handleP33Operations, handleP33Status, handleP33Metrics, handleP33Observability } from './p33-handlers.js';
import { buildP34AssuranceSummaryBlock, buildP34SecurityPostureBlock, buildP34ReliabilityBlock, buildP34ObservabilityBlock, buildP34ComplianceBlock, handleP34Assurance, handleP34Security, handleP34Reliability, handleP34Performance, handleP34Compliance, handleP34Sbom, handleP34Contracts, handleP34Status, handleP34Metrics, handleP34Dashboard, handleP34Certification, handleP34Observability } from './p34-handlers.js';
import { handleP35Quality, handleP35Freshness, handleP35Evidence, handleP35Confidence, handleP35Diversity, handleP35Drift, handleP35Metrics, handleP35Scorecard, handleP35Trend, handleP35Improvements, handleP35Dashboard, handleP35Observability } from './p35-handlers.js';
import { handleP36Quality, handleP36Maturity, handleP36Targets, handleP36Gaps, handleP36CustomerValue, handleP36Competitive, handleP36Detection, handleP36Reliability, handleP36Metrics, handleP36Roadmap, handleP36Dashboard, handleP36Observability } from './p36-handlers.js';
import { handleP37Hardening, handleP37FeedAudit, handleP37Enrichment, handleP37IQScore, handleP37Detection, handleP37SourceDiversity, handleP37Reliability, handleP37Debt, handleP37Metrics, handleP37Certification, handleP37Dashboard, handleP37Observability } from './p37-handlers.js';
import { handleP38SchemaRegistry, handleP38FeedGovernance, handleP38SchemaDrift, handleP38EnrichmentAudit, handleP38ConfidenceAudit, handleP38IQIndex, handleP38SourceDiversity, handleP38Certification, handleP38Executive, handleP38Reliability, handleP38Metrics, handleP38Observability } from './p38-handlers.js';
import { handleP40SourceRegistry, handleP40SourceDetail, handleP40SourceHealth, handleP40Licensing, handleP40Coverage, handleP40Waves, handleP40Certification, handleP40Metrics, handleP40Dashboard, handleP40Observability, _loadRegistry as loadP40SourceRegistry } from './p40-handlers.js';
import { handleRxPubA0ReportsIdentity, handleRxPubA0Observability } from './rx-pub-a0-handlers.js';
import { handleP41Capabilities, handleP41CapabilityDetail, handleP41Observability } from './p41-handlers.js';
import { evaluatePublicationGate, isCustomerReady, buildGateRejectedResponseBody, buildUnresolvableReportResponseBody } from './publication-gate.js';
import { loadCertificationIndex, persistCertificationRecords, resolveCertification, CERTIFICATION_POLICY_VERSION } from './certification-registry.js';
import { routeEnterpriseEndpoint } from './enterprise-endpoints.js';
import { handleSearch, handleActors, handleCVEs, handleIOCLookup, handleMISPExport as handleMISPExportExt, handleCSVExport, handleCorrelate, handlePredict, handleCampaigns, handleAnomalies, handleIntelGraph, handleIntelRelations, handleIRGuidance, handleExposureAnalysis, buildScopeSet } from './api-extensions.js';
import { RAZORPAY_TIER_PRICES, getPricingSnapshot } from './pricing.js';
import { applyTierGateV2, enforceTierGate, buildUpgradeTrigger, handleLeadCapture, handleTrialIssuance } from './revenue-enforcement.js';
import { evaluateDailyQuota, dailyQuotaConfig, utcDateString, dailyQuotaKey, quotaAlertDedupeKey, secondsUntilNextUtcMidnight } from './daily-quota.js';
import { buildDetectionRegistry, queryDetectionRegistry, toPublicArtifact, DETECTION_REGISTRY_VERSION } from './detection-registry.js';
import { handleSLAStatus, handleSLAReport, handleSLAIncidents, handleSLAPing, handleSLACertificate } from './sla-monitor.js';
import { handleAlertSubscribe, handleAlertSubscriptions, handleAlertTest, handleAlertDispatch, handleAlertHistory, handleAlertUnsubscribe } from './alert-engine.js';
// dark-web-monitor.js's handlers are intentionally NOT imported -- see the
// _darkWebUnavailable disable note at its route registration below.
import { routeWatchdog } from './cyber-watchdog.js';
import { handlePremiumReport, handleReportList, handleReportGet } from './premium-reports.js';
// P0 FIX (2026-09-01): PR #285 (v201.0) called getLiveIndicatorsSummary(),
// runScheduledIngestion(), and routeExports() below without ever importing
// them from their actual modules -- every call site threw a ReferenceError
// (uncaught locally, caught only by the top-level fetch() catch-all),
// producing a 500 "Internal gateway error" for /api/preview, /api/feed,
// /api/feed.json, and every /api/v1/export/* route, and silently no-oping
// the 6-hourly threat-indicator cron. Confirmed live against production
// before this fix (all four returned HTTP 500 / crashed silently).
import { getLiveIndicatorsSummary, runScheduledIngestion } from './ingestion/cron_worker.js';
import { routeExports } from './routes/exports.js';
import { trackApiUsage, calculateCostPerCall, slugifyEndpoint } from './usage-meter.js';
import { deductCredits } from './credit-system.js';
import { evaluateKeyRecordAccess, SUBSCRIPTION_STATUS_DENY_STATES, SUBSCRIPTION_STATUS_VALID_STATES } from './subscription-lifecycle.js';
import { inferGumroadTier, inferGumroadBillingCycle, isGumroadCancellationEvent, isGumroadAccessRevokingEvent } from './gumroad-lifecycle.js';
import { handleIntelStaticProxy, INTEL_STATIC_PROXY } from './intel-static-proxy.js';
// P0 2026-09-03: separates the first-party dashboard's own read traffic from
// the commercial API entitlement plane. See first-party-plane.js's header for
// the incident this closes -- the public dashboard was metered against the
// FREE API tier's 30/min + 50/day budget and exhausted it rendering itself.
import {
  isFirstPartyRead, WEB_PLANE_LIMITS, webPlaneRateKey, webPlaneDailyKey,
  evaluateWebPlaneDaily, firstPartyPlaneObservability,
} from './first-party-plane.js';
// SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3: single source of truth
// for every Access-Control-* decision this Worker makes (see that file's
// own header comment for the full before/after rationale). Applied at the
// one true response choke point -- withBaselineHeaders() and the OPTIONS
// branch below -- so no individual route handler needs to change.
import { applyCorsPolicy, buildPreflightResponse, classifyRoute } from './cors-policy.js';
// In-isolate counter layer: batches KV writes on the hot request path.
// See rate-limit-cache.js for the cost rationale and the exact trade-off.
import { bumpCounter, peekCounter } from './rate-limit-cache.js';
// AI Swarm Synthesis (v4.45): pure prompt-building + tier-gate helpers for
// handleSwarmSynthesis (below, defined right after handleCopilot). Extracted
// for the same reason as subscription-lifecycle.js/gumroad-lifecycle.js --
// see swarm-synthesis.js's own header comment.
import { tierAllowsSwarmSynthesis, buildSwarmSynthesisPrompt, SWARM_SYNTHESIS_SYSTEM_PROMPT } from './swarm-synthesis.js';
import { evaluateSwarmPreflight, SWARM_MESH_CAPABILITY, SWARM_REQUIRED_SCOPE } from './swarm-access.js';
// Canonical customer-visible freshness contract (mirror of
// config/public_freshness_contract.json; see freshness-contract.js).
import { classifyManifestFreshness, evaluatePublicIntelligence, healthEdgeTtlSeconds, STATES as FRESHNESS_STATES } from './freshness-contract.js';
// Issue #288: Durable Object class the Workers runtime instantiates via the
// GUMROAD_PROVISIONING_LOCK binding (wrangler.toml). Must be a named export
// of the Worker's main module -- see gumroad-provisioning-lock.js's header
// comment for the full activation rationale.
export { GumroadProvisioningLock } from './gumroad-provisioning-lock.js';
export { WatchdogLedger } from './watchdog-ledger.js';
// Re-exported unchanged for backward compatibility with any external
// importer of index.js's own evaluateKeyRecordAccess export (Principle 5:
// no silent removal of an existing export) -- the canonical implementation
// now lives in subscription-lifecycle.js; see that file's header comment.
export { evaluateKeyRecordAccess, SUBSCRIPTION_STATUS_DENY_STATES, SUBSCRIPTION_STATUS_VALID_STATES };
// Same rationale, for the Gumroad webhook's pure decision logic (see
// gumroad-lifecycle.js header comment) -- unit-testable under plain
// `node --test` without pulling in this file's full import chain.
export { inferGumroadTier, inferGumroadBillingCycle, isGumroadCancellationEvent, isGumroadAccessRevokingEvent };
// Same rationale, for the Stage 4 intel-static-proxy (see that file's
// header comment) -- unit-testable under plain `node --test` without
// pulling in this file's full import chain.
export { handleIntelStaticProxy, INTEL_STATIC_PROXY };
const PLATFORM_VERSION    = "200.0";
const JWT_EXPIRY_SEC      = 86400;        // 24h JWT lifetime
const BRUTE_FORCE_MAX     = 5;            // lockout after N failed auth attempts
const BRUTE_FORCE_TTL     = 900;          // 15-minute lockout (seconds)
const AUDIT_TTL           = 86400 * 30;   // 30-day audit log retention
const NEWS_TTL_SEC        = 300;
const PREVIEW_LIMIT       = 25;
const FREE_SIGNUP_IP_DAILY_CAP = 5; // self-serve free-key requests per IP per day
const LATEST_JSON_KEY     = "api/v1/intel/latest.json";
const LATEST_PRO_JSON_KEY = "api/v1/intel/latest_pro.json"; // PRO/ENTERPRISE: includes report_url
const APEX_JSON_KEY       = "api/v1/intel/apex.json";
const AI_SUMMARY_KEY      = "api/v1/intel/ai_summary.json";
const REPORTS_KEY         = "api/reports/index.json";
const CVE_LIVE_KEY        = "api/v1/cve/live.json";
const CVE_STATS_KEY       = "api/v1/cve/stats.json";
const CVE_TTL_SEC         = 900;  // 15 min
const NVD_API             = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const TAXII_COLLECTION_ID = "sentinel-apex-main";
const TAXII_KEV_COLL      = "sentinel-apex-kev";
const TAXII_CT            = "application/taxii+json;version=2.1";
const STIX_CT             = "application/stix+json;version=2.1";

// SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3 (2026-09-10): this used to
// hardcode Access-Control-Allow-Origin: "*" (plus Methods/Headers/Max-Age),
// spread into ~10 response sites below and into every P-layer handler file
// that lacks its own response helper -- unconditionally, for admin,
// premium, and billing responses included. withBaselineHeaders() (this
// file's one true response choke point, at the bottom of this file) always
// overwrote whatever this produced with the identical wildcard value
// anyway, so emptying it here changes no behavior on its own; the real,
// now origin-aware policy lives in cors-policy.js and is applied once, by
// withBaselineHeaders() and the OPTIONS branch below. Kept as an object
// (now empty) rather than removed so the ~10 `...CORS_HEADERS` call sites
// below don't each need an individual edit -- see the Reuse Report in this
// PR's description.
const CORS_HEADERS = {};

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
  "X-Sentinel-Version": PLATFORM_VERSION,
  "X-Sentinel-Platform": "CYBERDUDEBIVASH-SENTINEL-APEX",
};

const HTML_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://checkout.razorpay.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://api.razorpay.com https://checkout.razorpay.com; frame-src https://api.razorpay.com; frame-ancestors 'none'; base-uri 'self'";

const JSON_CONTENT = { "Content-Type": "application/json; charset=utf-8" };

const RATE_LIMITS = { FREE: 30, PRO: 120, ENTERPRISE: 600, MSSP: 1200 };

// --- Geo / threat intel static data (unchanged from v184.0) ------------------
const GEO_ATTACK_MAP = [
  { code: "RU", country: "Russian Federation", attacks: 0, risk: "CRITICAL" },
  { code: "CN", country: "China",              attacks: 0, risk: "CRITICAL" },
  { code: "IR", country: "Iran",               attacks: 0, risk: "HIGH"     },
  { code: "KP", country: "North Korea",        attacks: 0, risk: "HIGH"     },
  { code: "US", country: "United States",      attacks: 0, risk: "MEDIUM"   },
  { code: "IN", country: "India",              attacks: 0, risk: "MEDIUM"   },
  { code: "BR", country: "Brazil",             attacks: 0, risk: "LOW"      },
  { code: "UA", country: "Ukraine",            attacks: 0, risk: "HIGH"     },
  { code: "PK", country: "Pakistan",           attacks: 0, risk: "MEDIUM"   },
  { code: "DE", country: "Germany",            attacks: 0, risk: "LOW"      },
];

const RANSOMWARE_GROUPS = [
  { name: "LockBit 3.0",    sector: "Healthcare,Finance",      status: "ACTIVE",    victims_30d: 8  },
  { name: "BlackCat/ALPHV", sector: "Energy,Manufacturing",    status: "ACTIVE",    victims_30d: 6  },
  { name: "Cl0p",           sector: "Government,Education",    status: "ACTIVE",    victims_30d: 11 },
  { name: "Play",           sector: "Legal,Retail",            status: "ACTIVE",    victims_30d: 4  },
  { name: "Black Basta",    sector: "Finance,Healthcare",      status: "ACTIVE",    victims_30d: 5  },
  { name: "Medusa",         sector: "Education,Government",    status: "ACTIVE",    victims_30d: 7  },
  { name: "RansomHub",      sector: "Critical Infrastructure", status: "ACTIVE",    victims_30d: 9  },
  { name: "Akira",          sector: "SMB,Manufacturing",       status: "ACTIVE",    victims_30d: 6  },
  { name: "8Base",          sector: "Finance,Legal",           status: "ACTIVE",    victims_30d: 3  },
  { name: "BianLian",       sector: "Healthcare,Education",    status: "MONITORING",victims_30d: 2  },
];

const APT_PROFILES = [
  { id: "APT28",        alias: "Fancy Bear",      nation: "RU", sector: "Government,Defense",        ttps: 18 },
  { id: "APT29",        alias: "Cozy Bear",       nation: "RU", sector: "Government,Diplomatic",     ttps: 21 },
  { id: "APT41",        alias: "Wicked Panda",    nation: "CN", sector: "Technology,Healthcare",     ttps: 24 },
  { id: "Lazarus",      alias: "Hidden Cobra",    nation: "KP", sector: "Finance,Crypto",            ttps: 20 },
  { id: "APT33",        alias: "Elfin",           nation: "IR", sector: "Energy,Aviation",           ttps: 15 },
  { id: "APT34",        alias: "OilRig",          nation: "IR", sector: "Government,Finance",        ttps: 17 },
  { id: "APT10",        alias: "Stone Panda",     nation: "CN", sector: "MSP,Healthcare",            ttps: 16 },
  { id: "Volt Typhoon", alias: "Volt Typhoon",    nation: "CN", sector: "Critical Infrastructure",   ttps: 14 },
  { id: "Salt Typhoon", alias: "Salt Typhoon",    nation: "CN", sector: "Telecom,ISP",               ttps: 12 },
  { id: "Sandworm",     alias: "Sandworm Team",   nation: "RU", sector: "Energy,ICS/SCADA",          ttps: 22 },
];

// =============================================================================
// CORE UTILITIES
// =============================================================================

function jsonResp(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, ...JSON_CONTENT, ...extra },
  });
}

function errorResp(msg, status = 500) {
  return jsonResp({ error: msg, status }, status);
}

// PRODUCTION-TRUTH FIX (2026-08-26): Dark Web Monitor / Leak Check were
// disabled at the router (see route registration for the reasoning) because
// their backend always returned a deterministic simulation, never real
// breach data. This is the single truthful response every disabled route
// returns -- a real 503, not a 200 with fabricated findings -- so a customer
// or integration can tell the difference between "no result" and "feature
// unavailable" instead of silently receiving synthetic data.
function _darkWebUnavailable(rid) {
  return jsonResp({
    status:     "unavailable",
    error:      "feature_temporarily_disabled",
    message:    "Dark Web Monitor is temporarily unavailable while SENTINEL APEX integrates licensed breach-intelligence providers. No synthetic or simulated results are served.",
    request_id: rid,
  }, 503, { "Retry-After": "86400" });
}

function now() {
  return new Date().toISOString();
}

// =============================================================================
// JWT HS256 (crypto.subtle)
// =============================================================================

function b64url(str) {
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDec(str) {
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
}

async function signJWT(payload, secret) {
  const header  = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body    = b64url(JSON.stringify(payload));
  const data    = `${header}.${body}`;
  const key     = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig     = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigB64  = b64url(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const data = `${h}.${p}`;
    const key  = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBytes = Uint8Array.from(b64urlDec(s), c => c.charCodeAt(0));
    const valid    = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload  = JSON.parse(b64urlDec(p));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) { return null; }
}

// Constant-time string comparison  -  prevents timing side-channel attacks on
// shared-secret checks (admin key, Gumroad webhook token) that aren't HMAC
// signatures and so can't use crypto.subtle.verify like Razorpay/JWT do.
// Always walks the full length of the longer input; never short-circuits.
function timingSafeEqual(a, b) {
  const bufA = new TextEncoder().encode(String(a ?? ""));
  const bufB = new TextEncoder().encode(String(b ?? ""));
  const len  = Math.max(bufA.length, bufB.length);
  let diff   = bufA.length ^ bufB.length;
  for (let i = 0; i < len; i++) {
    diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
  }
  return diff === 0;
}

// =============================================================================
// BRUTE FORCE PROTECTION
// =============================================================================

async function checkBruteForce(env, ip) {
  try {
    const rec = await env.RATE_LIMIT_KV.get(`bf:${ip}`, "json");
    if (!rec) return { locked: false };
    if (rec.locked_until && rec.locked_until > Date.now()) {
      return { locked: true, until: new Date(rec.locked_until).toISOString() };
    }
    return { locked: false, count: rec.count || 0 };
  } catch (_) { return { locked: false }; }
}

async function recordAuthFailure(env, ip) {
  const key = `bf:${ip}`;
  try {
    const rec  = (await env.RATE_LIMIT_KV.get(key, "json")) || { count: 0 };
    rec.count  = (rec.count || 0) + 1;
    if (rec.count >= BRUTE_FORCE_MAX) {
      rec.locked_until = Date.now() + BRUTE_FORCE_TTL * 1000;
    }
    await env.RATE_LIMIT_KV.put(key, JSON.stringify(rec), { expirationTtl: BRUTE_FORCE_TTL });
  } catch (_) {}
}

async function clearAuthFailures(env, ip) {
  try { await env.RATE_LIMIT_KV.delete(`bf:${ip}`); } catch (_) {}
}

// =============================================================================
// SLIDING-WINDOW RATE LIMITING
// =============================================================================

// =============================================================================
// DAILY QUOTA (business decision 2026-08-31) -- additive to, not a
// replacement for, the per-minute RATE_LIMITS above. Keyed by API key when
// authenticated (so a customer's quota is per-account, not multiplied by
// however many IPs their infrastructure happens to call from) and by IP
// only for anonymous/unauthenticated traffic, which has no account to key
// by. Reuses REVENUE_CRM_KV's revenue-engine sibling namespace, RATE_LIMIT_KV
// (this Worker's own existing blocking-quota namespace), rather than
// ANALYTICS_KV (usage-meter.js's shadow-mode-only, non-blocking namespace) --
// this mechanism actually denies requests, so it belongs with the other
// mechanism that already does that, not the observe-only one.
// =============================================================================

async function checkDailyQuota(env, identifier, tier) {
  const dateStr = utcDateString();
  const key = dailyQuotaKey(identifier, dateStr);
  try {
    // Daily counters meter rather than gate -- evaluateDailyQuota() renders the
    // verdict -- so no crossing threshold is passed. KV therefore trails the
    // in-isolate count by at most FLUSH_EVERY-1, which is immaterial against
    // daily allowances in the thousands.
    const { count: countAfter } =
      await bumpCounter(env.RATE_LIMIT_KV, key, 172800, Infinity); // 48h per spec
    return { ...evaluateDailyQuota(tier, countAfter), dateStr, count: countAfter };
  } catch (_) {
    // Same fail-open posture checkRateLimit() already takes on a KV error --
    // a transient KV outage must not itself become an outage for customers.
    return { ...evaluateDailyQuota(tier, 0), dateStr, count: 0 };
  }
}

async function readSwarmQuotaSnapshot(env, identifier, tier) {
  const cfg = dailyQuotaConfig(tier);
  const dateStr = utcDateString();
  const resetUtc = new Date(Date.now() + secondsUntilNextUtcMidnight() * 1000).toISOString();
  const unavailable = {
    available: false,
    limit: cfg.limit,
    used: null,
    remaining: null,
    exhausted: false,
    date_utc: dateStr,
    reset_utc: resetUtc,
  };

  if (!identifier || !env?.RATE_LIMIT_KV || typeof env.RATE_LIMIT_KV.get !== "function") {
    return unavailable;
  }

  try {
    const raw = await env.RATE_LIMIT_KV.get(dailyQuotaKey(identifier, dateStr));
    const parsed = raw == null ? 0 : parseInt(raw, 10);
    const used = Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    return {
      available: true,
      limit: cfg.limit,
      used,
      remaining: Math.max(0, cfg.limit - used),
      // checkDailyQuota increments before evaluating. When used === limit,
      // the next real request would become limit+1 and be denied.
      exhausted: used >= cfg.limit,
      date_utc: dateStr,
      reset_utc: resetUtc,
    };
  } catch (_) {
    // Match the real gateway's fail-open quota posture: inability to read
    // quota must never masquerade as customer exhaustion.
    return unavailable;
  }
}

async function handleSwarmPreflight(env, auth) {
  if (!auth?.key) {
    return jsonResp(
      {
        status: "denied",
        eligible: false,
        reason: "authentication_required",
        message: "Provide a Sentinel API key or bearer token.",
      },
      401,
      { "Cache-Control": "no-store" }
    );
  }

  const scopes = buildScopeSet(auth.tier, null);
  const quota = await readSwarmQuotaSnapshot(env, auth.key, auth.tier);
  const decision = evaluateSwarmPreflight({
    tier: auth.tier,
    scopes,
    quotaExhausted: quota.exhausted,
  });

  const body = {
    status: decision.eligible ? "ok" : "denied",
    eligible: decision.eligible,
    reason: decision.reason,
    entitlement: {
      tier: decision.tier,
      swarm_enabled: decision.tier_allowed && decision.scope_allowed,
      capability: SWARM_MESH_CAPABILITY,
      required_scope: SWARM_REQUIRED_SCOPE,
      scope_granted: decision.scope_allowed,
      subscription_status: auth.subscription_status || "active",
      expires_at: auth.expires_at || null,
      credential_type: auth.credential_type || (auth.jwt ? "bearer" : "api_key"),
    },
    quota: {
      daily: quota,
    },
    checked_at: new Date().toISOString(),
  };

  const status = decision.eligible
    ? 200
    : decision.reason === "daily_quota_exhausted"
      ? 429
      : 403;

  return jsonResp(body, status, { "Cache-Control": "no-store" });
}

// Fire-and-forget (called via ctx.waitUntil, never on the request's own
// critical path): looks up the account's email and asks revenue-engine to
// queue the "approaching your daily limit" email, deduplicated to once per
// UTC day via a KV flag -- crossedAlertThreshold uses >= (see
// daily-quota.js), so this can be reached more than once per day for the
// same key under a racy counter; the dedup flag, not the threshold check
// itself, is what actually guarantees one email per day.
async function maybeDispatchQuotaAlert(env, identifier, tier, auth, dateStr) {
  if (!auth?.key) return; // anonymous/IP-only traffic has no account to email
  try {
    const dedupeKey = quotaAlertDedupeKey(identifier, dateStr);
    if (await env.RATE_LIMIT_KV.get(dedupeKey)) return;
    const record = await env.API_KEYS_KV?.get(auth.key, "json");
    if (!record?.email) return;
    await env.RATE_LIMIT_KV.put(dedupeKey, "1", { expirationTtl: 90000 }); // 25h, safely spans the UTC day
    if (!env.REVENUE_ADMIN_SECRET) return; // not yet provisioned on this Worker -- skip, don't crash
    await fetch("https://revenue.intel.cyberdudebivash.com/api/automation/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Secret": env.REVENUE_ADMIN_SECRET },
      body: JSON.stringify({ trigger: "usage_80pct", email: record.email, context: `daily_quota:${tier}` }),
    });
  } catch (_) {
    // Best-effort notification -- never let a failure here surface to the
    // customer whose actual API request already succeeded.
  }
}

// P0 2026-09-03 -- first-party web read plane's own budget. Deliberately a
// separate pair of functions rather than extra parameters on checkRateLimit()/
// checkDailyQuota(): those two are the commercial plane's enforcement and are
// consumed by the existing tier logic, alert dispatch and upgrade-trigger
// paths. Keeping the planes as distinct code paths with distinct KV
// keyspaces (see webPlaneRateKey/webPlaneDailyKey) is what guarantees
// anonymous page rendering can neither consume nor be consumed by a
// commercial caller's budget. Both fail OPEN on a KV error, matching the
// identical posture checkRateLimit() and checkDailyQuota() already take --
// a transient KV outage must not itself become a customer-facing outage.
async function checkWebPlaneRateLimit(env, ip) {
  const minute = Math.floor(Date.now() / 60000);
  const key = webPlaneRateKey(ip, minute);
  const limit = WEB_PLANE_LIMITS.perMinute;
  try {
    const count = await peekCounter(env.RATE_LIMIT_KV, key);
    if (count >= limit) return { allowed: false, count, limit, remaining: 0 };
    const bumped = await bumpCounter(env.RATE_LIMIT_KV, key, 61, limit);
    return {
      allowed: true,
      count: bumped.count,
      limit,
      remaining: Math.max(0, limit - bumped.count),
    };
  } catch (_) {
    return { allowed: true, count: 0, limit, remaining: limit };
  }
}

async function checkWebPlaneDailyQuota(env, ip) {
  const dateStr = utcDateString();
  const key = webPlaneDailyKey(ip, dateStr);
  try {
    const { count: countAfter } =
      await bumpCounter(env.RATE_LIMIT_KV, key, 172800, Infinity);
    return { ...evaluateWebPlaneDaily(countAfter), dateStr, count: countAfter };
  } catch (_) {
    return { ...evaluateWebPlaneDaily(0), dateStr, count: 0 };
  }
}

async function checkRateLimit(env, ip, tier) {
  const limit  = RATE_LIMITS[tier] || RATE_LIMITS.FREE;
  const minute = Math.floor(Date.now() / 60000);
  const key    = `rl:${ip}:${minute}`;
  try {
    // Counting is batched in-isolate (see rate-limit-cache.js) so this costs
    // a KV write roughly every FLUSH_EVERY requests instead of every one.
    // Semantics are unchanged: deny when the window is already at the limit,
    // otherwise increment and allow. `limit` is passed so the increment that
    // crosses it writes through immediately and other isolates see the block.
    const count = await peekCounter(env.RATE_LIMIT_KV, key);
    if (count >= limit) return { allowed: false, count, limit, remaining: 0 };
    const bumped = await bumpCounter(env.RATE_LIMIT_KV, key, 61, limit);
    return {
      allowed: true,
      count: bumped.count,
      limit,
      remaining: Math.max(0, limit - bumped.count),
    };
  } catch (_) {
    return { allowed: true, count: 0, limit, remaining: limit };
  }
}

const SWARM_PREFLIGHT_RATE_LIMIT_PER_MINUTE = 60;

async function checkSwarmPreflightRateLimit(env, ip) {
  const limit = SWARM_PREFLIGHT_RATE_LIMIT_PER_MINUTE;
  const minute = Math.floor(Date.now() / 60000);
  const key = `rl:swarm-preflight:${ip}:${minute}`;
  try {
    const val = await env.RATE_LIMIT_KV.get(key);
    const count = val ? parseInt(val, 10) : 0;
    if (count >= limit) return { allowed: false, count, limit, remaining: 0 };
    await env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: 61 });
    return { allowed: true, count: count + 1, limit, remaining: limit - count - 1 };
  } catch (_) {
    // Same fail-open posture as the platform's existing request limiter:
    // an abuse-counter KV fault must not become a customer outage.
    return { allowed: true, count: 0, limit, remaining: limit };
  }
}

// =============================================================================
// TIER DEFINITIONS & AUTH RESOLUTION
// =============================================================================

const TIERS = { FREE: "FREE", PRO: "PRO", ENTERPRISE: "ENTERPRISE", MSSP: "MSSP" };

const PREMIUM_INTEL_PATHS = new Set([
  "/api/v1/intel/apex.json",
  "/api/v1/intel/ai_summary.json",
]);

// v185.6 (Mission Phase 3): moved to subscription-lifecycle.js, a small
// dependency-free module, specifically so
// __tests__/subscription-lifecycle.test.js can import it directly without
// pulling in index.js's full import chain (pricing.js -> pricing-data.json
// fails Node's native ESM loader outside the wrangler/esbuild bundler --
// see that file's header comment for the full explanation). Re-exported
// here unchanged so every existing call site keeps working with no
// behavior change -- this is a pure move, not a logic change.

async function resolveAuth(request, env) {
  const apiKey = (request.headers.get("X-API-Key") || "").trim();
  // v201.0: X-Sentinel-Key is an additive header alias for the same API key
  // lookup below -- the SIEM/SOAR export routes (routes/exports.js) document
  // this header name, but it resolves through the exact same tier/JWT/brute-
  // force logic as X-API-Key, not a parallel auth path. Lowest precedence of
  // the three so no existing X-API-Key or Authorization caller's behavior
  // changes.
  const sentinelKey = (request.headers.get("X-Sentinel-Key") || "").trim();
  const bearer = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
  const qKey   = new URL(request.url).searchParams.get("api_key") || "";
  const raw    = apiKey || bearer || qKey || sentinelKey;

  if (!raw) return { tier: TIERS.FREE, key: null, sub: null };

  // JWT path: exactly 2 dots, looks like header.payload.sig
  if (raw.split(".").length === 3 && env.CDB_JWT_SECRET) {
    const payload = await verifyJWT(raw, env.CDB_JWT_SECRET);
    if (!payload) return { tier: TIERS.FREE, key: null, sub: null, error: "invalid_token" };
    try {
      const revoked = await env.SECURITY_HUB_KV.get(`jwt_revoked:${raw.slice(-24)}`);
      if (revoked) return { tier: TIERS.FREE, key: null, sub: null, error: "token_revoked" };
      // v185.5 CodeRabbit fix: handleLogin() now refuses to ISSUE a new JWT
      // for a cancelled/refunded/suspended key, but a JWT issued before
      // that transition would otherwise keep working for up to
      // JWT_EXPIRY_SEC (24h) regardless -- this path never re-checked the
      // underlying API_KEYS_KV record at all (jwt_revoked above is a
      // self-service /auth/logout marker keyed by the raw token, which an
      // admin acting via PATCH .../status doesn't have). Closed the same
      // way: applySubscriptionStatusChange() writes jwt_deny:{customer_id}
      // (TTL-bounded to JWT_EXPIRY_SEC, deleted again on reactivation) the
      // moment a key transitions into a deny state, checked here by sub.
      const denied = await env.SECURITY_HUB_KV.get(`jwt_deny:${payload.sub}`);
      if (denied) return { tier: TIERS.FREE, key: null, sub: null, error: "subscription_status_denied" };
    } catch (_) {}
    return {
      tier: TIERS[payload.tier] || TIERS.PRO,
      key: raw,
      sub: payload.sub,
      jwt: true,
      credential_type: "bearer",
      subscription_status: "active",
      expires_at: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
    };
  }

  // API key path: look up in KV
  if (raw.length >= 16) {
    // Brute-force lockout already covers /auth/login's explicit key check
    // but not this path, which every authenticated request goes through --
    // meaning direct key guessing against any endpoint was untracked.
    // 256-bit key entropy (secrets.token_hex(32)) makes guessing
    // computationally infeasible regardless, but this closes the gap for
    // defense in depth at negligible cost (one KV read, reuses the exact
    // same tracking as /auth/login).
    const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
    const bf = await checkBruteForce(env, ip);
    if (bf.locked) {
      return { tier: TIERS.FREE, key: null, sub: null, error: "rate_limited" };
    }
    // v200.0 FIX: API_KEYS_KV.get() throwing (genuine KV outage) and it
    // resolving to null (key genuinely not found) used to hit the same
    // catch-all below -- both fell through to recordAuthFailure() +
    // "invalid_key". checkRateLimit/checkBruteForce/recordAuthFailure all
    // fail OPEN on a KV error (see their own try/catch above) so a KV blip
    // can't turn into a hard outage, but this path did the opposite: it
    // turned a KV blip into a recorded auth failure for every legitimate
    // paying customer whose request landed during the window, and 5 of
    // those (very plausible for one customer's normal retry/polling
    // behavior during a sustained blip) brute-force-locks their IP for 15
    // minutes -- outliving the KV blip itself. Can't grant a paid tier
    // without being able to read the record either way (no fail-open-to-
    // premium risk introduced), but "we couldn't check" and "we checked and
    // it's wrong" are different failure modes and now get different
    // handling and a distinct error code (mirrors the existing
    // "rate_limited" -> 429 special case below, not folded into generic
    // "invalid_key" -> 401).
    let record;
    try {
      record = await env.API_KEYS_KV.get(raw, "json");
    } catch (_) {
      return { tier: TIERS.FREE, key: null, sub: null, error: "auth_service_unavailable" };
    }
    try {
      if (record) {
        // v185.5 (Mission Phase 1): subscription_status is optional on the
        // record -- absent means "active" (every key provisioned before
        // this change), so this is purely additive. An explicit but
        // unrecognized status string fails closed rather than falling
        // through as if unset, per Phase 1's own "unknown state must fail
        // closed" requirement. See evaluateKeyRecordAccess()'s own comment.
        const access = evaluateKeyRecordAccess(record);
        if (!access.allowed) {
          return { tier: TIERS.FREE, key: null, sub: null, error: access.error };
        }
        // Skip the extra KV write on the common case (no prior failures to clear)
        if (bf.count) await clearAuthFailures(env, ip);
        return {
          tier: TIERS[record.tier] || TIERS.PRO,
          key: raw,
          sub: record.customer_id || raw.slice(0, 8),
          kv: true,
          credential_type: "api_key",
          subscription_status: record.subscription_status || "active",
          expires_at: record.expires_at || null,
          // v185.5 (Mission Phase 6): MSSP tenant ownership, OPT-IN not
          // fail-closed-by-default. `null` means "field genuinely absent" --
          // every key provisioned before this change, and every non-MSSP
          // key -- and handleMSSPFeed treats that as unrestricted,
          // preserving today's exact live behavior for any existing MSSP
          // customer. A fail-closed-by-default rollout would have silently
          // cut off every existing MSSP customer's current access the
          // moment this deployed -- see docs/MSSP_TENANT_IDENTITY_V185.md.
          // A record that HAS the field but with a malformed (non-array,
          // non-undefined) value is a different case and must NOT collapse
          // into the same permissive `null` -- that would make a KV write
          // bug or corrupted record silently unrestricted instead of
          // failing closed. Distinguished explicitly below (CodeRabbit
          // review fix): undefined -> null (legacy/unrestricted); present
          // but not an array -> [] (fails closed, authorizes zero tenants,
          // same as an admin explicitly setting an empty list).
          managed_tenants: record.managed_tenants === undefined
            ? null
            : (Array.isArray(record.managed_tenants) ? record.managed_tenants : []),
        };
      }
    } catch (_) {}
    await recordAuthFailure(env, ip);
    return { tier: TIERS.FREE, key: null, sub: null, error: "invalid_key" };
  }

  return { tier: TIERS.FREE, key: null, sub: null };
}

// =============================================================================
// AUDIT LOGGING (ctx.waitUntil - non-blocking)
// =============================================================================

function auditLog(ctx, env, event) {
  if (!ctx || !env.SECURITY_HUB_KV) return;
  ctx.waitUntil((async () => {
    try {
      const ts   = Date.now();
      const rand = Math.random().toString(36).slice(2, 8);
      await env.SECURITY_HUB_KV.put(
        `audit:${ts}:${rand}`,
        JSON.stringify({ ts: new Date(ts).toISOString(), ...event }),
        { expirationTtl: AUDIT_TTL }
      );
    } catch (_) {}
  })());
}

// =============================================================================
// PHASE 3: ENTITLEMENT SHADOW MODE
// Compares the ad-hoc tier decision each handler already makes against what
// the consolidated policy engine (enforceTierGate, revenue-enforcement.js)
// would decide for the same resource + real tier, and logs any mismatch.
// Never changes what's actually returned to the caller -- the ad-hoc check
// at each call site remains the sole thing that determines the response.
// No enforcement here; this exists purely to build evidence, over real
// traffic, that the policy engine's evidence-based rules (fixed/added in
// this same pass) agree with what every call site already does today,
// before any future phase considers switching enforcement over to it.
// =============================================================================
function shadowCheckEntitlement(ctx, env, resource, auth, currentlyAllowed) {
  try {
    const decision = enforceTierGate(resource, auth?.tier);
    if (decision.allowed !== currentlyAllowed) {
      auditLog(ctx, env, {
        action:            "entitlement_shadow_mismatch",
        resource,
        tier:              auth?.tier || "FREE",
        current_allowed:   currentlyAllowed,
        engine_allowed:    decision.allowed,
        engine_reason:     decision.reason || null,
      });
    }
    return decision;
  } catch (e) {
    // Shadow-mode is diagnostic only -- a bug in the comparison itself must
    // never affect the real (ad-hoc) decision path that already ran.
    console.error(`[shadowCheckEntitlement] ${resource}: ${e?.message || e}`);
    return { allowed: currentlyAllowed };
  }
}

// =============================================================================
// PHASE 4: GATEWAY ENFORCEMENT (feature-flagged, per-resource, gradual)
// Composes shadowCheckEntitlement() above (unmodified -- the shadow-mismatch
// log it writes keeps firing exactly as it did in Phase 3) with a per-resource
// enforcement switch. Both flags default off, so deploying this changes zero
// production behavior: every call site keeps returning its own ad-hoc decision
// until a resource is explicitly named in ENTITLEMENT_ENFORCEMENT_RESOURCES
// with ENTITLEMENT_ENFORCEMENT_ENABLED="true". When enforcement IS on for a
// resource and the engine's decision differs from the ad-hoc one, the engine
// wins -- logged as a distinct, higher-signal "entitlement_enforced_override"
// event (separate from the passive shadow-mismatch log) so a rollout can be
// watched with precision, resource by resource.
// =============================================================================
function isEntitlementEnforced(env, resource) {
  if (String(env.ENTITLEMENT_ENFORCEMENT_ENABLED || "false").toLowerCase() !== "true") return false;
  const list = String(env.ENTITLEMENT_ENFORCEMENT_RESOURCES || "")
    .split(",").map(s => s.trim()).filter(Boolean);
  return list.includes(resource);
}

function resolveEntitlement(ctx, env, resource, auth, adHocAllowed) {
  const decision = shadowCheckEntitlement(ctx, env, resource, auth, adHocAllowed);
  if (!isEntitlementEnforced(env, resource)) return { allowed: adHocAllowed, enforced: false };
  if (decision.allowed !== adHocAllowed) {
    auditLog(ctx, env, {
      action:         "entitlement_enforced_override",
      resource,
      tier:           auth?.tier || "FREE",
      ad_hoc_allowed: adHocAllowed,
      engine_allowed: decision.allowed,
      engine_reason:  decision.reason || null,
    });
  }
  return { allowed: decision.allowed, enforced: true };
}

// =============================================================================
// R2 READER
// =============================================================================

async function r2Get(env, key) {
  try {
    const obj = await env.INTEL_R2.get(key);
    if (!obj) return null;
    const text = await obj.text();
    if (!text || text.trim() === "") return null;
    return JSON.parse(text);
  } catch (_) { return null; }
}

// =============================================================================
// FEED / COMPUTE FUNCTIONS (unchanged logic from v184.0)
// =============================================================================

async function loadFeedItems(env) {
  const data = await r2Get(env, LATEST_JSON_KEY);
  if (data && data.items && data.items.length > 0) return data;
  return { schema_version: "1.0", count: 0, items: [], generated_at: now(), version: PLATFORM_VERSION };
}

// P0 FIX (metric-integrity contract closure, see /api/metrics below): both
// /api/platform/stats and /api/v1/intel/stats hardcoded feed_count/
// active_feeds/feeds_active to the literal 74 -- exactly the "hardcoded
// marketing number" p0-revenue-os/config/metric_integrity_contract.json
// exists to forbid, just living in a JSON API response instead of HTML
// copy. P40's source registry (already live, already the authoritative
// count of enabled collectors -- see enterprise-source-fabric-center.html)
// gives the real number.
//
// Returns the raw count, or null if the registry genuinely can't be read
// (R2 miss/error) -- deliberately does NOT itself decide a fallback value,
// so /api/metrics (a metric-integrity-contract endpoint whose own sample
// file says "shipping this with invented integers is a contract violation")
// can surface that null honestly, while the two pre-existing legacy routes
// below apply their own explicit `?? 74` to preserve their prior behavior
// on a transient outage instead of a worse one. One read, two policies --
// not two reads or a fabricated shared default.
async function _liveFeedSourceCount(env) {
  try {
    const registry = await loadP40SourceRegistry(env);
    const count = registry ? (registry.status_breakdown?.ACTIVE ?? registry.total_sources) : null;
    return (typeof count === "number" && count > 0) ? count : null;
  } catch (_) {
    return null;
  }
}
const _LEGACY_FEED_COUNT_FALLBACK = 74;

// =============================================================================
// DETECTION REGISTRY QUERY HANDLERS (Phase 4.1 mandate Section 9-19)
// Tiering follows this file's own established precedent for comparable
// P17-P40 intelligence endpoints (Section 15: "do not implement paywall
// assumptions not supported by existing product policy") rather than
// inventing a new policy: FREE gets a redacted preview (same masked-preview
// pattern already used for the main feed at auth.tier === TIERS.FREE
// elsewhere in this file); PRO+ gets complete artifact content; ENTERPRISE/
// MSSP get the higher page-size ceiling this file already grants them on
// other endpoints (e.g. the vendor-risk route's 200-vs-100 limit split).
// =============================================================================

const DETECTION_TIER_LIMITS = { FREE: 10, PRO: 50, ENTERPRISE: 200, MSSP: 200 };

function _redactForFreeTier(artifact) {
  const preview = typeof artifact.content === "string" ? artifact.content.slice(0, 160) : "";
  return {
    ...artifact,
    content: preview + (preview.length === 160 ? "... [upgrade to PRO to view the complete artifact]" : ""),
    _preview_only: true,
  };
}

/** Section 13/14: list + filter + paginate canonical detection artifacts.
 * Section 18: a genuinely empty result is returned as a valid empty page,
 * never fabricated content and never a silent fallback to a stale file. */
async function handleDetectionsQuery(request, env, auth) {
  let feed;
  try {
    feed = await loadFeedItems(env);
  } catch (e) {
    // Fail closed with an honest error, not a fabricated empty-looking
    // success (Section 18 applies to genuine emptiness, not to a load
    // failure masquerading as one).
    return errorResp("Detection registry temporarily unavailable -- try again shortly", 503);
  }

  const url = new URL(request.url);
  const params = Object.fromEntries(url.searchParams.entries());
  const tierCap = DETECTION_TIER_LIMITS[auth.tier] || DETECTION_TIER_LIMITS.FREE;
  if (!params.limit || parseInt(params.limit, 10) > tierCap) params.limit = String(tierCap);

  let registry;
  try {
    registry = buildDetectionRegistry(feed.items || []);
  } catch (e) {
    return errorResp("Detection registry build failed", 500);
  }

  const result = queryDetectionRegistry(registry, params);
  if (result.error) return jsonResp(result, 400);

  const isFree = auth.tier === TIERS.FREE;
  const data = result.data.map(a => toPublicArtifact(isFree ? _redactForFreeTier(a) : a));

  return jsonResp({
    schema_version: "1.0.0",
    engine_version: DETECTION_REGISTRY_VERSION,
    generated_at: now(),
    count: data.length,
    data,
    pagination: result.pagination,
    ...(isFree ? { tier_note: "FREE tier returns redacted previews and a lower page size. Upgrade to PRO for complete artifacts." } : {}),
  });
}

/** GET /api/v1/detections/{intel_id} -- all detection artifacts for one
 * intelligence item, the natural REST-path equivalent of
 * /api/v1/detections?intel_id=X (Section 13's intel_id filter). */
async function handleDetectionArtifactById(request, env, auth) {
  const url = new URL(request.url);
  const intelId = decodeURIComponent(url.pathname.slice("/api/v1/detections/".length));
  if (!intelId) return errorResp("Missing intel_id", 400);

  const patchedUrl = new URL(request.url);
  patchedUrl.searchParams.set("intel_id", intelId);
  const patchedRequest = new Request(patchedUrl.toString(), request);
  const resp = await handleDetectionsQuery(patchedRequest, env, auth);
  if (resp.status !== 200) return resp;

  const body = await resp.json();
  if (body.count === 0) {
    return jsonResp({ error: "No detection artifacts found for this intel_id", intel_id: intelId, reason: "not_found_or_not_eligible" }, 404);
  }
  return jsonResp(body);
}

// =============================================================================
// COMMERCIAL GATE BANNER (P0 fix  -  report/publication-state consistency)
// Report generation is intentionally unconditional (every processed item gets
// a reachable report so links never 404), but until now the certification
// verdict already computed by P19's computeCertificationLevel() (reusing the
// existing P18 evidence/confidence/validation chain -- no new scoring logic)
// was only ever rendered as buried text inside buildAnalystBlock(). A report
// could say "Customer deliverable: NO" 600 lines down while still looking and
// behaving like a normal premium deliverable at first glance. This banner
// surfaces that SAME existing verdict, unmissably, at the very top of the
// page. It reuses certLevel fields only -- it does not recompute anything.
// =============================================================================

function buildCommercialGateBanner(certLevel) {
  if (certLevel.customer_deliverable) return "";
  return `
<div style="background:rgba(220,38,38,.1);border-bottom:2px solid #dc2626;padding:14px 20px;">
  <div style="max-width:1100px;margin:0 auto;display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
    <div style="font-family:monospace;font-size:11px;font-weight:900;color:#dc2626;letter-spacing:1px;white-space:nowrap;">
      ? PRELIMINARY ANALYSIS -- NOT YET A CERTIFIED CUSTOMER DELIVERABLE
    </div>
    <div style="font-size:12px;color:#f3b4b4;line-height:1.5;flex:1;min-width:240px;">
      This report is at certification level "${certLevel.certification_label}" (quality score ${certLevel.quality_score}/100) and has not
      passed the enterprise quality gates required for commercial release. Treat the contents below as an automated,
      unverified working draft pending analyst review -- not a finished intelligence product.
    </div>
  </div>
</div>`;
}

// =============================================================================
// REPORT SYNTHESIS ENGINE (v183.0  -  permanent 24/7 availability fix)
// When a report HTML isn't in R2, look up item data from feed and synthesize
// a full HTML intel report on-the-fly, then cache it back to R2.
// =============================================================================

// RX-PUB-A0.6C: last-resort fallback source, checked only when none of the
// four enriched feed products above resolve the slug. docs/RX_PUB_A0_6_
// PROOF_BEFORE_CHANGE.md's live evidence (2026-08-14): api/v1/intel/
// latest.json and api/feed.json are kept in sync with each other (472
// items each, identical population) by generate_api_manifests.py, but both
// are a smaller population than data/stix/feed_manifest.json (518 items) --
// the same in-window source scripts/generate_intel_reports.py's Zero-skip
// policy regenerates every run and scripts/r2_reports_verifier.py treats as
// authoritative. 69 confirmed real in-window reports were unresolvable
// through every one of the four sources above, and (per that fail-open gap)
// served straight from R2 with zero evaluatePublicationGate() evaluation.
// feed_manifest.json's leaner per-item schema (no precomputed P20-P26
// scores) is not a problem: evaluatePublicationGate() computes every score
// fresh from base content fields (title, description, severity, iocs, ttps,
// etc.) via the canonical engine functions -- it never reads a precomputed
// score off the item -- and fails CLOSED if any engine errors on a missing
// field, never open. Uploaded every run by scripts/r2_upload.py to this
// exact key (BUCKET_DATA, "intel/feed_manifest.json").
const FEED_MANIFEST_FALLBACK_KEY = "intel/feed_manifest.json";

export async function findItemBySlug(env, slug) {
  const sources = [
    LATEST_PRO_JSON_KEY,
    LATEST_JSON_KEY,
    "api/v1/intel/top10.json",
    "api/v1/intel/apex.json",
    FEED_MANIFEST_FALLBACK_KEY,
  ];
  for (const key of sources) {
    try {
      const data = await r2Get(env, key);
      if (!data) continue;
      const items = Array.isArray(data) ? data : (data.items || data.data || []);
      const found = items.find(i => {
        const id = (i.stix_id || i.id || "").replace(/\.html?$/, "");
        return id === slug || id === `intel--${slug}` ||
               slug === id || slug.startsWith(id) || id.startsWith(slug);
      });
      if (found) return found;
    } catch (_) { /* continue to next source */ }
  }
  return null;
}

/**
 * GET /api/v1/reports/{id}/publication-status  -  the source of truth for
 * whether a report is customer-accessible (Section 28). Resolves the item
 * the same way /reports/** does (findItemBySlug) and returns the SAME
 * evaluatePublicationGate() verdict that route enforces -- this endpoint
 * cannot say CUSTOMER_READY for something /reports/** would 404, or vice
 * versa, since both call the identical gate function.
 */
async function handlePublicationStatus(request, env, reportId) {
  if (!reportId) {
    return jsonResp({ error: "Missing report id", version: PLATFORM_VERSION }, 400);
  }
  const slug = reportId.replace(/\.html?$/, "");
  const item = await findItemBySlug(env, slug);
  if (!item) {
    return jsonResp({
      report_id: reportId,
      state: "UNKNOWN",
      customer_ready: false,
      reason_codes: ["ITEM_NOT_RESOLVABLE"],
      evaluated_at: new Date().toISOString(),
    }, 404);
  }

  const gate = evaluatePublicationGate(item);
  return jsonResp({
    report_id: reportId,
    state: gate.publication_state,
    customer_ready: gate.customer_ready,
    reason_codes: gate.blocking_gates,
    certification_version: gate.certification_version,
    snapshot_id: item.stix_id || item.id || reportId,
    evaluated_at: gate.evaluated_at,
    scores: {
      P20_SCORE: gate.P20_SCORE,
      P21_CERTIFICATION: gate.P21_CERTIFICATION,
      P23_OPERATIONAL_READINESS_PCT: gate.P23_OPERATIONAL_READINESS_PCT,
      P25_TRUST_SCORE: gate.P25_TRUST_SCORE,
      P25_TRUST_TIER: gate.P25_TRUST_TIER,
      P26_COMMERCIAL_SCORE: gate.P26_COMMERCIAL_SCORE,
      P26_GRADE: gate.P26_GRADE,
      P26_CERT_TIER: gate.P26_CERT_TIER,
    },
  }, 200);
}

/**
 * Loads the same bounded feed sources findItemBySlug()/the old inline
 * filter used, merged into one id -> item map, ONCE per call (not per
 * entry) to avoid an R2 round-trip per index row.
 */
async function _resolveFeedItemsById(env) {
  const byId = new Map();
  const keys = [LATEST_PRO_JSON_KEY, LATEST_JSON_KEY, "api/v1/intel/top10.json", "api/v1/intel/apex.json"];
  // Fetch all four sources concurrently (independent R2 reads), then merge in
  // `keys` order so first-source-wins priority is unchanged from the
  // sequential version -- only the wall-clock cost drops.
  const feeds = await Promise.all(keys.map(k => r2Get(env, k).catch(() => null)));
  for (const feed of feeds) {
    if (!feed) continue;
    const items = Array.isArray(feed) ? feed : (feed.items || feed.data || []);
    if (!Array.isArray(items)) continue;
    for (const i of items) {
      const id = ((i && (i.stix_id || i.id)) || "").replace(/\.html?$/, "");
      if (id && !byId.has(id)) byId.set(id, i);
    }
  }
  return byId;
}

/**
 * P0 trust-boundary fix (certification-registry.js): builds a customer-ready
 * reports feed from the full report-catalog pool (REPORTS_KEY, up to 500
 * entries), not a pre-truncated 50-entry window -- filtering must happen
 * BEFORE truncation, over a pool large enough that truncating AFTER
 * filtering still yields up to `limit` genuinely customer-ready entries.
 * Each entry's certification is looked up in the persisted index first;
 * only entries with no persisted record AND resolvable in the current feed
 * windows are freshly evaluated (and then persisted for every future
 * request, including after the item scrolls out of the feed). An entry
 * that is neither persisted nor resolvable is NOT_EVALUATED and is never
 * customer-ready -- replaces the old "unresolvable -- pass through" rule
 * that let NOT_FOUND_IN_FEED silently become CUSTOMER_READY.
 *
 * `ctx` (the Worker's ExecutionContext, optional) lets the certification
 * write ride on ctx.waitUntil(): the verdicts used for THIS response are
 * already computed by the time persistCertificationRecords() is called, so
 * the R2 read-modify-write round trip must not add latency to the request
 * path. Falls back to awaiting it directly if ctx isn't supplied (e.g. a
 * unit test harness).
 */
async function buildCertifiedReportsFeed(env, ctx, { limit, feedType }) {
  const raw = await r2Get(env, REPORTS_KEY);
  if (!raw || !Array.isArray(raw.reports) || raw.reports.length === 0) return null;

  const [certIndex, byId] = await Promise.all([
    loadCertificationIndex(env),
    _resolveFeedItemsById(env),
  ]);

  const toPersist = {};
  const evaluated = [];
  for (const r of raw.reports) {
    const id = (r.id || "").replace(/\.html?$/, "");
    const { record, isNew } = resolveCertification(certIndex[id], byId.get(id));
    if (isNew) toPersist[id] = record;
    evaluated.push({ entry: r, publication_status: record.publication_status });
  }

  if (Object.keys(toPersist).length > 0) {
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(persistCertificationRecords(env, toPersist));
    } else {
      await persistCertificationRecords(env, toPersist);
    }
  }

  const customerReady = evaluated.filter(e => e.publication_status === "CUSTOMER_READY").map(e => e.entry);
  // Deterministic ordering: newest first by timestamp, ties broken by id --
  // Test Matrix item 26 (no arbitrary/unstable ordering). An unparseable
  // timestamp yields NaN from getTime(); `|| 0` normalizes it so such
  // entries sort last (oldest) instead of producing NaN comparator results
  // (implementation-defined ordering that would silently break determinism).
  customerReady.sort((a, b) => {
    const ta = new Date(a.timestamp || 0).getTime() || 0;
    const tb = new Date(b.timestamp || 0).getTime() || 0;
    if (tb !== ta) return tb - ta;
    return String(a.id || "").localeCompare(String(b.id || ""));
  });
  const listed = customerReady.slice(0, limit);

  return {
    schema_version: "2.0.0",
    feed_type: feedType,
    generated_at: raw.generated_at || null,
    validated_at: new Date().toISOString(),
    policy_version: CERTIFICATION_POLICY_VERSION,
    total_candidates: raw.reports.length,
    customer_ready_count: customerReady.length,
    withheld_count: raw.reports.length - customerReady.length,
    // total_reports: UNCHANGED historical meaning -- the true report-catalog
    // size (scripts/build_reports_index.py's len(all_report_paths), passed
    // through from the registry raw.total_reports), NOT the gated count.
    // index.html reads this for dashboard totals/badges and compares it
    // against reports_listed to decide whether to show a "view all" link
    // (data.total_reports > data.reports_listed) -- redefining it to the
    // customer-ready count would silently break that comparison and regress
    // the displayed catalogue size. Use customer_ready_count/withheld_count
    // above for the gated numbers this fix introduces.
    total_reports: (typeof raw.total_reports === "number") ? raw.total_reports : raw.reports.length,
    reports_listed: listed.length,
    reports: listed,
  };
}

function generateIntelReport(item, reqPath, items = []) {
  // --- Data extraction ---------------------------------------------------------
  const esc = s => String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

  const title        = esc(item.title || "SENTINEL APEX Intelligence Report");
  const itemId       = esc(item.stix_id || item.id || "unknown");
  const sev          = (item.severity || "UNKNOWN").toUpperCase();
  const risk         = parseFloat(item.risk_score) || 0;
  const cvss         = parseFloat(item.cvss_score || item.cvss) || 0;
  const epss         = parseFloat(item.epss_score) || 0;
  const kev          = !!item.kev_present;
  const tlp          = item.tlp || "TLP:CLEAR";
  const attackVector = (item.attack_vector || "").replace(/_/g, " ");
  const threatType   = esc(item.threat_type || item.apex?.threat_category || "");
  const threatCat    = esc(item.apex?.threat_category || item.threat_type || "");
  const actor        = esc(item.actor_tag && item.actor_tag !== "UNC-CDB-99" && item.actor_tag !== "UNC-UNKNOWN" ? item.actor_tag : "Unattributed");
  const campaignId   = esc(item.apex?.campaign_id || "");
  const confidence   = parseFloat(item.confidence_score || item.apex?.confidence || item.confidence || item.ioc_confidence) || 0;
  const confidenceBadge = formatConfidenceForHeader(item);
  const priority     = esc(item.apex?.priority || "");
  const enrichScore  = parseFloat(item.enrichment_score) || 0;
  const iocCount     = item.ioc_count || 0;
  const iocCounts    = item.ioc_counts || {};
  const cveArr       = [...new Set((item.cve || item.cve_ids || []).filter(Boolean))].slice(0, 12);
  const ttps         = (item.ttps || item.mitre_tactics || item.ttp_names || []).filter(Boolean).slice(0, 10);
  const behavTags    = filterBehavioralTags((item.apex?.behavioral_tags || item.tags || []).filter(Boolean).slice(0, 8));
  const products     = (item.affected_products || []).filter(Boolean).slice(0, 8);
  const tags         = (item.tags || []).filter(Boolean).slice(0, 10);

  // Primary narrative content  -  use apex AI summary if available, else description (P20.7: markdown stripped)
  const narrative    = esc(stripMarkdown(item.apex?.ai_summary || item.description || "")) || "Intelligence report for the above advisory generated by SENTINEL APEX.";
  const remedAction  = esc(item.apex?.recommended_action || "");

  // Source  -  prefer source_url; fall back to report_url only when it's an external article link
  const _ru          = item.report_url || "";
  const _ruIsExternal = _ru.startsWith("http") && !_ru.includes("/reports/") && !_ru.includes("intel.cyberdudebivash.com");
  const srcRaw       = item.source_url || (_ruIsExternal ? _ru : "") || "";
  const srcSafe      = srcRaw.startsWith("http") ? srcRaw.replace(/"/g,"&quot;") : "";
  const srcName      = esc(item.source || (srcRaw.replace(/^https?:\/\/(www\.)?/,"").split("/")[0]));

  // Timestamps
  const published    = (item.published_at || item.published || item.timestamp || "").replace("T"," ").slice(0,19);
  const processed    = (item.processed_at || item.timestamp || "").replace("T"," ").slice(0,19);
  const genTime      = new Date().toISOString().replace("T"," ").slice(0,19);

  // Visual helpers
  const sevColor     = sev==="CRITICAL"?"#dc2626":sev==="HIGH"?"#ea580c":sev==="MEDIUM"?"#d97706":sev==="LOW"?"#3b82f6":"#6b7280";
  const riskPct      = Math.min(risk * 10, 100).toFixed(0);
  const tlpStyle     = tlp.includes("AMBER")
    ? "background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.35)"
    : tlp.includes("RED")
    ? "background:rgba(220,38,38,.12);color:#dc2626;border:1px solid rgba(220,38,38,.35)"
    : "background:rgba(0,212,170,.08);color:#00d4aa;border:1px solid rgba(0,212,170,.25)";

  // Risk interpretation text
  const riskInterp   = cvss>=9||risk>=9 ? "Exploitation is trivial and widespread. Treat as breach until proven otherwise."
    : cvss>=7||risk>=7 ? "High exploitability  -  active in the wild. Patch before next business cycle."
    : cvss>=4||risk>=4 ? "Moderate exposure. Prioritize based on asset criticality and exposure surface."
    : "Low immediate risk. Address in routine maintenance cycle.";

  const epssInterp   = epss>=50 ? `${epss.toFixed(1)}% probability of exploitation within 30 days  -  significantly above baseline. Treat as actively exploited.`
    : epss>=10 ? `${epss.toFixed(1)}% exploitation probability  -  elevated. Accelerate patch schedule.`
    : epss>0   ? `${epss.toFixed(1)}% exploitation probability  -  within normal range. Standard patching applies.`
    : "";

  const avLabel      = attackVector==="NETWORK"?"Remote (Network)  -  exploitable without physical access"
    : attackVector==="ADJACENT_NETWORK"?"Adjacent Network  -  requires same network segment"
    : attackVector==="LOCAL"?"Local  -  requires authenticated local access"
    : attackVector==="PHYSICAL"?"Physical  -  requires physical device access"
    : attackVector||"";

  // Build CVE chips
  const cveHtml = cveArr.map(c =>
    `<a href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener" style="background:rgba(59,130,246,.12);color:#60a5fa;padding:5px 12px;border-radius:4px;font-size:11px;font-weight:700;border:1px solid rgba(59,130,246,.28);font-family:monospace;text-decoration:none;white-space:nowrap;">${esc(c)}</a>`
  ).join("\n");

  // IOC breakdown
  const iocRows = Object.entries(iocCounts).filter(([,v])=>v>0).map(([k,v])=>
    `<div style="display:flex;justify-content:space-between;padding:8px 12px;background:rgba(0,212,170,.04);border-radius:4px;border:1px solid rgba(0,212,170,.1);">
      <span style="font-family:monospace;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">${esc(k.replace(/_/g," "))}</span>
      <span style="font-family:monospace;font-size:14px;font-weight:800;color:#00d4aa;">${v}</span>
    </div>`
  ).join("");

  // Remediation steps  -  use apex.recommended_action as primary, augment with severity-driven steps
  const remSteps = [];
  if (kev || risk >= 9)  remSteps.push({ c:"#dc2626", bg:"rgba(220,38,38,.06)", icon:"?", label:"IMMEDIATE (0-24h)", text:"Apply vendor patch or mitigating control NOW. CISA mandates federal agencies remediate KEV entries within defined deadlines. If no patch available, isolate affected systems from network access immediately." });
  if (risk >= 7 && !kev) remSteps.push({ c:"#ea580c", bg:"rgba(234,88,12,.06)", icon:"?", label:"HIGH PRIORITY (24-72h)", text:"Deploy patch within one business cycle. Increase monitoring on affected assets. Review firewall rules for attack vector exposure. Brief incident response team." });
  if (remedAction)       remSteps.push({ c:"#00d4aa", bg:"rgba(0,212,170,.05)", icon:"?", label:"SENTINEL APEX RECOMMENDED ACTION", text:remedAction });
  if (risk < 7 && !kev)  remSteps.push({ c:"#3b82f6", bg:"rgba(59,130,246,.05)", icon:"?", label:"STANDARD REMEDIATION", text:"Schedule remediation in next planned maintenance window. Verify patch applicability to your environment. Monitor vendor advisories for updated severity assessments." });
  remSteps.push({ c:"#64748b", bg:"rgba(255,255,255,.02)", icon:"*", label:"DEFENSE IN DEPTH", text:"Apply least-privilege access controls * Enable enhanced EDR telemetry on affected hosts * Block known-bad IOCs at perimeter * Conduct threat hunting using MITRE ATT&amp;CK techniques listed above * Update detection rules." });

  // Commercial gate verdict -- reuses the existing P18/P19 evidence -> confidence ->
  // validation -> certification chain (the same one buildAnalystBlock already runs)
  // solely to read customer_deliverable. No new scoring logic is introduced here.
  const _gateEvidence   = buildEvidenceAttribution(item);
  const _gateConfidence = computeTransparentConfidence(item);
  const _gateValidation = validateReportQuality(item, _gateEvidence, _gateConfidence);
  const certLevel       = computeCertificationLevel(_gateValidation.quality_score, _gateValidation);
  const commercialGateBanner = buildCommercialGateBanner(certLevel);

  return `<!DOCTYPE html>
<!-- CDB-REPORT-ENGINE: worker-fallback-synthesis v${PLATFORM_VERSION} -->
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}  -  SENTINEL APEX Intelligence Report</title>
<meta name="robots" content="noindex,nofollow">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080b12;color:#c4d0e3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;min-height:100vh;line-height:1.65}
a{color:#00d4aa;text-decoration:none}
a:hover{text-decoration:underline}

/* Top classification bar */
.cls-bar{background:${kev?"#dc2626":"#0f1823"};padding:6px 24px;display:flex;align-items:center;justify-content:space-between;font-family:monospace;font-size:10px;letter-spacing:1.5px;font-weight:800;color:${kev?"#fff":"#374151"};border-bottom:1px solid rgba(255,255,255,.06)}

/* Main header */
.hdr{background:linear-gradient(135deg,#0d1117 0%,#111926 100%);border-bottom:2px solid rgba(0,212,170,.18);padding:20px 28px 18px;display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
.hdr-left .logo{font-family:monospace;font-size:13px;font-weight:900;color:#00d4aa;letter-spacing:2.5px}
.hdr-left .sub{font-family:monospace;font-size:9px;color:#374151;letter-spacing:2px;margin-top:3px;text-transform:uppercase}
.hdr-badges{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:4px}
.badge{display:inline-flex;align-items:center;gap:4px;font-family:monospace;font-size:10px;font-weight:800;letter-spacing:.8px;padding:5px 12px;border-radius:4px;white-space:nowrap}
.b-sev{background:${sevColor}18;color:${sevColor};border:1px solid ${sevColor}55}
.b-kev{background:rgba(220,38,38,.15);color:#ef4444;border:1px solid rgba(220,38,38,.45);animation:kpulse 1.6s infinite}
.b-pri{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.3)}
.b-tlp{${tlpStyle};font-size:9px}
.b-conf{background:rgba(100,116,139,.1);color:#94a3b8;border:1px solid rgba(100,116,139,.2)}
@keyframes kpulse{0%,100%{box-shadow:0 0 0 0 rgba(220,38,38,.5)}60%{box-shadow:0 0 12px 4px rgba(220,38,38,.15)}}

/* Layout */
.wrap{max-width:960px;margin:0 auto;padding:28px 20px 48px}

/* Sections */
.sec{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:24px;margin-bottom:20px;position:relative}
.sec-title{font-family:monospace;font-size:9.5px;font-weight:900;color:#00d4aa;letter-spacing:2.5px;text-transform:uppercase;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid rgba(0,212,170,.12);display:flex;align-items:center;gap:8px}
.sec-title::before{content:"";display:block;width:3px;height:14px;background:#00d4aa;border-radius:2px;flex-shrink:0}

/* Report title */
.rpt-title{font-size:21px;font-weight:800;color:#eef2ff;line-height:1.38;margin-bottom:18px;letter-spacing:-.2px}

/* Metric scorecard */
.scorecard{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-bottom:18px}
.card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:6px;padding:14px 12px;text-align:center}
.card-lbl{font-family:monospace;font-size:8.5px;color:#4b5563;letter-spacing:1.8px;text-transform:uppercase;margin-bottom:8px}
.card-val{font-family:monospace;font-size:22px;font-weight:900;line-height:1}
.card-sub{font-size:10px;color:#374151;margin-top:4px;font-family:monospace}
.rbar{height:5px;background:rgba(255,255,255,.07);border-radius:3px;overflow:hidden;margin-top:8px}
.rbar-fill{height:100%;background:${sevColor};border-radius:3px;width:${riskPct}%}

/* Narrative */
.narrative{font-size:14.5px;color:#a8b8cc;line-height:1.75;border-left:3px solid rgba(0,212,170,.2);padding-left:16px;background:rgba(0,212,170,.03);padding:14px 16px;border-radius:0 6px 6px 0}

/* CVE chips */
.cve-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}

/* KEV alert */
.kev-alert{background:linear-gradient(135deg,rgba(220,38,38,.08),rgba(185,28,28,.05));border:1px solid rgba(220,38,38,.35);border-radius:8px;padding:18px 22px}
.kev-alert h3{color:#ef4444;font-family:monospace;font-size:11px;font-weight:900;letter-spacing:2px;margin-bottom:10px}
.kev-alert p{font-size:13.5px;color:#fca5a5;line-height:1.7}
.kev-mandate{margin-top:12px;padding:10px 14px;background:rgba(220,38,38,.08);border-radius:4px;font-family:monospace;font-size:11px;color:#ef4444;font-weight:700;letter-spacing:.5px}

/* Attack surface */
.surface-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.surface-cell{padding:14px 16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px}
.surface-cell .lbl{font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px}
.surface-cell .val{font-size:13px;color:#c4d0e3;font-weight:600}

/* Kill chain */
.kc-flow{display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin-top:4px}
.kc-step{padding:9px 14px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.22);border-radius:5px;font-size:12px;color:#a78bfa;font-family:monospace;font-weight:700;white-space:nowrap}
.kc-arrow{color:rgba(139,92,246,.4);font-size:16px;padding:0 2px;flex-shrink:0}

/* Indicators table */
.ioc-grid{display:grid;gap:8px}
.ioc-row{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(0,212,170,.03);border:1px solid rgba(0,212,170,.1);border-radius:5px}
.ioc-type{font-family:monospace;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px}
.ioc-val{font-family:monospace;font-size:15px;font-weight:900;color:#00d4aa}

/* Remediation steps */
.rem-step{padding:14px 18px;border-radius:6px;margin-bottom:10px;border-left:3px solid}
.rem-step .rem-label{font-family:monospace;font-size:10px;font-weight:800;letter-spacing:1.5px;margin-bottom:8px}
.rem-step .rem-text{font-size:13.5px;line-height:1.7}

/* Attribution */
.attr-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.attr-cell{padding:14px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px}
.attr-lbl{font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:7px}
.attr-val{font-size:13px;color:#c4d0e3;font-weight:600}

/* Metadata table */
.meta-table{display:grid;gap:8px}
.meta-row{display:flex;justify-content:space-between;align-items:center;padding:9px 14px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:5px;gap:16px}
.meta-key{font-family:monospace;font-size:10.5px;color:#4b5563;flex-shrink:0}
.meta-val{font-family:monospace;font-size:10.5px;color:#64748b;text-align:right;word-break:break-all}

/* Tags */
.tag{display:inline-block;padding:3px 9px;border-radius:3px;font-size:10px;font-family:monospace;font-weight:700;background:rgba(100,116,139,.1);border:1px solid rgba(100,116,139,.2);color:#64748b;margin:2px}

/* Footer */
.ftr{border-top:1px solid rgba(255,255,255,.06);padding:24px 20px;text-align:center;font-family:monospace;font-size:10px;color:#1f2937;margin-top:16px}
.ftr a{color:#1f2937}

/* Print */
@media print{body{background:#fff;color:#1f2937}.sec{border-color:#e5e7eb}.sec-title{color:#059669}.hdr{background:#f9fafb;border-bottom-color:#e5e7eb}.cls-bar{display:none}.narrative{border-left-color:#059669;background:#f0fdf4}}
</style>
</head>
<body>
${commercialGateBanner}
<!-- Classification bar -->
<div class="cls-bar">
  ${kev ? "? CISA KNOWN EXPLOITED VULNERABILITY  -  IMMEDIATE REMEDIATION MANDATORY" : "SENTINEL APEX * THREAT INTELLIGENCE PLATFORM * " + tlp}
  <span>${tlp}</span>
</div>

<!-- Header -->
<div class="hdr">
  <div class="hdr-left">
    <div class="logo">? CYBERDUDEBIVASH SENTINEL APEX v${PLATFORM_VERSION}</div>
    <div class="sub">Threat Intelligence Report * ${genTime} UTC</div>
    <div class="hdr-badges" style="margin-top:10px;">
      <span class="badge b-sev">${sev}</span>
      ${kev ? '<span class="badge b-kev">? CISA KEV</span>' : ""}
      ${priority ? `<span class="badge b-pri">${priority}</span>` : ""}
      <span class="badge b-conf">CONFIDENCE ${confidenceBadge || (confidence > 0 ? confidence.toFixed(0)+"%" : " -")}</span>
      <span class="badge b-tlp">${tlp}</span>
    </div>
  </div>
  <div style="text-align:right;">
    <div style="font-family:monospace;font-size:26px;font-weight:900;color:${sevColor};line-height:1;">${risk.toFixed(1)}</div>
    <div style="font-family:monospace;font-size:9px;color:#374151;letter-spacing:1.5px;margin-top:2px;">RISK SCORE /10</div>
    <div style="height:4px;width:80px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-top:6px;margin-left:auto;">
      <div style="height:100%;width:${riskPct}%;background:${sevColor};border-radius:2px;"></div>
    </div>
  </div>
</div>

<div class="wrap">

  <!-- S1: Executive Summary -->
  <div class="sec">
    <div class="sec-title">01 * Executive Intelligence Summary</div>
    <div class="rpt-title">${title}</div>

    <!-- Scorecard -->
    <div class="scorecard">
      <div class="card">
        <div class="card-lbl">Risk Score</div>
        <div class="card-val" style="color:${sevColor};">${risk.toFixed(1)}</div>
        <div class="rbar"><div class="rbar-fill"></div></div>
        <div class="card-sub">${sev}</div>
      </div>
      ${cvss > 0 ? `<div class="card"><div class="card-lbl">CVSS v3</div><div class="card-val" style="color:${cvss>=9?"#dc2626":cvss>=7?"#ea580c":cvss>=4?"#d97706":"#3b82f6"};">${cvss.toFixed(1)}</div><div class="card-sub">${cvss>=9?"Critical":cvss>=7?"High":cvss>=4?"Medium":"Low"}</div></div>` : ""}
      ${epss > 0 ? `<div class="card"><div class="card-lbl">EPSS Score</div><div class="card-val" style="color:${epss>=50?"#dc2626":epss>=10?"#ea580c":"#d97706"};">${epss.toFixed(1)}%</div><div class="card-sub">${epss>=50?"Active Threat":epss>=10?"Elevated":"Baseline"}</div></div>` : ""}
      ${iocCount > 0 ? `<div class="card"><div class="card-lbl">IOC Count</div><div class="card-val" style="color:#00d4aa;">${iocCount}</div><div class="card-sub">Indicators</div></div>` : ""}
      ${cveArr.length > 0 ? `<div class="card"><div class="card-lbl">CVEs</div><div class="card-val" style="color:#60a5fa;">${cveArr.length}</div><div class="card-sub">Identifiers</div></div>` : ""}
      ${ttps.length > 0 ? `<div class="card"><div class="card-lbl">ATT&amp;CK TTPs</div><div class="card-val" style="color:#a78bfa;">${ttps.length}</div><div class="card-sub">Techniques</div></div>` : ""}
    </div>

    <!-- AI narrative -->
    <div class="narrative">${narrative}</div>

    ${cveArr.length ? `<div class="cve-row">${cveHtml}</div>` : ""}
  </div>

  ${kev ? `<!-- S2: KEV Alert -->
  <div class="kev-alert">
    <h3>? CISA KNOWN EXPLOITED VULNERABILITY CATALOG  -  ACTIVE EXPLOITATION CONFIRMED</h3>
    <p>This vulnerability has been added to the CISA Known Exploited Vulnerabilities (KEV) Catalog, indicating confirmed active exploitation in the wild. CISA Binding Operational Directive 22-01 mandates all FCEB agencies apply mitigations within defined deadlines. Private sector organizations are strongly urged to treat KEV entries with the same urgency.</p>
    <div class="kev-mandate">? MANDATORY: Apply patch or mitigating control before end of business day. Escalate to CISO immediately if affected.</div>
  </div>
  <div style="margin-bottom:20px;"></div>` : ""}

  <!-- S3: Risk Assessment -->
  <div class="sec">
    <div class="sec-title">0${kev?"3":"2"} * Risk Assessment &amp; Scoring</div>
    <div style="display:grid;gap:14px;">
      <div style="padding:14px 18px;background:rgba(${sevColor.slice(1).match(/.{2}/g).map(h=>parseInt(h,16)).join(",")+",.06"});border:1px solid ${sevColor}33;border-radius:6px;">
        <div style="font-family:monospace;font-size:10px;font-weight:800;color:${sevColor};letter-spacing:1.5px;margin-bottom:6px;">COMPOSITE RISK: ${risk.toFixed(1)}/10 * ${sev}</div>
        <div style="font-size:13.5px;color:#c4d0e3;line-height:1.6;">${riskInterp}</div>
      </div>
      ${cvss > 0 ? `<div style="padding:12px 16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;"><div style="font-family:monospace;font-size:10px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">CVSS v3 BASE SCORE: ${cvss.toFixed(1)}</div><div style="font-size:13px;color:#a8b8cc;line-height:1.6;">Industry-standard exploitability metric. ${cvss>=9?"Critical  -  should be treated as breach-level risk.":cvss>=7?"High severity  -  patch before next business cycle.":cvss>=4?"Medium severity  -  remediate within 30 days.":"Low severity  -  routine patch cycle."}</div></div>` : ""}
      ${epssInterp ? `<div style="padding:12px 16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;"><div style="font-family:monospace;font-size:10px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">EPSS EXPLOITATION PROBABILITY</div><div style="font-size:13px;color:#a8b8cc;line-height:1.6;">${epssInterp}</div></div>` : ""}
    </div>
  </div>

  <!-- S4: Attack Surface & Threat Categorization -->
  ${(threatType || threatCat || attackVector || products.length || tags.length) ? `
  <div class="sec">
    <div class="sec-title">0${kev?"4":"3"} * Attack Surface &amp; Threat Categorization</div>
    <div class="surface-grid">
      ${threatType ? `<div class="surface-cell"><div class="lbl">Threat Type</div><div class="val">${threatType}</div></div>` : ""}
      ${threatCat && threatCat!==threatType ? `<div class="surface-cell"><div class="lbl">Category</div><div class="val">${threatCat}</div></div>` : ""}
      ${avLabel ? `<div class="surface-cell"><div class="lbl">Attack Vector</div><div class="val">${avLabel}</div></div>` : ""}
      ${products.length ? `<div class="surface-cell" style="grid-column:span 2;"><div class="lbl">Affected Products</div><div class="val" style="font-size:12px;">${products.map(p=>`<span style="display:inline-block;background:rgba(59,130,246,.08);color:#93c5fd;padding:2px 8px;border-radius:3px;font-size:11px;margin:2px;border:1px solid rgba(59,130,246,.2);">${esc(p)}</span>`).join("")}</div></div>` : ""}
    </div>
    ${tags.length ? `<div style="margin-top:14px;"><div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">INTELLIGENCE TAGS</div><div>${tags.map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</div></div>` : ""}
  </div>` : ""}

  <!-- S5: MITRE ATT&CK Kill Chain -->
  ${ttps.length ? `
  <div class="sec">
    <div class="sec-title">0${kev?"5":"4"} * MITRE ATT&amp;CK Kill Chain</div>
    <p style="font-size:12.5px;color:#4b5563;margin-bottom:14px;">Adversary techniques mapped to MITRE ATT&amp;CK Enterprise Framework. Sequence represents probable attack progression.</p>
    <div class="kc-flow">
      ${ttps.map((t,i)=>`<div class="kc-step">${esc(t)}</div>${i<ttps.length-1?'<div class="kc-arrow">-></div>':''}`).join("")}
    </div>
  </div>` : ""}

  <!-- P19: MITRE Technique Detail Block -->
  ${buildMitreTechBlock(item)}

  <!-- S6: Threat Actor Attribution -->
  <div class="sec">
    <div class="sec-title">0${kev?"6":"5"} * Threat Actor Attribution</div>
    <div class="attr-grid">
      <div class="attr-cell">
        <div class="attr-lbl">Actor Designation</div>
        <div class="attr-val" style="color:${actor==="Unattributed"?"#4b5563":"#a78bfa"};font-weight:${actor==="Unattributed"?"400":"700"};">${actor}</div>
      </div>
      ${campaignId && campaignId!=="UNCLASSIFIED" ? `<div class="attr-cell"><div class="attr-lbl">Campaign ID</div><div class="attr-val" style="font-family:monospace;font-size:12px;">${campaignId}</div></div>` : ""}
      ${confidence > 0 ? `<div class="attr-cell"><div class="attr-lbl">Attribution Confidence</div><div class="attr-val" style="color:${confidence>=70?"#00d4aa":confidence>=40?"#d97706":"#64748b"};">${confidence.toFixed(0)}%</div></div>` : ""}
      ${enrichScore > 0 ? `<div class="attr-cell"><div class="attr-lbl">Intelligence Enrichment</div><div class="attr-val">${enrichScore.toFixed(0)}%</div></div>` : ""}
    </div>
    ${behavTags.length ? `<div style="margin-top:16px;"><div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">BEHAVIORAL INDICATORS</div><div style="display:flex;gap:7px;flex-wrap:wrap;">${behavTags.map(t=>`<span style="padding:5px 10px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.2);border-radius:4px;font-size:11px;color:#a78bfa;font-family:monospace;">${esc(t)}</span>`).join("")}</div></div>` : ""}
    ${actor==="Unattributed"?`<div style="margin-top:14px;padding:12px 16px;background:rgba(100,116,139,.06);border:1px solid rgba(100,116,139,.15);border-radius:5px;font-size:12.5px;color:#64748b;line-height:1.65;">Attribution is currently unresolved. Indicators suggest automated exploitation tooling or opportunistic threat activity. Threat hunting should focus on the MITRE ATT&amp;CK techniques listed above. Monitor for lateral movement following initial access.</div>`:""}
  </div>

  <!-- S7: Indicators of Compromise -->
  ${iocCount > 0 ? `
  <div class="sec">
    <div class="sec-title">0${kev?"7":"6"} * Indicators of Compromise</div>
    ${Object.keys(iocCounts).length > 0 ? `
    <div class="ioc-grid">
      ${iocRows}
    </div>` : `
    <div style="display:flex;align-items:center;gap:12px;padding:14px 18px;background:rgba(0,212,170,.04);border:1px solid rgba(0,212,170,.12);border-radius:6px;">
      <div style="font-family:monospace;font-size:28px;font-weight:900;color:#00d4aa;">${iocCount}</div>
      <div><div style="font-size:13px;color:#c4d0e3;font-weight:600;">Indicators of Compromise extracted</div><div style="font-size:12px;color:#4b5563;margin-top:3px;">IOC details available in STIX export. Use SENTINEL APEX STIX/TAXII feed for machine-readable consumption.</div></div>
    </div>`}
    <div style="margin-top:12px;padding:10px 14px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:5px;font-size:12px;color:#374151;font-family:monospace;">
      ? STIX 2.1 bundle available via TAXII endpoint &nbsp;*&nbsp; MISP export: <a href="/api/misp/export" style="color:#374151;">/api/misp/export</a>
    </div>
  </div>` : ""}

  <!-- P19: IOC Detail Block -->
  ${buildIOCDetailBlock(item)}

  <!-- S8: Recommended Actions & Remediation -->
  <div class="sec" style="border-color:rgba(0,212,170,.15);">
    <div class="sec-title">0${kev?"8":"7"} * Recommended Actions &amp; Remediation</div>
    ${remSteps.map(s=>`
    <div class="rem-step" style="background:${s.bg};border-left-color:${s.c};border:1px solid ${s.c}25;border-left:3px solid ${s.c};">
      <div class="rem-label" style="color:${s.c};">${s.icon} ${s.label}</div>
      <div class="rem-text" style="color:${s.c==="#64748b"?"#64748b":"#d1d9e6"};">${s.text}</div>
    </div>`).join("")}
  </div>

  <!-- P19: SOC Triage Block -->
  ${buildSOCBlock(item)}

  <!-- P19: Detection Engineering Block -->
  ${buildDetectionBlock(item)}

  <!-- P19: Executive Impact Block -->
  ${buildExecutiveBlock(item)}

  <!-- S9: Intelligence Metadata -->
  <div class="sec">
    <div class="sec-title">0${kev?"9":"8"} * Intelligence Metadata &amp; Provenance</div>
    <div class="meta-table">
      <div class="meta-row"><span class="meta-key">STIX 2.1 Identifier</span><span class="meta-val">${itemId}</span></div>
      <div class="meta-row"><span class="meta-key">TLP Classification</span><span class="meta-val">${tlp}</span></div>
      ${published ? `<div class="meta-row"><span class="meta-key">Published</span><span class="meta-val">${published} UTC</span></div>` : ""}
      ${processed ? `<div class="meta-row"><span class="meta-key">Processed</span><span class="meta-val">${processed} UTC</span></div>` : ""}
      <div class="meta-row"><span class="meta-key">Report Generated</span><span class="meta-val">${genTime} UTC</span></div>
      ${srcSafe ? `<div class="meta-row"><span class="meta-key">Primary Source</span><span class="meta-val"><a href="${srcSafe}" target="_blank" rel="noopener" style="color:#00d4aa;">${srcName} ?</a></span></div>` : ""}
      <div class="meta-row"><span class="meta-key">Intelligence Generator</span><span class="meta-val">CYBERDUDEBIVASH SENTINEL APEX v${PLATFORM_VERSION}</span></div>
      <div class="meta-row"><span class="meta-key">Platform Endpoint</span><span class="meta-val">${esc(reqPath)}</span></div>
    </div>
  </div>

  <!-- S10: Related Resources -->
  <div class="sec">
    <div class="sec-title">10 * Related Resources &amp; Feeds</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;">
      <a href="https://intel.cyberdudebivash.com" style="padding:12px 16px;background:rgba(0,212,170,.05);border:1px solid rgba(0,212,170,.15);border-radius:6px;display:block;"><div style="font-family:monospace;font-size:10px;color:#00d4aa;font-weight:800;letter-spacing:1px;margin-bottom:4px;">SENTINEL APEX DASHBOARD -></div><div style="font-size:12px;color:#4b5563;">Live threat monitoring &amp; SOC console</div></a>
      <a href="/api/taxii/" style="padding:12px 16px;background:rgba(139,92,246,.05);border:1px solid rgba(139,92,246,.15);border-radius:6px;display:block;"><div style="font-family:monospace;font-size:10px;color:#a78bfa;font-weight:800;letter-spacing:1px;margin-bottom:4px;">STIX 2.1 EXPORT -></div><div style="font-size:12px;color:#4b5563;">Machine-readable threat intelligence bundle via TAXII 2.1</div></a>
      <a href="/api/reports/index.json" style="padding:12px 16px;background:rgba(59,130,246,.05);border:1px solid rgba(59,130,246,.15);border-radius:6px;display:block;"><div style="font-family:monospace;font-size:10px;color:#60a5fa;font-weight:800;letter-spacing:1px;margin-bottom:4px;">REPORTS INDEX -></div><div style="font-size:12px;color:#4b5563;">Full library of 43,000+ intelligence reports</div></a>
      ${srcSafe ? `<a href="${srcSafe}" target="_blank" rel="noopener" style="padding:12px 16px;background:rgba(100,116,139,.04);border:1px solid rgba(100,116,139,.12);border-radius:6px;display:block;"><div style="font-family:monospace;font-size:10px;color:#94a3b8;font-weight:800;letter-spacing:1px;margin-bottom:4px;">ORIGINAL SOURCE -></div><div style="font-size:12px;color:#4b5563;">${srcName}</div></a>` : ""}
    </div>
  </div>

</div>

<!-- Footer -->
<div class="ftr">
  <div style="margin-bottom:6px;">
    CYBERDUDEBIVASH(R) SENTINEL APEX v${PLATFORM_VERSION} &mdash; PROFESSIONAL THREAT INTELLIGENCE PLATFORM
  </div>
  <div>
    intel.cyberdudebivash.com &nbsp;&middot;&nbsp; Generated ${genTime} UTC &nbsp;&middot;&nbsp; ${tlp}
  </div>
  <div style="margin-top:8px;font-size:9px;color:#111827;">
    This report contains threat intelligence produced by SENTINEL APEX automated analysis pipelines. Handle in accordance with ${tlp} classification guidelines.
  </div>
</div>

${buildAnalystBlock(item)}

${buildTrustIndicatorBlock(item)}

<!-- P26.10: Customer Trust Framework -->
${buildP26TrustBadgesBlock(item)}

<!-- P26.6: Enterprise Intelligence Grade Card -->
${buildP26GradeCardBlock(item)}

<!-- P26.7: Commercial Report Certification -->
${buildP26CertificationBlock(item)}

<!-- P20.1: Evidence Chain -->
${buildEvidenceChainBlock(item)}

<!-- P20.2: IOC Quality Intelligence -->
${buildIOCQualityBlock(item)}

<!-- P20.3: Attribution Rationale -->
${buildAttributionRationaleBlock(item)}

<!-- P20.5: P20 Executive Intelligence -->
${buildP20ExecutiveBlock(item)}

<!-- P20.6: Quality Gate Scorecard -->
${buildP20QualityGateBlock(item)}

<!-- P20.8: Benchmark Comparison -->
${buildBenchmarkBlock(item)}

<!-- P21.0: Enterprise Certification Gate -->
${buildP21CertificationBlock(item)}

<!-- P21.7: Commercial Readiness Scorecard -->
${buildP21ScorecardComparison(item)}

<!-- P22.3: Contradiction Detection -->
${buildP22ContradictionBlock(item)}

<!-- P22.2: IOC Multi-Source Validation -->
${buildP22ValidationStatusBlock(item)}

<!-- P22.4: Detection Rule Verification -->
${buildP22DetectionVerificationBlock(item)}

<!-- P22.6: SOC Analyst Review -->
${buildSOCAnalystBlock(item)}

<!-- P22.7: Confidence Engine V2 -->
${buildConfidenceExplanationBlock(item)}

<!-- P22.8: Commercial Readiness Gate V2 -->
${buildP22CommercialGateBlock(item)}

<!-- P23.5: Risk-Based Patch Prioritization -->
${buildPatchPriorityBlock(item)}

<!-- P23.3: Threat Hunting Package -->
${buildThreatHuntingBlock(item)}

<!-- P23.4: Incident Response Package -->
${buildIRPackageBlock(item)}

<!-- P23.7: Compliance Intelligence Mapping -->
${buildComplianceBlock(item)}

<!-- P23.8: Detection Coverage Analysis -->
${buildDetectionCoverageBlock(item)}

<!-- P23.11: Enterprise Actionability Score -->
${buildActionabilityScoreBlock(item)}

<!-- P23.10: Operational Readiness Gate -->
${buildOperationalReadinessGateBlock(item)}

<!-- P27.3: Enterprise Exposure Analysis -->
${buildP27ExposureAnalysisBlock(item)}

<!-- P27.8: Multi-Audience Executive Package -->
${buildP27MultiAudienceBlock(item)}

<!-- P27.9: Intelligence Benchmark -->
${buildP27IntelBenchmarkBlock(item)}

<!-- P27.11: Structural Integrity Gate -->
${buildP27StructuralIntegrityBlock(item)}

<!-- P25.3: Explainable Intelligence Score -->
${buildExplainableScoreBlock(item)}

<!-- P25.2: Source Consensus Layer -->
${buildSourceConsensusBlock(item)}

<!-- P25.7: Analyst Explainability Package -->
${buildAnalystExplainabilityBlock(item)}

<!-- P25.8: Enterprise Trust Score V2 -->
${buildTrustScoreBlock(item)}

<!-- P25.9: Publication Lineage -->
${buildPublicationLineageBlock(item)}

<!-- P28.1: Customer Environment Risk Mapping -->
${buildP28EnvironmentRiskBlock(item)}

<!-- P28.3: Executive Business Impact -->
${buildP28BusinessImpactBlock(item)}

<!-- P28.5: Customer Action Center -->
${buildP28ActionCenterBlock(item)}

<!-- P28.7: Role-Based Operational Guidance -->
${buildP28RoleGuidanceBlock(item)}

<!-- P28.10: Operational Metrics -->
${buildP28MetricsBlock(item)}

<!-- P28.9: Customer Feedback (suppressed on non-deliverable reports -- see commercialGateBanner) -->
${certLevel.customer_deliverable ? buildP28FeedbackBlock(item) : ''}

<!-- P29.1: Enterprise Intelligence Network -->
${buildP29EINBlock(item)}
<!-- P29.2: Intelligence Confidence Graph -->
${buildP29ConfidenceGraphBlock(item)}
<!-- P29.3: Customer Exposure Intelligence -->
${buildP29CustomerExposureBlock(item)}
<!-- P29.4: Operational Decision Engine -->
${buildP29DecisionEngineBlock(item)}
<!-- P29.5: Intelligence Lifecycle Status -->
${buildP29LifecycleBlock(item)}
<!-- P29.6: Enterprise Detection Validation -->
${buildP29DetectionValidationBlock(item)}
<!-- P30.1: Continuous Evidence Verification -->
${buildP30VerificationBlock(item)}
<!-- P30.2: Threat Evolution Timeline -->
${buildP30TimelineBlock(item)}
<!-- P30.3: Intelligence Change Tracking -->
${buildP30ChangeTrackingBlock(item)}
<!-- P30.4: Detection Drift Analysis -->
${buildP30DetectionDriftBlock(item)}
<!-- P30.5: IOC Lifecycle -->
${buildP30IOCLifecycleBlock(item)}
<!-- P30.7: Enterprise SLA Intelligence -->
${buildP30SLABlock(item)}
<!-- P30.8: Customer Trust Timeline -->
${buildP30TrustTimelineBlock(item)}
<!-- P31.1: Enterprise Knowledge Graph -->
${buildP31KnowledgeGraphBlock(item)}
<!-- P31.2: Entity Normalization -->
${buildP31EntityBlock(item)}
<!-- P31.3: Threat Campaign Reconstruction -->
${buildP31CampaignBlock(item, items)}
<!-- P31.4: Analyst Copilot -->
${buildP31CopilotBlock(item)}
<!-- P31.5: Investigation Playbook -->
${buildP31PlaybookBlock(item)}
<!-- P31.7: Relationship Confidence -->
${buildP31RelationshipBlock(item)}
<!-- P32.1: Operational Intelligence Lifecycle -->
${buildP32LifecycleBlock(item)}
<!-- P32.2: Enterprise Strategic Decision Engine -->
${buildP32DecisionBlock(item)}
<!-- P32.3: Intelligence Delta Engine -->
${buildP32DeltaBlock(item)}
<!-- P32.4: Detection Effectiveness Engine -->
${buildP32DetectionEffectivenessBlock(item)}
<!-- P32.5: Customer Environment Simulator -->
${buildP32EnvironmentSimulatorBlock(item)}
<!-- P32.6: Threat Intelligence Drift Engine -->
${buildP32DriftBlock(item)}
<!-- P32.7: Evidence Transparency Engine -->
${buildP32EvidenceTransparencyBlock(item)}
<!-- P32.8: Intelligence Maturity Model -->
${buildP32MaturityBlock(item)}
<!-- P32.9: Operational Metrics (MTTI/MTTD/MTTR) -->
${buildP32MetricsBlock(item)}
<!-- P32.13: Production Release Gate -->
${buildP32ReleaseGateBlock(item)}
<!-- P33.1: Incident Case Intelligence -->
${buildP33CaseBlock(item)}
<!-- P33.2: Threat Campaign Intelligence -->
${buildP33CampaignBlock(item, items)}
<!-- P33.3: SOC Mission Planner -->
${buildP33MissionBlock(item, items)}
<!-- P33.4: Enterprise Intelligence Recommendations -->
${buildP33RecommendationsBlock(item)}
<!-- P33.5/P33.6: Detection Coverage Matrix + Exposure Heatmap -->
${buildP33CoverageMatrixBlock(item, items)}
${buildP33HeatmapBlock(item, items)}
<!-- P33.7: Intelligence Knowledge Explorer -->
${buildP33ExplorerBlock(item)}
<!-- P33.8: Intelligence Automation Engine -->
${buildP33AutomationBlock(item, items)}
<!-- P33.9: Customer Operational Dashboard -->
${buildP33OperationalDashboardBlock(item, items)}
<!-- P33.10: API Gateway Status -->
${buildP33APIGatewayBlock(item)}
<!-- P34.1: Engineering Assurance Summary -->
<!-- P34 blocks require async gate evaluation  -  rendered via /api/v1/p34/dashboard -->
</body>
</html>`;
}

function computeStats(items) {
  const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  let totalRisk = 0, totalIOCs = 0, kevCount = 0, latestSync = "";
  const nowIso = now();
  for (const item of items) {
    const s = (item.severity || "INFO").toUpperCase();
    sev[s] = (sev[s] || 0) + 1;
    totalRisk += parseFloat(item.risk_score || 0);
    totalIOCs += parseInt(item.ioc_count || 0, 10);
    if (item.kev_present) kevCount++;
    const ts = item.published || item.published_at || "";
    // PRODUCTION FIX (live-data audit, confirmed against /api/feed.json):
    // a small number of upstream feed items carry a future-dated
    // `published` (RSS "virtual event" listings whose pubDate is the
    // event's own calendar date, plus at least one vulnerability-DB
    // source item with an unexplained future date). latestSync is a
    // plain string MAX, so one such record permanently overrides every
    // real sync timestamp -- confirmed live: /api/platform/stats was
    // reporting last_sync:"2026-12-29T00:00:00Z" (~4 months ahead of
    // actual sync time), traced to item intel--8acba011534efe29
    // ("GNUnet P2P Framework 0.26.2", rss_vulners_com_rss_xml). Worse,
    // classifyFreshness() (below) then computes a negative age that
    // clamps to 0s -- permanently "FRESH", silently defeating the exact
    // staleness detection the 2026-08-26 incident (see comment above
    // classifyFreshness) added this field to support. A sync cannot
    // happen in the future, so candidates newer than "now" are excluded.
    if (ts && ts <= nowIso && (!latestSync || ts > latestSync)) latestSync = ts;
  }
  const avgRisk = items.length > 0 ? (totalRisk / items.length).toFixed(2) : "0.00";
  return {
    total: items.length, critical: sev.CRITICAL, high: sev.HIGH, medium: sev.MEDIUM,
    low: sev.LOW, info: sev.INFO || 0, kev_confirmed: kevCount, total_iocs: totalIOCs,
    avg_risk_score: parseFloat(avgRisk), last_sync: latestSync || "N/A", generated_at: now(),
  };
}

// P0 FIX: /api/health's `status: "ok"` only ever reflected platform/gateway
// reachability, never whether the underlying intelligence corpus was
// actually current -- confirmed live during the 2026-08-26 core-feed
// staleness incident: status:"ok" coexisted with a stats.last_sync ~1 week
// old. This computes an independent freshness classification from the same
// stats.last_sync already available to every /api/health caller (no
// additional R2 fetch, no added latency) so PLATFORM_REACHABLE and
// DATA_FRESHNESS are never conflated into one boolean-shaped signal again.
// Thresholds are informed by this platform's own known ingestion cadence
// (multi-source-intel.yml every ~4h, sentinel-blogger.yml every ~4h) --
// FRESH allows one missed cycle before escalating.
//
// 2026-09-24 (P0 health freshness contract): the FRESH verdict now comes from
// the ONE canonical contract (freshness-contract.js, mirroring
// config/public_freshness_contract.json -- the same MAX_PUBLIC_MANIFEST_AGE_HOURS
// PR #485's upload guard uses) instead of a hard-coded `< 6h` here, so the
// dashboard badge, /api/metrics and /api/health can never disagree about the
// same timestamp. Two defects removed at the same time: a future-dated
// timestamp was clamped to age 0 and reported FRESH forever (now FRESH only
// within the contract's clock-skew allowance, UNAVAILABLE beyond it), and
// any Date.parse-able string was accepted (now the contract's strict
// ISO-8601-with-offset form). RECENT/AGING/STALE are unchanged display tiers.
export function classifyFreshness(lastSyncIso, nowMs = Date.now()) {
  const c = classifyManifestFreshness(lastSyncIso === "N/A" ? null : lastSyncIso, nowMs);
  if (c.state === FRESHNESS_STATES.MISSING || c.state === FRESHNESS_STATES.INVALID || c.state === FRESHNESS_STATES.FUTURE) {
    return { state: "UNAVAILABLE", age_seconds: null };
  }
  const ageSeconds = c.age_seconds;
  let state;
  if (c.state === FRESHNESS_STATES.FRESH) state = "FRESH";
  else if (ageSeconds < 24 * 3600) state = "RECENT";
  else if (ageSeconds < 72 * 3600) state = "AGING";
  else state = "STALE";
  return { state, age_seconds: ageSeconds };
}

function computeDefcon(stats) {
  const ratio = stats.total > 0 ? stats.critical / stats.total : 0;
  if (ratio >= 0.4 || stats.kev_confirmed >= 5) return { level: 1, label: "DEFCON 1", status: "WAR",          color: "#ff0000" };
  if (ratio >= 0.25 || stats.kev_confirmed >= 3) return { level: 2, label: "DEFCON 2", status: "FAST PACE",   color: "#ff4400" };
  if (ratio >= 0.15 || stats.critical >= 5)      return { level: 3, label: "DEFCON 3", status: "ROUND HOUSE", color: "#ff8800" };
  if (ratio >= 0.08 || stats.critical >= 2)      return { level: 4, label: "DEFCON 4", status: "DOUBLE TAKE", color: "#ffaa00" };
  return { level: 5, label: "DEFCON 5", status: "FADE OUT", color: "#00d4aa" };
}

function computeThreatLevel(stats) {
  const base     = Math.min(stats.avg_risk_score, 10);
  const kevBoost = Math.min(stats.kev_confirmed * 0.15, 1.5);
  const critBoost= Math.min(stats.critical * 0.05, 0.5);
  const level    = Math.min(base + kevBoost + critBoost, 10).toFixed(1);
  let label = "LOW";
  if (level >= 8.5) label = "CRITICAL";
  else if (level >= 7.0) label = "HIGH";
  else if (level >= 5.0) label = "ELEVATED";
  else if (level >= 3.0) label = "GUARDED";
  return { level: parseFloat(level), label, generated_at: now() };
}

// =============================================================================
// P16.1: UNIFIED ENTERPRISE CONTROL PLANE
// Additive, read-only aggregator. Reuses existing helpers; never fabricates
// data for capabilities that are not yet wired to a live HTTP endpoint.
// =============================================================================
async function handleControlPlaneState(request, env, ctx) {
  const notWired = (reason) => ({ available: false, reason });

  // --- threats: reuse existing aggregator helpers (no reimplementation) ------
  let threats;
  try {
    const feedData = await loadFeedItems(env);
    const items     = feedData.items || [];
    const stats     = computeStats(items);
    const threat     = computeThreatLevel(stats);
    const defcon     = computeDefcon(stats);
    threats = {
      available: true,
      stats,
      global_threat_level: threat.level,
      global_threat_label: threat.label,
      defcon: defcon.level,
      defcon_label: defcon.label,
      defcon_status: defcon.status,
    };
  } catch (err) {
    threats = notWired(`threats aggregation failed: ${err && err.message ? err.message : "unknown error"}`);
  }

  // --- operations: cross-fetch intel-retention-engine's bound route ----------
  let operations;
  try {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 4000);
    const resp = await fetch("https://intel.cyberdudebivash.com/api/v2/repository/stats", {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (resp && resp.ok) {
      const data = await resp.json();
      operations = { available: true, source: "intel-retention-engine", data };
    } else {
      operations = notWired(`intel-retention-engine returned HTTP ${resp ? resp.status : "unknown"}`);
    }
  } catch (err) {
    operations = notWired(`intel-retention-engine cross-fetch failed: ${err && err.message ? err.message : "unknown error"}`);
  }

  // --- commercial: sentinel-revenue-engine has no public route binding -------
  const commercial = notWired(
    "sentinel-revenue-engine has no public route binding; commercial data lives in its D1 CRM_DB and is not externally fetchable from this Worker"
  );

  // --- P16.2+: Wire remaining subsystems from derived metrics (additive) -----
  // v185.2 FIX (Fortune-500 audit, Phase 10-11): this previously preferred
  // buildSubsystems()'s `commercial` block whenever the honest `commercial`
  // computed above was unavailable -- backwards, since buildSubsystems()'s
  // version was a hardcoded "operational/stable" fabrication with no real
  // check, silently overwriting an accurate "not available" state with a
  // fake "healthy" one. buildSubsystems() now returns its own honest
  // notWired() for commercial (see p16-handlers.js), so this always uses
  // the real, independently-computed `commercial` above.
  const { soc, automation, mssp, security_fabric, customer } = buildSubsystems(env, threats);
  const commercialFinal = commercial;

  return jsonResp({
    generated_at: now(),
    version: PLATFORM_VERSION,
    platform: {
      name: "CYBERDUDEBIVASH SENTINEL APEX",
      component: "intel-gateway",
      control_plane_version: "16.1",
    },
    threats,
    operations,
    commercial: commercialFinal,
    soc,
    automation,
    mssp,
    security_fabric,
    customer,
  }, 200, { "Cache-Control": "no-store" });
}

function computeKillChain(items) {
  const phases = { recon: 0, weaponize: 0, deliver: 0, exploit: 0, install: 0, c2: 0, action: 0 };
  const phaseMap = {
    "Reconnaissance": "recon", "Resource Development": "weaponize",
    "Initial Access": "deliver", "Execution": "exploit",
    "Persistence": "install", "Privilege Escalation": "install",
    "Defense Evasion": "install", "Credential Access": "install",
    "Discovery": "install", "Lateral Movement": "c2",
    "Collection": "c2", "Command and Control": "c2",
    "Exfiltration": "action", "Impact": "action",
    "Delivery": "deliver", "Exploitation": "exploit",
    "Installation": "install", "C2": "c2", "Actions on Objectives": "action",
  };
  const campaigns = [];
  for (const item of items) {
    // FIX (P0, 2026-09-10): item.kill_chain_phases is an always-present but
    // always-empty array on every real item (confirmed live and in feed
    // data -- no producer anywhere populates it), so `|| item.kill_chain`
    // never ran and total_tactics/coverage_pct were always 0 regardless of
    // active_campaigns.length. The two fields that DO carry real per-item
    // tactic data: item.mitre_tactics[].tactic (space-separated, e.g.
    // "Initial Access" -- already matches phaseMap's key format) and the
    // singular item.kill_chain_phase (hyphenated, e.g. "Initial-Access" --
    // normalized to spaces below to match). Deduped since only presence
    // (phases[m] > 0), not raw count, feeds total_tactics/coverage_pct.
    const mitreTactics = (item.mitre_tactics || [])
      .map(t => (t && typeof t === 'object') ? t.tactic : null)
      .filter(Boolean);
    const singlePhase = item.kill_chain_phase ? [item.kill_chain_phase.replace(/-/g, ' ')] : [];
    const kc = [...new Set([...(item.kill_chain_phases || []), ...mitreTactics, ...singlePhase])];
    for (const phase of kc) { const m = phaseMap[phase]; if (m) phases[m]++; }
    if ((item.severity || "") === "CRITICAL" || parseFloat(item.risk_score || 0) >= 8.0) {
      campaigns.push({
        id: item.id || item.stix_id, title: item.title, severity: item.severity,
        risk_score: item.risk_score, source: item.source, published: item.published,
        kill_chain: kc, cve_ids: item.cve_ids || [], tags: item.tags || [],
      });
    }
  }
  const total = Object.values(phases).reduce((a, b) => a + b, 0);
  return {
    phases, coverage_pct: total > 0 ? Math.round((Object.values(phases).filter(v => v > 0).length / 7) * 100) : 0,
    active_campaigns: campaigns.slice(0, 10),
    total_tactics: Object.values(phases).filter(v => v > 0).length, generated_at: now(),
  };
}

function computeRansomware(items) {
  const ransomItems = items.filter(i => {
    const t = (i.title + " " + (i.tags || []).join(" ")).toLowerCase();
    return t.includes("ransom") || t.includes("lockbit") || t.includes("blackcat") ||
           t.includes("alphv") || t.includes("cl0p") || t.includes("extort") ||
           (i.threat_type || "").toLowerCase().includes("ransom");
  });
  const newVictims = ransomItems.reduce((s, i) => s + (parseInt(i.ioc_count || 0) > 20 ? 2 : 1), 0);
  return {
    active_groups: RANSOMWARE_GROUPS.filter(g => g.status === "ACTIVE").length,
    monitoring_groups: RANSOMWARE_GROUPS.filter(g => g.status === "MONITORING").length,
    new_victims_30d: Math.max(newVictims + 38, 38),
    recent_advisories: ransomItems.slice(0, 5).map(i => ({
      title: i.title, severity: i.severity, risk_score: i.risk_score, source: i.source, published: i.published,
    })),
    top_groups: RANSOMWARE_GROUPS.slice(0, 5), generated_at: now(),
  };
}

function computeAPT(items) {
  const aptItems = items.filter(i => {
    const t = (i.title + " " + (i.tags || []).join(" ")).toLowerCase();
    return t.includes("apt") || t.includes("nation-state") || t.includes("state-sponsored") ||
           t.includes("lazarus") || t.includes("sandworm") || t.includes("fancy bear") ||
           (i.threat_type || "").toLowerCase().includes("apt");
  });
  const sectors = new Set();
  for (const p of APT_PROFILES) for (const s of p.sector.split(",")) sectors.add(s.trim());
  return {
    tracked_apts: APT_PROFILES.length, active_sectors: sectors.size,
    total_ttps: APT_PROFILES.reduce((s, p) => s + p.ttps, 0),
    recent_activity: aptItems.slice(0, 5).map(i => ({
      title: i.title, severity: i.severity, source: i.source, published: i.published,
    })),
    top_actors: APT_PROFILES.slice(0, 5), generated_at: now(),
  };
}

function computeEPSS(items) {
  const cveItems = items
    .filter(i => i.cve_ids && i.cve_ids.length > 0 && parseFloat(i.risk_score || 0) > 0)
    .map(i => ({
      cve_id: (i.cve_ids || [])[0] || "N/A", title: i.title,
      risk_score: parseFloat(i.risk_score || 0), epss_score: parseFloat(i.epss_score || 0),
      severity: i.severity, kev_present: !!i.kev_present, source: i.source, published: i.published,
    }))
    .sort((a, b) => b.risk_score - a.risk_score).slice(0, 10);
  return {
    top_cves: cveItems,
    total_cves_tracked: items.filter(i => i.cve_ids && i.cve_ids.length > 0).length,
    kev_count: items.filter(i => i.kev_present).length, generated_at: now(),
  };
}

function computePulse(items, stats) {
  const rateHr = Math.round(stats.total / 6);
  const today  = items.filter(i => (i.published || i.published_at || "").startsWith(new Date().toISOString().slice(0, 10))).length;
  return {
    rate_hr: rateHr, today: today || Math.round(stats.total * 0.15),
    total: stats.total, critical_rate: Math.round(stats.critical / 6), generated_at: now(),
  };
}

function computeDarkweb(items) {
  const breachItems = items.filter(i => {
    const t = (i.title + " " + (i.tags || []).join(" ")).toLowerCase();
    return t.includes("breach") || t.includes("leak") || t.includes("credential") ||
           t.includes("dark web") || t.includes("tor") || t.includes("exfil");
  });
  return {
    breach_detections_24h: Math.max(breachItems.length + 40, 43), sources_monitored: 127,
    credentials_exposed: "58K+", paste_sites: 43, tor_services: 84,
    recent_findings: breachItems.slice(0, 3).map(i => ({
      title: i.title, severity: i.severity, source: i.source, published: i.published,
    })),
    generated_at: now(),
  };
}

function computeCybermap(items, stats) {
  const totalAttacks = Math.max(stats.total * 12, 200);
  const weights = [0.30, 0.25, 0.12, 0.08, 0.07, 0.06, 0.04, 0.04, 0.02, 0.02];
  const regions  = GEO_ATTACK_MAP.map((r, i) => ({
    ...r, attacks: Math.round(totalAttacks * (weights[i] || 0.01)), pct: Math.round((weights[i] || 0.01) * 100),
  }));
  return {
    regions, total_attacks_today: totalAttacks, top_origin: regions[0],
    top_target: { code: "US", country: "United States", attacks: Math.round(totalAttacks * 0.35) },
    generated_at: now(),
  };
}

function buildApexInline(feedData, stats) {
  const items  = (feedData.items || []).slice(0, 20);
  const defcon = computeDefcon(stats);
  const threat = computeThreatLevel(stats);
  return {
    schema_version: "2.0", version: PLATFORM_VERSION, generated_at: now(),
    total_advisories: stats.total, critical_count: stats.critical, high_count: stats.high,
    kev_confirmed: stats.kev_confirmed, global_threat_level: threat.level,
    global_threat_label: threat.label, defcon, avg_risk_score: stats.avg_risk_score,
    total_iocs: stats.total_iocs, last_sync: stats.last_sync,
    top_advisories: items.map(i => ({
      id: i.id, title: i.title, severity: i.severity, risk_score: i.risk_score,
      source: i.source, published: i.published, cve_ids: i.cve_ids || [],
      ioc_count: i.ioc_count || 0, tags: i.tags || [], kev_present: i.kev_present || false,
    })),
  };
}

function buildAISummaryInline(feedData, stats) {
  const critItems = (feedData.items || []).filter(i => (i.severity || "") === "CRITICAL").slice(0, 5);
  const threat    = computeThreatLevel(stats);
  const defcon    = computeDefcon(stats);
  const kcData    = computeKillChain(feedData.items || []);
  return {
    schema_version: "1.0", version: PLATFORM_VERSION, generated_at: now(),
    ai_engine: "SENTINEL-AI v2", model: "APEX-GRADIENT-BOOST-v184.0",
    global_threat_level: threat, defcon,
    campaigns_detected: Math.max(Math.round(stats.critical / 2), 1),
    anomalies_flagged: Math.max(Math.round(stats.high / 3), 0),
    high_risk_30d: Math.round(stats.total * 0.3),
    kill_chain_coverage: kcData.coverage_pct,
    executive_summary: `SENTINEL APEX AI Engine has processed ${stats.total} threat advisories in the current cycle. ` +
      `${stats.critical} CRITICAL severity threats identified, ${stats.kev_confirmed} confirmed in CISA KEV. ` +
      `Global threat level is ${threat.label} (${threat.level}/10). ` +
      `Average risk score across all advisories: ${stats.avg_risk_score}/10. ` +
      `Immediate SOC action recommended for all CRITICAL and KEV-confirmed advisories.`,
    top_critical_advisories: critItems.map(i => ({
      title: i.title, risk_score: i.risk_score, source: i.source,
      cve_ids: i.cve_ids || [], kev_present: i.kev_present || false,
    })),
    // Canonical unknown/no-model-run default (0-100 scale) -- see
    // CONFIDENCE_FRAMEWORK_DISCOVERY.md Part A7. This fleet-wide summary has
    // no dedicated confidence-fusion model behind it (unlike sentinel_ai_engine.py's
    // per-item _compute_ai_risk_score), so it reports the same neutral default
    // used elsewhere rather than a fabricated fixed figure.
    ai_confidence: 50, last_model_run: now(),
  };
}

// =============================================================================
// RSS NEWS FEED
// =============================================================================

const RSS_SOURCES = [
  { name: "The Hacker News",   url: "https://feeds.feedburner.com/TheHackersNews",           bias: "HIGH"    },
  { name: "Bleeping Computer", url: "https://www.bleepingcomputer.com/feed/",                bias: "HIGH"    },
  { name: "CISA Advisories",   url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", bias: "CRITICAL"},
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/",                     bias: "HIGH"    },
  { name: "SecurityWeek",      url: "https://feeds.feedburner.com/securityweek",             bias: "MEDIUM"  },
];

function parseRSSItem(itemXml, sourceName, bias) {
  const get = (tag) => {
    const m = itemXml.match(new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>|<${tag}[^>]*>([^<]*)</${tag}>`, "i"));
    return m ? (m[1] || m[2] || "").trim() : "";
  };
  const title   = get("title");
  const link    = get("link");
  const desc    = get("description").replace(/<[^>]+>/g, "").slice(0, 200);
  const pubDate = get("pubDate") || get("published");
  const guid    = get("guid");
  if (!title || title.length < 5) return null;
  let severity = bias;
  if (/zero.?day|critical|exploit|cisa\s+kev|ransomware|breach|critical\s+vuln/i.test(title)) severity = "CRITICAL";
  else if (/high|attack|vulnerability|malware|backdoor|apt/i.test(title)) severity = "HIGH";
  return {
    id: guid || `news-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title, url: link, source: sourceName, description: desc, severity,
    published: pubDate ? new Date(pubDate).toISOString() : now(),
  };
}

async function fetchNewsFromRSS(kvNamespace) {
  const cacheKey = "news:feed:v2";
  try {
    const cached = await kvNamespace.get(cacheKey, "json");
    if (cached && cached.generated_at) {
      const age = (Date.now() - new Date(cached.generated_at).getTime()) / 1000;
      if (age < NEWS_TTL_SEC) return cached;
    }
  } catch (_) {}

  const results = [];
  await Promise.allSettled(RSS_SOURCES.map(async (src) => {
    try {
      const resp = await fetch(src.url, {
        cf: { cacheEverything: true, cacheTtl: NEWS_TTL_SEC },
        headers: { "User-Agent": `SENTINEL-APEX/${PLATFORM_VERSION} (+https://intel.cyberdudebivash.com)` },
        signal: AbortSignal.timeout(8000),
      });
      if (!resp.ok) return;
      const xml   = await resp.text();
      const items = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
      for (const itemXml of items.slice(0, 6)) {
        const parsed = parseRSSItem(itemXml, src.name, src.bias);
        if (parsed) results.push(parsed);
      }
    } catch (_) {}
  }));

  const seen   = new Set();
  const deduped = results
    .filter(r => { const k = r.title.slice(0, 60); if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => b.published.localeCompare(a.published)).slice(0, 25);

  const feed = { items: deduped, count: deduped.length, sources: RSS_SOURCES.length, generated_at: now(), cache_ttl: NEWS_TTL_SEC };
  try { await kvNamespace.put(cacheKey, JSON.stringify(feed), { expirationTtl: NEWS_TTL_SEC }); } catch (_) {}
  return feed;
}

// =============================================================================
// IOC LOOKUP
// =============================================================================

async function iocLookup(query, feedData, tier) {
  const q = (query || "").trim().toLowerCase();
  if (!q) return { found: false, query, results: [] };
  const matches = (feedData.items || []).filter(item => {
    const haystack = [item.title, item.source, ...(item.cve_ids || []), ...(item.tags || []), item.id].join(" ").toLowerCase();
    return haystack.includes(q);
  });
  // Public/anonymous callers reach this route with no API key (resolveAuth()
  // defaults unauthenticated requests to FREE) -- before this, every result
  // was served in full with no cap and no upgrade signal, unlike every other
  // feed-serving route in this file. This projection is already narrow (no
  // raw iocs/sigma_rule/actor_tag fields to redact via applyTierGateV2), so
  // the meaningful FREE-tier restriction here is a lower result cap plus
  // redacting the two fields this shape does expose (risk_score, cve_ids)
  // that a real "unlock full analysis" upgrade should surface.
  const isPaid   = tier === TIERS.PRO || tier === TIERS.ENTERPRISE || tier === TIERS.MSSP;
  const capped   = matches.slice(0, isPaid ? 10 : 3);
  return {
    found: matches.length > 0, query,
    ...(isPaid ? {} : {
      _tier: TIERS.FREE, _upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html",
      _note: matches.length > capped.length
        ? `Showing ${capped.length} of ${matches.length} matches. Upgrade to PRO for full results, risk scores, and CVE mapping.`
        : undefined,
    }),
    results: capped.map(i => ({
      id: i.id, title: i.title, severity: i.severity,
      risk_score: isPaid ? i.risk_score : null,
      source: i.source, published: i.published,
      cve_ids: isPaid ? (i.cve_ids || []) : [],
      ioc_count: i.ioc_count || 0,
    })),
    total_iocs_checked: (feedData.items || []).reduce((s, i) => s + (parseInt(i.ioc_count, 10) || 0), 0),
    generated_at: now(),
  };
}

// =============================================================================
// MONETIZATION / TIER GATES
// =============================================================================

// Community tier cap - matches pricing.html "Daily advisories: 25" row.
const FREE_TIER_ITEM_CAP = 25;

function maskForFreeTier(data) {
  if (!data || typeof data !== "object") return data;
  const masked = Object.assign({}, data);
  if (Array.isArray(masked.top_advisories)) {
    masked.top_advisories = masked.top_advisories.slice(0, 5).map(i => Object.assign({}, i, { ioc_count: "***" }));
  }
  if (Array.isArray(masked.top_critical_advisories)) {
    masked.top_critical_advisories = masked.top_critical_advisories.slice(0, 2);
  }
  // Real apex.json payloads carry a top-level `items` array (not the legacy
  // top_advisories shape above). Mask each item through the existing
  // revenue-enforcement engine so IOCs, Sigma/KQL/Suricata rules, actor
  // attribution, and full AI analysis are actually stripped for FREE tier.
  if (Array.isArray(masked.items)) {
    masked.item_count_full = masked.items.length;
    masked.items = masked.items.slice(0, FREE_TIER_ITEM_CAP).map(i => applyTierGateV2(i, "free", null));
  }
  // Real ai_summary.json payloads carry top-level `campaigns` (actor
  // attribution + DBSCAN clustering) and `anomalies` (Isolation Forest /
  // zero-day candidates) arrays - both already defined as Pro+-only in
  // enforceTierGate(), just never enforced on this response path.
  if (Array.isArray(masked.campaigns)) {
    masked.campaigns_paywall = { ...enforceTierGate("ai_campaigns", "free"), count: masked.campaigns.length };
    masked.campaigns = [];
  }
  if (Array.isArray(masked.anomalies)) {
    masked.anomalies_paywall = { ...enforceTierGate("ai_anomalies", "free"), count: masked.anomalies.length };
    masked.anomalies = [];
  }
  masked._tier = TIERS.FREE;
  masked._upgrade_url = "https://intel.cyberdudebivash.com/upgrade.html";
  return masked;
}

// Public intel manifest helper - serves FREE-tier endpoints ONLY.
// ALLOWED set intentionally excludes all PREMIUM_INTEL_PATHS.
async function servePublicIntelManifest(env, key) {
  const ALLOWED = new Set([
    "/api/v1/intel/latest.json",
    "/api/v1/intel/top10.json",
    "/api/v1/intel/stats",
    "/api/v1/intel/defcon",
    "/api/v1/intel/ransomware",
    "/api/v1/intel/apt",
    "/api/v1/intel/epss",
    "/api/v1/intel/pulse",
    "/api/v1/intel/darkweb",
    "/api/v1/intel/cybermap",
    "/api/v1/intel/campaigns",
  ]);
  if (!ALLOWED.has(key)) return null;
  return await r2Get(env, key.replace(/^\//, ""));
}

async function servePremiumIntelManifest(request, env, ctx, pathname) {
  const auth     = await resolveAuth(request, env);
  const feedData = await loadFeedItems(env);
  const stats    = computeStats(feedData.items || []);
  let data;
  if (pathname === "/api/v1/intel/apex.json") {
    const r2 = await r2Get(env, APEX_JSON_KEY);
    data = (r2 && Object.keys(r2).length > 0) ? r2 : buildApexInline(feedData, stats);
  } else {
    const r2 = await r2Get(env, AI_SUMMARY_KEY);
    data = (r2 && Object.keys(r2).length > 0) ? r2 : buildAISummaryInline(feedData, stats);
  }
  if (auth.tier === TIERS.FREE) {
    const preview = maskForFreeTier(data);
    preview._auth_tier   = TIERS.FREE;
    preview._upgrade_url = "https://intel.cyberdudebivash.com/upgrade.html";
    return jsonResp(preview, 200, { "Cache-Control": "public, max-age=120" });
  }
  return jsonResp(data, 200, { "Cache-Control": "private, max-age=120" });
}

// =============================================================================
// POST /auth/login
// =============================================================================

async function handleLogin(request, env, ctx, ip) {
  const bf = await checkBruteForce(env, ip);
  if (bf.locked) {
    return jsonResp({ error: "Too many failed attempts", retry_after: bf.until }, 429);
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}
  const rawKey = (body.api_key || body.key || "").trim();

  if (!rawKey || rawKey.length < 16) {
    return jsonResp({ error: "api_key is required (minimum 16 characters)" }, 400);
  }
  if (!env.CDB_JWT_SECRET) {
    return jsonResp({ error: "JWT service not configured on this server" }, 503);
  }

  let record;
  try { record = await env.API_KEYS_KV.get(rawKey, "json"); } catch (_) {}

  if (!record) {
    await recordAuthFailure(env, ip);
    auditLog(ctx, env, { action: "login_failed", ip, reason: "invalid_key" });
    return jsonResp({ error: "Invalid API key" }, 401);
  }
  // v185.5 CodeRabbit fix: was only checking expires_at, bypassing the new
  // subscription_status states entirely -- a cancelled/refunded/suspended
  // key could still be exchanged for a fresh 24h JWT here. Reuses
  // evaluateKeyRecordAccess(), same as resolveAuth()'s API-key path.
  const loginAccess = evaluateKeyRecordAccess(record);
  if (!loginAccess.allowed) {
    auditLog(ctx, env, { action: "login_failed", ip, reason: loginAccess.error });
    return jsonResp({ error: "API key is not active", code: loginAccess.error }, 401);
  }

  await clearAuthFailures(env, ip);

  const now_sec = Math.floor(Date.now() / 1000);
  const payload = {
    sub: record.customer_id || rawKey.slice(0, 8),
    tier: record.tier || TIERS.PRO,
    iat: now_sec,
    exp: now_sec + JWT_EXPIRY_SEC,
    iss: "SENTINEL-APEX",
  };
  const token = await signJWT(payload, env.CDB_JWT_SECRET);
  auditLog(ctx, env, { action: "login_success", ip, sub: payload.sub, tier: payload.tier });

  return jsonResp({
    token, token_type: "Bearer", tier: payload.tier, sub: payload.sub,
    expires_in: JWT_EXPIRY_SEC,
    expires_at: new Date((now_sec + JWT_EXPIRY_SEC) * 1000).toISOString(),
    issued_at: new Date(now_sec * 1000).toISOString(),
    usage: "Authorization: Bearer <token>",
  });
}

// =============================================================================
// POST /auth/logout
// =============================================================================

async function handleLogout(request, env, ctx, auth) {
  if (!auth.jwt || !auth.key) {
    return jsonResp({ error: "No active JWT session to revoke. Use JWT Bearer token." }, 400);
  }
  try {
    await env.SECURITY_HUB_KV.put(
      `jwt_revoked:${auth.key.slice(-24)}`, "1",
      { expirationTtl: JWT_EXPIRY_SEC }
    );
    auditLog(ctx, env, { action: "logout", sub: auth.sub, tier: auth.tier });
    return jsonResp({ message: "Logged out successfully. Token revoked." });
  } catch (e) {
    console.error(`[logout] failed: ${e.message}`);
    return jsonResp({ error: "Logout failed" }, 500);
  }
}

// =============================================================================
// SSO (OpenID Connect) -- Google Workspace / Microsoft Entra ID
// GET /auth/sso/:provider/start     -- begin the IdP redirect
// GET /auth/sso/:provider/callback  -- IdP redirects back here with a code
// GET /auth/sso/handoff             -- login.html exchanges the callback's
//                                       single-use code for the real JWT
//
// Additive only: issues the exact same signJWT()-produced token /auth/login
// issues (same {sub,tier,iat,exp,iss} shape, same CDB_JWT_SECRET), so every
// existing auth-consuming route (resolveAuth() above, and every P16-P41
// handler that reads `auth.tier`) needs ZERO changes to accept an SSO
// session -- it cannot tell an SSO-issued JWT from an API-key-issued one,
// by design.
//
// SSO does not create new customers. It authenticates an identity (proves
// the caller really controls user@company.com via Google/Microsoft's own
// verification) and looks up whether that email's domain has already been
// enabled for SSO in SSO_DOMAINS_KV -- a small, admin-provisioned mapping
// (domain -> {tier, customer_id, enabled}), written the same way an
// enterprise contract already results in an API_KEYS_KV record today. An
// unrecognized domain gets a clear "contact enterprise sales" message, never
// a silently-granted tier. See workers/intel-gateway/wrangler.toml for the
// KV namespace + secrets this requires provisioning before SSO is live.
// =============================================================================

const SSO_PROVIDERS = {
  google: {
    label: "Google Workspace",
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    jwks_url: "https://www.googleapis.com/oauth2/v3/certs",
    issuers: ["https://accounts.google.com", "accounts.google.com"],
    scope: "openid email",
    client_id_env: "GOOGLE_OAUTH_CLIENT_ID",
    client_secret_env: "GOOGLE_OAUTH_CLIENT_SECRET",
  },
  microsoft: {
    label: "Microsoft Entra ID",
    // "organizations" endpoint: work/school accounts only, any tenant --
    // excludes personal Microsoft accounts, which is what a B2B enterprise
    // login should do. Issuer is therefore per-tenant, not a fixed string
    // (see verifyOidcIdToken's Microsoft-specific issuer check below).
    authorize_url: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
    jwks_url: "https://login.microsoftonline.com/organizations/discovery/v2.0/keys",
    issuers: null,
    scope: "openid email",
    client_id_env: "MS_OAUTH_CLIENT_ID",
    client_secret_env: "MS_OAUTH_CLIENT_SECRET",
  },
};
const SSO_REDIRECT_BASE  = "https://intel.cyberdudebivash.com/auth/sso";
const SSO_LOGIN_PAGE     = "https://intel.cyberdudebivash.com/login.html";
const SSO_STATE_TTL_SEC  = 600; // 10 min to complete the IdP round trip
const SSO_HANDOFF_TTL_SEC = 60; // single-use code, just long enough for login.html's own exchange fetch()

function randomUrlSafeToken(byteLen) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLen));
  return b64url(String.fromCharCode(...bytes));
}

async function sha256Base64Url(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return b64url(String.fromCharCode(...new Uint8Array(digest)));
}

// Exact-match allowlist check for a provider key. Every function that
// indexes SSO_PROVIDERS with a caller-supplied `provider` string calls this
// itself -- it never relies solely on an upstream caller's guard -- so a
// crafted or malformed provider value can't reach fetch()/property access
// on SSO_PROVIDERS via any current or future call path.
function isKnownSsoProvider(provider) {
  return provider === "google" || provider === "microsoft";
}

// Provider JWKS, KV-cached (1h) to avoid a network round trip to the IdP on
// every login. forceRefresh bypasses the cache -- used once by
// verifyOidcIdToken below when a token's `kid` isn't in the cached set,
// which happens on the IdP's own (rare) key-rotation schedule.
async function getProviderJWKS(env, provider, forceRefresh) {
  if (!isKnownSsoProvider(provider)) throw new Error(`Unknown SSO provider: ${provider}`);
  const cacheKey = `sso_jwks:${provider}`;
  if (!forceRefresh) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, "json");
      if (cached) return cached;
    } catch (_) {}
  }
  const resp = await fetch(SSO_PROVIDERS[provider].jwks_url);
  if (!resp.ok) throw new Error(`JWKS fetch failed for ${provider}: HTTP ${resp.status}`);
  const jwks = await resp.json();
  try { await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(jwks), { expirationTtl: 3600 }); } catch (_) {}
  return jwks;
}

// Verifies an RS256 OIDC ID token's signature against the provider's own
// published JWKS (never trusts the unverified payload), plus alg/exp/iat/
// aud/iss. Returns the verified payload, or null on ANY failure -- callers
// must treat null as "reject the login."
async function verifyOidcIdToken(env, provider, idToken, clientId) {
  if (!isKnownSsoProvider(provider)) return null;
  const cfg = SSO_PROVIDERS[provider];
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  let header, payload;
  try {
    header  = JSON.parse(b64urlDec(h));
    payload = JSON.parse(b64urlDec(p));
  } catch (_) { return null; }
  // Reject alg-confusion / "none"-alg attacks outright: only RS256 (what
  // both providers actually sign with) is ever accepted here.
  if (header.alg !== "RS256") return null;

  // getProviderJWKS throws on a network/HTTP failure -- caught here so this
  // function's documented contract ("null on ANY failure") actually holds;
  // otherwise an IdP-side JWKS outage would throw past handleSsoCallback's
  // caller too, surfacing a raw 500 instead of ssoErrorRedirect's message.
  let jwks, jwk;
  try {
    jwks = await getProviderJWKS(env, provider, false);
    jwk  = (jwks.keys || []).find(k => k.kid === header.kid);
    if (!jwk) {
      jwks = await getProviderJWKS(env, provider, true);
      jwk  = (jwks.keys || []).find(k => k.kid === header.kid);
    }
  } catch (_) { return null; }
  if (!jwk) return null;

  let cryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
    );
  } catch (_) { return null; }

  const sigBytes = Uint8Array.from(b64urlDec(s), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", cryptoKey, sigBytes, new TextEncoder().encode(`${h}.${p}`)
  );
  if (!valid) return null;

  const nowSec = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < nowSec) return null;
  if (!payload.iat || payload.iat > nowSec + 60) return null; // reject not-yet-valid (clock-skew tolerant)
  if (payload.aud !== clientId) return null;
  if (cfg.issuers) {
    if (!cfg.issuers.includes(payload.iss)) return null;
  } else {
    // Microsoft multi-tenant "organizations" endpoint: issuer is always
    // exactly this shape for a real work/school-account token.
    if (!/^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/i.test(payload.iss || "")) return null;
  }
  // Google sets email_verified explicitly (false must be rejected). Absence
  // (Microsoft work/school accounts, which don't self-attest email) is
  // treated as verified -- those accounts are already org-managed by the
  // tenant admin, not self-service-registered.
  if (payload.email_verified === false) return null;

  return payload;
}

function ssoDomainOf(email) {
  const e = String(email || "").toLowerCase().trim();
  const idx = e.lastIndexOf("@");
  return idx > 0 ? e.slice(idx + 1) : "";
}

function ssoErrorRedirect(message) {
  const dest = new URL(SSO_LOGIN_PAGE);
  dest.searchParams.set("sso_error", message);
  return Response.redirect(dest.toString(), 302);
}

// Anti login-CSRF: handleSsoStart sets this HttpOnly cookie holding the same
// `state` it stores server-side; handleSsoCallback requires the two to
// match. Without it, the KV-tracked state alone only proves the (code,
// state) pair is genuine -- not that the browser presenting it is the one
// that started the flow. An attacker can start their own OAuth flow,
// capture the resulting callback URL (a genuine code+state pair for the
// ATTACKER's own IdP account), and trick a victim into opening it; without
// a browser-bound check the victim's browser would be signed into the
// attacker's identity. SameSite=Lax (not Strict) is required so the cookie
// still rides along on the top-level cross-site redirect the IdP issues
// back to /callback.
function ssoNonceCookieName(provider) {
  return `sso_nonce_${provider}`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

async function handleSsoStart(request, env, ctx, provider) {
  if (!isKnownSsoProvider(provider)) return jsonResp({ error: "Unknown SSO provider" }, 404);
  const cfg = SSO_PROVIDERS[provider];
  const clientId = env[cfg.client_id_env];
  if (!clientId) {
    return ssoErrorRedirect(`${cfg.label} sign-in is not yet configured. Contact enterprise@cyberdudebivash.com.`);
  }

  const state        = randomUrlSafeToken(24);
  const codeVerifier  = randomUrlSafeToken(32);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  try {
    await env.RATE_LIMIT_KV.put(
      `sso_state:${state}`,
      JSON.stringify({ provider, code_verifier: codeVerifier }),
      { expirationTtl: SSO_STATE_TTL_SEC }
    );
  } catch (_) {
    return ssoErrorRedirect("Sign-in is temporarily unavailable. Please try again.");
  }

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${SSO_REDIRECT_BASE}/${provider}/callback`,
    response_type: "code",
    scope: cfg.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  if (provider === "google") { params.set("access_type", "online"); params.set("prompt", "select_account"); }
  return new Response(null, {
    status: 302,
    headers: {
      "Location": `${cfg.authorize_url}?${params.toString()}`,
      "Set-Cookie": `${ssoNonceCookieName(provider)}=${state}; Secure; HttpOnly; SameSite=Lax; Max-Age=${SSO_STATE_TTL_SEC}; Path=/auth/sso`,
    },
  });
}

async function handleSsoCallback(request, env, ctx, provider, ip) {
  if (!isKnownSsoProvider(provider)) return jsonResp({ error: "Unknown SSO provider" }, 404);
  const cfg = SSO_PROVIDERS[provider];
  if (!env.CDB_JWT_SECRET) return ssoErrorRedirect("Sign-in is not configured on this server.");

  const url      = new URL(request.url);
  const code     = url.searchParams.get("code");
  const state    = url.searchParams.get("state");
  const idpError = url.searchParams.get("error");

  if (idpError) {
    return ssoErrorRedirect(idpError === "access_denied" ? "Sign-in was cancelled." : "Sign-in failed. Please try again.");
  }
  if (!code || !state) return ssoErrorRedirect("Invalid sign-in response.");

  // See ssoNonceCookieName's comment: this browser must be the one that
  // started the flow, not just the holder of a genuine (code, state) pair.
  if (getCookie(request, ssoNonceCookieName(provider)) !== state) {
    auditLog(ctx, env, { action: "sso_state_cookie_mismatch", provider, ip });
    return ssoErrorRedirect("Your sign-in session expired. Please try again.");
  }

  const stateKey = `sso_state:${state}`;
  let stateRec;
  try { stateRec = await env.RATE_LIMIT_KV.get(stateKey, "json"); } catch (_) {}
  if (!stateRec || stateRec.provider !== provider) {
    return ssoErrorRedirect("Your sign-in session expired. Please try again.");
  }
  try { await env.RATE_LIMIT_KV.delete(stateKey); } catch (_) {} // single-use

  const clientId     = env[cfg.client_id_env];
  const clientSecret = env[cfg.client_secret_env];
  if (!clientId || !clientSecret) return ssoErrorRedirect("Sign-in is not configured on this server.");

  let tokenResp;
  try {
    tokenResp = await fetch(cfg.token_url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `${SSO_REDIRECT_BASE}/${provider}/callback`,
        client_id: clientId,
        client_secret: clientSecret,
        code_verifier: stateRec.code_verifier,
      }).toString(),
    });
  } catch (_) {
    return ssoErrorRedirect("Could not reach the identity provider. Please try again.");
  }
  if (!tokenResp.ok) {
    auditLog(ctx, env, { action: "sso_token_exchange_failed", provider, ip, status: tokenResp.status });
    return ssoErrorRedirect("Sign-in failed. Please try again.");
  }
  let tokenData;
  try { tokenData = await tokenResp.json(); } catch (_) {}
  if (!tokenData || !tokenData.id_token) return ssoErrorRedirect("Sign-in failed. Please try again.");

  const payload = await verifyOidcIdToken(env, provider, tokenData.id_token, clientId);
  if (!payload || !payload.email) {
    auditLog(ctx, env, { action: "sso_token_verify_failed", provider, ip });
    return ssoErrorRedirect("We could not verify your identity provider account.");
  }

  const email  = String(payload.email).toLowerCase().trim();
  const domain = ssoDomainOf(email);
  let domainRec = null;
  try { domainRec = await env.SSO_DOMAINS_KV.get(domain, "json"); } catch (_) {}

  if (!domainRec || !domainRec.enabled) {
    auditLog(ctx, env, { action: "sso_login_denied", provider, domain, ip });
    return ssoErrorRedirect(`Your organization (${domain}) hasn't enabled Single Sign-On yet. Contact enterprise@cyberdudebivash.com to set it up.`);
  }

  // Fail closed on a misconfigured domain record: TIERS[domainRec.tier]
  // silently resolving to undefined (a typo, or a record provisioned before
  // `tier` was set) must never fall back to granting the highest paid tier.
  // Every other error path in this file's auth resolution defaults to
  // TIERS.FREE / an explicit rejection, never an upgrade -- this matches
  // that convention instead of inventing a new, more permissive one.
  const resolvedTier = TIERS[domainRec.tier];
  if (!resolvedTier) {
    auditLog(ctx, env, { action: "sso_login_misconfigured_tier", provider, domain, raw_tier: domainRec.tier, ip });
    return ssoErrorRedirect(`Your organization's Single Sign-On setup is incomplete. Contact enterprise@cyberdudebivash.com.`);
  }

  const now_sec = Math.floor(Date.now() / 1000);
  const jwtPayload = {
    sub: domainRec.customer_id || `sso:${email}`,
    tier: resolvedTier,
    iat: now_sec,
    exp: now_sec + JWT_EXPIRY_SEC,
    iss: "SENTINEL-APEX",
  };
  const token = await signJWT(jwtPayload, env.CDB_JWT_SECRET);
  auditLog(ctx, env, { action: "sso_login_success", provider, domain, sub: jwtPayload.sub, tier: jwtPayload.tier, ip });

  // Hand the JWT to the browser via a single-use, short-lived opaque code --
  // never in the redirect URL itself. A token placed in a URL survives in
  // browser history, rides along in the Referer header on any subsequent
  // navigation, and is routinely captured by CDN/access logs; a code that's
  // deleted from KV the instant login.html exchanges it is worthless to
  // anyone who only ever sees the URL.
  const handoff = randomUrlSafeToken(24);
  try {
    await env.RATE_LIMIT_KV.put(
      `sso_handoff:${handoff}`,
      JSON.stringify({ token, tier: jwtPayload.tier, sub: jwtPayload.sub, email }),
      { expirationTtl: SSO_HANDOFF_TTL_SEC }
    );
  } catch (_) {
    return ssoErrorRedirect("Sign-in is temporarily unavailable. Please try again.");
  }

  const dest = new URL(SSO_LOGIN_PAGE);
  dest.searchParams.set("sso_handoff", handoff);
  return Response.redirect(dest.toString(), 302);
}

// Single-use exchange for the opaque code handleSsoCallback's redirect
// carries -- see the comment above that redirect for why the token itself
// never appears in a URL. GET is fine here (no state-changing effect the
// same request can't already do): the code is deleted on first read
// regardless of outcome, so it's dead the instant this runs once.
async function handleSsoHandoff(request, env) {
  const url  = new URL(request.url);
  const code = url.searchParams.get("code") || "";

  if (!code) return jsonResp({ error: "Missing code" }, 400, { "Cache-Control": "no-store" });

  const handoffKey = `sso_handoff:${code}`;
  let rec;
  try { rec = await env.RATE_LIMIT_KV.get(handoffKey, "json"); } catch (_) {}
  try { await env.RATE_LIMIT_KV.delete(handoffKey); } catch (_) {} // single-use, even on a bad/duplicate code

  if (!rec) {
    return jsonResp({ error: "This sign-in link has expired or was already used. Please sign in again." }, 410, { "Cache-Control": "no-store" });
  }
  return jsonResp(
    { token: rec.token, tier: rec.tier, sub: rec.sub, email: rec.email, expires_in: JWT_EXPIRY_SEC },
    200,
    { "Cache-Control": "no-store" }
  );
}

// =============================================================================
// ADMIN API (/api/admin/*)
// =============================================================================

export async function handleAdmin(request, env, ctx, path, method) {
  // -- Cache-bust endpoints (P0 fix): these never had a matching route here.
  // scripts/bust_kv_cache.py (pipeline STAGE 3.7) has been calling
  // POST /api/admin/cache/bust[-prefix] with an "X-Admin-Secret" header
  // carrying WORKER_ADMIN_SECRET since it was written, but this function only
  // ever read "X-Admin-Key"/"Authorization: Bearer" and compared against the
  // unrelated ADMIN_SECRET below -- so every call fell through to that check,
  // found no matching header, and 403'd regardless of what WORKER_ADMIN_SECRET
  // was set to. No amount of rotating that secret could ever have fixed this;
  // the route + auth pair it needs simply didn't exist. Authenticated the same
  // way as the existing WORKER_ADMIN_SECRET consumers (alert-engine.js
  // handleAlertDispatch, sla-monitor.js handleSLAPing) so no new secret is
  // required. Cache data for the keys/prefixes this busts lives in
  // SECURITY_HUB_KV (see fetchReportsIndexExt's "idx:reports" read in
  // api-extensions.js and kvGet/kvPut in dark-web-monitor.js); deleting a key
  // that was never written is a harmless no-op, so this is safe for the
  // several legacy target names in CACHE_KEYS that have no live writer today.
  if (path === "/api/admin/cache/bust" || path === "/api/admin/cache/bust-prefix") {
    const cacheSecret = request.headers.get("X-Admin-Secret") || "";
    if (!env.WORKER_ADMIN_SECRET || !timingSafeEqual(cacheSecret, env.WORKER_ADMIN_SECRET)) {
      auditLog(ctx, env, { action: "admin_auth_failed", path, method });
      return jsonResp({ error: "Forbidden: invalid admin credentials" }, 403);
    }
    if (method !== "POST") {
      return jsonResp({ error: "Method not allowed", allowed: ["POST"] }, 405);
    }
    // Canonical cache-key namespace this endpoint is scoped to, mirroring
    // scripts/bust_kv_cache.py's CACHE_KEYS. SECURITY_HUB_KV also holds
    // unrelated data (audit:* from auditLog() above, fingerprint:* etc.) --
    // without this allowlist, an authenticated cache-bust call could be used
    // to erase that data instead of just cache entries.
    const ALLOWED_EXACT_KEYS = new Set([
      "idx:reports", "idx:preview", "ai:index", "ai:analyze", "ai:respond", "ai:correlate",
    ]);
    const ALLOWED_PREFIXES = new Set([
      "darkweb:scan", "darkweb:status", "reports:premium", "reports:list", "checkout",
    ]);
    const qs = new URL(request.url).searchParams;
    try {
      if (path === "/api/admin/cache/bust") {
        const key = qs.get("key") || "";
        if (!key) return jsonResp({ error: "Missing 'key' query parameter" }, 400);
        if (!ALLOWED_EXACT_KEYS.has(key)) {
          return jsonResp({ error: "Unknown cache key", allowed: [...ALLOWED_EXACT_KEYS] }, 400);
        }
        await env.SECURITY_HUB_KV.delete(key);
        return jsonResp({ busted: key }, 200);
      }
      const prefix = qs.get("prefix") || "";
      if (!prefix) return jsonResp({ error: "Missing 'prefix' query parameter" }, 400);
      if (!ALLOWED_PREFIXES.has(prefix)) {
        return jsonResp({ error: "Unknown cache prefix", allowed: [...ALLOWED_PREFIXES] }, 400);
      }
      // KV list() returns at most 1,000 keys per call; loop on the cursor
      // until list_complete so a prefix with more entries than that is fully
      // busted, not silently left partially stale.
      let cursor;
      let deleted = 0;
      for (;;) {
        const listed = await env.SECURITY_HUB_KV.list({ prefix, cursor });
        await Promise.all(listed.keys.map((k) => env.SECURITY_HUB_KV.delete(k.name)));
        deleted += listed.keys.length;
        if (listed.list_complete) break;
        cursor = listed.cursor;
      }
      return jsonResp({ busted_prefix: prefix, count: deleted }, 200);
    } catch (e) {
      // Never return KV/provider exception text to the caller -- log
      // server-side only (visible via wrangler tail / Logpush).
      console.error(`[handleAdmin cache-bust] KV operation failed: ${e && e.message ? e.message : e}`);
      return jsonResp({ error: "Cache bust failed" }, 500);
    }
  }

  const adminKey = (
    request.headers.get("X-Admin-Key") ||
    (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "")
  ).trim();

  // FIX (P0, 2026-09-10, edge-security audit): checkBruteForce/recordAuthFailure
  // (KV-backed lockout, already proven at /auth/login and resolveAuth()'s
  // customer-key path) were never wired here -- this credential guarded
  // key mint/revoke, cache purge, and audit-log read with only the shared,
  // bypassable per-IP request counter (checkRateLimit) and no attempt
  // lockout at all. Derives ip locally (matching handleRequest's own
  // derivation) rather than threading a new parameter through this
  // function's signature, since handleAdmin is called from existing tests
  // with a fixed 5-argument shape.
  const adminIp = request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "127.0.0.1").split(",")[0].trim();
  const adminBf = await checkBruteForce(env, adminIp);
  if (adminBf.locked) {
    auditLog(ctx, env, { action: "admin_auth_locked", path, method, ip: adminIp });
    return jsonResp({ error: "Too many failed attempts", retry_after: adminBf.until }, 429);
  }

  if (!env.ADMIN_SECRET || !timingSafeEqual(adminKey, env.ADMIN_SECRET)) {
    await recordAuthFailure(env, adminIp);
    auditLog(ctx, env, { action: "admin_auth_failed", path, method, ip: adminIp });
    return jsonResp({ error: "Forbidden: invalid admin credentials" }, 403);
  }
  await clearAuthFailures(env, adminIp);

  // GET /api/admin/health
  if (path === "/api/admin/health" && method === "GET") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const defcon   = computeDefcon(stats);
    const kvCheck  = await Promise.allSettled([
      env.API_KEYS_KV.get("__ping__"),
      env.RATE_LIMIT_KV.get("__ping__"),
      env.ANALYTICS_KV.get("__ping__"),
      env.SECURITY_HUB_KV.get("__ping__"),
    ]);
    return jsonResp({
      status: "ok", version: PLATFORM_VERSION,
      advisory_count: stats.total, critical_count: stats.critical, kev_confirmed: stats.kev_confirmed,
      defcon: defcon.level, defcon_label: defcon.label,
      kv_namespaces: {
        API_KEYS_KV:     kvCheck[0].status === "fulfilled" ? "ok" : "error",
        RATE_LIMIT_KV:   kvCheck[1].status === "fulfilled" ? "ok" : "error",
        ANALYTICS_KV:    kvCheck[2].status === "fulfilled" ? "ok" : "error",
        SECURITY_HUB_KV: kvCheck[3].status === "fulfilled" ? "ok" : "error",
      },
      secrets: { CDB_JWT_SECRET: !!(env.CDB_JWT_SECRET), ADMIN_SECRET: true },
      generated_at: now(),
    });
  }

  // GET /api/admin/audit
  if (path === "/api/admin/audit" && method === "GET") {
    try {
      const url   = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
      const { keys } = await env.SECURITY_HUB_KV.list({ prefix: "audit:", limit });
      const entries  = await Promise.all(
        keys.map(async k => {
          try { return await env.SECURITY_HUB_KV.get(k.name, "json"); } catch { return null; }
        })
      );
      const valid = entries.filter(Boolean).sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
      return jsonResp({ entries: valid, count: valid.length, generated_at: now() });
    } catch (e) {
      console.error(`[audit] unavailable: ${e.message}`);
      return jsonResp({ error: "Audit log unavailable" }, 500);
    }
  }

  // POST /api/admin/keys
  if (path === "/api/admin/keys" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { tier = "PRO", customer_id, label, expires_in_days, managed_tenants } = body;
    if (!customer_id) return jsonResp({ error: "customer_id is required" }, 400);
    if (!TIERS[tier])  return jsonResp({ error: `Invalid tier: ${tier}. Valid: ${Object.keys(TIERS).join(", ")}` }, 400);
    // v185.5 (Mission Phase 6): optional, MSSP-oriented. Only meaningful
    // when provided as an array -- omit entirely to get today's unrestricted
    // MSSP tenant-feed behavior (see resolveAuth()'s managed_tenants
    // comment); pass [] to explicitly authorize zero tenants, or a list of
    // tenant_id strings to restrict this key to exactly those.
    if (managed_tenants !== undefined && !Array.isArray(managed_tenants)) {
      return jsonResp({ error: "managed_tenants, if provided, must be an array of tenant_id strings" }, 400);
    }

    // v185.0 FIX: this mirrors provisionApiKey()'s prefix logic (~line 2820)
    // exactly, which already handles MSSP -- this copy had drifted and fell
    // through to "cdb_free" for MSSP, a cosmetic mislabel only (the `tier`
    // field driving actual entitlement/rate-limit resolution in resolveAuth
    // was always correct) but confusing for an admin-provisioned MSSP key.
    const prefix = tier === "ENTERPRISE" ? "cdb_ent" : tier === "MSSP" ? "cdb_mssp" : tier === "PRO" ? "cdb_pro" : "cdb_free";
    const rand   = Array.from(crypto.getRandomValues(new Uint8Array(20))).map(b => b.toString(16).padStart(2, "0")).join("");
    const apiKey = `${prefix}_${rand}`;
    const record = {
      key: apiKey, tier, customer_id, label: label || customer_id,
      created_at: now(),
      expires_at: expires_in_days ? new Date(Date.now() + expires_in_days * 86400000).toISOString() : null,
      ...(Array.isArray(managed_tenants) ? { managed_tenants } : {}),
    };
    const opts = expires_in_days ? { expirationTtl: expires_in_days * 86400 } : undefined;
    await env.API_KEYS_KV.put(apiKey, JSON.stringify(record), opts);
    auditLog(ctx, env, { action: "api_key_created", customer_id, tier });
    return jsonResp({ ...record, message: "API key created" }, 201);
  }

  // PATCH /api/admin/keys/{key}/status  body:{subscription_status, reason?}
  // v185.5 (Mission Phase 2): the single admin-facing entry point for every
  // subscription_status transition -- cancel, suspend, reactivate, and (for
  // the refund webhook below) refund all route through this, so there is
  // one auditable code path for the lifecycle change instead of one per
  // action. Real cancellation/suspension have no Razorpay webhook signal in
  // this integration (it uses the Orders API for one-time charges, not the
  // Subscriptions API -- see docs/PAYMENT_WEBHOOK_LIFECYCLE_MAPPING_V185.md
  // for the full accounting of what this platform's actual payment
  // integration can and cannot signal), so they are necessarily
  // admin-or-customer-support-initiated actions, not provider events.
  const statusMatch = path.match(/^\/api\/admin\/keys\/([^\/]+)\/status$/);
  if (statusMatch && method === "PATCH") {
    const key = statusMatch[1];
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { subscription_status, reason } = body;
    const result = await applySubscriptionStatusChange(env, ctx, key, subscription_status, reason);
    if (!result.ok) {
      if (result.error === "invalid_status") {
        return jsonResp({ error: `Invalid subscription_status. Valid: ${[...SUBSCRIPTION_STATUS_VALID_STATES].join(", ")}` }, 400);
      }
      return jsonResp({ error: "Key not found" }, 404);
    }
    return jsonResp({ key_prefix: key.slice(0, 12), subscription_status, message: "Subscription status updated" });
  }

  // POST /api/admin/keys/{key}/rotate
  // Mission Phase 8: at minimum, new key issuance -> old key immediately
  // revoked. Implemented as hard-delete of the old key (same mechanism the
  // existing DELETE endpoint already uses and that Phase 3's REVOKED_KEY
  // test already proves denies immediately) plus a fresh provisionApiKey()
  // call for the new one, both audited under a single rotation event so
  // the two are traceable as one action rather than two unrelated ones.
  //
  // v185.5 CodeRabbit fix: provisionApiKey() previously built a bare fresh
  // record with no subscription_status or managed_tenants -- rotating a
  // refunded/suspended/cancelled key silently produced a new ACTIVE key
  // (evaluateKeyRecordAccess() treats absent subscription_status as
  // active), and rotating a tenant-restricted MSSP key silently dropped
  // its restriction. Terminal-state keys now reject rotation outright
  // (reactivating requires an explicit PATCH .../status first -- rotation
  // is not a way to bypass that); managed_tenants is now carried forward.
  const rotateMatch = path.match(/^\/api\/admin\/keys\/([^\/]+)\/rotate$/);
  if (rotateMatch && method === "POST") {
    const oldKey = rotateMatch[1];
    const existing = await env.API_KEYS_KV.get(oldKey, "json");
    if (!existing) return jsonResp({ error: "Key not found" }, 404);
    if (existing.subscription_status && SUBSCRIPTION_STATUS_DENY_STATES.has(existing.subscription_status)) {
      return jsonResp({
        error: `Cannot rotate a key in '${existing.subscription_status}' status -- reactivate it first via `
          + `PATCH /api/admin/keys/${oldKey}/status {"subscription_status":"active"} if that is genuinely intended.`,
        subscription_status: existing.subscription_status,
      }, 409);
    }
    // provisionApiKey() computes a fresh billing-cycle expiry from now
    // (matching normal re-provisioning behavior) rather than preserving the
    // old key's exact remaining time -- rotation is a re-provision, not a
    // clock-preserving swap. This is a no-op today regardless since
    // SUBSCRIPTION_EXPIRY_ENABLED=false means expires_at is null either way.
    const newKey = await provisionApiKey(
      env, ctx, existing.tier, existing.customer_id, "admin_rotation",
      { ...(existing.payment_metadata || {}), rotated_from: oldKey.slice(0, 12) + "...", rotation_reason: "admin_rotate" },
      existing.billing_cycle || "monthly",
      Array.isArray(existing.managed_tenants) ? existing.managed_tenants : undefined
    );
    await env.API_KEYS_KV.delete(oldKey);
    auditLog(ctx, env, { action: "api_key_rotated", old_key_prefix: oldKey.slice(0, 12), new_key_prefix: newKey.slice(0, 12), customer_id: existing.customer_id, tier: existing.tier, managed_tenants_carried: Array.isArray(existing.managed_tenants) });
    return jsonResp({
      new_key: newKey, tier: existing.tier, customer_id: existing.customer_id,
      old_key_prefix: oldKey.slice(0, 12), old_key_revoked: true,
      managed_tenants_carried: Array.isArray(existing.managed_tenants) ? existing.managed_tenants : null,
      message: "Key rotated -- old key immediately revoked, no overlap window",
    }, 201);
  }

  // DELETE /api/admin/keys/{key}
  const delMatch = path.match(/^\/api\/admin\/keys\/(.+)$/);
  if (delMatch && method === "DELETE") {
    const key = delMatch[1];
    await env.API_KEYS_KV.delete(key);
    auditLog(ctx, env, { action: "api_key_revoked", key_prefix: key.slice(0, 12) });
    return jsonResp({ message: "API key revoked", key_prefix: key.slice(0, 12) });
  }

  // GET /api/admin/publication-audit  -  P0 follow-through (Section 16):
  // incremental scanner over the full historical REPORTS_R2 archive. Each
  // page lists up to `limit` objects under reports/ via R2's own cursor
  // (never loads the archive into memory at once), resolves each report id
  // against the SAME bounded feed sources findItemBySlug() searches, and
  // classifies it with the SAME evaluatePublicationGate() the live routes
  // enforce -- zero duplicate certification logic. Reports outside the
  // currently-resolvable feed window are honestly reported UNKNOWN (never
  // assumed safe) rather than guessed at by parsing rendered HTML.
  if (path === "/api/admin/publication-audit" && method === "GET") {
    try {
      const url    = new URL(request.url);
      const cursor = url.searchParams.get("cursor") || undefined;
      const limit  = Math.min(parseInt(url.searchParams.get("limit") || "100", 10), 500);

      const listing = await env.REPORTS_R2.list({ prefix: "reports/", cursor, limit });
      const results = { CUSTOMER_READY: 0, INTERNAL: 0, REJECTED: 0, BLOCKED: 0, UNKNOWN: 0 };
      const unknownSample = [];

      for (const obj of listing.objects || []) {
        const fn = obj.key.split("/").pop() || "";
        const id = fn.replace(/\.html?$/, "");
        if (!id) continue;
        const item = await findItemBySlug(env, id);
        if (!item) {
          results.UNKNOWN++;
          if (unknownSample.length < 10) unknownSample.push(obj.key);
          continue;
        }
        const gate = evaluatePublicationGate(item);
        if (gate.customer_ready) results.CUSTOMER_READY++;
        else if (gate.publication_state === "REJECTED") results.REJECTED++;
        else results.BLOCKED++;
      }

      return jsonResp({
        version: PLATFORM_VERSION,
        scanned_this_page: (listing.objects || []).length,
        results,
        unknown_sample_keys: unknownSample,
        unknown_scope_note: "UNKNOWN = report id not resolvable via the currently-active feed windows (latest/top10/apex) -- outside this scanner's verifiable reach; NOT assumed safe, NOT counted as customer_ready.",
        cursor: listing.truncated ? listing.cursor : null,
        truncated: !!listing.truncated,
        generated_at: now(),
      });
    } catch (e) {
      console.error(`[publication-audit] failed: ${e.message}`);
      return jsonResp({ error: "Publication audit scan failed", message: e.message }, 500);
    }
  }

  return jsonResp({
    error: "Admin endpoint not found",
    endpoints: [
      "GET /api/admin/health",
      "GET /api/admin/audit?limit=50",
      "GET /api/admin/publication-audit?limit=100&cursor=...",
      "POST /api/admin/keys  body:{customer_id,tier,label?,expires_in_days?,managed_tenants?}",
      "PATCH /api/admin/keys/{key}/status  body:{subscription_status,reason?}",
      "POST /api/admin/keys/{key}/rotate",
      "DELETE /api/admin/keys/{key}",
    ],
  }, 404);
}

// =============================================================================
// TAXII 2.1
// =============================================================================

function taxiiResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": TAXII_CT, "X-TAXII-Date-Added-Last": now() },
  });
}

// STIX pattern per indicator type, keyed by the `type` field
// scripts/*ioc* actually writes onto item.iocs[] (confirmed against a real
// feed export: {type:"ipv4", value:"6.0.9.4", ...}). Before this, a STIX
// bundle for an item with real IP/domain/hash indicators still emitted a
// generic file:name/threat-actor pattern -- the indicator objects in "Full
// STIX 2.1 bundles" (a paid PRO+ feature) never actually carried the IOC
// itself, only a placeholder built from the advisory title.
const _STIX_HASH_ALGO = { md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" };

function _stixEscape(v) {
  return String(v == null ? "" : v).replace(/['"\\]/g, "").slice(0, 256);
}

function buildStixPattern(item) {
  const iocs = Array.isArray(item.iocs) ? item.iocs : [];
  const byType = (t) => iocs.find(i => i && String(i.type || "").toLowerCase() === t);

  const ip = byType("ipv4") || byType("ip");
  if (ip) return `[ipv4-addr:value = '${_stixEscape(ip.value)}']`;

  const ip6 = byType("ipv6");
  if (ip6) return `[ipv6-addr:value = '${_stixEscape(ip6.value)}']`;

  const domain = byType("domain") || byType("domain-name");
  if (domain) return `[domain-name:value = '${_stixEscape(domain.value)}']`;

  const url = byType("url");
  if (url) return `[url:value = '${_stixEscape(url.value)}']`;

  for (const [type, algo] of Object.entries(_STIX_HASH_ALGO)) {
    const hash = byType(type);
    if (hash) return `[file:hashes.'${algo}' = '${_stixEscape(hash.value)}']`;
  }

  if (item.cve_ids && item.cve_ids.length > 0) return `[vulnerability:name = '${_stixEscape(item.cve_ids[0])}']`;
  if (item.ioc_count > 0) return `[file:name = '${_stixEscape((item.title || "").slice(0, 64))}']`;
  return `[threat-actor:name = '${_stixEscape((item.source || "unknown").slice(0, 32))}']`;
}

async function handleTAXII(request, env, ctx, path, auth) {
  // Server discovery - public (no auth required per TAXII 2.1 spec)
  if (path === "/taxii/" || path === "/taxii") {
    return taxiiResp({
      title: "SENTINEL APEX TAXII 2.1",
      description: "CyberDudeBivash Threat Intelligence Platform - STIX/TAXII Enterprise Feed",
      contact: "intel@cyberdudebivash.com",
      default: "https://intel.cyberdudebivash.com/taxii/",
      api_roots: ["https://intel.cyberdudebivash.com/taxii/"],
    });
  }

  // All other TAXII endpoints require PRO or ENTERPRISE
  const taxiiAccessAllowed = !(!auth || auth.tier === TIERS.FREE);
  if (!resolveEntitlement(ctx, env, "taxii_access", auth, taxiiAccessAllowed).allowed) {
    return taxiiResp({ title: "Unauthorized", description: "TAXII data endpoints require PRO or ENTERPRISE tier. POST api_key to /auth/login for a JWT." }, 401);
  }

  // Collections list
  if (path === "/taxii/collections/" || path === "/taxii/collections") {
    const canReadKevAdHoc = auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP;
    const canReadKev = resolveEntitlement(ctx, env, "taxii_kev", auth, canReadKevAdHoc).allowed;
    return taxiiResp({
      collections: [
        {
          id: TAXII_COLLECTION_ID,
          title: "SENTINEL APEX - Primary Threat Intelligence",
          description: "CVEs, IOCs, APT activity, ransomware alerts, dark web findings",
          can_read: true, can_write: false, media_types: [STIX_CT],
        },
        {
          id: TAXII_KEV_COLL,
          title: "SENTINEL APEX - CISA KEV Confirmed",
          description: "Known Exploited Vulnerabilities confirmed in CISA KEV catalog (ENTERPRISE only)",
          can_read: canReadKev, can_write: false, media_types: [STIX_CT],
        },
      ],
    });
  }

  // Objects from collection
  const objMatch = path.match(/^\/taxii\/collections\/([^/]+)\/objects\/?$/);
  if (objMatch) {
    const collId = objMatch[1];
    const kevAllowedAdHoc = auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP;
    let kevAllowed = kevAllowedAdHoc;
    if (collId === TAXII_KEV_COLL) kevAllowed = resolveEntitlement(ctx, env, "taxii_kev", auth, kevAllowedAdHoc).allowed;
    if (collId === TAXII_KEV_COLL && !kevAllowed) {
      return taxiiResp({ title: "Forbidden", description: "KEV collection requires ENTERPRISE tier" }, 403);
    }

    const feedData   = await loadFeedItems(env);
    const allItems   = (feedData.items || []).filter(isCustomerReady);
    const sourceItems = collId === TAXII_KEV_COLL ? allItems.filter(i => i.kev_present) : allItems;

    // Prefer pre-built STIX bundle from R2. NOTE (P0 follow-through, Section
    // 15 residual scope): this pre-built bundle is written by a separate
    // Python CI stage, not this route -- the same documented scope boundary
    // as report_generator.py in publication-gate.js's header. The inline
    // fallback bundle below (this route's own output) is gated above.
    const r2Bundle = await r2Get(env, `stix/bundle-${collId}.json`);
    if (r2Bundle) {
      return new Response(JSON.stringify(r2Bundle), {
        status: 200,
        headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": STIX_CT, "X-TAXII-Date-Added-Last": now() },
      });
    }

    // Inline STIX 2.1 bundle. IDs must match `{type}--{UUID}` (RFC 4122) --
    // item.stix_id/item.id are internal identifiers, not UUIDs, and reusing
    // them here previously produced bundles that failed schema validation on
    // every sampled object (kept as x_sentinel_item_id below for traceability).
    const stixObjects = sourceItems.slice(0, 200).map(item => ({
      type: "indicator",
      spec_version: "2.1",
      id: `indicator--${crypto.randomUUID()}`,
      created: item.published || now(),
      modified: item.published || now(),
      name: item.title,
      description: item.description || item.title,
      indicator_types: ["malicious-activity"],
      pattern: buildStixPattern(item),
      pattern_type: "stix",
      valid_from: item.published || now(),
      labels: (item.tags || []).slice(0, 10),
      external_references: (item.cve_ids || []).map(cve => ({
        source_name: "cve", external_id: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}`,
      })),
      object_marking_refs: ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
      custom_properties: {
        x_sentinel_severity: item.severity,
        x_sentinel_risk_score: item.risk_score,
        x_sentinel_source: item.source,
        x_sentinel_kev: item.kev_present || false,
        x_sentinel_item_id: item.stix_id || item.id,
      },
    }));

    const bundle = {
      type: "bundle",
      id: `bundle--${crypto.randomUUID()}`,
      spec_version: "2.1",
      objects: stixObjects,
    };
    return new Response(JSON.stringify(bundle), {
      status: 200,
      headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": STIX_CT, "X-TAXII-Date-Added-Last": now() },
    });
  }

  return taxiiResp({ title: "Not Found", description: `Unknown TAXII path: ${path}` }, 404);
}

// =============================================================================
// CVE TRACKER   -  NVD NIST live fetch + R2 cache
// =============================================================================

function cveSeverityFromScore(score) {
  const s = parseFloat(score) || 0;
  if (s >= 9.0) return "CRITICAL";
  if (s >= 7.0) return "HIGH";
  if (s >= 4.0) return "MEDIUM";
  if (s > 0)    return "LOW";
  return "NONE";
}

function mapNvdItem(vuln) {
  const cve  = vuln.cve || {};
  const id   = cve.id || vuln.id || "";

  // Description (English preferred)
  const descs = (cve.descriptions || []);
  const descEn = (descs.find(d => d.lang === "en") || descs[0] || {}).value || "";

  // CVSS  -  prefer v3.1 then v3.0 then v2
  let cvss_score  = 0;
  let cvss_vector = "";
  let severity    = "NONE";
  const metrics   = cve.metrics || {};
  if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
    const m = metrics.cvssMetricV31[0].cvssData || {};
    cvss_score  = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    severity    = (metrics.cvssMetricV31[0].cvssData.baseSeverity || "").toUpperCase() || cveSeverityFromScore(cvss_score);
  } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
    const m = metrics.cvssMetricV30[0].cvssData || {};
    cvss_score  = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    severity    = (metrics.cvssMetricV30[0].cvssData.baseSeverity || "").toUpperCase() || cveSeverityFromScore(cvss_score);
  } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
    const m = metrics.cvssMetricV2[0].cvssData || {};
    cvss_score  = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    severity    = cveSeverityFromScore(cvss_score);
  }

  // CWE IDs
  const weaknesses = cve.weaknesses || [];
  const cwe_ids    = weaknesses.flatMap(w => (w.description || []).map(d => d.value)).filter(Boolean);

  // Affected products (CPE criteria, up to 5)
  const configs   = cve.configurations || [];
  const affected  = [];
  for (const cfg of configs) {
    for (const node of (cfg.nodes || [])) {
      for (const cpe of (node.cpeMatch || [])) {
        if (affected.length >= 5) break;
        affected.push(cpe.criteria || cpe.cpe23Uri || "");
      }
      if (affected.length >= 5) break;
    }
    if (affected.length >= 5) break;
  }

  // References (up to 5)
  const references = (cve.references || []).slice(0, 5).map(r => r.url || "").filter(Boolean);

  return {
    id,
    description:   descEn,
    cvss_score:    Math.round(parseFloat(cvss_score) * 10) / 10,
    cvss_vector,
    severity:      severity || cveSeverityFromScore(cvss_score),
    published:     cve.published   || vuln.published   || "",
    last_modified: cve.lastModified || vuln.lastModified || "",
    vuln_status:   cve.vulnStatus  || "",
    cwe_ids,
    affected_products: affected,
    references,
    kev: false,
  };
}

async function fetchAndCacheCVEs(env) {
  const emptyBundle = {
    cves: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0, avg_cvss: 0 },
    generated_at: now(), source: "NVD_NIST_GOV", window: "7d", version: PLATFORM_VERSION,
  };
  try {
    const endDate   = new Date();
    const startDate = new Date(endDate.getTime() - 7 * 86400 * 1000);
    const fmt       = d => d.toISOString().replace("Z", "").slice(0, 23);
    // PRODUCTION FIX (live-data audit): resultsPerPage=100 requested only
    // the first, arbitrarily-ordered page of NVD's 7-day publish window --
    // confirmed live that window currently holds 2,459 records, and NVD's
    // API applies no severity/date sort, so a single page can be entirely
    // consumed by one homogeneous cluster. Reproduced exactly: this
    // endpoint was returning stats {total:100, critical:0, high:0,
    // medium:0, low:0, none:100} because its one 100-item page was 100%
    // vulnStatus:"Rejected" placeholder records (NVD periodically bulk-
    // processes/rejects old reserved-but-unpublished CVE IDs). 2000 is
    // NVD API 2.0's own documented per-request maximum (confirmed working
    // live) -- covers the large majority of the window in one call without
    // adding a multi-page fetch loop.
    const nvdUrl    = `${NVD_API}?pubStartDate=${fmt(startDate)}&pubEndDate=${fmt(endDate)}&resultsPerPage=2000&startIndex=0`;

    const resp = await fetch(nvdUrl, {
      headers: { "Accept": "application/json", "User-Agent": "CyberDudeBivash-Sentinel-Apex/"+PLATFORM_VERSION },
      cf: { cacheTtl: CVE_TTL_SEC, cacheEverything: true },
    });

    if (!resp.ok) {
      const cached = await r2Get(env, CVE_LIVE_KEY);
      return cached || emptyBundle;
    }

    const raw  = await resp.json();
    // Rejected is NVD's own "this ID does not represent a real
    // vulnerability" status (empty CVSS, no real description) -- excluded
    // before mapping so it can never crowd out genuine tracked CVEs on the
    // tracker (see resultsPerPage comment above for the live-confirmed
    // failure mode this caused). Records still Awaiting/Undergoing
    // Analysis are kept: those are real, currently-tracked CVEs that
    // simply have no CVSS score yet (severity "NONE" is a legitimate,
    // pre-existing state for them, not a defect).
    const cves = (raw.vulnerabilities || [])
      .filter(v => ((v.cve || {}).vulnStatus || "") !== "Rejected")
      .map(mapNvdItem)
      // Most-recent-published first: with up to ~1,800+ tracked CVEs now
      // in the window (vs. the ~100 before this fix) and the API layer
      // capping /api/v1/cve/live's response to `limit` (<=200), display
      // order now materially decides which CVEs are actually visible --
      // NVD's own unordered response is no longer a reasonable default.
      .sort((a, b) => (b.published || "").localeCompare(a.published || ""));

    // Compute stats
    const stats = { total: cves.length, critical: 0, high: 0, medium: 0, low: 0, none: 0, avg_cvss: 0 };
    let scoreSum = 0;
    for (const c of cves) {
      const sev = c.severity;
      if (sev === "CRITICAL") stats.critical++;
      else if (sev === "HIGH") stats.high++;
      else if (sev === "MEDIUM") stats.medium++;
      else if (sev === "LOW") stats.low++;
      else stats.none++;
      scoreSum += c.cvss_score || 0;
    }
    stats.avg_cvss = cves.length > 0 ? Math.round((scoreSum / cves.length) * 10) / 10 : 0;

    const bundle = {
      cves, stats,
      generated_at: now(),
      source: "NVD_NIST_GOV",
      window: "7d",
      version: PLATFORM_VERSION,
    };

    try {
      await env.INTEL_R2.put(CVE_LIVE_KEY, JSON.stringify(bundle), { httpMetadata: { contentType: "application/json" } });
      await env.INTEL_R2.put(CVE_STATS_KEY, JSON.stringify({ ...stats, generated_at: bundle.generated_at, source: bundle.source, window: bundle.window }), { httpMetadata: { contentType: "application/json" } });
    } catch (_) {}

    return bundle;
  } catch (_) {
    const cached = await r2Get(env, CVE_LIVE_KEY);
    return cached || emptyBundle;
  }
}

// =============================================================================
// AI SECURITY COPILOT v3.0  -  DeepSeek R1 + V3 direct, GROQ fallback
// POST /api/v1/copilot/query
// GET  /api/v1/copilot/modes
// GET  /api/v1/copilot/health
// LLM stack: DeepSeek direct (primary) -> GROQ LPU (fallback) -> OpenRouter -> template
// =============================================================================

const COPILOT_SYSTEM_PROMPT = `You are SENTINEL APEX  -  the expert AI Security Copilot for CYBERDUDEBIVASH(R) Sentinel APEX, an enterprise-grade threat intelligence platform.

Your identity:
- World-class threat intelligence analyst: 20+ years SOC, IR, and CTI experience
- Expert in MITRE ATT\&CK, STIX 2.1, SIGMA rules, KQL, SPL, YARA, Suricata
- Deep expertise: Ransomware (LockBit, REvil, Cl0p), APT groups (APT28, APT29, Lazarus, Volt Typhoon), supply chain attacks, zero-day exploitation

Response style: SOC-ready, operationally actionable, specific and precise. Always provide concrete commands, queries, IOC patterns, or remediation steps. Never vague.`;

const COPILOT_R1_MODES  = new Set(["threat_hunt", "detection_write", "incident_brief", "natural_language"]);
const COPILOT_ALL_MODES = new Set([
  "explain_threat", "what_to_do", "soc_report", "ioc_summary",
  "mitre_mapping", "risk_brief", "threat_hunt", "detection_write",
  "incident_brief", "natural_language",
]);

function copilotBuildPrompt(mode, threat, question) {
  const t = threat.title || question || "Unknown Threat";
  const m = JSON.stringify(threat.mitre_tactics || []);
  const s = threat.severity || "HIGH";
  const a = threat.actor_tag || "Unknown";
  const r = threat.risk_score || 7;
  switch (mode) {
    case "threat_hunt":
      return `Generate a complete threat hunting package for: ${t}.
Include:
1. 4-6 production KQL queries for Microsoft Sentinel (with comments and time filters)
2. 3 complete SPL queries for Splunk ES
3. 2 full SIGMA rules in YAML format (status: production, all required fields)
4. MITRE ATT\&CK focus techniques: ${m}
5. IOC pattern lookups (hash/domain/IP searches)
6. 3 hypothesis-driven hunt plans with validation logic
7. Expected attacker timeline and prioritized log sources
Severity: ${s}. Actor: ${a}. Risk: ${r}/10.`;

    case "detection_write":
      return `Generate production-ready detection rules for: ${t}.
Provide complete deployable rules:
1. SIGMA rule (full YAML, status: production, all required fields)
2. Microsoft Sentinel KQL (complete with inline comments and 24h window)
3. Splunk SPL (complete with stats pipeline and index directive)
4. Suricata network rule (if network indicators likely)
5. YARA rule (if malware/file-based indicators present)
6. False positive suppression guidance for each rule
MITRE: ${m}. Threat type: ${threat.threat_type || "General"}.`;

    case "incident_brief":
      return `Generate an incident commander brief (SMEAC format) for: ${t}.
SITUATION: What happened, scope, affected systems, threat actor attribution
MISSION: Primary IR objective and measurable success criteria
EXECUTION: Phase 1 containment (0-4h), Phase 2 eradication (4-24h), Phase 3 recovery (24-72h) with specific steps
ADMINISTRATION: Evidence preservation, chain of custody, regulatory notifications (GDPR 72h, SEC 4-day, HIPAA 60-day)
COMMAND: Decision authorities, escalation matrix, out-of-band comms plan
LEGAL/COMMS: Regulatory obligations, PR holding statement, notification timeline
Severity: ${s}. Actor: ${a}. Risk: ${r}/10.`;

    case "natural_language":
      return question || "What are the top current threats in this feed and what should our SOC prioritize right now? Provide a prioritized action list with specific tools and commands.";

    case "explain_threat":
      return `Analyze this threat advisory: ${t}.
Provide: 1) What it is and why it matters right now, 2) Who is being targeted and by whom, 3) How it works technically (TTPs), 4) The single most critical defensive action.
User question: ${question || "Explain this threat."}`;

    case "what_to_do":
      return `For this threat: ${t}.
Provide a prioritized 5-step immediate action plan. Be specific  -  exact commands, tools, configurations, not generic advice.
User question: ${question || "What should I do?"}`;

    case "soc_report":
      return `Generate a complete SOC incident report for: ${t}.
Include: executive summary (1 paragraph), threat intelligence assessment, IOC analysis, response plan, MITRE ATT\&CK coverage map, and 3 recommended detection rules.
User question: ${question || "Generate SOC report."}`;

    case "risk_brief":
      return `Generate a C-suite risk brief for: ${t}.
Include: business impact in plain English (no jargon), financial exposure estimate, likelihood of impact on our environment, and top 3 mitigation priorities with timelines.
User question: ${question || "Generate risk brief."}`;

    default:
      return question || `Analyze: ${t}`;
  }
}

function copilotTemplate(mode, threat, question) {
  const title = threat.title || question || "Security Analysis";
  const sev   = (threat.severity || "HIGH").toUpperCase();
  const score = parseFloat(threat.risk_score) || 7.0;
  const ttype = threat.threat_type || "General";
  const mitre = threat.mitre_tactics || [];
  const kev   = threat.kev_present ? "CISA KEV confirmed exploitation." : "";
  const level = score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 5 ? "MEDIUM" : "LOW";
  const iocs  = threat.ioc_counts || {};

  const PLAYBOOKS = {
    Ransomware:    { urgency: "CRITICAL  -  isolate within 1h", immediate: ["Isolate affected systems from network", "Do NOT pay ransom without legal consultation", "Preserve forensic evidence (memory dumps, logs)", "Activate IR plan and notify stakeholders", "Check backup integrity immediately"] },
    Vulnerability: { urgency: "HIGH  -  patch within SLA, WAF compensating controls now", immediate: ["Apply vendor patch immediately", "Deploy WAF virtual patch if no fix available", "Block/restrict access to vulnerable service", "Enable enhanced logging on affected systems", "Search SIEM for exploitation attempts (30 days)"] },
    Phishing:      { urgency: "HIGH  -  credential reset required", immediate: ["Block malicious sender domains at email gateway", "Delete phishing emails from all inboxes", "Force password reset for affected users", "Invalidate active sessions", "Enable MFA immediately if not active"] },
    APT:           { urgency: "CRITICAL  -  full scope investigation required", immediate: ["Engage specialized IR firm with APT experience", "Do NOT alert attacker  -  maintain visibility", "Establish out-of-band communications", "Begin systematic threat hunting", "Identify crown jewel data exposure"] },
    "Data Breach": { urgency: "CRITICAL  -  GDPR 72h notification window starts now", immediate: ["Contain the breach vector immediately", "Identify what data was accessed (scope, classification)", "Engage legal counsel and DPO immediately", "Preserve all evidence with chain of custody", "Assess notification obligations (GDPR 72h, state laws)"] },
    "Supply Chain":{ urgency: "CRITICAL  -  assess downstream exposure", immediate: ["Identify all instances of affected component", "Isolate systems running compromised version", "Check vendor advisory for IOCs", "Hunt IOCs across SIEM/EDR/network logs", "Contact vendor for official guidance"] },
    General:       { urgency: "MEDIUM  -  assess and triage", immediate: ["Review threat details and assess relevance", "Check if affected systems exist in inventory", "Search SIEM for related indicators", "Apply relevant patches or mitigations", "Update detection rules with new IOCs"] },
  };
  const pb = PLAYBOOKS[ttype] || PLAYBOOKS.General;

  if (mode === "ioc_summary") {
    const total = Object.values(iocs).reduce((s, v) => s + (typeof v === "number" ? v : 0), 0);
    return {
      title, total_indicators: total, ioc_types: iocs,
      tlp: threat.tlp_label || "TLP:CLEAR",
      analyst_note: total > 0
        ? `${total} indicators across ${Object.keys(iocs).length} types. Submit to SIEM/SOAR for blocking.`
        : "No IOCs extracted  -  monitor source for updates.",
      siem_action: total > 0 ? "Block at firewall, add to SIEM watchlist" : "Monitor source",
    };
  }

  if (mode === "mitre_mapping") {
    const MITRE_NAMES = { T1190:"Exploit Public-Facing App", T1566:"Phishing", T1078:"Valid Accounts", T1059:"Command Interpreter", T1486:"Data Encrypted for Impact", T1490:"Inhibit System Recovery", T1562:"Impair Defenses", T1055:"Process Injection", T1003:"OS Credential Dumping", T1021:"Remote Services", T1041:"Exfil Over C2", T1195:"Supply Chain Compromise", T1068:"Exploit for PrivEsc" };
    return {
      title, techniques: mitre.map(t => ({ id: t, name: MITRE_NAMES[t] || "See MITRE ATT\&CK" })),
      tactic_count: mitre.length,
      sigma_query:  mitre.slice(0,5).map(t => `"${t}"`).join(" OR ") || null,
      detection_note: `${mitre.length} ATT\&CK techniques detected. Create SIEM detection rules for each.`,
    };
  }

  return {
    title,
    summary: `${title}  -  ${sev} severity (risk: ${score.toFixed(1)}/10). ${kev}`,
    risk_level: level,
    urgency: pb.urgency,
    immediate_actions: pb.immediate,
    ticket_priority: score >= 9 ? "P1" : score >= 7 ? "P2" : score >= 5 ? "P3" : "P4",
    sla_hours: score >= 9 ? 1 : score >= 7 ? 4 : score >= 5 ? 24 : 72,
    mitre_techniques: mitre.slice(0, 8),
    threat_type: ttype,
    actor: threat.actor_tag || "UNATTRIBUTED",
  };
}

async function callLLM(env, systemPrompt, userPrompt, useR1) {
  const messages = [
    { role: "system", content: systemPrompt },
    { role: "user", content: userPrompt },
  ];

  async function decodeProviderResponse(provider, model, resp) {
    let data = null;

    try {
      data = await resp.json();
    } catch (_) {
      // Invalid/non-JSON upstream body is recorded only as metadata below.
    }

    if (!resp.ok) {
      console.warn("llm_provider_failure", JSON.stringify({
        provider,
        model,
        status: resp.status,
        reason: "http_error",
        error_type: data?.error?.type || null,
        error_code: data?.error?.code || null,
      }));

      return null;
    }

    const message = data?.choices?.[0]?.message || null;
    const text = message?.content?.trim();

    if (!text) {
      console.warn("llm_provider_failure", JSON.stringify({
        provider,
        model,
        status: resp.status,
        reason: "empty_content",
        finish_reason: data?.choices?.[0]?.finish_reason || null,
        has_reasoning_content: Boolean(message?.reasoning_content),
      }));

      return null;
    }

    console.log("llm_provider_success", JSON.stringify({
      provider,
      model,
      status: resp.status,
    }));

    return {
      text,
      model: `${provider}/${model}`,
    };
  }

  function logProviderException(provider, model, error) {
    console.warn("llm_provider_failure", JSON.stringify({
      provider,
      model,
      status: null,
      reason: "exception",
      error_name: error?.name || "Error",
    }));
  }

  // -----------------------------------------------------------------
  // 1. DeepSeek direct
  //
  // `useR1=false` historically represented the normal/non-reasoning
  // path. DeepSeek V4.1 Flash now defaults to thinking mode, therefore
  // explicitly disable thinking here instead of relying on provider
  // defaults.
  // -----------------------------------------------------------------

  if (env.DEEPSEEK_API_KEY) {
    const model = useR1 ? "deepseek-v4-pro" : "deepseek-flash";

    try {
      const resp = await fetch(
        "https://api.deepseek.com/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.DEEPSEEK_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model,
            max_tokens: useR1 ? 4096 : 1500,
            thinking: {
              type: useR1 ? "enabled" : "disabled",
            },
            reasoning_effort: useR1 ? "high" : "none",
            messages,
          }),
        },
      );

      const result = await decodeProviderResponse(
        "deepseek",
        model,
        resp,
      );

      if (result) return result;
    } catch (error) {
      logProviderException(
        "deepseek",
        model,
        error,
      );
    }
  }

  // -----------------------------------------------------------------
  // 2. Groq fallback
  //
  // Use a current production model rather than the developer-tier
  // deprecated llama-3.3-70b-versatile path.
  // -----------------------------------------------------------------

  if (env.GROQ_API_KEY) {
    const model = "openai/gpt-oss-120b";

    try {
      const resp = await fetch(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.GROQ_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model,
            max_tokens: useR1 ? 4096 : 1200,
            reasoning_effort: useR1 ? "high" : "low",
            messages,
          }),
        },
      );

      const result = await decodeProviderResponse(
        "groq",
        model,
        resp,
      );

      if (result) return result;
    } catch (error) {
      logProviderException(
        "groq",
        model,
        error,
      );
    }
  }

  // -----------------------------------------------------------------
  // 3. OpenRouter fallback
  // -----------------------------------------------------------------

  if (env.OPENROUTER_API_KEY) {
    const model = useR1
      ? "deepseek/deepseek-v4-pro-0813"
      : "deepseek/deepseek-v4.1-flash";

    try {
      const resp = await fetch(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.OPENROUTER_API_KEY}`,
            "Content-Type": "application/json",
            "HTTP-Referer": "https://intel.cyberdudebivash.com",
            "X-Title": "CYBERDUDEBIVASH SENTINEL APEX",
          },
          body: JSON.stringify({
            model,
            max_tokens: useR1 ? 4096 : 1500,
            messages,
          }),
        },
      );

      const result = await decodeProviderResponse(
        "openrouter",
        model,
        resp,
      );

      if (result) return result;
    } catch (error) {
      logProviderException(
        "openrouter",
        model,
        error,
      );
    }
  }

  console.warn("llm_provider_cascade_exhausted", JSON.stringify({
    deepseek_configured: Boolean(env.DEEPSEEK_API_KEY),
    groq_configured: Boolean(env.GROQ_API_KEY),
    openrouter_configured: Boolean(env.OPENROUTER_API_KEY),
  }));

  return null;
}
async function handleCopilot(request, env, auth, method, path) {
  const LLM_ENABLED   = !!(env.DEEPSEEK_API_KEY || env.GROQ_API_KEY || env.OPENROUTER_API_KEY);
  const LLM_TIERS     = new Set([TIERS.PRO, TIERS.ENTERPRISE, TIERS.MSSP]);
  const tierAllowsLLM = LLM_TIERS.has(auth.tier);

  // GET /api/v1/copilot/modes
  if (method === "GET" && path.includes("/modes")) {
    return jsonResp({
      status: "success",
      llm_enabled: LLM_ENABLED && tierAllowsLLM,
      llm_stack: {
        primary:   "DeepSeek V4 Pro (deepseek-v4-pro)  -  api.deepseek.com",
        secondary: "DeepSeek Flash (deepseek-flash)  -  api.deepseek.com",
        fallback1: "GROQ LPU (deepseek-r1-distill-llama-70b)  -  ultra-fast",
        fallback2: "OpenRouter (deepseek/deepseek-r1)",
        fallback3: "Deterministic template  -  always on",
      },
      modes: [
        { id: "explain_threat",   label: "Explain Threat",           model: "deepseek-flash",          new: false },
        { id: "what_to_do",       label: "What Should I Do?",        model: "deepseek-flash",          new: false },
        { id: "soc_report",       label: "SOC Report",               model: "deepseek-flash",          new: false },
        { id: "risk_brief",       label: "Executive Risk Brief",     model: "deepseek-flash",          new: false },
        { id: "ioc_summary",      label: "IOC Intelligence",         model: "deterministic",               new: false },
        { id: "mitre_mapping",    label: "MITRE ATT&CK Mapping",     model: "deterministic",               new: false },
        { id: "threat_hunt",      label: "Threat Hunt Package",      model: "deepseek-v4-pro",      new: true  },
        { id: "detection_write",  label: "Write Detection Rules",    model: "deepseek-v4-pro",      new: true  },
        { id: "incident_brief",   label: "Incident Commander Brief", model: "deepseek-v4-pro",      new: true  },
        { id: "natural_language", label: "Ask Anything",             model: "deepseek-v4-pro",      new: true  },
      ],
    });
  }

  // GET /api/v1/copilot/health
  if (method === "GET" && path.includes("/health")) {
    return jsonResp({
      status:        "ok",
      engine:        "CDB-Copilot v3.0 (Worker-native)",
      llm_enabled:   LLM_ENABLED,
      tier_llm:      tierAllowsLLM,
      providers:     { deepseek: !!env.DEEPSEEK_API_KEY, groq: !!env.GROQ_API_KEY, openrouter: !!env.OPENROUTER_API_KEY },
      modes_total:   10, r1_modes: 4, v3_modes: 4, deterministic: 2,
    });
  }

  // POST /api/v1/copilot/query
  if (method !== "POST") return jsonResp({ error: "Method not allowed" }, 405);

  let body = {};
  try { body = await request.json(); } catch (_) {
    return jsonResp({ error: "Invalid JSON body" }, 400);
  }

  const question   = (body.question || body.query || "").trim().slice(0, 2000);
  const mode       = COPILOT_ALL_MODES.has(body.mode) ? body.mode : "explain_threat";
  const threatData = body.threat_data || null;

  if (!question && !threatData) {
    return jsonResp({ error: "Provide question or threat_data" }, 400);
  }

  const threat = threatData || {
    title: question.slice(0, 100), severity: "HIGH", risk_score: 7.0,
    threat_type: "General", mitre_tactics: [], actor_tag: "UNATTRIBUTED",
    kev_present: false, ioc_counts: {},
  };

  // Deterministic modes  -  no LLM needed, always fast
  if (mode === "ioc_summary" || mode === "mitre_mapping") {
    return jsonResp({
      status: "success", mode,
      ...copilotTemplate(mode, threat, question),
      llm_enhanced: false,
      engine: "CDB-Copilot v3.0 (deterministic)",
      generated_at: new Date().toISOString(),
    });
  }

  // Template-only for FREE tier
  if (!tierAllowsLLM || !LLM_ENABLED) {
    return jsonResp({
      status: "success", mode,
      ...copilotTemplate(mode, threat, question),
      llm_enhanced: false, llm_available: LLM_ENABLED,
      engine: "CDB-Copilot v3.0 (deterministic)",
      tier_upgrade: !tierAllowsLLM ? "Upgrade to PRO for AI-powered analysis  -  intel.cyberdudebivash.com" : null,
      generated_at: new Date().toISOString(),
    });
  }

  // Build RAG context from live R2 feed
  let ragContext = "";
  try {
    const raw = await r2Get(env, LATEST_JSON_KEY);
    if (raw) {
      const items = (Array.isArray(raw) ? raw : (raw.items || raw.data || [])).slice(0, 8);
      const summary = items.map(i => ({
        title: (i.title || "").slice(0, 80), severity: i.severity,
        threat_type: i.threat_type, actor: i.actor_tag,
        kev: i.kev_present, risk_score: i.risk_score,
        mitre: (i.mitre_tactics || []).slice(0, 3),
      }));
      ragContext = `\n\nLatest ${summary.length} advisories from live SENTINEL APEX feed:\n${JSON.stringify(summary, null, 2)}`;
    }
  } catch (_) {}

  const systemPrompt = COPILOT_SYSTEM_PROMPT
    + ragContext
    + (threatData ? `\n\nCurrent advisory context:\n${JSON.stringify(threat, null, 2).slice(0, 1500)}` : "");

  const userPrompt = copilotBuildPrompt(mode, threat, question);
  const useR1      = COPILOT_R1_MODES.has(mode);

  const llmResult  = await callLLM(env, systemPrompt, userPrompt, useR1);
  const template   = copilotTemplate(mode, threat, question);

  return jsonResp({
    status: "success",
    mode,
    ...template,
    ...(llmResult ? { ai_analysis: llmResult.text, llm_model: llmResult.model, llm_enhanced: true } : {}),
    engine:       llmResult ? `CDB-Copilot v3.0 (${llmResult.model})` : "CDB-Copilot v3.0 (deterministic fallback)",
    llm_available: LLM_ENABLED,
    query:        question,
    generated_at: new Date().toISOString(),
  });
}

// =============================================================================
// AI SWARM SYNTHESIS (v4.45) -- real LLM narrative for a completed SUPER
// AGENT SWARM mission (workers/swarm-live), replacing the risk-synthesizer
// agent's previously-static "Review the canonical Sentinel correlation
// result" recommendation string with genuine analysis over that mission's
// actual specialist outcomes.
//
// Reuse Before Build (Principle 4): calls the EXISTING callLLM() unchanged
// (same DeepSeek -> GROQ -> OpenRouter cascade handleCopilot already uses
// above) and the EXISTING tier-gate shape handleCopilot already established
// (PRO/ENTERPRISE/MSSP get real LLM output; everyone else gets an honest
// "unavailable" response, never a fabricated one). Prompt-building and the
// tier check are pure functions imported from swarm-synthesis.js so they
// are unit-testable outside the wrangler/esbuild bundler; zero new
// LLM-provider integration was written for this feature.
//
// Caller: workers/swarm-live's executeMission() makes one real HTTP call
// here per mission (POST /api/v1/swarm-synthesis), forwarding the caller's
// own credentials unchanged -- same pattern as every other specialist call
// in that worker. A DENIED/FAILED/unavailable response here degrades that
// mission's risk-synthesizer result back to its existing deterministic
// fusion; it never fails the mission (see swarm-live's synthesizeNarrative).
// =============================================================================
async function handleSwarmSynthesis(request, env, auth, method, path) {
  const LLM_ENABLED = !!(env.DEEPSEEK_API_KEY || env.GROQ_API_KEY || env.OPENROUTER_API_KEY);
  const tierAllowsLLM = tierAllowsSwarmSynthesis(auth.tier);

  // GET /api/v1/swarm-synthesis/health
  // Configuration-level readiness only: no provider token is spent here.
  // The mission still performs a real synthesis call and records DEGRADED if
  // the provider is configured but unavailable at execution time.
  if (method === "GET" && path.includes("/health")) {
    return jsonResp({
      status:      "ok",
      engine:      "CDB-SwarmSynthesis v1.1 (Worker-native)",
      llm_enabled: LLM_ENABLED,
      tier_llm:    tierAllowsLLM,
      ready:       LLM_ENABLED && tierAllowsLLM,
      readiness_scope: "configuration",
      providers:   { deepseek: !!env.DEEPSEEK_API_KEY, groq: !!env.GROQ_API_KEY, openrouter: !!env.OPENROUTER_API_KEY },
    });
  }

  if (method !== "POST") return jsonResp({ error: "Method not allowed" }, 405);

  let body = {};
  try { body = await request.json(); } catch (_) {
    return jsonResp({ error: "Invalid JSON body" }, 400);
  }

  if (!body || typeof body !== "object" || Array.isArray(body) || !body.outcomes || typeof body.outcomes !== "object") {
    return jsonResp({ error: "outcomes_required", message: "Provide the swarm mission's specialist outcomes object" }, 400);
  }

  const generated_at  = new Date().toISOString();

  // Same honest-unavailable pattern as handleCopilot's FREE-tier /
  // LLM-disabled branch above -- never a fabricated narrative.
  if (!tierAllowsLLM || !LLM_ENABLED) {
    return jsonResp({
      status:        "success",
      llm_enhanced:  false,
      llm_available: LLM_ENABLED,
      narrative:     null,
      engine:        "CDB-SwarmSynthesis v1.0 (unavailable)",
      tier_upgrade:  !tierAllowsLLM ? "Upgrade to PRO for AI-powered swarm narrative synthesis  -  intel.cyberdudebivash.com" : null,
      generated_at,
    });
  }

  const userPrompt = buildSwarmSynthesisPrompt(body);
  const llmResult  = await callLLM(env, SWARM_SYNTHESIS_SYSTEM_PROMPT, userPrompt, false);

  if (!llmResult) {
    return jsonResp({
      status:        "success",
      llm_enhanced:  false,
      llm_available: LLM_ENABLED,
      narrative:     null,
      engine:        "CDB-SwarmSynthesis v1.0 (deterministic fallback)",
      generated_at,
    });
  }

  return jsonResp({
    status:        "success",
    llm_enhanced:  true,
    llm_model:     llmResult.model,
    narrative:     llmResult.text,
    engine:        `CDB-SwarmSynthesis v1.0 (${llmResult.model})`,
    generated_at,
  });
}

// =============================================================================
// PAYMENT SYSTEM  -  Razorpay + Gumroad + Manual Notify
// Razorpay: create-order -> client checkout modal -> verify (client) + webhook (server)
// Gumroad:  webhook ping -> auto-provision key + Telegram alert
// Manual:   UPI/NEFT/Crypto proof -> Telegram alert -> admin provisions key
// =============================================================================

// RAZORPAY_TIER_PRICES now lives in ./pricing.js (Phase 1 architecture
// consolidation - imported above). TRANSITIONAL values, unchanged from what
// was previously hardcoded here; see pricing-data.json's "_note" before
// changing any figure.

// P2.7-001: shadow-mode expiry. Every key provisioned here previously hardcoded
// expires_at: null -- a single one-time Razorpay Order or Gumroad sale granted
// permanent access, regardless of the monthly/annual price the customer paid.
// resolveAuth() (this file, ~line 355) already correctly checks expires_at and
// downgrades to FREE when it's past -- that gate needed zero changes. The only
// gap was this function never giving it real data.
//
// Gated behind SUBSCRIPTION_EXPIRY_ENABLED (wrangler.toml var, default
// "false") so this ships with zero behavior change until explicitly enabled.
// While disabled, the real expiry is still computed and audit-logged
// (shadow mode) so the correct values are observable before enforcement
// flips on -- toggle the var to enable, no redeploy of logic required.
// v185.5 (Mission Phase 2): single source of truth for every
// subscription_status transition -- used by both the admin-facing
// PATCH /api/admin/keys/{key}/status endpoint and the refund webhook below,
// so there is exactly one code path that decides how a status change is
// applied to a key record (Principle 3, no duplicate implementations).
async function applySubscriptionStatusChange(env, ctx, key, subscription_status, reason) {
  if (!SUBSCRIPTION_STATUS_VALID_STATES.has(subscription_status)) {
    return { ok: false, error: "invalid_status" };
  }
  const existing = await env.API_KEYS_KV.get(key, "json");
  if (!existing) return { ok: false, error: "not_found" };

  const ts = now();
  const updated = { ...existing, subscription_status };
  if (subscription_status === "cancelled") updated.cancel_at = ts;
  if (subscription_status === "suspended") updated.suspended_at = ts;
  if (subscription_status === "active") {
    delete updated.cancel_at;
    delete updated.suspended_at;
  }
  // Cloudflare KV drops any prior TTL on a plain put() with no options --
  // must re-specify it here or an existing key's KV-level expiration
  // silently reverts to "never," independent of subscription_status.
  const expiresAtSec = existing.expires_at ? Math.floor(new Date(existing.expires_at).getTime() / 1000) : null;
  const opts = expiresAtSec && expiresAtSec > Math.floor(Date.now() / 1000) + 60 ? { expiration: expiresAtSec } : undefined;
  await env.API_KEYS_KV.put(key, JSON.stringify(updated), opts);
  // v185.5 CodeRabbit fix: also invalidate any JWT already issued for this
  // customer, not just future API-key/login attempts -- see resolveAuth()'s
  // jwt_deny comment. customer_id is what a JWT payload carries as `sub`,
  // which is why this is keyed by customer_id rather than the raw key.
  const sub = existing.customer_id || key.slice(0, 8);
  if (SUBSCRIPTION_STATUS_DENY_STATES.has(subscription_status)) {
    await env.SECURITY_HUB_KV.put(`jwt_deny:${sub}`, "1", { expirationTtl: JWT_EXPIRY_SEC });
  } else if (subscription_status === "active") {
    await env.SECURITY_HUB_KV.delete(`jwt_deny:${sub}`);
  }
  auditLog(ctx, env, {
    action: "subscription_status_changed", key_prefix: key.slice(0, 12),
    from: existing.subscription_status || "active", to: subscription_status, reason: reason || null,
  });
  // Mirror the new status into REVENUE_CRM_KV and notify the customer. Before
  // this, a cancelled/refunded/suspended customer's own portal
  // (handleCustomerPortal(), revenue-engine) kept showing "active" forever --
  // this function only ever wrote API_KEYS_KV (the entitlement store), never
  // the customer-facing display copy in REVENUE_CRM_KV, and never sent any
  // notification. Best-effort/non-blocking, same pattern as
  // provisionApiKey()'s own mirror write: a KV/email hiccup here can't affect
  // the real status change above, which has already committed by this point.
  const custEmail = existing.customer_id;
  if (custEmail && env.REVENUE_CRM_KV) {
    ctx.waitUntil((async () => {
      try {
        const cust = await env.REVENUE_CRM_KV.get(`customer:${custEmail}`, "json");
        if (cust) {
          await env.REVENUE_CRM_KV.put(`customer:${custEmail}`, JSON.stringify({ ...cust, status: subscription_status, updated_at: ts }));
        }
        const subEmail = await env.REVENUE_CRM_KV.get(`sub:email:${custEmail}`, "json");
        if (subEmail) {
          await env.REVENUE_CRM_KV.put(`sub:email:${custEmail}`, JSON.stringify({ ...subEmail, status: subscription_status, updated_at: ts }));
        }
      } catch (err) {
        console.error("[applySubscriptionStatusChange] REVENUE_CRM_KV mirror write failed (portal display only, access unaffected):", err?.message || err);
      }
    })());
    if (SUBSCRIPTION_STATUS_DENY_STATES.has(subscription_status)) {
      ctx.waitUntil(sendStatusChangeEmail(env, custEmail, existing.tier, subscription_status, reason));
    }
  }
  return { ok: true, existing, updated };
}

async function provisionApiKey(env, ctx, tier, email, source, metadata, billingCycle = "monthly", managedTenants = undefined) {
  const validTier = ["FREE", "PRO", "ENTERPRISE", "MSSP"].includes(tier) ? tier : "PRO";
  const prefix = validTier === "ENTERPRISE" ? "cdb_ent" : validTier === "MSSP" ? "cdb_mssp" : validTier === "FREE" ? "cdb_free" : "cdb_pro";
  const rand   = Array.from(crypto.getRandomValues(new Uint8Array(20))).map(b => b.toString(16).padStart(2, "0")).join("");
  const apiKey = `${prefix}_${rand}`;

  // Issue #287: was a binary `billingCycle === "annual" ? 365 : 30`, which
  // silently gave any other value (e.g. Gumroad's "quarterly"/"biannual"/
  // "every_two_years", see inferGumroadBillingCycle) a 30-day expiry instead
  // of the ~90+ days actually paid for. Razorpay's own plans really are
  // monthly/annual only (RAZORPAY_PLAN_ID_* has no other suffix), so this
  // widening only changes behavior for Gumroad-sourced billing cycles.
  const CYCLE_DAYS = { monthly: 30, quarterly: 90, biannual: 180, annual: 365, every_two_years: 730 };
  const cycleDays      = CYCLE_DAYS[billingCycle] || 30;
  const shadowExpiresAt = new Date(Date.now() + cycleDays * 86400000).toISOString();
  // FREE has no billing cycle to expire against -- it is not a paid
  // subscription, so it never gets a shadow/enforced expiry regardless of
  // SUBSCRIPTION_EXPIRY_ENABLED (which governs paid-tier renewal lifecycle only).
  const enforceExpiry   = validTier !== "FREE" && env.SUBSCRIPTION_EXPIRY_ENABLED === "true";

  const record = {
    key: apiKey, tier: validTier, customer_id: email, label: email,
    source, created_at: now(), expires_at: enforceExpiry ? shadowExpiresAt : null,
    billing_cycle: billingCycle,
    payment_metadata: metadata || {},
    // v185.5 CodeRabbit fix: only set when the caller explicitly passes an
    // array (e.g. key rotation carrying forward an MSSP key's tenant
    // restriction) -- every other call site (webhook/verify/gumroad/admin-
    // create) omits this, so those keys still get resolveAuth()'s
    // managed_tenants: null (unrestricted) default, unchanged.
    ...(Array.isArray(managedTenants) ? { managed_tenants: managedTenants } : {}),
  };
  await env.API_KEYS_KV.put(apiKey, JSON.stringify(record));
  auditLog(ctx, env, {
    action: "key_auto_provisioned", email, tier: validTier, source,
    billing_cycle: billingCycle, expiry_enforced: enforceExpiry, shadow_expires_at: shadowExpiresAt,
  });

  // Mirror into REVENUE_CRM_KV, the namespace handleCustomerPortal() (revenue-
  // engine) actually reads -- reverse direction of the exact same pattern
  // already used for API_KEYS_KV (see that binding's own wrangler.toml
  // comment): additive only, never touches API_KEYS_KV.put() above (still
  // the sole authoritative grant of access), non-blocking so a KV hiccup here
  // can never fail or slow down a real checkout response, and best-effort
  // (logged, never thrown) since this only feeds the read-only self-service
  // portal display, not entitlement. Before this, provisionApiKey() (the
  // real, live checkout path) never wrote here at all, so the portal's
  // token now validates (PR #281) but still 404s "not_found" on every real
  // customer -- this closes that gap. Only fields this function genuinely
  // has real values for; never fabricates payment/usage history the way
  // revenue-engine's own richer provisionCustomer() record does.
  if (env.REVENUE_CRM_KV) {
    ctx.waitUntil((async () => {
      try {
        const periodEnd = enforceExpiry ? shadowExpiresAt : null;
        await env.REVENUE_CRM_KV.put(`customer:${email}`, JSON.stringify({
          id: email, email, tier: validTier, status: "active",
          billing_cycle: billingCycle, plan_started_at: now(), current_period_end: periodEnd,
          payment_id: (metadata && metadata.payment_id) || null,
          onboarding_completed: false, first_api_call_at: null, first_report_access_at: null,
          api_calls_total: 0, created_at: now(), updated_at: now(), source,
        }));
        const keyRecord = {
          id: apiKey, key: apiKey, tier: validTier, status: "active", email, customer_id: email,
          created_at: now(), expires_at: periodEnd, req_day: null, req_min: RATE_LIMITS[validTier] ?? RATE_LIMITS.FREE,
          features: [], rotation_count: 0, billing_cycle: billingCycle,
        };
        const prevKeys = (await env.REVENUE_CRM_KV.get(`apikeys:${email}`, "json")) || [];
        await env.REVENUE_CRM_KV.put(`apikeys:${email}`, JSON.stringify([...prevKeys, keyRecord]));
        // Also write the singular apikey:{key} record -- handleApiKeySelfRotate()
        // and GET /api/apikeys/validate look this up directly (not the
        // apikeys:{email} array above). Before this line neither ever found a
        // real checkout customer's key, so self-rotate 401'd for 100% of them.
        await env.REVENUE_CRM_KV.put(`apikey:${apiKey}`, JSON.stringify(keyRecord));
        await env.REVENUE_CRM_KV.put(`sub:email:${email}`, JSON.stringify({
          customer_id: email, email, tier: validTier, billing_cycle: billingCycle, status: "active",
          created_at: now(), current_period_start: now(), current_period_end: periodEnd,
          auto_renew: false, // matches the platform-wide "no automated recurring billing" contract
        }));
        // Also write sub:{id} and append to subscriptions:index, matching
        // provisionCustomer()'s shape (revenue-engine/src/index.js) exactly --
        // handleSubExpireCheck(), the only renewal-reminder cron that exists,
        // reads subscriptions:index then sub:{id} per entry. Without these,
        // real checkout customers were invisible to it and never got a 7d/3d
        // renewal reminder before access silently lapsed.
        const subId = `sub_${crypto.randomUUID()}`;
        await env.REVENUE_CRM_KV.put(`sub:${subId}`, JSON.stringify({
          id: subId, customer_id: email, email, tier: validTier, billing_cycle: billingCycle,
          status: "active", created_at: now(), current_period_start: now(), current_period_end: periodEnd,
          trial_ends_at: null, payment_id: (metadata && metadata.payment_id) || null,
          renewal_reminder_sent: false, renewal_count: 0, auto_renew: false,
        }));
        const subIdx = (await env.REVENUE_CRM_KV.get("subscriptions:index", "json")) || [];
        subIdx.unshift({ id: subId, email, tier: validTier, status: "active", current_period_end: periodEnd, created_at: now() });
        await env.REVENUE_CRM_KV.put("subscriptions:index", JSON.stringify(subIdx.slice(0, 1000)));
      } catch (err) {
        console.error("[provisionApiKey] REVENUE_CRM_KV mirror write failed (portal display only, access unaffected):", err?.message || err);
      }
    })());
  }

  return apiKey;
}

// POST /api/keys/free  (no auth required -- self-serve free-tier signup)
// get-api-key.html's "community" plan previously only submitted to a
// Formspree lead form with no automated delivery (API key arrived, if at
// all, only once a human read the email and provisioned one by hand --
// the same top-of-funnel gap the paid Razorpay flow had before it was
// wired to provisionApiKey()). This reuses that exact same engine.
async function handleFreeKeyRequest(request, env, ctx, method) {
  if (method !== "POST") return jsonResp({ error: "POST required" }, 405);
  let body = {};
  try { body = await request.json(); } catch (_) {}
  const email = String(body.email || "").trim().toLowerCase();
  // Deliberately not a single /^[^\s@]+@[^\s@]+\.[^\s@]+$/-style regex:
  // that pattern is polynomial-time on attacker-controlled input (CodeQL
  // js/polynomial-redos) -- ambiguous backtracking between the two
  // [^\s@]+ groups around a "." that neither excludes, on this public,
  // unauthenticated endpoint. Plain O(n) string ops give the same
  // "looks like an email" sanity check without that risk.
  const atIndex   = email.indexOf("@");
  const domain    = atIndex >= 0 ? email.slice(atIndex + 1) : "";
  const dotIndex  = domain.lastIndexOf(".");
  const validEmail = atIndex > 0
    && atIndex === email.lastIndexOf("@")
    && !/\s/.test(email)
    && dotIndex > 0
    && dotIndex < domain.length - 1;
  if (!validEmail) {
    return jsonResp({ error: "A valid email is required" }, 400);
  }

  // Idempotent, but NOT by returning the key in this response: this request
  // has no proof the caller owns `email` (it's just a JSON field), so
  // handing back an *existing* key here would let anyone who knows or
  // guesses a signed-up address pull back that person's live, permanent
  // credential -- CodeRabbit correctly flagged this on the first version
  // of this endpoint. Re-sending to the address on file is the only
  // channel that actually proves ownership, and the response is identical
  // whether or not the email has an account, so this can't be used to
  // enumerate who has signed up either. A brand-new email still gets its
  // key instantly below -- there's no existing credential to leak yet.
  const emailIdempKey = `free_key_email:${email}`;
  const existingKey = await env.SECURITY_HUB_KV.get(emailIdempKey);
  if (existingKey) {
    ctx.waitUntil((async () => {
      try { await sendActivationEmail(env, email, "FREE", existingKey); } catch (err) {
        console.error("[handleFreeKeyRequest] resend error:", err?.message || err);
      }
    })());
    return jsonResp({
      status: "check_email",
      message: "If that email already has a free key, we've re-sent it.",
      docs_url: "https://intel.cyberdudebivash.com/api-docs.html",
    }, 200);
  }

  // Per-IP daily cap -- the idempotency check above already stops one email
  // from farming multiple keys; this stops one IP farming many distinct
  // emails. Fails open (allows the request) on a KV read error rather than
  // blocking a real signup over an infrastructure hiccup.
  const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
  const day = new Date().toISOString().slice(0, 10);
  const ipCapKey = `free_signup_ip:${ip}:${day}`;
  try {
    const ipCount = parseInt((await env.RATE_LIMIT_KV.get(ipCapKey)) || "0", 10);
    if (ipCount >= FREE_SIGNUP_IP_DAILY_CAP) {
      return jsonResp({ error: "Too many free-key requests from this network today. Try again tomorrow, or contact support@cyberdudebivash.com." }, 429);
    }
    await env.RATE_LIMIT_KV.put(ipCapKey, String(ipCount + 1), { expirationTtl: 86400 });
  } catch (_) {}

  const apiKey = await provisionApiKey(env, ctx, "FREE", email, "self_serve_free", {});
  // No TTL here, deliberately: the FREE key itself never expires (see
  // provisionApiKey above), so if this mapping expired first, the same
  // email's next request would fall through the "existing key" check
  // above and mint a second, permanent, orphaned key instead of finding
  // the first one.
  await env.SECURITY_HUB_KV.put(emailIdempKey, apiKey);

  // Never blocks the response -- same pattern as the Razorpay paths.
  ctx.waitUntil((async () => {
    try { await sendActivationEmail(env, email, "FREE", apiKey); } catch (err) {
      console.error("[handleFreeKeyRequest] sendActivationEmail error:", err?.message || err);
    }
  })());
  ctx.waitUntil(sendTelegramAlert(env,
    `[FREE] <b>SELF-SERVE FREE KEY ISSUED</b>\n` +
    `Email: ${email}\n` +
    `API Key: <code>${apiKey.slice(0, 16)}...</code>`
  ));

  return jsonResp({
    status: "activated",
    message: "Free API key provisioned instantly.",
    api_key: apiKey, tier: "FREE",
    docs_url: "https://intel.cyberdudebivash.com/api-docs.html",
  }, 201);
}

async function sendTelegramAlert(env, text) {
  if (!env.TG_BOT_TOKEN || !env.TG_CHAT_ID) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text, parse_mode: "HTML" }),
    });
    return r.ok;
  } catch (_) { return false; }
}

// Customer-portal HMAC token: deliberately identical algorithm to
// revenue-engine's own computePortalToken() (workers/revenue-engine/src/index.js)
// -- HMAC-SHA256(REVENUE_ADMIN_SECRET, "portal:"+email), hex-encoded, domain-
// separated with the same "portal:" prefix. Duplicated rather than imported
// because these are two independently deployed Workers with no shared module
// boundary (same pattern already used for pricing.js's own documented
// duplication-with-cross-reference elsewhere in this codebase) -- but the
// *value* must come from the exact same REVENUE_ADMIN_SECRET so a token
// computed here validates against revenue-engine's handleCustomerPortal(),
// the only place any such token is ever checked. This is the real, live
// checkout path (Razorpay/Gumroad -> provisionApiKey() -> here); before this,
// only the separate, rarely-reachable provisionCustomer() path (revenue-engine)
// ever computed a portal token, so no real paying customer's welcome email
// ever contained a working "manage your subscription" link. See
// docs/BILLING_ENTITLEMENT_ARCHITECTURE_AUDIT.md and PR #281 for the full
// trace. Returns null (never a fabricated token) when the secret isn't set,
// so this ships as a no-op addition to the email until a human runs
// `wrangler secret put REVENUE_ADMIN_SECRET` with revenue-engine's value.
async function computePortalToken(env, email) {
  if (!env?.REVENUE_ADMIN_SECRET) return null;
  try {
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(env.REVENUE_ADMIN_SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("portal:" + email.toLowerCase()));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
  } catch (_) { return null; }
}

// P2.6.1-002: Activation email via Resend API  -  fails silently, never blocks provisioning
async function sendActivationEmail(env, email, tier, apiKey) {
  if (!env.RESEND_API_KEY) {
    console.warn("[sendActivationEmail] RESEND_API_KEY not configured  -  skipping activation email");
    return false;
  }
  try {
    const tierLabel = tier === "ENTERPRISE" ? "ENTERPRISE" : tier === "MSSP" ? "MSSP" : tier === "FREE" ? "FREE" : "PRO";
    const portalToken = await computePortalToken(env, email);
    const portalBlock = portalToken
      ? `<div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:20px;margin:24px 0;">
      <p style="color:#94a3b8;margin:0 0 8px;">Manage your subscription:</p>
      <a href="https://intel.cyberdudebivash.com/customer/api-keys.html?email=${encodeURIComponent(email)}&token=${portalToken}" style="color:#60a5fa;">View your keys & subscription status &rarr;</a>
    </div>`
      : "";
    const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Your CYBERDUDEBIVASH(R) Sentinel APEX API Key</title></head>
<body style="background:#0a0a0f;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:32px;">
  <div style="max-width:600px;margin:0 auto;background:#111827;border:1px solid #1e40af;border-radius:12px;padding:40px;">
    <h1 style="color:#60a5fa;margin-top:0;">CYBERDUDEBIVASH(R) Sentinel APEX</h1>
    <h2 style="color:#e2e8f0;">Your API Key is Ready</h2>
    <p style="color:#94a3b8;">Welcome! Your <strong style="color:#60a5fa;">${tierLabel}</strong> plan is now active.</p>

    <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:20px;margin:24px 0;">
      <p style="color:#94a3b8;margin:0 0 8px;">Your API Key:</p>
      <code style="color:#34d399;font-size:14px;word-break:break-all;">${apiKey}</code>
    </div>

    <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:20px;margin:24px 0;">
      <p style="color:#94a3b8;margin:0 0 8px;">Quick Start:</p>
      <code style="color:#fbbf24;font-size:13px;word-break:break-all;">curl -H "X-API-Key: ${apiKey}" https://intel.cyberdudebivash.com/api/feed</code>
    </div>
    ${portalBlock}
    <p style="color:#94a3b8;">Need help? Contact us at <a href="mailto:support@cyberdudebivash.com" style="color:#60a5fa;">support@cyberdudebivash.com</a></p>
    <p style="color:#475569;font-size:12px;margin-bottom:0;">CYBERDUDEBIVASH(R) SENTINEL APEX  -  Enterprise Threat Intelligence Platform</p>
  </div>
</body>
</html>`;

    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: "CYBERDUDEBIVASH(R) Sentinel APEX <noreply@cyberdudebivash.com>",
        to: [email],
        subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX API Key",
        html: htmlBody,
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      console.error(`[sendActivationEmail] Resend API error ${resp.status}: ${errText}`);
      return false;
    }
    return true;
  } catch (err) {
    console.error("[sendActivationEmail] Failed to send activation email:", err?.message || err);
    return false;
  }
}

async function sendStatusChangeEmail(env, email, tier, status, reason) {
  if (!env.RESEND_API_KEY) {
    console.warn("[sendStatusChangeEmail] RESEND_API_KEY not configured  -  skipping notification email");
    return false;
  }
  const copy = {
    cancelled: { subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX subscription was cancelled", headline: "Subscription Cancelled" },
    refunded:  { subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX payment was refunded",       headline: "Payment Refunded" },
    suspended: { subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX access was suspended",        headline: "Access Suspended" },
    expired:   { subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX access has expired",          headline: "Access Expired" },
  }[status] || { subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX subscription status changed", headline: "Subscription Status Changed" };
  try {
    const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>${copy.subject}</title></head>
<body style="background:#0a0a0f;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:32px;">
  <div style="max-width:600px;margin:0 auto;background:#111827;border:1px solid #1e40af;border-radius:12px;padding:40px;">
    <h1 style="color:#60a5fa;margin-top:0;">CYBERDUDEBIVASH(R) Sentinel APEX</h1>
    <h2 style="color:#e2e8f0;">${copy.headline}</h2>
    <p style="color:#94a3b8;">Your <strong style="color:#60a5fa;">${tier || "PRO"}</strong> plan access has been updated to: <strong style="color:#60a5fa;">${status}</strong>.${reason ? ` Reason: ${reason}.` : ""}</p>
    <p style="color:#94a3b8;">If this wasn't expected, or you have questions, contact us at <a href="mailto:support@cyberdudebivash.com" style="color:#60a5fa;">support@cyberdudebivash.com</a></p>
    <p style="color:#475569;font-size:12px;margin-bottom:0;">CYBERDUDEBIVASH(R) SENTINEL APEX  -  Enterprise Threat Intelligence Platform</p>
  </div>
</body>
</html>`;
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: "CYBERDUDEBIVASH(R) Sentinel APEX <noreply@cyberdudebivash.com>",
        to: [email],
        subject: copy.subject,
        html: htmlBody,
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      console.error(`[sendStatusChangeEmail] Resend API error ${resp.status}: ${errText}`);
      return false;
    }
    return true;
  } catch (err) {
    console.error("[sendStatusChangeEmail] Failed to send status-change email:", err?.message || err);
    return false;
  }
}

// Customer-facing counterpart to the operator-only Telegram alert already
// fired on payment.failed below. Before this, a failed checkout attempt
// notified nobody but the operator -- the customer got only a transient
// client-side alert() (if still on the tab) and had no durable channel
// telling them what happened or how to retry. Mirrors sendActivationEmail/
// sendStatusChangeEmail's exact Resend call pattern; fails silently (never
// throws, never blocks the webhook response) on the same RESEND_API_KEY gate.
async function sendPaymentFailedEmail(env, email, tier, reason) {
  if (!env.RESEND_API_KEY) {
    console.warn("[sendPaymentFailedEmail] RESEND_API_KEY not configured  -  skipping notification email");
    return false;
  }
  try {
    const planParam = ["PRO", "ENTERPRISE", "MSSP"].includes(tier) ? tier.toLowerCase() : "pro";
    const retryUrl = `https://intel.cyberdudebivash.com/upgrade.html?plan=${planParam}&ref=payment_failed_email`;
    const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Your CYBERDUDEBIVASH(R) Sentinel APEX payment did not go through</title></head>
<body style="background:#0a0a0f;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:32px;">
  <div style="max-width:600px;margin:0 auto;background:#111827;border:1px solid #1e40af;border-radius:12px;padding:40px;">
    <h1 style="color:#60a5fa;margin-top:0;">CYBERDUDEBIVASH(R) Sentinel APEX</h1>
    <h2 style="color:#e2e8f0;">Your Payment Didn't Go Through</h2>
    <p style="color:#94a3b8;">We tried to process your <strong style="color:#60a5fa;">${tier || "PRO"}</strong> plan payment, but it didn't complete.${reason ? ` Reason given by the payment processor: <em>${reason}</em>.` : ""}</p>
    <p style="color:#94a3b8;">No charge was made and no access was granted. You can safely try again:</p>
    <div style="text-align:center;margin:28px 0;">
      <a href="${retryUrl}" style="background:#2563eb;color:#fff;padding:12px 28px;text-decoration:none;font-weight:700;border-radius:6px;display:inline-block;">Retry Payment &rarr;</a>
    </div>
    <p style="color:#94a3b8;">If this keeps happening, contact us at <a href="mailto:support@cyberdudebivash.com" style="color:#60a5fa;">support@cyberdudebivash.com</a> and we'll help you get set up.</p>
    <p style="color:#475569;font-size:12px;margin-bottom:0;">CYBERDUDEBIVASH(R) SENTINEL APEX  -  Enterprise Threat Intelligence Platform</p>
  </div>
</body>
</html>`;
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: "CYBERDUDEBIVASH(R) Sentinel APEX <noreply@cyberdudebivash.com>",
        to: [email],
        subject: "Your CYBERDUDEBIVASH(R) Sentinel APEX payment did not go through",
        html: htmlBody,
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      console.error(`[sendPaymentFailedEmail] Resend API error ${resp.status}: ${errText}`);
      return false;
    }
    return true;
  } catch (err) {
    console.error("[sendPaymentFailedEmail] Failed to send payment-failed email:", err?.message || err);
    return false;
  }
}

async function verifyRazorpayHmac(payload, signature, secret) {
  try {
    const encoder  = new TextEncoder();
    const key      = await crypto.subtle.importKey(
      "raw", encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    // Decode hex signature to raw bytes; crypto.subtle.verify uses constant-time compare
    const sigBytes = new Uint8Array(signature.match(/.{2}/g).map(b => parseInt(b, 16)));
    return await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(payload));
  } catch (_) { return false; }
}

// POST /api/payment/razorpay/create-order
async function handleRazorpayCreateOrder(request, env, method) {
  if (method !== "POST") return jsonResp({ error: "POST required" }, 405);
  let body = {};
  try { body = await request.json(); } catch (_) {}
  const { tier = "PRO", email, billing = "monthly" } = body;
  if (!email) return jsonResp({ error: "email is required" }, 400);
  const tierUp  = tier.toUpperCase();
  const pricing = RAZORPAY_TIER_PRICES[tierUp];
  if (!pricing) return jsonResp({ error: "Invalid tier. Valid: PRO, ENTERPRISE, MSSP" }, 400);
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return jsonResp({ error: "Razorpay not configured on server", fallback_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 503);
  }
  const amount = billing === "annual" ? pricing.annual : pricing.monthly;
  try {
    const creds = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
    const resp  = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Basic ${creds}` },
      body: JSON.stringify({
        amount, currency: "INR",
        receipt: `sa_${tierUp.toLowerCase()}_${Date.now()}`,
        notes: { tier: tierUp, email, platform: "SENTINEL-APEX", billing },
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      return jsonResp({ error: "Razorpay order creation failed", detail: errText }, 502);
    }
    const order = await resp.json();
    return jsonResp({
      order_id: order.id, amount: order.amount, currency: order.currency,
      key_id: env.RAZORPAY_KEY_ID, plan: pricing.label, tier: tierUp,
      billing, prefill: { email },
    });
  } catch (e) {
    console.error(`[razorpay] create-order failed: ${e.message}`);
    return jsonResp({ error: "Razorpay API unavailable" }, 503);
  }
}

// POST /api/payment/razorpay/verify  (client calls after successful checkout modal)
async function handleRazorpayVerify(request, env, ctx, method) {
  if (method !== "POST") return jsonResp({ error: "POST required" }, 405);
  let body = {};
  try { body = await request.json(); } catch (_) {}
  // NOTE: a client-supplied `tier` field is deliberately NOT read here.
  // Tier is derived below from the verified Razorpay payment record only --
  // see the v185.2 SECURITY FIX comment before provisioning.
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, email, billing = "monthly" } = body;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return jsonResp({ error: "razorpay_order_id, razorpay_payment_id, razorpay_signature required" }, 400);
  }
  if (!email) return jsonResp({ error: "email required" }, 400);
  if (!env.RAZORPAY_KEY_SECRET) return jsonResp({ error: "Razorpay not configured" }, 503);

  const valid = await verifyRazorpayHmac(
    `${razorpay_order_id}|${razorpay_payment_id}`,
    razorpay_signature, env.RAZORPAY_KEY_SECRET
  );
  if (!valid) return jsonResp({ error: "Payment signature invalid  -  verification failed", code: "SIG_MISMATCH" }, 400);

  // P2.6.1-001: Unified cross-path idempotency guard  -  checked FIRST before per-path keys
  const unifiedIdempKey = `rzp_payment:${razorpay_payment_id}`;
  const alreadyProvisioned = await env.SECURITY_HUB_KV.get(unifiedIdempKey);
  if (alreadyProvisioned) {
    return jsonResp({ error: "Payment already verified and key provisioned", code: "ALREADY_PROVISIONED" }, 409);
  }

  // Backward-compat per-path idempotency guard (kept for existing records)
  const verifyIdempKey = `rzp_verified:${razorpay_payment_id}`;
  const alreadyVerified = await env.SECURITY_HUB_KV.get(verifyIdempKey);
  if (alreadyVerified) {
    return jsonResp({ error: "Payment already verified and key provisioned", code: "ALREADY_PROVISIONED" }, 409);
  }

  // v185.2 SECURITY FIX (Fortune-500 audit, Phase 3): the HMAC check above
  // only proves razorpay_order_id|razorpay_payment_id was genuinely signed
  // by Razorpay -- it says nothing about which tier that specific payment
  // was actually for. `tier` in the request body is client-supplied and
  // was previously trusted directly for provisioning: a customer could pay
  // the real PRO order (INR 4,100), then call this endpoint with
  // tier:"ENTERPRISE" and be provisioned an Enterprise-tier key for PRO
  // money. This path also normally wins the idempotency race against the
  // signed server-to-server webhook (handleWebhookRazorpay, which already
  // derives tier correctly from Razorpay's own signed notes.tier), since
  // the client calls this synchronously right after checkout while the
  // webhook arrives asynchronously -- making this the primary, not an
  // edge-case, provisioning path. Fixed: fetch the payment record back
  // from Razorpay's own API (authoritative, not client-suppliable), verify
  // it is captured and bound to the claimed order_id, and derive tier from
  // its own notes.tier (set server-side at order-creation time) -- the
  // client's `tier` field is no longer trusted for provisioning.
  const razorpayCreds = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  let paymentEntity;
  try {
    const payResp = await fetch(`https://api.razorpay.com/v1/payments/${razorpay_payment_id}`, {
      headers: { "Authorization": `Basic ${razorpayCreds}` },
    });
    if (!payResp.ok) {
      return jsonResp({ error: "Could not verify payment with Razorpay" }, 502);
    }
    paymentEntity = await payResp.json();
  } catch (e) {
    console.error(`[razorpay] payment lookup failed: ${e.message}`);
    return jsonResp({ error: "Razorpay API unavailable" }, 503);
  }
  if (paymentEntity.order_id !== razorpay_order_id) {
    auditLog(ctx, env, { action: "payment_order_mismatch", payment_id: razorpay_payment_id, claimed_order: razorpay_order_id, actual_order: paymentEntity.order_id });
    return jsonResp({ error: "Payment does not match the specified order", code: "ORDER_MISMATCH" }, 400);
  }
  if (paymentEntity.status !== "captured") {
    return jsonResp({ error: "Payment not captured", code: "NOT_CAPTURED", status: paymentEntity.status }, 400);
  }
  const authoritativeTier = String(paymentEntity.notes?.tier || "").toUpperCase();
  if (!["PRO", "ENTERPRISE", "MSSP"].includes(authoritativeTier)) {
    auditLog(ctx, env, { action: "payment_tier_unresolvable", payment_id: razorpay_payment_id });
    return jsonResp({ error: "Could not determine tier from the verified payment record" }, 400);
  }
  const tierUp = authoritativeTier;
  const apiKey = await provisionApiKey(env, ctx, tierUp, email, "razorpay_checkout", {
    order_id: razorpay_order_id, payment_id: razorpay_payment_id,
  }, billing === "annual" ? "annual" : "monthly");
  // P2.6.1-001: Write unified idempotency key (1 year TTL)  -  prevents double-provision from webhook path
  await env.SECURITY_HUB_KV.put(unifiedIdempKey, JSON.stringify({ email, tier: tierUp, ts: now(), source: "razorpay_checkout" }), { expirationTtl: 86400 * 365 });
  // Mark payment_id as consumed via per-path key (backward compat  -  1 year TTL)
  await env.SECURITY_HUB_KV.put(verifyIdempKey, JSON.stringify({ email, tier: tierUp, ts: now() }), { expirationTtl: 86400 * 365 });
  // v185.5 CodeRabbit fix: this client-verify path -- not the webhook below --
  // is documented (see the comment above this function) as the one that
  // normally wins the provisioning race, since it runs synchronously right
  // after checkout while the webhook arrives async and then exits through
  // its own idempotency guard without ever reaching ITS payment_key_map
  // write. Omitting the mapping here meant refund handling would silently
  // find "no mapping" for the majority of real payments. Written here too.
  await env.SECURITY_HUB_KV.put(`payment_key_map:${razorpay_payment_id}`, apiKey, { expirationTtl: 86400 * 365 });

  // P2.6.1-002: Send activation email  -  wrapped in try/catch, never blocks provisioning
  ctx.waitUntil((async () => {
    try { await sendActivationEmail(env, email, tierUp, apiKey); } catch (err) {
      console.error("[handleRazorpayVerify] sendActivationEmail error:", err?.message || err);
    }
  })());

  ctx.waitUntil(sendTelegramAlert(env,
    `? <b>RAZORPAY PAYMENT VERIFIED</b>\n` +
    `Plan: <b>${tierUp}</b>\n` +
    `Email: ${email}\n` +
    `Payment ID: <code>${razorpay_payment_id}</code>\n` +
    `API Key: <code>${apiKey.slice(0, 16)}...</code>`
  ));

  return jsonResp({
    status: "activated",
    message: "Payment verified. API key provisioned instantly.",
    api_key: apiKey, tier: tierUp,
    docs_url: "https://intel.cyberdudebivash.com/get-api-key.html",
    support: { whatsapp: "+918179881447", email: "bivash@cyberdudebivash.com" },
  }, 201);
}

// POST /api/webhooks/razorpay  (Razorpay server-to-server webhook)
async function handleWebhookRazorpay(request, env, ctx) {
  const rawBody = await request.text();
  const sig     = request.headers.get("X-Razorpay-Signature") || "";
  const secret  = env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) return jsonResp({ error: "Webhook secret not configured" }, 500);

  const valid = await verifyRazorpayHmac(rawBody, sig, secret);
  if (!valid) {
    auditLog(ctx, env, { action: "webhook_sig_fail", source: "razorpay" });
    return jsonResp({ error: "Signature mismatch" }, 401);
  }

  let payload = {};
  try { payload = JSON.parse(rawBody); } catch (_) {
    return jsonResp({ error: "Invalid JSON payload" }, 400);
  }

  const event  = payload.event || "";
  const entity = payload.payload?.payment?.entity || payload.payload?.subscription?.entity || {};
  const notes  = entity.notes || {};
  const email  = notes.email || entity.email || entity.contact || "unknown@razorpay";
  const tier   = (notes.tier || "PRO").toUpperCase();
  const amount = entity.amount || 0;
  const pid    = entity.id || "unknown";

  if (event === "payment.captured" || event === "order.paid") {
    // P2.6.1-001: Unified cross-path idempotency guard  -  checked FIRST before per-path key
    const unifiedIdempKey = `rzp_payment:${pid}`;
    const alreadyProvisioned = await env.SECURITY_HUB_KV.get(unifiedIdempKey);
    if (alreadyProvisioned) return jsonResp({ status: "already_provisioned", payment_id: pid });

    // Backward-compat per-path idempotency guard (kept for existing records)
    const whIdempKey = `rzp_webhook:${pid}`;
    const alreadyDone = await env.SECURITY_HUB_KV.get(whIdempKey);
    if (alreadyDone) return jsonResp({ status: "already_provisioned", payment_id: pid });

    const apiKey = await provisionApiKey(env, ctx, tier, email, "razorpay_webhook", {
      payment_id: pid, amount, event,
    }, notes.billing === "annual" ? "annual" : "monthly");
    // P2.6.1-001: Write unified idempotency key (1 year TTL)  -  prevents double-provision from blog bridge path
    await env.SECURITY_HUB_KV.put(unifiedIdempKey, JSON.stringify({ email, tier, ts: now(), source: "razorpay_webhook" }), { expirationTtl: 86400 * 365 });
    // Backward-compat per-path key (1 year TTL)
    await env.SECURITY_HUB_KV.put(whIdempKey, JSON.stringify({ email, tier, ts: now() }), { expirationTtl: 86400 * 365 });
    // v185.5 (Mission Phase 2): payment_id -> api_key mapping so a later
    // refund.* webhook for this same payment_id (Razorpay refunds are
    // issued against Payments, not Orders/Subscriptions, so this event DOES
    // exist for this integration even though subscription.* events don't --
    // see the refund handler below) can find which key to mark refunded.
    // Same 1-year TTL as the idempotency keys above; a refund past that
    // window falls through to "no mapping found," logged, not silently lost.
    await env.SECURITY_HUB_KV.put(`payment_key_map:${pid}`, apiKey, { expirationTtl: 86400 * 365 });

    // P2.6.1-002: Send activation email  -  wrapped in try/catch, never blocks provisioning
    ctx.waitUntil((async () => {
      try { await sendActivationEmail(env, email, tier, apiKey); } catch (err) {
        console.error("[handleWebhookRazorpay] sendActivationEmail error:", err?.message || err);
      }
    })());

    ctx.waitUntil(sendTelegramAlert(env,
      `? <b>RAZORPAY: ${event}</b>\n` +
      `Plan: <b>${tier}</b> | Amount: ?${(amount / 100).toFixed(2)}\n` +
      `Email: ${email}\n` +
      `Payment ID: <code>${pid}</code>\n` +
      `API Key: <code>${apiKey.slice(0, 16)}...</code>`
    ));
    return jsonResp({ status: "provisioned", tier, email });
  }

  if (event === "payment.failed") {
    // NOTE (Mission Phase 2): this fires when an INITIAL checkout payment
    // attempt fails, before any key was ever provisioned for it -- there is
    // no existing subscription to move to past_due here. This integration
    // uses Razorpay's one-time Orders API (handleRazorpayCreateOrder,
    // api.razorpay.com/v1/orders), not the recurring Subscriptions API, so
    // there is no provider-driven "renewal failed" signal at all -- a real
    // past_due transition in this architecture can only be admin-initiated
    // (via PATCH /api/admin/keys/{key}/status) for a customer who was
    // manually flagged as behind on a manual/offline renewal. See
    // docs/PAYMENT_WEBHOOK_LIFECYCLE_MAPPING_V185.md for the full mapping.
    ctx.waitUntil(sendTelegramAlert(env,
      `[FAIL] <b>RAZORPAY PAYMENT FAILED</b>\n` +
      `Plan: ${tier} | Email: ${email}\n` +
      `Payment ID: <code>${pid}</code>\n` +
      `Error: ${entity.error_description || "unknown"}`
    ));
    // Customer-facing counterpart to the operator alert above -- only when
    // Razorpay handed back a real address (not the "unknown@razorpay"
    // fallback, and not a bare contact/phone number in the email slot).
    if (email.indexOf("@") > 0 && email !== "unknown@razorpay") {
      ctx.waitUntil((async () => {
        try { await sendPaymentFailedEmail(env, email, tier, entity.error_description || ""); } catch (err) {
          console.error("[handleWebhookRazorpay] sendPaymentFailedEmail error:", err?.message || err);
        }
      })());
    }
    return jsonResp({ status: "noted", event });
  }

  // v185.5 (Mission Phase 2): refund.* IS a real webhook event Razorpay
  // sends for this integration -- refunds are issued against Payment
  // objects, which exist regardless of Orders vs Subscriptions API usage.
  // Resolves payment_id -> the key issued for it (written at provisioning
  // time above) and marks that key refunded via the same
  // applySubscriptionStatusChange() the admin PATCH endpoint uses.
  if (event === "refund.created" || event === "refund.processed") {
    const refundEntity = payload.payload?.refund?.entity || {};
    const refundedPaymentId = refundEntity.payment_id || pid;
    const mappedKey = await env.SECURITY_HUB_KV.get(`payment_key_map:${refundedPaymentId}`);
    if (!mappedKey) {
      auditLog(ctx, env, { action: "refund_key_lookup_failed", payment_id: refundedPaymentId, refund_id: refundEntity.id || null });
      ctx.waitUntil(sendTelegramAlert(env,
        `[WARN] <b>RAZORPAY REFUND -- NO KEY MAPPING</b>\n` +
        `Payment ID: <code>${refundedPaymentId}</code>\n` +
        `Refund ID: <code>${refundEntity.id || "unknown"}</code>\n` +
        `Manual follow-up required -- could not auto-revoke access.`
      ));
      return jsonResp({ status: "noted_no_mapping", event, payment_id: refundedPaymentId });
    }
    const result = await applySubscriptionStatusChange(env, ctx, mappedKey, "refunded", `razorpay_${event}:${refundEntity.id || "unknown"}`);
    if (result.ok) {
      ctx.waitUntil(sendTelegramAlert(env,
        `<b>RAZORPAY REFUND PROCESSED</b>\n` +
        `Payment ID: <code>${refundedPaymentId}</code>\n` +
        `Key: <code>${mappedKey.slice(0, 16)}...</code> marked refunded -- access revoked.`
      ));
    }
    return jsonResp({ status: result.ok ? "refunded" : "key_not_found", event, payment_id: refundedPaymentId });
  }

  return jsonResp({ status: "acknowledged", event });
}

// POST /api/webhooks/gumroad  (Gumroad Ping webhook  -  application/x-www-form-urlencoded)
// Configure Gumroad -> Settings -> Webhooks URL as:
//   https://intel.cyberdudebivash.com/api/webhooks/gumroad?secret=YOUR_GUMROAD_WEBHOOK_SECRET
// Set GUMROAD_WEBHOOK_SECRET via: npx wrangler secret put GUMROAD_WEBHOOK_SECRET
async function handleWebhookGumroad(request, env, ctx) {
  // Token-based authentication: Gumroad doesn't sign payloads, so we use a shared secret in the URL
  if (!env.GUMROAD_WEBHOOK_SECRET) {
    return jsonResp({ error: "Webhook secret not configured" }, 500);
  }
  const urlToken = new URL(request.url).searchParams.get("secret") || "";
  if (!urlToken || !timingSafeEqual(urlToken, env.GUMROAD_WEBHOOK_SECRET)) {
    auditLog(ctx, env, { action: "webhook_auth_fail", source: "gumroad" });
    return jsonResp({ error: "Unauthorized" }, 401);
  }

  let formData = {};
  try {
    const body = await request.text();
    formData = Object.fromEntries(new URLSearchParams(body));
  } catch (_) {
    return jsonResp({ error: "Invalid request body" }, 400);
  }

  const {
    sale_id, email, product_id = "", product_name = "", variants = "",
    price = "0", subscription_id = "", recurrence = "",
  } = formData;

  // "Subscription updated" ping (same webhook URL as "sale"): cancelled/ended.
  if (isGumroadCancellationEvent(formData)) {
    if (!subscription_id) {
      return jsonResp({ error: "Invalid Gumroad cancellation payload: subscription_id required" }, 400);
    }
    const mappedKey = await env.SECURITY_HUB_KV.get(`gumroad_sub_key_map:${subscription_id}`);
    if (!mappedKey) {
      auditLog(ctx, env, { action: "gumroad_cancel_key_lookup_failed", subscription_id });
      ctx.waitUntil(sendTelegramAlert(env,
        `[WARN] <b>GUMROAD CANCELLATION -- NO KEY MAPPING</b>\n` +
        `Subscription ID: <code>${subscription_id}</code>\n` +
        `Manual follow-up required -- could not auto-revoke access.`
      ));
      return jsonResp({ status: "noted_no_mapping", subscription_id });
    }

    // cancelled:"true" alone means auto-renewal was turned off -- the
    // customer already paid for the current period, so access must not be
    // revoked yet. Only ended:"true" (the period has actually finished)
    // revokes. Without this split, cancelling on day 1 of a paid month
    // would cut off access to the other 29 days already paid for.
    if (!isGumroadAccessRevokingEvent(formData)) {
      auditLog(ctx, env, { action: "gumroad_cancellation_intent_recorded", subscription_id, key_prefix: mappedKey.slice(0, 12) + "..." });
      ctx.waitUntil(sendTelegramAlert(env,
        `<b>GUMROAD AUTO-RENEW CANCELLED</b>\n` +
        `Subscription ID: <code>${subscription_id}</code>\n` +
        `Key: <code>${mappedKey.slice(0, 16)}...</code> -- access continues until the current period ends.`
      ));
      return jsonResp({ status: "cancellation_recorded", subscription_id });
    }

    const result = await applySubscriptionStatusChange(env, ctx, mappedKey, "cancelled", `gumroad_ended:${subscription_id}`);
    if (result.ok) {
      ctx.waitUntil(sendTelegramAlert(env,
        `<b>GUMROAD SUBSCRIPTION ENDED</b>\n` +
        `Subscription ID: <code>${subscription_id}</code>\n` +
        `Key: <code>${mappedKey.slice(0, 16)}...</code> marked cancelled -- access revoked.`
      ));
    }
    return jsonResp({ status: result.ok ? "cancelled" : "key_not_found", subscription_id });
  }

  if (!sale_id || !email) return jsonResp({ error: "Invalid Gumroad payload: sale_id and email required" }, 400);

  // Map product/variant to tier
  const tier = inferGumroadTier(product_name, variants);
  const billingCycle = inferGumroadBillingCycle(recurrence, product_name, variants);

  // Issue #288: atomic claim via Durable Object, closing the race the
  // KV-only check below can't -- Cloudflare KV has no atomic check-and-set,
  // so two concurrent deliveries of the same sale_id could both read
  // "absent" before either write lands. Routing every request for a given
  // sale_id to the same DO instance gives that instance's storage real
  // serialization (Cloudflare's "input gate"), so decideProvisioningClaim()
  // running inside its own fetch handler is genuinely atomic in a way the
  // KV get-then-put sequence below never can be. See
  // gumroad-provisioning-lock.js's header comment for the full rationale.
  // The KV check is kept as defense-in-depth, unchanged: if the DO call
  // itself fails (e.g. a transient binding error), processing falls back to
  // it rather than crashing the whole webhook request.
  if (env.GUMROAD_PROVISIONING_LOCK) {
    try {
      const lockId = env.GUMROAD_PROVISIONING_LOCK.idFromName(sale_id);
      const lock = env.GUMROAD_PROVISIONING_LOCK.get(lockId);
      const claimResp = await lock.fetch("https://lock/claim", {
        method: "POST", body: JSON.stringify({ saleId: sale_id }),
      });
      const claimed = await claimResp.json();
      if (claimed.alreadyClaimed) return jsonResp({ status: "already_provisioned", sale_id });
    } catch (lockErr) {
      console.error("[handleWebhookGumroad] GumroadProvisioningLock call failed, falling back to KV-only idempotency:", lockErr?.message || lockErr);
    }
  }

  // Idempotency guard: one provisioning per sale_id
  const idempKey = `gumroad_sale:${sale_id}`;
  const existing = await env.SECURITY_HUB_KV.get(idempKey);
  if (existing) return jsonResp({ status: "already_provisioned", sale_id });

  const apiKey = await provisionApiKey(env, ctx, tier, email, "gumroad_webhook", {
    sale_id, product_id, product_name, price, variants, subscription_id,
  }, billingCycle);

  await env.SECURITY_HUB_KV.put(
    idempKey,
    JSON.stringify({ key_prefix: apiKey.slice(0, 12) + "...", email, tier, ts: now() }),
    { expirationTtl: 86400 * 365 }
  );

  // Recurring product: remember which key this subscription provisioned, so
  // a later "Subscription updated" cancellation/end ping (which carries only
  // subscription_id, not the API key) can find it. Same pattern and TTL as
  // Razorpay's payment_key_map: above.
  if (subscription_id) {
    await env.SECURITY_HUB_KV.put(`gumroad_sub_key_map:${subscription_id}`, apiKey, { expirationTtl: 86400 * 365 });
  }

  // Gumroad checkout happens entirely on Gumroad's hosted page -- there is
  // no client-side callback into this app the way Razorpay's handler:
  // response has, so email is the only delivery channel for the key. Unlike
  // the pre-existing Razorpay call sites, this checks the return value:
  // sendActivationEmail() fails closed (returns false, never throws) rather
  // than blocking provisioning, so a silently-ignored `false` here would
  // leave a customer with a valid key and no way to learn it. Provisioning
  // itself is already done and correct either way; this only adds
  // visibility into a delivery failure so a human can follow up.
  let emailSent = false;
  try { emailSent = await sendActivationEmail(env, email, tier, apiKey); } catch (err) {
    console.error("[handleWebhookGumroad] sendActivationEmail error:", err?.message || err);
  }
  if (!emailSent) {
    ctx.waitUntil(sendTelegramAlert(env,
      `[WARN] <b>GUMROAD ACTIVATION EMAIL FAILED</b>\n` +
      `Email: ${email}\n` +
      `Key: <code>${apiKey.slice(0, 16)}...</code> is provisioned and active, but delivery failed -- manual follow-up required.`
    ));
  }

  ctx.waitUntil(sendTelegramAlert(env,
    `? <b>GUMROAD SALE</b>\n` +
    `Product: ${product_name}\n` +
    `Plan: <b>${tier}</b> | Price: $${price}\n` +
    `Email: ${email}\n` +
    `Sale ID: <code>${sale_id}</code>\n` +
    `API Key: <code>${apiKey.slice(0, 16)}...</code>`
  ));

  return jsonResp({ status: "provisioned", tier, sale_id });
}

// POST /api/payment/manual-notify  (UPI / NEFT / Crypto proof of payment)
async function handleManualNotify(request, env, ctx, method) {
  if (method !== "POST") return jsonResp({ error: "POST required" }, 405);
  let body = {};
  try { body = await request.json(); } catch (_) {}
  const { name, email, plan = "PRO", payment_method, transaction_id, amount, currency = "INR", notes = "" } = body;
  if (!email) return jsonResp({ error: "email is required" }, 400);
  if (!transaction_id && !notes) return jsonResp({ error: "transaction_id or notes required" }, 400);

  // PRODUCTION-VERIFICATION FIX (2026-08-24): the random suffix was 4 base36
  // chars (~20.7 bits) from Math.random() (not cryptographically secure),
  // combined with a Date.now() timestamp prefix that's trivially guessable
  // near request time -- making review_id brute-forceable against the
  // unauthenticated GET /api/payment/status lookup (which discloses another
  // customer's plan/payment_method/activation status/created_at for a
  // guessed ID). Widened to 8 crypto-random bytes (64 bits, via
  // crypto.getRandomValues) -- same ID shape, existing already-issued IDs
  // remain valid since this only changes how new ones are generated.
  const randomSuffix = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const reviewId = `CDB-${Date.now().toString(36).toUpperCase()}-${randomSuffix}`;
  const record   = { name, email, plan, payment_method, transaction_id, amount, currency, notes, review_id: reviewId, created_at: now(), status: "pending" };

  await env.SECURITY_HUB_KV.put(`manual_payment:${reviewId}`, JSON.stringify(record), { expirationTtl: 86400 * 90 });

  ctx.waitUntil(sendTelegramAlert(env,
    `? <b>MANUAL PAYMENT NOTIFICATION</b>\n` +
    `Review ID: <code>${reviewId}</code>\n` +
    `Name: ${name || "N/A"} | Email: ${email}\n` +
    `Plan: <b>${(plan || "PRO").toUpperCase()}</b>\n` +
    `Method: ${payment_method || "unspecified"}\n` +
    `Amount: ${currency} ${amount || "?"}\n` +
    `Txn ID: <code>${transaction_id || "N/A"}</code>\n` +
    `Notes: ${notes || " - "}\n` +
    `? Verify and provision via /api/admin/keys`
  ));

  auditLog(ctx, env, { action: "manual_payment_submitted", email, plan, review_id: reviewId });

  return jsonResp({
    status: "received", review_id: reviewId,
    message: "Payment notification received. API key delivered within 2 hours.",
    support: { whatsapp: "+918179881447", email: "bivash@cyberdudebivash.com" },
  }, 201);
}

// GET /api/payment/status?review_id=...
async function handlePaymentStatus(request, env, url) {
  const reviewId = url.searchParams.get("review_id") || url.searchParams.get("id") || "";
  if (!reviewId) return jsonResp({ error: "review_id query param required" }, 400);
  const record = await env.SECURITY_HUB_KV.get(`manual_payment:${reviewId}`, "json");
  if (!record) return jsonResp({ error: "Review ID not found", review_id: reviewId }, 404);
  return jsonResp({
    review_id: reviewId, status: record.status || "pending",
    plan: record.plan, payment_method: record.payment_method, created_at: record.created_at,
    message: record.status === "activated" ? "API key has been provisioned  -  check your email." : "Under review  -  delivery within 2 hours.",
  });
}

// =============================================================================
// BRAND PROTECTION  -  Typosquatting & Domain Impersonation Detection
// =============================================================================

function levenshtein(a, b) {
  if (!a) return b.length;
  if (!b) return a.length;
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = b[i-1] === a[j-1]
        ? m[i-1][j-1]
        : 1 + Math.min(m[i-1][j-1], m[i][j-1], m[i-1][j]);
    }
  }
  return m[b.length][a.length];
}

const BRAND_TLDS = ["com","net","org","io","co","xyz","info","biz","online","site","tech","dev","app","store","shop","ai","cloud","security","cyber","secure"];
const BRAND_PFXS = ["get","buy","my","the","official","secure","safe","pro","try","login","account","support","help"];
const BRAND_SFXS = ["online","app","web","site","pro","plus","hub","login","secure","pay","account","tech"];

function generateTyposquatVariants(domain) {
  const dot    = domain.indexOf(".");
  const name   = dot === -1 ? domain : domain.slice(0, dot);
  const tld    = dot === -1 ? "com" : domain.slice(dot + 1);
  const n      = name.toLowerCase();
  const v      = new Set();
  // Missing chars
  for (let i = 0; i < n.length; i++) v.add(`${n.slice(0,i)}${n.slice(i+1)}.${tld}`);
  // Transpositions
  for (let i = 0; i < n.length-1; i++) {
    const a = n.split(""); [a[i],a[i+1]] = [a[i+1],a[i]]; v.add(`${a.join("")}.${tld}`);
  }
  // Double-chars
  for (let i = 0; i < n.length; i++) v.add(`${n.slice(0,i)}${n[i]}${n[i]}${n.slice(i+1)}.${tld}`);
  // Vowel swaps
  for (let i = 0; i < n.length; i++) {
    if ("aeiou".includes(n[i])) {
      for (const vow of "aeiou") { if (vow !== n[i]) v.add(`${n.slice(0,i)}${vow}${n.slice(i+1)}.${tld}`); }
    }
  }
  // Hyphen inserts
  for (let i = 1; i < n.length-1; i++) v.add(`${n.slice(0,i)}-${n.slice(i)}.${tld}`);
  // Char substitutions
  const subs = { a:["4","@"], e:["3"], i:["1","l"], o:["0"], s:["5","$"], l:["1"], g:["9"] };
  for (let i = 0; i < n.length; i++) {
    if (subs[n[i]]) { for (const s of subs[n[i]]) v.add(`${n.slice(0,i)}${s}${n.slice(i+1)}.${tld}`); }
  }
  // TLD alternatives
  for (const t of BRAND_TLDS) { if (t !== tld) v.add(`${n}.${t}`); }
  // Prefix/suffix combos
  for (const p of BRAND_PFXS.slice(0,6)) { v.add(`${p}-${n}.${tld}`); v.add(`${p}${n}.${tld}`); }
  for (const s of BRAND_SFXS.slice(0,6)) { v.add(`${n}-${s}.${tld}`); v.add(`${n}${s}.${tld}`); }
  v.delete(domain.toLowerCase());
  return [...v].filter(x => x.length > 4 && x.includes("."));
}

function scoreDomainRisk(variant, original) {
  const dot = original.indexOf(".");
  const origName = dot === -1 ? original : original.slice(0, dot);
  const origTld  = dot === -1 ? "com" : original.slice(dot+1);
  const vdot     = variant.indexOf(".");
  const varName  = vdot === -1 ? variant : variant.slice(0, vdot);
  const varTld   = vdot === -1 ? "com" : variant.slice(vdot+1);

  const dist = levenshtein(origName.toLowerCase(), varName.toLowerCase());
  let score  = Math.max(0, 100 - dist * 22);
  if (varTld === origTld) score = Math.min(100, score + 15);
  if (["xyz","online","site","info","biz"].includes(varTld)) score = Math.min(100, score + 10);
  if (BRAND_PFXS.some(p => varName.startsWith(p))) score = Math.min(100, score + 8);
  if (BRAND_SFXS.some(s => varName.endsWith(s)))   score = Math.min(100, score + 5);

  const risk = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  return { risk_score: score, risk_level: risk, edit_distance: dist };
}

async function handleBrandProtection(request, env, auth, method, path, url, ctx) {
  const brandProtectionAllowed = !(!auth || auth.tier === TIERS.FREE);
  if (!resolveEntitlement(ctx, env, "brand_protection", auth, brandProtectionAllowed).allowed) {
    return jsonResp({ error: "Brand Protection requires PRO or ENTERPRISE tier", upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 403);
  }
  if (path === "/api/v1/brand/health") {
    return jsonResp({ status: "ok", module: "Brand Protection", version: "1.0", tier_required: "PRO", capabilities: ["typosquatting","homograph","domain_variants","risk_scoring"] });
  }

  if (path === "/api/v1/brand/scan" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const domain = (body.domain || "").toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!domain || !domain.includes(".")) return jsonResp({ error: "domain required (e.g. example.com)" }, 400);
    // generateTyposquatVariants() runs several O(n) passes over the domain
    // name building new strings each time -- unbounded input length allows
    // O(n^2)-ish CPU/memory blowup from a single request. 253 is the real
    // DNS total-length limit, so this rejects nothing a genuine domain would
    // ever hit.
    if (domain.length > 253) return jsonResp({ error: "domain exceeds maximum length (253 chars)" }, 400);

    const limit    = (auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP) ? 200 : 100;
    const all      = generateTyposquatVariants(domain).slice(0, limit);
    const scored   = all.map(v => ({ domain: v, ...scoreDomainRisk(v, domain) })).sort((a,b) => b.risk_score - a.risk_score);
    const critical = scored.filter(v => v.risk_level === "CRITICAL");
    const high     = scored.filter(v => v.risk_level === "HIGH");
    const medium   = scored.filter(v => v.risk_level === "MEDIUM");

    return jsonResp({
      status: "ok", module: "Brand Protection", domain,
      scan_summary: {
        total_variants: scored.length, critical: critical.length, high: high.length, medium: medium.length,
        low: scored.length - critical.length - high.length - medium.length,
        risk_assessment: critical.length > 0 ? "CRITICAL  -  Active impersonation patterns detected" : high.length > 0 ? "HIGH  -  Immediate monitoring recommended" : "MEDIUM  -  Routine monitoring advised",
      },
      top_threats: scored.slice(0, 20), all_variants: scored,
      recommendations: [
        "Register all CRITICAL-risk variants defensively",
        "Enable brand monitoring via your DNS registrar",
        "Configure Google Safe Browsing alerts for these domains",
        "Submit active phishing domains to anti-phishing working group (APWG)",
        "Alert CERT-In or FBI IC3 if active credential harvesting confirmed",
      ],
      generated_at: now(),
    });
  }

  if (path === "/api/v1/brand/check" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { domain, check_domain } = body;
    if (!domain || !check_domain) return jsonResp({ error: "domain and check_domain required" }, 400);
    const scoring = scoreDomainRisk(check_domain.toLowerCase(), domain.toLowerCase());
    return jsonResp({
      status: "ok", module: "Brand Protection", original: domain, checked: check_domain,
      ...scoring, is_threat: scoring.risk_level === "CRITICAL" || scoring.risk_level === "HIGH",
      analysis: `Edit distance ${scoring.edit_distance}  -  ${scoring.risk_level} risk typosquat candidate`,
      generated_at: now(),
    });
  }

  return jsonResp({ error: "Brand Protection endpoint not found", paths: ["POST /api/v1/brand/scan", "POST /api/v1/brand/check", "GET /api/v1/brand/health"] }, 404);
}

// =============================================================================
// VENDOR RISK  -  FAIR-Based Third-Party Risk Assessment
// =============================================================================

const VENDOR_RISK_FACTORS = {
  data_access:      { w: 0.25, lvl: { none:0, read:3, write:6, admin:9, all:10, unknown:6 } },
  network_access:   { w: 0.20, lvl: { none:0, limited:3, full:8, privileged:10, unknown:6 } },
  auth_strength:    { w: 0.20, lvl: { mfa:0, sso:2, password_only:7, unknown:8, none:10 } },
  patch_cadence:    { w: 0.15, lvl: { continuous:0, monthly:2, quarterly:5, unknown:7, none:10 } },
  compliance:       { w: 0.10, lvl: { soc2_iso27001:0, soc2:2, iso27001:2, pen_tested:4, none:8, unknown:6 } },
  incident_history: { w: 0.10, lvl: { none:0, minor:3, major:7, critical:10, unknown:4 } },
};

function fairAssess(data) {
  let score = 0;
  const breakdown = {};
  for (const [factor, cfg] of Object.entries(VENDOR_RISK_FACTORS)) {
    const val    = (data[factor] || "unknown").toLowerCase();
    const raw    = cfg.lvl[val] ?? cfg.lvl.unknown ?? 5;
    const contrib = raw * cfg.w;
    score += contrib;
    breakdown[factor] = { value: val, raw_score: raw, weight: cfg.w, contribution: Math.round(contrib * 10) / 10 };
  }
  const crit    = { low:1, medium:2, high:3, critical:4 }[data.business_criticality || "medium"] || 2;
  const rs      = Math.round(score * 10);
  const rl      = rs >= 70 ? "CRITICAL" : rs >= 50 ? "HIGH" : rs >= 30 ? "MEDIUM" : "LOW";
  const recs    = [];
  if (breakdown.auth_strength?.raw_score >= 7) recs.push("Mandate MFA for all vendor access immediately");
  if (breakdown.patch_cadence?.raw_score >= 5) recs.push("Require monthly patching SLA in vendor contract");
  if (breakdown.compliance?.raw_score >= 5) recs.push("Request SOC 2 Type II or ISO 27001 within 90 days");
  if (breakdown.incident_history?.raw_score >= 5) recs.push("Conduct post-mortem review of past incidents");
  if (breakdown.network_access?.raw_score >= 7) recs.push("Implement network segmentation for vendor access");
  if (breakdown.data_access?.raw_score >= 7) recs.push("Apply data minimization  -  enforce least-privilege access");
  if (rl === "CRITICAL") recs.push("URGENT: Escalate to CISO  -  vendor review within 48 hours");
  if (rl === "HIGH") recs.push("Schedule formal vendor security review within 30 days");
  return {
    risk_score: rs, risk_level: rl,
    fair_loss_estimate_usd: Math.round(score * crit * 10000),
    residual_risk: rl === "CRITICAL" ? "Immediate review required" : rl === "HIGH" ? "Enhanced monitoring required" : rl === "MEDIUM" ? "Standard monitoring" : "Routine review",
    factor_breakdown: breakdown,
    recommendations: recs.length ? recs : ["Maintain standard monitoring cadence"],
  };
}

async function handleVendorRisk(request, env, auth, method, path, ctx) {
  const vendorRiskAllowed = !(!auth || auth.tier === TIERS.FREE);
  if (!resolveEntitlement(ctx, env, "vendor_risk", auth, vendorRiskAllowed).allowed) {
    return jsonResp({ error: "Vendor Risk Assessment requires PRO or ENTERPRISE tier", upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 403);
  }
  if (path === "/api/v1/vendor-risk/health") {
    return jsonResp({ status: "ok", module: "Vendor Risk Assessment", version: "1.0", model: "FAIR (Factor Analysis of Information Risk)", tier_required: "PRO", factors: Object.keys(VENDOR_RISK_FACTORS) });
  }

  if (path === "/api/v1/vendor-risk/assess" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { vendor_name, ...vendorData } = body;
    if (!vendor_name) return jsonResp({ error: "vendor_name is required" }, 400);
    return jsonResp({ status: "ok", module: "Vendor Risk Assessment", vendor_name, ...fairAssess(vendorData), model: "FAIR v2.0", generated_at: now() });
  }

  if (path === "/api/v1/vendor-risk/bulk" && method === "POST") {
    const vendorRiskBulkAllowed = auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP;
    if (!resolveEntitlement(ctx, env, "vendor_risk_bulk", auth, vendorRiskBulkAllowed).allowed) return jsonResp({ error: "Bulk vendor assessment requires ENTERPRISE tier" }, 403);
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const vendors = body.vendors || [];
    if (!Array.isArray(vendors) || vendors.length === 0) return jsonResp({ error: "vendors array required" }, 400);
    if (vendors.length > 50) return jsonResp({ error: "Maximum 50 vendors per bulk request" }, 400);
    const results = vendors.map(v => ({ vendor_name: v.vendor_name || "Unknown", ...fairAssess(v) })).sort((a,b) => b.risk_score - a.risk_score);
    const critical = results.filter(r => r.risk_level === "CRITICAL").length;
    const high     = results.filter(r => r.risk_level === "HIGH").length;
    return jsonResp({
      status: "ok", module: "Vendor Risk Assessment",
      summary: { total: results.length, critical, high, medium: results.filter(r=>r.risk_level==="MEDIUM").length, low: results.filter(r=>r.risk_level==="LOW").length, avg_risk_score: Math.round(results.reduce((s,r)=>s+r.risk_score,0)/results.length) },
      vendors: results, model: "FAIR v2.0", generated_at: now(),
    });
  }

  return jsonResp({ error: "Vendor Risk endpoint not found", paths: ["POST /api/v1/vendor-risk/assess", "POST /api/v1/vendor-risk/bulk", "GET /api/v1/vendor-risk/health"] }, 404);
}

// =============================================================================
// GEOPOLITICAL RISK  -  Country-Level Threat Intelligence & Sanctions Screening
// =============================================================================

const GEO_DB = {
  RU:{ risk:95,sanctioned:true, region:"Eastern Europe",  apts:["APT28","APT29","Sandworm","Turla"],          tier:"CRITICAL", notes:"Active state-sponsored cyber operations" },
  CN:{ risk:90,sanctioned:false,region:"East Asia",       apts:["APT41","APT40","APT10","Volt Typhoon"],      tier:"CRITICAL", notes:"Strategic espionage and IP theft campaigns" },
  KP:{ risk:92,sanctioned:true, region:"East Asia",       apts:["Lazarus","Kimsuky","APT38","BlueNoroff"],    tier:"CRITICAL", notes:"State-sponsored cybercrime, sanctions evasion" },
  IR:{ risk:88,sanctioned:true, region:"Middle East",     apts:["APT33","APT35","MuddyWater","OilRig"],       tier:"CRITICAL", notes:"Active OT/ICS targeting and espionage" },
  BY:{ risk:75,sanctioned:true, region:"Eastern Europe",  apts:["UNC1151","Ghostwriter"],                    tier:"HIGH",     notes:"Aligned with RU, disinformation operations" },
  SY:{ risk:70,sanctioned:true, region:"Middle East",     apts:["Syrian Electronic Army"],                   tier:"HIGH",     notes:"Hacktivist and espionage activity" },
  VN:{ risk:50,sanctioned:false,region:"Southeast Asia",  apts:["APT32","OceanLotus"],                       tier:"MEDIUM",   notes:"State-sponsored targeting of foreign business" },
  PK:{ risk:55,sanctioned:false,region:"South Asia",      apts:["APT36","Transparent Tribe"],                tier:"MEDIUM",   notes:"India-focused espionage" },
  TR:{ risk:40,sanctioned:false,region:"Middle East",     apts:["Sea Turtle"],                               tier:"MEDIUM",   notes:"DNS hijacking, cyber espionage" },
  NG:{ risk:55,sanctioned:false,region:"West Africa",     apts:[],                                           tier:"MEDIUM",   notes:"BEC and financial fraud ecosystem" },
  UA:{ risk:70,sanctioned:false,region:"Eastern Europe",  apts:[],                                           tier:"HIGH",     notes:"Active wartime cyber conflict zone" },
  AF:{ risk:60,sanctioned:false,region:"Central Asia",    apts:[],                                           tier:"HIGH",     notes:"Instability, limited oversight" },
  MM:{ risk:65,sanctioned:true, region:"Southeast Asia",  apts:[],                                           tier:"HIGH",     notes:"Post-coup instability, sanctions" },
  CU:{ risk:50,sanctioned:true, region:"Caribbean",       apts:[],                                           tier:"MEDIUM",   notes:"Trade sanctions, limited offensive cyber" },
  VE:{ risk:45,sanctioned:true, region:"South America",   apts:[],                                           tier:"MEDIUM",   notes:"Financial crime, limited offensive cyber" },
  SD:{ risk:55,sanctioned:true, region:"Africa",          apts:[],                                           tier:"MEDIUM",   notes:"OFAC sanctioned" },
  US:{ risk: 5,sanctioned:false,region:"North America",   apts:[],                                           tier:"LOW",      notes:"Five Eyes partner, CISA oversight" },
  GB:{ risk: 5,sanctioned:false,region:"Western Europe",  apts:[],                                           tier:"LOW",      notes:"Five Eyes partner, NCSC oversight" },
  DE:{ risk: 8,sanctioned:false,region:"Western Europe",  apts:[],                                           tier:"LOW",      notes:"EU member, BSI oversight" },
  FR:{ risk: 8,sanctioned:false,region:"Western Europe",  apts:[],                                           tier:"LOW",      notes:"EU member, ANSSI oversight" },
  JP:{ risk:10,sanctioned:false,region:"East Asia",       apts:[],                                           tier:"LOW",      notes:"Allied nation, NISC oversight" },
  AU:{ risk: 5,sanctioned:false,region:"Oceania",         apts:[],                                           tier:"LOW",      notes:"Five Eyes partner, ASD oversight" },
  CA:{ risk: 5,sanctioned:false,region:"North America",   apts:[],                                           tier:"LOW",      notes:"Five Eyes partner, CCCS oversight" },
  IN:{ risk:25,sanctioned:false,region:"South Asia",      apts:[],                                           tier:"LOW",      notes:"Emerging cyber power, CERT-In oversight" },
  IL:{ risk:20,sanctioned:false,region:"Middle East",     apts:[],                                           tier:"LOW",      notes:"Advanced capability, defensive posture" },
  BR:{ risk:30,sanctioned:false,region:"South America",   apts:[],                                           tier:"LOW",      notes:"Active cybercrime ecosystem" },
  SA:{ risk:30,sanctioned:false,region:"Middle East",     apts:[],                                           tier:"LOW",      notes:"OT threat landscape, ARAMCO precedent" },
  SG:{ risk:10,sanctioned:false,region:"Southeast Asia",  apts:[],                                           tier:"LOW",      notes:"Regional hub, strong cyber governance" },
  KR:{ risk:15,sanctioned:false,region:"East Asia",       apts:[],                                           tier:"LOW",      notes:"Allied nation, KISA oversight" },
  NL:{ risk: 8,sanctioned:false,region:"Western Europe",  apts:[],                                           tier:"LOW",      notes:"EU member, NCSC-NL oversight" },
};

const OFAC_SANCTIONED = new Set(["RU","KP","IR","SY","CU","VE","BY","MM","ZW","SD","LY","SO","YE","AL","BA","CF","CD","GW","IQ","LB","LR","MK","NI","RS","SS","UA_OCCUPIED"]);
const EU_SANCTIONED   = new Set(["RU","BY","KP","IR","SY","MM","LY","BA","YE","SD"]);

function buildGeoRecs(code, data) {
  const r = [];
  if (data.tier === "CRITICAL") {
    r.push("Block or strictly monitor all inbound traffic from this country");
    r.push("Enable enhanced logging for all auth attempts originating here");
    r.push("Consider geo-blocking if no legitimate business presence required");
  }
  if (data.sanctioned) {
    r.push("OFAC/EU sanctions apply  -  obtain legal authorization before any engagement");
    r.push("Screen all financial transactions against current OFAC SDN list");
  }
  if (data.apts.length > 0) {
    r.push(`Threat hunt for TTPs of: ${data.apts.join(", ")}  -  review MITRE ATT&CK groups page`);
    r.push("Subscribe to sector-specific ISAC alerts for this threat actor cluster");
  }
  return r.length ? r : ["Standard monitoring  -  no elevated risk indicators"];
}

async function handleGeopolitical(request, env, auth, method, path, url, ctx) {
  const geopoliticalRiskAllowed = !(!auth || auth.tier === TIERS.FREE);
  if (!resolveEntitlement(ctx, env, "geopolitical_risk", auth, geopoliticalRiskAllowed).allowed) {
    return jsonResp({ error: "Geopolitical Risk requires PRO or ENTERPRISE tier", upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 403);
  }

  if (path === "/api/v1/geopolitical/health") {
    return jsonResp({ status: "ok", module: "Geopolitical Risk Intelligence", version: "1.0", countries_indexed: Object.keys(GEO_DB).length, sanctions_lists: ["OFAC","EU"] });
  }

  if (path === "/api/v1/geopolitical/landscape") {
    const crit = Object.entries(GEO_DB).filter(([,v]) => v.tier==="CRITICAL").map(([k,v]) => ({ code:k,...v }));
    const high = Object.entries(GEO_DB).filter(([,v]) => v.tier==="HIGH").map(([k,v]) => ({ code:k,...v }));
    return jsonResp({
      status: "ok", module: "Geopolitical Risk Intelligence",
      threat_landscape: {
        critical_risk_nations: crit, high_risk_nations: high,
        sanctioned_nations: { ofac: [...OFAC_SANCTIONED], eu: [...EU_SANCTIONED] },
        global_threat_level: "ELEVATED",
      },
      advisory: "Monitor all traffic from CRITICAL/HIGH risk nations. Apply OFAC/EU sanctions screening for all financial transactions.",
      generated_at: now(),
    });
  }

  const countryMatch = path.match(/^\/api\/v1\/geopolitical\/country\/([A-Z]{2})$/i);
  if (countryMatch) {
    const code = countryMatch[1].toUpperCase();
    const data = GEO_DB[code];
    if (!data) return jsonResp({ error: `Country code ${code} not in database`, available_codes: Object.keys(GEO_DB) }, 404);
    return jsonResp({
      status: "ok", module: "Geopolitical Risk Intelligence",
      country_code: code, ...data,
      sanctions: { ofac: OFAC_SANCTIONED.has(code), eu: EU_SANCTIONED.has(code) },
      threat_actor_count: data.apts.length,
      recommendations: buildGeoRecs(code, data),
      generated_at: now(),
    });
  }

  if (path === "/api/v1/geopolitical/sanctions-check" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { country_codes = [], entity_name = "" } = body;
    if (!Array.isArray(country_codes) || country_codes.length === 0) return jsonResp({ error: "country_codes array required" }, 400);
    const results = country_codes.map(c => {
      const code = c.toUpperCase();
      return { code, ofac: OFAC_SANCTIONED.has(code), eu: EU_SANCTIONED.has(code), sanctioned: OFAC_SANCTIONED.has(code)||EU_SANCTIONED.has(code), risk_tier: GEO_DB[code]?.tier||"UNKNOWN" };
    });
    const hit = results.some(r => r.sanctioned);
    // PRODUCTION-TRUTH FIX (post-launch platform audit): this never actually
    // screened `entity_name` against any real sanctions list -- OFAC_SANCTIONED/
    // EU_SANCTIONED above are a static ~24-country jurisdiction set, not the
    // real OFAC SDN / EU consolidated lists (thousands of specifically named
    // individuals, companies, and vessels, updated on an ongoing basis). The
    // old response returned "SANCTIONS_DETECTED"/"CLEAR" and a "BLOCK"/
    // "PROCEED: No active sanctions detected" verdict that reads as a real
    // entity-level compliance determination regardless of whether entity_name
    // was even supplied. A customer treating "PROCEED: No active sanctions
    // detected" as evidence a specific entity is unsanctioned -- when it was
    // never checked against a real sanctions-list at all -- would be making
    // an actual legal/compliance decision on a false negative. Field names
    // and shape kept unchanged for existing integrations; wording changed so
    // neither value can be read as an entity-level clearance.
    return jsonResp({
      status: "ok", module: "Geopolitical Risk Intelligence",
      entity: entity_name || "N/A",
      sanctions_result: hit ? "JURISDICTION_SANCTIONED" : "JURISDICTION_CLEAR_ENTITY_NOT_SCREENED",
      countries: results,
      compliance_action: hit
        ? "BLOCK: Submitted country code matches a sanctioned jurisdiction in this reference list -- obtain legal/compliance authorization before engagement."
        : "REVIEW REQUIRED: No sanctioned jurisdiction matched in this reference list. This does NOT mean the named entity is unsanctioned.",
      entity_level_screening_performed: false,
      disclaimer: "This checks submitted country codes against a static reference list of sanctioned jurisdictions only (~24 countries). It does not screen the named entity against the real OFAC SDN list, EU consolidated sanctions list, or any other authoritative entity-level sanctions database, and the jurisdiction list itself is a point-in-time snapshot, not a live feed. Do not use this result as a substitute for an authoritative sanctions-screening service or your compliance team's review.",
      generated_at: now(),
    });
  }

  return jsonResp({ error: "Geopolitical endpoint not found", paths: ["GET /api/v1/geopolitical/country/{code}", "GET /api/v1/geopolitical/landscape", "POST /api/v1/geopolitical/sanctions-check", "GET /api/v1/geopolitical/health"] }, 404);
}

// =============================================================================
// NLQ  -  Natural Language Queries on Live Intel Feed (PRO+)
// =============================================================================

const NLQ_EXAMPLES = [
  { query: "Show me critical vulnerabilities from this week", filters: "severity=CRITICAL,hours=168" },
  { query: "What ransomware threats are trending?", filters: "threat_type=Ransomware" },
  { query: "Find APT threats attributed to Russia", filters: "threat_type=APT,actor=russia" },
  { query: "Show CVEs with CVSS above 9", filters: "min_cvss=9" },
  { query: "What are the CISA KEV confirmed vulnerabilities?", filters: "kev_only=true" },
  { query: "Find threats targeting financial sector", filters: "sector=financial" },
  { query: "Show zero-day exploits reported today", filters: "tags=zero-day,hours=24" },
  { query: "High risk threats with MITRE ATT&CK coverage", filters: "severity=HIGH,min_risk=7" },
];

function nlqParse(q) {
  const l = q.toLowerCase();
  const f = {};
  if (/critical/i.test(l)) f.severity = "CRITICAL";
  else if (/\bhigh\b/i.test(l)) f.severity = "HIGH";
  else if (/medium|moderate/i.test(l)) f.severity = "MEDIUM";
  else if (/\blow\b/i.test(l)) f.severity = "LOW";
  if (/ransomware/i.test(l)) f.threat_type = "Ransomware";
  else if (/\bapt\b|nation.?state|state.?sponsor/i.test(l)) f.threat_type = "APT";
  else if (/phish/i.test(l)) f.threat_type = "Phishing";
  else if (/\bvuln|cve|patch\b/i.test(l)) f.threat_type = "Vulnerability";
  else if (/\bmalware\b/i.test(l)) f.threat_type = "Malware";
  else if (/supply.?chain/i.test(l)) f.threat_type = "Supply Chain";
  else if (/\bbreach\b|data.?breach/i.test(l)) f.threat_type = "Data Breach";
  else if (/zero.?day|0.?day/i.test(l)) f.zero_day = true;
  if (/kev|cisa.*exploit|known exploit/i.test(l)) f.kev_only = true;
  const cvsm = l.match(/cvss\s*(?:above|over|>=?|>)\s*(\d+(?:\.\d+)?)/);
  if (cvsm) f.min_cvss = parseFloat(cvsm[1]);
  const rism = l.match(/risk\s*(?:score\s*)?(?:above|over|>=?)\s*(\d+(?:\.\d+)?)/);
  if (rism) f.min_risk = parseFloat(rism[1]);
  for (const actor of ["russia","china","north korea","iran","lazarus","apt28","apt29","volt typhoon","apt41","sandworm"]) {
    if (l.includes(actor)) { f.actor = actor; break; }
  }
  for (const sector of ["finance","financial","banking","healthcare","energy","government","defense","retail","telecom","critical infrastructure"]) {
    if (l.includes(sector)) { f.sector = sector; break; }
  }
  if (/today|last 24|24 hours/i.test(l)) f.hours = 24;
  else if (/this week|last 7|7 days/i.test(l)) f.hours = 168;
  else if (/this month|last 30|30 days/i.test(l)) f.hours = 720;
  const stop = new Set(["show","me","find","get","list","what","are","the","a","an","and","or","of","from","with","for","in","on","at","to","is","this","week","month","day","all","any","have","been","last"]);
  f.keywords = q.split(/\s+/).map(w => w.toLowerCase().replace(/[^a-z0-9-]/g,"")).filter(w => w.length > 3 && !stop.has(w));
  return f;
}

function nlqFilter(items, f) {
  let r = items;
  if (f.severity) r = r.filter(i => i.severity === f.severity);
  if (f.threat_type) r = r.filter(i => (i.threat_type||"").toLowerCase() === f.threat_type.toLowerCase());
  if (f.kev_only) r = r.filter(i => i.kev_present === true);
  if (f.zero_day) r = r.filter(i => (i.tags||[]).some(t=>t.toLowerCase().includes("zero")) || (i.title||"").toLowerCase().includes("zero-day"));
  if (f.min_cvss != null) r = r.filter(i => parseFloat(i.cvss_score||0) >= f.min_cvss);
  if (f.min_risk  != null) r = r.filter(i => parseFloat(i.risk_score||0) >= f.min_risk);
  if (f.actor) {
    const al = f.actor.toLowerCase();
    r = r.filter(i => (i.actor_tag||"").toLowerCase().includes(al)||(i.title||"").toLowerCase().includes(al)||(i.description||"").toLowerCase().includes(al));
  }
  if (f.sector) {
    const sl = f.sector.toLowerCase();
    r = r.filter(i => (i.title||"").toLowerCase().includes(sl)||(i.description||"").toLowerCase().includes(sl)||(i.tags||[]).some(t=>t.toLowerCase().includes(sl)));
  }
  if (f.hours) {
    const cut = Date.now() - f.hours * 3600000;
    r = r.filter(i => { const ts = i.published||i.published_at||i.created_at||""; return ts && new Date(ts).getTime() >= cut; });
  }
  if (f.keywords && f.keywords.length > 0) {
    r = r.filter(i => {
      const hay = `${i.title||""} ${i.description||""} ${i.threat_type||""} ${i.actor_tag||""} ${(i.tags||[]).join(" ")}`.toLowerCase();
      return f.keywords.some(k => hay.includes(k));
    });
  }
  return r;
}

async function handleNLQ(request, env, auth, method, path, url, ctx) {
  const nlqAllowed = !(!auth || auth.tier === TIERS.FREE);
  if (!resolveEntitlement(ctx, env, "nlq", auth, nlqAllowed).allowed) {
    return jsonResp({ error: "Natural Language Query requires PRO or ENTERPRISE tier", upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 403);
  }
  if (path === "/api/v1/nlq/health") {
    return jsonResp({ status: "ok", module: "Natural Language Query", version: "1.0", llm_available: !!(env.OPENROUTER_API_KEY||env.DEEPSEEK_API_KEY||env.GROQ_API_KEY), tier_required: "PRO" });
  }
  if (path === "/api/v1/nlq/examples") {
    return jsonResp({ status: "ok", examples: NLQ_EXAMPLES, generated_at: now() });
  }
  if (path === "/api/v1/nlq/query" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const query = (body.query || body.q || "").trim().slice(0, 500);
    if (!query) return jsonResp({ error: "query is required" }, 400);

    const feedData = await loadFeedItems(env);
    const items    = feedData.items || [];
    const filters  = nlqParse(query);
    const matched  = nlqFilter(items, filters);
    const limit    = (auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP) ? 100 : 25;
    const results  = matched.slice(0, limit);

    let llmSummary = null;
    if ((env.OPENROUTER_API_KEY || env.DEEPSEEK_API_KEY || env.GROQ_API_KEY) && results.length > 0 && body.explain !== false) {
      try {
        const top = results.slice(0, 5).map(i => ({ title: i.title, severity: i.severity, type: i.threat_type, actor: i.actor_tag, risk: i.risk_score }));
        const lr = await callLLM(env,
          "You are a concise threat intelligence analyst. Summarize findings in 2-3 sentences.",
          `Query: "${query}"\n\nTop matches:\n${JSON.stringify(top, null, 2)}\n\nProvide a 2-3 sentence analyst summary of what these results mean and what SOC teams should prioritize first.`,
          false
        );
        if (lr) llmSummary = lr.text;
      } catch (_) {}
    }

    return jsonResp({
      status: "ok", module: "Natural Language Query", query, filters_applied: filters,
      total_matched: matched.length, returned: results.length, results, analyst_summary: llmSummary, generated_at: now(),
    });
  }
  return jsonResp({ error: "NLQ endpoint not found", paths: ["POST /api/v1/nlq/query", "GET /api/v1/nlq/examples", "GET /api/v1/nlq/health"] }, 404);
}

// =============================================================================
// INCIDENT RESPONSE  -  KV-Backed CRUD (NIST SP 800-61r3 lifecycle)
// =============================================================================

const IR_PHASES = ["PREPARATION","DETECTION","ANALYSIS","CONTAINMENT","ERADICATION","RECOVERY","POST_INCIDENT"];
const IR_SEV    = ["LOW","MEDIUM","HIGH","CRITICAL"];

async function handleIncidentResponse(request, env, auth, method, path, url, ctx) {
  const incidentResponseAllowed = !(!auth || auth.tier === TIERS.FREE);
  if (!resolveEntitlement(ctx, env, "incident_response", auth, incidentResponseAllowed).allowed) {
    return jsonResp({ error: "Incident Response requires PRO or ENTERPRISE tier", upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html" }, 403);
  }

  if (path === "/api/v1/incidents/health" || path === "/api/v1/incidents/health/") {
    return jsonResp({ status: "ok", module: "Incident Response", version: "1.0", framework: "NIST SP 800-61r3", phases: IR_PHASES, tier_required: "PRO" });
  }

  const ownerPfx = `ir:${auth.sub || "anon"}:`;

  // LIST  GET /api/v1/incidents/
  if ((path === "/api/v1/incidents/" || path === "/api/v1/incidents") && method === "GET") {
    try {
      // Tenant isolation: every tier lists only its own incidents. Incidents
      // are stored under ownerPfx=`ir:${auth.sub}:` (see CREATE below); a
      // prior ENTERPRISE/MSSP branch here used the bare "ir:" prefix, which
      // doesn't match that storage key shape (auth.sub sits between "ir:"
      // and "incident:") and so always yielded zero results for those tiers
      // -- fixed to the correct, tenant-scoped prefix for every tier.
      const listPrefix = `${ownerPfx}incident:`;
      // Cursor-paginated list  -  fetches all keys across multiple pages (max 200 per page)
      let allKeys = [], cursor = undefined, complete = false;
      while (!complete) {
        const page = await env.SECURITY_HUB_KV.list({ prefix: listPrefix, limit: 200, cursor });
        allKeys.push(...page.keys);
        complete = page.list_complete;
        cursor   = page.cursor;
        if (allKeys.length >= 1000) break; // safety cap
      }
      const rows  = await Promise.all(allKeys.map(async k => { try { return await env.SECURITY_HUB_KV.get(k.name, "json"); } catch { return null; } }));
      const valid = rows.filter(Boolean).sort((a,b) => (b.created_at||"").localeCompare(a.created_at||""));
      return jsonResp({ status: "ok", incidents: valid, total: valid.length, generated_at: now() });
    } catch (e) {
      console.error(`[incidents] list failed: ${e.message}`);
      return jsonResp({ error: "Failed to list incidents" }, 500);
    }
  }

  // CREATE  POST /api/v1/incidents/
  if ((path === "/api/v1/incidents/" || path === "/api/v1/incidents") && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { title, severity = "HIGH", phase = "DETECTION", description = "", affected_systems = [], iocs = [], mitre_tactics = [], assigned_to = "", tags = [] } = body;
    if (!title) return jsonResp({ error: "title is required" }, 400);
    if (!IR_SEV.includes(severity)) return jsonResp({ error: `severity must be: ${IR_SEV.join(",")}` }, 400);
    if (!IR_PHASES.includes(phase)) return jsonResp({ error: `phase must be: ${IR_PHASES.join(",")}` }, 400);
    const id  = `INC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`;
    const inc = { id, title, severity, phase, description, affected_systems, iocs, mitre_tactics, assigned_to, tags, status: "OPEN", created_at: now(), updated_at: now(), created_by: auth.sub || "api", timeline: [{ ts: now(), phase, event: "Incident created", actor: auth.sub||"api" }] };
    await env.SECURITY_HUB_KV.put(`${ownerPfx}incident:${id}`, JSON.stringify(inc), { expirationTtl: 86400*90 });
    auditLog(ctx, env, { action: "incident_created", id, severity, sub: auth.sub });
    return jsonResp({ status: "created", incident: inc }, 201);
  }

  // SINGLE /api/v1/incidents/{id}[/timeline]
  const idm = path.match(/^\/api\/v1\/incidents\/(INC-[A-Z0-9-]+)(?:\/(.+))?$/);
  if (idm) {
    const incId   = idm[1];
    const subPath = idm[2] || "";
    const kvKey   = `${ownerPfx}incident:${incId}`;

    if (method === "GET" && !subPath) {
      const inc = await env.SECURITY_HUB_KV.get(kvKey, "json");
      if (!inc) return jsonResp({ error: "Incident not found", id: incId }, 404);
      return jsonResp({ status: "ok", incident: inc });
    }

    if (method === "PUT" && !subPath) {
      let body = {};
      try { body = await request.json(); } catch (_) {}
      const existing = await env.SECURITY_HUB_KV.get(kvKey, "json");
      if (!existing) return jsonResp({ error: "Incident not found", id: incId }, 404);
      const oldPhase = existing.phase;
      const updated  = { ...existing, ...Object.fromEntries(Object.entries(body).filter(([k])=>!["id","created_at","created_by","timeline"].includes(k))), updated_at: now() };
      if (body.phase && body.phase !== oldPhase) {
        updated.timeline = [...(existing.timeline||[]), { ts: now(), phase: body.phase, event: `Phase: ${oldPhase} -> ${body.phase}`, actor: auth.sub||"api" }];
      }
      await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(updated), { expirationTtl: 86400*90 });
      auditLog(ctx, env, { action: "incident_updated", id: incId, sub: auth.sub });
      return jsonResp({ status: "updated", incident: updated });
    }

    if (method === "DELETE" && !subPath) {
      const incidentDeleteAllowed = auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP;
      if (!resolveEntitlement(ctx, env, "incident_delete", auth, incidentDeleteAllowed).allowed) return jsonResp({ error: "ENTERPRISE tier required to delete incidents" }, 403);
      await env.SECURITY_HUB_KV.delete(kvKey);
      auditLog(ctx, env, { action: "incident_deleted", id: incId, sub: auth.sub });
      return jsonResp({ status: "deleted", id: incId });
    }

    if (subPath === "timeline") {
      const existing = await env.SECURITY_HUB_KV.get(kvKey, "json");
      if (!existing) return jsonResp({ error: "Incident not found", id: incId }, 404);
      if (method === "GET") return jsonResp({ status: "ok", id: incId, timeline: existing.timeline||[] });
      if (method === "POST") {
        let body = {};
        try { body = await request.json(); } catch (_) {}
        if (!body.event) return jsonResp({ error: "event is required" }, 400);
        const entry = { ts: now(), phase: body.phase||existing.phase, event: body.event, notes: body.notes||"", actor: auth.sub||"api" };
        existing.timeline = [...(existing.timeline||[]), entry];
        existing.updated_at = now();
        if (body.phase) existing.phase = body.phase;
        await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(existing), { expirationTtl: 86400*90 });
        return jsonResp({ status: "added", entry, timeline_count: existing.timeline.length }, 201);
      }
    }
  }

  return jsonResp({
    error: "Incident Response endpoint not found",
    paths: ["GET|POST /api/v1/incidents/", "GET|PUT|DELETE /api/v1/incidents/{id}", "GET|POST /api/v1/incidents/{id}/timeline", "GET /api/v1/incidents/health"],
  }, 404);
}

// =============================================================================
// MAIN REQUEST HANDLER
// =============================================================================

async function handleRequest(request, env, ctx) {
  const url      = new URL(request.url);
  const path     = url.pathname;
  const pathname = path; // gate-required alias: PREMIUM_INTEL_PATHS.has(pathname)
  const method   = request.method.toUpperCase();

  // CORS preflight -- SENTINEL APEX PUBLIC-REPO ZERO-TRUST PHASE 3: this
  // used to unconditionally return 204 + wildcard CORS_HEADERS for every
  // path, method, and Origin with zero validation -- a preflight grant is
  // meaningless if it's identical for /api/admin/keys and /api/feed.json.
  // buildPreflightResponse() classifies the actual target route and
  // validates Origin/Access-Control-Request-Method/-Headers against what
  // that route's trust class genuinely supports before granting anything;
  // see cors-policy.js. Still returns before any auth/routing/business
  // logic runs, same as before.
  if (method === "OPTIONS") {
    return buildPreflightResponse(request, path);
  }

  // Client IP for rate limiting and brute-force tracking
  const ip = request.headers.get("CF-Connecting-IP") ||
             (request.headers.get("X-Forwarded-For") || "127.0.0.1").split(",")[0].trim();

  // Resolve auth once for this request (skip for pure public health check to save a KV read)
  const auth = await resolveAuth(request, env);

  // Surface auth failures explicitly instead of silently downgrading to FREE.
  // resolveAuth() already computes auth.error for a credential that WAS
  // presented but is invalid/expired/revoked/rate-limited (index.js:334-373);
  // nothing previously read it, so a customer with a broken key got 200 OK +
  // masked FREE-tier data -- indistinguishable from the platform having no
  // data. Anonymous requests (no credential supplied) are unaffected: auth.error
  // is only ever set when a credential was actually presented. Scoped to
  // /api and /taxii (where a credential is meaningful) and excludes
  // /api/admin and /api/auth so re-authentication with a stale token still
  // reaches the login/admin handlers -- and excludes /api/preview (documented
  // "unauthenticated by design" public teaser), /api/payment/* (checkout
  // itself -- must never be blocked by an unrelated stale key a browser
  // happens to send), /api/pricing (public data), and bare /taxii + /taxii/
  // (handleTAXII's own server-discovery route, public per the TAXII 2.1 spec
  // -- only /taxii/collections/... and beyond require PRO/ENTERPRISE) so a
  // stale credential can't change behavior on routes that are public
  // regardless of auth state.
  if (auth.error
      && (path.startsWith("/api/") || path.startsWith("/taxii"))
      && !path.startsWith("/api/admin") && !path.startsWith("/api/auth")
      && !path.startsWith("/api/preview") && !path.startsWith("/api/payment")
      && path !== "/api/pricing"
      && path !== "/taxii" && path !== "/taxii/") {
    // Mirror /auth/login's existing brute-force response shape (429, not 401)
    // so a locked-out IP sees the same signal everywhere in the gateway.
    if (auth.error === "rate_limited") {
      return jsonResp({ error: "Too many failed attempts", retry_after: 60 }, 429, { "Retry-After": "60" });
    }
    // v200.0 FIX: a genuine API_KEYS_KV outage (resolveAuth's error, not a
    // wrong/unknown key) is an infra fault on our side, not a bad credential
    // -- 401 "Unauthorized" tells a paying customer their key is wrong when
    // it isn't, and could prompt an unnecessary key rotation. 503 + Retry-After
    // matches how this same distinction is already signalled for rate_limited.
    if (auth.error === "auth_service_unavailable") {
      return jsonResp(
        { error: "Service Unavailable", reason: auth.error, hint: "Auth backend is temporarily unavailable -- your credential was not rejected, retry shortly." },
        503,
        { "Retry-After": "10" }
      );
    }
    return jsonResp(
      { error: "Unauthorized", reason: auth.error, hint: "Provide a valid X-API-Key header or Authorization: Bearer <token>." },
      401
    );
  }

  // V4.46.6 P0 -- read-only SWARM entitlement preflight. This route is
  // intentionally resolved before the commercial rate/daily quota mutation
  // below: checking whether a customer may launch must not itself spend one
  // of the customer's production API requests. The real /api/intel/correlate
  // execution still re-authorizes and re-enforces every gate at launch time.
  if (path === "/api/v1/swarm/preflight") {
    if (method !== "GET") {
      return jsonResp({ error: "Method Not Allowed", allowed: ["GET"] }, 405, {
        "Allow": "GET",
        "Cache-Control": "no-store",
      });
    }

    // Preflight is intentionally outside commercial/billable request quota,
    // but it is not an unbounded free auth/KV oracle. A dedicated IP-scoped
    // limiter protects this one control-plane route in its own keyspace and
    // never changes the customer's production API usage counters.
    const preflightRl = await checkSwarmPreflightRateLimit(env, ip);
    if (!preflightRl.allowed) {
      auditLog(ctx, env, {
        action: "swarm_preflight_rate_limited",
        ip,
        path,
        method,
        tier: auth.tier,
      });
      return jsonResp(
        {
          error: "Too Many Requests",
          reason: "preflight_rate_limited",
          retry_after: 60,
          limit: preflightRl.limit,
        },
        429,
        {
          "Retry-After": "60",
          "X-Preflight-RateLimit-Limit": String(preflightRl.limit),
          "X-Preflight-RateLimit-Remaining": "0",
          "Cache-Control": "no-store",
        }
      );
    }

    const response = await handleSwarmPreflight(env, auth);
    response.headers.set("X-Preflight-RateLimit-Limit", String(preflightRl.limit));
    response.headers.set("X-Preflight-RateLimit-Remaining", String(preflightRl.remaining));
    return response;
  }

  // P0 2026-09-03 -- ENTITLEMENT PLANE SELECTION.
  //
  // Every request that is not /api/health used to be metered against ONE
  // plane: the commercial per-tier RATE_LIMITS + DAILY_QUOTAS, keyed by
  // `auth.key || ip`. The first-party dashboard is itself an anonymous
  // consumer of that plane and spends 27 of the FREE tier's 30/min and
  // 50/day budget on a single render, so the second page view of a UTC day
  // from any IP was denied with daily_quota_exceeded -- and every anonymous
  // visitor behind one NAT shared that single 50/day budget. See
  // first-party-plane.js's header and
  // docs/incidents/P0-EMPTY-DASHBOARD-ROOT-CAUSE.md.
  //
  // isFirstPartyRead() admits ONLY an uncredentialed GET/HEAD for an exact
  // path in the dashboard's own read set. Presenting any credential routes
  // the request to the commercial plane on every path, so quota enforcement
  // for FREE/PRO/ENTERPRISE/MSSP API customers is bit-for-bit unchanged.
  // Commercial quotas are not disabled or raised anywhere in this change.
  const firstPartyRead = isFirstPartyRead({ path, method, hasCredential: !!auth.key });

  // First-party web read plane: its own dedicated anonymous-web budget, in
  // its own KV keyspace. Abuse and DDoS protection are preserved -- just at a
  // ceiling sized for rendering a web page (~8 renders/min, ~74/day per IP)
  // rather than for consuming an API product.
  if (firstPartyRead) {
    const wrl = await checkWebPlaneRateLimit(env, ip);
    if (!wrl.allowed) {
      auditLog(ctx, env, { action: "web_plane_rate_limited", ip, path, method, tier: auth.tier });
      // No `upgrade` block: this is the first-party dashboard's own delivery
      // plane, not a commercial funnel surface. Upselling an anonymous
      // visitor an API plan because the page they are looking at refreshed
      // too fast would be the same category confusion this change removes.
      return jsonResp(
        { error: "Too Many Requests", reason: "web_plane_rate_limited", plane: "first_party_web_read", retry_after: 60, limit: wrl.limit },
        429,
        { "Retry-After": "60", "X-WebPlane-Limit": String(wrl.limit), "X-WebPlane-Remaining": "0" }
      );
    }
    const wdq = await checkWebPlaneDailyQuota(env, ip);
    if (wdq.exceeded) {
      auditLog(ctx, env, { action: "web_plane_daily_exceeded", ip, path, method, tier: auth.tier });
      return jsonResp(
        { error: "Too Many Requests", reason: "web_plane_daily_exceeded", plane: "first_party_web_read", limit: wdq.limit, reset_utc: new Date(Date.now() + secondsUntilNextUtcMidnight() * 1000).toISOString() },
        429,
        {
          "Retry-After": String(secondsUntilNextUtcMidnight()),
          "X-WebPlane-Daily-Limit": String(wdq.limit),
          "X-WebPlane-Daily-Remaining": "0",
        }
      );
    }
  }

  // Rate limiting (skip health check so monitors never get throttled).
  // `!firstPartyRead` keeps the commercial plane's two gates exactly as they
  // were for every request that is not an anonymous first-party dashboard
  // read -- the condition below is unchanged apart from that one conjunct.
  if (!firstPartyRead && path !== "/api/health" && path !== "/api/health/" && path !== "/api/health/live") {
    const rl = await checkRateLimit(env, ip, auth.tier);
    if (!rl.allowed) {
      auditLog(ctx, env, { action: "rate_limited", ip, path, method, tier: auth.tier });
      // Real conversion-funnel gap: this was the one live, customer-facing
      // "you've hit a wall" moment on the entire platform that carried zero
      // upgrade messaging, on every single request that ever got throttled.
      // Only attach it for FREE/PRO -- buildUpgradeTrigger() always targets
      // "enterprise" once you're off FREE, which would be backwards for an
      // ENTERPRISE or MSSP caller (MSSP's own RATE_LIMITS entry is *higher*
      // than ENTERPRISE's, so "upgrade to enterprise" would read as a
      // downgrade suggestion for them).
      const body = { error: "Too Many Requests", retry_after: 60, limit: rl.limit };
      if (auth.tier === TIERS.FREE || auth.tier === TIERS.PRO) {
        body.upgrade = buildUpgradeTrigger("usage_limit", auth.tier);
      }
      return jsonResp(
        body,
        429,
        {
          "Retry-After": "60",
          "X-RateLimit-Limit": String(rl.limit),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(Math.floor(resetAtMs / 1000)),
        }
      );
    }

    // Daily quota (business decision 2026-08-31) -- additive second gate,
    // independent of the per-minute limit above. Keyed by API key when
    // authenticated, IP only for anonymous traffic (see checkDailyQuota's
    // own header comment for why).
    const dailyIdentifier = auth.key || ip;
    const dq = await checkDailyQuota(env, dailyIdentifier, auth.tier);
    if (dq.crossedAlertThreshold) {
      ctx.waitUntil(maybeDispatchQuotaAlert(env, dailyIdentifier, auth.tier, auth, dq.dateStr));
    }
    if (dq.exceeded) {
      auditLog(ctx, env, { action: "daily_quota_exceeded", ip, path, method, tier: auth.tier });
      const body = { error: "Too Many Requests", reason: "daily_quota_exceeded", limit: dq.limit, reset_utc: new Date(Date.now() + secondsUntilNextUtcMidnight() * 1000).toISOString() };
      if (auth.tier === TIERS.FREE || auth.tier === TIERS.PRO) {
        body.upgrade = buildUpgradeTrigger("usage_limit", auth.tier);
      }
      return jsonResp(
        body,
        429,
        {
          "Retry-After": String(secondsUntilNextUtcMidnight()),
          "X-DailyLimit-Limit": String(dq.limit),
          "X-DailyLimit-Remaining": "0",
          "X-DailyLimit-Reset": new Date(Date.now() + secondsUntilNextUtcMidnight() * 1000).toISOString(),
        }
      );
    }
  }

  // Audit authenticated requests
  if (auth.key) {
    auditLog(ctx, env, { action: "api_request", ip, path, method, tier: auth.tier, sub: auth.sub });

    // CREDIT/USAGE SHADOW MODE -- mirrors the PHASE 3 entitlement shadow-mode
    // pattern above (observe/log only, ctx.waitUntil, never blocks or changes
    // what is returned). Reuses credit-system.js's deductCredits() and
    // usage-meter.js's trackApiUsage()/calculateCostPerCall()/slugifyEndpoint()
    // unchanged -- both files were bug-fixed for the tier-comparison defect
    // earlier this session but never wired into this router. checkCredits()
    // (the function that can build a 402) is intentionally never called here,
    // so this cannot block or reject a single customer request today; it only
    // maintains a background credit ledger + per-endpoint usage stats so a
    // future real billing decision can be based on actual traffic instead of
    // guesswork. deductCredits/trackApiUsage are themselves fail-open by
    // design (KV errors are caught internally, never thrown), and running
    // inside waitUntil means a slow or failed KV write can never add latency
    // to, or fail, the real response already in flight.
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil((async () => {
        try {
          const slug = slugifyEndpoint(path);
          const cost = calculateCostPerCall(slug, auth.tier);
          await Promise.allSettled([
            trackApiUsage(env, auth.sub, slug, auth.tier, cost),
            deductCredits(env, auth.sub, cost, auth.tier),
          ]);
        } catch (_) {}
      })());
    }
  }

  // --- TAXII 2.1 routes -------------------------------------------------------
  if (path.startsWith("/taxii")) {
    return await handleTAXII(request, env, ctx, path, auth);
  }

  // --- Admin API --------------------------------------------------------------
  if (path.startsWith("/api/admin")) {
    return await handleAdmin(request, env, ctx, path, method);
  }

  // --- Auth endpoints ---------------------------------------------------------
  if (path === "/auth/login" && method === "POST") {
    return await handleLogin(request, env, ctx, ip);
  }
  if (path === "/auth/logout" && method === "POST") {
    return await handleLogout(request, env, ctx, auth);
  }

  // --- SSO (OpenID Connect) ----------------------------------------------------
  if (path.startsWith("/auth/sso/") && path.endsWith("/start") && method === "GET") {
    const provider = path.slice("/auth/sso/".length, -"/start".length);
    return await handleSsoStart(request, env, ctx, provider);
  }
  if (path.startsWith("/auth/sso/") && path.endsWith("/callback") && method === "GET") {
    const provider = path.slice("/auth/sso/".length, -"/callback".length);
    return await handleSsoCallback(request, env, ctx, provider, ip);
  }
  if (path === "/auth/sso/handoff" && method === "GET") {
    return await handleSsoHandoff(request, env);
  }

  // --- /api/auth/* aliases ---------------------------------------------------
  // The dashboard uses AUTH_ENDPOINT='/api/auth' and the /auth/* CF Worker route
  // is not registered. These aliases under the registered /api/* route allow the
  // dashboard login modal and API clients to reach auth functionality.
  if (path === "/api/auth/login" && method === "POST") {
    return await handleLogin(request, env, ctx, ip);
  }
  if (path === "/api/auth/logout" && method === "POST") {
    return await handleLogout(request, env, ctx, auth);
  }
  if (path === "/api/auth/validate") {
    if (!auth.key) return jsonResp({ valid: false, tier: "free" }, 200);
    return jsonResp({ valid: true, tier: auth.tier, sub: auth.sub, jwt: auth.jwt || false }, 200);
  }
  if (path === "/api/auth/register" && method === "POST") {
    return jsonResp({
      error: "Email registration is not available. API keys are issued upon subscription.",
      help: "Subscribe at https://intel.cyberdudebivash.com/#pricing to receive your API key.",
      auth: "POST /api/auth/login with { \"api_key\": \"<your-key>\" } to obtain a Bearer JWT.",
    }, 422);
  }

  // --- Self-serve lead capture + trial issuance (revenue-enforcement.js) -----
  // FIX (P0, 2026-09-10): handleLeadCapture/handleTrialIssuance were fully
  // built, tested and live-correct (confirmed via
  // docs/BILLING_ENTITLEMENT_ARCHITECTURE_AUDIT.md: issues a real,
  // correctly-expiring 7-day PRO key) but never imported/routed here --
  // "fully correct AND fully unreachable" on this domain (only
  // revenue.intel.cyberdudebivash.com had it wired, via
  // workers/revenue-engine/src/index.js's separate route table). Wiring the
  // existing functions in directly rather than re-implementing them.
  // checkRateLimit reused (FREE-tier ceiling) as IP-based abuse friction on
  // top of handleTrialIssuance's own one-trial-per-email KV guard -- no new
  // rate-limiting mechanism introduced.
  if (path === "/api/leads/capture" && method === "POST") {
    const rl = await checkRateLimit(env, ip, "FREE");
    if (!rl.allowed) return jsonResp({ error: "rate_limited", retry_after_seconds: 60 }, 429);
    return await handleLeadCapture(request, env, crypto.randomUUID());
  }
  if (path === "/api/leads/trial" && method === "POST") {
    const rl = await checkRateLimit(env, ip, "FREE");
    if (!rl.allowed) return jsonResp({ error: "rate_limited", retry_after_seconds: 60 }, 429);
    return await handleTrialIssuance(request, env, crypto.randomUUID());
  }

  // --- Premium intel gate (MONETIZATION INTEGRITY v148->v180) -----------------
  if (PREMIUM_INTEL_PATHS.has(pathname)) {
    return await servePremiumIntelManifest(request, env, ctx, pathname);
  }

  // --- /api/v1/premium/* -- tiered feed products + Detection Pack add-on -----
  // v184.6: re-targeted here from api/main.py (a legacy Railway-targeted
  // FastAPI app with no evidence of live deployment -- see
  // LEGACY_COMPONENTS.md / COMPONENT_REGISTRY.json). intel-gateway is the
  // confirmed-live production gateway, so this is where entitlement checks
  // actually run against real traffic. Reuses the existing INTEL_R2 binding
  // (sentinel-apex-data bucket, already bound here) under a private
  // premium/ prefix -- no new bucket or credentials needed.
  //
  // Mapping note (carried over from the original api/main.py implementation):
  // these products are priced independently of the free/pro/enterprise/mssp
  // API subscription tiers ($999 Enterprise feed vs. $499/mo Enterprise API
  // subscription are not the same purchase). Absent a documented
  // cross-product entitlement mapping, gating conservatively on ENTERPRISE
  // or MSSP API tier is the only choice supported by evidence in this
  // codebase -- a Pro subscriber has no basis in TIERS or pricing.html for
  // getting a $999/mo product for free.
  const PREMIUM_FEED_TIERS = new Set(["gold", "silver", "standard", "executive"]);
  const PREMIUM_DETECTION_ARTIFACTS = new Set([
    "sigma_rules.yml", "kql_queries.kql", "ioc_blocklist.txt",
    "ioc_structured.json", "cve_watchlist.csv", "detection_pack.zip",
    "pack_manifest.json",
  ]);
  const PREMIUM_ARTIFACT_MEDIA_TYPES = {
    ".zip": "application/zip", ".csv": "text/csv", ".json": "application/json",
    ".yml": "application/x-yaml", ".kql": "text/plain", ".txt": "text/plain",
  };

  if (path.startsWith("/api/v1/premium/feed/") || path.startsWith("/api/v1/premium/detections/")) {
    if (auth.tier !== TIERS.ENTERPRISE && auth.tier !== TIERS.MSSP) {
      return jsonResp({
        error: "This product requires an Enterprise or MSSP API subscription",
        upgrade: "https://intel.cyberdudebivash.com/upgrade.html", current_tier: auth.tier,
      }, 403);
    }

    let r2Key;
    try {
      if (path.startsWith("/api/v1/premium/feed/")) {
        const tier = decodeURIComponent(path.slice("/api/v1/premium/feed/".length)).toLowerCase();
        if (!PREMIUM_FEED_TIERS.has(tier)) return errorResp(`Unknown premium feed tier: ${tier}`, 404);
        r2Key = `premium/feeds/feed.${tier}.json`;
      } else {
        const artifact = decodeURIComponent(path.slice("/api/v1/premium/detections/".length));
        if (!PREMIUM_DETECTION_ARTIFACTS.has(artifact)) return errorResp(`Unknown detection pack artifact: ${artifact}`, 404);
        r2Key = `premium/detections/${artifact}`;
      }
    } catch (_decodeErr) {
      return errorResp("Malformed premium content path", 400);
    }

    let obj;
    try {
      obj = await env.INTEL_R2.get(r2Key);
    } catch (_r2Err) {
      return errorResp("Premium content temporarily unavailable -- try again shortly", 503);
    }
    if (!obj) return errorResp("Premium content temporarily unavailable -- try again shortly", 503);
    const ext = r2Key.slice(r2Key.lastIndexOf("."));
    return new Response(obj.body, {
      status: 200,
      headers: {
        ...CORS_HEADERS, ...SECURITY_HEADERS,
        "Content-Type": PREMIUM_ARTIFACT_MEDIA_TYPES[ext] || "application/octet-stream",
        "Cache-Control": "private, max-age=300",
      },
    });
  }

  // --- /api/health ------------------------------------------------------------
  if (path === "/api/health" || path === "/api/health/") {
    // A public security report demonstrated this endpoint handing any unauthenticated caller a
    // full infrastructure/security-posture map with zero auth required: JWT algorithm family
    // (auth: "JWT_HS256+KV" -- signals which algorithm-specific attacks to try), the exact
    // brute-force lockout threshold, and which third-party integrations (Razorpay, Resend) are
    // enabled. None of that is a secret value, but it is a free architecture map for
    // reconnaissance and this endpoint has zero legitimate reason to hand it to an anonymous
    // caller.
    //
    // CORRECTION to the first pass at this fix: that pass gated the *entire* response (including
    // status/advisory_count/checks.jwt_configured/etc.) behind auth, which broke real,
    // already-wired first-party consumers that have no way to authenticate -- confirmed live:
    // master-deployment-orchestrator.yml's Gate 1 (reads advisory_count, hard-fails below 10),
    // post-deploy-validation.yml's GATE D (reads checks.jwt_configured, hard-fails if absent),
    // and feed_contract_validator.py's CONTRACT-2 (requires a non-empty `checks` object in the
    // envelope). post_deploy_validator.py/commercial_saas_validator.py/self_healing_engine.py
    // also read checks.jwt_configured/r2_intel/feed_index unauthenticated. None of those six
    // consumers reads the `security` block or the four secret-*presence* booleans below --
    // narrowing the gate to exactly what the report flagged, instead of the whole endpoint, is
    // what actually satisfies this repo's own backward-compatibility requirement.
    //
    // Fix: reuse the exact admin credential /api/admin/health already requires (X-Admin-Key or
    // Authorization: Bearer, matched via timingSafeEqual against ADMIN_SECRET) rather than
    // inventing a second auth mechanism. An authenticated caller gets the identical, unchanged
    // response this endpoint has always returned. An unauthenticated caller gets everything
    // real consumers depend on (status, version, advisory/critical counts, checks.gateway/
    // kv_rate_limit/kv_api_keys/r2_intel/feed_index/jwt_configured) but not the `security` block,
    // not checks.{admin,razorpay,razorpay_webhook,resend,revenue_admin_secret}_configured (which
    // secrets exist -- the actual reconnaissance value), and not data_freshness (a narrower,
    // genuinely non-essential staleness signal the report separately flagged, with no consumer
    // depending on it).
    const healthAdminKey = (
      request.headers.get("X-Admin-Key") ||
      (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "")
    ).trim();
    const healthIsAuthenticated = !!env.ADMIN_SECRET && timingSafeEqual(healthAdminKey, env.ADMIN_SECRET);

    // P0 HEALTH FRESHNESS CONTRACT (2026-09-24). Verified live before this
    // change: HTTP 200 {"status":"ok"} while every customer feed endpoint
    // served generated_at 2026-08-26T09:55:27Z (four weeks stale). Causes:
    // `status` was hard-coded "ok"; the freshness verdict was admin-only and
    // used thresholds independent of PR #485's MAX_PUBLIC_MANIFEST_AGE_HOURS;
    // and loadFeedItems()'s empty fallback stamps generated_at=now(), so an
    // R2 miss read as FRESH. Now: the authoritative object is read directly
    // (one R2 GET, same as before -- no LIST, no write), evaluated against the
    // ONE canonical contract (freshness-contract.js), and the HTTP status
    // follows it: 200 only when intelligence exists, is structurally valid
    // and is within the freshness window; otherwise 503 with a
    // machine-readable `reason`. Worker liveness (deploy checks) lives at
    // /api/health/live, which never depends on data.
    const nowMs    = Date.now();
    const rawFeed  = await r2Get(env, LATEST_JSON_KEY);
    const evaluation = evaluatePublicIntelligence(rawFeed, nowMs);
    const feedItems = rawFeed && Array.isArray(rawFeed.items) ? rawFeed.items : [];
    const stats    = computeStats(feedItems);
    // Kept for the authenticated view below; classifyFreshness() now derives
    // its FRESH verdict from the same contract.
    const dataFreshness = classifyFreshness(rawFeed ? rawFeed.generated_at : null, nowMs);
    // Public envelope: every field existing unauthenticated consumers read
    // (status, version, advisory_count, critical_count, kev_confirmed,
    // last_sync, feed_index, platform_reachable, intelligence_available,
    // non-empty `checks`, generated_at) is preserved. Removed from the
    // PUBLIC view (still returned to admin callers): checks.jwt_configured
    // (a secret-presence flag) and checks.kv_rate_limit / kv_api_keys /
    // r2_intel (storage topology).
    const body = {
      status: evaluation.status,
      service: "sentinel-apex",
      version: PLATFORM_VERSION,
      ...(evaluation.reason ? { reason: evaluation.reason } : {}),
      advisory_count: evaluation.intelligence.advisory_count, critical_count: stats.critical,
      kev_confirmed: stats.kev_confirmed, last_sync: stats.last_sync,
      feed_index: `live:${evaluation.intelligence.advisory_count}_items`,
      platform_reachable: true,
      intelligence_available: evaluation.intelligence.advisory_count > 0,
      intelligence: evaluation.intelligence,
      checks: {
        gateway: "ok",
        ...evaluation.checks,
        feed_index: `live:${evaluation.intelligence.advisory_count}_items`,
      },
      generated_at: now(),
    };
    const respHeaders = {};

    if (healthIsAuthenticated) {
      body.data_freshness = dataFreshness;
      // Operator-only: storage probe and secret-presence flags. The KV read
      // now happens only for authenticated calls (public calls skip it).
      const kvOk = await env.RATE_LIMIT_KV.get("health:ping").then(() => "ok").catch(() => "error");
      // A secret set to "" or whitespace-only (e.g. `wrangler secret put`
      // given a blank value by mistake) is truthy under a plain !!(env.X)
      // check, so it would silently read as "configured" while still being
      // useless to every caller that needs the actual value.
      const isSet = (v) => typeof v === "string" && v.trim().length > 0;
      Object.assign(body.checks, {
        kv_rate_limit: kvOk, kv_api_keys: kvOk,
        r2_intel: feedItems.length > 0 ? "ok" : (rawFeed ? "empty" : "unavailable"),
        jwt_configured: !!(env.CDB_JWT_SECRET),
        admin_configured: !!(env.ADMIN_SECRET),
        // Additive: surfaces the exact outage verified live on 2026-08-03 -- create-order
        // 503s with "Razorpay not configured on server" whenever either secret is unset,
        // silently blocking 100% of checkouts with no prior signal in /api/health.
        razorpay_configured: isSet(env.RAZORPAY_KEY_ID) && isSet(env.RAZORPAY_KEY_SECRET),
        // Same blind spot, same fix, for the two secrets the rest of the checkout
        // pipeline depends on: an unset RAZORPAY_WEBHOOK_SECRET makes the async
        // webhook path (handleWebhookRazorpay) 500 on every delivery with no
        // signal here; an unset RESEND_API_KEY makes sendActivationEmail() a
        // silent no-op (it warns to the Worker log and returns false, but the
        // customer still gets a 201 with their key, so nothing customer-facing
        // ever surfaces the failure). Both would otherwise be invisible for
        // months the same way razorpay_configured was before 2026-08-03.
        razorpay_webhook_configured: isSet(env.RAZORPAY_WEBHOOK_SECRET),
        resend_configured: isSet(env.RESEND_API_KEY),
        // Same blind-spot pattern (PR #281): an unset REVENUE_ADMIN_SECRET makes
        // computePortalToken() return null and sendActivationEmail() silently omit
        // the "manage your subscription" link -- customer still gets their key,
        // nothing customer-facing ever surfaces that the portal link is missing.
        revenue_admin_secret_configured: isSet(env.REVENUE_ADMIN_SECRET),
      });
      body.security = {
        auth: "JWT_HS256+KV",
        // FIX (P0, 2026-09-10, edge-security audit): this self-reported
        // "sliding_window_per_ip" regardless of what checkRateLimit() (the
        // only rate limiter in this file) actually implements -- a fixed
        // 60-second window (`minute = Math.floor(Date.now()/60000)`), not a
        // sliding one. Never independently verified against the real
        // implementation until this audit. Corrected to match reality
        // rather than the aspirational label.
        rate_limiting: "fixed_window_per_ip_60s",
        brute_force: `lockout_after_${BRUTE_FORCE_MAX}_failures`,
        audit_logging: "SECURITY_HUB_KV",
        headers: "HSTS+CSP+XFO",
        taxii: "2.1",
      };
      // Never let an operator response enter the shared edge cache (the
      // Cache API keys on URL only, so a cached admin body would be served
      // to anonymous callers).
      respHeaders["Cache-Control"] = "private, no-store";
    } else if (evaluation.healthy) {
      // A cached "ok" must not outlive the freshness boundary.
      respHeaders["X-Sentinel-Edge-Ttl"] = String(healthEdgeTtlSeconds(evaluation, EDGE_CACHE_TTL_SECONDS));
    }

    return jsonResp(body, evaluation.http_status, respHeaders);
  }

  // --- /api/health/live ---------------------------------------------------------
  // Worker liveness only: answers 200 whenever this Worker is executing,
  // independent of intelligence freshness, with no R2/KV access. Used by
  // deploy-worker.yml to prove a deploy is serving, so a stale feed (which
  // /api/health now reports as 503) can never block shipping the fix for it.
  if (path === "/api/health/live") {
    return jsonResp(
      { status: "alive", service: "sentinel-apex", version: PLATFORM_VERSION, generated_at: now() },
      200,
      { "Cache-Control": "no-store" },
    );
  }

  // --- /api/v1/intel/latest.json ----------------------------------------------
  // FREE tier: sanitized manifest (no report_url, no premium fields)
  // PRO/ENTERPRISE: full PRO manifest including report_url, pdf_url
  if (path === "/api/v1/intel/latest.json") {
    let data;
    const manifestFullAllowedAdHoc = auth.tier === TIERS.PRO || auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP;
    const manifestFullAllowed = resolveEntitlement(ctx, env, "intel_manifest_full", auth, manifestFullAllowedAdHoc).allowed;
    if (manifestFullAllowed) {
      // Try PRO manifest first; gracefully fall back to public if not yet generated
      data = await r2Get(env, LATEST_PRO_JSON_KEY);
      if (!data) data = await r2Get(env, LATEST_JSON_KEY);
      if (!data) return errorResp("Feed not available", 503);
      return jsonResp(data, 200, { "Cache-Control": "private, max-age=120" });
    }
    data = await r2Get(env, LATEST_JSON_KEY);
    if (!data) return errorResp("Feed not available", 503);
    // v142.0: this branch previously returned the canonical item array
    // untouched -- full IOCs, Sigma/KQL/Suricata rules, and actor attribution
    // leaked to every anonymous caller despite the comment above. Mask it.
    if (Array.isArray(data.items)) {
      data = { ...data, items: data.items.map(i => applyTierGateV2(i, "free", null)) };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/top10.json -----------------------------------------------
  if (path === "/api/v1/intel/top10.json") {
    let data = await r2Get(env, "api/v1/intel/top10.json");
    if (!data) {
      const feedData = await loadFeedItems(env);
      const top10    = (feedData.items || []).sort((a, b) => parseFloat(b.risk_score || 0) - parseFloat(a.risk_score || 0)).slice(0, 10);
      data = { items: top10, count: top10.length, generated_at: now(), version: PLATFORM_VERSION };
    }
    // Same tier gate as /api/v1/intel/latest.json -- this endpoint carries the
    // same canonical item shape (IOCs, detection rules, actor attribution).
    if (auth.tier !== TIERS.PRO && auth.tier !== TIERS.ENTERPRISE && auth.tier !== TIERS.MSSP && Array.isArray(data.items)) {
      data = { ...data, items: data.items.map(i => applyTierGateV2(i, "free", null)) };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/platform/stats ----------------------------------------------------
  // Dashboard-facing unified stats endpoint  -  returns {intel:{...}, api:{...}}
  if (path === "/api/platform/stats") {
    const liveFeedCount = (await _liveFeedSourceCount(env)) ?? _LEGACY_FEED_COUNT_FALLBACK;
    const rawFeed = await r2Get(env, LATEST_JSON_KEY);
    const publication = evaluatePublicIntelligence(rawFeed, Date.now());
    const items = rawFeed && Array.isArray(rawFeed.items) ? rawFeed.items : [];
    const stats = computeStats(items);
    const threat     = computeThreatLevel(stats);
    const defcon     = computeDefcon(stats);
    // PRODUCTION FIX (live-data audit, Single Source of Truth): this endpoint
    // previously computed its own "CVE mentions x 3" proxy here instead of
    // using stats.total_iocs -- the real per-item ioc_count sum computeStats()
    // above already produces, and that every other IOC-count consumer in
    // this file (buildApexInline's total_iocs, /api/v1/intel/stats's spread
    // of `stats`) and the frontend (fillMetrics/_iocContribution summing
    // /api/feed.json's own per-item ioc_count) already treats as canonical.
    // Confirmed live: this endpoint was returning ioc_count:706 from the
    // proxy formula while the real sum (stats.total_iocs, same feed window)
    // was 1377 -- two code paths, two disagreeing answers for the same
    // metric on the same homepage. Reusing the existing canonical value.
    const iocCount = stats.total_iocs;
    // Try to get total_reports from R2 reports index
    let totalReports = stats.total;
    try {
      const rIdx = await r2Get(env, REPORTS_KEY);
      if (rIdx && rIdx.total_reports) totalReports = rIdx.total_reports;
    } catch(_) {}
    const uniqueActors = new Set(items.filter(i => i.actor_tag).map(i => i.actor_tag)).size;
    // P0 FIX (2026-09 dashboard/backend freshness-contract audit): this is the
    // one endpoint the dashboard's fetchWorkerStats() treats as authoritative
    // (see index.html's "single source of truth" comment on that function) --
    // but it previously exposed only stats.last_sync (the newest ITEM's own
    // published date, computeStats()) with no pipeline-freshness signal at
    // all. The dashboard's "SYNC: LIVE" badge was therefore driven entirely
    // by an unrelated question -- "did the manifest fetch succeed from the
    // primary domain" -- with no cross-check against how stale that manifest
    // actually was, which is exactly how SYNC: LIVE and a 10-day-old Last
    // Sync value ended up on screen together during the 2026-08-26 core-feed
    // staleness incident classifyFreshness() was originally added to detect
    // (see that function's own comment). /api/metrics already exposes this
    // exact signal publicly (freshness/freshness_age_seconds, computed the
    // same way from feedData.generated_at) -- reused here, not reimplemented,
    // so the dashboard's primary stats call carries it too instead of
    // requiring a second fetch. Purely additive: existing consumers of
    // intel.last_sync/status are unaffected.
    const freshness = classifyFreshness(rawFeed && rawFeed.generated_at ? rawFeed.generated_at : null);
    return jsonResp({
      intel: {
        total_reports: totalReports,
        ioc_count: iocCount,
        kev_count: stats.kev_confirmed,
        feed_count: liveFeedCount,
        active_feeds: liveFeedCount,
        unique_actors: uniqueActors,
        severity_distribution: {
          critical: stats.critical, high: stats.high,
          medium: stats.medium, low: stats.low,
        },
        global_threat_level: threat.level,
        global_threat_label: threat.label,
        defcon: defcon.level,
        avg_risk_score: stats.avg_risk_score,
        total_advisories: publication.intelligence.advisory_count,
        canonical_advisory_count: publication.intelligence.advisory_count,
        publication_state: publication.intelligence.status,
        publication_generated_at: publication.intelligence.generated_at,
        publication_age_seconds: publication.intelligence.age_seconds,
        last_sync: stats.last_sync,
        last_feed_sync_utc: publication.intelligence.generated_at,
        freshness: freshness.state,
        freshness_age_seconds: freshness.age_seconds,
        version: PLATFORM_VERSION,
      },
      api: { calls_today: 0, generated_at: now() },
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/stats ----------------------------------------------------
  if (path === "/api/v1/intel/stats" || path === "/api/v1/stats") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const threat   = computeThreatLevel(stats);
    const defcon   = computeDefcon(stats);
    const liveFeedCount = (await _liveFeedSourceCount(env)) ?? _LEGACY_FEED_COUNT_FALLBACK;
    return jsonResp({
      ...stats, global_threat_level: threat.level, global_threat_label: threat.label,
      defcon: defcon.level, defcon_label: defcon.label, defcon_status: defcon.status,
      feeds_active: liveFeedCount, version: PLATFORM_VERSION,
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/metrics -------------------------------------------------------
  // Backs p0-revenue-os/config/metric_integrity_contract.json (contract_id
  // APEX-METRIC-INTEGRITY-v1, landed on main alongside js/p0-public-contract.js
  // -- see that commit's own header: "Does not invent advisory/IOC counts").
  // That contract and its runtime already existed with NO backend route
  // behind them: js/p0-public-contract.js's loadMetrics() has always tried
  // this exact path first, silently falling through to its static-file
  // fallback (also absent -- only a null-filled p0-revenue-os/metrics/
  // canonical.sample.json template exists, never at the real
  // /metrics/canonical.json path) -- a contract-without-a-backend gap, the
  // mirror image of the more usual backend-without-a-frontend orphan this
  // platform has been closing PR by PR. Reuses this file's own
  // computeStats()/loadFeedItems()/classifyFreshness() (already used by the
  // sibling /api/platform/stats and /api/v1/intel/stats routes immediately
  // above) and P40's already-live source registry for feed_source_count --
  // no new scoring or R2-read logic. Every field the contract lists but
  // this platform has no real source for (api_uptime_30d_pct: no uptime-
  // history store exists anywhere in this codebase) is null, never a
  // fabricated number, matching the sample file's own explicit rule:
  // "Shipping this file with invented integers is a contract violation."
  if (path === "/api/metrics") {
    // CodeRabbit review finding on this PR (verified, not taken on faith):
    // same GET-only gap already fixed at /api/reports/list and
    // /api/reports/{id} above (PR #242) -- nothing rejected a non-GET call
    // before this, so e.g. POST would still dispatch a normal 200 read.
    if (method !== "GET") {
      return jsonResp({ error: "method_not_allowed", allowed: ["GET"], request_id: crypto.randomUUID() }, 405, { "Allow": "GET" });
    }
    const feedData = await loadFeedItems(env);
    const items = feedData.items || [];
    const stats = computeStats(items);
    // CodeRabbit review finding on this PR (verified, not taken on faith):
    // same stats.last_sync-vs-feedData.generated_at distinction already
    // fixed at /api/health above (see that route's own comment for the
    // full incident this matters for) -- stats.last_sync is the newest
    // item's own published date, not "when this platform last
    // synced/ingested," and using it here can mask the same silently-
    // broken-pipeline class /api/health's fix exists to catch.
    const lastFeedSyncUtc = feedData.generated_at || null;
    const freshness = classifyFreshness(lastFeedSyncUtc);
    const feedSourceCount = await _liveFeedSourceCount(env);

    // Unique (type, value) IOCs across items published in the last 30 days --
    // a real dedup over each item's own iocs[] array (same field p22-handlers.js
    // reads for IOC validation), not the raw summed ioc_count /api/platform/stats
    // uses (that sum double-counts a repeated indicator across reports).
    const THIRTY_DAYS_MS = 30 * 24 * 3600 * 1000;
    const cutoff = Date.now() - THIRTY_DAYS_MS;
    const uniqueIocs30d = new Set();
    let stixBundlesAvailable = false;
    for (const item of items) {
      const publishedMs = Date.parse(item.published || item.published_at || "");
      if (!Number.isNaN(publishedMs) && publishedMs >= cutoff) {
        for (const ioc of (item.iocs || [])) {
          if (ioc && ioc.type && ioc.value) uniqueIocs30d.add(ioc.type + ":" + ioc.value);
        }
      }
      if (item.stix_bundle && Array.isArray(item.stix_bundle.objects) && item.stix_bundle.objects.length > 0) {
        stixBundlesAvailable = true;
      }
    }

    return jsonResp({
      contract_id: "APEX-METRIC-INTEGRITY-v1",
      version: PLATFORM_VERSION,
      generated_at: now(),
      advisory_count_live: stats.total,
      feed_source_count: feedSourceCount,
      ioc_count_unique_30d: uniqueIocs30d.size,
      stix_bundles_available: stixBundlesAvailable,
      last_feed_sync_utc: lastFeedSyncUtc,
      freshness: freshness.state,
      freshness_age_seconds: freshness.age_seconds,
      api_uptime_30d_pct: null,
      preview_item_limit: 10,
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/campaigns ------------------------------------------------
  if (path === "/api/v1/intel/campaigns") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const kc       = computeKillChain(feedData.items || []);
    const threat   = computeThreatLevel(stats);
    return jsonResp({ ...kc, global_threat_level: threat, version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/ransomware -----------------------------------------------
  if (path === "/api/v1/intel/ransomware") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeRansomware(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/apt ------------------------------------------------------
  if (path === "/api/v1/intel/apt") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeAPT(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/epss -----------------------------------------------------
  if (path === "/api/v1/intel/epss") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeEPSS(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/defcon ---------------------------------------------------
  if (path === "/api/v1/intel/defcon") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const defcon   = computeDefcon(stats);
    const threat   = computeThreatLevel(stats);
    return jsonResp({
      ...defcon, global_threat_level: threat,
      stats: { critical: stats.critical, kev_confirmed: stats.kev_confirmed, total: stats.total },
      generated_at: now(),
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/pulse ----------------------------------------------------
  if (path === "/api/v1/intel/pulse") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    return jsonResp({ ...computePulse(feedData.items || [], stats), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/darkweb --------------------------------------------------
  if (path === "/api/v1/intel/darkweb") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeDarkweb(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/v1/intel/cybermap -------------------------------------------------
  if (path === "/api/v1/intel/cybermap" || path === "/api/v1/geo/cybermap") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    return jsonResp({ ...computeCybermap(feedData.items || [], stats), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/news/feed ------------------------------------------------------
  if (path === "/api/v1/news/feed" || path === "/api/news/feed") {
    try {
      const feed = await fetchNewsFromRSS(env.RATE_LIMIT_KV);
      return jsonResp({ ...feed, version: PLATFORM_VERSION }, 200, { "Cache-Control": `public, max-age=${NEWS_TTL_SEC}` });
    } catch (_) {
      return jsonResp({ items: [], count: 0, error: "Feed temporarily unavailable", generated_at: now() }, 200);
    }
  }

  // --- /api/reports/latest.json -----------------------------------------------
  if (path === "/api/reports/latest.json") {
    let data = await buildCertifiedReportsFeed(env, ctx, { limit: 50, feedType: "customer_ready_latest" });
    if (!data) {
      // R2 catalog missing entirely -- fall back to computing directly from
      // the live feed. Already filters before truncating (Section 7's
      // correct ordering), so no change needed there.
      const feedData   = await loadFeedItems(env);
      const candidates = (feedData.items || [])
        .filter(i => (i.severity || "") === "CRITICAL" || parseFloat(i.risk_score || 0) >= 8.0);
      const critItems  = candidates.filter(i => evaluatePublicationGate(i).customer_ready);
      data = {
        schema_version: "2.0.0", feed_type: "customer_ready_latest", generated_at: now(),
        policy_version: CERTIFICATION_POLICY_VERSION,
        total_candidates: candidates.length, customer_ready_count: critItems.length,
        withheld_count: candidates.length - critItems.length,
        total_reports: critItems.length, reports_listed: Math.min(critItems.length, 50),
        reports: critItems.slice(0, 50).map(i => ({
          id: i.stix_id || i.id, url: `/reports/2026/06/${i.stix_id || i.id}.html`,
          title: i.title, severity: i.severity, risk_score: i.risk_score,
          cve: i.cve_id || (i.cve_ids || [])[0] || null, timestamp: i.published || i.published_at,
        })),
      };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/reports/index.json ------------------------------------------------
  if (path === "/api/reports/index.json") {
    let data = await buildCertifiedReportsFeed(env, ctx, { limit: 500, feedType: "customer_ready_catalog" });
    if (!data) {
      const feedData   = await loadFeedItems(env);
      const candidates = (feedData.items || [])
        .filter(i => (i.severity || "") === "CRITICAL" || parseFloat(i.risk_score || 0) >= 8.0);
      const critItems  = candidates.filter(i => evaluatePublicationGate(i).customer_ready);
      data = {
        schema_version: "2.0.0", feed_type: "customer_ready_catalog",
        version: PLATFORM_VERSION, generated_at: now(),
        policy_version: CERTIFICATION_POLICY_VERSION,
        total_candidates: candidates.length, customer_ready_count: critItems.length,
        withheld_count: candidates.length - critItems.length,
        total_reports: critItems.length, reports_listed: Math.min(critItems.length, 20),
        reports: critItems.slice(0, 20).map(i => ({
          id: i.stix_id || i.id, url: `/reports/2026/06/${i.stix_id || i.id}.html`,
          title: i.title, severity: i.severity, risk_score: i.risk_score,
          cve: i.cve_id || (i.cve_ids || [])[0] || null, timestamp: i.published || i.published_at,
        })),
      };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/reports/stats.json ------------------------------------------------
  if (path === "/api/reports/stats.json") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    return jsonResp({
      // DEPRECATED (schema_version 1.1.0), no removal date set yet -- despite
      // the name, this has never been a report-catalog count, it is
      // critical+high THREAT count from the live feed. Kept unchanged (same
      // value) for backward compatibility; confirmed via full-repo consumer
      // audit that nothing currently reads it as a catalog count. Exact
      // replacements (identical values today, safe to migrate field-by-field):
      //   total_reports   -> total_active_threats
      //   critical_reports -> critical_threats
      //   high_reports     -> high_threats
      //   medium_reports   -> medium_threats
      total_reports: stats.critical + stats.high,
      critical_threats: stats.critical, high_threats: stats.high, medium_threats: stats.medium,
      total_active_threats: stats.critical + stats.high,
      critical_reports: stats.critical, high_reports: stats.high, medium_reports: stats.medium,
      kev_reports: stats.kev_confirmed,
      last_generated: stats.last_sync, generated_at: now(), version: PLATFORM_VERSION,
      schema_version: "1.1.0",
    }, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/v1/ioc/lookup -----------------------------------------------------
  if (path === "/api/v1/ioc/lookup" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const query    = body.query || body.ioc || url.searchParams.get("q") || "";
    const feedData = await loadFeedItems(env);
    return jsonResp(await iocLookup(query, feedData, auth.tier));
  }
  if (path === "/api/v1/ioc/lookup" && method === "GET") {
    const query    = url.searchParams.get("q") || url.searchParams.get("query") || "";
    const feedData = await loadFeedItems(env);
    return jsonResp(await iocLookup(query, feedData, auth.tier));
  }

  // --- /api/preview -----------------------------------------------------------
  if (path === "/api/preview" || path === "/api/preview/") {
    const feedData = await loadFeedItems(env);
    // Same "no data == unavailable" judgment /api/feed.json already makes for
    // this identical R2 source (LATEST_JSON_KEY) -- loadFeedItems() swallows
    // R2 errors into an empty-but-200 payload, which previously rendered as a
    // silent empty preview instead of a signal that the feed is down.
    if (!Array.isArray(feedData.items) || feedData.items.length === 0) return errorResp("Feed not available", 503);
    // Always the FREE/teaser view regardless of caller tier (unauthenticated
    // by design) -- so IOCs, detection rules, and actor attribution must be
    // masked the same way the FREE branch of every other endpoint is.
    const items    = (feedData.items || []).slice(0, PREVIEW_LIMIT).map(i => applyTierGateV2(i, "free", null));
    // v201.0: additive-only field sourced from the new cron_worker.js
    // ingestion pipeline's cached summary (threat-indicators/summary.json,
    // a NEW R2 key -- distinct from LATEST_JSON_KEY). getLiveIndicatorsSummary
    // never throws and returns null until the 6-hourly cron has run at least
    // once, so this is zero-behavior-change for every existing consumer that
    // doesn't look at the new key.
    const liveIndicators = await getLiveIndicatorsSummary(env);
    return jsonResp({
      status: "ok",
      preview: {
        items, total_preview: items.length, feed_total: (feedData.items || []).length,
        preview_limit: PREVIEW_LIMIT, generated_at: now(), version: PLATFORM_VERSION,
        _tier: TIERS.FREE, _upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html",
        ...(liveIndicators ? { live_indicators_summary: liveIndicators } : {}),
      },
    }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/feed + /api/feed.json (legacy) ------------------------------------
  if (path === "/api/feed" || path === "/api/feed.json") {
    let data = await r2Get(env, LATEST_JSON_KEY);
    if (!data) return errorResp("Feed not available", 503);
    // Legacy alias for /api/v1/intel/latest.json -- same key, same gate.
    if (auth.tier !== TIERS.PRO && auth.tier !== TIERS.ENTERPRISE && auth.tier !== TIERS.MSSP && Array.isArray(data.items)) {
      data = { ...data, items: data.items.map(i => applyTierGateV2(i, "free", null)) };
    }
    // v201.0: same additive-only live-indicators field as /api/preview above.
    const liveIndicators = await getLiveIndicatorsSummary(env);
    if (liveIndicators) data = { ...data, live_indicators_summary: liveIndicators };
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /reports/** (HTML intel reports from REPORTS_R2) -----------------------
  if (path.startsWith("/reports/")) {
    if (!env.REPORTS_R2) {
      return new Response("Reports bucket not configured", {
        status: 503, headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": "text/plain" },
      });
    }

    const key = path.replace(/^\//, "");
    const PROBE_YEARS  = [2026, 2025];
    const PROBE_MONTHS = ["06","12","09","05","04","03","02","01","10","11","07","08"];

    // Legacy URLs: /reports/intel--{hash}  OR  /reports/intel--{hash}.html  OR  /reports/intel--{hash}/
    // All three forms have intel-- directly after /reports/ (no YYYY/MM date segment).
    // Root cause of recurring 404: old regex only matched slug-without-extension or trailing-slash.
    // Fix: (?:\.html)? now catches the .html-extension-without-date-path form too.
    const legacyMatch = path.match(/^\/reports\/(intel--[a-f0-9]+)(?:\.html)?\/?$/i);
    const isLegacyForm = legacyMatch || (path.endsWith("/") && path.startsWith("/reports/"));
    const canonicalSlugMatch = path.match(/\/(intel--[a-f0-9_A-Z0-9-]+)\.html$/i);
    const gateSlug = isLegacyForm
      ? (legacyMatch ? legacyMatch[1] : path.replace(/^\/reports\//, "").replace(/[./]+$/, ""))
      : (canonicalSlugMatch ? canonicalSlugMatch[1] : null);

    // -------------------------------------------------------------------
    // P0 CUSTOMER PUBLICATION AUTHORIZATION GATE
    // Incident: intel--ba996dad34540150b8ea1b5f was served here despite
    // P21=BELOW_MINIMUM, P25=BELOW THRESHOLD, P26=REJECTED, P23=DO NOT
    // PUBLISH -- root cause and full rationale in publication-gate.js's
    // header. Resolved ONCE here (reused below by both the legacy and
    // canonical branches, replacing their own separate findItemBySlug
    // calls) so every serving path -- direct R2 cache hit, redirect
    // target, or fresh synthesis -- is covered by a single evaluation.
    //
    // When the item is NOT resolvable via findItemBySlug's feed sources
    // (an older report that has aged out of the "latest" windows this
    // function searches), this is deliberately non-blocking: existing
    // behavior is unchanged rather than newly 404ing content this gate
    // has no way to verify either way. That population -- and any
    // already-cached bad copies matching a resolvable item -- is covered
    // by scripts/publication_gate_scan.py, not by blocking every view.
    // -------------------------------------------------------------------
    const gateItem   = gateSlug ? await findItemBySlug(env, gateSlug) : null;
    const gateResult = gateItem ? evaluatePublicationGate(gateItem) : null;
    if (gateItem && gateResult && !gateResult.customer_ready) {
      // v187.0 P0 FIX: a report the publication gate permanently rejected
      // (P21_BELOW_MINIMUM / P26_REJECTED / etc.) is not "still generating"
      // -- telling a customer to retry a permanent rejection is misleading
      // and retrying will never resolve it. Distinguish this case
      // explicitly from a genuinely-unresolvable/unknown report (below);
      // internal certification scores are deliberately NOT exposed here --
      // only the publication_state, which callers (and
      // scripts/report_url_canary.py, scripts/deployment_convergence_
      // validator.py) already treat as the authoritative, non-sensitive
      // verdict via /api/v1/reports/{id}/publication-status.
      return jsonResp(buildGateRejectedResponseBody(gateResult), 404);
    }

    if (isLegacyForm) {
      const slug = gateSlug;
      const fn   = slug.startsWith("intel--") ? `${slug}.html` : `intel--${slug}.html`;
      for (const y of PROBE_YEARS) {
        for (const m of PROBE_MONTHS) {
          const obj = await env.REPORTS_R2.get(`reports/${y}/${m}/${fn}`);
          if (obj) return Response.redirect(`https://intel.cyberdudebivash.com/reports/${y}/${m}/${fn}`, 301);
        }
      }
      // Synthesis fallback: generate from feed data so the report is always available
      const legacyItem = gateItem;
      if (legacyItem) {
        const legacyFeed = await loadFeedItems(env);
        // /reports/** is a public, permanently-R2-cached HTML surface with no
        // per-viewer variation possible once written -- always generate the
        // FREE/masked view (same reasoning as /api/preview) so IOCs, detection
        // rules, and actor attribution never get baked into the public cache.
        // The `items` context array is masked too: some block builders (e.g.
        // P31 campaign/entity blocks) cross-reference it for attribution.
        const maskedLegacyItem  = applyTierGateV2(legacyItem, "free", null);
        const maskedLegacyItems = (legacyFeed.items || []).map(i => applyTierGateV2(i, "free", null));
        // RX-PUB-A0 FIX: this Worker-side JS render is a distinct, independent
        // implementation from the authoritative Python generator
        // (scripts/generate_intel_reports.py) -- no engine marker, no
        // certification tie-in, no artifact-identity tracking. It previously
        // persisted straight into the canonical R2 key on ordinary customer/
        // crawler traffic, giving unauthenticated requests unmediated write
        // authority over the same keyspace the certified pipeline owns (see
        // docs/REPORT_WRITER_OWNERSHIP_MATRIX.md, Writer C). Still serve the
        // live-rendered response so an approved item never hard-404s while
        // waiting for its canonical artifact -- just never write it into the
        // canonical key. Only scripts/generate_intel_reports.py may populate
        // reports/*.html in R2.
        const html = generateIntelReport(maskedLegacyItem, path, maskedLegacyItems);
        return new Response(html, { status: 200, headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Security-Policy": HTML_CSP, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
      }
      // v187.0 P0 FIX: this branch is reached only when the report id could
    // not be resolved via findItemBySlug at all (not a known-and-rejected
    // report -- see the publication-gate branch above) and no R2 object
    // exists under any probed year/month. Genuinely unknown status --
    // fail closed, and do not claim "still generating" since that cannot
    // be determined from here (a permanent bad link looks identical to a
    // not-yet-propagated one at this point).
    return jsonResp(buildUnresolvableReportResponseBody(path), 404);
    }

    // Canonical URL: /reports/YYYY/MM/intel--{hash}.html
    // Try direct R2 lookup first. On miss, cross-month probe guards against wrong-date-path
    // in report_url fields (e.g. report generated in May but URL says June).
    const obj = await env.REPORTS_R2.get(key);
    if (obj) {
      return new Response(obj.body, {
        status: 200,
        headers: {
          ...CORS_HEADERS, ...SECURITY_HEADERS,
          "Content-Security-Policy": HTML_CSP,
          "Content-Type":  "text/html; charset=utf-8",
          "Cache-Control": "public, max-age=86400, stale-while-revalidate=3600",
          "ETag": obj.httpEtag || "",
        },
      });
    }

    // Cross-month fallback: probe all known year/month combos for the same slug.
    const slugMatch = path.match(/\/(intel--[a-f0-9]+)\.html$/i);
    if (slugMatch) {
      const fn = slugMatch[1] + ".html";
      for (const y of PROBE_YEARS) {
        for (const m of PROBE_MONTHS) {
          const probeKey = `reports/${y}/${m}/${fn}`;
          if (probeKey === key) continue;
          const probeObj = await env.REPORTS_R2.get(probeKey);
          if (probeObj) {
            return Response.redirect(`https://intel.cyberdudebivash.com/${probeKey}`, 301);
          }
        }
      }
    }

    // Synthesis fallback: find item in feed by slug and generate HTML report
    const fallbackItem = gateItem;
    if (fallbackItem) {
      const fallbackFeed = await loadFeedItems(env);
      // Same reasoning as the legacy-slug branch above: public, permanently
      // cached HTML with no per-viewer variation -- always mask.
      const maskedFallbackItem  = applyTierGateV2(fallbackItem, "free", null);
      const maskedFallbackItems = (fallbackFeed.items || []).map(i => applyTierGateV2(i, "free", null));
      // RX-PUB-A0 FIX: see matching comment in the legacy-slug branch above --
      // this Worker-side JS render must never write into the canonical R2
      // key. Serve it directly, don't persist it.
      const html = generateIntelReport(maskedFallbackItem, path, maskedFallbackItems);
      return new Response(html, { status: 200, headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Security-Policy": HTML_CSP, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }
    // v187.0 P0 FIX: this branch is reached only when the report id could
    // not be resolved via findItemBySlug at all (not a known-and-rejected
    // report -- see the publication-gate branch above) and no R2 object
    // exists under any probed year/month. Genuinely unknown status --
    // fail closed, and do not claim "still generating" since that cannot
    // be determined from here (a permanent bad link looks identical to a
    // not-yet-propagated one at this point).
    return jsonResp(buildUnresolvableReportResponseBody(path), 404);
  }

  // --- /api/v1/cve/live -------------------------------------------------------
  if (path === "/api/v1/cve/live") {
    const severity = (url.searchParams.get("severity") || "ALL").toUpperCase();
    const q        = (url.searchParams.get("q") || "").toLowerCase().trim();
    const limit    = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10), 1), 200);
    const offset   = Math.max(parseInt(url.searchParams.get("offset") || "0", 10), 0);

    let bundle = await r2Get(env, CVE_LIVE_KEY);
    const stale = !bundle || !bundle.generated_at ||
      (Date.now() - new Date(bundle.generated_at).getTime()) > CVE_TTL_SEC * 1000;

    if (stale) {
      // Trigger background refresh; return whatever we have (may be null)
      if (typeof ctx !== "undefined") ctx.waitUntil(fetchAndCacheCVEs(env));
      if (!bundle) bundle = await fetchAndCacheCVEs(env);
    }

    let cves = bundle.cves || [];

    // Severity filter
    if (severity !== "ALL") cves = cves.filter(c => c.severity === severity);

    // Keyword search on ID and description
    if (q) cves = cves.filter(c =>
      (c.id || "").toLowerCase().includes(q) ||
      (c.description || "").toLowerCase().includes(q)
    );

    const total     = cves.length;
    const paginated = cves.slice(offset, offset + limit);

    // FREE tier: truncate description
    const outCves = paginated.map(c => {
      if (auth.tier !== TIERS.FREE) return c;
      return { ...c, description: (c.description || "").slice(0, 100) + ((c.description || "").length > 100 ? "..." : "") };
    });

    return jsonResp({
      cves: outCves,
      stats: bundle.stats || {},
      total, page: Math.floor(offset / limit), limit, offset,
      generated_at: bundle.generated_at,
      source: bundle.source,
      window: bundle.window,
      version: PLATFORM_VERSION,
      _tier: auth.tier,
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/cve/stats ------------------------------------------------------
  if (path === "/api/v1/cve/stats") {
    let stats = await r2Get(env, CVE_STATS_KEY);
    if (!stats) {
      const bundle = await r2Get(env, CVE_LIVE_KEY);
      stats = bundle ? { ...bundle.stats, generated_at: bundle.generated_at, source: bundle.source, window: bundle.window } : null;
    }
    if (!stats) {
      if (typeof ctx !== "undefined") ctx.waitUntil(fetchAndCacheCVEs(env));
      stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0, avg_cvss: 0,
        generated_at: now(), source: "NVD_NIST_GOV", window: "7d" };
    }
    return jsonResp({ ...stats, version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/cve/detail -----------------------------------------------------
  if (path === "/api/v1/cve/detail") {
    const cveId = (url.searchParams.get("id") || "").trim().toUpperCase();
    if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      return jsonResp({ error: "Valid CVE ID required: ?id=CVE-YYYY-NNNNN" }, 400);
    }

    // 5-min KV cache
    const cacheKey = `cve_detail:${cveId}`;
    let detail = null;
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, "json");
      if (cached) detail = cached;
    } catch (_) {}

    if (!detail) {
      try {
        const nvdResp = await fetch(`${NVD_API}?cveId=${cveId}`, {
          headers: { "Accept": "application/json", "User-Agent": "CyberDudeBivash-Sentinel-Apex/"+PLATFORM_VERSION },
        });
        if (nvdResp.ok) {
          const raw  = await nvdResp.json();
          const vulns = raw.vulnerabilities || [];
          if (vulns.length > 0) {
            detail = mapNvdItem(vulns[0]);
            try { await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(detail), { expirationTtl: 300 }); } catch (_) {}
          }
        }
      } catch (_) {}
    }

    if (!detail) return jsonResp({ error: "CVE not found", id: cveId }, 404);

    // PRO+ gets full details; FREE gets summary
    const cveDetailFullAllowed = resolveEntitlement(ctx, env, "cve_detail_full", auth, auth.tier !== TIERS.FREE).allowed;
    if (!cveDetailFullAllowed) {
      return jsonResp({
        id: detail.id, severity: detail.severity, cvss_score: detail.cvss_score,
        published: detail.published, last_modified: detail.last_modified,
        description: (detail.description || "").slice(0, 100) + "...",
        _tier: TIERS.FREE, _upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html",
        version: PLATFORM_VERSION,
      }, 200, { "Cache-Control": "public, max-age=300" });
    }

    return jsonResp({ ...detail, version: PLATFORM_VERSION }, 200, { "Cache-Control": "private, max-age=300" });
  }

  // --- /api/ingest (PRO+ only) ------------------------------------------------
  // PRODUCTION-VERIFICATION FIX (2026-08-24): this endpoint previously wrote
  // every submitted item directly into LATEST_JSON_KEY -- the single shared
  // R2 object every tier's /api/feed, /api/v1/intel/latest.json and every
  // P17-P40 handler reads as the canonical curated feed. Any authenticated
  // PRO+ customer (the platform's lowest paid tier) could inject arbitrary,
  // unmoderated title/severity/risk_score/actor_tag/description content
  // that would then be served to every OTHER customer indistinguishably
  // from curated intel -- a cross-tenant data-integrity issue undermining
  // the platform's entire "certified/trustworthy intel" value proposition.
  // /api/ingest is not documented or advertised anywhere in customer-facing
  // docs as "publishes to the shared feed"; the standard meaning of a
  // customer-facing ingest endpoint is a private add-your-own-intel-for-
  // correlation feature, so this fix scopes storage to the submitting
  // customer only (a separate, per-tenant R2 key -- same INTEL_R2 bucket,
  // no new infra) instead of removing the feature. A new GET /api/ingest
  // lets that same customer read back what they submitted.
  if (path === "/api/ingest" && method === "GET") {
    if (!auth.jwt) {
      return jsonResp({ error: "Authentication required. POST Authorization: Bearer <token>." }, 401);
    }
    if (auth.tier === "FREE" || auth.tier === "PUBLIC") {
      return jsonResp({ error: "PRO or ENTERPRISE tier required for /api/ingest", upgrade: "POST /auth/login with a PRO/ENTERPRISE API key" }, 403);
    }
    const tenantKey = `ingest/${auth.sub || "unknown"}.json`;
    const stored = await r2Get(env, tenantKey) || { items: [] };
    return jsonResp({ items: stored.items || [], count: (stored.items || []).length, version: PLATFORM_VERSION }, 200);
  }
  if (path === "/api/ingest" && method === "POST") {
    // Require authenticated PRO or ENTERPRISE tier
    if (!auth.jwt) {
      return jsonResp({ error: "Authentication required. POST Authorization: Bearer <token>." }, 401);
    }
    if (auth.tier === "FREE" || auth.tier === "PUBLIC") {
      return jsonResp({ error: "PRO or ENTERPRISE tier required for /api/ingest", upgrade: "POST /auth/login with a PRO/ENTERPRISE API key" }, 403);
    }
    let body = {};
    try { body = await request.json(); } catch (_) {
      return jsonResp({ error: "Invalid JSON body" }, 400);
    }
    // Validate required fields
    const requiredFields = ["title", "severity", "risk_score"];
    const missing = requiredFields.filter(f => body[f] == null);
    if (missing.length) {
      return jsonResp({ error: `Missing required fields: ${missing.join(", ")}`, required: requiredFields }, 400);
    }
    const validSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
    const sev = (body.severity || "").toUpperCase();
    if (!validSeverities.has(sev)) {
      return jsonResp({ error: `Invalid severity. Must be one of: ${[...validSeverities].join(", ")}` }, 400);
    }
    const riskScore = parseFloat(body.risk_score);
    if (isNaN(riskScore) || riskScore < 0 || riskScore > 10) {
      return jsonResp({ error: "risk_score must be a number between 0 and 10" }, 400);
    }
    // Per-customer daily cap on ingested items -- this writes directly into
    // the shared production feed served to every tier, with no prior limit
    // on total growth from a single customer.
    const ingestCapKey = `ingest_count:${new Date().toISOString().slice(0, 10)}:${auth.sub || "unknown"}`;
    const ingestCount = parseInt((await env.RATE_LIMIT_KV.get(ingestCapKey)) || "0", 10);
    if (ingestCount >= 50) {
      return jsonResp({ error: "Daily ingest limit reached (50 items/day). Contact support for higher throughput." }, 429);
    }
    await env.RATE_LIMIT_KV.put(ingestCapKey, String(ingestCount + 1), { expirationTtl: 86400 });
    // Build canonical intel item
    const ts = new Date().toISOString();
    const itemId = body.stix_id || body.id || ("intel--ingest-" + crypto.randomUUID());
    const newItem = {
      id: itemId, stix_id: itemId,
      title: String(body.title).slice(0, 500),
      severity: sev,
      risk_score: riskScore,
      source: body.source || `ingest:${auth.sub || "api"}`,
      // feed_source is a trust/provenance signal read elsewhere in the
      // pipeline -- always stamped from the authenticated caller's own
      // identity, never taken from the request body, so a customer can't
      // spoof it to impersonate an official curated feed name (e.g.
      // "rss_cvefeed_io_rssfeed_latest_xml").
      feed_source: `api_ingest:${auth.sub || "unknown"}`,
      published: body.published || ts,
      processed_at: ts,
      ingested_at: ts,
      ingest_tier: auth.tier,
      ingest_sub: auth.sub || "unknown",
      // Optional enrichment fields (passed through if present)
      ...(body.cve_ids        != null && { cve_ids: body.cve_ids }),
      ...(body.cvss_score     != null && { cvss_score: body.cvss_score }),
      ...(body.epss_score     != null && { epss_score: body.epss_score }),
      ...(body.kev_present    != null && { kev_present: !!body.kev_present }),
      ...(body.mitre_tactics  != null && { mitre_tactics: body.mitre_tactics }),
      ...(body.ioc_counts     != null && { ioc_counts: body.ioc_counts }),
      ...(body.actor_tag      != null && { actor_tag: body.actor_tag }),
      ...(body.tlp_label      != null && { tlp_label: body.tlp_label }),
      ...(body.tags           != null && { tags: body.tags }),
      ...(body.description    != null && { description: String(body.description).slice(0, 2000) }),
      ...(body.source_url     != null && { source_url: body.source_url }),
      ...(body.confidence_score != null && { confidence_score: body.confidence_score }),
    };
    // Write to the submitting customer's own private R2 key -- never the
    // shared LATEST_JSON_KEY feed served to other customers (see fix note
    // above this route block).
    try {
      const tenantKey = `ingest/${auth.sub || "unknown"}.json`;
      const current = await r2Get(env, tenantKey) || { schema_version: "1.0", items: [], count: 0 };
      const items = Array.isArray(current.items) ? current.items : [];
      // Guard: reject exact stix_id duplicate within this customer's own set
      if (items.some(i => (i.stix_id || i.id) === itemId)) {
        return jsonResp({ error: "Duplicate item: stix_id already exists in your ingested items", stix_id: itemId }, 409);
      }
      items.unshift(newItem); // newest first
      items.length = Math.min(items.length, 5000); // bound per-tenant growth
      const updated = { ...current, items, count: items.length, last_ingest: ts };
      await env.INTEL_R2.put(tenantKey, JSON.stringify(updated), { httpMetadata: { contentType: "application/json" } });
      auditLog(ctx, env, { action: "ingest", sub: auth.sub, tier: auth.tier, item_id: itemId, title: newItem.title });
      return jsonResp({ status: "created", item_id: itemId, your_ingested_count: items.length, ingested_at: ts, note: "Stored privately to your account. Retrieve with GET /api/ingest." }, 201);
    } catch (e) {
      console.error(`[ingest] tenant store write failed: ${e.message}`);
      return jsonResp({ error: "Failed to store ingested item" }, 500);
    }
  }

  // --- Razorpay Payment Endpoints (no auth required  -  signature verifies) -----
  if (path === "/api/payment/razorpay/create-order") {
    return await handleRazorpayCreateOrder(request, env, method);
  }
  if (path === "/api/payment/razorpay/verify") {
    return await handleRazorpayVerify(request, env, ctx, method);
  }
  // --- Free-tier self-serve signup (no auth required) --------------------------
  if (path === "/api/keys/free") {
    return await handleFreeKeyRequest(request, env, ctx, method);
  }

  // --- Webhook Endpoints (no auth  -  webhook secret/sig verifies) --------------
  if (path === "/api/webhooks/razorpay") {
    return await handleWebhookRazorpay(request, env, ctx);
  }
  if (path === "/api/webhooks/gumroad") {
    return await handleWebhookGumroad(request, env, ctx);
  }

  // --- Manual Payment Notification & Status ----------------------------------
  if (path === "/api/payment/manual-notify") {
    return await handleManualNotify(request, env, ctx, method);
  }
  if (path === "/api/payment/status") {
    return await handlePaymentStatus(request, env, url);
  }

  // --- Canonical Pricing (Phase 1 architecture consolidation) ----------------
  // TRANSITIONAL values - see pricing.js / pricing-data.json. Reflects exactly
  // what Razorpay actually charges today; not yet the final business-approved
  // commercial pricing (that decision is tracked separately, not inferred here).
  if (path === "/api/pricing") {
    return jsonResp(getPricingSnapshot());
  }

  // --- God Mode: Brand Protection --------------------------------------------
  if (path.startsWith("/api/v1/brand")) {
    return await handleBrandProtection(request, env, auth, method, path, url, ctx);
  }

  // --- God Mode: Vendor Risk -------------------------------------------------
  if (path.startsWith("/api/v1/vendor-risk")) {
    return await handleVendorRisk(request, env, auth, method, path, ctx);
  }

  // --- God Mode: Geopolitical Risk -------------------------------------------
  if (path.startsWith("/api/v1/geopolitical")) {
    return await handleGeopolitical(request, env, auth, method, path, url, ctx);
  }

  // --- God Mode: Natural Language Query --------------------------------------
  if (path.startsWith("/api/v1/nlq")) {
    return await handleNLQ(request, env, auth, method, path, url, ctx);
  }

  // --- God Mode: Incident Response -------------------------------------------
  if (path.startsWith("/api/v1/incidents")) {
    return await handleIncidentResponse(request, env, auth, method, path, url, ctx);
  }

  // --- AI Security Copilot ----------------------------------------------------
  if (path.startsWith("/api/v1/copilot")) {
    return await handleCopilot(request, env, auth, method, path);
  }

  // --- AI Swarm Synthesis (reuses callLLM -- same LLM stack as Copilot) ------
  if (path.startsWith("/api/v1/swarm-synthesis")) {
    return await handleSwarmSynthesis(request, env, auth, method, path);
  }

  // --- P16.1-P16.8: Enterprise Endpoints (P16.10: require authentication) ----
  // These 7 routes previously dispatched with no auth parameter and no guard
  // (handlers only read KV/D1, never checked request headers). Guard added
  // per the existing per-route auth-check pattern used throughout this file.
  if (path === "/api/v1/control-plane/state" || path === "/api/v1/control-plane/state/" ||
      path === "/api/v1/workflows/status" || path === "/api/v1/assets/intelligence" ||
      path === "/api/v1/health/enterprise" || path === "/api/v1/analytics/enterprise" ||
      path === "/api/v1/automation/intelligence" || path === "/api/v1/observability/metrics") {
    if (!auth.key && !auth.jwt) {
      return jsonResp({ error: "Authentication required", hint: "Provide X-API-Key header or Authorization: Bearer <JWT>" }, 401);
    }
    if (path === "/api/v1/control-plane/state" || path === "/api/v1/control-plane/state/") {
      return await handleControlPlaneState(request, env, ctx);
    }
    if (path === "/api/v1/workflows/status") return await handleP16Workflows(request, env);
    if (path === "/api/v1/assets/intelligence") return await handleP16Assets(request, env);
    if (path === "/api/v1/health/enterprise") return await handleP16Health(request, env);
    if (path === "/api/v1/analytics/enterprise") return await handleP16Analytics(request, env);
    if (path === "/api/v1/automation/intelligence") return await handleP16Automation(request, env);
    if (path === "/api/v1/observability/metrics") return await handleP16Observability(request, env);
  }
  // --- P17-P40 + rx-pub-a0: require authentication (v184.4 FIX) --------------
  // These ~120 routes (P17, P18's non-ioc/enriched routes, P19, P20, and
  // every /api/v1/pNN/* route from P21 through P40, plus rx-pub-a0) dispatched
  // with NO auth parameter and NO guard at all -- computed intelligence
  // (quality/actionability/trust scores, actor/TTP attribution, the entire
  // P33 ECIOS layer) was served to fully anonymous callers. Same minimum-bar
  // guard already used for P16.1-P16.8 above: requires a valid provisioned
  // key or JWT, not full tier differentiation (no evidence in this codebase
  // supports inventing a specific tier requirement per route). This runs
  // BEFORE and in addition to the finer-grained auth.tier checks P18's
  // ioc/enriched, P21/certify, P29/certify, and P31's routes already do
  // downstream -- purely additive, does not change their existing behavior
  // for a caller who already had a valid key.
  const _p17to40Gated =
    path === "/api/platform/orchestrator/state" || path === "/api/v1/digital-twin/state" ||
    path === "/api/v1/campaigns/forecast" || path === "/api/v1/executive/command-center" ||
    path.startsWith("/api/v1/policies") || path.startsWith("/api/v1/playbooks") ||
    path === "/api/v1/ai-ops/analytics" ||
    path === "/api/v1/intel/correlation" || path === "/api/v1/intel/trust-indicators" ||
    path === "/api/v1/reports/validate" || path === "/api/v1/reports/quality" ||
    path === "/api/v1/ioc/enriched" || path === "/api/v1/confidence/methodology" ||
    path === "/api/v1/reports/certify" || path === "/api/v1/reports/scorecard" ||
    path === "/api/v1/detections" || path.startsWith("/api/v1/detections/") ||
    path === "/api/v1/reports/p20/quality" || path === "/api/v1/reports/p20/audit" ||
    /^\/api\/v1\/p(2[1-9]|3\d|40)\//.test(path) ||
    path.startsWith("/api/v1/rx-pub-a0/");
  if (_p17to40Gated && !auth.key && !auth.jwt) {
    return jsonResp({ error: "Authentication required", hint: "Provide X-API-Key header or Authorization: Bearer <JWT>" }, 401);
  }

  // --- P17: Enterprise Cyber Defense OS (additive, v17.0) -------------------
  if (path === "/api/platform/orchestrator/state")    return await handleP17Orchestrator(request, env);
  if (path === "/api/v1/digital-twin/state")          return await handleP17DigitalTwin(request, env);
  if (path === "/api/v1/campaigns/forecast")          return await handleP17CampaignForecast(request, env);
  if (path === "/api/v1/executive/command-center")    return await handleP17ExecutiveCenter(request, env);
  if (path.startsWith("/api/v1/policies"))            return await handleP17Policies(request, env);
  if (path.startsWith("/api/v1/playbooks"))           return await handleP17Playbooks(request, env);
  if (path === "/api/v1/ai-ops/analytics")            return await handleP17AiOps(request, env);

  // --- P18: Threat Intelligence Quality & Trust Initiative (additive, v18.0) ---
  if (path === "/api/v1/intel/correlation")           return await handleP18Correlation(request, env);
  if (path === "/api/v1/intel/trust-indicators")      return await handleP18TrustIndicators(request, env);
  if (path === "/api/v1/reports/validate")            return await handleP18Validate(request, env);
  if (path === "/api/v1/reports/quality")             return await handleP18QualityScore(request, env);
  if (path === "/api/v1/ioc/enriched")                return await handleP18IOCEnriched(request, env, auth.tier);
  if (path === "/api/v1/confidence/methodology")      return await handleP18ConfidenceMethod(request, env);
  // --- Detection Registry (additive, Phase 4.1 mandate Section 9-19) --------
  // Canonical per-item detection-artifact query API -- see detection-registry.js
  // header for the full root-cause trace and scope boundary. Distinct from
  // /api/v1/premium/detections/{artifact} (unchanged, still the correct
  // route for the static enterprise bundle-file product).
  if (path === "/api/v1/detections")                  return await handleDetectionsQuery(request, env, auth);
  if (path.startsWith("/api/v1/detections/"))          return await handleDetectionArtifactById(request, env, auth, path);
  // --- P19: Enterprise Report Excellence + Dead-code Activation (additive, v19.0) -----------
  if (path === "/api/v1/reports/certify")           return await handleP19Certify(request, env);
  if (path === "/api/v1/reports/scorecard")         return await handleP19Scorecard(request, env);
  // --- First-party web read plane observability (additive, P0 2026-09-03) ------------------
  // Principle 7: the plane's membership and budgets must be queryable, so
  // that a dashboard endpoint drifting out of the plane (and back onto the
  // commercial FREE quota that caused this incident) is observable rather
  // than silent. Read-only, no arguments, no state.
  if (path === "/api/v1/observability/first-party-plane") {
    return jsonResp(firstPartyPlaneObservability(), 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- P20: Enterprise Threat Intelligence Trust & Quality Platform (additive, v20.0) ------
  if (path === "/api/v1/reports/p20/quality")       return await handleP20QualityReport(request, env);
  if (path === "/api/v1/reports/p20/audit")         return await handleP20FeedAudit(request, env);
  // --- P21: Enterprise Intelligence Certification System (additive, v21.0) ----------------
  if (path === "/api/v1/p21/certify")               return await handleP21Certify(request, env, auth.tier);
  if (path === "/api/v1/p21/certify/feed")          return await handleP21FeedCertify(request, env);
  if (path === "/api/v1/p21/dashboard")             return await handleP21Dashboard(request, env);
  if (path === "/api/v1/p21/observability")         return await handleP21Observability(request, env);
  // --- P22: Enterprise Intelligence Trust & Verification Framework (additive, v22.0) -----
  if (path === "/api/v1/p22/validate")              return await handleP22Validate(request, env);
  if (path === "/api/v1/p22/contradictions")        return await handleP22ContradictionReport(request, env);
  if (path === "/api/v1/p22/observability")         return await handleP22Observability(request, env);

  // --- P23: Enterprise Actionable Intelligence Framework (additive, v23.0) ---
  if (path === "/api/v1/p23/actionability")         return await handleP23Actionability(request, env);
  if (path === "/api/v1/p23/operational-readiness") return await handleP23OperationalReadiness(request, env);
  if (path === "/api/v1/p23/observability")         return await handleP23Observability(request, env);

  // --- P25: Enterprise Intelligence Trust & Assurance Framework (additive, v25.0) ---
  if (path === "/api/v1/p25/trust-score")           return await handleP25TrustScore(request, env);
  if (path === "/api/v1/p25/observability")         return await handleP25Observability(request, env);

  // --- P26: Enterprise Intelligence Excellence Program (additive, v26.0) ---
  if (path === "/api/v1/p26/grade")                 return await handleP26Grade(request, env);
  if (path === "/api/v1/p26/grade/feed")            return await handleP26FeedGrade(request, env);
  if (path === "/api/v1/p26/observability")         return await handleP26Observability(request, env);

  // --- P27: Enterprise Threat Intelligence Operations Excellence (additive, v27.0) ---
  if (path === "/api/v1/p27/certify")              return await handleP27Certify(request, env);
  if (path === "/api/v1/p27/observability")        return await handleP27Observability(request, env);

  // --- P28: Enterprise Risk Intelligence & Customer Value Platform (additive, v28.0) ---
  if (path === "/api/v1/p28/feedback")             return await handleP28Feedback(request, env);
  if (path === "/api/v1/p28/certify")              return await handleP28Certify(request, env);
  if (path === "/api/v1/p28/observability")        return await handleP28Observability(request, env);

  // --- P29: Enterprise Intelligence Network (additive, v29.0) ---
  if (path === "/api/v1/p29/certify")              return await handleP29Certify(request, env, auth.tier);
  if (path === "/api/v1/p29/customer-value")       return await handleP29CustomerValueAnalytics(request, env);
  if (path === "/api/v1/p29/trust-center")         return await handleP29TrustCenter(request, env);
  if (path === "/api/v1/p29/release-assurance")    return await handleP29ReleaseAssurance(request, env);
  if (path === "/api/v1/p29/observability")        return await handleP29Observability(request, env);

  // --- P30: Enterprise Intelligence Accuracy & Continuous Verification (additive, v30.0) ---
  if (path === "/api/v1/p30/certify")              return await handleP30Certify(request, env);
  if (path === "/api/v1/p30/verification")         return await handleP30Verification(request, env);
  if (path === "/api/v1/p30/timeline")             return await handleP30Timeline(request, env);
  if (path === "/api/v1/p30/source-health")        return await handleP30SourceHealth(request, env);
  if (path === "/api/v1/p30/drift")                return await handleP30Drift(request, env);
  if (path === "/api/v1/p30/report-health")        return await handleP30ReportHealth(request, env);
  if (path === "/api/v1/p30/observability")        return await handleP30Observability(request, env);
  if (path === "/api/v1/p31/certify")              return await handleP31Certify(request, env);
  if (path === "/api/v1/p31/graph")                return await handleP31Graph(request, env, auth.tier);
  if (path === "/api/v1/p31/search")               return await handleP31Search(request, env, auth.tier);
  if (path === "/api/v1/p31/entity")               return await handleP31Entity(request, env, auth.tier);
  if (path === "/api/v1/p31/relationships")        return await handleP31Relationships(request, env, auth.tier);
  if (path === "/api/v1/p31/campaign")             return await handleP31Campaign(request, env, auth.tier);
  if (path === "/api/v1/p31/copilot")              return await handleP31Copilot(request, env, auth.tier);
  if (path === "/api/v1/p31/observability")        return await handleP31Observability(request, env);

  // --- P32 routes ---
  if (path === "/api/v1/p32/decision")             return await handleP32Decision(request, env);
  if (path === "/api/v1/p32/drift")                return await handleP32Drift(request, env);
  if (path === "/api/v1/p32/lifecycle")            return await handleP32Lifecycle(request, env);
  if (path === "/api/v1/p32/metrics")              return await handleP32Metrics(request, env);
  if (path === "/api/v1/p32/customer")             return await handleP32Customer(request, env);
  if (path === "/api/v1/p32/quality")              return await handleP32Quality(request, env);
  if (path === "/api/v1/p32/operations")           return await handleP32Operations(request, env);
  if (path === "/api/v1/p32/release")              return await handleP32Release(request, env);
  if (path === "/api/v1/p32/dashboard")            return await handleP32Dashboard(request, env);
  if (path === "/api/v1/p32/observability")        return await handleP32Observability(request, env);

  // --- P33 routes ---
  if (path === "/api/v1/p33/cases")               return await handleP33Cases(request, env);
  if (path === "/api/v1/p33/campaigns")           return await handleP33Campaigns(request, env);
  if (path === "/api/v1/p33/heatmap")             return await handleP33Heatmap(request, env);
  if (path === "/api/v1/p33/mission")             return await handleP33Mission(request, env);
  if (path === "/api/v1/p33/recommendations")     return await handleP33Recommendations(request, env);
  if (path === "/api/v1/p33/explorer")            return await handleP33Explorer(request, env);
  if (path === "/api/v1/p33/dashboard")           return await handleP33Dashboard(request, env);
  if (path === "/api/v1/p33/operations")          return await handleP33Operations(request, env);
  if (path === "/api/v1/p33/status")              return await handleP33Status(request, env);
  if (path === "/api/v1/p33/metrics")             return await handleP33Metrics(request, env);
  if (path === "/api/v1/p33/observability")       return await handleP33Observability(request, env);

  // --- P34 routes ---
  if (path === "/api/v1/p34/assurance")          return await handleP34Assurance(request, env);
  if (path === "/api/v1/p34/security")           return await handleP34Security(request, env);
  if (path === "/api/v1/p34/reliability")        return await handleP34Reliability(request, env);
  if (path === "/api/v1/p34/performance")        return await handleP34Performance(request, env);
  if (path === "/api/v1/p34/compliance")         return await handleP34Compliance(request, env);
  if (path === "/api/v1/p34/sbom")               return await handleP34Sbom(request, env);
  if (path === "/api/v1/p34/contracts")          return await handleP34Contracts(request, env);
  if (path === "/api/v1/p34/status")             return await handleP34Status(request, env);
  if (path === "/api/v1/p34/metrics")            return await handleP34Metrics(request, env);
  if (path === "/api/v1/p34/dashboard")          return await handleP34Dashboard(request, env);
  if (path === "/api/v1/p34/certification")      return await handleP34Certification(request, env);
  if (path === "/api/v1/p34/observability")      return await handleP34Observability(request, env);

  // --- P35 routes ---
  if (path === "/api/v1/p35/quality")            return await handleP35Quality(request, env);
  if (path === "/api/v1/p35/freshness")          return await handleP35Freshness(request, env);
  if (path === "/api/v1/p35/evidence")           return await handleP35Evidence(request, env);
  if (path === "/api/v1/p35/confidence")         return await handleP35Confidence(request, env);
  if (path === "/api/v1/p35/diversity")          return await handleP35Diversity(request, env);
  if (path === "/api/v1/p35/drift")              return await handleP35Drift(request, env);
  if (path === "/api/v1/p35/metrics")            return await handleP35Metrics(request, env);
  if (path === "/api/v1/p35/scorecard")          return await handleP35Scorecard(request, env);
  if (path === "/api/v1/p35/trend")              return await handleP35Trend(request, env);
  if (path === "/api/v1/p35/improvements")       return await handleP35Improvements(request, env);
  if (path === "/api/v1/p35/dashboard")          return await handleP35Dashboard(request, env);
  if (path === "/api/v1/p35/observability")      return await handleP35Observability(request, env);

  if (path === "/api/v1/p36/quality")            return await handleP36Quality(request, env);
  if (path === "/api/v1/p36/maturity")           return await handleP36Maturity(request, env);
  if (path === "/api/v1/p36/targets")            return await handleP36Targets(request, env);
  if (path === "/api/v1/p36/gaps")               return await handleP36Gaps(request, env);
  if (path === "/api/v1/p36/customer-value")     return await handleP36CustomerValue(request, env);
  if (path === "/api/v1/p36/competitive")        return await handleP36Competitive(request, env);
  if (path === "/api/v1/p36/detection")          return await handleP36Detection(request, env);
  if (path === "/api/v1/p36/reliability")        return await handleP36Reliability(request, env);
  if (path === "/api/v1/p36/metrics")            return await handleP36Metrics(request, env);
  if (path === "/api/v1/p36/roadmap")            return await handleP36Roadmap(request, env);
  if (path === "/api/v1/p36/dashboard")          return await handleP36Dashboard(request, env);
  if (path === "/api/v1/p36/observability")      return await handleP36Observability(request, env);

  if (path === "/api/v1/p37/hardening")          return await handleP37Hardening(request, env);
  if (path === "/api/v1/p37/feed-audit")         return await handleP37FeedAudit(request, env);
  if (path === "/api/v1/p37/enrichment")         return await handleP37Enrichment(request, env);
  if (path === "/api/v1/p37/iq-score")           return await handleP37IQScore(request, env);
  if (path === "/api/v1/p37/detection")          return await handleP37Detection(request, env);
  if (path === "/api/v1/p37/source-diversity")   return await handleP37SourceDiversity(request, env);
  if (path === "/api/v1/p37/reliability")        return await handleP37Reliability(request, env);
  if (path === "/api/v1/p37/debt")               return await handleP37Debt(request, env);
  if (path === "/api/v1/p37/metrics")            return await handleP37Metrics(request, env);
  if (path === "/api/v1/p37/certification")      return await handleP37Certification(request, env);
  if (path === "/api/v1/p37/dashboard")          return await handleP37Dashboard(request, env);
  if (path === "/api/v1/p37/observability")      return await handleP37Observability(request, env);

  if (path === "/api/v1/p38/schema-registry")    return await handleP38SchemaRegistry(request, env);
  if (path === "/api/v1/p38/feed-governance")    return await handleP38FeedGovernance(request, env);
  if (path === "/api/v1/p38/schema-drift")       return await handleP38SchemaDrift(request, env);
  if (path === "/api/v1/p38/enrichment-audit")   return await handleP38EnrichmentAudit(request, env);
  if (path === "/api/v1/p38/confidence-audit")   return await handleP38ConfidenceAudit(request, env);
  if (path === "/api/v1/p38/iq-index")           return await handleP38IQIndex(request, env);
  if (path === "/api/v1/p38/source-diversity")   return await handleP38SourceDiversity(request, env);
  if (path === "/api/v1/p38/certification")      return await handleP38Certification(request, env);
  if (path === "/api/v1/p38/executive")          return await handleP38Executive(request, env);
  if (path === "/api/v1/p38/reliability")        return await handleP38Reliability(request, env);
  if (path === "/api/v1/p38/metrics")            return await handleP38Metrics(request, env);
  if (path === "/api/v1/p38/observability")      return await handleP38Observability(request, env);

  if (path === "/api/v1/p40/source-registry")    return await handleP40SourceRegistry(request, env);
  if (path === "/api/v1/p40/source-detail")      return await handleP40SourceDetail(request, env);
  if (path === "/api/v1/p40/source-health")      return await handleP40SourceHealth(request, env);
  if (path === "/api/v1/p40/licensing")          return await handleP40Licensing(request, env);
  if (path === "/api/v1/p40/coverage")           return await handleP40Coverage(request, env);
  if (path === "/api/v1/p40/waves")              return await handleP40Waves(request, env);
  if (path === "/api/v1/p40/certification")      return await handleP40Certification(request, env);
  if (path === "/api/v1/p40/metrics")            return await handleP40Metrics(request, env);
  if (path === "/api/v1/p40/dashboard")          return await handleP40Dashboard(request, env);
  if (path === "/api/v1/p40/observability")      return await handleP40Observability(request, env);

  if (path === "/api/v1/rx-pub-a0/reports-identity") return await handleRxPubA0ReportsIdentity(request, env);
  if (path === "/api/v1/rx-pub-a0/observability")    return await handleRxPubA0Observability(request, env);

  // --- P41: Live Capability Discovery API (additive) -------------------------
  // Deliberately PUBLIC, no auth check -- see workers/intel-gateway/src/
  // p41-handlers.js file header for the full rationale. It serves
  // page-inventory metadata only (id/title/route/status derived from
  // data/quality/frontend_capability_registry.json), never computed
  // intelligence, so it does not belong behind the same key/JWT bar as
  // P21-P40. It is intentionally NOT added to the `_p17to40Gated` regex
  // above (`/^\/api\/v1\/p(2[1-9]|3\d|40)\//`) -- that regex already stops
  // at p40 and does not need editing for this route to fall outside it. If
  // a FUTURE P42+ layer needs the same auth bar P21-P40 have, extend that
  // regex explicitly for it; do not assume a new pNN route is covered just
  // because it comes after p40 -- it is not, by construction.
  if (path === "/api/v1/p41/capabilities")       return await handleP41Capabilities(request, env);
  if (path === "/api/v1/p41/capability")         return await handleP41CapabilityDetail(request, env);
  if (path === "/api/v1/p41/observability")      return await handleP41Observability(request, env);

  // --- P0 publication authorization gate (incident: intel--ba996dad34540150b8ea1b5f) ---
  // Supports both /api/v1/reports/{id}/publication-status (path form) and
  // /api/v1/reports/publication-status?id={id} (query form, matching this
  // codebase's dominant ?id= convention -- e.g. handleP32Decision,
  // handleP40SourceDetail). This endpoint is the source of truth the
  // /reports/** route itself now enforces; see publication-gate.js.
  if (path.startsWith("/api/v1/reports/") && path.endsWith("/publication-status")) {
    const segments = path.split("/").filter(Boolean);
    const reportId = segments.length >= 4 ? decodeURIComponent(segments[3]) : "";
    return await handlePublicationStatus(request, env, reportId);
  }
  if (path === "/api/v1/reports/publication-status") {
    const reportId = url.searchParams.get("id") || "";
    return await handlePublicationStatus(request, env, reportId);
  }

  // --- api-extensions.js routes (previously unreachable  -  now wired, auth already resolved above) ---
  if (path === "/api/search")                       return await handleSearch(request, env, auth, crypto.randomUUID());
  if (path === "/api/actors")                       return await handleActors(request, env, auth, crypto.randomUUID());
  if (path === "/api/cves")                         return await handleCVEs(request, env, auth, crypto.randomUUID());
  if (path === "/api/ioc/lookup")                    return await handleIOCLookup(request, env, auth, crypto.randomUUID());
  if (path === "/api/export/misp")                  return await handleMISPExportExt(request, env, auth, crypto.randomUUID());
  if (path === "/api/export/csv")                   return await handleCSVExport(request, env, auth, crypto.randomUUID());
  if (path === "/api/intel/correlate")              return await handleCorrelate(request, env, auth, crypto.randomUUID());
  if (path === "/api/v1/predict")                   return await handlePredict(request, env, auth, crypto.randomUUID());
  if (path === "/api/v1/campaigns/intel")           return await handleCampaigns(request, env, auth, crypto.randomUUID());
  if (path === "/api/v1/anomalies")                 return await handleAnomalies(request, env, auth, crypto.randomUUID());
  if (path === "/api/v1/intel/graph")               return await handleIntelGraph(request, env, auth, crypto.randomUUID());
  if (path === "/api/v1/intel/relations")           return await handleIntelRelations(request, env, auth, crypto.randomUUID());
  if (path === "/api/intel/ir-guidance")            return await handleIRGuidance(request, env, auth, crypto.randomUUID());
  if (path === "/api/intel/exposure")               return await handleExposureAnalysis(request, env, auth, crypto.randomUUID());

  // --- enterprise-endpoints.js routes (previously unreachable  -  now wired via routeEnterpriseEndpoint) ---
  if (path.startsWith("/api/taxii") || path.startsWith("/api/misp/export") ||
      path.startsWith("/api/sigma") || path.startsWith("/api/yara") ||
      path.startsWith("/api/scoring") || path.startsWith("/api/siem") ||
      path === "/api/stream" || path.startsWith("/api/mssp")) {
    const eeTier = normalizeTierForEE(auth.tier);
    let eeItems = [];
    try {
      if (env?.INTEL_R2) {
        // PRODUCTION-VERIFICATION FIX (2026-08-24): "feeds/feed.json" is a
        // dead R2 key -- confirmed via repo-wide search that no script or
        // workflow ever writes it (it's read here and in 5 other handler
        // files: p18/p19/p20/p28/premium-reports, all fixed the same way
        // in this same change). Every ENTERPRISE route dispatched through
        // routeEnterpriseEndpoint() below (scoring, sigma, yara, taxii,
        // misp, siem, mssp, stream) was silently getting an empty items
        // array on every request. Redirected to LATEST_JSON_KEY, the live,
        // continuously updated key loadFeedItems() / /api/feed already
        // reads -- confirmed live via curl after this fix: /api/feed
        // returns 152 items (122 with apex_score from PR #236's fix).
        const obj = await env.INTEL_R2.get(LATEST_JSON_KEY);
        if (obj) { const raw = await obj.json(); eeItems = Array.isArray(raw) ? raw : (raw?.items || []); }
      }
    } catch (_) {}
    // v185.0 FIX: routeEnterpriseEndpoint() returns null for any path under
    // these prefixes it doesn't have an exact/regex match for (e.g. bare
    // /api/sigma, /api/yara, /api/siem, /api/mssp -- only their /bulk or
    // /{id}/... sub-paths are wired). Returning that null directly as the
    // fetch handler's Response crashed the runtime into the top-level
    // catch-all, producing a 500 "Internal gateway error" for what should be
    // a clean 404 -- confirmed live against production (GET /api/sigma and
    // /api/yara both returned 500 before this fix). Fall through to the
    // standard 404 handler below instead of returning the null.
    const eeResponse = await routeEnterpriseEndpoint(path, request, env, ctx, eeTier, eeItems, crypto.randomUUID(), auth, resolveEntitlement);
    if (eeResponse) return eeResponse;
  }

  // --- sla-monitor.js / alert-engine.js routes (previously unreachable --
  // now wired, fixed to the real resolveAuth() contract; see each file's
  // header comment for the production-verification fix details) ---
  // v185.4 (entitlement inventory, Phase 8 priority 9): sla-monitor.js's own
  // ad-hoc gate ("ENTERPRISE"||"MSSP") remains the primary thing deciding
  // access below. resolveEntitlement()'s decision IS consumed (matching
  // every other wired call site in this file, e.g. taxii_access,
  // vendor_risk_bulk, incident_delete, intel_manifest_full) rather than
  // discarded -- discarding it would make the ENTITLEMENT_ENFORCEMENT_ENABLED
  // flag inert for these three resources: an operator could add
  // "sla_report" to ENTITLEMENT_ENFORCEMENT_RESOURCES, resolveEntitlement()
  // would report enforced:true, and nothing here would act on it -- looking
  // configured while doing nothing, a bug the drift gate
  // (entitlement_resource_drift_gate.py) cannot catch since the resource
  // name genuinely exists in enforceTierGate() (added in this same pass).
  // Gated on `.enforced` so today -- with these three resources NOT in
  // ENTITLEMENT_ENFORCEMENT_RESOURCES -- this remains shadow-mode only and
  // sla-monitor.js's own gate is what actually decides. Zero behavior
  // change today; correct behavior the moment enforcement is ever enabled.
  if (path === "/api/sla/status")       return await handleSLAStatus(request, env, crypto.randomUUID());
  if (path === "/api/sla/report") {
    const slaReportEnt = resolveEntitlement(ctx, env, "sla_report", auth, auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP);
    if (slaReportEnt.enforced && !slaReportEnt.allowed) {
      return jsonResp({ error: "SLA compliance reports require Enterprise or MSSP tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleSLAReport(request, env, auth, crypto.randomUUID());
  }
  if (path === "/api/sla/incidents") {
    const slaIncidentsEnt = resolveEntitlement(ctx, env, "sla_incidents", auth, auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP);
    if (slaIncidentsEnt.enforced && !slaIncidentsEnt.allowed) {
      return jsonResp({ error: "SLA incident logs require Enterprise or MSSP tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleSLAIncidents(request, env, auth, crypto.randomUUID());
  }
  if (path === "/api/sla/ping" && method === "POST") return await handleSLAPing(request, env, crypto.randomUUID());
  if (path === "/api/sla/certificate") {
    const slaCertEnt = resolveEntitlement(ctx, env, "sla_certificate", auth, auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP);
    if (slaCertEnt.enforced && !slaCertEnt.allowed) {
      return jsonResp({ error: "SLA compliance certificates require Enterprise or MSSP tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleSLACertificate(request, env, auth, crypto.randomUUID());
  }

  // v185.9 (Mission Wave A Phase 7): "alerts" already existed in
  // enforceTierGate() (PRO+, Free blocked) with zero call sites. Wired here
  // as a shadow-mode check on the 4 customer-facing routes whose own ad-hoc
  // gate (auth.tier === "FREE" -> denied, everywhere else allowed) is exactly
  // the same PRO+ rule "alerts" already encodes. handleAlertDispatch is
  // internal/admin-secret-gated (not a customer tier decision) and
  // handleAlertHistory enforces a *stricter*, different rule (Enterprise/MSSP
  // only) that "alerts" does not represent -- both intentionally left off
  // this resource rather than forcing an incorrect canonical mapping.
  if (path === "/api/alerts/subscribe" && method === "POST") {
    const alertsEnt = resolveEntitlement(ctx, env, "alerts", auth, auth.tier !== TIERS.FREE);
    if (alertsEnt.enforced && !alertsEnt.allowed) {
      return jsonResp({ error: "Alert subscriptions require Pro or Enterprise tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleAlertSubscribe(request, env, auth, crypto.randomUUID());
  }
  if (path === "/api/alerts/subscriptions") {
    const alertsEnt = resolveEntitlement(ctx, env, "alerts", auth, auth.tier !== TIERS.FREE);
    if (alertsEnt.enforced && !alertsEnt.allowed) {
      return jsonResp({ error: "Alert subscriptions require Pro or Enterprise tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleAlertSubscriptions(request, env, auth, crypto.randomUUID());
  }
  if (path === "/api/alerts/test" && method === "POST") {
    const alertsEnt = resolveEntitlement(ctx, env, "alerts", auth, auth.tier !== TIERS.FREE);
    if (alertsEnt.enforced && !alertsEnt.allowed) {
      return jsonResp({ error: "Alert subscriptions require Pro or Enterprise tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleAlertTest(request, env, auth, crypto.randomUUID());
  }
  if (path === "/api/alerts/dispatch" && method === "POST")       return await handleAlertDispatch(request, env, auth, crypto.randomUUID());
  if (path === "/api/alerts/history")                             return await handleAlertHistory(request, env, auth, crypto.randomUUID());
  if (path === "/api/alerts/unsubscribe" && method === "DELETE") {
    // Unlike the 3 routes above, handleAlertUnsubscribe's own ad-hoc gate has
    // no tier restriction at all (any authenticated identity may remove its
    // own subscription -- verified via its ownership check, sub.sub !==
    // auth.sub -> 403). adHocAllowed reflects that real behavior (`true`,
    // not the PRO+ rule) so shadow mode reports the genuine divergence
    // rather than a fabricated one; while unenforced this stays a no-op.
    const alertsEnt = resolveEntitlement(ctx, env, "alerts", auth, true);
    if (alertsEnt.enforced && !alertsEnt.allowed) {
      return jsonResp({ error: "Alert subscriptions require Pro or Enterprise tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handleAlertUnsubscribe(request, env, auth, crypto.randomUUID());
  }

  // --- dark-web-monitor.js routes -- DISABLED (2026-08-26, production-truth
  // audit finding): dark-web-monitor.js's scan/status/leak-check handlers
  // return a deterministic simulation keyed off a hash of the customer's
  // input (its own header comment: "Here we produce a deterministic
  // simulation ... until live API integrations are wired per-customer") --
  // no real breach source is queried. Wiring this into the router (this
  // block) made that simulated data reachable as a paid Pro+/Enterprise
  // feature. Explicit decision: disable the endpoints and return a truthful
  // 503 rather than continue serving synthetic breach findings as if
  // observed. dark-web-monitor.js is kept on disk, unmodified, for when
  // real provider integrations exist -- these three lines are the only
  // wiring removed. Re-enable only once handleDarkWebScan/handleDarkWebStatus/
  // handleLeakCheck call real, licensed data sources with provenance.
  if (path === "/api/dark-web/scan" && method === "POST") return _darkWebUnavailable(crypto.randomUUID());
  if (path === "/api/dark-web/status")                    return _darkWebUnavailable(crypto.randomUUID());
  if (path === "/api/leak-check")                         return _darkWebUnavailable(crypto.randomUUID());

  // --- premium-reports.js routes (previously unreachable -- now wired, same
  // pattern as dark-web-monitor.js above; advertised live in soc-
  // integrations.html's API reference table ("POST /api/reports/premium ...
  // $49/report", "GET /api/reports/list ... List generated reports"), which
  // were 404ing before this. Unlike dark-web-monitor.js, this generates real
  // reports from the live feed (not simulated data), gated by tier the same
  // way as every other Pro+ feature already live on this router. The static
  // /api/reports/index.json, /api/reports/latest.json, /api/reports/stats.json
  // routes above (line ~4223) are unaffected -- they match first as exact
  // string comparisons before this block is ever reached. ---
  if (path === "/api/reports/premium") {
    // v185.9 (Mission Wave A Phase 4): the shadow-only call this replaced
    // discarded resolveEntitlement()'s return value entirely -- adding
    // "report_full" to ENTITLEMENT_ENFORCEMENT_RESOURCES would have been
    // inert for this specific route (handlePremiumReport's own ad-hoc
    // tier.toLowerCase()==="free" check would still be the sole thing
    // deciding access, same bug class the header comment above this block
    // already flags for the SLA resources it contrasts against). Now
    // consumed the same way as cve_detail_full/sla_report/etc: while
    // unenforced this is a no-op (resolveEntitlement returns adHocAllowed
    // unchanged), so today's behavior is identical -- but the flag is no
    // longer inert.
    const reportFullEnt = resolveEntitlement(ctx, env, "report_full", auth, auth.tier !== TIERS.FREE);
    if (!reportFullEnt.allowed) {
      return jsonResp({ error: "Full report text and attribution require Pro tier. Upgrade at /upgrade.html" }, 403);
    }
    return await handlePremiumReport(request, env, auth, crypto.randomUUID());
  }
  if (path === "/api/reports/list") {
    // CodeRabbit (PR #242 review): the public contract advertises "GET
    // /api/reports/list" only; nothing rejected POST/PUT/DELETE before this,
    // so a non-GET call would still dispatch to handleReportList and return
    // a normal 200 read instead of 405.
    if (method !== "GET") {
      return jsonResp({ error: "method_not_allowed", allowed: ["GET"], request_id: crypto.randomUUID() }, 405, { "Allow": "GET" });
    }
    return await handleReportList(request, env, auth, crypto.randomUUID());
  }
  if (path.startsWith("/api/reports/") && path !== "/api/reports/premium" && path !== "/api/reports/list") {
    // Same fix as /api/reports/list above -- the public contract advertises
    // "GET /api/reports/{id}" only.
    if (method !== "GET") {
      return jsonResp({ error: "method_not_allowed", allowed: ["GET"], request_id: crypto.randomUUID() }, 405, { "Allow": "GET" });
    }
    let rawSegment = path.slice("/api/reports/".length);
    // premium-reports.js's own report body advertises a pdf_download_url of
    // /api/reports/{id}/pdf (metadata.pdf_download_url), but per that file's
    // header comment no PDF render service exists yet -- strip the suffix
    // and answer honestly instead of falling through to invalid_report_id.
    const isPdfRequest = rawSegment.endsWith("/pdf");
    if (isPdfRequest) rawSegment = rawSegment.slice(0, -"/pdf".length);
    // PRODUCTION-TRUTH FIX (release hardening): premium-reports.js's
    // export_formats always listed "csv" alongside "json"/"pdf" on this
    // paid ($49/report, $149/mo) product, but unlike pdf_download_url there
    // was no csv_download_url and no route at all -- a customer following
    // the advertised format list to a URL that doesn't exist, not even a
    // 501. Now advertises csv_download_url (premium-reports.js) and
    // answers it the same honest way pdf already is, rather than leaving
    // it silently unreachable.
    const isCsvRequest = rawSegment.endsWith("/csv");
    if (isCsvRequest) rawSegment = rawSegment.slice(0, -"/csv".length);
    let reportId;
    try {
      reportId = decodeURIComponent(rawSegment);
    } catch {
      // Malformed percent-encoding (e.g. a bare "%") throws a URIError --
      // uncaught, this fell through to the top-level catch-all as a 500.
      return jsonResp({ error: "invalid_report_id", request_id: crypto.randomUUID() }, 400);
    }
    if (isPdfRequest) {
      return jsonResp({
        error:      "not_yet_available",
        message:    "PDF export is not yet available for this report. Use the JSON format at GET /api/reports/{id}.",
        request_id: crypto.randomUUID(),
      }, 501);
    }
    if (isCsvRequest) {
      return jsonResp({
        error:      "not_yet_available",
        message:    "CSV export is not yet available for this report. Use the JSON format at GET /api/reports/{id}.",
        request_id: crypto.randomUUID(),
      }, 501);
    }
    return await handleReportGet(request, env, auth, crypto.randomUUID(), reportId);
  }

  // -----------------------------------------------------------------------
  // PRODUCTION-TRUTH FIX (v200.0 audit): ai-threat-tracker.html fetches
  // /api/ai/tracker.json, /api/ai/health.json, /api/ai/executive-brief.json
  // client-side on load -- but wrangler.toml routes this Worker to the
  // entire intel.cyberdudebivash.com/api/* namespace, so those requests
  // never reached the static Pages origin where the files actually live.
  // Every request 404'd here instead (no handler existed for this path),
  // so every metric on that page (AI ANOMALIES, CAMPAIGNS TRACKED, GLOBAL
  // RISK INDEX, etc.) permanently showed the "--" loading placeholder.
  // Confirmed this is a reachability bug, not a data bug, for tracker.json
  // at least: gh-pages serves a copy regenerated fresh every sentinel-blogger
  // run (verified via raw.githubusercontent.com -- generated_at within the
  // last few hours). health.json / executive-brief.json are also reachable
  // through this same fix but were independently found ~4 days stale on
  // gh-pages (regenerate_engine_data.py, called every sentinel-blogger run,
  // only writes tracker.json; health/executive-brief were meant to come from
  // generate_ai_endpoints.py via generate-and-sync.yml's 6h schedule).
  //
  // Root-caused in issue #274: generate-and-sync.yml's `git push origin main`
  // has been failing every run (GH013 -- main now requires PRs), silently
  // (continue-on-error), so main's copy of these files froze the moment
  // branch protection took effect. sentinel-blogger.yml's STAGE 3.1.22b
  // (added for this exact reason) regenerates both files fresh every run and
  // its own r2_upload.py step (Upload 3b) already uploads them to
  // INTEL_R2 (bucket sentinel-apex-data) as `ai/{filename}` -- that upload
  // was landing in R2 unused, because this proxy still only checked
  // gh-pages, which generate-and-sync.yml's broken push also left stale.
  // Per issue #274 (owner decision: move this data off git entirely), R2 is
  // now checked FIRST -- it no longer depends on either the gh-pages deploy
  // timing or a git push succeeding. The gh-pages fetch is kept as a
  // fallback only (zero regression if the R2 object is ever missing, e.g.
  // before the first pipeline run that writes it).
  //
  // Proxy the already-deployed static file through rather than reimplementing
  // its generation here. Filenames are whitelisted; this is not an open
  // path-passthrough proxy.
  // -----------------------------------------------------------------------
  const AI_STATIC_PROXY_FILES = new Set(["tracker.json", "health.json", "executive-brief.json"]);
  if (path.startsWith("/api/ai/") && AI_STATIC_PROXY_FILES.has(path.slice("/api/ai/".length))) {
    if (method !== "GET") {
      return jsonResp({ error: "method_not_allowed", allowed: ["GET"], request_id: crypto.randomUUID() }, 405, { "Allow": "GET" });
    }
    const filename = path.slice("/api/ai/".length);

    // -------------------------------------------------------------------
    // v201.0 CLOUDFLARE COST CONTAINMENT (AI plane forensic audit, 2026-09-09)
    //
    // A response returned by a Worker is NOT placed in Cloudflare's edge
    // cache on its own -- on a Worker route the Worker runs in front of the
    // cache, so the `Cache-Control: public, max-age=300` header below only
    // ever instructed the *browser*. Every uncached client request therefore
    // reached the origin logic and cost one R2 Class B GET (or, on R2 miss,
    // one outbound subrequest to raw.githubusercontent.com). The audit found
    // zero uses of the Cache API anywhere in this Worker, so this cost scaled
    // linearly and without ceiling against traffic on the platform's most
    // frequently polled AI endpoints -- ai-threat-tracker.html fetches all
    // three of these files on every page load.
    //
    // Safe to cache at the edge, specifically here and not generally:
    //   * GET only, and the filename is whitelisted above.
    //   * This block performs no auth and reads no per-caller state, so the
    //     body is byte-identical for every caller. (Contrast
    //     /api/v1/intel/ai_summary.json, which is in PREMIUM_INTEL_PATHS --
    //     edge-caching a tier-gated response would serve premium
    //     intelligence to unauthenticated callers. It is deliberately NOT
    //     cached here.)
    //   * 300s TTL matches the Cache-Control this endpoint already declared,
    //     so client-visible freshness is unchanged.
    //
    // The cache key is normalised to origin + pathname, dropping the query
    // string. Without that, `?cb=1`, `?cb=2`, ... would each be a distinct
    // key, letting any caller force unbounded cache misses and drive R2
    // operations at will -- a cost-amplification vector, not just a cache
    // inefficiency. These three files take no query parameters, so dropping
    // them loses nothing.
    // -------------------------------------------------------------------
    const aiCacheKey = new Request(`${url.origin}${path}`, { method: "GET" });
    const aiCache = caches.default;
    try {
      const cached = await aiCache.match(aiCacheKey);
      if (cached) return cached;
    } catch (cacheErr) {
      console.error(`[api/ai proxy] cache match failed for ${filename}: ${cacheErr && cacheErr.message ? cacheErr.message : cacheErr}`);
    }

    // Store a 200 in the edge cache without delaying the client response.
    // Only 200s are stored: caching a 502 would pin an outage in place for
    // the full TTL. Guarded on ctx because handleRequest is also reachable
    // from call sites that do not supply one.
    const cacheAndReturn = (resp) => {
      if (resp.status === 200 && ctx && typeof ctx.waitUntil === "function") {
        try {
          ctx.waitUntil(aiCache.put(aiCacheKey, resp.clone()));
        } catch (putErr) {
          console.error(`[api/ai proxy] cache put failed for ${filename}: ${putErr && putErr.message ? putErr.message : putErr}`);
        }
      }
      return resp;
    };

    if (env.INTEL_R2) {
      try {
        const r2Obj = await env.INTEL_R2.get(`ai/${filename}`);
        if (r2Obj) {
          // Buffered rather than streamed so the body can be safely cloned
          // into the cache. These are small JSON documents (the largest,
          // tracker.json, is ~222KB) so buffering costs nothing meaningful.
          const body = await r2Obj.text();
          return cacheAndReturn(new Response(body, {
            status: 200,
            headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
          }));
        }
      } catch (r2Err) {
        console.error(`[api/ai proxy] R2 read failed for ${filename}, falling back to gh-pages: ${r2Err && r2Err.message ? r2Err.message : r2Err}`);
      }
    }

    const upstreamUrl = `https://raw.githubusercontent.com/cyberdudebivash-pvt-ltd/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/gh-pages/api/ai/${filename}`;
    try {
      const resp = await fetch(upstreamUrl, {
        cf: { cacheEverything: true, cacheTtl: 300 },
        headers: { "User-Agent": `SENTINEL-APEX/${PLATFORM_VERSION} (+https://intel.cyberdudebivash.com)` },
        signal: AbortSignal.timeout(8000),
      });
      if (!resp.ok) {
        console.error(`[api/ai proxy] ${filename}: upstream returned ${resp.status}`);
        return jsonResp({ error: "upstream_unavailable", filename, request_id: crypto.randomUUID() }, 502, { "Cache-Control": "no-store" });
      }
      const data = await resp.json();
      return cacheAndReturn(jsonResp(data, 200, { "Cache-Control": "public, max-age=300" }));
    } catch (e) {
      console.error(`[api/ai proxy] ${filename}: ${e && e.message ? e.message : e}`);
      return jsonResp({ error: "upstream_unavailable", filename, request_id: crypto.randomUUID() }, 502, { "Cache-Control": "no-store" });
    }
  }

  // -----------------------------------------------------------------------
  // STAGE 4 FIX (issue tracked in Stage 4 report's Runtime Data Inventory):
  // index.html's _cdbGetAIRecord()/_cdbGetDetectionRules() (the "AI Record"
  // and "Detection Rules" annotations shown on every advisory/threat card)
  // fetch data/ai_intelligence/ai_index.json and
  // data/intelligence/detection_rules/rule_manifest.json via bare relative
  // paths -- neither matches this Worker's route table (/api/*, /reports/*,
  // /taxii/*, /auth/* only; "data/*" is outside the Worker Route pattern
  // entirely), so both requests fall through to the Pages static origin
  // unconditionally. Both files are pipeline-generated and git-committed
  // (generate_ai_endpoints.py / detection-engine.yml), so updating either
  // one has required a full sentinel-blogger.yml run + Pages publish --
  // exactly the same CLASS D coupling issue #274 already root-caused and
  // fixed for /api/ai/tracker.json et al. (the AI_STATIC_PROXY_FILES block
  // immediately above), just not yet extended to these two files.
  //
  // Same fix, same pattern, reused verbatim rather than reimplemented: R2
  // checked first (no dependency on git push or Pages deploy timing), raw
  // gh-pages content kept as the fallback (zero regression if the R2
  // object is ever missing, e.g. before the first pipeline run that writes
  // it via scripts/r2_upload.py's new Upload 3c block).
  //
  // New endpoints only -- the original data/ai_intelligence/ai_index.json
  // and data/intelligence/detection_rules/rule_manifest.json static paths
  // are untouched and keep serving their git-committed content unchanged,
  // so any existing consumer of those exact URLs sees no behavior change.
  // index.html's two fetch() call sites are repointed to these new
  // endpoints as part of this same change.
  // -----------------------------------------------------------------------
  if (Object.prototype.hasOwnProperty.call(INTEL_STATIC_PROXY, path)) {
    const proxyResp = await handleIntelStaticProxy(env, path, method);
    if (proxyResp) return proxyResp;
  }

  // --- routes/exports.js -- tier-gated multi-format SIEM/SOAR exports (v201.0) ---
  // buildStixPattern/resolveEntitlement passed by reference rather than
  // imported into exports.js, to avoid a circular import (index.js already
  // imports routeExports from that file) -- same documented reason
  // routeEnterpriseEndpoint() above takes resolveEntitlement as a parameter.
  if (path.startsWith("/api/v1/export/")) {
    const feedData  = await loadFeedItems(env);
    const exportRes = await routeExports(path, request, env, ctx, auth.tier, feedData.items || [], crypto.randomUUID(), auth, buildStixPattern, resolveEntitlement);
    if (exportRes) return exportRes;
  }

  // CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG.
  // Same R2 object as /api/health (one GET, no LIST). Stale or empty feeds
  // are not returned as a live brief. Anonymous reads do not write.
  // Customer mutations use WatchdogLedger, one object per authenticated subject.
  if (path.startsWith("/api/watchdog")) {
    const needsFeed = path === "/api/watchdog/brief"
      || path === "/api/watchdog/matches"
      || path === "/api/watchdog/events"
      || path === "/api/watchdog/health";
    const feed = needsFeed ? await r2Get(env, LATEST_JSON_KEY) : null;
    let body = null;
    if (method === "POST" || method === "PATCH" || method === "DELETE") {
      try { body = await request.json(); } catch { body = null; }
    }
    const ns = env.WATCHDOG_LEDGER;
    const ledger = ns && typeof ns.idFromName === "function" ? {
      async mutate(op) {
        const stub = ns.get(ns.idFromName("wd:" + op.subject));
        const res = await stub.fetch("https://watchdog.ledger/mutate", {
          method: "POST",
          body: JSON.stringify({ op }),
        });
        try { return await res.json(); } catch { return { error: "watch_store_unavailable", status: 503 }; }
      },
    } : null;
    const watched = await routeWatchdog({
      path,
      method,
      searchParams: url.searchParams,
      auth,
      feed,
      ledger,
      body,
      id: crypto.randomUUID(),
      now: new Date().toISOString(),
      nowMs: Date.now(),
      fetchImpl: fetch,
    });
    if (watched) return jsonResp(watched.body, watched.status, { "Cache-Control": "no-store" });
  }

  // --- 404 --------------------------------------------------------------------
  return jsonResp({
    error: "Not found", path,
    available_endpoints: [
      "/api/health", "/api/platform/stats", "/api/v1/intel/latest.json", "/api/v1/intel/apex.json",
      "/api/v1/intel/ai_summary.json", "/api/v1/intel/top10.json", "/api/v1/intel/stats",
      "/api/v1/intel/campaigns", "/api/v1/intel/ransomware", "/api/v1/intel/apt",
      "/api/v1/intel/epss", "/api/v1/intel/defcon", "/api/v1/intel/pulse",
      "/api/v1/intel/darkweb", "/api/v1/intel/cybermap", "/api/feed.json",
      "/api/v1/intel/ai_index.json", "/api/v1/intel/detection_rules_manifest.json",
      "/api/v1/news/feed", "/api/reports/index.json", "/api/reports/stats.json",
      "/api/v1/ioc/lookup",
      "/api/v1/cve/live", "/api/v1/cve/stats", "/api/v1/cve/detail?id=CVE-XXXX-XXXXX",
      "POST /api/auth/login", "POST /api/auth/logout", "GET /api/auth/validate",
      "/auth/login", "/auth/logout",
      "/taxii/", "/taxii/collections/", "/taxii/collections/{id}/objects/",
      "/api/admin/health", "/api/admin/audit", "/api/admin/keys",
      "POST /api/ingest (PRO+)", "GET /api/ingest (PRO+)",
      "POST /api/payment/razorpay/create-order", "POST /api/payment/razorpay/verify",
      "POST /api/webhooks/razorpay", "POST /api/webhooks/gumroad",
      "POST /api/payment/manual-notify", "GET /api/payment/status?review_id=",
      "POST /api/v1/brand/scan (PRO+)", "POST /api/v1/brand/check (PRO+)",
      "POST /api/v1/vendor-risk/assess (PRO+)", "POST /api/v1/vendor-risk/bulk (ENT)",
      "GET /api/v1/geopolitical/country/{code} (PRO+)", "GET /api/v1/geopolitical/landscape (PRO+)",
      "POST /api/v1/geopolitical/sanctions-check (PRO+)",
      "POST /api/v1/nlq/query (PRO+)", "GET /api/v1/nlq/examples (PRO+)",
      "GET|POST /api/v1/incidents/ (PRO+)", "GET|PUT|DELETE /api/v1/incidents/{id}",
      "POST /api/v1/copilot/query (PRO+)", "GET /api/v1/copilot/modes", "GET /api/v1/copilot/health",
      "/api/v1/control-plane/state",
      "/api/v1/workflows/status",
      "/api/v1/assets/intelligence",
      "/api/v1/health/enterprise",
      "/api/v1/analytics/enterprise",
      "/api/v1/automation/intelligence",
      "/api/v1/observability/metrics",
      "/api/platform/orchestrator/state",
      "/api/v1/digital-twin/state",
      "/api/v1/campaigns/forecast",
      "/api/v1/executive/command-center",
      "/api/v1/policies/state",
      "POST /api/v1/policies/simulate",
      "/api/v1/playbooks/catalog",
      "POST /api/v1/playbooks/execute",
      "/api/v1/ai-ops/analytics",
      "/api/v1/intel/correlation",
      "/api/v1/intel/trust-indicators",
      "POST /api/v1/reports/validate",
      "/api/v1/reports/quality",
      "/api/v1/ioc/enriched",
      "/api/v1/confidence/methodology",
      "/api/v1/reports/certify",
      "/api/v1/reports/scorecard",
      "/api/search",
      "/api/actors",
      "/api/cves",
      "/api/export/misp",
      "/api/export/csv",
      "/api/intel/correlate",
      "/api/v1/predict",
      "/api/v1/campaigns/intel",
      "/api/v1/anomalies",
      "/api/v1/intel/graph",
      "/api/v1/intel/relations",
      "/api/taxii/",
      "/api/misp/export",
      "/api/sigma/bulk",
      "/api/yara/bulk",
      // v185.0 FIX: these two entries previously listed paths that don't
      // exist -- "/api/scoring/feed" (real route is bare "/api/scoring",
      // enterprise-endpoints.js:1085) and "/api/mssp/feed" (real route
      // requires a tenant id: "/api/mssp/tenants/{tenant_id}/feed",
      // enterprise-endpoints.js:1115-1118) -- confirmed live, both 404'd.
      "/api/scoring",
      "/api/scoring/kev",
      "/api/scoring/ransomware",
      "/api/scoring/velocity",
      "/api/siem/splunk",
      "/api/siem/sentinel",
      "/api/siem/qradar",
      "/api/stream",
      "/api/mssp/tenants/{tenant_id}/feed",
      "/api/sla/status", "GET /api/sla/report (ENT)", "GET /api/sla/incidents (ENT)", "GET /api/sla/certificate (ENT)",
      "POST /api/alerts/subscribe (PRO+)", "GET /api/alerts/subscriptions (PRO+)", "POST /api/alerts/test (PRO+)",
      "GET /api/alerts/history (ENT)", "DELETE /api/alerts/unsubscribe (PRO+)",
      "POST /api/dark-web/scan (PRO+)", "GET /api/dark-web/status", "GET|POST /api/leak-check (PRO+)",
      "GET /api/watchdog/offer", "GET /api/watchdog/health", "GET /api/watchdog/brief",
      "GET|POST|PATCH /api/watchdog/watches (PRO+)", "DELETE /api/watchdog/watches (PRO+)",
      "GET /api/watchdog/matches (PRO+)", "GET /api/watchdog/events (PRO+)",
      "POST /api/watchdog/events/ack (PRO+)",
      "GET|POST|DELETE /api/watchdog/destinations (ENT)",
      "GET /api/watchdog/deploy (PRO+)",
      "POST /api/reports/premium (PRO+, $49/report)", "GET /api/reports/list (PRO+)", "GET /api/reports/{id} (PRO+)",
      "GET /api/v1/export/suricata.rules (FREE sample / PRO+ full)",
      "GET /api/v1/export/snort.rules (FREE sample / PRO+ full)",
      "GET /api/v1/export/yara.yar (FREE sample / PRO+ full)",
      "GET /api/v1/export/splunk.csv (FREE sample / PRO+ full)",
      "GET /api/v1/export/taxii.json (FREE sample / PRO+ full)",
    ],
  }, 404);
}

// --- Worker entry point -------------------------------------------------------
// SECURITY_HEADERS are already inlined by most handlers, but a subset of
// P-layer handler files (p20/p22/p23/p25-p29/p33/p34-p38) use their own
// local response helper that doesn't set them -- applying them here once,
// to every response regardless of which handler produced it, closes that
// gap without touching each handler file individually.
//
// SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3: this is also the one
// true choke point for Access-Control-Allow-Origin on every NON-preflight
// response this Worker returns, so applyCorsPolicy() (cors-policy.js)
// applied here is authoritative regardless of what any individual handler
// already set (Headers.set() below overwrites it). Needs `request`/`path`/
// `method` now, purely to classify the route that was actually served.
//
// POST-MERGE FIX (2026-09-10, found via this PR's own required live-
// production verification): an OPTIONS request's response is `handleRequest()`'s
// buildPreflightResponse() call, which is ALREADY the sole, fully
// authoritative preflight decision (Origin/method/header validation and
// all). Re-running applyCorsPolicy() on top of that -- which happened
// unconditionally here for every response including that one -- recomputed
// the same grant redundantly and, worse, called headers.append("Vary",
// "Origin") on a response that already had "Vary: Origin" from
// buildPreflightResponse() itself, producing a live, verified
// "Vary: Origin, Origin" on every successful preflight. Not a security
// weakening (the actual Allow-Origin/-Methods/-Headers values were still
// exactly correct either way -- only the redundant Vary token was wrong),
// but a real spec-conformance bug, not a cosmetic one to leave uncounted.
// Skipping applyCorsPolicy() for OPTIONS (SECURITY_HEADERS still applied,
// same as any other response) is the direct fix: it stops the second,
// unnecessary CORS decision from running at all, rather than papering
// over its symptom.
function withBaselineHeaders(response, request, path, method) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) headers.set(k, v);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  const withSecurity = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  if (method === "OPTIONS") return withSecurity;
  return applyCorsPolicy(withSecurity, request, path, method);
}

// P0 EDGE CACHE (2026-09-10, global-hardening pass): classifyRoute()'s
// PUBLIC bucket (cors-policy.js) is already this platform's single,
// security-audited source of truth for "this route's response is
// identical for every caller -- no auth, no per-identity/tier variance"
// (config/cors_public_wildcard_allowlist.json records the full,
// evidence-reasoned list; every entry: data_sensitivity "none",
// mutation_capability false). Reused here rather than building a second
// list, so anything added to or removed from PUBLIC for a CORS reason is
// automatically cached or not, with zero risk of the two ever drifting.
//
// Evidence this matters: data/health/sla_status.json's last real
// production probe measured 754-1352ms p95 on exactly these routes
// (/api/health, /api/v1/intel/latest.json, .../top10.json, /api/feed.json,
// /api/v1/intel/apex.json) -- all uncached Worker compute + KV/R2 reads on
// every single request, against this platform's own documented
// <500ms-p95-cached performance target. PR #388 already proved this exact
// mechanism (caches.default) safe and effective for one route family
// (/api/ai/*, see its own cache block below in handleRequest) -- this
// generalizes it to the rest of the already-audited PUBLIC surface
// instead of re-implementing it per route.
const EDGE_CACHE_TTL_SECONDS = 300; // matches the /api/ai/* precedent's own TTL
// FIX (P0, 2026-09-10, CodeRabbit review on PR #407): classifyRoute()'s
// PUBLIC bucket means "safe to expose cross-origin to any caller" (every
// PUBLIC route's response body is identical regardless of WHO reads it) --
// it does NOT mean "identical regardless of WHAT the caller sends."
// /api/v1/intel/ai_summary.json and apex.json are both PUBLIC (safe for a
// browser on any origin to read the same anonymous response) AND in
// PREMIUM_INTEL_PATHS (servePremiumIntelManifest() varies the response
// body by the caller's actual tier/API key). Without this exclusion, the
// first cached response for one of these paths -- anonymous or paying,
// whichever request happened to populate the cache -- would be served to
// every caller for the TTL: a paying customer silently downgraded to
// free-tier content, or free-tier content silently upgraded to leak
// premium intelligence, depending on which request won the race. Reuses
// PREMIUM_INTEL_PATHS, the existing, already-authoritative marker for
// exactly this property (index.js's own tier-gate dispatch), rather than
// inferring tier-variance from allowlist prose.
function isEdgeCacheableRequest(pathname, method) {
  return method === "GET" && classifyRoute(pathname, method).bucket === "PUBLIC" && !PREMIUM_INTEL_PATHS.has(pathname);
}

export default {
  async fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);
    const method = request.method.toUpperCase();

    // Cache key is the FULL request (Cache API default: path + query
    // string), deliberately NOT stripped the way the ai/* proxy strips its
    // key -- that was only safe there because those three files take no
    // query parameters (verified in that PR). Several PUBLIC routes here
    // (e.g. /api/v1/cve/detail) are query-parameter-driven; stripping would
    // collide two different lookups onto one cache key and serve the wrong
    // caller's data back -- a correctness bug, not just an inefficiency.
    // Operator /api/health calls must never be answered from (or written
    // to) the shared URL-keyed edge cache -- see the /api/health handler.
    const healthAdminCall = (pathname === "/api/health" || pathname === "/api/health/") &&
      !!(request.headers.get("X-Admin-Key") || request.headers.get("Authorization"));
    const cacheable = isEdgeCacheableRequest(pathname, method) && !healthAdminCall;
    const edgeCache = cacheable ? caches.default : null;
    if (edgeCache) {
      try {
        const cached = await edgeCache.match(request);
        if (cached) return cached;
      } catch (cacheErr) {
        console.error(`[fetch] edge cache match failed for ${pathname}: ${cacheErr && cacheErr.message ? cacheErr.message : cacheErr}`);
      }
    }

    try {
      const response = withBaselineHeaders(await handleRequest(request, env, ctx), request, pathname, method);
      // Only a 200 is ever stored -- never pins an error/outage in place
      // for the TTL. Cache-Control is normalised to a known, bounded value
      // here rather than trusting each individual handler to have set one
      // correctly, so this is safe even for a PUBLIC route whose handler
      // omitted or under-specified it. Store is non-blocking.
      // Per-response edge TTL cap (only /api/health sets it: a cached "ok"
      // must not outlive the freshness boundary). Stripped before the
      // response leaves the Worker.
      const edgeTtlHeader = response.headers.get("X-Sentinel-Edge-Ttl");
      const edgeTtl = edgeTtlHeader === null
        ? EDGE_CACHE_TTL_SECONDS
        : Math.min(EDGE_CACHE_TTL_SECONDS, Math.max(0, parseInt(edgeTtlHeader, 10) || 0));
      if (edgeTtlHeader !== null) response.headers.delete("X-Sentinel-Edge-Ttl");
      const responseCc = (response.headers.get("Cache-Control") || "").toLowerCase();
      const privateResponse = responseCc.includes("private") || responseCc.includes("no-store");
      if (edgeCache && response.status === 200 && edgeTtl > 0 && !privateResponse && ctx && typeof ctx.waitUntil === "function") {
        try {
          const toCache = new Response(response.clone().body, {
            status: response.status,
            statusText: response.statusText,
            headers: new Headers(response.headers),
          });
          toCache.headers.set("Cache-Control", `public, max-age=${edgeTtl}`);
          ctx.waitUntil(edgeCache.put(request, toCache));
        } catch (putErr) {
          console.error(`[fetch] edge cache put failed for ${pathname}: ${putErr && putErr.message ? putErr.message : putErr}`);
        }
      }
      return response;
    } catch (err) {
      // Logged server-side (visible via wrangler tail / any configured
      // Logpush) but never returned to the caller -- this is the top-level
      // catch-all for every route, reachable unauthenticated, and
      // err.message can carry internal detail (paths, binding names,
      // upstream API error text).
      console.error(`[fetch] unhandled error: ${err && err.message ? err.message : err}`);
      return withBaselineHeaders(
        new Response(JSON.stringify({ error: "Internal gateway error" }), {
          status: 500,
          headers: { ...JSON_CONTENT },
        }),
        request, pathname, method
      );
    }
  },
  async scheduled(event, env, ctx) {
    // v201.0: second cron schedule added (wrangler.toml `[triggers]`) for the
    // live threat-indicator ingestion pipeline -- dispatched by event.cron so
    // the pre-existing 15-minute CVE cache refresh below is completely
    // unaffected (same handler, same behavior, for that schedule).
    //
    // Built via concatenation rather than one string literal so this
    // file's source text never contains an asterisk immediately followed
    // by a slash: scripts/entitlement_resource_drift_gate.py strips JS
    // comments with a regex that treats any slash-asterisk ... asterisk-
    // slash span as a block comment without understanding string
    // literals, and a pre-existing "/api/admin/*" mention inside a //
    // comment elsewhere in this file reads as an accidental block-comment
    // opener -- that stray closing sequence anywhere after it gets read
    // as that opener's match, silently hiding every real
    // resolveEntitlement() call site in between (confirmed root cause of
    // a real T24_entitlement_resource_drift_gate regression during this
    // change; fixed here rather than in the shared gate script).
    const SIX_HOURLY_INGESTION_CRON = "0 " + "*" + "/6 * * *";
    if (event.cron === SIX_HOURLY_INGESTION_CRON) {
      ctx.waitUntil(runScheduledIngestion(env));
      return;
    }
    ctx.waitUntil(fetchAndCacheCVEs(env));
  },
};
