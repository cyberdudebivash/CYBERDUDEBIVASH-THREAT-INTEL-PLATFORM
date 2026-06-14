/**
 * CYBERDUDEBIVASH(R) SENTINEL APEX - k6 API Load Test
 * tests/load/k6-api-load-test.js
 *
 * Usage:
 *   k6 run tests/load/k6-api-load-test.js
 *   k6 run --env TARGET_URL=https://intel.cyberdudebivash.com tests/load/k6-api-load-test.js
 *   k6 run --env API_KEY=cdb_pro_xxx --env SCENARIO=load tests/load/k6-api-load-test.js
 *
 * Scenarios:
 *   smoke  - 5 VUs for 1m  (quick sanity check)
 *   load   - ramp to 50 VUs over 9m (sustained load)
 *   spike  - burst to 200 VUs (stress test rate limiting)
 *
 * Thresholds:
 *   p95 latency < 500ms for public endpoints
 *   error rate < 1%
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Counter, Trend, Rate } from "k6/metrics";

const TARGET_URL = __ENV.TARGET_URL || "https://intel.cyberdudebivash.com";
const API_KEY    = __ENV.API_KEY || "";
const SCENARIO   = __ENV.SCENARIO || "smoke";

const rateLimitHits = new Counter("rate_limit_hits");
const authErrors    = new Counter("auth_errors");
const apiLatency    = new Trend("api_latency_ms");
const successRate   = new Rate("success_rate");

const SMOKE_OPTS = {
  scenarios: {
    smoke: { executor: "constant-vus", vus: 5, duration: "1m" },
  },
  thresholds: {
    http_req_duration: ["p(95)<500"],
    http_req_failed: ["rate<0.01"],
    success_rate: ["rate>0.99"],
  },
};

const LOAD_OPTS = {
  scenarios: {
    load: {
      executor: "ramping-vus",
      stages: [
        { duration: "2m", target: 25 },
        { duration: "5m", target: 50 },
        { duration: "2m", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    http_req_failed: ["rate<0.01"],
    success_rate: ["rate>0.99"],
  },
};

const SPIKE_OPTS = {
  scenarios: {
    spike: {
      executor: "ramping-vus",
      stages: [
        { duration: "30s", target: 200 },
        { duration: "1m", target: 200 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<2000"],
    http_req_failed: ["rate<0.05"],
  },
};

export const options = SCENARIO === "load" ? LOAD_OPTS : SCENARIO === "spike" ? SPIKE_OPTS : SMOKE_OPTS;

const authHeaders = API_KEY
  ? { "X-API-Key": API_KEY }
  : {};

function checkSecurityHeaders(res) {
  check(res, {
    "has HSTS":              (r) => r.headers["Strict-Transport-Security"] !== undefined,
    "has X-Content-Type":    (r) => r.headers["X-Content-Type-Options"] === "nosniff",
    "has X-Frame-Options":   (r) => r.headers["X-Frame-Options"] === "DENY",
    "has X-Sentinel-Version":(r) => r.headers["X-Sentinel-Version"] !== undefined,
  });
}

export default function () {
  // --- Public health check ---
  group("health", () => {
    const res = http.get(`${TARGET_URL}/api/health`);
    const ok  = check(res, {
      "health 200":    (r) => r.status === 200,
      "health has ok": (r) => JSON.parse(r.body || "{}").status === "ok",
    });
    successRate.add(ok);
    apiLatency.add(res.timings.duration);
    checkSecurityHeaders(res);
    if (res.status === 429) rateLimitHits.add(1);
  });

  sleep(0.2);

  // --- Public intel endpoints ---
  group("public_intel", () => {
    const endpoints = [
      "/api/v1/intel/stats",
      "/api/v1/intel/defcon",
      "/api/v1/intel/ransomware",
      "/api/v1/intel/apt",
    ];

    for (const ep of endpoints) {
      const res = http.get(`${TARGET_URL}${ep}`);
      const ok  = check(res, {
        [`${ep} 200`]: (r) => r.status === 200,
        [`${ep} json`]: (r) => {
          try { JSON.parse(r.body); return true; } catch { return false; }
        },
      });
      successRate.add(ok);
      apiLatency.add(res.timings.duration);
      if (res.status === 429) rateLimitHits.add(1);
    }
  });

  sleep(0.3);

  // --- Authenticated endpoints (only if API key provided) ---
  if (API_KEY) {
    group("authenticated_intel", () => {
      const res = http.get(`${TARGET_URL}/api/v1/intel/apex.json`, { headers: authHeaders });
      const ok  = check(res, {
        "apex.json 200":     (r) => r.status === 200,
        "apex.json has tier":(r) => JSON.parse(r.body || "{}").schema_version !== undefined,
      });
      successRate.add(ok);
      if (res.status === 401 || res.status === 403) authErrors.add(1);
      if (res.status === 429) rateLimitHits.add(1);
    });

    sleep(0.2);
  }

  // --- TAXII discovery (public) ---
  group("taxii_discovery", () => {
    const res = http.get(`${TARGET_URL}/taxii/`, {
      headers: { "Accept": "application/taxii+json;version=2.1" },
    });
    check(res, {
      "taxii discovery 200": (r) => r.status === 200,
      "taxii has title":     (r) => JSON.parse(r.body || "{}").title !== undefined,
    });
    if (res.status === 429) rateLimitHits.add(1);
  });

  sleep(0.5);

  // --- IOC lookup ---
  group("ioc_lookup", () => {
    const res = http.get(`${TARGET_URL}/api/v1/ioc/lookup?q=CVE-2024-0001`);
    check(res, {
      "ioc lookup 200": (r) => r.status === 200,
    });
    if (res.status === 429) rateLimitHits.add(1);
  });

  sleep(0.5);
}

export function handleSummary(data) {
  const now = new Date().toISOString();
  const summary = {
    timestamp: now,
    scenario: SCENARIO,
    target: TARGET_URL,
    metrics: {
      http_reqs: data.metrics.http_reqs?.values?.count || 0,
      http_req_duration_p95: data.metrics.http_req_duration?.values?.["p(95)"] || 0,
      http_req_failed_rate: data.metrics.http_req_failed?.values?.rate || 0,
      rate_limit_hits: data.metrics.rate_limit_hits?.values?.count || 0,
      auth_errors: data.metrics.auth_errors?.values?.count || 0,
    },
    thresholds_passed: Object.entries(data.metrics)
      .filter(([_, m]) => m.thresholds)
      .every(([_, m]) => Object.values(m.thresholds).every(t => t.ok)),
  };

  console.log("\n=== SENTINEL APEX Load Test Summary ===");
  console.log(JSON.stringify(summary, null, 2));

  return {
    "stdout": JSON.stringify(summary, null, 2) + "\n",
    "/tmp/k6-load-test-result.json": JSON.stringify(summary, null, 2),
  };
}
