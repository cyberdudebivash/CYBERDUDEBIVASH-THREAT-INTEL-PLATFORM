// GET /reports/sitemap.xml: the customer-ready report catalog as a sitemap.
// Pure builder tests + route tests through worker.fetch (watchdog-harness).
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildReportsSitemapXml, reportPath, lastmodOf, SITE_ORIGIN, MAX_SITEMAP_URLS } from "../reports-sitemap.js";
import { harness } from "./watchdog-harness.js";
import { CERTIFICATION_INDEX_KEY, CERTIFICATION_POLICY_VERSION } from "../certification-registry.js";

const R = (id, month = "09", ts = "2026-09-20T10:00:00Z") =>
  ({ id, path: `/reports/2026/${month}/${id}.html`, url: `${SITE_ORIGIN}/reports/2026/${month}/${id}.html`, timestamp: ts, title: "t" });

test("builder: one <url> per servable report, absolute loc, W3C lastmod", () => {
  const xml = buildReportsSitemapXml([R("intel--aa11"), R("intel--bb22", "08", "2026-08-01T00:00:00Z")]);
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>\n<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.equal((xml.match(/<url>/g) || []).length, 2);
  assert.ok(xml.includes(`<loc>${SITE_ORIGIN}/reports/2026/09/intel--aa11.html</loc><lastmod>2026-09-20</lastmod>`));
  assert.ok(xml.includes("<lastmod>2026-08-01</lastmod>"));
  assert.ok(xml.trimEnd().endsWith("</urlset>"));
});

test("builder: drops non-report, foreign-origin, malformed and duplicate entries", () => {
  const xml = buildReportsSitemapXml([
    R("intel--aa11"), R("intel--aa11"),                       // duplicate
    { path: "/pricing.html" },                                 // not a report
    { url: "https://evil.example/reports/2026/09/intel--x.html" },
    { path: "/reports/2026/09/intel--x.html?<script>" },
    { path: "/reports/../../etc/passwd" },
    null, 42, "x",
  ]);
  assert.equal((xml.match(/<url>/g) || []).length, 1);
  assert.ok(!xml.includes("evil.example") && !xml.includes("<script>") && !xml.includes("passwd"));
});

test("builder: path derived from url when path is absent; no lastmod when timestamp is bad", () => {
  assert.equal(reportPath({ url: `${SITE_ORIGIN}/reports/2026/07/intel--cc33.html` }), "/reports/2026/07/intel--cc33.html");
  assert.equal(lastmodOf({ timestamp: "not a date" }), null);
  const xml = buildReportsSitemapXml([{ url: `${SITE_ORIGIN}/reports/2026/07/intel--cc33.html` }]);
  assert.ok(xml.includes("<url><loc>") && !xml.includes("<lastmod>"));
});

test("builder: capped at the sitemaps.org per-file limit", () => {
  const many = Array.from({ length: MAX_SITEMAP_URLS + 5 }, (_, i) => R("intel--" + i.toString(16)));
  const xml = buildReportsSitemapXml(many);
  assert.equal((xml.match(/<url>/g) || []).length, MAX_SITEMAP_URLS);
});

function withCatalog(hx, catalog, certRecords) {
  const base = hx.env.INTEL_R2.get;
  hx.env.INTEL_R2.get = async (key) => {
    const payload = key === "api/reports/index.json" ? catalog
      : key === CERTIFICATION_INDEX_KEY ? certRecords && { schema_version: "1.0.0", records: certRecords }
      : undefined;
    if (payload === undefined) return base(key);
    if (payload === null) return null;
    const text = JSON.stringify(payload);
    return { text: async () => text, json: async () => JSON.parse(text) };
  };
  hx.env.INTEL_R2.put = async () => {};
}

test("route: lists CUSTOMER_READY reports only, as application/xml", async () => {
  const hx = harness();
  // These synthetic historical snapshots model records certified under the
  // current policy. Legacy records without proof must never enter a sitemap.
  const certified = fingerprint => ({
    publication_status: "CUSTOMER_READY", certification_status: "CERTIFIED",
    policy_version: CERTIFICATION_POLICY_VERSION,
    content_hash: fingerprint, blocking_gates: [],
  });
  withCatalog(hx, { reports: [R("intel--aa11"), R("intel--bb22"), R("intel--cc33"), R("intel--dd44")] }, {
    "intel--aa11": certified("fp_12345678"),
    "intel--bb22": { publication_status: "WITHHELD", certification_status: "BLOCKED" },
    "intel--cc33": certified("fp_aabbccdd"),
    "intel--dd44": { publication_status: "CUSTOMER_READY", certification_status: "CERTIFIED" },
  });
  const res = await hx.call("GET", "/reports/sitemap.xml");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("Content-Type"), /^application\/xml/);
  assert.ok(res.text.includes("/reports/2026/09/intel--aa11.html"));
  assert.ok(res.text.includes("/reports/2026/09/intel--cc33.html"));
  assert.ok(!res.text.includes("intel--bb22"), "a withheld report (404 on /reports/**) must not be listed");
  assert.ok(!res.text.includes("intel--dd44"), "legacy customer-ready without proof must never enter sitemap");
});

test("route: 503 + Retry-After when the catalog is unavailable", async () => {
  const hx = harness();
  withCatalog(hx, null, {});
  const res = await hx.call("GET", "/reports/sitemap.xml");
  assert.equal(res.status, 503);
  assert.equal(res.headers.get("Retry-After"), "3600");
});

test("route: non-GET is refused", async () => {
  const hx = harness();
  withCatalog(hx, { reports: [] }, {});
  const res = await hx.call("POST", "/reports/sitemap.xml", { body: {} });
  assert.equal(res.status, 405);
});
