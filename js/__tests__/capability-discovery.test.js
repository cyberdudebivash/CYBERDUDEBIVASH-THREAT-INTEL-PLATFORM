import assert from "node:assert/strict";
import { test } from "node:test";
import CapabilityDiscovery from "../capability-discovery.js";

// ---------------------------------------------------------------------------
// js/capability-discovery.js -- P41 frontend consumer. This file has no jsdom
// dependency (none exists elsewhere in this repo's js/__tests__ suite), so
// it exercises only the DOM-free pure functions the module exports
// (isSafeRoute, statusLabel, buildViewModel, classifyResult). mount() itself
// (the thin DOM-touching layer) was verified in a real headless browser --
// see the PR description for that verification's exact steps/output.
// ---------------------------------------------------------------------------

// ── isSafeRoute: XSS / malformed-URL defense-in-depth ───────────────────────

test("isSafeRoute: accepts a normal same-origin path", () => {
  assert.equal(CapabilityDiscovery.isSafeRoute("/cves.html"), true);
  assert.equal(CapabilityDiscovery.isSafeRoute("/enterprise-quality-center.html"), true);
});

test("isSafeRoute: rejects javascript: URLs", () => {
  assert.equal(CapabilityDiscovery.isSafeRoute("javascript:alert(1)"), false);
  assert.equal(CapabilityDiscovery.isSafeRoute("javascript:alert(document.cookie)"), false);
});

test("isSafeRoute: rejects data: URLs", () => {
  assert.equal(CapabilityDiscovery.isSafeRoute("data:text/html,<script>alert(1)</script>"), false);
});

test("isSafeRoute: rejects protocol-relative URLs", () => {
  assert.equal(CapabilityDiscovery.isSafeRoute("//evil.example.com/phish.html"), false);
});

test("isSafeRoute: rejects absolute external URLs", () => {
  assert.equal(CapabilityDiscovery.isSafeRoute("https://evil.example.com"), false);
  assert.equal(CapabilityDiscovery.isSafeRoute("http://evil.example.com/x.html"), false);
});

test("isSafeRoute: rejects HTML-breaking / non-path strings", () => {
  assert.equal(CapabilityDiscovery.isSafeRoute("<script>alert(1)</script>"), false);
  assert.equal(CapabilityDiscovery.isSafeRoute("\"><img src=x onerror=alert(1)>"), false);
  assert.equal(CapabilityDiscovery.isSafeRoute(""), false);
  assert.equal(CapabilityDiscovery.isSafeRoute(null), false);
  assert.equal(CapabilityDiscovery.isSafeRoute(undefined), false);
  assert.equal(CapabilityDiscovery.isSafeRoute(42), false);
});

// ── statusLabel ───────────────────────────────────────────────────────────

test("statusLabel: known statuses map to human copy", () => {
  assert.equal(CapabilityDiscovery.statusLabel("live"), "Live — dynamic, real-time data");
  assert.equal(CapabilityDiscovery.statusLabel("static_content"), "Reference / informational");
});

test("statusLabel: unknown/missing status degrades to a safe default, never throws", () => {
  assert.equal(CapabilityDiscovery.statusLabel("some_future_status_value"), "Available");
  assert.equal(CapabilityDiscovery.statusLabel(undefined), "Available");
  assert.equal(CapabilityDiscovery.statusLabel(null), "Available");
});

// ── buildViewModel: malformed records, XSS payloads, missing fields ────────

test("buildViewModel: well-formed payload produces the expected items", () => {
  const vm = CapabilityDiscovery.buildViewModel({
    registry_generated_at: "2026-09-01T00:00:00Z",
    capabilities: [
      { id: "cves.html", title: "Cves", frontend_route: "/cves.html", status: "live" },
      { id: "ransomware.html", title: "Ransomware", frontend_route: "/ransomware.html", status: "live" },
    ],
  });
  assert.equal(vm.total, 2);
  assert.equal(vm.generatedAt, "2026-09-01T00:00:00Z");
  assert.equal(vm.items[0].title, "Cves");
});

test("buildViewModel: empty capabilities array produces total:0, not a crash", () => {
  const vm = CapabilityDiscovery.buildViewModel({ capabilities: [] });
  assert.equal(vm.total, 0);
  assert.deepEqual(vm.items, []);
});

test("buildViewModel: missing capabilities key (malformed payload) produces total:0, not a crash", () => {
  const vm = CapabilityDiscovery.buildViewModel({});
  assert.equal(vm.total, 0);
  const vm2 = CapabilityDiscovery.buildViewModel(null);
  assert.equal(vm2.total, 0);
  const vm3 = CapabilityDiscovery.buildViewModel(undefined);
  assert.equal(vm3.total, 0);
});

test("buildViewModel: one malformed entry is dropped, the rest still render", () => {
  const vm = CapabilityDiscovery.buildViewModel({
    capabilities: [
      { id: "cves.html", frontend_route: "/cves.html", status: "live" },
      { id: "broken" /* missing frontend_route */ },
      null,
      "not-an-object",
      { id: "ransomware.html", frontend_route: "/ransomware.html", status: "live" },
    ],
  });
  assert.equal(vm.total, 2);
  assert.deepEqual(vm.items.map((i) => i.id), ["cves.html", "ransomware.html"]);
});

test("buildViewModel: an entry with a hostile frontend_route (XSS payload) is dropped entirely, not rendered with a neutered href", () => {
  const vm = CapabilityDiscovery.buildViewModel({
    capabilities: [
      { id: "evil", title: "<script>alert(1)</script>", frontend_route: "javascript:alert(document.cookie)", status: "live" },
      { id: "cves.html", frontend_route: "/cves.html", status: "live" },
    ],
  });
  assert.equal(vm.total, 1);
  assert.equal(vm.items[0].id, "cves.html");
});

test("buildViewModel: falls back to id when title is missing, never fabricates a description", () => {
  const vm = CapabilityDiscovery.buildViewModel({
    capabilities: [{ id: "mystery-page.html", frontend_route: "/mystery-page.html", status: "orphan" }],
  });
  assert.equal(vm.items[0].title, "mystery-page.html");
});

// ── classifyResult: the full failure-class taxonomy must map to explicit states ──

test("classifyResult: a successful non-empty response classifies as 'success'", () => {
  const c = CapabilityDiscovery.classifyResult({ ok: true, data: { capabilities: [{ id: "a.html", frontend_route: "/a.html", status: "live" }] } });
  assert.equal(c.state, "success");
  assert.equal(c.viewModel.total, 1);
});

test("classifyResult: a successful but genuinely empty response classifies as 'empty', not 'error' or fabricated zero-metrics", () => {
  const c = CapabilityDiscovery.classifyResult({ ok: true, data: { capabilities: [] } });
  assert.equal(c.state, "empty");
});

test("classifyResult: timeout classifies as 'error' with the failure class surfaced in the message", () => {
  const c = CapabilityDiscovery.classifyResult({ ok: false, failureClass: "timeout", message: "Request timed out. Data unavailable." });
  assert.equal(c.state, "error");
  assert.match(c.message, /timeout/);
});

test("classifyResult: http_5xx, http_4xx, malformed_json, and network all classify as 'error', never silently as empty", () => {
  for (const fc of ["http_5xx", "http_4xx", "malformed_json", "network"]) {
    const c = CapabilityDiscovery.classifyResult({ ok: false, failureClass: fc, message: "x" });
    assert.equal(c.state, "error", `failureClass ${fc} must classify as error`);
  }
});

test("classifyResult: a null/undefined result (defensive) classifies as 'error', never crashes", () => {
  assert.equal(CapabilityDiscovery.classifyResult(null).state, "error");
  assert.equal(CapabilityDiscovery.classifyResult(undefined).state, "error");
});
