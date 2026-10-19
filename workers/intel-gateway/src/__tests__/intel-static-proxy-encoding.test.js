import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { weeklyBriefIsCurrent } from "../intel-static-proxy.js";

test("Worker proxy source contains ASCII bytes only for strict integrity/build gate", () => {
  const bytes = readFileSync(new URL("../intel-static-proxy.js", import.meta.url));
  assert.equal(bytes.every(byte => byte <= 0x7f), true);
});

test("escaped source separator preserves canonical Week 42 ISO period", () => {
  const now = Date.parse("2026-10-19T12:00:00Z");
  const current = {
    _schema: "sentinel-apex-weekly-brief-v1",
    week: "Week 42 2026",
    period: "12 Oct 2026 " + String.fromCharCode(0x2014) + " 18 Oct 2026",
    generated_at: "2026-10-19T09:00:00Z",
    stats: {total_advisories: 1},
    top_threats: [{title:"Public advisory",tlp:"TLP:CLEAR"}]
  };
  assert.equal(weeklyBriefIsCurrent(current, now), true);
  assert.equal(weeklyBriefIsCurrent({...current,period:"12 Oct 2026 - 18 Oct 2026"},now),false);
});
