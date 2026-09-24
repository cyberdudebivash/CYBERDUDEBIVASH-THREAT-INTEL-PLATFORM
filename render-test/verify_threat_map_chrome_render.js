#!/usr/bin/env node
/**
 * SENTINEL APEX — Threat Map / Demo Video Chrome Render Regression Test
 * ====================================================================
 * Real-browser (headless Chromium) verification that the homepage's
 * "Premium interactive threat map" (#299) and self-hosted demo video
 * (#299/#309/#310) actually render, and stay rendered through the exact
 * new user interactions those PRs added -- immersive fullscreen expand
 * and city hover tooltips -- instead of only checking for thrown errors.
 *
 * Root cause this closes: #cdb-threat-canvas has a long documented
 * history (index.html's RC1-RC13 / v159-v186 governance CSS comments;
 * js/engines/renderer-recovery-engine.js's blank-frame scanner;
 * js/engines/compositor-governance-engine.js) of going silently blank
 * on real hardware-accelerated Chrome from GPU compositor layer
 * pre-promotion -- a failure mode that throws no JS error and 404s
 * nothing, so it is invisible to verify_pages_fast_publish_smoke.js and
 * every other existing render-test/*.js script (grepped: none reference
 * the threat map or demo video). That blind spot is exactly why this
 * one panel reached production broken 13+ times before being caught by
 * a real customer's bug report each time. This script is the first
 * automated check that samples actual canvas pixel content instead of
 * only watching for thrown errors, and the first to exercise the new
 * (#299) fullscreen-toggle and tooltip interaction code at all.
 *
 * It cannot reproduce the GPU-hardware-specific trigger itself --
 * headless Chromium here runs on SwiftShader software rendering, not
 * the D3D11/ANGLE hardware path prior incidents were traced to -- but it
 * locks in what IS deterministic and host-independent: the canvas must
 * never be left with no painted content, the governed CSS properties
 * the RC1-RC13 history traced the trap to (will-change/transform/
 * box-shadow/border-radius on the canvas) must stay neutralized, and
 * none of the new interaction-layer code may throw. A future regression
 * that reintroduces any of those properties, or that leaves the canvas
 * zero-sized after the immersive toggle, fails this check even without
 * hardware acceleration, because the properties are asserted directly.
 *
 * Same pattern as this directory's other verify_*.js scripts -- local
 * static server + Playwright, hermetic (non-local requests aborted),
 * record()/exitCode convention -- and designed to run alongside
 * verify_pages_fast_publish_smoke.js in pages-fast-publish.yml.
 *
 * Usage:
 *   node render-test/verify_threat_map_chrome_render.js [dist-dir]
 *   (defaults to "dist" at the repo root, same default as
 *   verify_pages_fast_publish_smoke.js)
 *
 * Exit code 0 = all checks passed. Exit code 1 = at least one failed.
 */
'use strict';

const path = require('path');
const { startStaticServer } = require('./lib/static-server');
const http = require('http');
const fs = require('fs');
const { chromium } = require('playwright');

const REPO_ROOT = path.resolve(__dirname, '..');
const ROOT_DIR = path.resolve(REPO_ROOT, process.argv[2] || 'dist');
const PORT = 8960; // next free port after this dir's other scripts (8943/8944/8958) to avoid collision if ever run together
const PAGE_URL = `http://127.0.0.1:${PORT}/index.html`;
const NAV_TIMEOUT_MS = 20_000;

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.json': 'application/json', '.txt': 'text/plain', '.ico': 'image/x-icon',
  '.mp4': 'video/mp4',
};

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}

// Sampled-grid pixel check -- same concept as js/engines/renderer-recovery-
// engine.js's own _isBlank() blank-frame scanner (a stride sample, not a
// full scan), reused here as the definition of "actually painted".
async function canvasPaintRatio(page) {
  return page.evaluate(() => {
    const canvas = document.getElementById('cdb-threat-canvas');
    if (!canvas) return { found: false, ratio: 0, w: 0, h: 0 };
    const w = canvas.width, h = canvas.height;
    if (!w || !h) return { found: true, ratio: 0, w, h };
    const ctx = canvas.getContext('2d');
    const data = ctx.getImageData(0, 0, w, h).data;
    let nonZero = 0, sampleCount = 0;
    for (let i = 0; i < data.length; i += 400) {
      sampleCount++;
      if (data[i] || data[i + 1] || data[i + 2] || data[i + 3]) nonZero++;
    }
    return { found: true, ratio: sampleCount ? nonZero / sampleCount : 0, w, h };
  });
}

async function governanceState(page) {
  return page.evaluate(() => {
    const panel = document.getElementById('cdb-threat-map-panel');
    const canvas = document.getElementById('cdb-threat-canvas');
    if (!panel || !canvas) return { found: false };
    const pcs = getComputedStyle(panel);
    const ccs = getComputedStyle(canvas);
    return {
      found: true,
      panelHeight: pcs.height,
      canvasWillChange: ccs.willChange,
      canvasTransform: ccs.transform,
      canvasBoxShadow: ccs.boxShadow,
      canvasBorderRadius: ccs.borderRadius,
    };
  });
}

async function main() {
  if (!fs.existsSync(path.join(ROOT_DIR, 'index.html'))) {
    console.error(`[FATAL] ${path.join(ROOT_DIR, 'index.html')} does not exist -- nothing to test.`);
    process.exitCode = 1;
    return;
  }

  const server = await startStaticServer(ROOT_DIR, PORT, MIME);
  let browser;
  try {
    browser = await chromium.launch();
    // Service workers blocked: index.html registers one, which would
    // intercept fetches ahead of this script's own route handler below --
    // same precaution verify_gadget_runtime_recovery.js takes, for the
    // same reason.
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, serviceWorkers: 'block' });
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT_MS);

    const pageErrors = [];
    page.on('pageerror', (err) => pageErrors.push(String((err && err.message) || err)));
    page.on('console', (msg) => {
      if (msg.type() === 'error' && !/Failed to load resource:|frame-ancestors' is ignored/.test(msg.text())) {
        pageErrors.push('console.error: ' + msg.text());
      }
    });

    // Hermetic, same convention as verify_pages_fast_publish_smoke.js:
    // local requests pass through, everything cross-origin (production
    // API, CDN fonts/icons, CORS-proxied news feed) is aborted.
    await page.route('**/*', (route) => {
      const url = new URL(route.request().url());
      if (url.hostname === '127.0.0.1') return route.continue();
      return route.abort();
    });

    let videoRequestStatus = null;
    page.on('response', (resp) => {
      const url = new URL(resp.url());
      if (url.hostname === '127.0.0.1' && /DASHBOARD-OVERVIEW-LIVE-VIDEO\.mp4$/.test(url.pathname)) {
        videoRequestStatus = resp.status();
      }
    });

    // Pre-suppress the unrelated #apex-lead-modal (timed/scroll-depth/
    // exit-intent lead popup, live since #281 -- see index.html's
    // apex_lead_suppressed localStorage key) for THIS page's checks below.
    // Discovered live while first writing this script: Playwright's
    // click-target auto-scroll for step 5's demo-video click crosses the
    // modal's 60%-scroll-depth trigger, popping it open over the whole
    // viewport (z-index 99999) an instant before the click lands -- so the
    // click hits the modal's backdrop instead of the button under it,
    // hanging until Playwright's click-retry timeout. That is a real
    // click-trap (see the Escape/backdrop-click dismissal added alongside
    // this script, same commit), but it is a separate concern from what
    // this script exists to verify; §7 below exercises that fix directly
    // and deliberately does NOT rely on this suppression.
    await page.addInitScript(() => {
      try { localStorage.setItem('apex_lead_suppressed', String(Date.now() + 999999999)); } catch (e) {}
    });

    await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
    await page.waitForTimeout(3000); // let the RAF boot sequence + first frames settle

    // ── 1. Initial boot: canvas actually paints content ──────────────────
    const initial = await canvasPaintRatio(page);
    record('Threat map canvas is present with non-zero pixel dimensions', initial.found && initial.w > 0 && initial.h > 0,
      JSON.stringify({ w: initial.w, h: initial.h }));
    record('Threat map canvas paints real content on boot (not blank)', initial.ratio > 0.5,
      `paint ratio=${initial.ratio.toFixed(3)}`);

    // ── 2. Governed CSS is intact: the exact properties the RC1-RC13
    //      history traced Chrome's canvas-blanking compositor trap to. ───
    const gov = await governanceState(page);
    record('Canvas will-change is governed to auto', gov.canvasWillChange === 'auto', `will-change=${gov.canvasWillChange}`);
    record('Canvas transform is governed to none', gov.canvasTransform === 'none', `transform=${gov.canvasTransform}`);
    record('Canvas box-shadow is governed to none', gov.canvasBoxShadow === 'none', `box-shadow=${gov.canvasBoxShadow}`);
    record('Canvas border-radius is governed to 0', gov.canvasBorderRadius === '0px', `border-radius=${gov.canvasBorderRadius}`);

    // ── 3. City hover tooltip interaction (#299 interaction layer). Swept
    //      entirely inside one page.evaluate() -- synthetic 'mousemove'
    //      MouseEvents dispatched straight at the canvas, which the
    //      interaction layer's pointFromEvent() reads via e.clientX/Y the
    //      same way as a real pointer -- instead of one Node<->browser
    //      round trip per grid point (hundreds of them), which is what
    //      made an earlier version of this sweep too slow to be a CI gate. ──
    const tooltipSweep = await page.evaluate(() => {
      const canvas = document.getElementById('cdb-threat-canvas');
      const rect = canvas.getBoundingClientRect();
      for (let y = 8; y < rect.height; y += 12) {
        for (let x = 8; x < rect.width; x += 12) {
          canvas.dispatchEvent(new MouseEvent('mousemove', {
            clientX: rect.left + x, clientY: rect.top + y, bubbles: true,
          }));
          const t = document.querySelector('.cdb-map-tooltip');
          if (t && t.classList.contains('is-visible')) return { shown: true, x, y };
        }
      }
      return { shown: false };
    });
    record('City hover tooltip appears somewhere on the canvas', tooltipSweep.shown,
      tooltipSweep.shown ? `hit at canvas-relative (${tooltipSweep.x}, ${tooltipSweep.y})` : 'swept the full canvas grid, tooltip never showed');

    // Dismissal: a synthetic 'mouseleave' dispatched straight on the canvas,
    // matching the real listener (canvas.addEventListener('mouseleave', ...)
    // in the §G interaction layer) -- a real page.mouse.move() to an
    // off-canvas point isn't equivalent here, since the synthetic hover
    // above never moved Chromium's actual tracked pointer, so a real move
    // afterward wouldn't reliably cross the canvas boundary the listener
    // fires on. relatedTarget is set to <body>, outside the tooltip, so the
    // handler's `tip.contains(e.relatedTarget)` guard doesn't suppress it.
    await page.evaluate(() => {
      document.getElementById('cdb-threat-canvas')
        .dispatchEvent(new MouseEvent('mouseleave', { relatedTarget: document.body, bubbles: true }));
    });
    await page.waitForTimeout(500); // past the interaction layer's 250ms dismissal grace window
    const tooltipHidden = await page.evaluate(() => {
      const t = document.querySelector('.cdb-map-tooltip');
      return !(t && t.classList.contains('is-visible'));
    });
    record('Tooltip dismisses after the cursor leaves the canvas', tooltipHidden);

    // ── 4. Immersive fullscreen toggle -- the highest-risk new (#299) code
    //      path: it mutates the PANEL's inline style (position/width/
    //      height/z-index/border-radius) with !important, the exact
    //      category of properties RC1-RC13 traced the canvas-blanking
    //      compositor trap to (there, applied to the canvas itself). ─────
    const fsBtn = page.locator('#cdb-map-fs-btn');
    if (await fsBtn.count() > 0) {
      await fsBtn.click();
      await page.waitForTimeout(1200);
      const duringFs = await canvasPaintRatio(page);
      record('Canvas still paints after entering immersive fullscreen', duringFs.ratio > 0.5,
        `paint ratio=${duringFs.ratio.toFixed(3)}, dims=${duringFs.w}x${duringFs.h}`);

      await page.keyboard.press('Escape');
      await page.waitForTimeout(1200);
      const afterFs = await canvasPaintRatio(page);
      record('Canvas still paints after exiting immersive fullscreen', afterFs.ratio > 0.5, `paint ratio=${afterFs.ratio.toFixed(3)}`);

      const govAfter = await governanceState(page);
      record('Panel height is fully restored to its governed 340px after exiting fullscreen', govAfter.panelHeight === '340px', `height=${govAfter.panelHeight}`);
    } else {
      record('Fullscreen button (#cdb-map-fs-btn) is present in the DOM', false, 'not found -- #299 markup missing or renamed');
    }

    // ── 5. Demo video: click-to-play cover swaps in the real <video>, and
    //      its <source> resolves instead of 404ing (#309's regression
    //      class -- present at repo root but missing from dist/). ────────
    const demoPlaceholder = page.locator('#apex-demo-placeholder');
    if (await demoPlaceholder.count() > 0) {
      await demoPlaceholder.click();
      await page.waitForTimeout(1500);
      const videoVisible = await page.evaluate(() => {
        const v = document.getElementById('apex-demo-video');
        const ph = document.getElementById('apex-demo-placeholder');
        return !!(v && ph && getComputedStyle(v).display !== 'none' && getComputedStyle(ph).display === 'none');
      });
      record('Demo video element replaces the click-to-play cover on click', videoVisible);
      record('Demo video <source> resolves (not a 404 -- the #309 regression class)', videoRequestStatus !== null && videoRequestStatus < 400,
        `HTTP ${videoRequestStatus === null ? 'never requested' : videoRequestStatus}`);
    } else {
      record('Demo video click-to-play cover (#apex-demo-placeholder) is present in the DOM', false, 'not found');
    }

    // ── 6. No uncaught errors from boot or any interaction above ─────────
    // index.html's feed-state resolver (js/feed-state.js resolveFeedTerminalState(),
    // P0 incident 2026-09-03) can legitimately compute a healthy LIVE/STALE/
    // EMPTY state from within its own "terminal failure" logging branch and
    // still log its one-line diagnostic via console.error regardless -- see
    // verify_pages_fast_publish_smoke.js's identical, already-shipped fix for
    // the full root-cause writeup (confirmed live: this exact line fired
    // twice here, once at boot and once after the fullscreen/video
    // interactions above re-triggered the fetch chain, both with a healthy
    // LIVE state). Checked once here, after every interaction that could
    // have logged it, deferring to the app's own authoritative
    // window.__FEED_TERMINAL_STATE__.isTerminalFailure rather than guessing
    // from log text. A genuine terminal failure still fails this script.
    const termState = await page.evaluate(() => window.__FEED_TERMINAL_STATE__ || null).catch(() => null);
    if (termState && termState.isTerminalFailure === false) {
      const goc = 'console.error: [GOC v201.0] Primary feed terminal state:';
      for (let i = pageErrors.length - 1; i >= 0; i--) {
        if (pageErrors[i].startsWith(goc)) pageErrors.splice(i, 1);
      }
    }
    record('Zero uncaught JS errors / console errors across boot + all interactions', pageErrors.length === 0, pageErrors.join(' | '));

    // ── 7. #apex-lead-modal click-trap fix (discovered live while writing
    //      this script -- see the addInitScript comment above and this
    //      script's own commit for the Escape/backdrop-click dismissal
    //      added to index.html alongside it). Forces the modal open
    //      directly (bypassing its own timers/suppression, which are
    //      trigger-only -- classList itself doesn't check them) so this
    //      doesn't race real timing, then proves both new dismissal paths
    //      actually reach the same apexLeadDismiss() the [x] button uses. ──
    await page.evaluate(() => document.getElementById('apex-lead-modal').classList.add('open'));
    const modalOpen = await page.evaluate(() => document.getElementById('apex-lead-modal').classList.contains('open'));
    record('Lead modal opens (pre-condition for the two checks below)', modalOpen);

    await page.keyboard.press('Escape');
    const modalClosedByEscape = await page.evaluate(() => !document.getElementById('apex-lead-modal').classList.contains('open'));
    record('Lead modal dismisses on Escape (previously: no handler, modal was a permanent click-trap)', modalClosedByEscape);

    await page.evaluate(() => document.getElementById('apex-lead-modal').classList.add('open'));
    // Click the backdrop itself, not the centered .apex-lead-box content --
    // top-left corner of a position:fixed;inset:0 element is always outside
    // the box's max-width:480px centered card.
    await page.mouse.click(5, 5);
    const modalClosedByBackdrop = await page.evaluate(() => !document.getElementById('apex-lead-modal').classList.contains('open'));
    record('Lead modal dismisses on a backdrop click (previously: no handler, modal was a permanent click-trap)', modalClosedByBackdrop);

    await context.close();
  } finally {
    if (browser) await browser.close();
    server.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log('='.repeat(64));
  console.log(`SUMMARY: ${results.length - failed.length}/${results.length} checks passed`);
  console.log('='.repeat(64));
  if (failed.length) {
    console.log('FAILED CHECKS:');
    for (const f of failed) console.log(`  - ${f.name}${f.detail ? ': ' + f.detail : ''}`);
    process.exitCode = 1;
  } else {
    process.exitCode = 0;
  }
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exitCode = 1;
});
