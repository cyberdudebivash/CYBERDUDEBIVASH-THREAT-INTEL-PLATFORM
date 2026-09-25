#!/usr/bin/env node
/**
 * SENTINEL APEX -- admin.html COMMERCIAL READINESS panel (real browser).
 *
 * Drives the shipped admin page with the revenue engine's
 * GET /api/v2/billing/admin/readiness stubbed. Checks:
 *   1. the secret is sent only as the X-Admin-Secret header, never in the
 *      URL or in localStorage / sessionStorage, and the input is cleared
 *   2. verdict, blockers, checks (with fixes) and the operator queue render
 *   3. a rejected secret shows a message and renders nothing
 *   4. server strings are rendered as text, never as HTML
 *   5. the admin page's script parses (it once shipped truncated)
 *   6. no page error
 *
 * Usage:
 *   PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH="$(npm root -g)" \
 *     node render-test/verify_admin_commercial_readiness.js [root]   (default: repo root; CI passes dist)
 */
'use strict';

const path = require('path');
const { startStaticServer } = require('./lib/static-server');
const { chromium } = require('playwright');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const PORT = 8794;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const SECRET = 'TEST_ONLY_revenue_admin_secret';
const XSS = '<img src=x onerror="window.__pwned=1">';

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : '  -- ' + detail}`);
  if (!ok) failures++;
}

const READINESS = {
  verdict: 'BLOCKED', blockers: ['razorpay_plan_ids'], warnings: ['gst_invoice_config'],
  generated_at: '2026-09-25T06:00:00.000Z',
  checks: [
    { id: 'razorpay_api_keys', ok: true, blocking: true, detail: 'Razorpay API key pair configured.' },
    { id: 'razorpay_plan_ids', ok: false, blocking: true, detail: '1 of 6 plans cannot be bought online: mssp_annual. ' + XSS, fix: 'wrangler secret put RAZORPAY_PLAN_ID_MSSP_ANNUAL' },
    { id: 'gst_invoice_config', ok: false, blocking: false, detail: 'GST invoices are held, not issued.', fix: 'wrangler secret put GST_INVOICE_CONFIG' },
  ],
  queue: { attention: 3, items: {
    refund_requests_to_decide: { count: 2, overdue: 1, oldest_age_hours: 72, action: 'POST /api/v2/billing/refunds/approve or /reject' },
    invoice_holds: { count: 1, overdue: 1, oldest_age_hours: 5, by_reason: {}, action: 'POST /api/v2/billing/invoices/issue' },
  } },
};

async function run(browser, { status = 200, body = READINESS }) {
  const page = await browser.newPage();
  const errors = [];
  const calls = [];
  page.on('pageerror', (e) => errors.push(String(e && e.message || e)));
  await page.route('**/*', async (route) => {
    const req = route.request();
    const url = req.url();
    if (!url.startsWith(ORIGIN)) return route.abort();
    const u = new URL(url);
    if (u.pathname === '/api/v2/billing/admin/readiness') {
      calls.push({ search: u.search, secret: req.headers()['x-admin-secret'] || null });
      return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    }
    if (u.pathname.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    return route.continue();
  });
  await page.goto(`${ORIGIN}/admin.html`, { waitUntil: 'domcontentloaded' });
  // The panel sits behind the page's own login gate; reveal it directly.
  await page.evaluate(() => {
    const main = document.getElementById('main'); if (main) main.style.display = 'block';
    document.querySelectorAll('.page').forEach((p) => p.classList.remove('active'));
    document.getElementById('page-commercial').classList.add('active');
  });
  await page.fill('#cr-secret', SECRET);
  await page.click('#cr-form button[type=submit]');
  await page.waitForTimeout(300);
  const state = await page.evaluate(() => ({
    verdict: document.getElementById('cr-verdict').textContent,
    msg: document.getElementById('cr-msg').textContent,
    checks: document.getElementById('cr-checks').innerText,
    queue: document.getElementById('cr-queue').innerText,
    attention: document.getElementById('cr-attention').textContent,
    input: document.getElementById('cr-secret').value,
    storage: JSON.stringify(localStorage) + JSON.stringify(sessionStorage),
    pwned: !!window.__pwned || !!document.querySelector('#page-commercial img'),
    adminScript: typeof window.showPage === 'function' && typeof window.showToast === 'function',
  }));
  await page.close();
  return { errors, calls, state };
}

(async () => {
  const server = await startStaticServer(ROOT, PORT, { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' });
  const browser = await chromium.launch();
  try {
    const ok = await run(browser, {});
    check('secret sent only as X-Admin-Secret header', ok.calls.length === 1 && ok.calls[0].secret === SECRET && !ok.calls[0].search.includes(SECRET), JSON.stringify(ok.calls));
    check('secret not stored, input cleared', !ok.state.storage.includes(SECRET) && ok.state.input === '');
    check('verdict and blockers shown', ok.state.verdict === 'BLOCKED' && /razorpay_plan_ids/.test(ok.state.msg) && /gst_invoice_config/.test(ok.state.msg), ok.state.msg);
    check('checks: blocker, warning and fix rendered', /BLOCKER/.test(ok.state.checks) && /WARNING/.test(ok.state.checks) && /RAZORPAY_PLAN_ID_MSSP_ANNUAL/.test(ok.state.checks), ok.state.checks);
    check('queue rendered with attention count', /refund requests to decide/.test(ok.state.queue) && /72/.test(ok.state.queue) && /3 NEED ACTION/.test(ok.state.attention), ok.state.queue);
    check('server strings rendered as text', !ok.state.pwned && ok.state.checks.includes('<img'));
    check('admin page script parses and loads (showPage, showToast defined)', ok.state.adminScript);
    check('no page error', ok.errors.length === 0, ok.errors.join(' | '));

    const denied = await run(browser, { status: 401, body: { error: 'unauthorized' } });
    check('rejected secret: message shown, nothing rendered', /rejected/.test(denied.state.msg) && denied.state.checks.trim() === '' && denied.state.verdict === 'NOT LOADED', denied.state.msg);
    check('rejected secret: no page error', denied.errors.length === 0, denied.errors.join(' | '));

    // Revived admin actions (the page's script was dead until now): key issue
    // and revoke report only what the gateway confirms; values are escaped.
    for (const mode of ['ok', 'fail']) {
      const page = await browser.newPage();
      const errors = []; const gw = [];
      page.on('pageerror', (e) => errors.push(String(e && e.message || e)));
      page.on('dialog', (d) => d.accept());
      await page.route('**/*', async (route) => {
        const req = route.request(); const url = req.url();
        if (url.startsWith('https://intel.cyberdudebivash.com/api/admin/keys')) {
          gw.push({ method: req.method(), path: new URL(url).pathname, key: req.headers()['x-admin-key'] || null, body: req.postData() });
          if (req.method() === 'POST') {
            return mode === 'ok'
              ? route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ key: 'cdb_pro_SERVERMINTED', tier: 'PRO', customer_id: XSS, created_at: '2026-09-25T06:00:00Z', expires_at: null }) })
              : route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"not_found"}' });
          }
          return route.fulfill({ status: mode === 'ok' ? 200 : 403, contentType: 'application/json', body: '{}' });
        }
        if (!url.startsWith(ORIGIN)) return route.abort();
        if (new URL(url).pathname.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
        return route.continue();
      });
      await page.goto(`${ORIGIN}/admin.html`, { waitUntil: 'domcontentloaded' });
      await page.fill('#admin-pass', 'TEST_ONLY_gateway_admin');
      await page.evaluate(() => doAuth());
      await page.evaluate(() => { document.querySelectorAll('.page').forEach((p) => p.classList.remove('active')); document.getElementById('page-issue-key').classList.add('active'); });
      await page.fill('#key-email', 'buyer@example.com');
      await page.evaluate(() => issueKey());
      await page.waitForTimeout(300);
      const r = await page.evaluate(() => ({ result: document.getElementById('key-result').innerText, tmpl: document.getElementById('email-template').innerText,
        pwned: !!window.__pwned || !!document.querySelector('#key-result img'),
        payments: document.getElementById('page-payments').innerText }));
      await page.evaluate(() => { document.querySelectorAll('.page').forEach((p) => p.classList.remove('active')); document.getElementById('page-users').classList.add('active'); });
      await page.fill('#revoke-key', 'cdb_pro_x/../y');
      await page.click('#revoke-form button[type=submit]');
      await page.waitForTimeout(300);
      const toast = await page.evaluate(() => document.getElementById('toast').textContent);
      const post = gw.find((c) => c.method === 'POST');
      const del = gw.find((c) => c.method === 'DELETE');
      check(`${mode}: issue key calls POST /api/admin/keys with the admin key`, post && post.key === 'TEST_ONLY_gateway_admin' && JSON.parse(post.body).tier === 'FREE' && JSON.parse(post.body).customer_id === 'buyer@example.com', JSON.stringify(post));
      if (mode === 'ok') {
        check('ok: the gateway-minted key is shown (never a browser-made one)', /cdb_pro_SERVERMINTED/.test(r.result) && /cdb_pro_SERVERMINTED/.test(r.tmpl), r.result);
        check('ok: server values escaped', !r.pwned && r.result.includes('<img'));
        check('ok: revoke calls DELETE with the key encoded, success reported', del && del.path === '/api/admin/keys/cdb_pro_x%2F..%2Fy' && /Key revoked/.test(toast), JSON.stringify(del) + ' ' + toast);
      } else {
        check('fail: no key shown, failure stated', /No key was issued/.test(r.result) && !/cdb_/.test(r.result) && /Nothing to send/.test(r.tmpl), r.result);
        check('fail: revoke failure reported, never "revoked"', /Revoke failed/.test(toast) && /still active/.test(toast), toast);
      }
      check(`${mode}: payments page carries no retired manual-payment channel`, !/bivash@ybl|paypal\.me|UPI TXN|CONFIRM PAYMENT/i.test(r.payments), r.payments.slice(0, 200));
      check(`${mode}: no page error`, errors.length === 0, errors.join(' | '));
      await page.close();
    }
  } finally {
    await browser.close();
    server.close();
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll admin commercial readiness checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
