#!/usr/bin/env node
/**
 * SENTINEL APEX -- billing.html Billing Center (real browser).
 *
 * Drives the shipped page in headless Chromium with every API stubbed (no
 * real key, no payment call). Checks:
 *   1. the key travels only in the X-API-Key header: never in the URL, never
 *      in localStorage / sessionStorage
 *   2. a refused key shows the server's message and does not open the account
 *   3. an active subscription: plan, renewal date, payments, invoice, refund
 *      eligibility and the cancel button are rendered from the API
 *   4. cancel: confirmation required; declining sends nothing; accepting
 *      POSTs subscriptions/cancel once and the page re-reads the account
 *   5. refund request: reason is posted; the request status is shown after
 *   6. invoice view renders in a sandboxed iframe (no scripts)
 *   7. hostile server strings are rendered as text, never as HTML
 *   8. sign out clears the key and the account from the page
 *   9. no page error on any path
 *
 * Usage:
 *   PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH="$(npm root -g)" \
 *     node render-test/verify_billing_center.js [root]   (default: repo root; CI passes dist)
 *
 * Exit 0 = all checks passed, 1 = at least one failed.
 */
'use strict';

const path = require('path');
const { startStaticServer } = require('./lib/static-server');
const { chromium } = require('playwright');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const PORT = 8792;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };
const KEY = 'cdb_TEST_ONLY_key_0123456789';
const XSS = '<img src=x onerror="window.__pwned=1">';

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : '  -- ' + detail}`);
  if (!ok) failures++;
}

const future = new Date(Date.now() + 20 * 86400e3).toISOString();
function account(overrides = {}) {
  return {
    account: { email: 'buyer@example.com' },
    subscription: {
      subscription_id: 'sub_TEST_ONLY_1', provider: 'razorpay', tier: 'PRO', billing_cycle: 'monthly', status: 'active',
      current_period_end: future, cancel_scheduled: false, cancel_scheduled_at: null, renews: true,
    },
    payments: [{
      payment_id: 'pay_TEST_ONLY_1', tier: 'PRO', billing_cycle: 'monthly', amount_paise: 410000, currency: 'INR',
      captured_at: new Date().toISOString(), invoice_status: 'issued', refund_status: 'none', refunded_paise: 0, disputed: false,
    }],
    invoices: [{ invoice_number: 'CDB/26-27/000001', invoice_date: '2026-09-25', payment_id: 'pay_TEST_ONLY_1', status: 'issued' }],
    credit_notes: [],
    refund: { eligible: true, code: null, message: null, window_ends_at: future, request: null },
    actions: { can_cancel: true, can_request_refund: true },
    policy: { cancellation: 'Cancel any time; access runs to the end of the paid period. No pro-rata refund.', refund: '7-day money-back guarantee on your first purchase.' },
    ...overrides,
  };
}

async function open(browser, { accountReplies, dialogs = 'accept' }) {
  const page = await browser.newPage();
  const errors = [];
  const calls = [];
  const confirms = [];
  page.on('pageerror', (e) => errors.push(String(e && e.message || e)));
  page.on('dialog', async (d) => {
    confirms.push(d.message());
    if (dialogs === 'accept') await d.accept(); else await d.dismiss();
  });
  let acctN = 0;
  await page.route('**/*', async (route) => {
    const req = route.request();
    const url = req.url();
    if (!url.startsWith(ORIGIN)) return route.abort();
    const u = new URL(url);
    if (u.pathname.startsWith('/api/')) {
      calls.push({ path: u.pathname, search: u.search, method: req.method(), key: req.headers()['x-api-key'] || null, body: req.postData() });
    }
    if (u.pathname === '/api/v2/billing/account') {
      const r = accountReplies[Math.min(acctN++, accountReplies.length - 1)];
      return route.fulfill({ status: r.status || 200, contentType: 'application/json', body: JSON.stringify(r.body) });
    }
    if (u.pathname === '/api/v2/billing/subscriptions/cancel') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'cancel_scheduled', message: 'Your subscription will not renew.' }) });
    }
    if (u.pathname === '/api/v2/billing/refunds/request') {
      return route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify({ status: 'pending_review', request_id: 'rfr_TEST_ONLY', message: 'Refund request received.' }) });
    }
    if (u.pathname === '/api/v2/billing/invoices/view') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: '<html><body><h1>Tax Invoice CDB/26-27/000001</h1><script>parent.__frameScript=1</script></body></html>' });
    }
    if (u.pathname.startsWith('/api/')) return route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
    return route.continue();
  });
  await page.goto(`${ORIGIN}/billing.html`, { waitUntil: 'domcontentloaded' });
  return { page, errors, calls, confirms };
}

async function signIn(page) {
  await page.fill('#api-key', KEY);
  await page.click('#signin-btn');
  await page.waitForTimeout(300);
}

const visible = (page, sel) => page.evaluate((s) => { const e = document.querySelector(s); return !!e && !e.closest('.hidden') && !e.classList.contains('hidden'); }, sel);

(async () => {
  const server = await startStaticServer(ROOT, PORT, MIME);
  const browser = await chromium.launch();
  try {
    // 2. refused key
    {
      const s = await open(browser, { accountReplies: [{ status: 401, body: { error: 'key_not_current', message: 'This API key was replaced or revoked. Use your current key.' } }] });
      await signIn(s.page);
      const txt = await s.page.textContent('#signin-msg');
      check('refused key: server message shown', /replaced or revoked/.test(txt), txt);
      check('refused key: account stays closed', !(await visible(s.page, '#account')));
      check('refused key: no page error', s.errors.length === 0, s.errors.join(' | '));
      await s.page.close();
    }

    // 1, 3, 6, 7, 8 -- active subscription
    {
      const hostile = account();
      hostile.refund = { eligible: false, code: 'x', message: XSS, window_ends_at: null, request: null };
      hostile.actions = { can_cancel: true, can_request_refund: false };
      hostile.payments[0].payment_id = XSS;
      const s = await open(browser, { accountReplies: [{ body: account() }] });
      await signIn(s.page);
      const text = await s.page.evaluate(() => document.body.innerText);
      const acctCall = s.calls.find((c) => c.path === '/api/v2/billing/account');
      check('key sent only as X-API-Key header', acctCall && acctCall.key === KEY && !s.calls.some((c) => c.search.includes(KEY)), JSON.stringify(acctCall));
      const stored = await s.page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage));
      check('key not in localStorage / sessionStorage', !stored.includes(KEY), stored);
      check('key input cleared after sign-in', (await s.page.inputValue('#api-key')) === '');
      check('account: email, plan and status shown', /buyer@example\.com/.test(text) && /PRO/.test(await s.page.textContent('#sub-tier')) && /Active/.test(await s.page.textContent('#sub-status')));
      check('account: renewal label for a renewing subscription', (await s.page.textContent('#sub-period-label')) === 'Renews on');
      check('account: payment row and amount', /pay_TEST_ONLY_1/.test(text) && /4,100\.00/.test(text), text.slice(0, 400));
      check('account: invoice listed', /CDB\/26-27\/000001/.test(text));
      check('account: cancel and refund offered when the API allows', (await visible(s.page, '#cancel-btn')) && (await visible(s.page, '#refund-form')));

      // 6. invoice viewer
      await s.page.click('#invoices-body button');
      await s.page.waitForTimeout(300);
      const frame = await s.page.evaluate(() => {
        const f = document.getElementById('doc-frame');
        return { sandbox: f.getAttribute('sandbox'), html: f.srcdoc, open: !document.getElementById('doc-modal').classList.contains('hidden'), ran: !!window.__frameScript };
      });
      const viewCall = s.calls.find((c) => c.path === '/api/v2/billing/invoices/view');
      check('invoice: fetched with the key header and encoded number', viewCall && viewCall.key === KEY && /number=CDB%2F26-27%2F000001/.test(viewCall.search), JSON.stringify(viewCall));
      check('invoice: shown in a script-less sandboxed iframe', frame.open && frame.sandbox === '' && /Tax Invoice/.test(frame.html) && !frame.ran, JSON.stringify(frame));
      await s.page.click('#doc-close');

      // 8. sign out
      await s.page.click('#signout-btn');
      const after = await s.page.evaluate(() => ({ acct: document.getElementById('account').classList.contains('hidden'), rows: document.querySelectorAll('#payments-body tr').length }));
      check('sign out: account hidden and cleared', after.acct && after.rows === 0, JSON.stringify(after));
      check('active: no page error', s.errors.length === 0, s.errors.join(' | '));
      await s.page.close();

      // 7. hostile strings
      const h = await open(browser, { accountReplies: [{ body: hostile }] });
      await signIn(h.page);
      const pwned = await h.page.evaluate(() => !!window.__pwned || !!document.querySelector('#account img'));
      const shownText = await h.page.textContent('#refund-status');
      check('hostile server strings rendered as text', !pwned && shownText.includes('<img'), shownText);
      await h.page.close();
    }

    // 4. cancel -- declined, then accepted
    {
      const s = await open(browser, { accountReplies: [{ body: account() }], dialogs: 'dismiss' });
      await signIn(s.page);
      await s.page.click('#cancel-btn');
      await s.page.waitForTimeout(200);
      check('cancel: confirmation asked, states access period and no pro-rata refund',
        s.confirms.length === 1 && /not renew/.test(s.confirms[0]) && /No pro-rata refund/.test(s.confirms[0]), s.confirms.join(' | '));
      check('cancel: declining sends nothing', !s.calls.some((c) => c.path.endsWith('/subscriptions/cancel')));
      await s.page.close();

      const scheduled = account({ actions: { can_cancel: false, can_request_refund: true } });
      scheduled.subscription = { ...scheduled.subscription, cancel_scheduled: true, cancel_scheduled_at: new Date().toISOString(), renews: false };
      const a = await open(browser, { accountReplies: [{ body: account() }, { body: scheduled }] });
      await signIn(a.page);
      await a.page.click('#cancel-btn');
      await a.page.waitForTimeout(400);
      const cancels = a.calls.filter((c) => c.path.endsWith('/subscriptions/cancel'));
      check('cancel: accepted -> one POST with the key', cancels.length === 1 && cancels[0].method === 'POST' && cancels[0].key === KEY);
      check('cancel: account re-read and shown as ending, button gone',
        a.calls.filter((c) => c.path === '/api/v2/billing/account').length === 2 &&
        /ends at period end/.test(await a.page.textContent('#sub-status')) && !(await visible(a.page, '#cancel-btn')) &&
        (await a.page.textContent('#sub-period-label')) === 'Access until');
      check('cancel: no page error', a.errors.length === 0, a.errors.join(' | '));
      await a.page.close();
    }

    // 5. refund request
    {
      const requested = account({ actions: { can_cancel: true, can_request_refund: false } });
      requested.refund = { eligible: false, code: 'already_requested', message: null, window_ends_at: future,
        request: { request_id: 'rfr_TEST_ONLY', status: 'pending_review', status_label: 'Under review', requested_at: new Date().toISOString(), decided_at: null, decision_note: '' } };
      const s = await open(browser, { accountReplies: [{ body: account() }, { body: requested }] });
      await signIn(s.page);
      await s.page.fill('#refund-reason', 'Not a fit for our SOC');
      await s.page.click('#refund-btn');
      await s.page.waitForTimeout(400);
      const req = s.calls.find((c) => c.path.endsWith('/refunds/request'));
      check('refund: reason posted with the key', req && req.key === KEY && JSON.parse(req.body).reason === 'Not a fit for our SOC', JSON.stringify(req));
      check('refund: request status shown, form withdrawn',
        /rfr_TEST_ONLY: Under review/.test(await s.page.textContent('#refund-status')) && !(await visible(s.page, '#refund-form')));
      check('refund: no page error', s.errors.length === 0, s.errors.join(' | '));
      await s.page.close();
    }

    // no subscription
    {
      const s = await open(browser, { accountReplies: [{ body: account({ subscription: null, payments: [], invoices: [], actions: { can_cancel: false, can_request_refund: false },
        refund: { eligible: false, code: 'no_eligible_payment', message: 'No subscription payment is on record for this account.', window_ends_at: null, request: null } }) }] });
      await signIn(s.page);
      check('no subscription: honest empty state, no actions',
        (await visible(s.page, '#sub-none')) && !(await visible(s.page, '#cancel-btn')) && !(await visible(s.page, '#refund-form')) && (await visible(s.page, '#payments-empty')));
      await s.page.close();
    }
  } finally {
    await browser.close();
    server.close();
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll Billing Center checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
