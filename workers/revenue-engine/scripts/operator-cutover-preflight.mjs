/**
 * P0 Revenue Engine operator identity cutover — read-only, fail-closed inventory.
 *
 * This does NOT query Cloudflare secrets, JWTs, billing data or external APIs.
 * A source match proves a legacy caller is present; it never proves that its
 * real deployment is still active, nor that the operator Access JWT is ready.
 * Explicitly pass the INTENDED target mode; do not default to "off".
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CRITICAL_CALLERS = Object.freeze([
  Object.freeze({ id: 'quota_alert_gateway', path: 'workers/intel-gateway/src/index.js',
    endpoint: '/api/automation/trigger', marker: 'X-Admin-Secret',
    risk: 'Customer quota warning and upsell notification lost on HTTP 403' }),
  Object.freeze({ id: 'billing_canary_admin', path: 'deploy/billing-canary/canary-lib.mjs',
    endpoint: 'runAdminChecks', marker: 'X-Admin-Secret',
    risk: 'Commercial go-live readiness probe cannot authenticate' }),
  Object.freeze({ id: 'release_readiness_report', path: '.github/workflows/deploy-revenue-engine.yml',
    endpoint: '/api/v2/billing/admin/readiness', marker: 'X-Admin-Secret',
    risk: 'Post-release financial readiness verdict cannot be collected' }),
  Object.freeze({ id: 'billing_admin_browser', path: 'admin.html',
    endpoint: '/api/v2/billing/admin/readiness', marker: 'X-Admin-Secret',
    risk: 'Operator billing dashboard loses access' }),
  Object.freeze({ id: 'lead_pipeline_browser', path: 'lead-pipeline.html',
    endpoint: '/api/crm/leads', marker: 'X-Admin-Secret',
    risk: 'Revenue lead pipeline loses operator access' }),
  Object.freeze({ id: 'revenue_dashboard_browser', path: 'revenue-dashboard.html',
    endpoint: '/api/revenue/commercial', marker: 'X-Admin-Secret',
    risk: 'Revenue reporting dashboard loses operator access' }),
  Object.freeze({ id: 'subscription_management_browser', path: 'subscription-management.html',
    endpoint: '/api/revenue/commercial', marker: 'X-Admin-Secret',
    risk: 'Subscriber administration loses operator access' }),
  Object.freeze({ id: 'enterprise_onboarding_browser', path: 'enterprise-onboarding.html',
    endpoint: '/api/revenue/commercial', marker: 'X-Admin-Secret',
    risk: 'Enterprise onboarding console loses operator access' }),
  Object.freeze({ id: 'payment_status_browser', path: 'payment-status-dashboard.html',
    endpoint: '/api/revenue/commercial', marker: 'X-Admin-Secret',
    risk: 'Payment-operations dashboard loses operator access' }),
  Object.freeze({ id: 'customer_success_browser', path: 'customer-success.html',
    endpoint: '/api/success/scores', marker: 'X-Admin-Secret',
    risk: 'Customer-success operator console loses access' }),
  Object.freeze({ id: 'mssp_tenant_browser', path: 'mssp-tenant-dashboard.html',
    endpoint: '/api/mssp/tenants', marker: 'X-Admin-Secret',
    risk: 'MSSP tenant administration loses operator access' }),
]);

export function assessOperatorCutover(mode, loadSource, callers = CRITICAL_CALLERS) {
  if (mode !== 'off' && mode !== 'required') {
    return { ok: false, state: 'INVALID_MODE', mode: String(mode),
      error: 'An explicit off or required mode is mandatory; no inferred production state.' };
  }
  if (typeof loadSource !== 'function' || !Array.isArray(callers) || callers.length < 1) {
    return { ok: false, state: 'INVALID_INVENTORY', mode };
  }
  const findings = [];
  for (const caller of callers) {
    let source;
    try { source = loadSource(caller.path); } catch { source = null; }
    if (typeof source !== 'string' || !source.includes(caller.endpoint) || !source.includes(caller.marker)) {
      // Treat source drift as a review requirement, never as proof of migration.
      findings.push({ id: caller.id, path: caller.path, disposition: 'SOURCE_DRIFT_REVIEW_REQUIRED' });
      continue;
    }
    // There is no source-level proof of a compatible JWT+admin-secret client:
    // an occurrence of the header name in any file is NOT evidence that the
    // request path has an approved Access identity, MFA or service token.
    findings.push({ id: caller.id, path: caller.path, disposition: 'JWT_MIGRATION_NOT_ATTESTED' });
  }
  return {
    ok: mode === 'off' && findings.every(f => f.disposition === 'JWT_MIGRATION_NOT_ATTESTED'),
    state: mode === 'required' ? 'CUTOVER_BLOCKED'
      : findings.some(f => f.disposition === 'SOURCE_DRIFT_REVIEW_REQUIRED') ? 'INVENTORY_DRIFT' : 'OFF_SOURCE_PREFLIGHT_ONLY',
    mode,
    evaluated: findings.length,
    findings,
    note: 'Cloudflare live mode, service-token eligibility, and operator JWT compatibility are NOT remotely verified.',
  };
}

const root = fileURLToPath(new URL('../../../', import.meta.url));
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv.length === 3 ? process.argv[2] : undefined;
  const result = assessOperatorCutover(mode, path => {
    // All paths are static code-owned literals from CRITICAL_CALLERS.
    return readFileSync(resolve(root, path), 'utf8');
  });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (!result.ok) process.exitCode = 1;
}
