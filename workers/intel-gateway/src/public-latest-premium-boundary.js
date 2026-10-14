/**
 * P0 anonymous latest.json field boundary.
 *
 * The publication generator removes premium fields before writing public
 * latest.json. The Worker applies applyTierGateV2() at request time and may
 * reintroduce premium-named properties (apex_ai, stix_bundle:null), violating
 * the anonymous feed's field-exclusion contract even when content is masked.
 *
 * Keep entitlement masking in revenue-enforcement.js intact for all other
 * callers. Strip these fields at the last-mile anonymous latest.json boundary
 * and reject regional edge-cache entries produced by older Worker versions.
 *
 * This list mirrors scripts/public_api_sanitizer.py PREMIUM_FIELDS, verified
 * by the parity regression test. Adding a Python premium field requires
 * updating this Worker list before public production release.
 */
export const PUBLIC_LATEST_PREMIUM_FIELDS = Object.freeze([
  'report_url',
  'internal_report_url',
  'stix_bundle_url',
  'stix_bundle',
  'pdf_url',
  'pdf_report_url',
  'apex_ai',
  'ioc_hashes',
  'ioc_payload',
  'kill_chain',
  'kill_chain_phases',
  'detection_rules',
  'sigma_rules',
  'yara_rules',
  'actor_attribution',
  'attribution_evidence',
  'mitre_navigator_url',
  'detailed_analysis',
  'executive_summary',
  'technical_analysis',
  'recommendations',
  'raw_iocs',
  'full_iocs',
  'ioc_list',
  'stix_id_bundle',
  'taxii_url',
  'misp_export',
  'splunk_query',
  'sentinel_query',
  'elastic_query',
  'qradar_query',
  'siem_rules',
  'integration_payload',
  'enterprise_package',
  'full_stix_bundle',
  'stix_objects',
]);

export function stripPublicLatestPremiumFields(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    throw new TypeError('PUBLIC_LATEST_ITEM_INVALID');
  }
  const publicItem = { ...item };
  for (const name of PUBLIC_LATEST_PREMIUM_FIELDS) delete publicItem[name];
  return publicItem;
}

export function hasPublicLatestPremiumFields(feed) {
  if (!feed || typeof feed !== 'object' || !Array.isArray(feed.items)) return true;
  return feed.items.some(item => !item || typeof item !== 'object' ||
    Array.isArray(item) || PUBLIC_LATEST_PREMIUM_FIELDS.some(name =>
      Object.prototype.hasOwnProperty.call(item, name)));
}
