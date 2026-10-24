import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyReportType, hasConfirmedKev, computeP20QualityScore } from '../p20-handlers.js';
import { computeOperationalReadiness } from '../p23-handlers.js';
import { evaluatePublicationGate } from '../publication-gate.js';
import { computeEnterpriseTrustScore, buildExplainableScoreBlock } from '../p25-handlers.js';

test('general risk score is never treated as a CVSS vulnerability signal', () => {
  for (const [threat_type, expected] of [
    ['phishing', 'PHISHING'], ['ransomware', 'RANSOMWARE'],
    ['malware', 'MALWARE'], ['security-news', 'SECURITY_NEWS'],
  ]) {
    assert.equal(
      classifyReportType({ threat_type, risk_score: 9.8, kev: 'NO' }),
      expected, threat_type
    );
  }
  assert.equal(
    classifyReportType({ title: 'Data breach at Example', risk_score: 8.7, kev_present: false }),
    'BREACH'
  );
  assert.equal(
    classifyReportType({ threat_type: 'phishing', risk_score: 8.7, cvss_score: null }),
    'PHISHING'
  );
});

test('explicit CVE, valid CVSS and genuinely confirmed KEV remain vulnerability signals', () => {
  const examples = [
    { cve_id: 'CVE-2026-12345' },
    { cve_ids: ['CVE-2026-12345'] },
    { cve: ['CVE-2026-12345'] },
    { cvss_score: 7.5 },
    { cvss_score: '8.8' },
    { title: 'Vendor advisory for CVE-2026-12345' },
    { kev_present: true },
    { kev: 'YES' },
  ];
  for (const item of examples) {
    assert.equal(classifyReportType({ threat_type: 'phishing', risk_score: 8.5, ...item }),
      'VULNERABILITY', JSON.stringify(item));
  }
});

test('negative and malformed KEV tokens must never become true through truthiness', () => {
  for (const value of [false, 0, null, undefined, 'NO', 'FALSE', '0', '', 'N/A', 'yes-no', {}, []]) {
    assert.equal(hasConfirmedKev({ kev: value }), false, String(value));
    assert.equal(classifyReportType({ threat_type: 'phishing', risk_score: 8.3, kev: value }),
      'PHISHING', String(value));
  }
  for (const value of [true, 1, 'YES', 'TRUE', '1', ' yes ']) {
    assert.equal(hasConfirmedKev({ kev_present: value }), true, String(value));
  }
});

test('invalid CVSS and arbitrary CVE-like strings do not create vulnerability evidence', () => {
  for (const value of [null, '', 0, '0', -1, 11, 'n/a', '7.5 junk']) {
    assert.equal(classifyReportType({
      threat_type: 'ransomware', risk_score: 9.5, cvss_score: value, kev: 'NO'
    }), 'RANSOMWARE', String(value));
  }
  for (const value of ['CVE-2026-1', 'CVE-bogus', 'not-a-CVE', 'CVE-2026-12345-more']) {
    assert.equal(classifyReportType({ threat_type: 'phishing', cve_id: value }), 'PHISHING', value);
  }
});

test('P23 operational readiness does not hallucinate CISA KEV-based IR or patch priority', () => {
  const item = {
    id: 'intel--' + 'a'.repeat(24),
    title: 'Phishing message',
    threat_type: 'phishing', risk_score: 8.9, kev: 'NO',
    description: 'A short unverified indicator',
    iocs: [], mitre_techniques: [], detection_bundle: [],
  };
  const readiness = computeOperationalReadiness(item);
  const ir = readiness.gates.find(g => g.name === 'IR Package');
  const patch = readiness.gates.find(g => g.name === 'Patch Priority');
  assert.equal(ir.pass, false);
  assert.equal(patch.pass, false);
  const verified = computeOperationalReadiness({ ...item, kev_present: true });
  assert.equal(verified.gates.find(g => g.name === 'IR Package').pass, true);
  assert.equal(verified.gates.find(g => g.name === 'Patch Priority').pass, true);
});

test('correcting report type does not grant customer publication to a weak item', () => {
  const item = {
    id: 'intel--' + 'b'.repeat(24),
    threat_type: 'phishing',
    title: 'Unverified phishing indicator',
    risk_score: 9.0, kev: 'NO',
    description: 'Short item',
  };
  const gate = evaluatePublicationGate(item);
  assert.equal(gate.REPORT_TYPE, 'PHISHING');
  assert.equal(gate.customer_ready, false);
  assert.notEqual(gate.publication_state, 'CUSTOMER_READY');
  assert.ok(gate.blocking_gates.length > 0);
  assert.ok(gate.P20_SCORE < 25);
  assert.equal(computeP20QualityScore(item).total, gate.P20_SCORE);
});


test('P25 trust cannot award CISA KEV exploitation points for negative string evidence', () => {
  const item = {
    id: 'intel--' + 'c'.repeat(24),
    title: 'CVE-2026-12345 Vendor Notice',
    threat_type: 'security-news',
    risk_score: 8.4,
    kev_present: false,
    kev: 'NO',
    _score_details: { kev: 'NO' },
    active_exploit: false,
  };
  const unverified = computeEnterpriseTrustScore(item);
  const exploitation = unverified.dims.find(d => d.name === 'Exploitation Verification');
  assert.ok(exploitation, 'P25 exploitation verification dimension exists');
  assert.equal(exploitation.earned, 0);
  assert.doesNotMatch(exploitation.rationale, /CISA KEV listing provides highest/i);
  assert.match(buildExplainableScoreBlock(item), /Not listed in CISA Known Exploited Vulnerabilities/);
  assert.doesNotMatch(buildExplainableScoreBlock(item), /Confirmed active exploitation in the wild/);

  const affirmed = computeEnterpriseTrustScore({
    ...item, kev_present: true, kev: true, _score_details: { kev: true }
  });
  const confirmedDim = affirmed.dims.find(d => d.name === 'Exploitation Verification');
  assert.equal(confirmedDim.earned, 10);

  const detailOnly = computeEnterpriseTrustScore({
    ...item, _score_details: { kev: 'YES' }
  });
  assert.equal(detailOnly.dims.find(d => d.name === 'Exploitation Verification').earned, 10);
});


test('declared vulnerabilities with missing CVE/CVSS stay under full operational readiness controls', () => {
  for (const threat_type of ['vulnerability', 'remote code execution', 'privilege escalation', 'CVE advisory', 'CVE_VULNERABILITY', 'rce']) {
    const item = {
      title: 'Unverified vulnerability notice',
      threat_type,
      risk_score: 9.7,
      kev: 'NO',
      cvss_score: null,
      description: 'Unverified notice lacking CVSS, IOCs and detection package'
    };
    assert.equal(classifyReportType(item), 'VULNERABILITY', threat_type);
    const gate = evaluatePublicationGate(item);
    assert.equal(gate.customer_ready, false);
    assert.deepEqual(gate.P23_NOT_APPLICABLE_GATES, [],
      'full IR and Patch Priority checks must stay applicable');
    assert.ok(gate.blocking_gates.includes('P23_OPERATIONAL_READINESS_DO_NOT_PUBLISH'));
  }
});
