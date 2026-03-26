/**
 * SMART CONTRACT SCANNER
 * =======================
 * Place at: /web3/components/contract/ContractScanner.tsx
 *
 * Detects: Reentrancy, Access Control, Honeypot patterns, and more.
 */

import React, { useState } from 'react';
import { scanContract } from '../../services/web3Api';
import { useRiskColor } from '../../hooks/useWeb3';
import type { ContractScanResult, ContractVulnerability, VulnSeverity } from '../../types';

type InputMode = 'address' | 'code';

const SEVERITY_META: Record<VulnSeverity, { color: string; icon: string }> = {
  CRITICAL: { color: '#ff0044', icon: '🔴' },
  HIGH:     { color: '#ff6600', icon: '🟠' },
  MEDIUM:   { color: '#ffaa00', icon: '🟡' },
  LOW:      { color: '#00ff88', icon: '🟢' },
  INFO:     { color: '#4499ff', icon: '🔵' },
};

interface Props {
  network: string;
}

export default function ContractScanner({ network }: Props) {
  const [mode,      setMode]      = useState<InputMode>('address');
  const [address,   setAddress]   = useState('');
  const [code,      setCode]      = useState('');
  const [result,    setResult]    = useState<ContractScanResult | null>(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  const handleScan = async () => {
    const payload =
      mode === 'address'
        ? { address: address.trim(), network }
        : { code: code.trim(), network };

    if (!payload.address && !payload.code) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const response = await scanContract(payload);
    setLoading(false);

    if (response.success && response.data) {
      setResult(response.data);
    } else {
      setError(response.error || 'Scan failed');
    }
  };

  return (
    <div className="web3-panel">
      <div className="web3-panel__header">
        <h2>📜 Smart Contract Scanner</h2>
        <p>Detect vulnerabilities: reentrancy, access control issues, honeypot patterns, and more.</p>
      </div>

      {/* Mode toggle */}
      <div className="web3-toggle-group">
        <button
          className={`web3-toggle ${mode === 'address' ? 'web3-toggle--active' : ''}`}
          onClick={() => setMode('address')}
        >
          🔗 By Address
        </button>
        <button
          className={`web3-toggle ${mode === 'code' ? 'web3-toggle--active' : ''}`}
          onClick={() => setMode('code')}
        >
          💻 By Source Code
        </button>
      </div>

      {/* Input */}
      {mode === 'address' ? (
        <div className="web3-input-group">
          <div className="web3-input-wrapper">
            <input
              className="web3-input"
              type="text"
              placeholder="Contract address (0x...)"
              value={address}
              onChange={e => setAddress(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
              maxLength={42}
              spellCheck={false}
            />
          </div>
          <button
            className="web3-btn web3-btn--primary"
            onClick={handleScan}
            disabled={loading || !address.trim()}
          >
            {loading ? <><span className="web3-spinner" /> Scanning...</> : 'Scan Contract'}
          </button>
        </div>
      ) : (
        <div className="web3-code-input-group">
          <textarea
            className="web3-textarea"
            placeholder="// Paste Solidity source code here...
pragma solidity ^0.8.0;

contract Example {
  mapping(address => uint) public balances;
  
  function withdraw() public {
    // paste your contract here
  }
}"
            value={code}
            onChange={e => setCode(e.target.value)}
            rows={12}
            spellCheck={false}
          />
          <button
            className="web3-btn web3-btn--primary"
            onClick={handleScan}
            disabled={loading || !code.trim()}
          >
            {loading ? <><span className="web3-spinner" /> Analyzing...</> : 'Analyze Code'}
          </button>
        </div>
      )}

      {error && (
        <div className="web3-alert web3-alert--error">
          <span>⚠️</span> {error}
        </div>
      )}

      {loading && <ScanProgress />}

      {result && <ScanResult result={result} />}
    </div>
  );
}

// ─── SCAN RESULT ─────────────────────────────────────────────────────────────
function ScanResult({ result }: { result: ContractScanResult }) {
  const risk = useRiskColor(result.riskScore);
  const [expanded, setExpanded] = useState<string | null>(null);

  const criticalCount = result.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount     = result.vulnerabilities.filter(v => v.severity === 'HIGH').length;

  return (
    <div className="web3-result">
      {/* Summary header */}
      <div className="web3-scan-summary"
        style={{ '--risk-color': risk.color } as React.CSSProperties}>
        <div className="web3-scan-summary__score">
          <div className="web3-scan-summary__number" style={{ color: risk.color }}>
            {result.riskScore}
          </div>
          <div className="web3-scan-summary__label">Risk Score</div>
        </div>

        <div className="web3-scan-summary__meta">
          {result.contractName && (
            <div className="web3-scan-summary__name">{result.contractName}</div>
          )}
          {result.address && (
            <code className="web3-mono">{result.address.slice(0, 10)}...{result.address.slice(-6)}</code>
          )}
          <div className="web3-scan-flags">
            {result.isHoneypot && (
              <span className="web3-flag web3-flag--danger">🍯 HONEYPOT DETECTED</span>
            )}
            {result.isVerified && (
              <span className="web3-flag web3-flag--ok">✓ VERIFIED</span>
            )}
          </div>
        </div>

        <div className="web3-scan-counts">
          <SeverityCount count={criticalCount} severity="CRITICAL" />
          <SeverityCount count={highCount}     severity="HIGH" />
          <SeverityCount
            count={result.vulnerabilities.filter(v => v.severity === 'MEDIUM').length}
            severity="MEDIUM"
          />
        </div>
      </div>

      {/* Detected patterns */}
      {result.detectedPatterns.length > 0 && (
        <div className="web3-section">
          <h3 className="web3-section__title">Detected Patterns</h3>
          <div className="web3-tags">
            {result.detectedPatterns.map(pattern => (
              <span key={pattern} className="web3-tag web3-tag--pattern">
                {pattern}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerabilities */}
      {result.vulnerabilities.length > 0 && (
        <div className="web3-section">
          <h3 className="web3-section__title">
            Vulnerabilities ({result.vulnerabilities.length})
          </h3>
          <div className="web3-vuln-list">
            {result.vulnerabilities.map(vuln => (
              <VulnCard
                key={vuln.id}
                vuln={vuln}
                expanded={expanded === vuln.id}
                onToggle={() => setExpanded(expanded === vuln.id ? null : vuln.id)}
              />
            ))}
          </div>
        </div>
      )}

      {/* AI Summary */}
      {result.summary && (
        <div className="web3-section">
          <h3 className="web3-section__title">Analysis Summary</h3>
          <div className="web3-summary">{result.summary}</div>
        </div>
      )}

      <div className="web3-result__footer">
        Scanned: {new Date(result.scannedAt).toLocaleString()}
      </div>
    </div>
  );
}

function SeverityCount({ count, severity }: { count: number; severity: VulnSeverity }) {
  const { color } = SEVERITY_META[severity];
  if (count === 0) return null;
  return (
    <div className="web3-count" style={{ color, borderColor: `${color}33` }}>
      <span className="web3-count__num">{count}</span>
      <span className="web3-count__label">{severity}</span>
    </div>
  );
}

function VulnCard({
  vuln,
  expanded,
  onToggle,
}: {
  vuln: ContractVulnerability;
  expanded: boolean;
  onToggle: () => void;
}) {
  const meta = SEVERITY_META[vuln.severity];

  return (
    <div
      className={`web3-vuln ${expanded ? 'web3-vuln--expanded' : ''}`}
      style={{ '--sev-color': meta.color } as React.CSSProperties}
    >
      <button className="web3-vuln__header" onClick={onToggle}>
        <span className="web3-vuln__icon">{meta.icon}</span>
        <span className="web3-vuln__name">{vuln.name}</span>
        <span className="web3-vuln__sev" style={{ color: meta.color }}>
          {vuln.severity}
        </span>
        {vuln.cwe && (
          <span className="web3-vuln__cwe">{vuln.cwe}</span>
        )}
        <span className="web3-vuln__chevron">{expanded ? '▲' : '▼'}</span>
      </button>

      {expanded && (
        <div className="web3-vuln__body">
          <p className="web3-vuln__desc">{vuln.description}</p>
          {vuln.lineRef && (
            <div className="web3-vuln__lineref">📍 {vuln.lineRef}</div>
          )}
          <div className="web3-vuln__rec">
            <span className="web3-vuln__rec-label">Recommendation:</span>
            {vuln.recommendation}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── SCAN PROGRESS ───────────────────────────────────────────────────────────
const SCAN_STEPS = [
  'Fetching contract bytecode...',
  'Decompiling ABI...',
  'Checking reentrancy patterns...',
  'Analyzing access control...',
  'Detecting honeypot signatures...',
  'Scoring risk vectors...',
];

function ScanProgress() {
  const [step, setStep] = React.useState(0);

  React.useEffect(() => {
    const timer = setInterval(() => {
      setStep(s => (s < SCAN_STEPS.length - 1 ? s + 1 : s));
    }, 1200);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="web3-scan-progress">
      <div className="web3-scan-progress__bar">
        <div
          className="web3-scan-progress__fill"
          style={{ width: `${((step + 1) / SCAN_STEPS.length) * 100}%` }}
        />
      </div>
      <div className="web3-scan-progress__step">
        <span className="web3-spinner" />
        {SCAN_STEPS[step]}
      </div>
    </div>
  );
}
