/**
 * WALLET INTELLIGENCE ANALYZER
 * ==============================
 * Place at: /web3/components/wallet/WalletAnalyzer.tsx
 *
 * Input:  wallet address
 * Output: risk score (0-100), tags, transaction summary
 */

import React, { useState } from 'react';
import { analyzeWallet } from '../../services/web3Api';
import { useRiskColor, useCopyToClipboard } from '../../hooks/useWeb3';
import type { WalletAnalysis, WalletTag } from '../../types';

const TAG_META: Record<WalletTag, { icon: string; color: string }> = {
  scam:      { icon: '🚨', color: '#ff0044' },
  mixer:     { icon: '🌀', color: '#cc44ff' },
  exchange:  { icon: '🏦', color: '#4499ff' },
  whale:     { icon: '🐋', color: '#00ccff' },
  phishing:  { icon: '🎣', color: '#ff6600' },
  'rug-pull':{ icon: '🪤', color: '#ff4400' },
  sanctioned:{ icon: '🚫', color: '#ff0000' },
  defi:      { icon: '⚗️', color: '#00ff88' },
  nft:       { icon: '🖼️', color: '#ffaa00' },
  'mev-bot': { icon: '🤖', color: '#aaaaff' },
  unknown:   { icon: '❓', color: '#666666' },
};

interface Props {
  network: string;
}

export default function WalletAnalyzer({ network }: Props) {
  const [address,  setAddress]  = useState('');
  const [result,   setResult]   = useState<WalletAnalysis | null>(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const { copy, copied }        = useCopyToClipboard();

  const handleAnalyze = async () => {
    if (!address.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    const response = await analyzeWallet(address.trim(), network);
    setLoading(false);

    if (response.success && response.data) {
      setResult(response.data);
    } else {
      setError(response.error || 'Analysis failed');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleAnalyze();
  };

  return (
    <div className="web3-panel">
      {/* ── HEADER ── */}
      <div className="web3-panel__header">
        <h2>🔍 Wallet Intelligence Engine</h2>
        <p>Analyze any wallet address for risk score, tags, and transaction patterns.</p>
      </div>

      {/* ── INPUT ── */}
      <div className="web3-input-group">
        <div className="web3-input-wrapper">
          <span className="web3-input-prefix">0x</span>
          <input
            className="web3-input"
            type="text"
            placeholder="Enter wallet address (0x...)"
            value={address}
            onChange={e => setAddress(e.target.value)}
            onKeyDown={handleKeyDown}
            maxLength={42}
            spellCheck={false}
            autoComplete="off"
          />
          {address && (
            <button
              className="web3-input-clear"
              onClick={() => { setAddress(''); setResult(null); setError(null); }}
              aria-label="Clear"
            >✕</button>
          )}
        </div>
        <button
          className="web3-btn web3-btn--primary"
          onClick={handleAnalyze}
          disabled={loading || !address.trim()}
        >
          {loading ? (
            <><span className="web3-spinner" /> Analyzing...</>
          ) : 'Analyze Wallet'}
        </button>
      </div>

      {/* ── ERROR ── */}
      {error && (
        <div className="web3-alert web3-alert--error">
          <span>⚠️</span> {error}
        </div>
      )}

      {/* ── RESULT ── */}
      {result && <WalletResult result={result} onCopy={copy} copied={copied} />}

      {/* ── LOADING SKELETON ── */}
      {loading && <WalletSkeleton />}
    </div>
  );
}

// ─── RESULT DISPLAY ──────────────────────────────────────────────────────────
function WalletResult({
  result,
  onCopy,
  copied,
}: {
  result: WalletAnalysis;
  onCopy: (text: string) => void;
  copied: boolean;
}) {
  const risk = useRiskColor(result.risk.score);

  return (
    <div className="web3-result">
      {/* Address row */}
      <div className="web3-result__address-row">
        <span className="web3-result__address">
          {result.address.slice(0, 6)}...{result.address.slice(-4)}
        </span>
        <button
          className="web3-btn web3-btn--ghost web3-btn--xs"
          onClick={() => onCopy(result.address)}
        >
          {copied ? '✓ Copied' : '⎘ Copy'}
        </button>
        <span className="web3-badge web3-badge--network">{result.network}</span>
      </div>

      {/* Risk score */}
      <div className="web3-risk-display" style={{ '--risk-color': risk.color } as React.CSSProperties}>
        <div className="web3-risk-display__gauge">
          <svg viewBox="0 0 120 60" className="web3-risk-display__arc">
            <path
              d="M 10 60 A 50 50 0 0 1 110 60"
              fill="none"
              stroke="#1a1f2e"
              strokeWidth="10"
              strokeLinecap="round"
            />
            <path
              d="M 10 60 A 50 50 0 0 1 110 60"
              fill="none"
              stroke={risk.color}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={`${(result.risk.score / 100) * 157} 157`}
              className="web3-risk-display__arc-fill"
            />
          </svg>
          <div className="web3-risk-display__score">{result.risk.score}</div>
          <div className="web3-risk-display__label"
            style={{ color: risk.color }}>
            {risk.label}
          </div>
        </div>

        {/* Stats grid */}
        <div className="web3-risk-stats">
          <StatItem label="Balance" value={`${result.balance.eth} ETH`} />
          <StatItem label="USD Value" value={result.balance.usd} />
          <StatItem label="Transactions" value={result.transactionCount.toLocaleString()} />
          <StatItem label="First Seen" value={formatDate(result.firstSeen)} />
          <StatItem label="Last Active" value={formatDate(result.lastSeen)} />
        </div>
      </div>

      {/* Tags */}
      {result.tags.length > 0 && (
        <div className="web3-section">
          <h3 className="web3-section__title">Intelligence Tags</h3>
          <div className="web3-tags">
            {result.tags.map(tag => {
              const meta = TAG_META[tag] || TAG_META.unknown;
              return (
                <span
                  key={tag}
                  className="web3-tag"
                  style={{ color: meta.color, borderColor: `${meta.color}33` }}
                >
                  {meta.icon} {tag}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Risk factors */}
      {result.risk.factors.length > 0 && (
        <div className="web3-section">
          <h3 className="web3-section__title">Risk Factors</h3>
          <div className="web3-factors">
            {result.risk.factors.map(factor => (
              <div key={factor.id} className="web3-factor">
                <div className="web3-factor__header">
                  <span className="web3-factor__label">{factor.label}</span>
                  <span className="web3-factor__weight">+{factor.weight}</span>
                </div>
                <div className="web3-factor__desc">{factor.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary */}
      {result.summary && (
        <div className="web3-section">
          <h3 className="web3-section__title">AI Summary</h3>
          <div className="web3-summary">{result.summary}</div>
        </div>
      )}

      {/* Related addresses */}
      {result.relatedAddresses?.length > 0 && (
        <div className="web3-section">
          <h3 className="web3-section__title">Related Addresses</h3>
          <div className="web3-address-list">
            {result.relatedAddresses.map(addr => (
              <div key={addr} className="web3-address-item">
                <code>{addr.slice(0, 10)}...{addr.slice(-6)}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="web3-result__footer">
        Source: {result.source} · Analyzed: {formatDate(result.analysedAt)}
      </div>
    </div>
  );
}

function StatItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="web3-stat-item">
      <div className="web3-stat-item__label">{label}</div>
      <div className="web3-stat-item__value">{value}</div>
    </div>
  );
}

function WalletSkeleton() {
  return (
    <div className="web3-result web3-result--skeleton">
      <div className="web3-skeleton web3-skeleton--wide" />
      <div className="web3-skeleton web3-skeleton--gauge" />
      <div className="web3-skeleton web3-skeleton--text" />
      <div className="web3-skeleton web3-skeleton--text web3-skeleton--short" />
    </div>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    });
  } catch {
    return iso;
  }
}
