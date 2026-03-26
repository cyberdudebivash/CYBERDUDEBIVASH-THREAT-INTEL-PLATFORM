/**
 * RECENT THREATS WIDGET (Overview Panel)
 * Place at: /web3/components/dashboard/RecentThreats.tsx
 */

import React from 'react';
import { useAsync } from '../../hooks/useWeb3';
import { fetchThreatFeed } from '../../services/web3Api';
import type { Web3ThreatEntry, VulnSeverity } from '../../types';

const SEVERITY_COLORS: Record<VulnSeverity, string> = {
  CRITICAL: '#ff0044',
  HIGH:     '#ff6600',
  MEDIUM:   '#ffaa00',
  LOW:      '#00ff88',
  INFO:     '#4499ff',
};

const CATEGORY_ICONS: Record<string, string> = {
  'rug-pull':              '🪤',
  'exploit':               '💥',
  'phishing':              '🎣',
  'malicious-wallet':      '👛',
  'flash-loan-attack':     '⚡',
  'bridge-hack':           '🌉',
  'oracle-manipulation':   '🔮',
  'governance-attack':     '🗳️',
  'private-key-compromise':'🔑',
};

interface Props {
  limit?: number;
  onViewAll: () => void;
}

export default function RecentThreats({ limit = 5, onViewAll }: Props) {
  const { data, loading, error } = useAsync(
    () => fetchThreatFeed({ limit, page: 1 }),
    [limit]
  );

  return (
    <div className="web3-widget">
      <div className="web3-widget__header">
        <h2 className="web3-widget__title">
          <span>☣️</span> Recent Web3 Threats
        </h2>
        <button className="web3-btn web3-btn--ghost web3-btn--sm" onClick={onViewAll}>
          View All →
        </button>
      </div>

      <div className="web3-widget__body">
        {loading && (
          <div className="web3-threat-list">
            {Array.from({ length: limit }).map((_, i) => (
              <div key={i} className="web3-threat-row web3-threat-row--skeleton" />
            ))}
          </div>
        )}

        {error && (
          <div className="web3-error-inline">⚠️ Failed to load threats</div>
        )}

        {!loading && !error && data?.threats && (
          <div className="web3-threat-list">
            {data.threats.map(threat => (
              <ThreatRow key={threat.id} threat={threat} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ThreatRow({ threat }: { threat: Web3ThreatEntry }) {
  const color = SEVERITY_COLORS[threat.severity];
  const icon  = CATEGORY_ICONS[threat.category] || '⚠️';

  return (
    <div className="web3-threat-row">
      <div className="web3-threat-row__icon">{icon}</div>
      <div className="web3-threat-row__content">
        <div className="web3-threat-row__title">{threat.title}</div>
        <div className="web3-threat-row__meta">
          <span>{threat.network}</span>
          <span>·</span>
          <span>{threat.affectedProtocol || threat.category}</span>
          {threat.lossUSD && (
            <>
              <span>·</span>
              <span className="web3-threat-row__loss">
                ${(threat.lossUSD / 1_000_000).toFixed(1)}M lost
              </span>
            </>
          )}
        </div>
      </div>
      <div
        className="web3-threat-row__badge"
        style={{ color, borderColor: `${color}33`, background: `${color}11` }}
      >
        {threat.severity}
      </div>
    </div>
  );
}
