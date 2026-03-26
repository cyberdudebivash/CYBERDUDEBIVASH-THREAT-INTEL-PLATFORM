/**
 * WEB3 THREAT FEED
 * =================
 * Place at: /web3/components/feed/ThreatFeed.tsx
 *
 * Rug pulls, exploits, malicious wallets — paginated and filterable.
 */

import React, { useState, useCallback } from 'react';
import { useAsync, useAutoRefresh } from '../../hooks/useWeb3';
import { fetchThreatFeed } from '../../services/web3Api';
import type { Web3ThreatEntry, ThreatCategory, VulnSeverity } from '../../types';

const CATEGORY_META: Record<ThreatCategory, { icon: string; label: string }> = {
  'rug-pull':              { icon: '🪤', label: 'Rug Pull' },
  'exploit':               { icon: '💥', label: 'Exploit' },
  'phishing':              { icon: '🎣', label: 'Phishing' },
  'malicious-wallet':      { icon: '👛', label: 'Malicious Wallet' },
  'flash-loan-attack':     { icon: '⚡', label: 'Flash Loan' },
  'bridge-hack':           { icon: '🌉', label: 'Bridge Hack' },
  'oracle-manipulation':   { icon: '🔮', label: 'Oracle Manipulation' },
  'governance-attack':     { icon: '🗳️', label: 'Governance Attack' },
  'private-key-compromise':{ icon: '🔑', label: 'Private Key Compromise' },
};

const SEVERITY_COLORS: Record<VulnSeverity, string> = {
  CRITICAL: '#ff0044',
  HIGH:     '#ff6600',
  MEDIUM:   '#ffaa00',
  LOW:      '#00ff88',
  INFO:     '#4499ff',
};

const SEVERITIES: VulnSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const CATEGORIES = Object.keys(CATEGORY_META) as ThreatCategory[];

export default function ThreatFeed() {
  const [page,     setPage]     = useState(1);
  const [category, setCategory] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const fetchFn = useCallback(
    () => fetchThreatFeed({ page, limit: 15, category, severity }),
    [page, category, severity]
  );

  const { data, loading, error, refetch } = useAsync(fetchFn, [page, category, severity]);

  // Auto-refresh every 2 minutes
  useAutoRefresh(refetch, 2 * 60_000, true);

  const totalPages = data ? Math.ceil(data.total / 15) : 1;

  return (
    <div className="web3-panel">
      <div className="web3-panel__header">
        <div>
          <h2>☣️ Web3 Threat Feed</h2>
          <p>Live intelligence on rug pulls, exploits, and malicious actors.</p>
        </div>
        <button
          className="web3-btn web3-btn--ghost web3-btn--sm"
          onClick={refetch}
          disabled={loading}
        >
          {loading ? <span className="web3-spinner" /> : '↺'} Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="web3-filters">
        <div className="web3-filter-group">
          <label className="web3-filter-label">Severity</label>
          <div className="web3-filter-pills">
            <button
              className={`web3-pill ${!severity ? 'web3-pill--active' : ''}`}
              onClick={() => { setSeverity(''); setPage(1); }}
            >All</button>
            {SEVERITIES.map(s => (
              <button
                key={s}
                className={`web3-pill ${severity === s ? 'web3-pill--active' : ''}`}
                style={{ '--pill-color': SEVERITY_COLORS[s] } as React.CSSProperties}
                onClick={() => { setSeverity(s); setPage(1); }}
              >{s}</button>
            ))}
          </div>
        </div>

        <div className="web3-filter-group">
          <label className="web3-filter-label">Category</label>
          <select
            className="web3-select"
            value={category}
            onChange={e => { setCategory(e.target.value); setPage(1); }}
          >
            <option value="">All Categories</option>
            {CATEGORIES.map(cat => (
              <option key={cat} value={cat}>
                {CATEGORY_META[cat].label}
              </option>
            ))}
          </select>
        </div>

        {data && (
          <div className="web3-filter-count">
            {data.total.toLocaleString()} threats
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="web3-alert web3-alert--error">
          ⚠️ Failed to load threats: {error}
          <button className="web3-btn web3-btn--ghost web3-btn--xs" onClick={refetch}>
            Retry
          </button>
        </div>
      )}

      {/* Feed */}
      <div className="web3-feed">
        {loading && !data && (
          Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="web3-feed-card web3-feed-card--skeleton" />
          ))
        )}

        {data?.threats.map(threat => (
          <ThreatCard
            key={threat.id}
            threat={threat}
            expanded={expanded === threat.id}
            onToggle={() => setExpanded(expanded === threat.id ? null : threat.id)}
          />
        ))}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="web3-pagination">
          <button
            className="web3-btn web3-btn--ghost"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
          >← Prev</button>
          <span className="web3-pagination__info">
            Page {page} of {totalPages}
          </span>
          <button
            className="web3-btn web3-btn--ghost"
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
          >Next →</button>
        </div>
      )}
    </div>
  );
}

// ─── THREAT CARD ─────────────────────────────────────────────────────────────
function ThreatCard({
  threat,
  expanded,
  onToggle,
}: {
  threat: Web3ThreatEntry;
  expanded: boolean;
  onToggle: () => void;
}) {
  const catMeta  = CATEGORY_META[threat.category] || { icon: '⚠️', label: threat.category };
  const sevColor = SEVERITY_COLORS[threat.severity];

  return (
    <div
      className={`web3-feed-card ${expanded ? 'web3-feed-card--expanded' : ''}`}
      style={{ '--sev-color': sevColor } as React.CSSProperties}
    >
      <button className="web3-feed-card__header" onClick={onToggle}>
        <div className="web3-feed-card__left">
          <span className="web3-feed-card__icon">{catMeta.icon}</span>
          <div>
            <div className="web3-feed-card__title">{threat.title}</div>
            <div className="web3-feed-card__meta">
              <span>{catMeta.label}</span>
              <span>·</span>
              <span>{threat.network}</span>
              {threat.affectedProtocol && (
                <><span>·</span><span>{threat.affectedProtocol}</span></>
              )}
              <span>·</span>
              <span>{formatTimeAgo(threat.publishedAt)}</span>
            </div>
          </div>
        </div>
        <div className="web3-feed-card__right">
          {threat.lossUSD && (
            <span className="web3-feed-card__loss">
              ${(threat.lossUSD / 1_000_000).toFixed(1)}M
            </span>
          )}
          <span
            className="web3-badge"
            style={{ color: sevColor, borderColor: `${sevColor}33`, background: `${sevColor}11` }}
          >
            {threat.severity}
          </span>
        </div>
      </button>

      {expanded && (
        <div className="web3-feed-card__body">
          <p className="web3-feed-card__desc">{threat.description}</p>

          {threat.affectedAddresses?.length > 0 && (
            <div className="web3-feed-card__section">
              <h4>Affected Addresses</h4>
              <div className="web3-address-list">
                {threat.affectedAddresses.map(addr => (
                  <code key={addr} className="web3-mono">{addr}</code>
                ))}
              </div>
            </div>
          )}

          {threat.iocs?.length > 0 && (
            <div className="web3-feed-card__section">
              <h4>Indicators of Compromise</h4>
              <div className="web3-ioc-list">
                {threat.iocs.map(ioc => (
                  <div key={ioc} className="web3-ioc">{ioc}</div>
                ))}
              </div>
            </div>
          )}

          {threat.exploitTxHash && (
            <div className="web3-feed-card__section">
              <h4>Exploit Transaction</h4>
              <code className="web3-mono">{threat.exploitTxHash}</code>
            </div>
          )}

          {threat.tags?.length > 0 && (
            <div className="web3-tags">
              {threat.tags.map(tag => (
                <span key={tag} className="web3-tag">{tag}</span>
              ))}
            </div>
          )}

          {threat.sourceUrl && (
            <a
              href={threat.sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="web3-link"
            >
              🔗 Source →
            </a>
          )}
        </div>
      )}
    </div>
  );
}

function formatTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(diff / 3_600_000);
  if (hours < 1) return `${Math.floor(diff / 60_000)}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
