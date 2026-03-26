/**
 * TRANSACTION MONITOR
 * ====================
 * Place at: /web3/components/transactions/TransactionMonitor.tsx
 *
 * Tracks: Large transactions, suspicious patterns, alert system (UI-based).
 */

import React, { useState, useCallback } from 'react';
import { useAsync, useAutoRefresh, useCopyToClipboard } from '../../hooks/useWeb3';
import { fetchSuspiciousTransactions } from '../../services/web3Api';
import type { SuspiciousTransaction, TxAlertType } from '../../types';

const ALERT_META: Record<TxAlertType, { icon: string; color: string; label: string }> = {
  'large-transfer':   { icon: '🐋', color: '#00ccff', label: 'Large Transfer'   },
  'mixer-interaction':{ icon: '🌀', color: '#cc44ff', label: 'Mixer Interaction' },
  'known-scammer':    { icon: '🚨', color: '#ff0044', label: 'Known Scammer'    },
  'rapid-drain':      { icon: '💨', color: '#ff6600', label: 'Rapid Drain'      },
  'unusual-pattern':  { icon: '❓', color: '#ffaa00', label: 'Unusual Pattern'  },
};

interface Props {
  network: string;
}

export default function TransactionMonitor({ network }: Props) {
  const [page,        setPage]        = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [alerts,      setAlerts]      = useState<string[]>([]);   // dismissed alert IDs

  const fetchFn = useCallback(
    () => fetchSuspiciousTransactions({ page, limit: 20, network }),
    [page, network]
  );

  const { data, loading, error, refetch } = useAsync(fetchFn, [page, network]);

  useAutoRefresh(refetch, 60_000, autoRefresh);

  const totalPages   = data ? Math.ceil(data.total / 20) : 1;
  const visibleTxs   = data?.transactions.filter(tx => !alerts.includes(tx.hash)) || [];
  const criticalCount = visibleTxs.filter(tx => tx.riskScore >= 81).length;

  return (
    <div className="web3-panel">
      <div className="web3-panel__header">
        <div>
          <h2>⚡ Transaction Monitor</h2>
          <p>Real-time detection of suspicious transactions and fund movements.</p>
        </div>
        <div className="web3-panel__controls">
          {criticalCount > 0 && (
            <span className="web3-badge web3-badge--alert">
              🔴 {criticalCount} Critical
            </span>
          )}
          <button
            className={`web3-btn web3-btn--sm ${autoRefresh ? 'web3-btn--primary' : 'web3-btn--ghost'}`}
            onClick={() => setAutoRefresh(ar => !ar)}
          >
            {autoRefresh ? '⏸ Pause' : '▶ Live'}
          </button>
          <button
            className="web3-btn web3-btn--ghost web3-btn--sm"
            onClick={refetch}
            disabled={loading}
          >
            {loading ? <span className="web3-spinner" /> : '↺'} Refresh
          </button>
        </div>
      </div>

      {/* Live indicator */}
      {autoRefresh && (
        <div className="web3-live-bar">
          <span className="web3-live-dot" />
          <span>Live monitoring active — refreshes every 60s</span>
        </div>
      )}

      {error && (
        <div className="web3-alert web3-alert--error">
          ⚠️ {error}
          <button className="web3-btn web3-btn--ghost web3-btn--xs" onClick={refetch}>Retry</button>
        </div>
      )}

      {/* Stats bar */}
      {data && (
        <div className="web3-tx-stats">
          <TxStatChip label="Total Flagged" value={data.total} color="#ffaa00" />
          <TxStatChip label="Critical Risk" value={criticalCount} color="#ff0044" />
          <TxStatChip
            label="High Risk"
            value={visibleTxs.filter(tx => tx.riskScore >= 61 && tx.riskScore < 81).length}
            color="#ff6600"
          />
        </div>
      )}

      {/* Transaction list */}
      <div className="web3-tx-list">
        {loading && !data &&
          Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="web3-tx-row web3-tx-row--skeleton" />
          ))
        }

        {visibleTxs.map(tx => (
          <TxRow
            key={tx.hash}
            tx={tx}
            onDismiss={() => setAlerts(prev => [...prev, tx.hash])}
          />
        ))}

        {!loading && visibleTxs.length === 0 && !error && (
          <div className="web3-empty">
            <span>✅</span>
            <p>No suspicious transactions detected on {network}</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="web3-pagination">
          <button
            className="web3-btn web3-btn--ghost"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
          >← Prev</button>
          <span className="web3-pagination__info">Page {page} / {totalPages}</span>
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

// ─── TX ROW ──────────────────────────────────────────────────────────────────
function TxRow({
  tx,
  onDismiss,
}: {
  tx: SuspiciousTransaction;
  onDismiss: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const alert      = ALERT_META[tx.alertType];
  const { copy, copied } = useCopyToClipboard();

  const riskColor =
    tx.riskScore >= 81 ? '#ff0044' :
    tx.riskScore >= 61 ? '#ff6600' :
    tx.riskScore >= 31 ? '#ffaa00' :
    '#00ff88';

  return (
    <div
      className={`web3-tx-row ${expanded ? 'web3-tx-row--expanded' : ''}`}
      style={{ '--risk-color': riskColor, '--alert-color': alert.color } as React.CSSProperties}
    >
      <div className="web3-tx-row__main" onClick={() => setExpanded(e => !e)}>
        <div className="web3-tx-row__alert">
          <span className="web3-tx-row__alert-icon">{alert.icon}</span>
          <span className="web3-tx-row__alert-label"
            style={{ color: alert.color }}>
            {alert.label}
          </span>
        </div>

        <div className="web3-tx-row__addresses">
          <span className="web3-mono web3-tx-row__addr">
            {tx.from.slice(0, 6)}...{tx.from.slice(-4)}
          </span>
          <span className="web3-tx-row__arrow">→</span>
          <span className="web3-mono web3-tx-row__addr">
            {tx.to.slice(0, 6)}...{tx.to.slice(-4)}
          </span>
        </div>

        <div className="web3-tx-row__value">
          <span className="web3-tx-row__eth">{tx.valueETH} ETH</span>
          <span className="web3-tx-row__usd">{tx.valueUSD}</span>
        </div>

        <div className="web3-tx-row__score"
          style={{ color: riskColor, borderColor: `${riskColor}33` }}>
          {tx.riskScore}
        </div>

        <div className="web3-tx-row__time">{formatTimeAgo(tx.timestamp)}</div>

        <button
          className="web3-tx-row__dismiss"
          onClick={e => { e.stopPropagation(); onDismiss(); }}
          title="Dismiss"
        >✕</button>
      </div>

      {expanded && (
        <div className="web3-tx-row__detail">
          <div className="web3-tx-detail-grid">
            <DetailItem label="Alert" value={tx.alertMessage} />
            <DetailItem label="Network" value={tx.network} />
            <DetailItem label="Block" value={`#${tx.blockNumber.toLocaleString()}`} />
          </div>
          <div className="web3-tx-hash-row">
            <code className="web3-mono web3-tx-hash">{tx.hash}</code>
            <button
              className="web3-btn web3-btn--ghost web3-btn--xs"
              onClick={() => copy(tx.hash)}
            >
              {copied ? '✓' : '⎘'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="web3-detail-item">
      <span className="web3-detail-item__label">{label}</span>
      <span className="web3-detail-item__value">{value}</span>
    </div>
  );
}

function TxStatChip({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="web3-tx-stat" style={{ '--stat-color': color } as React.CSSProperties}>
      <span className="web3-tx-stat__value" style={{ color }}>{value}</span>
      <span className="web3-tx-stat__label">{label}</span>
    </div>
  );
}

function formatTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}
