/**
 * DASHBOARD STATS CARDS
 * Place at: /web3/components/dashboard/DashboardStats.tsx
 */

import React from 'react';
import { useAsync } from '../../hooks/useWeb3';
import { fetchWeb3DashboardStats } from '../../services/web3Api';
import type { Web3DashboardStats } from '../../types';

interface Props {
  onNavigate: (id: string) => void;
}

interface StatCard {
  id: string;
  label: string;
  icon: string;
  key: keyof Web3DashboardStats;
  color: string;
  navTarget: string;
  format?: (v: number) => string;
}

const STAT_CARDS: StatCard[] = [
  {
    id: 'wallets',
    label: 'High-Risk Wallets',
    icon: '👛',
    key: 'highRiskWallets',
    color: '#ff4444',
    navTarget: 'wallet',
  },
  {
    id: 'threats',
    label: 'Latest Threats',
    icon: '☣️',
    key: 'latestThreats',
    color: '#ff6600',
    navTarget: 'threats',
  },
  {
    id: 'txs',
    label: 'Suspicious Txs',
    icon: '⚡',
    key: 'suspiciousTransactions',
    color: '#ffaa00',
    navTarget: 'transactions',
  },
  {
    id: 'contracts',
    label: 'High-Risk Contracts',
    icon: '📜',
    key: 'highRiskContracts',
    color: '#cc44ff',
    navTarget: 'contract',
  },
  {
    id: 'loss',
    label: 'Total Loss (USD)',
    icon: '💸',
    key: 'totalLossUSD',
    color: '#ff0044',
    navTarget: 'threats',
    format: (v) =>
      v >= 1_000_000
        ? `$${(v / 1_000_000).toFixed(1)}M`
        : `$${(v / 1_000).toFixed(0)}K`,
  },
];

export default function DashboardStats({ onNavigate }: Props) {
  const { data, loading, error, refetch } = useAsync(
    () => fetchWeb3DashboardStats(),
    [],
    { immediate: true }
  );

  if (loading) {
    return (
      <div className="web3-stats">
        {STAT_CARDS.map(card => (
          <div key={card.id} className="web3-stat-card web3-stat-card--skeleton">
            <div className="web3-stat-card__skeleton-icon" />
            <div className="web3-stat-card__skeleton-value" />
            <div className="web3-stat-card__skeleton-label" />
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="web3-error-inline">
        <span>⚠️ Stats unavailable</span>
        <button onClick={refetch} className="web3-btn web3-btn--sm">Retry</button>
      </div>
    );
  }

  return (
    <div className="web3-stats">
      {STAT_CARDS.map(card => {
        const rawValue = data ? (data[card.key] as number) : 0;
        const displayValue = card.format
          ? card.format(rawValue)
          : rawValue.toLocaleString();

        return (
          <button
            key={card.id}
            className="web3-stat-card"
            style={{ '--accent': card.color } as React.CSSProperties}
            onClick={() => onNavigate(card.navTarget)}
          >
            <div className="web3-stat-card__icon">{card.icon}</div>
            <div className="web3-stat-card__value">{displayValue}</div>
            <div className="web3-stat-card__label">{card.label}</div>
            <div className="web3-stat-card__glow" />
          </button>
        );
      })}

      {data?.lastUpdated && (
        <div className="web3-stats__timestamp">
          Updated: {new Date(data.lastUpdated).toLocaleTimeString()}
        </div>
      )}
    </div>
  );
}
