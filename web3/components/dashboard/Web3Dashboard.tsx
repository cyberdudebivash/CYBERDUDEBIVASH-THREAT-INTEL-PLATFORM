/**
 * WEB3 DASHBOARD — MAIN ENTRY POINT
 * ====================================
 * Place at: /web3/components/dashboard/Web3Dashboard.tsx
 *
 * This is the root component for /web3/ route.
 * Fully isolated. Safe to disable via WEB3_ENABLED flag.
 */

import React, { lazy, Suspense, useState } from 'react';
import Web3ErrorBoundary from '../Web3ErrorBoundary';
import DashboardStats   from './DashboardStats';
import RecentThreats    from './RecentThreats';
import NetworkSelector  from './NetworkSelector';

// ─── LAZY-LOADED SUB-VIEWS ────────────────────────────────────────────────────
const WalletAnalyzer   = lazy(() => import('../wallet/WalletAnalyzer'));
const ContractScanner  = lazy(() => import('../contract/ContractScanner'));
const ThreatFeed       = lazy(() => import('../feed/ThreatFeed'));
const TransactionMonitor = lazy(() => import('../transactions/TransactionMonitor'));

// ─── NAV ITEMS ────────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: 'overview',      label: 'Overview',      icon: '🛰' },
  { id: 'wallet',        label: 'Wallet Intel',   icon: '🔍' },
  { id: 'contract',      label: 'Contract Scan',  icon: '📜' },
  { id: 'threats',       label: 'Threat Feed',    icon: '☣️' },
  { id: 'transactions',  label: 'Transactions',   icon: '⚡' },
] as const;

type NavId = typeof NAV_ITEMS[number]['id'];

// ─── SUSPENSE FALLBACK ────────────────────────────────────────────────────────
function PanelLoader() {
  return (
    <div className="web3-loader">
      <div className="web3-loader__spinner" />
      <span>Loading module...</span>
    </div>
  );
}

// ─── MAIN DASHBOARD ──────────────────────────────────────────────────────────
export default function Web3Dashboard() {
  const [activeTab, setActiveTab] = useState<NavId>('overview');
  const [network,   setNetwork]   = useState<string>('ethereum');

  return (
    <div className="web3-root">
      {/* ── HEADER ── */}
      <header className="web3-header">
        <div className="web3-header__brand">
          <span className="web3-header__badge">WEB3</span>
          <h1 className="web3-header__title">Threat Intelligence</h1>
        </div>
        <NetworkSelector value={network} onChange={setNetwork} />
      </header>

      {/* ── NAV ── */}
      <nav className="web3-nav">
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            className={`web3-nav__item ${activeTab === item.id ? 'web3-nav__item--active' : ''}`}
            onClick={() => setActiveTab(item.id)}
          >
            <span className="web3-nav__icon">{item.icon}</span>
            <span className="web3-nav__label">{item.label}</span>
          </button>
        ))}
      </nav>

      {/* ── CONTENT ── */}
      <main className="web3-main">
        <Web3ErrorBoundary moduleName="Web3Dashboard">
          <Suspense fallback={<PanelLoader />}>
            {activeTab === 'overview' && (
              <OverviewPanel network={network} onNavigate={setActiveTab} />
            )}
            {activeTab === 'wallet' && (
              <WalletAnalyzer network={network} />
            )}
            {activeTab === 'contract' && (
              <ContractScanner network={network} />
            )}
            {activeTab === 'threats' && (
              <ThreatFeed />
            )}
            {activeTab === 'transactions' && (
              <TransactionMonitor network={network} />
            )}
          </Suspense>
        </Web3ErrorBoundary>
      </main>
    </div>
  );
}

// ─── OVERVIEW PANEL ──────────────────────────────────────────────────────────
function OverviewPanel({
  network,
  onNavigate,
}: {
  network: string;
  onNavigate: (id: NavId) => void;
}) {
  return (
    <div className="web3-overview">
      <Web3ErrorBoundary moduleName="DashboardStats">
        <DashboardStats onNavigate={onNavigate} />
      </Web3ErrorBoundary>

      <div className="web3-overview__grid">
        <Web3ErrorBoundary moduleName="RecentThreats">
          <RecentThreats
            limit={5}
            onViewAll={() => onNavigate('threats')}
          />
        </Web3ErrorBoundary>
      </div>
    </div>
  );
}
