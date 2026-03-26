/**
 * WEB3 MODULE SAFE INTEGRATION ENTRY POINT
 * ==========================================
 * Place at: /web3/index.tsx
 *
 * This is the ONLY file that existing system code needs to import.
 * It handles the feature flag check, lazy loading, and error isolation.
 *
 * Usage in your existing Next.js app:
 *
 *   import Web3Module from '../web3';
 *   // Then in your page/component:
 *   <Web3Module />
 *
 * If WEB3_ENABLED=false, renders nothing. Safe. Zero impact.
 */

import React, { lazy, Suspense } from 'react';
import Web3ErrorBoundary from './components/Web3ErrorBoundary';

// ─── FEATURE FLAG ─────────────────────────────────────────────────────────────
const WEB3_ENABLED =
  process.env.NEXT_PUBLIC_WEB3_ENABLED === 'true' || false;

// ─── LAZY LOAD — zero bundle cost when disabled ───────────────────────────────
const Web3Dashboard = WEB3_ENABLED
  ? lazy(() => import('./components/dashboard/Web3Dashboard').then(m => ({ default: m.default })))
  : null;

// ─── STYLESHEET — only injected when enabled ──────────────────────────────────
if (WEB3_ENABLED && typeof window !== 'undefined') {
  import('./styles/web3.css');
}

// ─── MODULE ENTRY ─────────────────────────────────────────────────────────────
export default function Web3Module() {
  // ZERO RENDER when disabled — no DOM nodes, no network calls, no side effects
  if (!WEB3_ENABLED || !Web3Dashboard) {
    return null;
  }

  return (
    <Web3ErrorBoundary
      moduleName="Web3Module"
      fallback={
        <div style={{
          padding:    '20px',
          color:      '#8b949e',
          fontSize:   '13px',
          fontFamily: 'monospace',
        }}>
          Web3 module encountered an error and has been safely disabled.
        </div>
      }
    >
      <Suspense fallback={<Web3LoadingShim />}>
        <Web3Dashboard />
      </Suspense>
    </Web3ErrorBoundary>
  );
}

// ─── MINIMAL LOADING SHIM ─────────────────────────────────────────────────────
function Web3LoadingShim() {
  return (
    <div style={{
      display:        'flex',
      alignItems:     'center',
      justifyContent: 'center',
      height:         '200px',
      color:          '#8b949e',
      fontSize:       '13px',
      fontFamily:     'monospace',
      gap:            '12px',
    }}>
      <div style={{
        width:         '16px',
        height:        '16px',
        border:        '2px solid #1e2433',
        borderTop:     '2px solid #00d4ff',
        borderRadius:  '50%',
        animation:     'spin 0.7s linear infinite',
      }} />
      Loading Web3 module...
    </div>
  );
}

// Named exports for individual components (advanced usage)
export { default as WalletAnalyzer }    from './components/wallet/WalletAnalyzer';
export { default as ContractScanner }   from './components/contract/ContractScanner';
export { default as ThreatFeed }        from './components/feed/ThreatFeed';
export { default as TransactionMonitor} from './components/transactions/TransactionMonitor';
export { Web3ErrorBoundary };
