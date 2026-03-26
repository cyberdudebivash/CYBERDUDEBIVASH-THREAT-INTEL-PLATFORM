/**
 * WEB3 ERROR BOUNDARY
 * ====================
 * CRITICAL: This component PREVENTS any Web3 failure from propagating
 * to the main Sentinel APEX dashboard or any other system.
 *
 * Place at: /web3/components/Web3ErrorBoundary.tsx
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  moduleName?: string;
  onError?: (error: Error, info: ErrorInfo) => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class Web3ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });
    // Log isolated — does not affect core system
    console.error('[WEB3 MODULE ERROR - ISOLATED]', {
      module: this.props.moduleName || 'Web3',
      error: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
    });
    this.props.onError?.(error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div style={{
          background: '#0d1117',
          border: '1px solid #ff004422',
          borderRadius: '8px',
          padding: '24px',
          margin: '16px 0',
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <span style={{ fontSize: '20px' }}>⚠️</span>
            <div>
              <div style={{ color: '#ff4444', fontWeight: 700, fontSize: '14px' }}>
                Web3 Module Error — Isolated
              </div>
              <div style={{ color: '#666', fontSize: '12px', marginTop: '2px' }}>
                Core system is unaffected
              </div>
            </div>
          </div>
          <div style={{
            background: '#ff000008',
            border: '1px solid #ff000022',
            borderRadius: '4px',
            padding: '12px',
            color: '#ff6666',
            fontSize: '12px',
            fontFamily: 'monospace',
            marginBottom: '16px',
          }}>
            {this.state.error?.message || 'An unexpected error occurred in the Web3 module'}
          </div>
          <button
            onClick={this.handleReset}
            style={{
              background: '#1a1f2e',
              border: '1px solid #30363d',
              borderRadius: '6px',
              color: '#8b949e',
              padding: '8px 16px',
              cursor: 'pointer',
              fontSize: '12px',
            }}
          >
            ↺ Retry
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default Web3ErrorBoundary;
