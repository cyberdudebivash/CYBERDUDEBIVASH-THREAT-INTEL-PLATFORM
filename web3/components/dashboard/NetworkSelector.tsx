/**
 * NETWORK SELECTOR
 * Place at: /web3/components/dashboard/NetworkSelector.tsx
 */

import React from 'react';

const NETWORKS = [
  { id: 'ethereum', label: 'Ethereum',  symbol: 'ETH',  color: '#627eea' },
  { id: 'polygon',  label: 'Polygon',   symbol: 'MATIC', color: '#8247e5' },
  { id: 'bsc',      label: 'BSC',       symbol: 'BNB',  color: '#f3ba2f' },
];

interface Props {
  value: string;
  onChange: (network: string) => void;
}

export default function NetworkSelector({ value, onChange }: Props) {
  const current = NETWORKS.find(n => n.id === value) || NETWORKS[0];

  return (
    <div className="web3-network-selector">
      <span className="web3-network-selector__dot"
        style={{ background: current.color }} />
      <select
        className="web3-network-selector__select"
        value={value}
        onChange={e => onChange(e.target.value)}
        aria-label="Select network"
      >
        {NETWORKS.map(n => (
          <option key={n.id} value={n.id}>
            {n.label} ({n.symbol})
          </option>
        ))}
      </select>
    </div>
  );
}
