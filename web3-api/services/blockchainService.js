/**
 * BLOCKCHAIN DATA SERVICE
 * ========================
 * Place at: /web3-api/services/blockchainService.js
 *
 * SECURITY: API keys NEVER exposed to frontend.
 * All blockchain queries go through this server-side service only.
 *
 * Supports: Etherscan, Alchemy
 * Fallback: Deterministic mock data (for dev/testing when APIs unavailable)
 */

'use strict';

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || '';
const ALCHEMY_API_KEY   = process.env.ALCHEMY_API_KEY   || '';
const USE_MOCK          = process.env.WEB3_USE_MOCK === 'true' || !ETHERSCAN_API_KEY;
const REQUEST_TIMEOUT   = 12_000; // 12s

// ─── HTTP FETCH WITH TIMEOUT ───────────────────────────────────────────────────
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return res.json();
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ─── NETWORK → ETHERSCAN ENDPOINT MAP ─────────────────────────────────────────
const ETHERSCAN_ENDPOINTS = {
  ethereum: 'https://api.etherscan.io/api',
  polygon:  'https://api.polygonscan.com/api',
  bsc:      'https://api.bscscan.com/api',
};

// ─── WALLET DATA FROM ETHERSCAN ───────────────────────────────────────────────
/**
 * Fetch wallet balance and transaction count from Etherscan.
 *
 * @param {string} address
 * @param {string} network
 * @returns {Promise<{ balanceWei: string; txCount: number; firstTx?: string; lastTx?: string }>}
 */
async function fetchWalletDataEtherscan(address, network = 'ethereum') {
  const base   = ETHERSCAN_ENDPOINTS[network] || ETHERSCAN_ENDPOINTS.ethereum;
  const apiKey = `&apikey=${ETHERSCAN_API_KEY}`;

  const [balanceRes, txListRes] = await Promise.allSettled([
    fetchWithTimeout(`${base}?module=account&action=balance&address=${address}&tag=latest${apiKey}`),
    fetchWithTimeout(`${base}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc${apiKey}`),
  ]);

  const balanceWei = balanceRes.status === 'fulfilled' && balanceRes.value?.result
    ? balanceRes.value.result
    : '0';

  let txCount  = 0;
  let firstTx  = null;
  let lastTx   = null;

  if (txListRes.status === 'fulfilled' && Array.isArray(txListRes.value?.result)) {
    const txs = txListRes.value.result;
    txCount   = txs.length;
    if (txs.length > 0) {
      firstTx = new Date(parseInt(txs[0].timeStamp, 10) * 1000).toISOString();
      lastTx  = new Date(parseInt(txs[txs.length - 1].timeStamp, 10) * 1000).toISOString();
    }
  }

  return { balanceWei, txCount, firstTx, lastTx };
}

/**
 * Public entry point: Get wallet data.
 * Falls back to mock when API unavailable.
 *
 * @param {string} address
 * @param {string} network
 */
async function getWalletData(address, network = 'ethereum') {
  if (USE_MOCK) return getMockWalletData(address, network);

  try {
    return await fetchWalletDataEtherscan(address, network);
  } catch (err) {
    console.warn(`[blockchainService] Etherscan error, falling back to mock: ${err.message}`);
    return getMockWalletData(address, network);
  }
}

// ─── CONTRACT DATA FROM ETHERSCAN ─────────────────────────────────────────────
/**
 * Fetch contract ABI and source code.
 *
 * @param {string} address
 * @param {string} network
 */
async function getContractData(address, network = 'ethereum') {
  if (USE_MOCK) return getMockContractData(address);

  const base   = ETHERSCAN_ENDPOINTS[network] || ETHERSCAN_ENDPOINTS.ethereum;
  const apiKey = `&apikey=${ETHERSCAN_API_KEY}`;

  try {
    const res = await fetchWithTimeout(
      `${base}?module=contract&action=getsourcecode&address=${address}${apiKey}`
    );

    const item = res?.result?.[0];
    if (!item) return getMockContractData(address);

    return {
      contractName:  item.ContractName || 'Unknown',
      sourceCode:    item.SourceCode   || '',
      abi:           item.ABI          || '[]',
      isVerified:    item.ABI !== 'Contract source code not verified',
      compilerVersion: item.CompilerVersion || 'unknown',
    };
  } catch (err) {
    console.warn(`[blockchainService] Contract fetch error: ${err.message}`);
    return getMockContractData(address);
  }
}

// ─── MOCK DATA (deterministic, address-seeded) ────────────────────────────────
function getMockWalletData(address, network) {
  // Seed mock values from address characters so same address = same mock data
  const seed = address.split('').reduce((a, c) => a + c.charCodeAt(0), 0);

  const balanceEth = ((seed % 1000) / 10).toFixed(4);
  const txCount    = (seed % 5000) + 10;
  const daysAgo    = (seed % 1000) + 30;
  const firstDate  = new Date(Date.now() - daysAgo * 86_400_000).toISOString();
  const lastDate   = new Date(Date.now() - (seed % 30) * 86_400_000).toISOString();

  return {
    balanceWei: String(BigInt(Math.floor(parseFloat(balanceEth) * 1e18))),
    balanceEth,
    txCount,
    firstTx:   firstDate,
    lastTx:    lastDate,
    source:    'mock',
    network,
  };
}

function getMockContractData(address) {
  const seed = address.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  const isVerified = seed % 3 !== 0;
  return {
    contractName:    isVerified ? `Contract_${address.slice(2, 8)}` : 'Unknown',
    sourceCode:      isVerified ? SAMPLE_SOLIDITY_WITH_VULN : '',
    abi:             '[]',
    isVerified,
    compilerVersion: '0.8.19',
    source:          'mock',
  };
}

// Sample vulnerable Solidity for mock scanning
const SAMPLE_SOLIDITY_WITH_VULN = `
pragma solidity ^0.8.0;

contract VulnerableBank {
  mapping(address => uint) public balances;

  function deposit() public payable {
    balances[msg.sender] += msg.value;
  }

  // VULNERABILITY: Reentrancy — state updated after external call
  function withdraw(uint _amount) public {
    require(balances[msg.sender] >= _amount);
    (bool sent, ) = msg.sender.call{value: _amount}("");
    require(sent, "Failed to send Ether");
    balances[msg.sender] -= _amount;  // State updated too late!
  }

  // VULNERABILITY: tx.origin authentication
  function transferOwnership(address newOwner) public {
    require(tx.origin == owner, "Not owner");  // Should use msg.sender
    owner = newOwner;
  }

  address public owner;
}
`;

module.exports = {
  getWalletData,
  getContractData,
};
