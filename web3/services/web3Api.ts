/**
 * WEB3 MODULE — API SERVICE LAYER
 * ================================
 * ISOLATION GUARANTEE: All API calls go through /web3-api/* endpoints only.
 * Zero shared state with core Sentinel APEX APIs.
 *
 * Place at: /web3/services/web3Api.ts
 */

import type {
  WalletAnalysis,
  ContractScanResult,
  Web3ThreatEntry,
  SuspiciousTransaction,
  Web3DashboardStats,
  ApiResponse,
} from '../types';

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const WEB3_API_BASE =
  process.env.NEXT_PUBLIC_WEB3_API_URL || '/web3-api';

const TIMEOUTS = {
  walletAnalyzer:  15_000,
  contractScanner: 30_000,
  threatFeed:      10_000,
  transactions:    10_000,
  dashboard:        8_000,
};

// ─── IN-MEMORY CACHE ─────────────────────────────────────────────────────────
const cache = new Map<string, { data: unknown; expiresAt: number }>();

function getCached<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.data as T;
}

function setCache(key: string, data: unknown, ttlMs: number): void {
  cache.set(key, { data, expiresAt: Date.now() + ttlMs });
}

// ─── FETCH WITH TIMEOUT + ISOLATION ─────────────────────────────────────────
async function fetchWithTimeout<T>(
  url: string,
  timeoutMs: number,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-Module': 'web3',           // Identifies Web3 module calls
        ...(options.headers || {}),
      },
    });

    clearTimeout(timer);

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({}));
      return {
        success: false,
        error: (errBody as { error?: string }).error || `HTTP ${response.status}`,
        timestamp: new Date().toISOString(),
      };
    }

    const data = await response.json() as ApiResponse<T>;
    return data;
  } catch (err: unknown) {
    clearTimeout(timer);
    const message =
      err instanceof Error
        ? err.name === 'AbortError'
          ? 'Request timed out'
          : err.message
        : 'Unknown error';
    return {
      success: false,
      error: message,
      timestamp: new Date().toISOString(),
    };
  }
}

// ─── DASHBOARD STATS ─────────────────────────────────────────────────────────
export async function fetchWeb3DashboardStats(): Promise<ApiResponse<Web3DashboardStats>> {
  const cacheKey = 'web3:dashboard:stats';
  const cached = getCached<ApiResponse<Web3DashboardStats>>(cacheKey);
  if (cached) return cached;

  const result = await fetchWithTimeout<Web3DashboardStats>(
    `${WEB3_API_BASE}/dashboard/stats`,
    TIMEOUTS.dashboard
  );

  if (result.success) setCache(cacheKey, result, 60_000); // 1 min
  return result;
}

// ─── WALLET ANALYZER ─────────────────────────────────────────────────────────
export async function analyzeWallet(
  address: string,
  network: string = 'ethereum'
): Promise<ApiResponse<WalletAnalysis>> {
  const sanitized = address.trim().toLowerCase();

  // Input validation
  if (!/^0x[a-fA-F0-9]{40}$/.test(sanitized)) {
    return {
      success: false,
      error: 'Invalid wallet address format. Must be a valid Ethereum address (0x...)',
      timestamp: new Date().toISOString(),
    };
  }

  const cacheKey = `web3:wallet:${network}:${sanitized}`;
  const cached = getCached<ApiResponse<WalletAnalysis>>(cacheKey);
  if (cached) return cached;

  const result = await fetchWithTimeout<WalletAnalysis>(
    `${WEB3_API_BASE}/wallet/analyze`,
    TIMEOUTS.walletAnalyzer,
    {
      method: 'POST',
      body: JSON.stringify({ address: sanitized, network }),
    }
  );

  if (result.success) setCache(cacheKey, result, 5 * 60_000); // 5 min
  return result;
}

// ─── CONTRACT SCANNER ────────────────────────────────────────────────────────
export async function scanContract(payload: {
  address?: string;
  code?: string;
  network?: string;
}): Promise<ApiResponse<ContractScanResult>> {
  if (!payload.address && !payload.code) {
    return {
      success: false,
      error: 'Either contract address or source code is required',
      timestamp: new Date().toISOString(),
    };
  }

  if (payload.address && !/^0x[a-fA-F0-9]{40}$/.test(payload.address.trim())) {
    return {
      success: false,
      error: 'Invalid contract address format',
      timestamp: new Date().toISOString(),
    };
  }

  const cacheKey = `web3:contract:${payload.address || 'code-' + payload.code?.slice(0, 32)}`;
  const cached = getCached<ApiResponse<ContractScanResult>>(cacheKey);
  if (cached) return cached;

  const result = await fetchWithTimeout<ContractScanResult>(
    `${WEB3_API_BASE}/contract/scan`,
    TIMEOUTS.contractScanner,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    }
  );

  if (result.success) setCache(cacheKey, result, 15 * 60_000); // 15 min
  return result;
}

// ─── THREAT FEED ─────────────────────────────────────────────────────────────
export async function fetchThreatFeed(params?: {
  page?: number;
  limit?: number;
  category?: string;
  severity?: string;
}): Promise<ApiResponse<{ threats: Web3ThreatEntry[]; total: number }>> {
  const query = new URLSearchParams({
    page:     String(params?.page  || 1),
    limit:    String(params?.limit || 20),
    ...(params?.category && { category: params.category }),
    ...(params?.severity && { severity: params.severity }),
  }).toString();

  const cacheKey = `web3:threats:${query}`;
  const cached = getCached<ApiResponse<{ threats: Web3ThreatEntry[]; total: number }>>(cacheKey);
  if (cached) return cached;

  const result = await fetchWithTimeout<{ threats: Web3ThreatEntry[]; total: number }>(
    `${WEB3_API_BASE}/threats?${query}`,
    TIMEOUTS.threatFeed
  );

  if (result.success) setCache(cacheKey, result, 2 * 60_000); // 2 min
  return result;
}

// ─── TRANSACTION MONITOR ─────────────────────────────────────────────────────
export async function fetchSuspiciousTransactions(params?: {
  page?: number;
  limit?: number;
  network?: string;
}): Promise<ApiResponse<{ transactions: SuspiciousTransaction[]; total: number }>> {
  const query = new URLSearchParams({
    page:     String(params?.page  || 1),
    limit:    String(params?.limit || 20),
    ...(params?.network && { network: params.network }),
  }).toString();

  const cacheKey = `web3:txs:${query}`;
  const cached = getCached<ApiResponse<{ transactions: SuspiciousTransaction[]; total: number }>>(cacheKey);
  if (cached) return cached;

  const result = await fetchWithTimeout<{ transactions: SuspiciousTransaction[]; total: number }>(
    `${WEB3_API_BASE}/transactions/suspicious?${query}`,
    TIMEOUTS.transactions
  );

  if (result.success) setCache(cacheKey, result, 60_000); // 1 min
  return result;
}

// ─── CACHE INVALIDATION ──────────────────────────────────────────────────────
export function clearWeb3Cache(prefix?: string): void {
  if (!prefix) {
    cache.clear();
    return;
  }
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) cache.delete(key);
  }
}
