/**
 * WEB3 MODULE — SHARED HOOKS
 * Place at: /web3/hooks/useWeb3.ts
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import type { ApiResponse } from '../types';

// ─── GENERIC ASYNC DATA HOOK ─────────────────────────────────────────────────
export function useAsync<T>(
  asyncFn: () => Promise<ApiResponse<T>>,
  deps: unknown[] = [],
  options: { immediate?: boolean; timeout?: number } = { immediate: true }
) {
  const [data, setData]       = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const abortRef              = useRef<AbortController | null>(null);
  const mountedRef            = useRef(true);

  const execute = useCallback(async () => {
    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();

    setLoading(true);
    setError(null);

    try {
      const result = await asyncFn();
      if (!mountedRef.current) return;

      if (result.success && result.data !== undefined) {
        setData(result.data);
      } else {
        setError(result.error || 'Unknown error');
      }
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setError(msg);
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    mountedRef.current = true;
    if (options.immediate !== false) execute();
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [execute]);

  return { data, loading, error, refetch: execute };
}

// ─── RISK COLOR HELPER ───────────────────────────────────────────────────────
export function useRiskColor(score: number): {
  color: string;
  bg: string;
  label: string;
} {
  if (score >= 81) return { color: '#ff0044', bg: '#ff004415', label: 'CRITICAL' };
  if (score >= 61) return { color: '#ff6600', bg: '#ff660015', label: 'HIGH' };
  if (score >= 31) return { color: '#ffaa00', bg: '#ffaa0015', label: 'MEDIUM' };
  return { color: '#00ff88', bg: '#00ff8815', label: 'LOW' };
}

// ─── DEBOUNCE HOOK ───────────────────────────────────────────────────────────
export function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState<T>(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debounced;
}

// ─── COUNTDOWN REFRESH HOOK ──────────────────────────────────────────────────
export function useAutoRefresh(
  callback: () => void,
  intervalMs: number,
  enabled: boolean = true
) {
  const callbackRef = useRef(callback);
  callbackRef.current = callback;

  useEffect(() => {
    if (!enabled) return;
    const timer = setInterval(() => callbackRef.current(), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs, enabled]);
}

// ─── CLIPBOARD ───────────────────────────────────────────────────────────────
export function useCopyToClipboard() {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }, []);

  return { copy, copied };
}
