/**
 * WEB3 REAL-TIME ALERT SYSTEM — Frontend
 * ========================================
 * Place at: /web3/components/alerts/AlertSystem.tsx
 *
 * Connects to the WebSocket server and shows toast-style alerts.
 * ISOLATED: Only renders when Web3 module is enabled.
 * SAFE: All errors are caught and contained — never crash the main UI.
 */

import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  createContext,
  useContext,
} from 'react';

// ─── TYPES ────────────────────────────────────────────────────────────────────
type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface Web3Alert {
  id:        string;
  channel:   string;
  severity:  AlertSeverity;
  title:     string;
  message:   string;
  color:     string;
  sound:     boolean;
  timestamp: string;
  data?:     Record<string, unknown>;
}

type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

interface AlertContextValue {
  alerts:           Web3Alert[];
  status:           ConnectionStatus;
  unreadCount:      number;
  dismissAlert:     (id: string) => void;
  dismissAll:       () => void;
  markAllRead:      () => void;
}

// ─── CONTEXT ─────────────────────────────────────────────────────────────────
const AlertContext = createContext<AlertContextValue>({
  alerts:       [],
  status:       'disconnected',
  unreadCount:  0,
  dismissAlert: () => {},
  dismissAll:   () => {},
  markAllRead:  () => {},
});

export const useWeb3Alerts = () => useContext(AlertContext);

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const WS_URL         = process.env.NEXT_PUBLIC_WEB3_WS_URL || 'ws://localhost:3001/web3-ws';
const MAX_ALERTS     = 50;
const RECONNECT_BASE = 2_000;   // 2s initial, exponential backoff
const RECONNECT_MAX  = 30_000;  // 30s max
const TOAST_TIMEOUT  = 8_000;   // Auto-dismiss non-critical alerts after 8s

// ─── PROVIDER ─────────────────────────────────────────────────────────────────
export function Web3AlertProvider({ children }: { children: React.ReactNode }) {
  const [alerts,      setAlerts]      = useState<Web3Alert[]>([]);
  const [status,      setStatus]      = useState<ConnectionStatus>('disconnected');
  const [unreadCount, setUnreadCount] = useState(0);

  const wsRef         = useRef<WebSocket | null>(null);
  const reconnectRef  = useRef<ReturnType<typeof setTimeout> | null>(null);
  const attemptsRef   = useRef(0);
  const mountedRef    = useRef(true);

  // ── Connect ──────────────────────────────────────────────────────────────
  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    try {
      setStatus('connecting');
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        attemptsRef.current = 0;
        setStatus('connected');

        // Subscribe to all channels
        ws.send(JSON.stringify({ type: 'SUBSCRIBE', channel: 'all' }));
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const msg = JSON.parse(event.data);
          handleServerMessage(msg);
        } catch {
          // Malformed message — ignore
        }
      };

      ws.onclose = (event) => {
        if (!mountedRef.current) return;
        setStatus('disconnected');

        // Reconnect with exponential backoff (unless intentional close)
        if (event.code !== 1000 && event.code !== 1001) {
          const delay = Math.min(
            RECONNECT_BASE * Math.pow(2, attemptsRef.current),
            RECONNECT_MAX
          );
          attemptsRef.current++;
          console.log(`[WEB3-WS] Reconnecting in ${delay}ms (attempt ${attemptsRef.current})`);
          reconnectRef.current = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => {
        if (!mountedRef.current) return;
        setStatus('error');
      };

    } catch (err) {
      console.warn('[WEB3-WS] Connection failed (contained):', err);
      setStatus('error');
    }
  }, []); // eslint-disable-line

  // ── Message handler ───────────────────────────────────────────────────────
  function handleServerMessage(msg: { type: string; payload: Record<string, unknown> }) {
    switch (msg.type) {
      case 'ALERT': {
        const alert = msg.payload as unknown as Web3Alert;

        setAlerts(prev => {
          const next = [alert, ...prev].slice(0, MAX_ALERTS);
          return next;
        });
        setUnreadCount(n => n + 1);

        // Auto-dismiss non-critical alerts
        if (alert.severity !== 'CRITICAL' && alert.severity !== 'HIGH') {
          setTimeout(() => {
            setAlerts(prev => prev.filter(a => a.id !== alert.id));
          }, TOAST_TIMEOUT);
        }

        // Sound notification for critical
        if (alert.sound && typeof Audio !== 'undefined') {
          try {
            new Audio('/sounds/alert.mp3').play().catch(() => {});
          } catch { /* Browser blocked audio */ }
        }
        break;
      }

      case 'CONNECTED': {
        const { recentAlerts } = msg.payload as { recentAlerts: Web3Alert[] };
        if (Array.isArray(recentAlerts) && recentAlerts.length > 0) {
          setAlerts(recentAlerts.reverse());
        }
        break;
      }

      case 'SERVER_SHUTDOWN': {
        setStatus('disconnected');
        break;
      }
    }
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      wsRef.current?.close(1000, 'Component unmounted');
    };
  }, [connect]);

  // ── Actions ───────────────────────────────────────────────────────────────
  const dismissAlert = useCallback((id: string) => {
    setAlerts(prev => prev.filter(a => a.id !== id));
  }, []);

  const dismissAll = useCallback(() => {
    setAlerts([]);
    setUnreadCount(0);
  }, []);

  const markAllRead = useCallback(() => {
    setUnreadCount(0);
  }, []);

  return (
    <AlertContext.Provider value={{ alerts, status, unreadCount, dismissAlert, dismissAll, markAllRead }}>
      {children}
    </AlertContext.Provider>
  );
}

// ─── ALERT TOAST PANEL ───────────────────────────────────────────────────────
export function Web3AlertPanel() {
  const { alerts, status, unreadCount, dismissAlert, dismissAll, markAllRead } = useWeb3Alerts();
  const [expanded, setExpanded] = useState(false);

  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL');
  const hasCritical    = criticalAlerts.length > 0;

  return (
    <div className="web3-alert-panel">
      {/* Toggle button */}
      <button
        className={`web3-alert-toggle ${hasCritical ? 'web3-alert-toggle--critical' : ''}`}
        onClick={() => { setExpanded(e => !e); markAllRead(); }}
        aria-label="Web3 Alerts"
      >
        <span className="web3-alert-toggle__icon">🔔</span>
        {unreadCount > 0 && (
          <span className={`web3-alert-toggle__badge ${hasCritical ? 'web3-alert-toggle__badge--critical' : ''}`}>
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
        <ConnectionDot status={status} />
      </button>

      {/* Alert drawer */}
      {expanded && (
        <div className="web3-alert-drawer">
          <div className="web3-alert-drawer__header">
            <span className="web3-alert-drawer__title">
              🛡 Web3 Alerts
              <ConnectionDot status={status} showLabel />
            </span>
            {alerts.length > 0 && (
              <button
                className="web3-btn web3-btn--ghost web3-btn--xs"
                onClick={dismissAll}
              >
                Clear all
              </button>
            )}
          </div>

          <div className="web3-alert-list">
            {alerts.length === 0 && (
              <div className="web3-alert-empty">
                ✅ No active alerts
              </div>
            )}
            {alerts.map(alert => (
              <AlertToast
                key={alert.id}
                alert={alert}
                onDismiss={() => dismissAlert(alert.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── ALERT TOAST ─────────────────────────────────────────────────────────────
function AlertToast({ alert, onDismiss }: { alert: Web3Alert; onDismiss: () => void }) {
  const timeAgo = formatTimeAgo(alert.timestamp);

  return (
    <div
      className={`web3-alert-toast web3-alert-toast--${alert.severity.toLowerCase()}`}
      style={{ '--alert-color': alert.color } as React.CSSProperties}
    >
      <div className="web3-alert-toast__header">
        <div className="web3-alert-toast__meta">
          <span className="web3-alert-toast__severity" style={{ color: alert.color }}>
            {alert.severity}
          </span>
          <span className="web3-alert-toast__channel">{alert.channel}</span>
          <span className="web3-alert-toast__time">{timeAgo}</span>
        </div>
        <button
          className="web3-alert-toast__close"
          onClick={onDismiss}
          aria-label="Dismiss"
        >✕</button>
      </div>
      <div className="web3-alert-toast__title">{alert.title}</div>
      <div className="web3-alert-toast__message">{alert.message}</div>
      {alert.data && Object.keys(alert.data).length > 0 && (
        <div className="web3-alert-toast__data">
          {Object.entries(alert.data).map(([k, v]) => (
            <span key={k} className="web3-alert-toast__datum">
              <span className="web3-alert-toast__datum-key">{k}:</span>
              <span>{String(v)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── CONNECTION DOT ───────────────────────────────────────────────────────────
function ConnectionDot({
  status,
  showLabel = false,
}: {
  status: ConnectionStatus;
  showLabel?: boolean;
}) {
  const meta: Record<ConnectionStatus, { color: string; label: string }> = {
    connected:    { color: '#00ff88', label: 'Live' },
    connecting:   { color: '#ffaa00', label: 'Connecting' },
    disconnected: { color: '#666',    label: 'Offline' },
    error:        { color: '#ff0044', label: 'Error' },
  };

  const { color, label } = meta[status];

  return (
    <span className="web3-conn-dot" title={label}>
      <span
        className={`web3-conn-dot__circle ${status === 'connected' ? 'web3-conn-dot--pulse' : ''}`}
        style={{ background: color, boxShadow: status === 'connected' ? `0 0 6px ${color}` : 'none' }}
      />
      {showLabel && <span className="web3-conn-dot__label" style={{ color }}>{label}</span>}
    </span>
  );
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function formatTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60)  return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60)  return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

// ─── ALERT PANEL CSS (append to web3.css) ─────────────────────────────────────
// Add these styles to /web3/styles/web3.css

/*
.web3-alert-panel {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 12px;
}

.web3-alert-toggle {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: #0d1117;
  border: 1px solid #1e2433;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  position: relative;
  transition: var(--web3-transition);
  box-shadow: 0 4px 16px #00000060;
}

.web3-alert-toggle:hover { border-color: var(--web3-accent); }

.web3-alert-toggle--critical {
  border-color: #ff0044;
  box-shadow: 0 0 0 2px #ff004433;
  animation: web3-blink 0.8s ease-in-out infinite;
}

.web3-alert-toggle__badge {
  position: absolute;
  top: -4px;
  right: -4px;
  background: var(--web3-accent);
  color: #000;
  font-size: 9px;
  font-weight: 700;
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 4px;
  font-family: var(--web3-font-mono);
}

.web3-alert-toggle__badge--critical { background: #ff0044; color: #fff; }

.web3-alert-drawer {
  width: 360px;
  max-height: 480px;
  background: #0d1117;
  border: 1px solid #1e2433;
  border-radius: 12px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 16px 48px #00000080;
  animation: web3-fadeIn 200ms ease;
}

.web3-alert-drawer__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 16px;
  border-bottom: 1px solid #1e2433;
}

.web3-alert-drawer__title {
  font-size: 14px;
  font-weight: 700;
  color: #f0f6fc;
  display: flex;
  align-items: center;
  gap: 10px;
}

.web3-alert-list {
  overflow-y: auto;
  max-height: 400px;
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.web3-alert-empty {
  padding: 32px;
  text-align: center;
  color: #8b949e;
  font-size: 13px;
}

.web3-alert-toast {
  padding: 12px 14px;
  border-left: 3px solid var(--alert-color);
  background: #111827;
  display: flex;
  flex-direction: column;
  gap: 4px;
  animation: web3-fadeIn 200ms ease;
}

.web3-alert-toast__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.web3-alert-toast__meta {
  display: flex;
  gap: 6px;
  font-size: 10px;
  align-items: center;
}

.web3-alert-toast__severity { font-weight: 700; font-family: monospace; }
.web3-alert-toast__channel  { color: #8b949e; text-transform: uppercase; }
.web3-alert-toast__time     { color: #666; }

.web3-alert-toast__close {
  background: transparent;
  border: none;
  color: #666;
  cursor: pointer;
  font-size: 11px;
  padding: 2px 6px;
  transition: color 150ms;
}
.web3-alert-toast__close:hover { color: #ff0044; }

.web3-alert-toast__title {
  font-size: 13px;
  font-weight: 700;
  color: #f0f6fc;
}

.web3-alert-toast__message {
  font-size: 12px;
  color: #8b949e;
  line-height: 1.5;
}

.web3-alert-toast__data {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 4px;
}

.web3-alert-toast__datum {
  font-family: monospace;
  font-size: 10px;
  background: #1a1f2e;
  padding: 2px 8px;
  border-radius: 4px;
  color: var(--alert-color);
  display: flex;
  gap: 4px;
}

.web3-alert-toast__datum-key { color: #8b949e; }

.web3-conn-dot {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.web3-conn-dot__circle {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}

.web3-conn-dot--pulse { animation: web3-blink 1.5s ease-in-out infinite; }
.web3-conn-dot__label { font-size: 11px; font-weight: 600; }
*/
