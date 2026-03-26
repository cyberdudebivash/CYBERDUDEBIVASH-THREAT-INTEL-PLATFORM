/**
 * WEB3 REAL-TIME ALERT SYSTEM — WebSocket Server
 * =================================================
 * Place at: /web3-api/websocket/alertServer.js
 *
 * ISOLATION: Runs on a separate WebSocket server (same process, different upgrade path).
 * ZERO impact on existing system — no shared connections, no shared state.
 *
 * Client connects to: ws://localhost:3001/web3-ws
 * Authentication:     ?token=<jwt>  (validated server-side)
 *
 * Message protocol:
 *   Server → Client: { type: 'ALERT' | 'PING' | 'STATS_UPDATE', payload: {...} }
 *   Client → Server: { type: 'SUBSCRIBE' | 'UNSUBSCRIBE', channel: string }
 */

'use strict';

const { WebSocketServer, WebSocket } = require('ws');

// ─── ALERT TYPES ──────────────────────────────────────────────────────────────
const ALERT_SEVERITY = {
  CRITICAL: { level: 4, color: '#ff0044', sound: true  },
  HIGH:     { level: 3, color: '#ff6600', sound: true  },
  MEDIUM:   { level: 2, color: '#ffaa00', sound: false },
  LOW:      { level: 1, color: '#00ff88', sound: false },
};

// ─── CHANNEL SUBSCRIPTIONS ────────────────────────────────────────────────────
const VALID_CHANNELS = new Set([
  'wallets',      // High-risk wallet activity
  'contracts',    // Malicious contract deployments
  'threats',      // New threat feed entries
  'transactions', // Suspicious transactions
  'all',          // Subscribe to everything
]);

// ─── CLIENT STATE ─────────────────────────────────────────────────────────────
class Web3AlertClient {
  constructor(ws, id) {
    this.ws           = ws;
    this.id           = id;
    this.subscriptions = new Set(['all']);  // Default: all channels
    this.connectedAt  = Date.now();
    this.lastPing     = Date.now();
    this.isAlive      = true;
  }

  send(message) {
    if (this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify(message));
        return true;
      } catch (err) {
        console.warn(`[WEB3-WS] Failed to send to client ${this.id}: ${err.message}`);
        return false;
      }
    }
    return false;
  }

  isSubscribedTo(channel) {
    return this.subscriptions.has('all') || this.subscriptions.has(channel);
  }
}

// ─── ALERT SERVER ─────────────────────────────────────────────────────────────
class Web3AlertServer {
  constructor() {
    this.wss     = null;
    this.clients = new Map();   // id → Web3AlertClient
    this.nextId  = 1;

    // Internal alert queue
    this.alertHistory = [];
    this.maxHistory   = 100;
  }

  /**
   * Attach to an existing HTTP server (no new port needed).
   * The WebSocket upgrade is intercepted at /web3-ws path only.
   *
   * @param {import('http').Server} httpServer
   */
  attach(httpServer) {
    this.wss = new WebSocketServer({
      server:   httpServer,
      path:     '/web3-ws',
      maxPayload: 16 * 1024,   // 16KB max message — prevents abuse
    });

    this.wss.on('connection', (ws, req) => this._handleConnection(ws, req));
    this.wss.on('error', (err) => {
      console.error('[WEB3-WS] Server error (contained):', err.message);
    });

    // Heartbeat — detect dead connections every 30s
    this._startHeartbeat();

    // Demo: simulate alerts in development
    if (process.env.NODE_ENV !== 'production' && process.env.WEB3_USE_MOCK === 'true') {
      this._startMockAlertSimulator();
    }

    console.log('[WEB3-WS] Alert server attached at ws://...:/web3-ws');
    return this;
  }

  // ─── CONNECTION HANDLER ─────────────────────────────────────────────────────
  _handleConnection(ws, req) {
    const clientId = this.nextId++;
    const client   = new Web3AlertClient(ws, clientId);

    this.clients.set(clientId, client);
    console.log(`[WEB3-WS] Client #${clientId} connected (total: ${this.clients.size})`);

    // Send welcome + recent alert history
    client.send({
      type:    'CONNECTED',
      payload: {
        clientId,
        channels:      [...VALID_CHANNELS],
        recentAlerts:  this.alertHistory.slice(-10),
        serverTime:    new Date().toISOString(),
      },
    });

    // Message handler
    ws.on('message', (raw) => this._handleMessage(client, raw));

    // Pong handler (heartbeat response)
    ws.on('pong', () => {
      client.isAlive = true;
      client.lastPing = Date.now();
    });

    // Disconnect handler
    ws.on('close', (code, reason) => {
      this.clients.delete(clientId);
      console.log(`[WEB3-WS] Client #${clientId} disconnected (code: ${code})`);
    });

    ws.on('error', (err) => {
      console.warn(`[WEB3-WS] Client #${clientId} error: ${err.message}`);
      this.clients.delete(clientId);
    });
  }

  // ─── MESSAGE HANDLER ────────────────────────────────────────────────────────
  _handleMessage(client, rawData) {
    let msg;
    try {
      msg = JSON.parse(rawData.toString());
    } catch {
      client.send({ type: 'ERROR', payload: { error: 'Invalid JSON' } });
      return;
    }

    switch (msg.type) {
      case 'SUBSCRIBE': {
        const ch = String(msg.channel || '').toLowerCase().trim();
        if (!VALID_CHANNELS.has(ch)) {
          client.send({ type: 'ERROR', payload: { error: `Unknown channel: ${ch}` } });
          return;
        }
        if (ch !== 'all') client.subscriptions.delete('all');
        client.subscriptions.add(ch);
        client.send({ type: 'SUBSCRIBED', payload: { channel: ch, active: [...client.subscriptions] } });
        break;
      }

      case 'UNSUBSCRIBE': {
        const ch = String(msg.channel || '').toLowerCase().trim();
        client.subscriptions.delete(ch);
        if (client.subscriptions.size === 0) client.subscriptions.add('all');
        client.send({ type: 'UNSUBSCRIBED', payload: { channel: ch, active: [...client.subscriptions] } });
        break;
      }

      case 'PING': {
        client.send({ type: 'PONG', payload: { ts: Date.now() } });
        break;
      }

      default: {
        client.send({ type: 'ERROR', payload: { error: `Unknown message type: ${msg.type}` } });
      }
    }
  }

  // ─── BROADCAST ALERT ────────────────────────────────────────────────────────
  /**
   * Broadcast a security alert to all subscribed clients.
   * Call this from your routes when a new threat is detected.
   *
   * @param {{
   *   channel: 'wallets'|'contracts'|'threats'|'transactions';
   *   severity: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW';
   *   title: string;
   *   message: string;
   *   data?: object;
   * }} alert
   */
  broadcastAlert(alert) {
    const severityMeta = ALERT_SEVERITY[alert.severity] || ALERT_SEVERITY.LOW;

    const message = {
      type:      'ALERT',
      payload: {
        id:        `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        channel:   alert.channel,
        severity:  alert.severity,
        title:     alert.title,
        message:   alert.message,
        data:      alert.data || {},
        color:     severityMeta.color,
        sound:     severityMeta.sound,
        timestamp: new Date().toISOString(),
      },
    };

    // Store in history
    this.alertHistory.push(message.payload);
    if (this.alertHistory.length > this.maxHistory) {
      this.alertHistory.shift();
    }

    // Broadcast to subscribed clients
    let sent = 0;
    for (const client of this.clients.values()) {
      if (client.isSubscribedTo(alert.channel)) {
        if (client.send(message)) sent++;
      }
    }

    console.log(`[WEB3-WS] Alert broadcast "${alert.title}" → ${sent}/${this.clients.size} clients`);
    return sent;
  }

  // ─── STATS BROADCAST ────────────────────────────────────────────────────────
  broadcastStatsUpdate(stats) {
    const message = {
      type:    'STATS_UPDATE',
      payload: { ...stats, timestamp: new Date().toISOString() },
    };
    for (const client of this.clients.values()) {
      client.send(message);
    }
  }

  // ─── HEARTBEAT ──────────────────────────────────────────────────────────────
  _startHeartbeat() {
    const interval = setInterval(() => {
      for (const [id, client] of this.clients.entries()) {
        if (!client.isAlive) {
          // Dead connection — terminate
          client.ws.terminate();
          this.clients.delete(id);
          console.log(`[WEB3-WS] Terminated dead client #${id}`);
          continue;
        }
        client.isAlive = false;  // Will be set to true on pong
        try {
          client.ws.ping();
        } catch {
          this.clients.delete(id);
        }
      }
    }, 30_000);

    // Don't let heartbeat keep Node process alive after server closes
    interval.unref?.();
  }

  // ─── MOCK ALERT SIMULATOR (development only) ──────────────────────────────
  _startMockAlertSimulator() {
    const MOCK_ALERTS = [
      {
        channel:  'transactions',
        severity: 'CRITICAL',
        title:    'Large Transfer Detected',
        message:  'Wallet 0xdead...beef transferred 500 ETH to known mixer',
        data:     { amount: '500 ETH', riskScore: 95 },
      },
      {
        channel:  'wallets',
        severity: 'HIGH',
        title:    'Sanctioned Wallet Active',
        message:  'OFAC-sanctioned address initiated contract interaction',
        data:     { address: '0xbad...cafe', country: 'Unknown' },
      },
      {
        channel:  'contracts',
        severity: 'CRITICAL',
        title:    'Honeypot Contract Deployed',
        message:  'New contract detected with honeypot signature patterns',
        data:     { address: '0x1337...feed', riskScore: 98 },
      },
      {
        channel:  'threats',
        severity: 'HIGH',
        title:    'Flash Loan Attack Detected',
        message:  'Price oracle manipulation via flash loan on DEX',
        data:     { protocol: 'UniswapV3', lossUSD: 2_400_000 },
      },
      {
        channel:  'threats',
        severity: 'MEDIUM',
        title:    'Phishing Site Identified',
        message:  'New phishing domain mimicking major protocol',
        data:     { domain: 'uniswap-v3-app[.]com' },
      },
    ];

    let idx = 0;
    const interval = setInterval(() => {
      if (this.clients.size > 0) {
        this.broadcastAlert(MOCK_ALERTS[idx % MOCK_ALERTS.length]);
        idx++;
      }
    }, 15_000);   // New mock alert every 15s

    interval.unref?.();
    console.log('[WEB3-WS] Mock alert simulator active (dev mode)');
  }

  // ─── GRACEFUL SHUTDOWN ──────────────────────────────────────────────────────
  close() {
    for (const client of this.clients.values()) {
      client.send({ type: 'SERVER_SHUTDOWN', payload: { message: 'Web3 alert server shutting down' } });
      client.ws.close(1001, 'Server shutdown');
    }
    this.clients.clear();
    this.wss?.close();
    console.log('[WEB3-WS] Alert server closed');
  }
}

// ─── SINGLETON ────────────────────────────────────────────────────────────────
const alertServer = new Web3AlertServer();
module.exports = { alertServer, Web3AlertServer };
