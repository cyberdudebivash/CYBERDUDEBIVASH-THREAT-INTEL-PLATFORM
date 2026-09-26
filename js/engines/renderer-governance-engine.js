// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Renderer Governance Engine v168.0
// Single RAF owner registry — eliminates dual-engine runtime collision.
//
// Root cause addressed:
//   RC1: Dual engine RAF ownership → compositor starvation → blank canvas
//   Guarantees exactly ONE requestAnimationFrame chain owns the render loop.
//
// API (window.CDB_RAF):
//   .acquire(ownerId)           — claim the RAF token (returns true/false)
//   .release(ownerId)           — release the token
//   .request(callback, ownerId) — guarded rAF (no-op if caller is not owner)
//   .owner()                    — returns current owner id or null
//   .isOwner(ownerId)           — boolean check
//   .reset()                    — emergency reset (clears all ownership)
// =============================================================================
(function (global) {
  'use strict';

  /* ── Constants ─────────────────────────────────────────────────────────── */
  var VERSION    = '168.0';
  var LOG_PREFIX = '[CDB-RAF-GOV v' + VERSION + ']';

  /* ── State ──────────────────────────────────────────────────────────────── */
  var _owner        = null;   /* Current registered RAF owner id          */
  var _acquireTime  = 0;      /* Epoch ms when ownership was acquired     */
  var _frameCount   = 0;      /* Frames rendered under current owner      */
  var _leaseTimeout = 30000;  /* 30s: stale lease auto-expire (ms)        */
  var _blocked      = 0;      /* Blocked rAF attempts (intruder counter)  */

  /* ── Internal helpers ───────────────────────────────────────────────────── */
  function log(msg)  { try { console.log (LOG_PREFIX + ' ' + msg); } catch(e){} }
  function warn(msg) { try { console.warn(LOG_PREFIX + ' ' + msg); } catch(e){} }

  function _isLeaseExpired() {
    if (!_owner) return false;
    return (Date.now() - _acquireTime) > _leaseTimeout;
  }

  /* ── Public API ─────────────────────────────────────────────────────────── */

  /**
   * acquire(ownerId) — claim exclusive RAF ownership.
   * Returns true if granted, false if another engine already owns the slot.
   * Expired leases are evicted automatically.
   */
  function acquire(ownerId) {
    if (!ownerId) { warn('acquire() called with empty ownerId — rejected'); return false; }

    /* Auto-evict stale lease */
    if (_owner && _isLeaseExpired()) {
      warn('Stale lease expired for "' + _owner + '" (' + _frameCount + ' frames) — evicting');
      _owner = null;
    }

    if (_owner && _owner !== ownerId) {
      warn('Acquire rejected — "' + ownerId + '" tried to claim slot owned by "' + _owner + '"');
      _blocked++;
      return false;
    }

    if (_owner === ownerId) {
      /* Re-entrancy: same owner re-acquires (idempotent) */
      _acquireTime = Date.now();
      return true;
    }

    _owner       = ownerId;
    _acquireTime = Date.now();
    _frameCount  = 0;
    log('RAF ownership acquired by "' + ownerId + '"');
    return true;
  }

  /**
   * release(ownerId) — relinquish RAF ownership.
   */
  function release(ownerId) {
    if (_owner !== ownerId) {
      warn('release() called by non-owner "' + ownerId + '" (owner is "' + _owner + '") — ignored');
      return;
    }
    log('RAF ownership released by "' + ownerId + '" after ' + _frameCount + ' frames');
    _owner = null;
  }

  /**
   * request(callback, ownerId) — governance-guarded requestAnimationFrame.
   * Silently drops the request if ownerId does not hold the RAF token.
   * Falls back to raw rAF if governance is bypassed (graceful degradation).
   */
  function request(callback, ownerId) {
    /* Graceful degradation: if no owner registered, pass through */
    if (!_owner) {
      return global.requestAnimationFrame(callback);
    }

    if (_owner !== ownerId) {
      _blocked++;
      warn('rAF request from non-owner "' + ownerId + '" blocked (owner: "' + _owner + '") — intruder #' + _blocked);
      return -1;  /* Sentinel value: blocked */
    }

    _frameCount++;
    /* Refresh lease on each frame */
    _acquireTime = Date.now();
    return global.requestAnimationFrame(callback);
  }

  /**
   * owner() — returns current owner id or null.
   */
  function owner() { return _owner; }

  /**
   * isOwner(ownerId) — boolean ownership check.
   */
  function isOwner(ownerId) { return _owner === ownerId; }

  /**
   * reset() — emergency reset for recovery scenarios.
   */
  function reset() {
    warn('Emergency reset triggered — clearing ownership (was: "' + _owner + '")');
    _owner       = null;
    _acquireTime = 0;
    _frameCount  = 0;
    _blocked     = 0;
  }

  /**
   * stats() — diagnostic snapshot.
   */
  function stats() {
    return {
      owner      : _owner,
      acquireAge : _owner ? (Date.now() - _acquireTime) : 0,
      frames     : _frameCount,
      blocked    : _blocked,
      version    : VERSION
    };
  }

  /* ── Export ─────────────────────────────────────────────────────────────── */
  global.CDB_RAF = {
    acquire  : acquire,
    release  : release,
    request  : request,
    owner    : owner,
    isOwner  : isOwner,
    reset    : reset,
    stats    : stats,
    VERSION  : VERSION
  };

  log('Renderer Governance Engine online — RAF token registry ready');

}(window));
