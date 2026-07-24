// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Telemetry Engine v168.0
// Performance telemetry: FPS, render stall detection, error tracking.
//
// Monitors the renderer for anomalies and surfaces diagnostics.
// Used by renderer-recovery-engine.js to make informed recovery decisions.
//
// API (window.CDB_TELEMETRY):
//   .frame(ts)              — call each render frame (timestamp from rAF)
//   .error(code, detail)    — log a renderer error event
//   .stall(reason)          — log a render stall event
//   .getFPS()               — current rolling FPS
//   .getStats()             — full diagnostic snapshot
//   .reset()                — clear all telemetry
//   .onStall(cb)            — register stall callback (fps=0 for N seconds)
//   .STALL_THRESHOLD_MS     — stall detection window (default 3000ms)
// =============================================================================
(function (global) {
  'use strict';

  /* ── Constants ─────────────────────────────────────────────────────────── */
  var VERSION             = '168.0';
  var LOG_PREFIX          = '[CDB-TELEMETRY v' + VERSION + ']';
  var STALL_THRESHOLD_MS  = 3000;   /* 3s without a frame = stall           */
  var FPS_WINDOW          = 60;     /* Rolling average over N frames         */
  var MAX_ERRORS          = 50;     /* Error log ring buffer size            */

  /* ── State ──────────────────────────────────────────────────────────────── */
  var _frameTimes   = [];       /* Rolling window of frame timestamps        */
  var _lastFrameTs  = 0;        /* Timestamp of last rendered frame          */
  var _totalFrames  = 0;        /* Lifetime frame count                      */
  var _errors       = [];       /* Ring buffer of error events               */
  var _stalls       = [];       /* Stall event log                           */
  var _stallCbs     = [];       /* Registered stall callbacks                */
  var _stallTimer   = null;     /* Stall detection interval                  */
  var _startTime    = Date.now();

  /* ── Internal helpers ───────────────────────────────────────────────────── */
  function log(msg)  { try { console.log (LOG_PREFIX + ' ' + msg); } catch(e){} }
  function warn(msg) { try { console.warn(LOG_PREFIX + ' ' + msg); } catch(e){} }

  function _startStallMonitor() {
    if (_stallTimer) return;
    _stallTimer = setInterval(function() {
      if (_lastFrameTs === 0) return;  /* Not started yet */
      var elapsed = Date.now() - _lastFrameTs;
      if (elapsed > STALL_THRESHOLD_MS) {
        var fps = getFPS();
        warn('STALL DETECTED — ' + elapsed + 'ms since last frame, FPS=' + fps);
        var ev = { ts: Date.now(), elapsed: elapsed, fps: fps };
        _stalls.push(ev);
        for (var i = 0; i < _stallCbs.length; i++) {
          try { _stallCbs[i](ev); } catch(e){}
        }
      }
    }, STALL_THRESHOLD_MS);
  }

  /* ── Public API ─────────────────────────────────────────────────────────── */

  /**
   * frame(ts) — record a rendered frame.
   * Call at the START of each renderFrame() with the rAF timestamp.
   */
  function frame(ts) {
    var now = ts || Date.now();
    _lastFrameTs = now;
    _totalFrames++;

    _frameTimes.push(now);
    if (_frameTimes.length > FPS_WINDOW) {
      _frameTimes.shift();
    }
  }

  /**
   * error(code, detail) — log a renderer error.
   */
  function error(code, detail) {
    var ev = { ts: Date.now(), code: code || 'UNKNOWN', detail: detail || '' };
    _errors.push(ev);
    if (_errors.length > MAX_ERRORS) _errors.shift();
    warn('ERROR [' + ev.code + '] ' + ev.detail);
  }

  /**
   * stall(reason) — manually log a stall event.
   */
  function stall(reason) {
    var ev = { ts: Date.now(), reason: reason || 'manual' };
    _stalls.push(ev);
    warn('STALL logged: ' + (reason || 'manual'));
  }

  /**
   * getFPS() — rolling FPS over the last FPS_WINDOW frames.
   */
  function getFPS() {
    if (_frameTimes.length < 2) return 0;
    var span = _frameTimes[_frameTimes.length - 1] - _frameTimes[0];
    if (span <= 0) return 0;
    return Math.round((_frameTimes.length - 1) / (span / 1000));
  }

  /**
   * getStats() — full diagnostic snapshot.
   */
  function getStats() {
    var uptime = Date.now() - _startTime;
    return {
      fps         : getFPS(),
      totalFrames : _totalFrames,
      lastFrameAge: _lastFrameTs ? (Date.now() - _lastFrameTs) : -1,
      errors      : _errors.slice(),
      stalls      : _stalls.slice(),
      uptimeMs    : uptime,
      version     : VERSION
    };
  }

  /**
   * reset() — clear all telemetry state.
   */
  function reset() {
    _frameTimes  = [];
    _lastFrameTs = 0;
    _totalFrames = 0;
    _errors      = [];
    _stalls      = [];
    _startTime   = Date.now();
    log('Telemetry reset');
  }

  /**
   * onStall(callback) — register a callback for stall events.
   * Callback receives: { ts, elapsed, fps }
   */
  function onStall(cb) {
    if (typeof cb !== 'function') return;
    _stallCbs.push(cb);
    _startStallMonitor();
  }

  /* ── Export ─────────────────────────────────────────────────────────────── */
  global.CDB_TELEMETRY = {
    frame              : frame,
    error              : error,
    stall              : stall,
    getFPS             : getFPS,
    getStats           : getStats,
    reset              : reset,
    onStall            : onStall,
    STALL_THRESHOLD_MS : STALL_THRESHOLD_MS,
    VERSION            : VERSION
  };

  log('Telemetry Engine online — FPS + stall monitoring ready');

}(window));
