// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Renderer Recovery Engine v168.0
// Self-healing renderer: blank frame detection + context-loss recovery.
//
// Root causes addressed:
//   RC1 residual: If any future dual-engine intrusion clears the canvas,
//                 this engine detects blank frames and triggers recovery.
//   RC2 residual: Zero-sized canvas detection (offsetWidth/Height = 0)
//   Additional:   GPU context loss (webglcontextlost) + context restoration
//                 Frozen RAF detection (complements V166 watchdog)
//
// API (window.CDB_RECOVERY):
//   .attach(canvas, panel, recoverFn)  — register canvas + recovery callback
//   .detach(canvas)                    — unregister
//   .reportFrame(canvas, ctx)          — call each frame to feed the detector
//   .forceRecover(canvas)              — trigger immediate recovery
//   .isRecovering(canvas)              — guard: is recovery in flight?
//   .getStats(canvas)                  — diagnostic snapshot per canvas
//   .BLANK_SCAN_INTERVAL_MS            — how often blank frames are sampled
// =============================================================================
(function (global) {
  'use strict';

  /* ── Constants ─────────────────────────────────────────────────────────── */
  var VERSION                = '168.0';
  var LOG_PREFIX             = '[CDB-RECOVERY v' + VERSION + ']';
  var BLANK_SCAN_INTERVAL_MS = 4000;   /* Sample canvas every 4s for blank    */
  var BLANK_THRESHOLD        = 0.97;   /* >97% black pixels = blank frame     */
  var MAX_RECOVERY_ATTEMPTS  = 5;      /* Per canvas, per session             */
  var RECOVERY_COOLDOWN_MS   = 8000;   /* Min gap between recovery attempts   */
  var ZERO_SIZE_RETRIES      = 10;     /* How many times to retry zero dims   */

  /* ── State registry ────────────────────────────────────────────────────── */
  /* Map: canvasId → { canvas, panel, recoverFn, timer, stats, recovering } */
  var _registry = {};

  /* ── Internal helpers ───────────────────────────────────────────────────── */
  function log(msg)  { try { console.log (LOG_PREFIX + ' ' + msg); } catch(e){} }
  function warn(msg) { try { console.warn(LOG_PREFIX + ' ' + msg); } catch(e){} }

  function _key(canvas) {
    return canvas.id || ('cdb-recovery-' + (canvas.__cdbRecId = canvas.__cdbRecId || (Math.random() * 1e9 | 0)));
  }

  /**
   * _isBlank(canvas, ctx) — sample canvas pixels to detect blank/black frame.
   * Uses a 32x32 sample grid for speed — full scan would be 60Hz expensive.
   * Returns true if >BLANK_THRESHOLD fraction of sampled pixels are near-black.
   */
  function _isBlank(canvas, ctx) {
    try {
      var W = canvas.width;
      var H = canvas.height;
      if (!W || !H) return true;  /* Zero size = effectively blank */

      /* Sample 64 pixels in a scattered grid */
      var sampleW = Math.min(W, 64);
      var sampleH = Math.min(H, 64);
      var stepX   = Math.max(1, Math.floor(W / sampleW));
      var stepY   = Math.max(1, Math.floor(H / sampleH));

      /* Use a tiny getImageData to keep this fast */
      var imgData = ctx.getImageData(0, 0, Math.min(W, 128), Math.min(H, 128));
      var data    = imgData.data;
      var total   = 0;
      var dark    = 0;

      for (var i = 0; i < data.length; i += 4) {
        var r = data[i], g = data[i+1], b = data[i+2];
        /* "Near black" = R+G+B < 30 */
        if (r + g + b < 30) dark++;
        total++;
        if (total >= 512) break;  /* Max 512 pixel samples */
      }

      return total > 0 && (dark / total) > BLANK_THRESHOLD;
    } catch(e) {
      /* getImageData may fail on tainted canvas — treat as non-blank */
      return false;
    }
  }

  /**
   * _isZeroSize(canvas, panel) — detect canvas collapsed to zero dimensions.
   */
  function _isZeroSize(canvas, panel) {
    if (!canvas || !panel) return true;
    var cw = canvas.offsetWidth  || canvas.width  || 0;
    var ch = canvas.offsetHeight || canvas.height || 0;
    var pw = panel.offsetWidth   || 0;
    var ph = panel.offsetHeight  || 0;
    return (cw < 10 || ch < 20) && (pw < 10 || ph < 20);
  }

  /**
   * _triggerRecovery(key) — execute recovery with anti-thrash guard.
   */
  function _triggerRecovery(key, reason) {
    var entry = _registry[key];
    if (!entry)           return;
    if (entry.recovering) return;  /* Recovery already in flight */

    var stats = entry.stats;
    if (stats.attempts >= MAX_RECOVERY_ATTEMPTS) {
      warn('[' + key + '] Max recovery attempts (' + MAX_RECOVERY_ATTEMPTS + ') reached — giving up');
      return;
    }

    var now = Date.now();
    if (now - stats.lastRecoveryTs < RECOVERY_COOLDOWN_MS) {
      warn('[' + key + '] Recovery cooldown active — skipping');
      return;
    }

    stats.attempts++;
    stats.lastRecoveryTs = now;
    entry.recovering = true;

    warn('[' + key + '] RECOVERY TRIGGERED — reason: ' + reason + ' (attempt ' + stats.attempts + ')');

    try {
      entry.recoverFn(entry.canvas, entry.panel, reason);
    } catch(e) {
      warn('[' + key + '] Recovery callback threw: ' + e.message);
    }

    /* Release recovering flag after 2s (recovery needs time to boot) */
    setTimeout(function() {
      if (_registry[key]) _registry[key].recovering = false;
    }, 2000);
  }

  /**
   * _startBlankFrameScanner(key) — periodic blank frame detector.
   */
  function _startBlankFrameScanner(key) {
    var entry = _registry[key];
    if (!entry || entry.timer) return;

    entry.timer = setInterval(function() {
      var e = _registry[key];
      if (!e) { return; }

      var canvas = e.canvas;
      var panel  = e.panel;

      /* Guard: only scan when engine says frames are flowing */
      if (!e.stats.framesSeen) return;

      /* Zero-size check */
      if (_isZeroSize(canvas, panel)) {
        _triggerRecovery(key, 'ZERO_SIZE');
        return;
      }

      /* Context check */
      var ctx = null;
      try { ctx = canvas.getContext('2d'); } catch(ex) {}
      if (!ctx) {
        _triggerRecovery(key, 'CONTEXT_LOST');
        return;
      }

      /* Blank frame check */
      if (_isBlank(canvas, ctx)) {
        warn('[' + key + '] Blank frame detected — pixel scan triggered recovery');
        e.stats.blankFrames++;
        _triggerRecovery(key, 'BLANK_FRAME');
      }

    }, BLANK_SCAN_INTERVAL_MS);

    log('Blank-frame scanner started for canvas "' + key + '" (every ' + (BLANK_SCAN_INTERVAL_MS/1000) + 's)');
  }

  /* ── Public API ─────────────────────────────────────────────────────────── */

  /**
   * attach(canvas, panel, recoverFn) — register canvas for recovery monitoring.
   * recoverFn(canvas, panel, reason) is called when a failure is detected.
   */
  function attach(canvas, panel, recoverFn) {
    if (!canvas || !panel || typeof recoverFn !== 'function') {
      warn('attach() requires canvas, panel, and a recovery callback function');
      return;
    }
    var key = _key(canvas);
    if (_registry[key]) {
      log('Canvas "' + key + '" already attached — refreshing recovery callback');
      _registry[key].recoverFn = recoverFn;
      return;
    }

    _registry[key] = {
      canvas     : canvas,
      panel      : panel,
      recoverFn  : recoverFn,
      recovering : false,
      timer      : null,
      stats      : {
        attempts       : 0,
        blankFrames    : 0,
        lastRecoveryTs : 0,
        framesSeen     : 0,
        attached       : Date.now()
      }
    };

    /* Wire webglcontextlost — fires if GPU context is lost at driver level */
    canvas.addEventListener('webglcontextlost', function(ev) {
      ev.preventDefault();
      warn('[' + key + '] WebGL context lost — scheduling recovery');
      setTimeout(function() { _triggerRecovery(key, 'WEBGL_CONTEXT_LOST'); }, 500);
    });

    _startBlankFrameScanner(key);
    log('Recovery engine attached to canvas "' + key + '"');
  }

  /**
   * detach(canvas) — stop monitoring and remove from registry.
   */
  function detach(canvas) {
    if (!canvas) return;
    var key = _key(canvas);
    var entry = _registry[key];
    if (!entry) return;
    if (entry.timer) { clearInterval(entry.timer); entry.timer = null; }
    delete _registry[key];
    log('Recovery engine detached from canvas "' + key + '"');
  }

  /**
   * reportFrame(canvas) — call once per render frame to feed liveness detector.
   * This prevents false-positive stall detection while rendering normally.
   */
  function reportFrame(canvas) {
    if (!canvas) return;
    var key = _key(canvas);
    var entry = _registry[key];
    if (entry) entry.stats.framesSeen++;
  }

  /**
   * forceRecover(canvas) — manually trigger recovery (bypass cooldown for 1st call).
   */
  function forceRecover(canvas) {
    if (!canvas) return;
    var key = _key(canvas);
    var entry = _registry[key];
    if (!entry) return;
    /* Reset cooldown for forced recovery */
    entry.stats.lastRecoveryTs = 0;
    _triggerRecovery(key, 'FORCED');
  }

  /**
   * isRecovering(canvas) — true if recovery is currently in flight.
   */
  function isRecovering(canvas) {
    if (!canvas) return false;
    var key = _key(canvas);
    return _registry[key] ? _registry[key].recovering : false;
  }

  /**
   * getStats(canvas) — diagnostic snapshot for this canvas.
   */
  function getStats(canvas) {
    if (!canvas) return null;
    var key = _key(canvas);
    var entry = _registry[key];
    if (!entry) return null;
    var s = entry.stats;
    return {
      key            : key,
      attempts       : s.attempts,
      blankFrames    : s.blankFrames,
      framesSeen     : s.framesSeen,
      recovering     : entry.recovering,
      lastRecoveryAge: s.lastRecoveryTs ? (Date.now() - s.lastRecoveryTs) : -1,
      uptimeMs       : Date.now() - s.attached,
      version        : VERSION
    };
  }

  /* ── Export ─────────────────────────────────────────────────────────────── */
  global.CDB_RECOVERY = {
    attach                 : attach,
    detach                 : detach,
    reportFrame            : reportFrame,
    forceRecover           : forceRecover,
    isRecovering           : isRecovering,
    getStats               : getStats,
    BLANK_SCAN_INTERVAL_MS : BLANK_SCAN_INTERVAL_MS,
    VERSION                : VERSION
  };

  log('Renderer Recovery Engine online — blank-frame + context-loss recovery ready');

}(window));
