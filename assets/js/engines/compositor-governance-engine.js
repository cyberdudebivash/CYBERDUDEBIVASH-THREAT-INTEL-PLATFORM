// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Compositor Governance Engine v168.0
// GPU layer management — eliminates Chrome pre-paint empty compositor trap.
//
// Root causes addressed:
//   RC3: will-change:transform before paint → Chrome pre-allocates empty GPU
//        layer → compositor captures blank frame → canvas stays blank.
//   Fix: Two-phase GPU promotion:
//     Phase 1 (init):    will-change:auto  — no pre-paint layer
//     Phase 2 (promote): will-change:transform AFTER first content is drawn
//
// API (window.CDB_COMPOSITOR):
//   .init(canvas)        — Phase 1: set will-change:auto (call at DOM ready)
//   .promote(canvas)     — Phase 2: promote GPU layer (call AFTER first paint)
//   .demote(canvas)      — remove GPU layer (pause/hide)
//   .isPromoted(canvas)  — boolean state check
//   .safeMode(canvas)    — force will-change:auto + translateZ:none (emergency)
//   .DPR_CAP             — max devicePixelRatio allowed (2)
//   .getDPR()            — capped DPR value
// =============================================================================
(function (global) {
  'use strict';

  /* ── Constants ─────────────────────────────────────────────────────────── */
  var VERSION    = '168.0';
  var LOG_PREFIX = '[CDB-COMPOSITOR v' + VERSION + ']';
  var DPR_CAP    = 2;           /* Hard cap: prevents GPU memory overflow   */

  /* ── State ──────────────────────────────────────────────────────────────── */
  var _promoted = new WeakMap ? new WeakMap() : null;  /* canvas → boolean   */

  /* WeakMap polyfill for older browsers */
  var _promotedSet  = [];   /* [{canvas, promoted}] fallback if no WeakMap  */

  /* ── Internal helpers ───────────────────────────────────────────────────── */
  function log(msg)  { try { console.log (LOG_PREFIX + ' ' + msg); } catch(e){} }
  function warn(msg) { try { console.warn(LOG_PREFIX + ' ' + msg); } catch(e){} }

  function _setPromoted(canvas, val) {
    if (_promoted) {
      _promoted.set(canvas, val);
    } else {
      for (var i = 0; i < _promotedSet.length; i++) {
        if (_promotedSet[i].canvas === canvas) { _promotedSet[i].promoted = val; return; }
      }
      _promotedSet.push({ canvas: canvas, promoted: val });
    }
  }

  function _getPromoted(canvas) {
    if (_promoted) return !!_promoted.get(canvas);
    for (var i = 0; i < _promotedSet.length; i++) {
      if (_promotedSet[i].canvas === canvas) return _promotedSet[i].promoted;
    }
    return false;
  }

  /* ── Public API ─────────────────────────────────────────────────────────── */

  /**
   * init(canvas) — Phase 1: apply will-change:auto.
   * Call immediately when canvas element is available, before any drawing.
   * Prevents Chrome from pre-allocating an empty GPU compositor layer.
   */
  function init(canvas) {
    if (!canvas) { warn('init() called with null canvas'); return; }
    /* CSS stylesheet is already set via RC3 (!important). Reinforce via inline. */
    canvas.style.setProperty('will-change',         'auto',      'important');
    canvas.style.setProperty('transform',           'none',      'important');
    canvas.style.setProperty('backface-visibility', 'hidden',    '');
    _setPromoted(canvas, false);
    log('Canvas initialized — pre-paint GPU trap prevented (will-change:auto)');
  }

  /**
   * promote(canvas) — Phase 2: promote to GPU compositor layer.
   * MUST be called inside requestAnimationFrame, AFTER the first content draw.
   * Chrome will composite the frame with actual content, not blank.
   */
  function promote(canvas) {
    if (!canvas) { warn('promote() called with null canvas'); return; }
    if (_getPromoted(canvas)) return;  /* Idempotent */

    canvas.style.setProperty('transform',   'translateZ(0)', 'important');
    canvas.style.setProperty('will-change', 'transform',     'important');
    _setPromoted(canvas, true);
    log('Canvas promoted to GPU compositor layer (post-paint, translateZ(0))');
  }

  /**
   * demote(canvas) — remove GPU compositor layer (use when hidden/paused).
   * Frees GPU memory when canvas is off-screen.
   */
  function demote(canvas) {
    if (!canvas) return;
    canvas.style.setProperty('will-change', 'auto',  'important');
    canvas.style.setProperty('transform',   'none',  'important');
    _setPromoted(canvas, false);
    log('Canvas GPU layer demoted (off-screen memory freed)');
  }

  /**
   * isPromoted(canvas) — check if canvas has been GPU-promoted.
   */
  function isPromoted(canvas) {
    if (!canvas) return false;
    return _getPromoted(canvas);
  }

  /**
   * safeMode(canvas) — emergency: force will-change:auto, clear transforms.
   * Use when canvas renders blank and normal recovery has failed.
   */
  function safeMode(canvas) {
    if (!canvas) { warn('safeMode() called with null canvas'); return; }
    warn('SAFE MODE activated on canvas — clearing GPU promotion');
    canvas.style.setProperty('will-change',         'auto', 'important');
    canvas.style.setProperty('transform',           'none', 'important');
    canvas.style.setProperty('backface-visibility', 'hidden', '');
    _setPromoted(canvas, false);
  }

  /**
   * getDPR() — returns devicePixelRatio capped at DPR_CAP.
   * Prevents GPU texture memory overflow on high-DPI displays.
   */
  function getDPR() {
    return Math.min(global.devicePixelRatio || 1, DPR_CAP);
  }

  /* ── Export ─────────────────────────────────────────────────────────────── */
  global.CDB_COMPOSITOR = {
    init      : init,
    promote   : promote,
    demote    : demote,
    isPromoted: isPromoted,
    safeMode  : safeMode,
    getDPR    : getDPR,
    DPR_CAP   : DPR_CAP,
    VERSION   : VERSION
  };

  log('Compositor Governance Engine online — GPU layer registry ready');

}(window));
