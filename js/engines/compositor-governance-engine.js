// =============================================================================
// CYBERDUDEBIVASH(r) SENTINEL APEX -- Compositor Governance Engine v172.0
// GPU layer management -- eliminates Chrome pre-paint empty compositor trap.
//
// Root causes addressed:
//   RC3:  will-change:transform before paint -> Chrome pre-allocates empty GPU
//         layer -> compositor captures blank frame -> canvas stays blank.
//   RC7:  backface-visibility:hidden (no !important) in init()/safeMode() ->
//         Chrome second GPU promotion trigger -> empty compositor layer BEFORE
//         first paint -> blank canvas Chrome Desktop.
//   RC11: promote()+translateZ(0) inside panel -> GPU promotion inside stencil-
//         clip container -> blank compositor texture.
//   RC12: box-shadow/border-radius on canvas -> Chrome D3D11/ANGLE pre-allocates
//         shadow paint layer before canvas has content -> blank GPU texture.
//         promote() IS NOW A NO-OP. GPU promotion permanently disabled.
//         All canvas styling governed exclusively by CSS !important overrides.
//
// API (window.CDB_COMPOSITOR):
//   .init(canvas)        -- Phase 1: set will-change:auto (call at DOM ready)
//   .promote(canvas)     -- Phase 2: promote GPU layer (call AFTER first paint)
//   .demote(canvas)      -- remove GPU layer (pause/hide)
//   .isPromoted(canvas)  -- boolean state check
//   .safeMode(canvas)    -- force will-change:auto + translateZ:none (emergency)
//   .DPR_CAP             -- max devicePixelRatio allowed (2)
//   .getDPR()            -- capped DPR value
// =============================================================================
(function (global) {
  'use strict';

  var VERSION    = '172.0';
  var LOG_PREFIX = '[CDB-COMPOSITOR v' + VERSION + ']';
  var DPR_CAP    = 2;

  var _promoted = (typeof WeakMap !== 'undefined') ? new WeakMap() : null;
  var _promotedSet = [];

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

  // init(canvas) -- Phase 1: set will-change:auto + block backface promotion.
  // RC7 FIX: backface-visibility:hidden (even without !important) is a Chrome
  // GPU compositor layer promotion trigger. Setting it in init() caused Chrome
  // to pre-allocate an EMPTY GPU layer BEFORE first paint -- blank canvas.
  // Edge does not promote on backface-visibility alone when will-change:auto
  // is set. Chrome always promotes. Fix: force 'visible' !important.
  function init(canvas) {
    if (!canvas) { warn('init() called with null canvas'); return; }
    canvas.style.setProperty('will-change',                'auto',    'important');
    canvas.style.setProperty('transform',                  'none',    'important');
    canvas.style.setProperty('backface-visibility',        'visible', 'important');
    canvas.style.setProperty('-webkit-backface-visibility','visible', 'important');
    _setPromoted(canvas, false);
    log('Canvas initialized -- RC7 GPU trap blocked (backface-visibility:visible, will-change:auto)');
  }

  // promote(canvas) -- RC11/RC12 PERMANENT NO-OP.
  // translateZ(0) and will-change:transform are PERMANENTLY DISABLED.
  // Forensic root cause: both properties trigger Chrome D3D11/ANGLE compositor
  // layer pre-allocation BEFORE canvas has content, resulting in a blank GPU
  // texture that persists until page reload. Edge composites post-paint
  // (no issue); Chrome pre-allocates (blank canvas).
  // GPU layer governance is handled entirely by CSS !important overrides in
  // the V172 renderer block. JS must never override CSS compositor hints.
  function promote(canvas) {
    // NO-OP: GPU promotion permanently disabled (RC11+RC12 forensic fix)
    warn('promote() called but is a permanent NO-OP (RC11/RC12) — GPU promotion disabled');
    // Do NOT set translateZ(0) or will-change:transform — ever.
  }

  // demote(canvas) -- remove GPU compositor layer (use when hidden/paused).
  function demote(canvas) {
    if (!canvas) return;
    canvas.style.setProperty('will-change', 'auto', 'important');
    canvas.style.setProperty('transform',   'none', 'important');
    _setPromoted(canvas, false);
    log('Canvas GPU layer demoted (off-screen memory freed)');
  }

  // isPromoted(canvas) -- check if canvas has been GPU-promoted.
  function isPromoted(canvas) {
    if (!canvas) return false;
    return _getPromoted(canvas);
  }

  // safeMode(canvas) -- emergency: force will-change:auto, clear transforms.
  // RC7 FIX: Do NOT set backface-visibility:hidden here -- it re-triggers
  // Chrome GPU compositor promotion in safe mode, creating a new empty layer.
  // Must stay compositor-clean during emergency recovery.
  function safeMode(canvas) {
    if (!canvas) { warn('safeMode() called with null canvas'); return; }
    warn('SAFE MODE activated -- clearing GPU promotion (RC7-safe)');
    canvas.style.setProperty('will-change',                'auto',    'important');
    canvas.style.setProperty('transform',                  'none',    'important');
    canvas.style.setProperty('backface-visibility',        'visible', 'important');
    canvas.style.setProperty('-webkit-backface-visibility','visible', 'important');
    _setPromoted(canvas, false);
  }

  // getDPR() -- returns devicePixelRatio capped at DPR_CAP.
  function getDPR() {
    return Math.min(global.devicePixelRatio || 1, DPR_CAP);
  }

  global.CDB_COMPOSITOR = {
    init       : init,
    promote    : promote,
    demote     : demote,
    isPromoted : isPromoted,
    safeMode   : safeMode,
    getDPR     : getDPR,
    DPR_CAP    : DPR_CAP,
    VERSION    : VERSION
  };

  log('Compositor Governance Engine v172 online -- RC7+RC11+RC12 GPU promotion permanently disabled');

}(window));
