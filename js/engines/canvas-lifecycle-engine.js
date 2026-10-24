// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Canvas Lifecycle Engine v168.0
// Canvas ownership registry + DPR-governed resize — eliminates context churn.
//
// Root causes addressed:
//   RC1: Multiple engines targeting same canvas → GPU texture invalidation
//   RC2: applySize() called per-frame → 60x/sec GPU texture reset
//   Fix: Single owner registry + dimension cache + context preservation
//
// API (window.CDB_CANVAS):
//   .claim(canvasId, ownerId)          — claim exclusive canvas ownership
//   .release(canvasId, ownerId)        — release ownership
//   .isOwner(canvasId, ownerId)        — boolean ownership check
//   .applySize(canvas, panel, force)   — governed resize (cached, DPR-aware)
//   .getContext(canvas)                — returns cached 2D context
//   .invalidate(canvas)                — force next applySize to reset
//   .getDims(canvas)                   — returns {W, H, dpr, ctx, bufW, bufH}
// =============================================================================
(function (global) {
  'use strict';

  /* ── Constants ─────────────────────────────────────────────────────────── */
  var VERSION    = '168.0';
  var LOG_PREFIX = '[CDB-CANVAS v' + VERSION + ']';
  var DPR_CAP    = (global.CDB_COMPOSITOR && global.CDB_COMPOSITOR.DPR_CAP) || 2;

  /* ── State ──────────────────────────────────────────────────────────────── */
  /* Registry: canvasId → { owner, acquireTime } */
  var _registry = {};

  /* Dimension cache: canvasId → { W, H, dpr, bufW, bufH, ctx } */
  var _dimCache = {};

  /* ── Internal helpers ───────────────────────────────────────────────────── */
  function log(msg)  { try { console.log (LOG_PREFIX + ' ' + msg); } catch(e){} }
  function warn(msg) { try { console.warn(LOG_PREFIX + ' ' + msg); } catch(e){} }

  function _cacheKey(canvas) {
    return canvas.id || ('cdb-canvas-' + _objId(canvas));
  }

  var _idCounter = 0;
  function _objId(obj) {
    if (!obj.__cdbId) obj.__cdbId = ++_idCounter;
    return obj.__cdbId;
  }

  /* ── Public API ─────────────────────────────────────────────────────────── */

  /**
   * claim(canvasId, ownerId) — register exclusive canvas ownership.
   * Returns true if granted. Rejects if another engine already owns it.
   */
  function claim(canvasId, ownerId) {
    if (!canvasId || !ownerId) {
      warn('claim() requires canvasId and ownerId');
      return false;
    }
    var existing = _registry[canvasId];
    if (existing && existing.owner !== ownerId) {
      warn('Canvas "' + canvasId + '" already owned by "' + existing.owner + '" — claim by "' + ownerId + '" rejected');
      return false;
    }
    _registry[canvasId] = { owner: ownerId, acquireTime: Date.now() };
    log('Canvas "' + canvasId + '" claimed by "' + ownerId + '"');
    return true;
  }

  /**
   * release(canvasId, ownerId) — relinquish canvas ownership.
   */
  function release(canvasId, ownerId) {
    var existing = _registry[canvasId];
    if (!existing || existing.owner !== ownerId) {
      warn('release() by non-owner "' + ownerId + '" on canvas "' + canvasId + '" — ignored');
      return;
    }
    delete _registry[canvasId];
    delete _dimCache[canvasId];
    log('Canvas "' + canvasId + '" released by "' + ownerId + '"');
  }

  /**
   * isOwner(canvasId, ownerId) — check if ownerId holds the canvas token.
   */
  function isOwner(canvasId, ownerId) {
    var existing = _registry[canvasId];
    if (!existing) return false;  /* No owner: allow access (graceful) */
    return existing.owner === ownerId;
  }

  /**
   * applySize(canvas, panel, forceReset) — governed, cached canvas resize.
   *
   * CRITICAL Chrome fix (RC2): canvas.width = X ALWAYS resets the GPU texture
   * even if X is unchanged. This function compares against cached values and
   * only resets the canvas buffer if dimensions have actually changed.
   *
   * Returns { W, H, dpr, ctx, bufW, bufH } or null on failure.
   */
  function applySize(canvas, panel, forceReset) {
    if (!canvas || !panel) { warn('applySize() — canvas or panel is null'); return null; }

    var key  = _cacheKey(canvas);
    var dpr  = Math.min(global.devicePixelRatio || 1, DPR_CAP);

    /* Measure panel — fall through chain to guarantee a real value */
    var W = panel.offsetWidth
          || panel.getBoundingClientRect().width
          || 800;

    var H = panel.offsetHeight
          || panel.getBoundingClientRect().height
          || 0;

    /* Responsive height floor — prevents canvas from collapsing to 0px */
    var vw    = global.innerWidth || 1200;
    var hFloor = vw <= 480 ? 220 : vw <= 768 ? 270 : vw >= 1600 ? 420 : 340;
    H = Math.max(H || 0, hFloor);
    if (W < 10) W = 800;

    var newBufW = Math.round(W * dpr);
    var newBufH = Math.round(H * dpr);

    var cached = _dimCache[key];

    var needsReset = forceReset
      || !cached
      || newBufW !== cached.bufW
      || newBufH !== cached.bufH
      || dpr     !== cached.dpr;

    if (needsReset) {
      /* ── CHROME FIX: Only set canvas.width/height when dimensions change ── */
      /* Each assignment to canvas.width/height destroys the GPU texture.     */
      /* By caching, we reduce GPU invalidations from 60/s → 0/s (no change) */
      canvas.style.setProperty('width',  W + 'px', 'important');
      canvas.style.setProperty('height', H + 'px', 'important');
      panel.style.setProperty('height',  H + 'px', 'important');

      canvas.width  = newBufW;
      canvas.height = newBufH;

      var ctx = canvas.getContext('2d');
      if (!ctx) { warn('applySize() — getContext("2d") returned null'); return null; }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      _dimCache[key] = {
        W    : W,
        H    : H,
        dpr  : dpr,
        bufW : newBufW,
        bufH : newBufH,
        ctx  : ctx
      };

      if (forceReset) {
        log('applySize() FORCE — ' + W + 'x' + H + ' @ DPR ' + dpr);
      }
    }

    var c = _dimCache[key];
    /* Re-apply transform in case context was recycled (e.g. after tab restore) */
    if (c.ctx) c.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    return { W: c.W, H: c.H, dpr: c.dpr, ctx: c.ctx, bufW: c.bufW, bufH: c.bufH };
  }

  /**
   * getContext(canvas) — returns cached 2D context or acquires a new one.
   */
  function getContext(canvas) {
    if (!canvas) return null;
    var key    = _cacheKey(canvas);
    var cached = _dimCache[key];
    if (cached && cached.ctx) return cached.ctx;
    return canvas.getContext('2d');
  }

  /**
   * invalidate(canvas) — force next applySize call to reset canvas buffer.
   * Use after visibility restore or GPU context loss.
   */
  function invalidate(canvas) {
    if (!canvas) return;
    var key = _cacheKey(canvas);
    delete _dimCache[key];
    log('Canvas "' + key + '" cache invalidated — next applySize will force reset');
  }

  /**
   * getDims(canvas) — returns last known dimensions without triggering resize.
   */
  function getDims(canvas) {
    if (!canvas) return null;
    var key = _cacheKey(canvas);
    return _dimCache[key] || null;
  }

  /* ── Export ─────────────────────────────────────────────────────────────── */
  global.CDB_CANVAS = {
    claim     : claim,
    release   : release,
    isOwner   : isOwner,
    applySize : applySize,
    getContext: getContext,
    invalidate: invalidate,
    getDims   : getDims,
    VERSION   : VERSION
  };

  log('Canvas Lifecycle Engine online — ownership registry ready');

}(window));
