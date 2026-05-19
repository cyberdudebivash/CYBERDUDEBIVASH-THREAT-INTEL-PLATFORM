// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — GPU Tier Engine v169.0
// Adaptive GPU governance: detects GPU capabilities and assigns render tier.
//
// TIERS:
//   TIER 0 — SAFE MODE    : No GPU / software renderer / context failure
//   TIER 1 — LOW GPU      : Canvas2D only, minimal effects, low particles
//   TIER 2 — MID GPU      : Full Canvas2D, medium particles, cinematic overlays
//   TIER 3 — HIGH GPU     : All effects, full particles, advanced telemetry
//
// DETECTION FACTORS:
//   - WebGL2 availability
//   - GPU vendor + renderer string (UNMASKED)
//   - DevicePixelRatio pressure
//   - Memory estimate (navigator.deviceMemory)
//   - Concurrent hardware threads (navigator.hardwareConcurrency)
//   - Chrome vs Edge vs Firefox vs Safari
//   - Hardware acceleration state
//
// API (window.CDB_GPU_TIER):
//   .tier              — 0|1|2|3 (current tier)
//   .label             — 'SAFE'|'LOW'|'MID'|'HIGH'
//   .vendor            — GPU vendor string
//   .renderer          — GPU renderer string
//   .webgl2            — boolean: WebGL2 available
//   .browser           — 'chrome'|'edge'|'firefox'|'safari'|'unknown'
//   .softwareRenderer  — boolean: is running software/swiftshader
//   .getQuality()      — returns quality config for current tier
//   .onTierResolved(cb)— callback when async detection completes
// =============================================================================
(function (global) {
  'use strict';

  /* ── Constants ─────────────────────────────────────────────────────────── */
  var VERSION    = '169.0';
  var LOG_PREFIX = '[CDB-GPU-TIER v' + VERSION + ']';

  /* ── Tier Quality Profiles ──────────────────────────────────────────────── */
  var QUALITY_PROFILES = {
    0: { /* SAFE MODE */
      particleMax    : 0,
      arcCount       : 8,
      glowIntensity  : 0,
      scanlines      : false,
      radarSweep     : false,
      threatZones    : false,
      bloomPasses    : 0,
      dprCap         : 1,
      targetFPS      : 30,
      label          : 'SAFE'
    },
    1: { /* LOW GPU */
      particleMax    : 40,
      arcCount       : 12,
      glowIntensity  : 0.4,
      scanlines      : false,
      radarSweep     : true,
      threatZones    : false,
      bloomPasses    : 0,
      dprCap         : 1,
      targetFPS      : 30,
      label          : 'LOW'
    },
    2: { /* MID GPU */
      particleMax    : 100,
      arcCount       : 18,
      glowIntensity  : 0.7,
      scanlines      : true,
      radarSweep     : true,
      threatZones    : true,
      bloomPasses    : 1,
      dprCap         : 1.5,
      targetFPS      : 60,
      label          : 'MID'
    },
    3: { /* HIGH GPU */
      particleMax    : 200,
      arcCount       : 26,
      glowIntensity  : 1.0,
      scanlines      : true,
      radarSweep     : true,
      threatZones    : true,
      bloomPasses    : 2,
      dprCap         : 2,
      targetFPS      : 60,
      label          : 'HIGH'
    }
  };

  /* ── State ──────────────────────────────────────────────────────────────── */
  var _tier           = 2;    /* Default: MID — safe assumption before detection */
  var _vendor         = 'UNKNOWN';
  var _renderer       = 'UNKNOWN';
  var _webgl2         = false;
  var _softwareRender = false;
  var _browser        = 'unknown';
  var _resolved       = false;
  var _callbacks      = [];

  /* ── Internal helpers ───────────────────────────────────────────────────── */
  function log(msg)  { try { console.log (LOG_PREFIX + ' ' + msg); } catch(e){} }
  function warn(msg) { try { console.warn(LOG_PREFIX + ' ' + msg); } catch(e){} }

  /* ── Browser Detection ──────────────────────────────────────────────────── */
  function _detectBrowser() {
    var ua = (global.navigator && global.navigator.userAgent) || '';
    if (/Edg\//.test(ua))     return 'edge';
    if (/Chrome\//.test(ua))  return 'chrome';
    if (/Firefox\//.test(ua)) return 'firefox';
    if (/Safari\//.test(ua))  return 'safari';
    return 'unknown';
  }

  /* ── WebGL GPU String Detection ─────────────────────────────────────────── */
  function _detectGPU() {
    var result = { vendor: 'UNKNOWN', renderer: 'UNKNOWN', webgl2: false, software: false };
    try {
      /* Try WebGL2 first */
      var canvas = document.createElement('canvas');
      canvas.width  = 1;
      canvas.height = 1;
      var gl2 = canvas.getContext('webgl2');
      if (gl2) {
        result.webgl2 = true;
        var ext = gl2.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          result.vendor   = gl2.getParameter(ext.UNMASKED_VENDOR_WEBGL)   || 'UNKNOWN';
          result.renderer = gl2.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'UNKNOWN';
        }
        gl2.getExtension('WEBGL_lose_context') && gl2.getExtension('WEBGL_lose_context').loseContext();
      } else {
        /* Fall back to WebGL1 */
        var gl1 = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl1) {
          var ext1 = gl1.getExtension('WEBGL_debug_renderer_info');
          if (ext1) {
            result.vendor   = gl1.getParameter(ext1.UNMASKED_VENDOR_WEBGL)   || 'UNKNOWN';
            result.renderer = gl1.getParameter(ext1.UNMASKED_RENDERER_WEBGL) || 'UNKNOWN';
          }
          gl1.getExtension('WEBGL_lose_context') && gl1.getExtension('WEBGL_lose_context').loseContext();
        }
      }
      canvas.remove();

      /* Detect software renderers */
      var r = result.renderer.toLowerCase();
      if (/swiftshader|llvmpipe|softpipe|mesa offscreen|virgl|angle.*swiftshader/.test(r)) {
        result.software = true;
      }
    } catch(e) {
      warn('GPU detection failed: ' + e.message);
    }
    return result;
  }

  /* ── Tier Assignment ────────────────────────────────────────────────────── */
  function _assignTier(gpuInfo, browser, dpr, memory, threads) {
    /* TIER 0: software renderer or WebGL unavailable */
    if (gpuInfo.software || (!gpuInfo.webgl2 && gpuInfo.renderer === 'UNKNOWN')) {
      warn('Tier 0 (SAFE): software renderer or no WebGL detected');
      return 0;
    }

    var r = gpuInfo.renderer.toLowerCase();
    var v = gpuInfo.vendor.toLowerCase();

    /* TIER 1: very old/weak integrated GPU signals */
    var lowGPUPatterns = [
      /intel.*hd.*(2000|3000|4000|5000)/,  /* Intel HD 2000-5000 */
      /intel.*gma/,                          /* Intel GMA */
      /mali-4/,                              /* ARM Mali 4xx */
      /adreno\s*[23]/,                       /* Adreno 2xx-3xx */
      /powervr/,                             /* PowerVR (old iOS) */
      /vc4/                                  /* Raspberry Pi */
    ];
    for (var i = 0; i < lowGPUPatterns.length; i++) {
      if (lowGPUPatterns[i].test(r)) {
        log('Tier 1 (LOW): matched low-GPU pattern ' + lowGPUPatterns[i]);
        return 1;
      }
    }

    /* TIER 1: low memory / low CPU threads */
    if (memory && memory < 2)   { log('Tier 1 (LOW): deviceMemory < 2GB'); return 1; }
    if (threads && threads < 2) { log('Tier 1 (LOW): hardwareConcurrency < 2'); return 1; }

    /* TIER 3: discrete high-end GPU signals */
    var highGPUPatterns = [
      /nvidia.*rtx/,
      /nvidia.*gtx\s*(1[06789]|20|30|40)/,  /* GTX 1060+ */
      /amd.*rx\s*(5[6789]|6[0-9]|7[0-9])/,  /* RX 5600+ */
      /amd.*radeon.*pro/,
      /apple.*m[1-9]/,                        /* Apple Silicon */
      /adreno\s*[6-9]/                        /* Adreno 6xx+ */
    ];
    for (var j = 0; j < highGPUPatterns.length; j++) {
      if (highGPUPatterns[j].test(r)) {
        log('Tier 3 (HIGH): matched high-GPU pattern ' + highGPUPatterns[j]);
        return 3;
      }
    }

    /* TIER 2: everything else (mid-range) */
    /* Edge/Firefox get +1 tier vs Chrome for same GPU (compositor differences) */
    if ((browser === 'edge' || browser === 'firefox') && gpuInfo.webgl2) {
      log('Tier 3 (HIGH): Edge/Firefox WebGL2 mid-range → promoted to HIGH');
      return 3;
    }

    log('Tier 2 (MID): default mid-range assignment');
    return 2;
  }

  /* ── Resolution + notification ──────────────────────────────────────────── */
  function _resolve() {
    _resolved = true;
    log('GPU Tier resolved: T' + _tier + ' (' + QUALITY_PROFILES[_tier].label + ') | ' +
        _vendor + ' | ' + _renderer + ' | WebGL2=' + _webgl2 +
        ' | Browser=' + _browser + ' | Software=' + _softwareRender);

    /* Fire registered callbacks */
    for (var i = 0; i < _callbacks.length; i++) {
      try { _callbacks[i](global.CDB_GPU_TIER); } catch(e) {}
    }
    _callbacks = [];
  }

  /* ── Main Detection ─────────────────────────────────────────────────────── */
  function detect() {
    _browser = _detectBrowser();

    var gpuInfo = _detectGPU();
    _vendor         = gpuInfo.vendor;
    _renderer       = gpuInfo.renderer;
    _webgl2         = gpuInfo.webgl2;
    _softwareRender = gpuInfo.software;

    var dpr     = Math.min(global.devicePixelRatio || 1, 3);
    var memory  = global.navigator && global.navigator.deviceMemory;
    var threads = global.navigator && global.navigator.hardwareConcurrency;

    _tier = _assignTier(gpuInfo, _browser, dpr, memory, threads);

    _resolve();
    return _tier;
  }

  /* ── Public API ─────────────────────────────────────────────────────────── */
  function getQuality() {
    return QUALITY_PROFILES[_tier] || QUALITY_PROFILES[2];
  }

  function onTierResolved(cb) {
    if (typeof cb !== 'function') return;
    if (_resolved) {
      try { cb(global.CDB_GPU_TIER); } catch(e) {}
    } else {
      _callbacks.push(cb);
    }
  }

  /* ── Export ─────────────────────────────────────────────────────────────── */
  global.CDB_GPU_TIER = {
    get tier()           { return _tier; },
    get label()          { return QUALITY_PROFILES[_tier] ? QUALITY_PROFILES[_tier].label : 'MID'; },
    get vendor()         { return _vendor; },
    get renderer()       { return _renderer; },
    get webgl2()         { return _webgl2; },
    get browser()        { return _browser; },
    get softwareRenderer(){ return _softwareRender; },
    getQuality           : getQuality,
    onTierResolved       : onTierResolved,
    detect               : detect,
    PROFILES             : QUALITY_PROFILES,
    VERSION              : VERSION
  };

  /* ── Auto-detect on script load ─────────────────────────────────────────── */
  detect();

  log('GPU Tier Engine online');

}(window));
