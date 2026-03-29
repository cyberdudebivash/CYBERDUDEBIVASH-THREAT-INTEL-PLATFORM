/**
 * CYBERDUDEBIVASH® SENTINEL APEX — UI Logic v1.0
 * Nav, toasts, subscribe CTAs, typewriter, Intersection Observer animations.
 */
'use strict';

/* ── Toast Notification System ─────────────────────────────────────────── */
const Toast = (() => {
  let container;
  function init() {
    container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
  }
  function show(msg, type = 'info', duration = 4500) {
    if (!container) init();
    const icons = { success: '✓', error: '✕', info: '◈', warning: '⚠' };
    const colors = { success: '#00e676', error: '#ff1744', info: '#00e5ff', warning: '#ff9800' };
    const t = document.createElement('div');
    t.className = 'toast';
    t.style.borderColor = colors[type];
    t.innerHTML = `<span style="color:${colors[type]};font-weight:700">${icons[type] || '◈'}</span><span>${msg}</span>`;
    container.appendChild(t);
    setTimeout(() => {
      t.style.animation = 'slide-in .3s ease reverse forwards';
      setTimeout(() => t.remove(), 280);
    }, duration);
  }
  return { show, success: m => show(m, 'success'), error: m => show(m, 'error'),
    info: m => show(m, 'info'), warn: m => show(m, 'warning') };
})();

/* ── Nav Scroll Behaviour ──────────────────────────────────────────────── */
function initNav() {
  const nav = document.querySelector('.nav');
  if (!nav) return;
  let ticking = false;
  window.addEventListener('scroll', () => {
    if (!ticking) {
      requestAnimationFrame(() => {
        nav.style.borderBottomColor = window.scrollY > 40
          ? 'rgba(0,229,255,.18)' : 'rgba(0,229,255,.1)';
        ticking = false;
      });
      ticking = true;
    }
  });
  // Mobile menu toggle
  const toggle = document.querySelector('.nav-mobile-toggle');
  const links  = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', () => {
      const open = links.style.display === 'flex';
      links.style.cssText = open ? '' :
        'display:flex;flex-direction:column;position:absolute;top:64px;left:0;right:0;background:rgba(2,8,16,.97);padding:20px 24px;border-bottom:1px solid rgba(0,229,255,.1);gap:18px;z-index:800';
    });
  }
}

/* ── Intersection Observer — Fade In ───────────────────────────────────── */
function initReveal() {
  const els = document.querySelectorAll('[data-reveal]');
  if (!els.length) return;
  const io = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.style.animation = `fade-up 0.6s ${e.target.dataset.delay || '0s'} var(--ease) both`;
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.08 });
  const style = document.createElement('style');
  style.textContent = `@keyframes fade-up{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:none}}`;
  document.head.appendChild(style);
  els.forEach(el => { el.style.opacity = '0'; io.observe(el); });
}

/* ── Subscribe Button Handler ──────────────────────────────────────────── */
async function handleSubscribe(btn) {
  const plan     = btn.dataset.plan     || 'pro';
  const provider = btn.dataset.provider || 'stripe';

  // Collect name + email if form present
  const nameEl  = document.getElementById('sub-name');
  const emailEl = document.getElementById('sub-email');
  const name    = nameEl ? nameEl.value.trim() : '';
  const email   = emailEl ? emailEl.value.trim() : '';

  if (emailEl && !email) {
    Toast.warn('Please enter your email address.');
    emailEl.focus();
    return;
  }

  btn.disabled = true;
  const orig = btn.innerHTML;
  btn.innerHTML = '<span style="font-family:var(--font-data)">⟳ Connecting...</span>';

  try {
    const { ok, data, error } = await APEX.subscribe(plan, provider, name, email);
    if (ok && data.checkout_url) {
      Toast.success(`Redirecting to ${data.provider || provider} checkout...`);
      setTimeout(() => { window.location.href = data.checkout_url; }, 800);
    } else if (ok && data.status === 'ok' && data.tier === 'free') {
      Toast.success('Free tier active — no payment needed!');
      btn.innerHTML = '✓ Free Plan Active';
      return;
    } else {
      Toast.error(typeof error === 'string' ? error : 'Subscription failed. Try again.');
      console.warn('[APEX] Subscribe error:', error || data);
    }
  } catch (e) {
    Toast.error('Network error — please try again.');
  }
  btn.disabled = false;
  btn.innerHTML = orig;
}

/* ── Typewriter Effect ─────────────────────────────────────────────────── */
function typewriter(el, lines, speed = 38) {
  if (!el) return;
  let li = 0, ci = 0;
  const cursor = el.querySelector('.term-cursor');
  function type() {
    if (li >= lines.length) { if (cursor) cursor.style.display = 'inline-block'; return; }
    const line = lines[li];
    if (ci === 0) {
      const row = document.createElement('div');
      row.className = 'term-line';
      row.innerHTML = `<span class="term-prompt">apex@sentinel:~$</span><span class="term-cmd"> </span>`;
      if (cursor) el.insertBefore(row, cursor.parentElement);
      else el.appendChild(row);
    }
    const cmdEl = el.querySelectorAll('.term-cmd');
    const target = cmdEl[cmdEl.length - 1];
    if (target && ci < line.cmd.length) {
      target.textContent += line.cmd[ci++];
      setTimeout(type, speed + Math.random() * 20);
    } else {
      ci = 0; li++;
      if (line.out) {
        const out = document.createElement('div');
        out.className = `term-line ${line.outClass || 'term-out'}`;
        out.textContent = line.out;
        if (cursor) el.insertBefore(out, cursor.parentElement);
        else el.appendChild(out);
      }
      setTimeout(type, 220);
    }
  }
  setTimeout(type, 800);
}

/* ── Counter Animation ─────────────────────────────────────────────────── */
function animateCounter(el, target, duration = 1600) {
  if (!el) return;
  const start = performance.now();
  const update = (now) => {
    const pct = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - pct, 3);
    el.textContent = (target >= 1000
      ? Math.floor(ease * target).toLocaleString()
      : (ease * target).toFixed(target % 1 ? 1 : 0));
    if (pct < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

/* ── DOM Init ──────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initReveal();

  // Subscribe buttons
  document.querySelectorAll('[data-subscribe]').forEach(btn => {
    btn.addEventListener('click', () => handleSubscribe(btn));
  });

  // Typewriter terminal
  const termBody = document.querySelector('.hero-terminal-body');
  if (termBody) {
    typewriter(termBody, [
      { cmd: 'apex scan --live --critical', out: '◈ Scanning 500 advisories...', outClass: 'term-out' },
      { cmd: 'apex threat list --severity=CRITICAL', out: '⚡ 125 CRITICAL threats detected', outClass: 'term-out-red' },
      { cmd: 'apex alert --engine=P1 --channel=telegram', out: '✓ 10 P1 alerts dispatched', outClass: 'term-out' },
      { cmd: 'apex response --mode=safe --auto', out: '→ 5 auto-responses executed [SAFE]', outClass: 'term-out-amb' },
    ]);
  }

  // Counter animations on scroll
  const counters = document.querySelectorAll('[data-count]');
  if (counters.length) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          animateCounter(e.target, parseFloat(e.target.dataset.count));
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.5 });
    counters.forEach(el => io.observe(el));
  }
});

window.APEX_UI = { Toast, handleSubscribe };
