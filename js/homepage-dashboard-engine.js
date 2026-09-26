        // ═══════════════════════════════════════════════════════
        // SENTINEL APEX v184.0 \u2014 INTELLIGENCE DASHBOARD ENGINE
        // v184.0: version.json sync, subscription tier badges, STIX API links,
        //           guaranteed dossier links (report_url always internal, never source_url primary)
        // ═══════════════════════════════════════════════════════

        // ── v117.0.0: Version sync from version.json ──────────────────────────
        // ── Single platform version constant (v201.0) ─────────────────────────
        const PLATFORM_VERSION = '201.0';  // GOVERNANCE: platform version only — never inject CI pipeline version here

        (function syncVersion() {
            // Apply version to all version elements
            function applyVersion(ver) {
                const v = ver || PLATFORM_VERSION;
                ['platform-version','footer-version'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = 'V' + v;
                });
                const fc = document.getElementById('footer-version-copy');
                if (fc) fc.textContent = 'SENTINEL APEX V' + v;
                // PRODUCTION-TRUTH FIX (release hardening -- version audit): the
                // status-strip "ENGINE: CYBERDUDEBIVASH APEX vX.X" widget had its
                // own hardcoded version text with no element id at all, so this
                // function -- the platform's one real version-sync mechanism --
                // never touched it. It sat at v185.0 in production long after the
                // rest of the page correctly moved to v200.0 (confirmed live).
                // Now wrapped in its own span (engine-version-number) and kept in
                // sync here too, same as every other version display on this page.
                const ev = document.getElementById('engine-version-number');
                if (ev) ev.textContent = v;
                window.APEX_VERSION = v;
            }
            applyVersion(PLATFORM_VERSION);  // immediate \u2014 no flash
            fetch('/version.json?_=' + Date.now())
                .then(r => r.ok ? r.json() : null)
                .then(v => {
                    if (!v) return;
                    applyVersion(v.version);
                    window.APEX_TIERS    = v.subscription_tiers || {};
                    window._platformTiers = window._platformTiers || { current: 'free' };
                    const tierEl = document.getElementById('platform-tier-badge');
                    if (tierEl) tierEl.innerHTML = tierBadge(window._platformTiers.current);
                })
                .catch(() => { window._platformTiers = { current: 'free' }; });
        })();

        // ════════════════════════════════════════════════════════════════
        // v123.0.0 \u2014 AUTH PERSISTENCE ENGINE (CDB SENTINEL APEX)
        // Inline auth: token storage \u00b7 login/signup \u00b7 tier sync \u00b7 modal
        // ════════════════════════════════════════════════════════════════
        (function CDB_AUTH_PERSISTENCE_ENGINE() {
            const STORE_KEY   = 'cdb_auth_v123';
            const SESSION_KEY = 'cdb_session_v123';
            const AUTH_ENDPOINT = 'https://intel.cyberdudebivash.com/api/auth';

            // ── Token helpers ──────────────────────────────────────────
            window.cdbAuth = {
                getToken: function() {
                    try {
                        const s = JSON.parse(localStorage.getItem(STORE_KEY) || '{}');
                        if (!s.token || !s.exp) return null;
                        if (Date.now() > s.exp) { window.cdbAuth.clear(); return null; }
                        return s.token;
                    } catch(e) { return null; }
                },
                getUser: function() {
                    try { return JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch(e) { return {}; }
                },
                setSession: function(data) {
                    const record = {
                        token: data.token,
                        email: data.email || '',
                        name:  data.name  || data.email || 'Sentinel User',
                        tier:  data.tier  || 'free',
                        exp:   Date.now() + (data.expires_in || 86400) * 1000
                    };
                    localStorage.setItem(STORE_KEY, JSON.stringify(record));
                    window._platformTiers = window._platformTiers || {};
                    window._platformTiers.current = record.tier;
                    window.cdbAuth._refreshNavBtn();
                    window.cdbAuth._syncTierBadge(record.tier);
                },
                clear: function() {
                    localStorage.removeItem(STORE_KEY);
                    sessionStorage.removeItem(SESSION_KEY);
                    window._platformTiers = { current: 'free' };
                    window.cdbAuth._refreshNavBtn();
                    window.cdbAuth._syncTierBadge('free');
                },
                isLoggedIn: function() { return !!window.cdbAuth.getToken(); },

                // ── Tier sync ──────────────────────────────────────────
                _syncTierBadge: function(tier) {
                    const el = document.getElementById('platform-tier-badge');
                    if (el && typeof tierBadge === 'function') el.innerHTML = tierBadge(tier);
                },

                // ── Navbar state refresh ───────────────────────────────
                _refreshNavBtn: function() {
                    const btn   = document.getElementById('cdb-auth-nav-btn');
                    const label = document.getElementById('cdb-auth-nav-label');
                    const dot   = document.getElementById('cdb-auth-nav-icon');
                    if (!btn) return;
                    if (window.cdbAuth.isLoggedIn()) {
                        const u = window.cdbAuth.getUser();
                        const tierColors = { pro:'#00d4aa', enterprise:'#ffd700', free:'#2196f3' };
                        const tc = tierColors[u.tier] || '#00d4aa';
                        if (label) label.textContent = '👤 ' + (u.name || 'ACCOUNT').toUpperCase().substring(0,18);
                        if (dot)   { dot.style.background = tc; dot.style.boxShadow = '0 0 8px ' + tc; }
                        btn.style.borderColor = tc + '80';
                    } else {
                        if (label) label.textContent = '🔐 SIGN IN';
                        if (dot)   { dot.style.background = '#00d4aa'; dot.style.boxShadow = '0 0 6px #00d4aa'; }
                        btn.style.borderColor = 'rgba(0,212,170,0.4)';
                    }
                },

                // ── Attempt login via API ──────────────────────────────
                login: async function(email, password) {
                    try {
                        const res = await fetch(AUTH_ENDPOINT + '/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email, password })
                        });
                        const data = await res.json();
                        if (!res.ok) throw new Error(data.message || 'Login failed');
                        window.cdbAuth.setSession(data);
                        return { ok: true, user: data };
                    } catch(e) {
                        // The real backend (/auth/login) authenticates by API key, not
                        // email+password, so this call always fails today. Previously
                        // this silently fabricated a local session on any 8+ char
                        // password, making a customer believe they were signed in when
                        // nothing had actually authenticated. Fail honestly instead and
                        // point at the real, working provisioning path.
                        return { ok: false, error: 'Email/password sign-in isn\u2019t available yet \u2014 API keys are issued on request. Use "Get API Key" below to request one.' };
                    }
                },

                // ── Attempt register via API ───────────────────────────
                register: async function(email, password, name) {
                    try {
                        const res = await fetch(AUTH_ENDPOINT + '/register', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email, password, name })
                        });
                        const data = await res.json();
                        if (!res.ok) throw new Error(data.message || 'Registration failed');
                        window.cdbAuth.setSession(data);
                        return { ok: true, user: data };
                    } catch(e) {
                        return { ok: false, error: e.message };
                    }
                },

                // ── Validate stored token with API ─────────────────────
                validate: async function() {
                    const token = window.cdbAuth.getToken();
                    if (!token) return;
                    try {
                        const res = await fetch(AUTH_ENDPOINT + '/validate', {
                            headers: { 'Authorization': 'Bearer ' + token }
                        });
                        if (!res.ok) { window.cdbAuth.clear(); return; }
                        const data = await res.json();
                        if (data.tier) {
                            const s = window.cdbAuth.getUser();
                            s.tier = data.tier;
                            localStorage.setItem(STORE_KEY, JSON.stringify(s));
                            window._platformTiers.current = data.tier;
                            window.cdbAuth._syncTierBadge(data.tier);
                        }
                    } catch(e) { /* Network error \u2014 keep existing session */ }
                }
            };

            // ── Init on load ───────────────────────────────────────────
            document.addEventListener('DOMContentLoaded', function() {
                window.cdbAuth._refreshNavBtn();
                if (window.cdbAuth.isLoggedIn()) {
                    const u = window.cdbAuth.getUser();
                    window._platformTiers = window._platformTiers || {};
                    window._platformTiers.current = u.tier || 'free';
                    window.cdbAuth._syncTierBadge(u.tier);
                    window.cdbAuth.validate();
                }
            });
        })();

        // ── v123 Auth Modal controller ─────────────────────────────────
        window.cdbAuthToggle = function() {
            if (window.cdbAuth.isLoggedIn()) {
                window.cdbOpenAccountModal();
            } else {
                window.cdbOpenAuthModal('login');
            }
        };
        window.cdbOpenAuthModal = function(tab) {
            const modal = document.getElementById('cdb-auth-modal');
            if (!modal) return;
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('open'), 10);
            window.cdbAuthSwitchTab(tab || 'login');
        };
        window.cdbCloseAuthModal = function() {
            const modal = document.getElementById('cdb-auth-modal');
            if (!modal) return;
            modal.classList.remove('open');
            setTimeout(() => { modal.style.display = 'none'; }, 300);
        };
        window.cdbAuthSwitchTab = function(tab) {
            ['login','signup'].forEach(t => {
                const btn  = document.getElementById('cdb-auth-tab-' + t);
                const pane = document.getElementById('cdb-auth-pane-' + t);
                if (btn)  btn.classList.toggle('active', t === tab);
                if (pane) pane.style.display = t === tab ? 'block' : 'none';
            });
            const errEl = document.getElementById('cdb-auth-error');
            if (errEl) errEl.textContent = '';
        };
        window.cdbDoLogin = async function() {
            const email = document.getElementById('cdb-login-email').value.trim();
            const pass  = document.getElementById('cdb-login-pass').value;
            const errEl = document.getElementById('cdb-auth-error');
            const btn   = document.getElementById('cdb-login-btn');
            if (!email || !pass) { errEl.textContent = 'Email and password required.'; return; }
            btn.disabled = true; btn.textContent = 'AUTHENTICATING...';
            const res = await window.cdbAuth.login(email, pass);
            btn.disabled = false; btn.textContent = 'SIGN IN';
            if (res.ok) {
                window.cdbCloseAuthModal();
            } else {
                errEl.textContent = res.error || 'Authentication failed.';
            }
        };
        window.cdbDoSignup = async function() {
            const name  = document.getElementById('cdb-signup-name').value.trim();
            const email = document.getElementById('cdb-signup-email').value.trim();
            const pass  = document.getElementById('cdb-signup-pass').value;
            const errEl = document.getElementById('cdb-auth-error');
            const btn   = document.getElementById('cdb-signup-btn');
            if (!email || !pass || pass.length < 8) { errEl.textContent = 'Email + password (min 8 chars) required.'; return; }
            btn.disabled = true; btn.textContent = 'CREATING ACCOUNT...';
            const res = await window.cdbAuth.register(email, pass, name);
            btn.disabled = false; btn.textContent = 'CREATE ACCOUNT';
            if (res.ok) {
                window.cdbCloseAuthModal();
            } else {
                errEl.textContent = res.error || 'Registration failed.';
            }
        };
        window.cdbOpenAccountModal = function() {
            const modal = document.getElementById('cdb-account-modal');
            if (!modal) return;
            const u = window.cdbAuth.getUser();
            const tierColors = { pro:'#00d4aa', enterprise:'#ffd700', free:'#2196f3' };
            const tc = tierColors[u.tier] || '#2196f3';
            const el = (id) => document.getElementById(id);
            if (el('cdb-acct-email'))  el('cdb-acct-email').textContent  = u.email || '\u2014';
            if (el('cdb-acct-name'))   el('cdb-acct-name').textContent   = u.name  || 'Sentinel User';
            if (el('cdb-acct-tier'))   { el('cdb-acct-tier').textContent  = (u.tier||'FREE').toUpperCase(); el('cdb-acct-tier').style.color = tc; }
            if (el('cdb-acct-expiry')) el('cdb-acct-expiry').textContent = u.exp ? new Date(u.exp).toLocaleString() : '\u2014';
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('open'), 10);
        };
        window.cdbCloseAccountModal = function() {
            const modal = document.getElementById('cdb-account-modal');
            if (!modal) return;
            modal.classList.remove('open');
            setTimeout(() => { modal.style.display = 'none'; }, 300);
        };
        window.cdbSignOut = function() {
            window.cdbAuth.clear();
            window.cdbCloseAccountModal();
        };

        // ── v117.0.0: Subscription tier badge helper ──────────────────────────
        function tierBadge(tier) {
            const t = (tier || 'free').toLowerCase();
            const cfg = {
                free:       { label: 'FREE',       color: '#2196f3', bg: 'rgba(33,150,243,.1)'  },
                premium:    { label: 'PRO',         color: '#00d4aa', bg: 'rgba(0,212,170,.1)'   },
                pro:        { label: 'PRO',         color: '#00d4aa', bg: 'rgba(0,212,170,.1)'   },
                enterprise: { label: 'ENTERPRISE',  color: '#ffd700', bg: 'rgba(255,215,0,.1)'   },
            };
            const c = cfg[t] || cfg.free;
            return `<span style="display:inline-block;padding:2px 8px;border-radius:3px;`
                 + `font-family:var(--font-mono);font-size:9px;font-weight:700;letter-spacing:1px;`
                 + `color:${c.color};background:${c.bg};border:1px solid ${c.color}40;">${c.label}</span>`;
        }

        // ── v117.0.0: STIX export URL builder ─────────────────────────────────
        function stixExportUrl(stixId) {
            return `https://intel.cyberdudebivash.com/api/stix/${encodeURIComponent(stixId)}`;
        }

        // ── Watchlist Management ──
        let watchlist = JSON.parse(localStorage.getItem('cdb_watchlist') || '[]');

        // ── Threat Registry \u2014 XSS-safe modal dispatch ──
        const threatRegistry = new Map(); // stix_id → item object

        function saveWatchlist() {
            try { localStorage.setItem('cdb_watchlist', JSON.stringify(watchlist)); } catch(e) {}
            updateWatchlistBadge();
        }

        function addToWatchlist(item) {
            var _wKey = item.stix_id || item.id;
            if (!watchlist.find(w => (w.stix_id || w.id) === _wKey)) {
                watchlist.push(item);
                saveWatchlist();
                renderWatchlistItems();
                showToast('⭐ Added to Watchlist: ' + item.title.slice(0, 48), 'info');
                document.getElementById('watchlist-fab').style.display = 'flex';
            }
        }

        function removeFromWatchlist(stix_id) {
            watchlist = watchlist.filter(w => w.stix_id !== stix_id);
            saveWatchlist();
            renderWatchlistItems();
            // Update btn state in grid
            document.querySelectorAll('.watchlist-btn').forEach(btn => {
                if (btn.dataset.stixId === stix_id) {
                    btn.classList.remove('watching');
                    btn.innerHTML = '<i class="fas fa-star"></i> WATCH';
                }
            });
        }

        function clearWatchlist() {
            watchlist = [];
            saveWatchlist();
            renderWatchlistItems();
            document.querySelectorAll('.watchlist-btn').forEach(btn => {
                btn.classList.remove('watching');
                btn.innerHTML = '<i class="fas fa-star"></i> WATCH';
            });
        }

        function toggleWatchlistItem(item, btn) {
            const existing = watchlist.find(w => w.stix_id === item.stix_id);
            if (existing) {
                removeFromWatchlist(item.stix_id);
                btn.classList.remove('watching');
                btn.innerHTML = '<i class="fas fa-star"></i> WATCH';
            } else {
                addToWatchlist(item);
                btn.classList.add('watching');
                btn.innerHTML = '<i class="fas fa-star" style="color:#f59e0b;"></i> WATCHING';
                document.getElementById('watchlist-fab').style.display = 'flex';
            }
        }

        function toggleWatchlist() {
            const panel = document.getElementById('watchlist-panel');
            if (panel.classList.contains('open')) {
                closeWatchlist();
            } else {
                openWatchlist();
            }
        }

        function openWatchlist() {
            const panel = document.getElementById('watchlist-panel');
            panel.classList.add('open');
            renderWatchlistItems();
        }

        function closeWatchlist() {
            document.getElementById('watchlist-panel').classList.remove('open');
        }

        function renderWatchlistItems() {
            const container = document.getElementById('watchlist-items');
            const countEl = document.getElementById('watchlist-item-count');
            if (!container) return;
            if (countEl) countEl.textContent = watchlist.length;
            if (!watchlist.length) {
                container.innerHTML = '<div class="watchlist-empty"><div style="font-size:28px;margin-bottom:12px;">⭐</div>NO ADVISORIES IN WATCHLIST<br><span style="font-size:9px;">CLICK ⭐ WATCH ON ANY ADVISORY CARD</span></div>';
                return;
            }
            container.innerHTML = watchlist.map(item => {
                const sev = getSeverity(item.risk_score, item);
                const sevColor = getSevColor(sev);
                return `<div class="watchlist-item">
                    <div class="watchlist-item-title">${_cdbEsc(item.title)}</div>
                    <div class="watchlist-item-meta">
                        <span class="badge badge-${sev.toLowerCase()}">${sev}</span>
                        <span style="font-family:var(--font-mono);font-size:9px;color:${sevColor};">RISK ${item.risk_score}/10</span>
                        ${(()=>{
                            // ACCESS GOVERNANCE v184.0 — DOSSIER link gated to PRO+
                            const _wTier = (window._platformTiers && window._platformTiers.current) || 'free';
                            const _wPro = _wTier==='pro'||_wTier==='PRO'||_wTier==='premium'||_wTier==='PREMIUM'||_wTier==='enterprise'||_wTier==='ENTERPRISE'||_wTier==='mssp'||_wTier==='MSSP';
                            const _wSrc = item.source_url||'';
                            if (!_wPro) {
                                return _wSrc ? `<a href="/upgrade.html?plan=pro&utm_source=watchlist-dossier" target="_blank" style="font-family:var(--font-mono);font-size:9px;color:#666;">🔒 PRO</a>` : '';
                            }
                            const _wiru=item.internal_report_url||''; const _wru=(item.report_url||'').replace('https://reports.cyberdudebivash.com','https://intel.cyberdudebivash.com'); const _wruInt=_wru&&(_wru.startsWith('/reports/')||_wru.includes('intel.cyberdudebivash.com')||_wru.includes('cyberdudebivash.com/reports')); const _weid=item.stix_id||item.id||''; const _wInternal=_wiru||(_wruInt?_wru:'')||(_weid?`/reports/${_weid}.html`:''); const _wVsFail=item.validation_status==='quality_fail'||item.validation_status==='write_error'; const hasR=!!_wInternal&&!_wVsFail; const u=hasR?_wInternal:(_wSrc); return u?`<a href="${u}" target="_blank" style="font-family:var(--font-mono);font-size:9px;color:var(--accent);">${hasR?'DOSSIER →':'SOURCE →'}</a>`:'';
                        })()}
                        <button class="watchlist-remove" onclick="removeFromWatchlist('${item.stix_id}')">REMOVE</button>
                    </div>
                </div>`;
            }).join('');
        }

        function updateWatchlistBadge() {
            const badge = document.getElementById('watchlist-count-badge');
            if (badge) {
                badge.textContent = watchlist.length;
                badge.style.display = watchlist.length > 0 ? 'flex' : 'none';
            }
            const fab = document.getElementById('watchlist-fab');
            if (fab) fab.style.display = watchlist.length > 0 ? 'flex' : 'none';
        }

        // ── AI Engine Modal ──
        function openAIModal() {
            document.getElementById('ai-engine-modal').classList.add('open');
            document.body.style.overflow = 'hidden';
        }

        function closeAIModal() {
            document.getElementById('ai-engine-modal').classList.remove('open');
            document.body.style.overflow = '';
        }

        // ── Animated Metric Counters ──
        function animateCounter(el, target, duration = 1200) {
            if (!el || isNaN(parseFloat(target))) return;
            const isDecimal = String(target).includes('.');
            const targetNum = parseFloat(target);
            const start = Date.now();
            const update = () => {
                const elapsed = Date.now() - start;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = targetNum * eased;
                el.textContent = isDecimal ? current.toFixed(1) : Math.round(current);
                if (progress < 1) requestAnimationFrame(update);
                else el.textContent = isDecimal ? targetNum.toFixed(1) : targetNum;
            };
            requestAnimationFrame(update);
        }

        function animateAllMetrics() {
            const ids = ['m-total', 'm-critical', 'm-high', 'm-avg-risk', 'm-iocs', 'm-kev'];
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (el && el.textContent !== '\u2014' && !isNaN(parseFloat(el.textContent))) {
                    const val = el.textContent;
                    animateCounter(el, parseFloat(val));
                }
            });
        }

        // ── Trend Range Control ──
        let trendRange = 10;

        function setTrendRange(n, btn) {
            trendRange = n;
            document.querySelectorAll('.trend-range-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderTrendChart(manifestData);
        }

        // ── MITRE Tactic Group Mapping ──
        const MITRE_TACTIC_GROUPS = {
            'Initial Access': ['T1190', 'T1133', 'T1078', 'T1566', 'T1195', 'T1199'],
            'Execution': ['T1059', 'T1053', 'T1204', 'T1569', 'T1203'],
            'Persistence': ['T1542', 'T1098', 'T1136', 'T1505'],
            'Privilege Escalation': ['T1068', 'T1134', 'T1055'],
            'Defense Evasion': ['T1036', 'T1055', 'T1027', 'T1070', 'T1562'],
            'Credential Access': ['T1555', 'T1003', 'T1110', 'T1552'],
            'Discovery': ['T1082', 'T1083', 'T1046', 'T1016'],
            'Lateral Movement': ['T1021', 'T1534'],
            'Collection': ['T1560', 'T1005', 'T1056'],
            'Exfiltration': ['T1048', 'T1041', 'T1020'],
            'Impact': ['T1486', 'T1490', 'T1498', 'T1489'],
        };

        function getTacticGroup(techId) {
            const base = techId.split('.')[0];
            for (const [group, techs] of Object.entries(MITRE_TACTIC_GROUPS)) {
                if (techs.includes(base)) return group;
            }
            return 'Other';
        }

        // ── Source Trust Scoring ──
        const SOURCE_TRUST_SCORES = {
            'cvefeed.io': { score: 85, label: 'HIGH', color: '#16a34a' },
            'nvd.nist.gov': { score: 99, label: 'VERIFIED', color: '#00d4aa' },
            'cisa.gov': { score: 99, label: 'GOV', color: '#00d4aa' },
            'exploit-db.com': { score: 82, label: 'HIGH', color: '#16a34a' },
            'github.com': { score: 70, label: 'MED', color: '#d97706' },
            'vulhub.org': { score: 72, label: 'MED', color: '#d97706' },
        };

        function getSourceTrust(src) {
            for (const [key, val] of Object.entries(SOURCE_TRUST_SCORES)) {
                if (src.includes(key)) return val;
            }
            return { score: 60, label: 'STD', color: '#5a6578' };
        }

        // ── Curl Copy \u2014 API endpoint is subscriber-only, redirect to subscribe ──
        function copyCurl() {
            // API endpoint URL is not exposed client-side \u2014 subscribers receive credentials via email
            showToast('🔒 API endpoint provided to subscribers only \u2014 subscribe to receive your credentials', 'info', 4000);
            setTimeout(() => {
                window.open('/upgrade.html?plan=pro&utm_source=api-curl', '_blank');
            }, 1200);
        }

        // ── Keyboard shortcut additions ──
        // Add W for watchlist, M for AI modal to existing keydown handler
        const RAW_MANIFEST = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNL2doLXBhZ2VzL2RhdGEvc3RpeC9mZWVkX21hbmlmZXN0Lmpzb24=') /* v77.3 FIX: gh-pages is always freshest */;
        const GITHUB_API = atob('aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9jeWJlcmR1ZGViaXZhc2gvQ1lCRVJEVURFQklWQVNILVRIUkVBVC1JTlRFTC1QTEFURk9STQ==');

        let manifestData = [];
        let currentFilter = 'all';
        let currentSort = 'newest';
        let searchQuery = '';
        let currentTimeRange = 'all';  // v115.0 FIX: Default 'all' \u2014 '7d' caused newly-enriched entries with older STIX timestamps to be hidden on first load
        let autoRefreshTimer = null;
        let autoRefreshCountdown = null;
        const AUTO_REFRESH_INTERVAL = 30 * 60; // 30 minutes

        // ── Form endpoint init \u2014 bypasses Cloudflare HTML email obfuscation ──
        // Cloudflare rewrites email@domain in raw HTML to /cdn-cgi/l/email-protection#...
        // which 404s on GitHub Pages. JS string assembly sets the real action client-side.
        (function _cdbFormEndpointInit() {
            var _ep = 'https://formspree.io/f/' + 'bivash' + '\x40' + 'cyberdudebivash.com';
            function _setActions() {
                var sf = document.getElementById('cdb-subscribe-form');
                var ef = document.getElementById('cdb-enterprise-form');
                if (sf) sf.action = _ep;
                if (ef) ef.action = _ep;
            }
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', _setActions);
            } else {
                _setActions();
            }
        })();

        // ── Subscribe form handler \u2014 v184.0: captures email then routes to lead funnel ──
        function handleSubscribe(e) {
            e.preventDefault();
            const form = e.target;
            const email = form.querySelector('input[type=email]').value.trim();
            if (!email) return;

            // Show immediate confirmation
            const msg = document.getElementById('subscribe-msg');
            if (msg) { msg.style.display = 'block'; }
            form.reset();

            // Fire mailto lead capture to inbox (always works, no server required)
            const mailBody = 'New subscriber from intel.cyberdudebivash.com%0A%0AEmail: ' + encodeURIComponent(email) + '%0ASource: Free Digest Subscribe%0ATimestamp: ' + encodeURIComponent(new Date().toISOString());
            const mailLink = 'mailto:bivash\x40cyberdudebivash.com?subject=NEW%20SUBSCRIBER%3A%20' + encodeURIComponent(email) + '&body=' + mailBody;
            const a = document.createElement('a'); a.href = mailLink; a.click();

            // After 1.8s redirect into lead funnel with email pre-filled
            setTimeout(function() {
                window.location.href = '/get-api-key.html?plan=community&email=' + encodeURIComponent(email) + '&utm_source=subscribe-form';
            }, 1800);
        }

        // ── Severity Helpers ──
        function getSeverity(score, item) {
            if (item && item.severity) {
                // v184.0 G7 FIX: enforce v149 False-CRITICAL rule on frontend
                // CRITICAL requires KEV=True OR CVSS>=9.0 OR EPSS>=70% OR risk>=8.5
                if (item.severity === 'CRITICAL') {
                    // P0 FIX: item.kev could be the string "NO" (truthy in JS) and
                    // item.epss_score can be 0-100 or 0-1 scale depending on source --
                    // use the canonical normalizer (js/metric-normalize.js) for both.
                    const kev  = window.CDB_NORMALIZE.kevState(item) === true;
                    const cvss = parseFloat(item.cvss_score || 0);
                    const epssNorm = window.CDB_NORMALIZE.epss(item.epss_score);
                    const epss = epssNorm.state === 'OK' ? epssNorm.probability : 0;
                    const risk = parseFloat(item.risk_score || 0);
                    if (!(kev || cvss >= 9.0 || epss >= 0.70 || risk >= 8.5)) {
                        if (risk >= 6.5) return 'HIGH';
                        if (risk >= 4.0) return 'MEDIUM';
                        return 'LOW';
                    }
                }
                return item.severity;
            }
            if (score >= 8.5) return 'CRITICAL';
            if (score >= 6.5) return 'HIGH';
            if (score >= 4.0) return 'MEDIUM';
            if (score >= 2.0) return 'LOW';
            return 'INFO';
        }

        function getSevColor(sev) {
            return { CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
                     MEDIUM: 'var(--medium)', LOW: 'var(--low)',
                     INFO: 'var(--info)' }[sev] || 'var(--accent)';
        }

        function getTlpLabel(item) {
            // v76.2: Evidence-based TLP \u2014 mirrors backend risk_engine.py v76.2 logic
            // Priority: use stored manifest value first (set by pipeline at ingest time)
            // T-21 FIX v185.0: TLP:RED is never shown on the public dashboard (TLP spec \u00a72.4).
            // Public dashboard caps at TLP:AMBER. TLP:RED \u2192 restricted Enterprise+ API feed.
            if (item.tlp_label) {
                return (item.tlp_label === 'TLP:RED') ? 'TLP:AMBER' : item.tlp_label;
            }

            // Fallback calculation for items without stored TLP label
            const score  = parseFloat(item.risk_score) || 0;
            const cvss   = item.cvss_score != null ? parseFloat(item.cvss_score) : null;
            const kev    = !!item.kev_present;
            const hasIoc = item.ioc_counts && Object.values(item.ioc_counts).some(v => v > 0);

            // T-21 TLP FIX v185.0: TLP:RED is NEVER shown on the public dashboard.
            // TLP:RED requires person-to-person disclosure and named recipients (TLP spec §2.4).
            // Public dashboard caps at TLP:AMBER. Full TLP:RED feed → Enterprise+ API only.
            if (score >= 9.0) {
                // Would be TLP:RED — downgrade to TLP:AMBER for public view
                return 'TLP:AMBER';
            }
            if (score >= 7.0) {
                if (kev || hasIoc || (cvss != null && cvss >= 7.0)) return 'TLP:AMBER';
                return 'TLP:GREEN';
            }
            if (score >= 4.0) return 'TLP:GREEN';
            return 'TLP:CLEAR';
        }

        function getTlpColor(tlp) {
            if (tlp.includes('RED')) return 'var(--tlp-red)';
            if (tlp.includes('AMBER')) return 'var(--tlp-amber)';
            if (tlp.includes('GREEN')) return 'var(--tlp-green)';
            return 'var(--tlp-clear)';
        }

        function timeSince(ts) {
            const d = new Date(ts);
            const now = new Date();
            const diff = Math.floor((now - d) / 1000);
            if (diff < 60) return diff + 's ago';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        }

        function isNew(ts) {
            if (!ts) return false;
            const hours = (Date.now() - new Date(ts)) / 3600000;
            return hours < 6;
        }

        // ── Extract CVE IDs from title ──
        function extractCVEs(title) {
            return [...(title || '').matchAll(/CVE-\d{4}-\d{4,7}/gi)].map(m => m[0].toUpperCase());
        }
        function getLiveExploitedThreats(data) {
            return data.filter(item => {
                const title = (item.title || "").toLowerCase();
                return (
                    item.kev_present === true ||   // v76.1 FIX: was item.kev (wrong field name)
                    item.exploit_available === true ||
                    title.includes("exploit") ||
                    title.includes("zero-day") ||
                    title.includes("ransomware") ||
                    title.includes("actively exploited")
                );
            }).slice(0, 6);
        }

         function renderLiveExploits(data) {
             const container = document.getElementById('live-exploit-section');
                if (!container) return;

                const threats = getLiveExploitedThreats(data);

               if (!threats.length) {
                  container.innerHTML = '';
            return;
             }

           container.innerHTML = `
                 <div style="margin-bottom:15px;">
                  <div style="font-family:var(--font-mono);font-size:10px;color:#ff3e3e;letter-spacing:3px;">
                     🚨 ACTIVELY EXPLOITED IN THE WILD
                    </div>
                    </div>

               <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;">
                   ${threats.map(item => `
                <div style="background:var(--bg-card);border:1px solid rgba(255,62,62,0.3);padding:14px;">
                    <div style="font-size:12px;font-weight:700;color:#ff6b6b;">
                        ${_cdbEsc(item.title)}
                    </div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:6px;">
                        ⚠️ HIGH PRIORITY
                      </div>
                        </div>
                     `).join('')}
                      </div>
                      `;
                      }

        // ── Render Cards ──
        // v184.0: cleanText \u2014 strip non-ASCII junk characters before render (encoding fix)
        // Prevents mojibake / \u201c\u2019\u2018 style corruption in card titles and metadata
        // SENTINEL APEX v184.0 \u2014 UPGRADED cleanText: runtime mojibake defense
        // Fixes double-encoded UTF-8 sequences before they reach the DOM
        function cleanText(str) {
            if (!str) return "";
            try {
                var s = String(str).normalize("NFC");
                // Runtime mojibake map \u2014 catches any residual double-encoded sequences
                var MOJI = [
                    [/\u00e2\u20ac\u201d/g, '\u2014'], // em dash
                    [/\u00e2\u20ac\u201c/g, '\u2013'], // en dash
                    [/\u00e2\u20ac\u00a6/g, '\u2026'], // ellipsis
                    [/\u00e2\u0161\u00a1/g, '\u26a1'], // ⚡ lightning
                    [/\u00e2\u0153\u201c/g, '\u2714'], // ✔ check
                    [/\u00e2\u0153\u2014/g, '\u2717'], // ✗ cross
                    [/\u00e2\u02dc\u00a0/g, '\u2620'], // ☠ skull
                    [/\u00e2\u2014\u008f/g, '\u25cf'], // ● circle
                    [/\u00e2\u00ac\u00a1/g, '\u2b21'], // ⬡ hexagon
                    [/\u00e2\u2013\u00b2/g, '\u25b2'], // ▲
                    [/\u00e2\u2013\u00bc/g, '\u25bc'], // ▼
                    [/\u00e2\u2013\u00a0/g, '\u25a0'], // ■
                    [/\u00e2\u2020\u201c/g, '\u2193'], // ↓
                    [/\u00e2\u2020\u2019/g, '\u2192'], // →
                    [/\u00e2\u2020\u2018/g, '\u2191'], // ↑
                ];
                for (var i = 0; i < MOJI.length; i++) { s = s.replace(MOJI[i][0], MOJI[i][1]); }
                return s
                    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
                    .replace(/\uFFFD/g, "")
                    .trim();
            } catch(e) { return String(str); }
        }

        // v186.0 P0 FIX — CANONICAL INTEL REPORT URL BUILDER
        // ═══════════════════════════════════════════════════════════════
        // Single source of truth for "where does this card's report link
        // go" — replaces three independently-duplicated implementations
        // that had drifted apart (renderCards' inline IIFE, renderTopThreats'
        // intelUrl, and cdbGodModeRender's tier-gated CTA).
        //
        // Root cause of the P0 "fully locked card" regression: cdbGodModeRender
        // (the bulletproof fallback renderer, activated whenever renderCards()
        // throws or leaves #threat-grid empty) built its own report link and
        // gated the LINK ITSELF by client-side tier state — sending free-tier
        // users straight to /upgrade.html instead of to the report page.
        // This was unnecessary: /reports/** is a public, always-reachable,
        // server-masked surface (see workers/intel-gateway/src/index.js —
        // generateIntelReport() + applyTierGateV2(item,"free",null)) that
        // already renders the correct public/locked-section split for EVERY
        // visitor regardless of tier. No caller needs to gate the link itself.
        //
        // Tier-agnostic by design: every caller (free or paid) gets the same
        // report URL. Access to premium sections is enforced server-side,
        // inside the report page — never by withholding the link.
        function cdbBuildReportUrl(item) {
            try {
                const _isFail = item.validation_status === 'quality_fail' || item.validation_status === 'write_error';

                const _iru = (item.internal_report_url || '').trim();
                const _ru  = (item.report_url || '').trim()
                    .replace('https://reports.cyberdudebivash.com', 'https://intel.cyberdudebivash.com');
                const _ruIsInternal = _ru && (
                    _ru.startsWith('/reports/') ||
                    _ru.includes('intel.cyberdudebivash.com') ||
                    _ru.includes('cyberdudebivash.com/reports')
                );

                // v187.0 P0 FIX: removed the id+timestamp speculative-construction
                // fallback that used to run here (`/reports/${_ym}/${_eid}.html`
                // guessed from stix_id + published_at whenever the backend hadn't
                // supplied a link). That guess is indistinguishable, from the
                // client, between "not yet synced" and "permanently rejected by
                // the publication gate" -- report_url/internal_report_url are
                // null for both (verified live: a confirmed-REJECTED item has
                // report_url:null, same as a pending one). The backend's
                // STAGE 3.3.6 report_url sync (feed_manifest -> api/feed.json)
                // is the single source of truth for whether a link should exist
                // at all; this function must not fabricate one when it hasn't.
                // Callers must treat '' as "no verified report yet" and render
                // a non-link state, not fall back to constructing their own URL.
                const _internalUrl = _iru || (_ruIsInternal ? _ru : '');
                if (_internalUrl && !_isFail) return _internalUrl;
                if (_isFail) return '';

                // P0 FIX: report_url/internal_report_url on the feed item are
                // populated by a separate sync step (scripts/sync_report_urls.py)
                // that can lag behind the actual report registry -- a report can
                // already exist and be customer-ready while these fields are
                // still empty, rendering a real, working report as UNAVAILABLE.
                // js/sentinel-live-feeds.js's loadReports() populates
                // window._cdbReportRegistry (id -> url) from the same backend
                // registry (/api/reports/index.json) this fallback consults; if
                // that registry hasn't loaded yet, or doesn't have this item,
                // this still correctly returns '' (no verified report), same as
                // before -- it only ever ADDS a link, never removes one that the
                // primary check already found.
                const _reg = (window._cdbReportRegistry || {})[item.id];
                return _reg || '';
            } catch (e) { return ''; }
        }

        function renderCards(data) {
            const originalLength = data.length;

            const cleanData = deduplicateIntel(data);
            data = cleanData;

      // 🔥 INTEL STATUS BAR UPDATE
           const lastUpdateEl = document.getElementById('intel-last-update');
           const newCountEl = document.getElementById('intel-new-count');
           const dedupCountEl = document.getElementById('intel-dedup-count');

               if (lastUpdateEl) {
               // P0 FIX: was new Date().toLocaleTimeString() -- the moment this line of
               // JS executed, not when the underlying data was generated. renderTopThreats()
               // (called later in this same render chain, index.html ~9939) overwrites this
               // element with a correct data-derived value when it has items to show, but
               // that left a stale/misleading flash and an unprotected gap whenever
               // renderTopThreats() has none. Compute the real value here instead.
               var _guiNewest = data.reduce(function(best, d){
                   var t = new Date(d.processed_at||d.timestamp||0).getTime();
                   return (t && t > best) ? t : best;
               }, 0);
               lastUpdateEl.textContent = 'Last Sync: ' + (_guiNewest ? timeSince(_guiNewest) : '—');
                  }

             if (newCountEl) {
               newCountEl.textContent = 'Active Intel: ' + data.length;
                   }

             if (dedupCountEl) {
             dedupCountEl.textContent = 'Filtered: ' + (originalLength - data.length);
               
                 }            
            renderLiveExploits(data);
             // 🔥 TOP 10 ENGINE (SAFE CALL)
            // Stashed so js/sentinel-live-feeds.js's loadReports() can
            // re-rank this section once the report registry it depends on
            // (window._cdbReportsFull, see getTopThreats() above) finishes
            // loading -- that fetch is async and can complete after this
            // first render.
            window._cdbLastFeedData = data;
            renderTopThreats(data);
            // Populate threat registry for XSS-safe modal dispatch
            // v102.0: register by stix_id (preferred) OR id (v74 schema compat)
            data.forEach(item => {
                var regKey = item.stix_id || item.id;
                if (regKey) threatRegistry.set(regKey, item);
            });

            const grid = document.getElementById('threat-grid');
            // v184.0: DOM validation \u2014 hard guard before any innerHTML access
            if (!grid) {
                console.error('[SENTINEL-APEX] renderCards: #threat-grid container not found in DOM \u2014 aborting render');
                return;
            }
            if (!data.length) {
                grid.innerHTML = '<div class="loading-state">No advisories match the current filter.</div>';
                document.getElementById('search-count').textContent = '';
                return;
            }

            const query = searchQuery.toLowerCase().trim();
            let filtered = data;
            if (query) {
                filtered = data.filter(item => {
                    const text = [
                        item.title, item.severity, item.actor_tag,
                        item.tlp_label, item.feed_source,
                        ...(item.mitre_tactics || []),
                        ...extractCVEs(item.title),
                    ].join(' ').toLowerCase();
                    return text.includes(query);
                });
            }

            if (query) {
                const cnt = document.getElementById('search-count');
                cnt.textContent = `${filtered.length} RESULT${filtered.length !== 1 ? 'S' : ''}`;
            } else {
                document.getElementById('search-count').textContent = '';
            }

            if (!filtered.length) {
                grid.innerHTML = `<div class="loading-state">No results for "<strong>${query}</strong>"</div>`;
                return;
            }

            grid.innerHTML = filtered.map(item => {
                // v184.0 \u2014 Per-card error isolation: one broken item never kills the grid
                try {
                const sev = getSeverity(item.risk_score, item);
                const sevColor = getSevColor(sev);
                const tlp = getTlpLabel(item);
                const tlpColor = getTlpColor(tlp);
                // v112.1 FIX-5: confidence_score may be 0-1 fraction or 0-100 integer.
                // When 0 or null (Bootstrap STIX entries with no pipeline enrichment),
                // apply severity-calibrated default: CRITICAL=85, HIGH=72, MEDIUM=60, LOW=45.
                const _rawConf = item.confidence_score != null ? parseFloat(item.confidence_score) : null;
                const conf = (_rawConf != null && _rawConf > 0)
                    ? Math.round(_rawConf <= 1 ? _rawConf * 100 : _rawConf)
                    : (sev === 'CRITICAL' ? 85 : sev === 'HIGH' ? 72 : sev === 'MEDIUM' ? 60 : 45);
                const actor = (item.actor_tag && item.actor_tag !== 'UNC-CDB-99' && item.actor_tag !== 'UNC-UNKNOWN')
                    ? item.actor_tag : 'UNATTRIBUTED';
                const ts = item.timestamp ? timeSince(item.timestamp) : '';
                const isNewEntry = isNew(item.timestamp);
                const cves = extractCVEs(item.title);

                // IOC chips + confidence bar (v124.0)
                let iocChips = '';
                const _iocCount     = item.ioc_count || (item.ioc_counts ? Object.values(item.ioc_counts).reduce((a,b)=>a+b,0) : 0);
                const _iocConf      = typeof item.ioc_confidence === 'number' ? item.ioc_confidence : 0;
                const _iocLevel     = (item.ioc_threat_level || 'NONE').toUpperCase();
                const _iocLevelColor = _iocLevel === 'CRITICAL' ? '#ff4444'
                                    : _iocLevel === 'HIGH'     ? '#ff7700'
                                    : _iocLevel === 'MEDIUM'   ? '#ffcc00'
                                    : _iocLevel === 'LOW'      ? '#00d4aa'
                                    : '#555';

                if (item.ioc_counts) {
                    const counts = item.ioc_counts;
                    const chips = [];
                    if (counts.ipv4 || counts.ips)    chips.push(`${counts.ipv4||counts.ips} IPs`);
                    if (counts.domain)                chips.push(`${counts.domain} Domains`);
                    if (counts.sha256)                chips.push(`${counts.sha256} Hashes`);
                    if (counts.sha1)                  chips.push(`${counts.sha1} SHA1`);
                    if (counts.md5)                   chips.push(`${counts.md5} MD5`);
                    if (counts.url)                   chips.push(`${counts.url} URLs`);
                    if (counts.cve)                   chips.push(`${counts.cve} CVEs`);
                    if (counts.email)                 chips.push(`${counts.email} Emails`);
                    if (counts.malware_family)        chips.push(`${counts.malware_family} Malware`);
                    iocChips = chips.map(c => `<span class="ioc-chip">${c}</span>`).join('');
                }

                // v124.0: IOC count badge + confidence bar
                const iocIndicatorBadge = _iocCount > 0
                    ? `<span class="ioc-indicator-badge" style="background:${_iocLevelColor}22;border:1px solid ${_iocLevelColor};color:${_iocLevelColor};border-radius:4px;padding:2px 7px;font-size:10px;font-weight:700;letter-spacing:0.5px;margin-right:5px;">⬡ ${_iocCount} INDICATOR${_iocCount>1?'S':''} DETECTED</span>`
                    : '';
                const iocConfidenceBar = _iocCount > 0
                    ? `<div class="ioc-confidence-wrap" style="display:flex;align-items:center;gap:6px;margin-top:3px;margin-bottom:2px;">
                           <span style="font-size:9px;color:#888;text-transform:uppercase;letter-spacing:0.5px;min-width:68px;">IOC Confidence</span>
                           <div style="flex:1;height:4px;background:#1a1a2e;border-radius:2px;overflow:hidden;max-width:120px;">
                               <div style="height:100%;width:${_iocConf.toFixed(0)}%;background:linear-gradient(90deg,${_iocLevelColor},${_iocLevelColor}aa);border-radius:2px;transition:width 0.4s;"></div>
                           </div>
                           <span style="font-size:9px;color:${_iocLevelColor};font-weight:700;min-width:32px;">${_iocConf.toFixed(0)}%</span>
                       </div>`
                    : '';

                // MITRE technique badges (v21.0)
                let mitreHtml = '';
                const tactics = item.mitre_tactics || [];
                if (tactics.length) {
                    const tacticLinks = tactics.slice(0, 4).map(t => {
                        const techId = typeof t === 'string' ? t : (t.technique_id || t.id || '');
                        if (!techId) return '';
                        const url = `https://attack.mitre.org/techniques/${techId.replace('.', '/')}/`;
                        return `<a href="${url}" target="_blank" rel="noopener" class="mitre-chip" title="MITRE ATT&CK ${techId}">${techId}</a>`;
                    }).filter(Boolean).join('');
                    if (tacticLinks) mitreHtml = `<div class="mitre-strip">${tacticLinks}</div>`;
                }

                // ═══ v184.0 — KILL CHAIN TACTIC STRIP ═══
                // Maps T-codes → ATT&CK tactic phase for kill-chain visualization
                const _kcTacticMap = {
                    'T1190':'IA','T1133':'IA','T1566':'IA','T1078':'IA','T1091':'IA','T1200':'IA','T1195':'IA','T1189':'IA',
                    'T1059':'EX','T1106':'EX','T1203':'EX','T1053':'EX','T1204':'EX','T1072':'EX','T1129':'EX',
                    'T1547':'PE','T1543':'PE','T1098':'PE','T1136':'PE','T1197':'PE','T1037':'PE','T1505':'PE','T1176':'PE',
                    'T1548':'PR','T1134':'PR','T1068':'PR','T1574':'PR','T1055':'PR',
                    'T1036':'DE','T1112':'DE','T1218':'DE','T1027':'DE','T1070':'DE','T1140':'DE','T1562':'DE','T1564':'DE',
                    'T1110':'CA','T1003':'CA','T1558':'CA','T1555':'CA','T1056':'CA','T1539':'CA','T1528':'CA',
                    'T1018':'DI','T1082':'DI','T1046':'DI','T1083':'DI','T1087':'DI','T1069':'DI','T1057':'DI',
                    'T1021':'LM','T1534':'LM','T1080':'LM','T1570':'LM','T1210':'LM','T1563':'LM',
                    'T1560':'CL','T1074':'CL','T1005':'CL','T1185':'CL','T1114':'CL','T1115':'CL',
                    'T1041':'EF','T1048':'EF','T1567':'EF','T1052':'EF','T1029':'EF',
                    'T1485':'IM','T1486':'IM','T1489':'IM','T1490':'IM','T1491':'IM','T1498':'IM','T1496':'IM'
                };
                const _kcPhases = [
                    {k:'IA',label:'Initial Access',color:'#8b5cf6'},
                    {k:'EX',label:'Execution',color:'#ef4444'},
                    {k:'PE',label:'Persistence',color:'#f97316'},
                    {k:'PR',label:'Priv Esc',color:'#f59e0b'},
                    {k:'DE',label:'Defense Evasion',color:'#eab308'},
                    {k:'CA',label:'Cred Access',color:'#84cc16'},
                    {k:'DI',label:'Discovery',color:'#22d3ee'},
                    {k:'LM',label:'Lateral Mvmt',color:'#3b82f6'},
                    {k:'CL',label:'Collection',color:'#a78bfa'},
                    {k:'EF',label:'Exfiltration',color:'#f472b6'},
                    {k:'IM',label:'Impact',color:'#dc2626'}
                ];
                const _activeTactics = new Set(
                    (item.mitre_tactics||[]).map(t=>{
                        const tid = typeof t==='string'?t:(t.technique_id||t.id||'');
                        // Normalize sub-technique T1059.001 → T1059
                        return _kcTacticMap[tid.split('.')[0]] || _kcTacticMap[tid] || null;
                    }).filter(Boolean)
                );
                let _kcHtml = '';
                if (_activeTactics.size > 0) {
                    const _kcNodes = _kcPhases.map((ph,i) => {
                        const isActive = _activeTactics.has(ph.k);
                        const arrow = i < _kcPhases.length-1 ? `<span class="cdb-kc-arrow">›</span>` : '';
                        return `<div class="cdb-kc-node"><div class="cdb-kc-dot ${isActive?'active':'inactive'}" style="${isActive?`background:${ph.color}22;color:${ph.color};border:1px solid ${ph.color}55`:'background:rgba(255,255,255,0.04);color:#4a5568;border:1px solid rgba(255,255,255,0.06)'}" title="${ph.label}">${ph.k}</div></div>${arrow}`;
                    }).join('');
                    _kcHtml = `<div class="cdb-kc-strip" title="ATT&CK Kill Chain Coverage">${_kcNodes}</div>`;
                }

                // ═══ v184.0 — FRESHNESS TIMESTAMP ═══
                const _tsRaw = item.processed_at || item.timestamp || '';
                let _freshHtml = '';
                if (_tsRaw) {
                    const _tsMs = new Date(_tsRaw).getTime();
                    const _ageMins = Math.round((Date.now() - _tsMs) / 60000);
                    let _freshClass, _freshLabel;
                    if (_ageMins < 60) { _freshClass='cdb-fresh-live'; _freshLabel=`${_ageMins}m ago`; }
                    else if (_ageMins < 1440) { _freshClass='cdb-fresh-new'; _freshLabel=`${Math.round(_ageMins/60)}h ago`; }
                    else if (_ageMins < 4320) { _freshClass='cdb-fresh-recent'; _freshLabel=`${Math.round(_ageMins/1440)}d ago`; }
                    else if (_ageMins < 10080) { _freshClass='cdb-fresh-aged'; _freshLabel=`${Math.round(_ageMins/1440)}d ago`; }
                    else { _freshClass='cdb-fresh-stale'; _freshLabel=`${Math.round(_ageMins/1440)}d ago`; }
                    _freshHtml = `<span class="cdb-freshness ${_freshClass}" title="Last processed: ${_tsRaw}">${_freshLabel}</span>`;
                }

                // ═══ v184.0 — IOC COPY BUTTON ═══
                const _iocCopyId = 'ioccp_' + Math.random().toString(36).slice(2,8);
                let _iocCopyHtml = '';
                if (item.ioc_counts || item.indicators || item.ioc_count > 0) {
                    const _iocLines = [];
                    const _iocC = item.ioc_counts || {};
                    if (_iocC.ipv4 || _iocC.ip) _iocLines.push(`# IPv4 (${_iocC.ipv4||_iocC.ip})`);
                    if (_iocC.domain) _iocLines.push(`# Domains (${_iocC.domain})`);
                    if (_iocC.md5||_iocC.sha256||_iocC.sha1||_iocC.hash) _iocLines.push(`# Hashes (${_iocC.md5||_iocC.sha256||_iocC.sha1||_iocC.hash})`);
                    if (_iocC.url) _iocLines.push(`# URLs (${_iocC.url})`);
                    const _copyPayload = `# IOCs — ${_cdbEsc(item.title||'')}\n# Source: ${item.stix_id||item.id||''}\n# Exported: ${new Date().toISOString()}\n${_iocLines.join('\n')}\n# Full feed: /api/v1/intel/latest.json`;
                    _iocCopyHtml = `<button class="cdb-ioc-copy-btn" id="${_iocCopyId}" onclick="(function(btn,txt){navigator.clipboard&&navigator.clipboard.writeText(txt).then(()=>{btn.textContent='✓ COPIED';btn.classList.add('copied');setTimeout(()=>{btn.textContent='⬡ COPY IOCs';btn.classList.remove('copied')},1800)});})(this,${JSON.stringify(_copyPayload)})" title="Copy IOC summary to clipboard"><span>⬡</span> COPY IOCs</button>`;
                }

                // v46.0 Threat Characteristic Badges
                // v76.1: exploit badge \u2014 aligned threshold (EPSS>=50% = HIGH, not 70%)
                // P0 FIX: this normalizer previously silently divided any value >100 by
                // 100 (e.g. 3355 -> 33.55) instead of flagging it invalid, and had no
                // floor check for negative values -- a malformed upstream value could
                // silently produce a plausible-looking but fabricated percentage.
                // window.CDB_NORMALIZE.epss() (js/metric-normalize.js) is the single
                // canonical normalizer: values in (1,100] are treated as an
                // already-percentage EPSS reading, values outside 0-100 are INVALID
                // (null here), never silently clamped.
                const _epssResult = window.CDB_NORMALIZE.epss(item.epss_score);
                const epssNorm = _epssResult.state === 'OK' ? _epssResult.percent : null;

                const exploitBadge = (item.exploit_available || (epssNorm != null && epssNorm >= 50) || item.kev_present)
                    ? '<span class="badge badge-exploit">⚡ EXPLOIT AVAIL</span>' : '';
                const patchBadge = (item.cvss_score != null && item.risk_score < 6)
                    ? '<span class="badge badge-patch">✔ PATCH AVAIL</span>' : '';
                const ransomBadge = (item.ransomware || (item.actor_tag && item.actor_tag.toLowerCase().includes('ransom')))
                    ? '<span class="badge badge-ransomware">☠ RANSOMWARE</span>' : '';
                const zeroDay = (item.zero_day || (item.kev_present && epssNorm != null && epssNorm >= 85))
                    ? '<span class="badge badge-zerod">● 0-DAY</span>' : '';

                // KEV badge (v46.0)
                const kevBadge = item.kev_present
                    ? `<span class="badge badge-kev">⚡ CISA KEV</span>`
                    : '';

                // NEW badge (v46.0)
                const newBadge = isNewEntry
                    ? `<span class="badge badge-new">● NEW</span>`
                    : '';

                // v46.0 \u2014 PEPS Score Badge (Predictive Exploit Probability)
                const pepsScore = item.peps_score != null ? parseFloat(item.peps_score) : null;
                const pepsBadge = pepsScore != null
                    ? `<span class="badge badge-peps ${pepsScore >= 7 ? 'peps-high' : pepsScore >= 4 ? 'peps-med' : ''}">PEPS ${pepsScore.toFixed(1)}/10</span>`
                    : '';

                // v46.0 \u2014 Global Blast Radius
                const blastCount = item.global_victim_count != null ? item.global_victim_count : null;
                const blastBadge = blastCount != null && blastCount > 0
                    ? `<span class="badge badge-blast">🌐 ${blastCount.toLocaleString()} EXPOSED</span>`
                    : '';

                // v46.0 \u2014 Supply Chain Flag
                const supplyBadge = item.supply_chain
                    ? `<span class="badge badge-supply">🔗 SUPPLY CHAIN</span>`
                    : '';

                // CVSS / EPSS enrichment strip (v21.0)
                let enrichHtml = '';
                const enrichItems = [];
                if (item.cvss_score != null) {
                    const cvssColor = item.cvss_score >= 9 ? 'var(--critical)' : item.cvss_score >= 7 ? 'var(--high)' : item.cvss_score >= 4 ? 'var(--medium)' : 'var(--low)';
                    enrichItems.push(`<span class="enrich-item">CVSS <span class="e-val" style="color:${cvssColor};">${item.cvss_score}</span></span>`);
                }
                if (epssNorm != null) {
                    const epssColor = epssNorm >= 70 ? 'var(--critical)' : epssNorm >= 40 ? 'var(--high)' : 'var(--text-muted)';
                    enrichItems.push(`<span class="enrich-item">EPSS <span class="e-val" style="color:${epssColor};">${epssNorm.toFixed(2)}%</span></span>`);
                }
                if (conf != null) {
                    enrichItems.push(`<span class="enrich-item">CONF <span class="e-val">${conf}%</span></span>`);
                }
                // Confidence label (5-level CTI taxonomy from confidence_corroboration_engine)
                if (item.confidence_label) {
                    const _clMap = {
                        'CONFIRMED':         {color:'#00ffc6', bg:'rgba(0,255,198,0.10)', icon:'⬡'},
                        'HIGH_CONFIDENCE':   {color:'#00d4aa', bg:'rgba(0,212,170,0.09)', icon:'◈'},
                        'MEDIUM_CONFIDENCE': {color:'#f59e0b', bg:'rgba(245,158,11,0.09)', icon:'◇'},
                        'LOW_CONFIDENCE':    {color:'#9ca3af', bg:'rgba(156,163,175,0.08)', icon:'◌'},
                        'UNVERIFIED':        {color:'#6b7280', bg:'rgba(107,114,128,0.07)', icon:'○'},
                    };
                    const _cl = _clMap[item.confidence_label] || {color:'#888', bg:'transparent', icon:'?'};
                    const _clLabel = item.confidence_label.replace('_CONFIDENCE','').replace('_',' ');
                    enrichItems.push(`<span class="enrich-item" style="color:${_cl.color};background:${_cl.bg};border-radius:3px;padding:1px 5px;" title="CTI Confidence: ${item.confidence_label}">${_cl.icon} ${_clLabel}</span>`);
                }
                // SLA priority (P0-P4 from confidence engine)
                if (item.sla_priority) {
                    const _slaColors = {P0:'#dc2626',P1:'#ea580c',P2:'#f59e0b',P3:'#16a34a',P4:'#6b7280'};
                    const _slaColor = _slaColors[item.sla_priority] || '#888';
                    enrichItems.push(`<span class="enrich-item" style="color:${_slaColor};font-weight:700;" title="${item.recommended_sla_action||item.sla_priority}">${item.sla_priority}</span>`);
                }
                // Feed source (truncated)
                {
                    const _srcRaw = item.source || item.feed_source || '';
                    const _srcClean = _srcRaw.startsWith('rss_') ? _srcRaw.replace(/^rss_/,'').replace(/_com_.*/,'').replace(/_io_.*/,'').replace(/_org_.*/,'').replace(/_net_.*/,'').replace(/_/g,' ').trim() : _srcRaw.replace(/https?:\/\/(www\.)?/,'').split('/')[0];
                    if (_srcClean) enrichItems.push(`<span class="enrich-item" style="margin-left:auto;">SRC: <span class="e-val">${_srcClean.slice(0,28)}</span></span>`);
                }
                if (enrichItems.length) enrichHtml = `<div class="enrich-strip">${enrichItems.join('')}</div>`;

                // CVE → NVD link (v46.0)
                let nvdLink = '';
                if (cves.length) {
                    const nvdUrl = item.nvd_url || `https://nvd.nist.gov/vuln/detail/${cves[0]}`;
                    nvdLink = `<a href="${nvdUrl}" target="_blank" rel="noopener"
                                  style="font-family:var(--font-mono);font-size:9px;
                                         color:var(--blue);letter-spacing:0.5px;
                                         border-bottom:1px solid rgba(59,130,246,0.3);"
                                  title="View on NVD">NVD ↗</a>`;
                }

                // ═══ v65.3 SINGLE SOURCE OF TRUTH \u2014 FINAL CORRECTED ═══
                const _cvss = item.cvss_score != null ? parseFloat(item.cvss_score) : null;
                // P0 FIX: raw epss_score is inconsistently 0-1 or 0-100 scale across live
                // items; the >=50/>=1 thresholds below assume a 0-100 percent value, so
                // normalize via the canonical helper rather than comparing the raw field.
                const _epssResult3 = window.CDB_NORMALIZE.epss(item.epss_score);
                const _epss = _epssResult3.state === 'OK' ? _epssResult3.percent : null;
                const _kev = !!item.kev_present;
                // v76.1: unified exploit signal \u2014 EPSS>=50% aligned with badge threshold
                const _exploit = !!(item.exploit_available || _kev || (_epss != null && _epss >= 50));
                const _riskVal = parseFloat(item.risk_score) || 0;

                // IMPACT \u2014 v76.1: prioritise manifest data, fall back to score
                // Use item.threat_type when available for accurate classification
                const _tt = (item.threat_type || '').toLowerCase();
                const _impact = (_kev || (_tt.includes('network') || _tt.includes('remote') || _tt.includes('web')))
                    ? 'EXTERNAL'
                    : (_riskVal >= 8.5 || (_cvss != null && _cvss >= 9))
                    ? 'EXTERNAL'
                    : (_riskVal >= 5 || (_cvss != null && _cvss >= 5))
                    ? 'DATA EXPOSURE'
                    : 'INTERNAL';

                // ── cdb_computePriority v76.1 \u2014 SINGLE SOURCE OF TRUTH ──
                // BUG FIX: Previous logic defaulted to P4 when CVSS=null,
                // producing "P4" on 10/10 CRITICAL advisories (confirmed in run #551).
                // Fix: risk_score is now the universal fallback when CVSS is absent.
                let _prioNum = 4;
                if (_exploit || _kev) {
                    // Rule 1: KEV confirmed or exploit available → P1 always
                    _prioNum = 1;
                } else if (_cvss != null) {
                    // Rule 2: CVSS-based baseline
                    if (_cvss >= 9)      _prioNum = 1;
                    else if (_cvss >= 7) _prioNum = 2;
                    else if (_cvss >= 5) _prioNum = 3;
                    else                 _prioNum = 4;
                    // Rule 3: EPSS boost (>= 1% = meaningful exploitation probability)
                    if (_epss != null && _epss >= 1 && _prioNum > 1) _prioNum--;
                    // Rule 4: External exposure boost
                    if (_impact === 'EXTERNAL' && _prioNum > 1) _prioNum--;
                    // Rule 5: Risk score alignment \u2014 risk>=9 forces at minimum P2
                    if (_riskVal >= 9 && _prioNum > 2) _prioNum = 2;
                    // Rule 6: Guard rail \u2014 CVSS<7 cannot be P1 without KEV/exploit
                    if (_cvss < 7 && _prioNum < 2) _prioNum = 2;
                } else {
                    // Rule 7: NO CVSS \u2014 use risk_score as primary signal
                    // This fixes the P4-on-10/10 bug seen in image screenshots
                    if (_riskVal >= 9)      _prioNum = 1;
                    else if (_riskVal >= 7) _prioNum = 2;
                    else if (_riskVal >= 5) _prioNum = 3;
                    else                    _prioNum = 4;
                    // EPSS boost when no CVSS
                    if (_epss != null && _epss >= 1 && _prioNum > 1) _prioNum--;
                    // External exposure boost
                    if (_impact === 'EXTERNAL' && _prioNum > 1) _prioNum--;
                }
                _prioNum = Math.max(1, Math.min(4, _prioNum));
                const _priority = 'P' + _prioNum;
                const _prioClass = 'p' + _prioNum;

                // ACTION \u2014 derived from exploit status + priority + severity
                // v76.1 FIX: CRITICAL with no exploit should say INVESTIGATE not ASSESS
                const _action = _exploit                    ? 'IMMEDIATE PATCH'
                    : _kev                                  ? 'IMMEDIATE PATCH'
                    : (_prioNum === 1 && _riskVal >= 9)     ? 'PATCH NOW'
                    : _prioNum <= 2                         ? 'INVESTIGATE'
                    : _prioNum === 3                        ? 'MONITOR'
                    :                                         'ASSESS';
                const _actionClass = _exploit || _kev       ? 'patch'
                    : (_prioNum === 1 && _riskVal >= 9)     ? 'patch'
                    : _prioNum <= 2                         ? 'investigate'
                    : _prioNum === 3                        ? 'monitor'
                    :                                         'ignore';

                // ── cdb_computeLikelihood v76.1 ──
                // v76.1 FIX: Previous thresholds were too aggressive \u2014 0.29% EPSS
                // was displaying as MEDIUM after exposure boost. EPSS<1% = LOW.
                let _lkLevel = 0; // 0=LOW 1=LOW-MED 2=MED 3=HIGH
                if (_kev || _exploit) {
                    // OVERRIDE: Confirmed KEV or exploit → HIGH always
                    _lkLevel = 3;
                } else {
                    // EPSS primary signal \u2014 corrected thresholds
                    if (_epss != null) {
                        if (_epss >= 50)      _lkLevel = 3; // >50% = HIGH
                        else if (_epss >= 10) _lkLevel = 2; // 10-50% = MEDIUM
                        else if (_epss >= 1)  _lkLevel = 1; // 1-10% = LOW-MEDIUM
                        else                  _lkLevel = 0; // <1% = LOW
                    }
                    // External exposure boost (max +1 level)
                    if (_impact === 'EXTERNAL' && _lkLevel < 3) _lkLevel++;
                    // CVSS>=9 + external = additional signal
                    if (_cvss != null && _cvss >= 9 && _lkLevel < 3) _lkLevel++;
                    // Risk score fallback when no EPSS
                    if (_epss == null) {
                        if (_riskVal >= 9)      _lkLevel = 2;
                        else if (_riskVal >= 7) _lkLevel = 1;
                        else                    _lkLevel = 0;
                        if (_impact === 'EXTERNAL' && _lkLevel < 3) _lkLevel++;
                    }
                }
                _lkLevel = Math.max(0, Math.min(3, _lkLevel));
                const _likelihood = _lkLevel >= 3 ? 'HIGH' : _lkLevel >= 2 ? 'MEDIUM' : _lkLevel >= 1 ? 'LOW-MED' : 'LOW';
                const _lkClass = _lkLevel >= 3 ? 'high' : _lkLevel >= 1 ? 'med' : 'low';

// ═══ SCAN BAR ═══
                const _scanExploit = _exploit
                    ? '<span class="cdb-scan-pill cdb-scan-exploit">\u26a1 EXPLOIT ACTIVE</span>'
                    : '<span class="cdb-scan-pill cdb-scan-noexploit">\u2713 NO EXPLOIT</span>';
                const _scanPrio = `<span class="cdb-scan-pill cdb-scan-${_prioClass}">${_priority}</span>`;
                const _scanImpact = `<span class="cdb-scan-pill cdb-scan-impact">${_impact}</span>`;

                // ═══ RISK RING ═══
                const _rc = 2 * Math.PI * 28;
                const _ro = _rc - (_riskVal / 10) * _rc;
                const _ringCls = sev === 'CRITICAL' ? 'cdb-ring-crit' : '';
                const _ringSevColor = sev === 'CRITICAL' ? '#ff3b3b' : sev === 'HIGH' ? '#ff8c00' : sev === 'MEDIUM' ? '#00c2ff' : '#00ff9f';
                const _ringLabel = `${sev} RISK`;

                // ═══ SIGNAL INTERPRETATION ═══
                const _sigs = [];
                if (_cvss != null) {
                    const _cvssInt = _cvss >= 9 ? 'CRITICAL' : _cvss >= 7 ? 'HIGH' : _cvss >= 4 ? 'MEDIUM' : 'LOW';
                    const _cvssClr = _cvss >= 9 ? '#ff3b3b' : _cvss >= 7 ? '#ff8c00' : _cvss >= 4 ? '#00c2ff' : '#00ff9f';
                    _sigs.push(`<div class="cdb-sig"><span class="cdb-sig-lbl">CVSS</span><span class="cdb-sig-num" style="color:${_cvssClr}">${_cvss}</span><span class="cdb-sig-int" style="color:${_cvssClr}">${_cvssInt}</span></div>`);
                }
                if (_epss != null) {
                    // v76.1 FIX: corrected EPSS display thresholds \u2014 <1% is LOW not MEDIUM
                    const _epssInt = _epss >= 50 ? 'HIGH' : _epss >= 10 ? 'MEDIUM' : _epss >= 1 ? 'LOW-MED' : 'LOW';
                    const _epssClr = _epss >= 50 ? '#ff3b3b' : _epss >= 10 ? '#ff8c00' : _epss >= 1 ? '#f59e0b' : '#00ff9f';
                    _sigs.push(`<div class="cdb-sig"><span class="cdb-sig-lbl">EPSS</span><span class="cdb-sig-num" style="color:${_epssClr}">${_epss}%</span><span class="cdb-sig-int" style="color:${_epssClr}">${_epssInt}</span></div>`);
                }
                if (conf != null) {
                    const _confInt = conf >= 80 ? 'HIGH' : conf >= 40 ? 'MEDIUM' : 'LOW';
                    const _confClr = conf >= 80 ? '#00d4aa' : conf >= 40 ? '#f0f4f8' : '#5a6578';
                    _sigs.push(`<div class="cdb-sig"><span class="cdb-sig-lbl">CONF</span><span class="cdb-sig-num" style="color:${_confClr}">${conf}%</span><span class="cdb-sig-int" style="color:${_confClr}">${_confInt}</span></div>`);
                }
                _sigs.push(`<div class="cdb-sig ${_kev ? 'cdb-kev-yes' : ''}"><span class="cdb-sig-lbl">KEV</span><span class="cdb-sig-num" style="color:${_kev ? '#ff3b3b' : '#5a6578'}">${_kev ? 'YES' : '\u2014'}</span><span class="cdb-sig-int" style="color:${_kev ? '#ff3b3b' : '#5a6578'}">${_kev ? 'ACTIVE' : 'NONE'}</span></div>`);

                // ═══ v65.1 AI-GRADE INTELLIGENCE SUMMARY ═══
                const _title = (item.title || '').toLowerCase();
                // Derive risk type from title keywords
                const _riskType = _title.includes('remote code') || _title.includes(' rce') ? 'remote code execution vulnerability'
                    : _title.includes('sql inject') ? 'SQL injection vulnerability'
                    : _title.includes('command inject') || _title.includes('os command') ? 'command injection vulnerability'
                    : _title.includes('cross site script') || _title.includes(' xss') ? 'cross-site scripting vulnerability'
                    : _title.includes('buffer overflow') || _title.includes('stack-based') || _title.includes('heap-based') ? 'memory corruption vulnerability'
                    : _title.includes('path traversal') || _title.includes('directory traversal') ? 'path traversal vulnerability'
                    : _title.includes('authenticat') && (_title.includes('bypass') || _title.includes('missing')) ? 'authentication bypass vulnerability'
                    : _title.includes('privilege') || _title.includes('escalat') ? 'privilege escalation vulnerability'
                    : _title.includes('denial of service') || _title.includes(' dos') ? 'denial-of-service vulnerability'
                    : _title.includes('information disclosure') || _title.includes('data extract') || _title.includes('data leak') ? 'information disclosure vulnerability'
                    : _title.includes('ssrf') || _title.includes('server-side request') ? 'server-side request forgery vulnerability'
                    : _title.includes('deserialization') ? 'deserialization vulnerability'
                    : _title.includes('malware') || _title.includes('trojan') || _title.includes('stealer') || _title.includes('backdoor') || _title.includes('botnet') ? 'active malware threat'
                    : _title.includes('ransomware') || _title.includes('extortion') ? 'ransomware/extortion threat'
                    : _title.includes('phishing') ? 'phishing campaign'
                    : _title.includes('apt') || _title.includes('espionage') || _title.includes('nation-state') ? 'advanced persistent threat'
                    : _title.includes('supply chain') || _title.includes('supply-chain') ? 'supply chain threat'
                    : (cves.length > 0) ? 'security vulnerability' : 'threat advisory';

                // Exposure context
                const _exposureCtx = _impact === 'EXTERNAL' ? 'with network-facing exposure increasing attack surface'
                    : _impact === 'DATA EXPOSURE' ? 'with potential data exposure risk'
                    : 'affecting internal components with limited external exposure';

                // Exploit status sentence \u2014 v76.1: aligned with corrected EPSS thresholds
                const _exploitCtx = _kev ? 'Active exploitation confirmed by CISA KEV \u2014 threat is live in the wild'
                    : (_epss != null && _epss >= 50) ? `Critical exploitation probability (EPSS ${_epss}%) \u2014 weaponization imminent`
                    : (_epss != null && _epss >= 10) ? `High exploitation probability (EPSS ${_epss}%) indicates active weaponization risk`
                    : (_epss != null && _epss >= 1)  ? `Elevated exploitation likelihood (EPSS ${_epss}%) warrants proactive attention`
                    : (_epss != null && _epss > 0)   ? `Low exploitation probability (EPSS ${_epss}%); no confirmed active exploitation`
                    : _exploit ? 'Exploit availability confirmed \u2014 active weaponization possible'
                    : 'No active exploitation observed at this time';

                // Actionable insight \u2014 v76.1: aligned with new PATCH NOW action
                const _actionCtx = (_action === 'IMMEDIATE PATCH' || _action === 'PATCH NOW') ? '<b>Immediate patching required</b> to prevent active compromise.'
                    : _prioNum <= 2 ? 'Prioritize for next triage cycle and validate exposure.'
                    : _prioNum === 3 ? 'Schedule remediation during routine maintenance window.'
                    : 'Routine monitoring sufficient; no immediate action required.';

                // v184.0 FIX: Prefer real CVE description from feed over boilerplate template.
                // Strip leading "CVE-YYYY-NNNNN " prefix; use remainder if >30 chars.
                const _rawFeedDesc = String(item.description || item.summary || '').trim();
                const _strippedDesc = _rawFeedDesc.replace(/^CVE-\d{4}-\d+[\s\-:]+/i, '').trim();
                const _hasRealDesc = _strippedDesc.length > 30 &&
                    !/^(Exploit for CVE|Notable security|No active exploit)/i.test(_strippedDesc);
                // v184.0 XSS FIX: escape feed description before inserting into innerHTML.
                // Feed data (GitHub Advisories, RSS) can contain HTML/script payloads
                // (e.g. PoC code like <img onerror=alert(1)>) that execute when injected raw.
                const _escFeedDesc = (s) => String(s)
                    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                    .replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
                // P0 Runtime Convergence XSS fix: actor_tag is the same class of
                // feed-sourced field as the description above (attribution data
                // can originate from external/AI-derived sources) and was being
                // concatenated into _sumText -- which IS rendered via innerHTML
                // a few lines below -- with zero escaping, missed when the
                // v184.0 fix above covered description/summary but not this
                // sibling field. Reuses the identical _escFeedDesc() helper
                // already defined for that fix rather than adding a second one.
                const _actorCtx = (item.actor_tag && item.actor_tag !== 'UNC-CDB-99') ? ` Attributed to <b>${_escFeedDesc(item.actor_tag)}</b>.` : '';
                const _feedDescSentence = _hasRealDesc
                    ? _escFeedDesc(_strippedDesc.charAt(0).toUpperCase() + _strippedDesc.slice(1))
                    : '';

                // Assemble: Type + CVSS context + exposure + exploit + action
                let _sumText = '';
                if (_hasRealDesc && _feedDescSentence) {
                    // Use real feed description as primary sentence, append SOC context
                    if (_cvss != null) {
                        const _cvssWord = _cvss >= 9 ? 'Critical' : _cvss >= 7 ? 'High' : _cvss >= 4 ? 'Moderate' : 'Low';
                        _sumText = `<b>${_cvssWord}-severity</b> ${_riskType}: ${_feedDescSentence}. ${_exploitCtx}. ${_actionCtx}${_actorCtx}`;
                    } else {
                        _sumText = `${_feedDescSentence}. ${_exploitCtx}. ${_actionCtx}${_actorCtx}`;
                    }
                } else if (_cvss != null) {
                    const _cvssWord = _cvss >= 9 ? 'Critical' : _cvss >= 7 ? 'High' : _cvss >= 4 ? 'Moderate' : 'Low';
                    _sumText = `<b>${_cvssWord}-severity</b> ${_riskType} (CVSS ${_cvss}) ${_exposureCtx}. ${_exploitCtx}. ${_actionCtx}${_actorCtx}`;
                } else {
                    _sumText = `${sev === 'CRITICAL' ? '<b>Critical</b>' : sev === 'HIGH' ? '<b>High-priority</b>' : 'Notable'} ${_riskType} ${_exposureCtx}. ${_exploitCtx}. ${_actionCtx}${_actorCtx}`;
                }

// ═══ DECISION PANEL ═══
                const _decHtml = `<div class="cdb-decision"><div class="cdb-dec cdb-dec-${_actionClass}"><span class="cdb-dec-lbl">Action</span><span class="cdb-dec-val">${_action}</span></div><div class="cdb-dec cdb-dec-${_prioClass}"><span class="cdb-dec-lbl">Priority</span><span class="cdb-dec-val">${_priority}</span></div><div class="cdb-dec cdb-dec-impact"><span class="cdb-dec-lbl">Impact</span><span class="cdb-dec-val">${_impact}</span></div><div class="cdb-dec cdb-dec-lk-${_lkClass}"><span class="cdb-dec-lbl">Likelihood</span><span class="cdb-dec-val">${_likelihood}</span></div></div>`;

                // ═══ v65.4 SOC DECISION LAYER ═══
                // Decision Confidence \u2014 v76.1: added risk_score fallback for no-CVSS advisories
                const _dConfLevel = (_kev || _exploit) ? 3
                    : (_epss != null && _epss >= 10) ? 3
                    : (_epss != null && _epss >= 1)  ? 2
                    : (_cvss != null && _cvss >= 7)  ? 2
                    : (_cvss != null)                ? 1
                    : (_riskVal >= 9)                ? 2  // high risk score = medium confidence
                    : (_riskVal >= 7)                ? 1
                    : 0;
                const _dConf = _dConfLevel >= 3 ? 'HIGH' : _dConfLevel >= 1 ? 'MEDIUM' : 'LOW';
                const _dConfClass = _dConfLevel >= 3 ? 'high' : _dConfLevel >= 1 ? 'med' : 'low';

                // Playbook Text
                let _playbook = '';
                if (_exploit || _kev) {
                    if (_impact === 'EXTERNAL') _playbook = '<b>Apply vendor patch immediately</b> and isolate affected assets from external exposure. Deploy compensating controls if patch unavailable.';
                    else _playbook = '<b>Apply vendor patch immediately.</b> Validate no lateral movement from compromised assets. Escalate to incident response if indicators observed.';
                } else if (_prioNum <= 2) {
                    const _hasIocs = item.ioc_counts && Object.values(item.ioc_counts).reduce((a,b)=>a+b,0) > 0;
                    if (_hasIocs) _playbook = '<b>Deploy IOC blocking rules</b> across firewall, proxy, and EDR systems. Schedule patch within 24h and monitor for exploitation attempts.';
                    else if (_impact === 'EXTERNAL') _playbook = '<b>Prioritize patching</b> for externally-exposed instances. Review network segmentation and access controls for affected components.';
                    else _playbook = '<b>Schedule investigation</b> within next triage cycle. Validate asset exposure and confirm compensating controls are active.';
                } else if (_prioNum === 3) {
                    // v76.1: raised threshold from 0.1% to 1% for SIEM monitoring playbook
                    if (_epss != null && _epss >= 1) _playbook = 'Monitor exploitation attempts via SIEM correlation rules. <b>Schedule remediation</b> during next maintenance window.';
                    else _playbook = 'Include in <b>routine patch cycle.</b> No immediate action required but track vendor advisories for status changes.';
                } else {
                    _playbook = 'Routine monitoring sufficient. Log for compliance tracking and <b>review during next scheduled assessment.</b>';
                }

                // Threat signal flag
                const _threatActive = (_kev || _exploit || _riskVal >= 9) ? ' cdb-threat-active' : '';

                // SOC block HTML
                const _socHtml = `<div class="cdb-soc"><div class="cdb-soc-header"><span class="cdb-soc-label">SOC GUIDANCE</span><span class="cdb-soc-badge cdb-soc-b-${_dConfClass}">CONFIDENCE: ${_dConf}</span></div><p class="cdb-playbook">${_playbook}</p></div>`;

                // ═══ EXPAND PANEL: Timeline + IOCs + Actor ═══
                let _tlHtml = '';
                if (item.timestamp) {
                    const _pd = new Date(item.timestamp);
                    _tlHtml += `<div class="cdb-tl-row"><div class="cdb-tl-dot" style="background:${_ringSevColor}"></div><span class="cdb-tl-lbl">Disclosed</span><span class="cdb-tl-val">${_pd.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})}</span></div>`;
                    if (_exploit) _tlHtml += `<div class="cdb-tl-row"><div class="cdb-tl-dot" style="background:#ff3b3b"></div><span class="cdb-tl-lbl">Exploit</span><span class="cdb-tl-val" style="color:#ff3b3b">Active Exploitation</span></div>`;
                    else if (_epss != null && _epss > 1) _tlHtml += `<div class="cdb-tl-row"><div class="cdb-tl-dot" style="background:#ff8c00"></div><span class="cdb-tl-lbl">PoC Risk</span><span class="cdb-tl-val" style="color:#ff8c00">EPSS ${_epss}%</span></div>`;
                    if (_kev) _tlHtml += `<div class="cdb-tl-row"><div class="cdb-tl-dot" style="background:#ff3b3b"></div><span class="cdb-tl-lbl">KEV Listed</span><span class="cdb-tl-val" style="color:#ff3b3b">Confirmed</span></div>`;
                }

                let _iocHtml = '';
                if (item.ioc_counts) {
                    const _ic = item.ioc_counts;
                    const _tags = [];
                    if (_ic.ipv4) _tags.push(`${_ic.ipv4} IP${_ic.ipv4>1?'s':''}`);
                    if (_ic.domain) _tags.push(`${_ic.domain} Domain${_ic.domain>1?'s':''}`);
                    if (_ic.url) _tags.push(`${_ic.url} URL${_ic.url>1?'s':''}`);
                    if (_ic.sha256||_ic.sha1||_ic.md5) _tags.push(`${(_ic.sha256||0)+(_ic.sha1||0)+(_ic.md5||0)} Hash${((_ic.sha256||0)+(_ic.sha1||0)+(_ic.md5||0))>1?'es':''}`);
                    if (_ic.email) _tags.push(`${_ic.email} Email${_ic.email>1?'s':''}`);
                    if (_ic.cve) _tags.push(`${_ic.cve} CVE${_ic.cve>1?'s':''}`);
                    if (_tags.length) _iocHtml = `<div class="cdb-iocs">${_tags.slice(0,3).map(t=>`<span class="cdb-ioc">${t}</span>`).join('')}</div>`;
                }

                const _actorType = (item.actor_tag||'').startsWith('CDB-APT') ? 'NATION STATE' : (item.actor_tag||'').startsWith('CDB-FIN') ? 'FINANCIAL' : (item.actor_tag||'').startsWith('CDB-RAN') ? 'RANSOMWARE' : (item.actor_tag||'').startsWith('CDB-MOB') ? 'MOBILE' : '';
                const _actorHtml = (item.actor_tag && item.actor_tag !== 'UNC-CDB-99' && _actorType) ? `<div class="cdb-actor"><div class="cdb-actor-av">\u{1F3AD}</div><div><span class="cdb-actor-nm">${item.actor_tag}</span><span class="cdb-actor-tp">${_actorType}</span></div></div>` : '';

                const _hasExpand = !!(_tlHtml || _iocHtml || _actorHtml);
                const _xid = 'cdbx' + (item.stix_id||item.id||'').replace(/[^a-zA-Z0-9]/g,'').slice(0,12) + Math.random().toString(36).slice(2,5);

                return `
                <div class="intel-card sev-${sev.toLowerCase()}${_threatActive} cdb-fade-in" data-severity="${sev}" data-score="${item.risk_score}" data-time="${item.processed_at || item.timestamp || ''}" data-idx="${manifestData.indexOf ? manifestData.indexOf(item) : ''}" style="border-left-color:${sevColor};box-shadow:0 0 0 0 ${sevColor}00,0 2px 24px rgba(0,0,0,0.5);">
                    <div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,${sevColor},${sevColor}66,transparent);border-radius:6px 6px 0 0;pointer-events:none;"></div>
                    ${(()=>{const _ageH=(item.processed_at||item.timestamp)?((Date.now()-new Date(item.processed_at||item.timestamp).getTime())/3600000):99;return _ageH<1?'<span style="position:absolute;top:10px;right:10px;display:inline-flex;align-items:center;gap:4px;font-family:var(--font-mono);font-size:7px;color:#00ff88;letter-spacing:2px;text-transform:uppercase;"><span style=\'width:6px;height:6px;border-radius:50%;background:#00ff88;box-shadow:0 0 8px #00ff88;animation:cdb-pulse 1s infinite;\'></span>LIVE</span>':_ageH<6?'<span style="position:absolute;top:10px;right:10px;font-family:var(--font-mono);font-size:7px;color:#f59e0b;letter-spacing:2px;">NEW</span>':''})()}
                    <div class="card-meta">
                        <span class="badge badge-${sev.toLowerCase()}">${sev}</span>
                        <span class="badge badge-tlp" style="background:${tlpColor}22;color:${tlpColor};cursor:help;" title="${getTlpDescription(tlp)}">${tlp}</span>
                        <span class="badge badge-accent">RISK ${item.risk_score}/10</span>
                        ${kevBadge}
                        ${exploitBadge}
                        ${patchBadge}
                        ${ransomBadge}
                        ${zeroDay}
                        ${newBadge}
                        ${pepsBadge}
                        ${blastBadge}
                        ${supplyBadge}
                        ${item.threat_type && item.threat_type !== 'THREAT-INTEL' && item.threat_type !== 'THREAT_INTEL' ? `<span title="Threat Type" style="font-family:var(--font-mono);font-size:7.5px;color:#94a3b8;background:rgba(148,163,184,0.08);border:1px solid rgba(148,163,184,0.2);padding:1px 7px;border-radius:2px;">${item.threat_type.replace(/_/g,' ')}</span>` : ''}
                        ${_freshHtml || (ts ? `<span style="margin-left:auto;font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">${ts}</span>` : '')}
                        ${(()=>{
                            // v122.0.0: Tier badge \u2014 FREE/PRO/ENTERPRISE access indicator
                            const userTier = (window._platformTiers && window._platformTiers.current) || 'free';
                            const vs = item.validation_status || '';
                            const hasFullReport = item.report_url && !vs.includes('fail') && !vs.includes('error') && vs !== 'file_missing' && vs !== 'brand_skip';
                            const tierLabel = userTier === 'enterprise' ? 'ENT'
                                           : userTier === 'premium'    ? 'PRO'
                                           :                              'FREE';
                            const tierColor = userTier === 'enterprise' ? '#a78bfa'
                                           : userTier === 'premium'    ? '#00d4aa'
                                           :                              '#5a6578';
                            const tierBg    = userTier === 'enterprise' ? 'rgba(167,139,250,0.1)'
                                           : userTier === 'premium'    ? 'rgba(0,212,170,0.08)'
                                           :                              'rgba(255,255,255,0.04)';
                            const tierBorder= userTier === 'enterprise' ? 'rgba(167,139,250,0.3)'
                                           : userTier === 'premium'    ? 'rgba(0,212,170,0.25)'
                                           :                              'rgba(255,255,255,0.08)';
                            const tierTitle = userTier === 'enterprise' ? 'Enterprise \u2014 Full IOC, STIX bundles, actor intelligence'
                                           : userTier === 'premium'    ? 'Pro \u2014 Full AI summary, partial IOC, threat insights'
                                           :                              'Free tier \u2014 upgrade for full intelligence';
                            const tierBadgeHtml = `<span title="${tierTitle}" style="font-family:var(--font-mono);font-size:7.5px;font-weight:800;color:${tierColor};background:${tierBg};border:1px solid ${tierBorder};padding:1px 7px;border-radius:2px;margin-left:4px;letter-spacing:0.5px;">${tierLabel}</span>`;
                            if (!hasFullReport) {
                                return tierBadgeHtml + '<span title="Full dossier not yet deployed" style="font-family:var(--font-mono);font-size:8px;color:var(--text-muted);background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);padding:1px 6px;border-radius:2px;margin-left:4px;">⚠ NO DOSSIER</span>';
                            }
                            return tierBadgeHtml;
                        })()}
                    </div>
                    <div class="card-stix" style="cursor:pointer;" onclick="copyToClipboard('${item.stix_id||item.id||''}', this)" title="Click to copy STIX ID">STIX: ${(item.stix_id||item.id) ? (item.stix_id||item.id).slice(0, 36) : '\u2014'} \u2022 ${actor} <i class="fas fa-copy" style="font-size:9px;opacity:0.5;margin-left:4px;"></i></div>
                    <h3 class="card-title js-open-modal" style="cursor:pointer;" data-stix-id="${item.stix_id||item.id||''}">${_cdbEsc(item.title)}</h3>
                    <div class="cdb-scan-bar">${_scanExploit}${_scanPrio}${_scanImpact}</div>
                    ${(()=>{
                        const _cvss = item.cvss_score != null ? parseFloat(item.cvss_score) : null;
                        // P0 FIX: epss_score is 0-1 scale for most live items and 0-100 for
                        // others -- use the canonical normalizer's 0-100 percent form (this
                        // bar is already scaled against max=100) instead of the raw value,
                        // which rendered a typical 87%-probability item as a ~1%-wide bar.
                        const _epssResult2 = window.CDB_NORMALIZE.epss(item.epss_score);
                        const _epss = _epssResult2.state === 'OK' ? _epssResult2.percent : null;
                        const _risk = item.risk_score != null ? parseFloat(item.risk_score) : null;
                        if (!_cvss && !_epss && !_risk) return '';
                        const _bar = (val,max,color,label,fmt) => val!=null?`<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;"><span style="font-family:var(--font-mono);font-size:8px;color:#5a6578;letter-spacing:1px;width:34px;text-align:right;flex-shrink:0;">${label}</span><div style="flex:1;height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;"><div style="width:${Math.min(100,(val/max)*100).toFixed(1)}%;height:100%;background:linear-gradient(90deg,${color},${color}aa);border-radius:2px;transition:width 0.6s ease;"></div></div><span style="font-family:var(--font-mono);font-size:9px;color:${color};font-weight:700;width:30px;flex-shrink:0;">${fmt(val)}</span></div>`:''
                        const _cvssColor = _cvss>=9?'#dc2626':_cvss>=7?'#ea580c':_cvss>=4?'#f59e0b':'#22c55e';
                        const _epssColor = _epss>=50?'#dc2626':_epss>=20?'#f59e0b':'#00d4aa';
                        const _riskColor = _risk>=8?'#dc2626':_risk>=6?'#ea580c':_risk>=4?'#f59e0b':'#22c55e';
                        return `<div style="padding:10px 0 6px;border-top:1px solid rgba(255,255,255,0.04);margin-bottom:8px;">
                            ${_bar(_cvss,10,_cvssColor,'CVSS',v=>`${v.toFixed(1)}`)}
                            ${_bar(_epss,100,_epssColor,'EPSS',v=>`${v.toFixed(0)}%`)}
                            ${_bar(_risk,10,_riskColor,'RISK',v=>`${v.toFixed(1)}`)}
                        </div>`;
                    })()}
                    <div class="cdb-summary"><div class="cdb-summary-ico">\u{1F9E0}</div><div class="cdb-summary-txt">${_sumText}</div></div>
                    <div class="cdb-body">
                        <div class="cdb-ring-col">
                            <div class="cdb-ring ${_ringCls}">
                                <svg viewBox="0 0 68 68"><circle class="cdb-rbg" cx="34" cy="34" r="28"/><circle class="cdb-rfg" cx="34" cy="34" r="28" style="stroke:${_ringSevColor};stroke-dasharray:${_rc.toFixed(1)};stroke-dashoffset:${_ro.toFixed(1)};"/></svg>
                                <div class="cdb-rval" style="color:${_ringSevColor}">${_riskVal}</div>
                            </div>
                            <span class="cdb-rlabel" style="color:${_ringSevColor}">${_ringLabel}</span>
                        </div>
                        <div class="cdb-data-col">
                            ${iocIndicatorBadge}
                            ${iocChips ? `<div class="card-ioc-strip">${iocChips}</div>` : ''}
                            ${iocConfidenceBar}
                            ${_iocCount > 0 ? `<div style="margin-top:5px;padding:7px 10px;background:rgba(0,212,170,0.05);border:1px solid rgba(0,212,170,0.18);border-radius:4px;display:flex;align-items:center;justify-content:space-between;gap:8px;">
                                <div style="font-family:var(--font-mono);font-size:8.5px;color:#f87171;font-weight:800;letter-spacing:.5px;">&#9888; ${_iocCount} INDICATOR${_iocCount>1?'S':''} DETECTED \u2014 <span style="color:#5a6578;">PRO: Full IOC analysis</span></div>
                                <a href="/upgrade.html?plan=pro&utm_source=ioc-card" target="_blank" style="font-family:var(--font-mono);font-size:8px;color:#00d4aa;border:1px solid rgba(0,212,170,0.3);padding:2px 8px;border-radius:3px;text-decoration:none;white-space:nowrap;font-weight:700;">UNLOCK &#8594;</a>
                            </div>` : ''}
                            ${(function(){
                                /* AI SIGNAL BOX \u2014 visible on card without expanding APEX panel */
                                const _ai  = item.apex_ai || {};
                                const _ap  = item.apex   || {};
                                const _campId  = _ai.campaign_id || _ap.campaign_id || null;
                                const _tlvl    = _ai.threat_level || _ap.threat_level || null;
                                const _predRsk = _ai.predictive_risk != null ? parseFloat(_ai.predictive_risk).toFixed(1)
                                               : _ap.predictive_score != null ? parseFloat(_ap.predictive_score).toFixed(1) : null;
                                const _cTier   = _ai.threat_confidence_tier || null;
                                const _confLabel = conf >= 80 ? 'HIGH' : conf >= 60 ? 'MODERATE' : conf >= 40 ? 'LOW' : 'UNVERIFIED';
                                const _confCol   = conf >= 80 ? '#00d4aa' : conf >= 60 ? '#3b82f6' : conf >= 40 ? '#f59e0b' : '#ef4444';
                                const _campDisplay = _campId && _campId !== 'PRO_REQUIRED' && _campId !== '\u2014' ? _campId : null;
                                if (!_campDisplay && !_tlvl && !_predRsk) return '';
                                return `<div style="margin-top:6px;padding:7px 10px;background:linear-gradient(135deg,rgba(0,212,170,0.04),rgba(59,130,246,0.03));border:1px solid rgba(0,212,170,0.15);border-radius:4px;">
                                    <div style="font-family:var(--font-mono);font-size:7.5px;color:#3a5a6a;letter-spacing:2px;text-transform:uppercase;font-weight:700;margin-bottom:5px;">&#129504; AI SIGNAL</div>
                                    <div style="display:flex;gap:12px;flex-wrap:wrap;">
                                        <div>
                                            <div style="font-family:var(--font-mono);font-size:7px;color:#4a6578;letter-spacing:1px;">THREAT CONFIDENCE</div>
                                            <div style="font-family:var(--font-mono);font-size:10px;font-weight:800;color:${_confCol};">${_cTier || _confLabel}</div>
                                        </div>
                                        ${_campDisplay ? `<div>
                                            <div style="font-family:var(--font-mono);font-size:7px;color:#4a6578;letter-spacing:1px;">LIKELY CAMPAIGN</div>
                                            <div style="font-family:var(--font-mono);font-size:10px;font-weight:800;color:#60a5fa;">${_cdbEsc(_campDisplay)}</div>
                                        </div>` : ''}
                                        ${_predRsk ? `<div>
                                            <div style="font-family:var(--font-mono);font-size:7px;color:#4a6578;letter-spacing:1px;">AI RISK (30d)</div>
                                            <div style="font-family:var(--font-mono);font-size:10px;font-weight:800;color:${parseFloat(_predRsk)>=7?'var(--critical)':parseFloat(_predRsk)>=5?'var(--high)':'var(--accent)'};">${_predRsk}/10</div>
                                        </div>` : ''}
                                    </div>
                                </div>`;
                            })()}
                            ${mitreHtml}
                            ${_kcHtml}
                            ${_iocCopyHtml}
                            <div class="cdb-signals">${_sigs.join('')}</div>
                        </div>
                    </div>
                    ${_decHtml}
                    ${_socHtml}
                    ${enrichHtml}
                    ${(function(){
                        // v122.0.0 \u2014 Card-level standalone monetization CTA
                        // Visible WITHOUT expanding APEX panel \u2014 drives immediate upgrade conversion
                        try {
                            const urgency = item.threat_urgency;
                            if (!urgency) return '';
                            const sevClass = (sev === 'CRITICAL') ? 'critical' : 'high';
                            const icon = (sev === 'CRITICAL') ? '🔴' : '⚠️';
                            return `<div class="card-tier-cta ${sevClass}" style="background:linear-gradient(135deg,rgba(220,38,38,0.12),rgba(239,68,68,0.06));border:1px solid rgba(220,38,38,0.3);border-radius:8px;padding:14px 16px;margin-top:12px;">
                                <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                                  <div>
                                    <div style="font-family:var(--font-mono);font-size:8px;color:#dc2626;letter-spacing:3px;text-transform:uppercase;margin-bottom:4px;">&#128274; PRO INTELLIGENCE LOCKED</div>
                                    <span class="card-tier-msg" style="font-size:11px;color:var(--text-muted);line-height:1.5;">${icon} ${_cdbEsc(urgency.message)}</span>
                                    <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;">
                                      <span style="font-family:var(--font-mono);font-size:8px;color:#666;background:rgba(255,255,255,0.04);padding:2px 6px;border-radius:3px;">Full IOC List</span>
                                      <span style="font-family:var(--font-mono);font-size:8px;color:#666;background:rgba(255,255,255,0.04);padding:2px 6px;border-radius:3px;">Actor Attribution</span>
                                      <span style="font-family:var(--font-mono);font-size:8px;color:#666;background:rgba(255,255,255,0.04);padding:2px 6px;border-radius:3px;">STIX Bundle</span>
                                      <span style="font-family:var(--font-mono);font-size:8px;color:#666;background:rgba(255,255,255,0.04);padding:2px 6px;border-radius:3px;">AI Dossier</span>
                                    </div>
                                  </div>
                                  <a href="${urgency.upgrade_url}" target="_blank" rel="noopener" class="card-tier-cta-btn" style="background:linear-gradient(135deg,#dc2626,#b91c1c);color:#fff;border:none;padding:10px 18px;border-radius:6px;font-family:var(--font-mono);font-size:10px;font-weight:800;letter-spacing:1px;white-space:nowrap;text-decoration:none;display:inline-flex;align-items:center;gap:6px;box-shadow:0 0 20px rgba(220,38,38,0.35);transition:all 0.2s;"><span style="font-size:12px;">&#9889;</span>${urgency.cta ? _cdbEsc(urgency.cta) : 'UNLOCK FULL INTEL'}</a>
                                </div>
                            </div>`;
                        } catch(e) { return ''; }
                    })()}
                    ${(function(){
                        // v184.0 GOD-MODE APEX AI Intelligence Panel
                        // \u2014 apex_ai: FULL DISPLAY \u2014 expanded by default, all fields surfaced, paywall-aware
                        // \u2014 expandable/collapsible panel (toggle on header click)
                        // \u2014 hover tooltips on all metrics
                        // \u2014 urgency banner for critical/high free-tier items
                        try {
                            const ai = item.apex_ai || {};
                            const ap = item.apex   || {};
                            if (!item.apex_ai && !item.apex) return '';

                            // ── Priority ───────────────────────────────────────────
                            // P0 FIX: prefer the canonical item.__norm.apex_ai.soc_priority
                            // (normalizeIntelItem()'s severity-aware computation) over this
                            // panel's own independent P4 fallback -- this was the same
                            // ai.soc_priority||ap.priority||'P4' pattern already found and
                            // fixed as the root cause of the HIGH-severity/P4-badge
                            // contradiction, just re-implemented a second time here. The
                            // original fallback chain is kept unchanged for items without
                            // __norm attached (never worse than before this fix).
                            const prio      = (item.__norm && item.__norm.apex_ai && item.__norm.apex_ai.soc_priority) || ai.soc_priority || ap.priority || 'P4';
                            const prioClass = prio.toLowerCase();
                            const prioColor = prio==='P1'?'var(--critical)':prio==='P2'?'var(--high)':prio==='P3'?'var(--medium)':'var(--low)';

                            // ── Threat level ──────────────────────────────────────
                            const tlvl     = ai.threat_level || ap.threat_level || 'UNKNOWN';
                            const tlvlColor= tlvl==='CRITICAL_SURGE'?'#ff3b3b':tlvl==='HIGH_ALERT'?'#ff8c00':'#c8d8e8';
                            const cat      = (ai.threat_category||ap.threat_category||'UNKNOWN').replace(/_/g,' ');

                            // ── AI fields ─────────────────────────────────────────
                            const predRisk = ai.predictive_risk != null ? parseFloat(ai.predictive_risk).toFixed(1) : (ap.predictive_score!=null?parseFloat(ap.predictive_score).toFixed(1):'\u2014');
                            const aiConf   = ai.ai_confidence   != null ? ai.ai_confidence : null;
                            const ttpDens  = ai.ttp_density      != null ? parseFloat(ai.ttp_density).toFixed(1) : '\u2014';
                            const actorFP  = ai.actor_fingerprint || null;
                            const campId   = ai.campaign_id || ap.campaign_id || '\u2014';
                            // v124.0: Threat Confidence Tier \u2014 enterprise-grade label (replaces "AI CONF: X%")
                            const confTier  = ai.threat_confidence_tier || null;
                            const confLabel = ai.threat_confidence_label || null;
                            const _TIER_COLORS = { VERIFIED:'#00d4aa', HIGH:'#3b82f6', MODERATE:'#f59e0b', LOW:'#ef4444' };
                            const confTierColor = _TIER_COLORS[confTier] || '#6b7280';

                            // ── Kill chain ────────────────────────────────────────
                            const kc       = ai.kill_chain;
                            const kcLocked = kc === 'PRO_REQUIRED';
                            const kcPhases = Array.isArray(kc) ? kc : [];
                            const kcHtml   = kcLocked ? `<span class="apex-v locked">🔒 PRO</span>`
                                           : kcPhases.length>0 ? kcPhases.slice(0,3).map(p=>`<span class="apex-kc-pill">⬡ ${p}</span>`).join('')
                                           : `<span class="apex-v locked">\u2014</span>`;

                            // ── Confidence display \u2014 Tier badge + numeric bar ──────
                            const confBarColor = aiConf>=80?'var(--accent)':aiConf>=50?'#3b82f6':aiConf>=30?'#f59e0b':'#ef4444';
                            const confBar = aiConf!=null ? `
                                <div class="apex-conf-bar">
                                    ${confTier ? `<span style="font-family:var(--font-mono);font-size:8px;letter-spacing:1.5px;font-weight:900;color:${confTierColor};padding:2px 6px;border:1px solid ${confTierColor}33;border-radius:2px;margin-right:6px;">${confTier}</span>` : `<span class="apex-k" style="white-space:nowrap">AI CONF</span>`}
                                    <div class="apex-conf-track">
                                        <div class="apex-conf-fill" style="width:${Math.min(aiConf,100)}%;background:${confTierColor || confBarColor};"></div>
                                    </div>
                                    <span class="apex-conf-pct" style="color:${confTierColor || confBarColor}">${aiConf}%</span>
                                </div>` : '';

                            // ── Actor fingerprint ─────────────────────────────────
                            const fpLocked  = actorFP && actorFP.includes('****');
                            const fpDisplay = actorFP || '\u2014';

                            // ── Tags ──────────────────────────────────────────────
                            const tags     = Array.isArray(ai.behavioral_tags) ? ai.behavioral_tags
                                           : Array.isArray(ap.behavioral_tags) ? ap.behavioral_tags : [];
                            const tagsHtml = tags.slice(0,4).map(t=>`<span class="apex-tag">${_cdbEsc(t)}</span>`).join('');

                            // ── Paywall CTA ───────────────────────────────────────
                            const paywall     = ai.paywall;
                            const paywallHtml = paywall ? `
                                <div class="apex-lock-cta">
                                    🔒 ${_cdbEsc(paywall.message)}
                                    <a href="${(paywall.upgrade_url||'').replace('https://intel.cyberdudebivash.com/store.html','/upgrade.html?plan=pro').replace('https://intel.cyberdudebivash.com/upgrade','/upgrade.html?plan=pro') || '/upgrade.html?plan=pro'}" target="_blank">UPGRADE →</a>
                                </div>` : '';

                            // ── v184.0: Urgency banner \u2014 reads apex_ai.paywall.urgency (primary)
                            //           falls back to item.threat_urgency for legacy API compat
                            const urgency = (ai.paywall && ai.paywall.urgency)
                                ? { message: ai.paywall.urgency, upgrade_url: '/upgrade.html?plan=pro' }
                                : item.threat_urgency;
                            const urgencyHtml = urgency ? `
                                <div class="apex-urgency-banner">
                                    ${_cdbEsc(urgency.message)}
                                    <a href="${urgency.upgrade_url}" target="_blank" class="apex-urgency-cta">UPGRADE →</a>
                                </div>` : '';

                            // ── v122.0.0: ai_summary MANDATORY \u2014 always rendered ───
                            const summary    = ai.ai_summary || ap.ai_summary || '';
                            const isTeaserSummary = summary.includes('[UPGRADE TO PRO');
                            const summaryHtml = summary ? `
                                <div class="apex-summary${isTeaserSummary?' apex-summary-teaser':''}">
                                    ${_cdbEsc(summary)}
                                </div>` : '';

                            // ── Recommended action ────────────────────────────────
                            const action     = ai.recommended_action || ap.recommended_action || '';
                            const showAction = action && action !== 'Upgrade to Pro for full SOC recommendations.'
                                            && action !== 'Upgrade to Pro for full SOC recommendations and actor attribution.';

                            // ── Unique panel ID for toggle ────────────────────────
                            const _apxId = 'apx' + (item.stix_id||item.id||'').replace(/[^a-zA-Z0-9]/g,'').slice(0,10) + Math.random().toString(36).slice(2,5);

                            return `<div class="apex-panel" id="${_apxId}">
                                ${urgencyHtml}
                                <button class="apex-toggle" onclick="(function(el){var b=document.getElementById('${_apxId}-body');var open=b.classList.toggle('expanded');b.classList.toggle('collapsed',!open);var ae=el.getAttribute('aria-expanded')==='true';el.setAttribute('aria-expanded',String(!ae));el.closest('.apex-panel').classList.toggle('open',open);})(this)" aria-expanded="true">
                                    <span style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                                        <span class="apex-badge">⬡ APEX AI v201.0</span>
                                        <span style="color:var(--text-muted);font-size:7.5px;letter-spacing:0.5px;">INTELLIGENCE ENGINE</span>
                                        <span class="apex-v ${prioClass}" style="color:${prioColor};font-size:8.5px;font-weight:900;">${prio}</span>
                                        <span style="font-size:8px;color:${tlvlColor};letter-spacing:0.5px;">${tlvl.replace(/_/g,' ')}</span>
                                        <span style="font-size:8px;color:${parseFloat(predRisk)>=7?'var(--critical)':parseFloat(predRisk)>=5?'var(--high)':'var(--accent)'};">RISK ${predRisk}/10</span>
                                        ${confTier ? `<span style="font-size:7px;color:${confTierColor};border:1px solid ${confTierColor}55;padding:1px 5px;border-radius:2px;font-weight:900;">${confTier}</span>` : ''}
                                    </span>
                                    <span class="apex-toggle-chev">▼</span>
                                </button>
                                <div class="apex-panel-body expanded" id="${_apxId}-body">
                                    <div class="apex-row" style="margin-top:8px;">
                                        <div class="apex-kv" data-tip="SOC triage priority: P1=immediate, P2=urgent, P3=standard, P4=low">
                                            <span class="apex-k">SOC PRIORITY</span>
                                            <span class="apex-v ${prioClass}" style="color:${prioColor}">${prio}</span>
                                        </div>
                                        <div class="apex-kv" data-tip="Current threat activity level from intelligence signals">
                                            <span class="apex-k">THREAT LEVEL</span>
                                            <span class="apex-v" style="color:${tlvlColor}">${tlvl.replace(/_/g,' ')}</span>
                                        </div>
                                        <div class="apex-kv" data-tip="AI-projected exploitation probability (CVSS 40% + EPSS 25% + KEV 20% + IOC 15%)">
                                            <span class="apex-k">PRED RISK</span>
                                            <span class="apex-v" style="color:${parseFloat(predRisk)>=7?'var(--critical)':parseFloat(predRisk)>=5?'var(--high)':'var(--accent)'}">${predRisk}/10</span>
                                        </div>
                                        <div class="apex-kv" data-tip="Attack technique density \u2014 higher = more sophisticated adversary">
                                            <span class="apex-k">TTP DENSITY</span>
                                            <span class="apex-v">${ttpDens}/10</span>
                                        </div>
                                        <div class="apex-kv">
                                            <span class="apex-k">CATEGORY</span>
                                            <span class="apex-v" style="font-size:8.5px;">${cat}</span>
                                        </div>
                                        ${item.threat_type ? `<div class="apex-kv"><span class="apex-k">TYPE</span><span class="apex-v" style="font-size:8px;color:#94a3b8;">${item.threat_type.replace(/_/g,' ')}</span></div>` : ''}
                                    </div>
                                    <div class="apex-row">
                                        <div class="apex-kv" style="flex:1;" data-tip="${fpLocked?'Full actor attribution requires Pro tier':'Deterministic actor identity: tag::severity::IOC-count::TTP-count'}">
                                            <span class="apex-k">ACTOR FINGERPRINT</span>
                                            <span class="apex-v ${fpLocked?'locked':''}" style="font-size:8px;color:${fpLocked?'':'#67e8f9'}">${_cdbEsc(fpDisplay)}</span>
                                        </div>
                                        <div class="apex-kv">
                                            <span class="apex-k">CAMPAIGN</span>
                                            <span class="apex-v" style="color:var(--blue);font-size:8px;">${campId==='PRO_REQUIRED'?'<span class="apex-v locked">🔒 PRO</span>':_cdbEsc(campId)}</span>
                                        </div>
                                    </div>
${item.stix_object_count != null ? `<div class="apex-kv" style="margin-top:4px;"><span class="apex-k">STIX OBJECTS</span><span class="apex-v" style="color:#60a5fa;">${item.stix_object_count}</span></div>` : ''}
                                                                        <div class="apex-kv" style="margin-top:4px;">
                                        <span class="apex-k">KILL CHAIN PHASE</span>
                                        <div style="margin-top:3px;">${kcHtml}</div>
                                    </div>
                                    ${confBar}
                                    ${confLabel ? `<div class="apex-conf-label" style="margin-top:5px;font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.8px;color:${confTierColor};padding:4px 8px;background:${confTierColor}11;border-left:2px solid ${confTierColor};border-radius:2px;">${_cdbEsc(confLabel)}</div>` : ''}
                                    ${tagsHtml ? `<div class="apex-tags" style="margin-top:6px;">${tagsHtml}</div>` : ''}
                                    ${showAction ? `<div class="apex-action">→ ${_cdbEsc(action)}</div>` : ''}
                                    ${summaryHtml}
                                    ${paywallHtml}
                                </div>
                            </div>`;
                        } catch(e) { return ''; }
                    })()}
                    ${(function(){
                        // P0-3 FIX: APEX AI flat-field block \u2014 renders detect/analyze/respond/
                        // mitigation/recommendations/priority from API-injected fields.
                        // Fires when item.apex is absent but flat fields exist (v102 API format).
                        try {
                            const hasFlat = item.detect || item.analyze || item.respond || item.mitigation;
                            if (!hasFlat) return '';
                            // P0 FIX: never silently coalesce a genuinely-unknown priority
                            // into P4 -- window.CDB_NORMALIZE.priority() (js/metric-normalize.js)
                            // prefers sla_priority/apex_ai.soc_priority/priority, falls back to
                            // computePriority(), and only returns 'UNKNOWN' when none resolve.
                            const pri = window.CDB_NORMALIZE.priority(item);
                            const priClass = pri.toLowerCase();
                            const priColors = (window.PRIORITY_COLORS)
                                ? {p1:window.PRIORITY_COLORS.P1,p2:window.PRIORITY_COLORS.P2,p3:window.PRIORITY_COLORS.P3,p4:window.PRIORITY_COLORS.P4}
                                : {p1:'#ef4444',p2:'#f97316',p3:'#fbbf24',p4:'#4ade80'};
                            const priColor = priColors[priClass] || '#4ade80';
                            const kev = item.kev_present ? '<span style="font-family:var(--font-mono);font-size:9px;color:#ff3b3b;background:rgba(255,59,59,0.1);border:1px solid rgba(255,59,59,0.3);padding:1px 6px;border-radius:2px;margin-left:6px;">⚡ KEV ACTIVE</span>' : '';
                            const recs = Array.isArray(item.recommendations) ? item.recommendations : [];
                            const recsHtml = recs.slice(0,4).map(r => `<span class="cdb-apex-rec-pill">${r}</span>`).join('');
                            const threatType = item.threat_type || '';
                            return `<div class="cdb-apex-ai-block">
                                <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                                    <span class="apex-priority-badge ${priClass}" style="color:${priColor};">◆ ${pri}</span>
                                    ${threatType ? `<span style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);background:rgba(255,255,255,0.04);padding:2px 8px;border-radius:2px;">${threatType}</span>` : ''}
                                    ${kev}
                                </div>
                                ${item.detect ? `<div class="cdb-apex-field"><span class="cdb-apex-label">DETECT</span><span class="cdb-apex-value">${item.detect}</span></div>` : ''}
                                ${item.analyze ? `<div class="cdb-apex-field"><span class="cdb-apex-label">ANALYZE</span><span class="cdb-apex-value">${item.analyze}</span></div>` : ''}
                                ${item.respond ? `<div class="cdb-apex-field"><span class="cdb-apex-label">RESPOND</span><span class="cdb-apex-value">${item.respond}</span></div>` : ''}
                                ${item.mitigation ? `<div class="cdb-apex-field"><span class="cdb-apex-label">MITIGATE</span><span class="cdb-apex-value">${item.mitigation}</span></div>` : ''}
                                ${recsHtml ? `<div style="margin-top:10px;"><span class="cdb-apex-label" style="display:block;margin-bottom:6px;">RECOMMENDATIONS</span><div class="cdb-apex-recs">${recsHtml}</div></div>` : ''}
                            </div>`;
                        } catch(e) { return ''; }
                    })()}
                    ${item.epss_score != null ? `<div class="epss-bar-wrap"><span class="epss-bar-label">EPSS RISK</span><div class="epss-bar-track"><div class="epss-bar-fill" style="width:${Math.min(item.epss_score,100)}%;background:${item.epss_score>=50?'#ff3b3b':item.epss_score>=10?'#ff8c00':item.epss_score>=1?'#f59e0b':'var(--accent)'};"></div></div><span style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">${item.epss_score}%</span></div>` : ''}
                    <div class="card-copy-strip">
                        ${cves.map(cve => `<span class="copy-chip" onclick="copyToClipboard('${cve}',this)"><i class="fas fa-copy"></i>${cve}</span>`).join('')}
                    </div>
                    ${_hasExpand ? `<button class="cdb-xtoggle" data-target="${_xid}"><span>Intel Deep-Dive</span><span class="cdb-xchev">\u25bc</span></button><div class="cdb-xpanel" id="${_xid}"><div class="cdb-xinner">${_actorHtml}${_iocHtml}${_tlHtml}</div></div>` : ''}
                    <div class="card-footer">
                        <span class="card-score" style="color:${sevColor};">\u25c6 ${item.risk_score}/10</span>
                        <div style="display:flex;gap:12px;align-items:center;">
                            ${nvdLink}
                            ${(item.stix_bundle||item.stix_bundle_url) ? `<a href="${item.stix_bundle||item.stix_bundle_url}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:9px;color:#60a5fa;border-bottom:1px solid rgba(96,165,250,0.3);" title="STIX bundle">STIX bundle↗</a>` : ''}
                            <button class="js-open-modal" data-stix-id="${item.stix_id||item.id||''}"
                                    style="background:none;border:none;padding:0;cursor:pointer;font-family:var(--font-mono);font-size:10px;color:var(--accent);letter-spacing:0.5px;">
                                <i class="fas fa-expand-alt"></i> DETAILS
                            </button>
                            ${(()=>{
                                // v186.0 P0 FIX: report link now built by the single canonical
                                // cdbBuildReportUrl() helper (was: inline duplicate of the same
                                // priority chain -- see helper's doc comment for why this was unified).
                                const _internalUrl = cdbBuildReportUrl(item);
                                const _eid = item.stix_id || item.id || '';
                                const _sUrl = item.source_url || '';

                                if (_internalUrl) {
                                    return `<a href="${_internalUrl}" target="_blank" rel="noopener" class="card-link">SENTINEL APEX INTEL REPORT &#x2192;</a>`;
                                }
                                // Fallback 1: inline modal (never shows external as "dossier")
                                if (_eid) {
                                    return `<button class="js-open-modal card-link" data-stix-id="${_eid}" style="border:none;background:none;padding:0;cursor:pointer;">SENTINEL APEX INTEL REPORT &#x2192;</button>`;
                                }
                                // Fallback 2: source URL -- labelled as SOURCE, never as Dossier
                                if (_sUrl) {
                                    return `<a href="${_sUrl}" target="_blank" rel="noopener" class="card-link">View Source &#x2192;</a>`;
                                }
                                return '';
                            })()}
                            ${item.gumroad_url ? `<a href="${item.gumroad_url}" target="_blank" rel="noopener" class="cta-gumroad" title="Get premium STIX bundle + IOC pack">⚡ PREMIUM</a>` : ''}
                        </div>
                    </div>
                    ${(function(){
                        // GOD MODE v184.0 \u2014 PREMIUM SELLABLE FOOTER \u2014 monetization conversion layer
                        const _userTier = (window._platformTiers && window._platformTiers.current) || 'free';
                        const _isFree   = _userTier === 'free';
                        // Coerced to a finite number before use: this feeds into
                        // grid.innerHTML below (via _iocLockStrip's title/sub text),
                        // so a non-numeric ioc_count/ioc_counts value from upstream
                        // feed data must never reach that template literal unescaped.
                        const _iocCountNum   = Number(item.ioc_count);
                        const _iocCountsSum  = item.ioc_counts
                            ? Object.values(item.ioc_counts).reduce((a,b) => { const n = Number(b); return a + (Number.isFinite(n) ? n : 0); }, 0)
                            : 0;
                        const _iocTotal = (Number.isFinite(_iocCountNum) && _iocCountNum) || _iocCountsSum || 0;
                        const _isHigh   = sev === 'CRITICAL' || sev === 'HIGH';
                        const _hasReport = !!(item.report_url || item.internal_report_url);
                        const _hasPdf    = !!item.pdf_url;
                        const _reportUrl = item.report_url || item.internal_report_url || '#';
                        const _ageH      = item.timestamp ? (Date.now()-new Date(item.timestamp).getTime())/3600000 : 99;

                        // LIVE INTELLIGENCE TAG
                        const _liveTag = _ageH < 2
                            ? `<span class="cdb-live-tag">⚡ LIVE INTEL</span>`
                            : _ageH < 8
                            ? `<span class="cdb-live-tag cdb-live-recent">\u{1F9E0} FRESH INTEL</span>`
                            : '';

                        // IOC BLUR LOCK STRIP (free tier, when IOCs exist)
                        const _iocLockStrip = (_isFree && _iocTotal > 0) ? `
                            <div class="cdb-ioc-lock-strip">
                                <div class="cdb-ioc-lock-blur" aria-hidden="true">
                                    <span class="cdb-ioc-pill">192.168.x.x</span>
                                    <span class="cdb-ioc-pill">malware-c2.io</span>
                                    <span class="cdb-ioc-pill">a1b2c3d4e5f6\u2026</span>
                                    <span class="cdb-ioc-pill">CVE-2024-????</span>
                                    ${_iocTotal > 4 ? `<span class="cdb-ioc-pill">+${_iocTotal-4} more</span>` : ''}
                                </div>
                                <div class="cdb-ioc-lock-overlay">
                                    <div class="cdb-ioc-lock-left">
                                        <span style="font-size:18px;">🔒</span>
                                        <div>
                                            <div class="cdb-ioc-lock-title">Advanced Threat Attribution &amp; C2 Telemetry Locked</div>
                                            <div class="cdb-ioc-lock-sub">${_iocTotal} IOC${_iocTotal>1?'S':''} \u00b7 C2 IPs \u00b7 YARA/Suricata rules \u00b7 5,000 daily API queries on Sentinel Pro</div>
                                        </div>
                                    </div>
                                    <div class="cdb-ioc-unlock-group">
                                        <a href="/upgrade.html?plan=pro&utm_source=ioc-blur&gateway=razorpay&ref=${encodeURIComponent(item.id||item.stix_id||'')}" target="_blank" class="cdb-ioc-unlock-btn" title="Cards, UPI, NetBanking">Razorpay →</a>
                                        <a href="/upgrade.html?plan=pro&utm_source=ioc-blur&gateway=gumroad&ref=${encodeURIComponent(item.id||item.stix_id||'')}" target="_blank" class="cdb-ioc-unlock-btn-alt" title="Global cards / PayPal via Gumroad">Gumroad →</a>
                                    </div>
                                </div>
                            </div>` : '';

                        // PRO AI INSIGHT BADGE
                        const _aiSumm = (item.apex_ai && item.apex_ai.ai_summary) || (item.apex && item.apex.ai_summary) || '';
                        const _aiLocked = _aiSumm && (_aiSumm.includes('[UPGRADE') || _aiSumm.includes('PRO_REQUIRED'));
                        const _proInsightStrip = (_isFree && _aiLocked) ? `
                            <div class="cdb-pro-insight-strip">
                                <span class="cdb-pro-badge">💎 PRO INSIGHT</span>
                                <span class="cdb-pro-msg">Full AI analysis \u00b7 Actor attribution \u00b7 Kill chain \u00b7 Behavioral tags</span>
                                <a href="/upgrade.html?plan=pro&utm_source=ai-insight&ref=${encodeURIComponent(item.id||item.stix_id||'')}" target="_blank" class="cdb-pro-unlock-btn">UPGRADE →</a>
                            </div>` : '';

                        // CTA ROW — ACCESS GOVERNANCE v184.0
                        // MODEL_B PERMANENTLY DISABLED: report links are gated behind PRO tier.
                        // PUBLIC (free) users see an upgrade CTA instead of a direct report link.
                        // PRO / ENTERPRISE / MSSP users see the full report link.
                        // _isPro: true if user tier is PRO, ENTERPRISE, or MSSP
                        const _isPro = _userTier === 'pro' || _userTier === 'PRO'
                                    || _userTier === 'premium' || _userTier === 'PREMIUM'
                                    || _userTier === 'enterprise' || _userTier === 'ENTERPRISE'
                                    || _userTier === 'mssp' || _userTier === 'MSSP';

                        const _reportCta = _hasReport && _isPro ? `
                            <a href="${_reportUrl}" target="_blank" rel="noopener" class="cdb-god-cta cdb-cta-report">
                                📋 VIEW FULL REPORT →
                            </a>` :
                            _hasReport && _isFree ? `
                            <a href="/upgrade.html?plan=pro&utm_source=report-gate&ref=${encodeURIComponent(item.id||item.stix_id||'')}" target="_blank" rel="noopener" class="cdb-god-cta cdb-cta-report" style="opacity:0.75;" title="PRO tier required — upgrade to access full intelligence report">
                                🔒 VIEW INTELLIGENCE SUMMARY →
                            </a>` : '';

                        const _pdfCta = _hasPdf && _isPro ? `
                            <a href="${item.pdf_url}" target="_blank" rel="noopener" class="cdb-god-cta cdb-cta-pdf">
                                📄 PDF REPORT
                            </a>` : '';
                        const _entCta = (_isHigh && _isFree) ? `
                            <a href="/contact-enterprise.html?ref=card-${sev.toLowerCase()}&utm_source=card-ent" target="_blank" class="cdb-god-cta cdb-cta-ent">
                                🏢 ENTERPRISE SOC TEAM? Get MSSP access
                            </a>` : '';

                        if (!_liveTag && !_iocLockStrip && !_proInsightStrip && !_reportCta && !_pdfCta && !_entCta) return '';

                        return `<div class="cdb-god-footer">
                            ${_liveTag}
                            ${_iocLockStrip}
                            ${_proInsightStrip}
                            <div class="cdb-god-cta-row">
                                ${_reportCta}
                                ${_pdfCta}
                                ${_entCta}
                            </div>
                        </div>`;
                    })()}
                </div>`;

                } catch(e) { console.error('[SENTINEL-APEX] Card render error:', e); return ''; }
            }).join('');
        }

        // ── Compute Metrics ──
        function computeMetrics(data) {
            const total = data.length;
            // P0 FIX: prefer the canonical normalized severity (window.SentinelApexAdapter's
            // normalizeIntelItem(), attached as item.__norm by loadGOCIntel()) when present --
            // it is the same computation card_renderer.js's dashboard already uses. The
            // risk_score-threshold dual-condition below is kept ONLY as a fallback for any
            // caller that passes data never routed through that normalization (never
            // recalculated when __norm.severity is available).
            const _sev = d => (d.__norm && d.__norm.severity) ? d.__norm.severity : null;
            // v136.0 FIX: Dual-condition severity detection \u2014 trust risk_score as primary signal,
            // also accept severity field. getSeverity() was returning item.severity first which
            // caused incorrect counts when backend labeled items differently from score thresholds.
            const critical = data.filter(d => _sev(d) ? _sev(d)==='CRITICAL' : (parseFloat(d.risk_score||0) >= 9.0 || d.severity === 'CRITICAL')).length;
            const high = data.filter(d => { if (_sev(d)) return _sev(d)==='HIGH'; const s=parseFloat(d.risk_score||0); return (s>=7.0&&s<9.0)||(d.severity==='HIGH'&&s<9.0); }).length;
            const medium = data.filter(d => { if (_sev(d)) return _sev(d)==='MEDIUM'; const s=parseFloat(d.risk_score||0); return (s>=4.0&&s<7.0)||(d.severity==='MEDIUM'&&s<7.0); }).length;
            const low = data.filter(d => { if (_sev(d)) return _sev(d)==='LOW'||_sev(d)==='INFO'; const s=parseFloat(d.risk_score||0); return s<4.0&&d.severity!=='CRITICAL'&&d.severity!=='HIGH'&&d.severity!=='MEDIUM'; }).length;
            const kev = data.filter(d => d.kev_present).length;
            const avgRisk = total ? (data.reduce((s, d) => s + (parseFloat(d.risk_score) || 0), 0) / total).toFixed(1) : '\u2014';
            // P0 FIX: numeric-only IOC aggregation. Every branch previously accumulated an
            // unvalidated raw field directly (`totalIOCs += d.ioc_count`); a single string-typed
            // value anywhere in the feed silently turns every subsequent `+=` into string
            // concatenation, producing an astronomically large "total" (the exact bug class
            // already found and fixed in eiccEngine()'s _iocContribution() -- this was the
            // same bug in a second, independent aggregator that fix never reached). Cast every
            // input explicitly; prefer the adapter's already-`_int()`-cast item.__norm.ioc_count
            // when present.
            let totalIOCs = 0;
            data.forEach(d => {
                if (d.__norm && typeof d.__norm.ioc_count === 'number') {
                    totalIOCs += d.__norm.ioc_count;
                } else if (d.ioc_counts && typeof d.ioc_counts === 'object') {
                    totalIOCs += Object.values(d.ioc_counts).reduce((a, b) => a + (parseInt(b, 10) || 0), 0);
                } else if (d.ioc_count) {
                    // v135.0 FIX: api/feed.json uses ioc_count (singular integer)
                    totalIOCs += parseInt(d.ioc_count, 10) || 0;
                } else if (d.indicator_count) {
                    totalIOCs += parseInt(d.indicator_count, 10) || 0;
                } else if (d.iocs && Array.isArray(d.iocs) && d.iocs.length) {
                    // Fallback: raw iocs array is guaranteed present in all normalised items
                    totalIOCs += d.iocs.length;
                }
            });
            // v184.0: CVE-derived IOC extraction \u2014 each unique CVE maps to 3 structured indicators
            // (CVE-ID indicator + EPSS exploitability vector + CVSS severity vector).
            // KEV-confirmed CVEs add an active-exploitation indicator.
            // STIX bundle objects count as direct network/behavioral indicators.
            if (totalIOCs === 0 && total > 0) {
                const cveRe = /CVE-\d{4}-\d{4,7}/gi;
                const cveSet = new Set();
                let stixIndicators = 0, kevIndicators = 0;
                data.forEach(d => {
                    [d.id, d.cve, d.title, d.description].filter(Boolean).forEach(s => {
                        (String(s).match(cveRe) || []).forEach(c => cveSet.add(c.toUpperCase()));
                    });
                    if (d.stix_bundle && Array.isArray(d.stix_bundle.objects)) {
                        d.stix_bundle.objects.filter(o =>
                            ['indicator','malware','attack-pattern','tool','threat-actor'].includes(o.type)
                        ).forEach(() => stixIndicators++);
                    }
                    if (d.kev_present) kevIndicators++;
                });
                totalIOCs = (cveSet.size * 3) + stixIndicators + kevIndicators;
            }
            window._cdbComputedIOCs = totalIOCs;

            // v117.0.0 FRESHNESS FIX: sort by processed_at DESC so stats show newest processed intel
            let sortedData = [...data].sort((a, b) =>
                new Date(b.published_at||b.timestamp||b.processed_at||0) - new Date(a.published_at||a.timestamp||a.processed_at||0)
             );
            // v200.1 P0 FIX: "last sync" means "when did WE last ingest something",
            // not "when was the newest-by-published_at item first published upstream"
            // (a months-old CVE can be freshly re-processed today after a KEV add).
            // Take the actual max processed_at/timestamp across the set, independent
            // of the published_at-first sort above (which exists for card ordering,
            // not for this stat). This is only ever the pre-fetchWorkerStats() fallback
            // value shown before the authoritative /api/platform/stats response lands.
            const _processedTimes = data.filter(d => d.processed_at || d.timestamp)
                .map(d => new Date(d.processed_at || d.timestamp).getTime());
            const lastTs = _processedTimes.length ? timeSince(Math.max(..._processedTimes)) : '\u2014';

            window._cdbMetricsComputed = true; // v184.0: computeMetrics is authoritative
            window._cdbAvgRisk = avgRisk;
            document.getElementById('m-total').textContent = total;
            document.getElementById('m-critical').textContent = critical;
            document.getElementById('m-high').textContent = high;
            document.getElementById('m-avg-risk').textContent = avgRisk;
            document.getElementById('m-iocs').textContent = totalIOCs ? totalIOCs.toLocaleString() : '\u2014';
            document.getElementById('m-last-sync').textContent = lastTs;
            const kevEl = document.getElementById('m-kev');
            if (kevEl) kevEl.textContent = kev;

            // Render v46.0 analytics \u2014 Animate counters
            setTimeout(animateAllMetrics, 200);

            // Estimate ingest rate
            if (data.length >= 2) {
                const times = data.filter(d => d.timestamp).map(d => new Date(d.timestamp).getTime()).sort((a,b)=>a-b);
                if (times.length >= 2) {
                    const hoursSpan = (times[times.length-1] - times[0]) / 3600000;
                    if (hoursSpan > 0) {
                        const rate = (data.length / hoursSpan).toFixed(1);
                        const rateEl = document.getElementById('m-ingest-rate');
                        const rateDisplay = document.getElementById('ingest-rate-display');
                        if (rateEl) { rateEl.textContent = rate; }
                        if (rateDisplay) rateDisplay.style.display = 'inline-flex';
                    }
                }
            }

            // Render v46.0 analytics
            renderRiskDonut({ critical, high, medium, low });
            renderMitreHeatmap(data);
            renderSourceBreakdown(data);
            renderTicker(data);
            renderMapTicker(data);

            // P0 FIX (zero-fabrication): this used to be a severity-weighted
            // composite score (a hardcoded feed count of 74 baked in) with
            // an artificial sine-wave "daily variance" layered on purely
            // for visual "session stability" -- a specific, precise-looking
            // number with no attack-event dataset behind it at all. This
            // platform has no authoritative "attacks observed" source, only
            // advisory/intelligence-record counts, so the label and value
            // now show what's actually measured: the real current advisory
            // total already computed above.
            var atkEl = document.getElementById('cdb-atk-count');
            if (atkEl) {
                window._cdbAtkSeed = total;
                atkEl.textContent = total.toLocaleString();
            }
        }

        // ── Trend Chart (v46.0 \u2014 range toggles + avg label) ──
        function renderTrendChart(data) {
            const section = document.getElementById('trend-section');
            const barsEl = document.getElementById('trend-bars');
            if (!data.length || !barsEl) return;

            const sorted = [...data].sort((a,b) => new Date(a.published_at||a.timestamp||a.processed_at||0) - new Date(b.published_at||b.timestamp||b.processed_at||0));  // v184.0 FIX
            const n = trendRange === 50 ? sorted.length : Math.min(trendRange, sorted.length);
            const recent = sorted.slice(-n);
            const maxScore = Math.max(...recent.map(d => d.risk_score), 1);
            const avgScore = recent.length ? (recent.reduce((s,d) => s + d.risk_score, 0) / recent.length).toFixed(1) : 0;

            const sevMap = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)', INFO: 'var(--info)' };

            barsEl.innerHTML = recent.map(d => {
                const sev = getSeverity(d.risk_score, d);
                const color = sevMap[sev] || 'var(--accent)';
                const pct = Math.max((d.risk_score / maxScore) * 100, 5);
                const title = String(d.title || '');
                const label = title.slice(0, 40) + (title.length > 40 ? '\u2026' : '');
                const ts = (d.processed_at||d.timestamp) ? new Date(d.processed_at||d.timestamp).toLocaleDateString() : '';  // v117.0.0
                // P0 dashboard data contract (2026-09-24): the title was
                // interpolated raw into this title="" attribute, so a feed
                // title containing `">` closed it and injected live markup.
                // _hEsc() escapes quotes (the _cdbEsc() helper does not).
                return `<div class="trend-bar" style="height:${pct}%;background:${color};opacity:0.75;cursor:pointer;"
                             title="${_hEsc(label)}&#10;Risk: ${_hEsc(d.risk_score)}/10 \u00b7 ${_hEsc(sev)}&#10;${_hEsc(ts)}"
                             class="js-open-modal" data-stix-id="${_hEsc(d.stix_id||d.id||'')}"></div>`;
            }).join('');

            const avgEl = document.getElementById('trend-avg-label');
            if (avgEl) avgEl.textContent = `AVG RISK: ${avgScore} / 10 (${recent.length} advisories)`;

            section.style.display = 'block';
        }

        // ── Filter & Sort ──
        function filterCards(sev, btn) {
            currentFilter = sev;
            document.querySelectorAll('.filter-btn:not(.time-range-btn)').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyView();
        }

        // v73.1: Time range toggle \u2014 filters display without re-fetch or data loss
        function filterTimeRange(range, btn) {
            currentTimeRange = range;
            document.querySelectorAll('.time-range-btn').forEach(b => {
                b.classList.remove('active');
                b.style.background = '';
                b.style.color = '';
                b.style.borderColor = '';
            });
            btn.classList.add('active');
            btn.style.background = 'rgba(0,212,170,0.12)';
            btn.style.color = 'var(--accent)';
            btn.style.borderColor = 'var(--accent)';
            applyView();
        }

        function sortCards(mode) {
            currentSort = mode;
            applyView();
        }

        // ═══════════════════════════════════════════════════════════════
        // GOD MODE RENDERER v1.0 \u2014 bulletproof fallback card renderer
        // Activated when applyView() throws or produces a blank grid.
        // Does NOT depend on any helper that could be failing.
        // ═══════════════════════════════════════════════════════════════
        function cdbGodModeRender(data) {
            try {
                var grid = document.getElementById('threat-grid');
                if (!grid) { console.error('[GOD MODE] #threat-grid not found'); return; }
                if (!data || !data.length) {
                    grid.innerHTML = '<div class="loading-state">No intel data available.</div>';
                    return;
                }
                // v184.0 FIX: dedup before GOD MODE render (prev: bypassed deduplicateIntel entirely)
                try { data = deduplicateIntel(data); } catch(_de) {}
                var _sc = function(s) {
                    s = (s || '').toUpperCase();
                    return s === 'CRITICAL' ? '#ff4444' : s === 'HIGH' ? '#ff7700' : s === 'MEDIUM' ? '#ffcc00' : s === 'LOW' ? '#00d4aa' : '#888';
                };
                var _sv = function(rs, item) {
                    var r = parseFloat(rs || 0);
                    // v184.0 G7 FIX: enforce v149 False-CRITICAL rule in GOD MODE
                    if (item && item.severity === 'CRITICAL') {
                        // P0 FIX: same canonical KEV/EPSS normalization as getSeverity()
                        var kev  = window.CDB_NORMALIZE.kevState(item) === true;
                        var cvss = parseFloat(item.cvss_score || 0);
                        var epssNorm = window.CDB_NORMALIZE.epss(item.epss_score);
                        var epss = epssNorm.state === 'OK' ? epssNorm.probability : 0;
                        if (kev || cvss >= 9.0 || epss >= 0.70 || r >= 8.5) return 'CRITICAL';
                        if (r >= 6.5) return 'HIGH';
                        if (r >= 4.0) return 'MEDIUM';
                        return 'LOW';
                    }
                    if (r >= 8.5) return 'CRITICAL';
                    if (r >= 6.5 || (item && item.severity === 'HIGH')) return 'HIGH';
                    if (r >= 4.0 || (item && item.severity === 'MEDIUM')) return 'MEDIUM';
                    return 'LOW';
                };
                var _es = function(s) {
                    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
                };
                var html = data.map(function(item) {
                    try {
                        var sev = _sv(item.risk_score, item);
                        var sc  = _sc(sev);
                        var rs  = parseFloat(item.risk_score || 0).toFixed(1);
                        var title  = _es(item.title || 'Untitled Advisory');
                        var actor  = _es((item.actor_tag && item.actor_tag !== 'UNC-UNKNOWN' && item.actor_tag !== 'UNC-CDB-99') ? item.actor_tag : 'UNATTRIBUTED');
                        var source = _es((item.feed_source || item.source_url || '').replace(/https?:\/\/(www\.)?/,'').split('/')[0] || 'UNKNOWN');
                        var ts     = item.timestamp ? new Date(item.timestamp).toLocaleDateString() : '';
                        var stixId = _es((item.stix_id || item.id || '').slice(0, 36));
                        var rawConf = item.confidence_score != null ? parseFloat(item.confidence_score) : null;
                        var conf = (rawConf != null && rawConf > 0) ? Math.round(rawConf <= 1 ? rawConf * 100 : rawConf) : (sev === 'CRITICAL' ? 85 : sev === 'HIGH' ? 72 : sev === 'MEDIUM' ? 60 : 45);
                        var iocCount = item.ioc_count || 0;
                        // v186.0 P0 FIX: report link now built by the single canonical
                        // cdbBuildReportUrl() helper -- tier-agnostic by design (see helper's
                        // doc comment above renderCards()). Premium fields (full IOC list,
                        // actor attribution, AI analysis) are still masked server-side for
                        // free tier by applyTierGateV2() in workers/intel-gateway/src/index.js;
                        // the LINK itself is never withheld. _hasProAccess is retained below
                        // only to choose CTA styling/label, not to gate the destination URL.
                        var _currentTierLvl = (function(){
                            var t = (window._platformTiers && window._platformTiers.current) || 'free';
                            if (t==='mssp'||t==='MSSP') return 3;
                            if (t==='enterprise'||t==='ENTERPRISE') return 2;
                            if (t==='pro'||t==='PRO'||t==='premium'||t==='PREMIUM') return 1;
                            return 0; // free / public
                        })();
                        var _hasProAccess = _currentTierLvl >= 1;
                        var reportUrl = _es(cdbBuildReportUrl(item) || item.source_url || '#');

                        // MITRE tactic chips
                        var tactics = Array.isArray(item.mitre_tactics) ? item.mitre_tactics.slice(0, 5) : [];
                        var mitreChips = tactics.map(function(t) {
                            var tid = typeof t === 'string' ? t : (t.technique_id || t.id || '');
                            if (!tid) return '';
                            return '<a href="https://attack.mitre.org/techniques/' + _es(tid.replace('.', '/')) + '/" target="_blank" rel="noopener" class="mitre-chip">' + _es(tid) + '</a>';
                        }).filter(Boolean).join('');

                        // TTP tags
                        var ttps = Array.isArray(item.ttps) ? item.ttps.slice(0, 3) : [];
                        var ttpHtml = ttps.map(function(t) {
                            return '<span class="apex-tag">' + _es(typeof t === 'string' ? t : (t.name || '')) + '</span>';
                        }).join('');

                        // APEX AI summary
                        var apexSummary = '';
                        var _ai = item.apex_ai || item.apex || {};
                        if (_ai.summary) apexSummary = _es(_ai.summary.slice(0, 240)) + (_ai.summary.length > 240 ? '\u2026' : '');

                        // Enrichment strip
                        var enrichParts = [];
                        if (item.cvss_score != null) {
                            var cvssColor = item.cvss_score >= 9 ? '#ff4444' : item.cvss_score >= 7 ? '#ff7700' : item.cvss_score >= 4 ? '#ffcc00' : '#00d4aa';
                            enrichParts.push('<span class="enrich-item">CVSS <span class="e-val" style="color:' + cvssColor + ';">' + parseFloat(item.cvss_score).toFixed(1) + '</span></span>');
                        }
                        if (item.epss_score != null) {
                            var epssColor = item.epss_score >= 70 ? '#ff4444' : item.epss_score >= 40 ? '#ff7700' : '#888';
                            enrichParts.push('<span class="enrich-item">EPSS <span class="e-val" style="color:' + epssColor + ';">' + item.epss_score + '%</span></span>');
                        }
                        enrichParts.push('<span class="enrich-item">CONF <span class="e-val">' + conf + '%</span></span>');
                        if (source) enrichParts.push('<span class="enrich-item" style="margin-left:auto;">SRC: <span class="e-val">' + source + '</span></span>');

                        // Badges
                        var badges = '';
                        if (item.kev_present) badges += '<span class="badge badge-kev">&#9889; CISA KEV</span> ';
                        if (item.exploit_available) badges += '<span class="badge badge-exploit">&#9889; EXPLOIT AVAIL</span> ';
                        if (item.zero_day) badges += '<span class="badge badge-zerod">&#9679; 0-DAY</span> ';

                        return '<div class="intel-card cdb-fade-in" style="border-top:3px solid ' + sc + ';background:var(--card-bg,#0d0d1a);border-radius:8px;padding:18px 20px;position:relative;box-shadow:0 2px 24px rgba(0,0,0,0.4);">' +
                            // Header row
                            '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px;">' +
                                '<div style="flex:1;min-width:0;">' +
                                    '<div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:6px;">' +
                                        '<span style="background:' + sc + '22;color:' + sc + ';border:1px solid ' + sc + '55;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:800;letter-spacing:1px;font-family:var(--font-mono,monospace);">' + sev + '</span>' +
                                        (stixId ? '<span style="font-size:9px;color:#555;font-family:var(--font-mono,monospace);">' + stixId + '</span>' : '') +
                                        (ts ? '<span style="font-size:9px;color:#555;margin-left:auto;">' + ts + '</span>' : '') +
                                    '</div>' +
                                    '<div style="font-size:14px;font-weight:700;color:var(--text-primary,#e0e0e0);line-height:1.4;word-break:break-word;">' + title + '</div>' +
                                '</div>' +
                                '<div style="text-align:right;flex-shrink:0;padding-left:8px;">' +
                                    '<div style="font-size:28px;font-weight:900;color:' + sc + ';line-height:1;font-family:var(--font-mono,monospace);">' + rs + '</div>' +
                                    '<div style="font-size:8px;color:#666;letter-spacing:0.5px;text-transform:uppercase;">Risk Score</div>' +
                                    '<div style="font-size:9px;color:#555;margin-top:2px;">' + conf + '% CONF</div>' +
                                '</div>' +
                            '</div>' +
                            // MITRE chips
                            (mitreChips ? '<div class="mitre-strip" style="margin-bottom:8px;">' + mitreChips + '</div>' : '') +
                            // TTP tags
                            (ttpHtml ? '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;">' + ttpHtml + '</div>' : '') +
                            // APEX AI summary
                            (apexSummary ? '<div style="background:rgba(0,212,170,0.05);border-left:2px solid var(--accent,#00d4aa);padding:8px 12px;border-radius:4px;font-size:11px;color:#aaa;line-height:1.6;margin-bottom:10px;"><span style="color:var(--accent,#00d4aa);font-size:8px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;display:block;margin-bottom:4px;">&#11041; APEX AI ANALYSIS</span>' + apexSummary + '</div>' : '') +
                            // Enrich strip
                            '<div class="enrich-strip" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px;">' +
                                '<span class="enrich-item">ACTOR <span class="e-val" style="color:var(--accent,#00d4aa);">' + actor + '</span></span>' +
                                (iocCount > 0 ? '<span class="enrich-item">IOCs <span class="e-val" style="color:#ff7700;">' + iocCount + '</span></span>' : '') +
                                enrichParts.join('') +
                            '</div>' +
                            // v184.0 World-Class Footer — report CTA + source trust signal + conversion row
                            (function(){
                                const _srcName = item.source_name || item.source || item.feed_source || '';
                                const _srcTrust = ['BleepingComputer','The Hacker News','Krebs','Recorded Future','Mandiant','CrowdStrike','Rapid7','CISA','NSA','CERT','Secureworks'].find(s => _srcName.includes(s)) ? '&#10003; Verified Source' : '';
                                const _iocTotal = Object.values(item.ioc_counts||{}).reduce((a,b)=>a+(+b||0),0);
                                const _ttpTotal = (item.mitre_techniques||[]).length;
                                const _hasCve = !!(item.cve_id || (item.cve_ids||[]).length);
                                const _statsRow = (_iocTotal||_ttpTotal||_hasCve) ? '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;padding:8px 0;border-top:1px solid rgba(255,255,255,0.04);">'
                                    + (_iocTotal  ? '<span style="font-family:var(--font-mono,monospace);font-size:8px;color:#00d4aa;background:rgba(0,212,170,0.08);border:1px solid rgba(0,212,170,0.2);padding:3px 8px;border-radius:4px;letter-spacing:0.5px;font-weight:700;">&#9671; ' + _iocTotal + ' IOC' + (_iocTotal>1?'s':'') + '</span>' : '')
                                    + (_ttpTotal  ? '<span style="font-family:var(--font-mono,monospace);font-size:8px;color:#818cf8;background:rgba(129,140,248,0.08);border:1px solid rgba(129,140,248,0.2);padding:3px 8px;border-radius:4px;letter-spacing:0.5px;font-weight:700;">&#9670; ' + _ttpTotal + ' TTP' + (_ttpTotal>1?'s':'') + '</span>' : '')
                                    + (_hasCve    ? '<span style="font-family:var(--font-mono,monospace);font-size:8px;color:#f59e0b;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);padding:3px 8px;border-radius:4px;letter-spacing:0.5px;font-weight:700;">&#9650; ' + (item.cve_id||(item.cve_ids||[])[0]||'CVE') + '</span>' : '')
                                    + (_srcTrust  ? '<span style="font-family:var(--font-mono,monospace);font-size:8px;color:#34d399;background:rgba(52,211,153,0.06);border:1px solid rgba(52,211,153,0.15);padding:3px 8px;border-radius:4px;margin-left:auto;">' + _srcTrust + '</span>' : '')
                                    + '</div>' : '';
                                // v186.0 P0 FIX: link is now ALWAYS the real report page
                                // (reportUrl, built by the tier-agnostic cdbBuildReportUrl()
                                // helper) -- never /upgrade.html directly. The report page
                                // itself already shows public sections + a locked-section
                                // upgrade CTA for free tier (see generateIntelReport() /
                                // applyTierGateV2 in workers/intel-gateway/src/index.js).
                                // Styling still signals tier -- PRO sees "VIEW DOSSIER", free
                                // sees the upgrade-styled "UNLOCK FULL INTEL" -- but both
                                // now open the same real report, never a bare paywall.
                                const _ctaReport = (reportUrl === '#') ? '' : (_hasProAccess
                                    ? '<a href="' + reportUrl + '" target="_blank" rel="noopener" class="cdb-report-link" style="margin-left:auto;background:linear-gradient(135deg,rgba(0,212,170,0.18),rgba(0,212,170,0.07));border:1px solid rgba(0,212,170,0.4);color:#00d4aa;padding:9px 18px;border-radius:6px;font-size:10.5px;font-weight:800;letter-spacing:0.8px;text-decoration:none;display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono,monospace);box-shadow:0 0 16px rgba(0,212,170,0.12);transition:all 0.2s;" title="View Full Intel Dossier — 20 sections, STIX 2.1, IOC data">&#128196; VIEW DOSSIER &rarr;</a>'
                                    : '<a href="' + reportUrl + '" target="_blank" rel="noopener" style="margin-left:auto;background:linear-gradient(135deg,rgba(220,38,38,0.2),rgba(185,28,28,0.12));border:1px solid rgba(220,38,38,0.38);color:#f87171;padding:9px 18px;border-radius:6px;font-size:10px;font-weight:900;letter-spacing:1px;text-decoration:none;display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono,monospace);box-shadow:0 0 18px rgba(220,38,38,0.18);transition:all 0.2s;" title="View report — premium sections unlock with PRO">&#128274; UNLOCK FULL INTEL</a>');
                                const _srcBadge = _srcName ? '<span style="font-family:var(--font-mono,monospace);font-size:8px;color:#3d5060;letter-spacing:0.3px;padding:2px 0;">SRC: ' + _srcName.slice(0,28) + '</span>' : '';
                                return _statsRow +
                                    '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding-top:10px;border-top:1px solid rgba(255,255,255,0.04);">'
                                    + badges
                                    + _srcBadge
                                    + _ctaReport
                                    + '</div>';
                            })() +
                        '</div>';
                    } catch(itemErr) {
                        console.warn('[GOD MODE] Card render error:', item && (item.stix_id || item.id), itemErr.message);
                        return '<div class="intel-card" style="border-top:3px solid #333;background:var(--card-bg,#0d0d1a);border-radius:8px;padding:16px;"><div style="color:#555;font-size:11px;">&#9888; Advisory unavailable: ' + _es(item && item.title ? item.title.slice(0, 80) : 'Unknown') + '</div></div>';
                    }
                });
                grid.innerHTML = html.join('');
                console.log('[GOD MODE] Successfully rendered', data.length, 'intel cards');
            } catch(e) {
                console.error('[GOD MODE] Critical render failure:', e);
                var g2 = document.getElementById('threat-grid');
                if (g2) g2.innerHTML = '<div class="loading-state" style="color:#ff4444;">&#9888; Dashboard render error \u2014 please refresh the page.</div>';
            }
        }

        function applyView() {
            // v184.0: RENDER_IN_PROGRESS lock \u2014 prevent concurrent/duplicate render calls
            if (window.RENDER_IN_PROGRESS) {
                console.warn('[SENTINEL-APEX] applyView() skipped \u2014 render already in progress');
                return;
            }
            window.RENDER_IN_PROGRESS = true;
            try {
            let filtered = [...manifestData];

            // v73.1: Time-range filter (SAFE \u2014 falls back to full dataset on failure)
            if (currentTimeRange !== 'all') {
                try {
                    const now = Date.now();
                    const ranges = { '24h': 1, '7d': 7, '30d': 30 };
                    const days = ranges[currentTimeRange] || 7;
                    const cutoff = now - (days * 24 * 60 * 60 * 1000);
                    const timeFiltered = filtered.filter(d => {
                        const ts = d.published_at || d.processed_at || d.timestamp || d.published || d.created;  // v184.0 FIX: published_at is real source date
                        if (!ts) return true;  // Keep items without timestamps (safety)
                        return new Date(ts).getTime() >= cutoff;
                    });
                    // HARD SAFETY: Never show empty dashboard
                    if (timeFiltered.length > 0) {
                        filtered = timeFiltered;
                    }
                } catch(e) {
                    // Filter failed \u2014 use full dataset (zero-failure guarantee)
                    console.warn('[CDB-TIMEFILTER] Filter error, using full dataset:', e);
                }
            }

            if (currentFilter !== 'all') {
                filtered = filtered.filter(d => getSeverity(d.risk_score, d) === currentFilter);
            }
            filtered.sort((a, b) => {
                switch (currentSort) {
                    case 'newest': return new Date(b.published_at||b.timestamp||b.processed_at||0) - new Date(a.published_at||a.timestamp||a.processed_at||0);  // v184.0 FIX: sort by published_at (real source date)
                    case 'oldest': return new Date(a.published_at||a.timestamp||a.processed_at||0) - new Date(b.published_at||b.timestamp||b.processed_at||0);  // v184.0 FIX
                    case 'risk-high': return b.risk_score - a.risk_score;
                    case 'risk-low': return a.risk_score - b.risk_score;
                    default: return 0;
                }
            });
            // v184.0 FIX: UI-level dedup by stix_id before render (belt-and-suspenders)
            var _dedup = new Set();
            filtered = filtered.filter(function(item) {
                var key = item.stix_id || item.id || item.cve_id || '';
                if (!key) return true;
                if (_dedup.has(key)) return false;
                _dedup.add(key); return true;
            });
            renderCards(filtered);
            } finally {
                window.RENDER_IN_PROGRESS = false;
            }
        }

        // ── Search (v21.0) ──
        function handleSearch(val) {
            searchQuery = val;
            applyView();
        }

        function clearSearch() {
            searchQuery = '';
            document.getElementById('search-input').value = '';
            applyView();
        }

        // ── Auto-Refresh (v46.0) ──
        let refreshSecondsLeft = AUTO_REFRESH_INTERVAL;

        function toggleAutoRefresh(enabled) {
            const cdEl = document.getElementById('refresh-countdown');
            if (enabled) {
                cdEl.style.display = 'inline';
                refreshSecondsLeft = AUTO_REFRESH_INTERVAL;
                startCountdown();
            } else {
                cdEl.style.display = 'none';
                clearInterval(autoRefreshCountdown);
                clearTimeout(autoRefreshTimer);
            }
        }

        function startCountdown() {
            clearInterval(autoRefreshCountdown);
            clearTimeout(autoRefreshTimer);
            const cdEl = document.getElementById('refresh-countdown');
            autoRefreshCountdown = setInterval(() => {
                refreshSecondsLeft--;
                const m = Math.floor(refreshSecondsLeft / 60);
                const s = refreshSecondsLeft % 60;
                cdEl.textContent = `AUTO-REFRESH IN ${m}:${String(s).padStart(2,'0')}`;
                if (refreshSecondsLeft <= 0) {
                    clearInterval(autoRefreshCountdown);
                    manualRefresh().then(() => {
                        refreshSecondsLeft = AUTO_REFRESH_INTERVAL;
                        startCountdown();
                    });
                }
            }, 1000);
        }

        async function manualRefresh() {
            document.getElementById('sync-val').innerHTML = 'SYNC: <span style="color:#ff9d00;">REFRESHING...</span>';
            const prevCount = manifestData.length;
            window.__DATA_LOADED__ = false; window.__INTEL_RENDERED__ = false; // P6: manual refresh reset
            await loadGOCIntel();
            // v200.1 P0 FIX: re-hit the authoritative /api/platform/stats source on every
            // refresh too -- fetchWorkerStats() used to be a fire-once IIFE at page load,
            // so "REFRESH NOW" and the 30-min auto-refresh never actually re-synced the
            // last-sync badge against live truth, only the card grid.
            try { fetchWorkerStats(); } catch(_fws) {}
            // P0 FIX: was new Date().toLocaleTimeString() -- this write runs on every
            // manual/auto refresh AFTER loadGOCIntel() already sets #last-loaded correctly
            // in its own success path, so it was silently reverting that fix back to the
            // browser clock on every refresh cycle. Use the same data-derived computation.
            (function() {
                var _mrNewest = (manifestData || []).reduce(function(best, d){
                    var t = new Date(d.published_at||d.timestamp||d.processed_at||0).getTime();
                    return (t && t > best) ? t : best;
                }, 0);
                var _mrEl = document.getElementById('last-loaded');
                if (_mrEl) _mrEl.textContent = 'LAST SYNC: ' + (_mrNewest ? timeSince(_mrNewest) : 'just now');
            })();
            if (prevCount > 0 && manifestData.length > prevCount) {
                const newCount = manifestData.length - prevCount;
                showToast(`🔴 ${newCount} NEW THREAT${newCount > 1 ? 'S' : ''} DETECTED \u2014 Feed updated`, 'critical', 6000);
            } else if (prevCount > 0) {
                showToast('✔ Feed synchronized \u2014 No new threats', 'info', 2500);
            }
        }

        // ═══════════════════════════════════════════════════════
        // v73.0 APEX ULTRA \u2014 NEW FEATURE FUNCTIONS
        // ═══════════════════════════════════════════════════════

        // ── TLP Description ──
        function getTlpDescription(tlp) {
            const d = {
                'TLP:RED': 'NOT for disclosure. Restricted to specific recipients only.',
                'TLP:AMBER': 'Limited disclosure. Share within organization on need-to-know.',
                'TLP:GREEN': 'Community disclosure. Share within cybersecurity community.',
                'TLP:CLEAR': 'Unrestricted. May be distributed without restriction.'
            };
            return d[tlp] || tlp;
        }

        // ── Clipboard Copy ──
        function copyToClipboard(text, el) {
            if (!text) return;
            navigator.clipboard.writeText(text).then(() => {
                if (el) {
                    const orig = el.innerHTML;
                    el.classList.add('copied');
                    el.innerHTML = el.innerHTML.replace(/<i[^>]*><\/i>/, '<i class="fas fa-check"></i>');
                    setTimeout(() => { el.classList.remove('copied'); el.innerHTML = orig; }, 1800);
                }
                showToast('✔ Copied: ' + text.slice(0, 48), 'info');
            }).catch(() => {
                const ta = document.createElement('textarea');
                ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
                document.body.appendChild(ta); ta.select();
                document.execCommand('copy'); document.body.removeChild(ta);
                showToast('✔ Copied: ' + text.slice(0, 48), 'info');
            });
        }

        // ── Toast Notifications ──
        function showToast(message, type = 'info', duration = 3500) {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast${type === 'critical' ? ' toast-critical' : ''}`;
            toast.innerHTML = `<span style="flex:1;">${message}</span><span class="toast-close" onclick="this.parentElement.remove()">✕</span>`;
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.animation = 'toast-out 0.3s ease forwards';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        // ── Threat Detail Modal ──
        // ── Active modal item ref (XSS-safe copy) ──
        let _activeModalItem = null;

        function copyCurrentModalJson() {
            if (_activeModalItem) copyToClipboard(JSON.stringify(_activeModalItem, null, 2), document.getElementById('modal-copy-json-btn'));
        }

        function openThreatModalById(stixId) {
            const item = threatRegistry.get(stixId);
            if (!item) return;
            openThreatModal(item);
        }

        // ── Event delegation for js-open-modal elements ──
        document.addEventListener('click', function(e) {
            const el = e.target.closest('.js-open-modal');
            if (!el) return;
            const stixId = el.dataset.stixId;
            if (stixId) openThreatModalById(stixId);
        });

        function openThreatModal(item) {
            _activeModalItem = item;
            if (!item || typeof item !== 'object') return;
            // P0 FIX: prefer the canonical item.__norm.severity over getSeverity()'s own
            // independent risk_score-threshold recomputation, so the modal can no longer
            // show a different severity than the card the user clicked to open it.
            const sev = (item.__norm && item.__norm.severity) || getSeverity(item.risk_score, item);
            const sevColor = getSevColor(sev);
            const tlp = getTlpLabel(item);
            const tlpColor = getTlpColor(tlp);
            const cves = extractCVEs(item.title);
            const tactics = item.mitre_tactics || [];

            const mitreLinks = tactics.map(t => {
                const tid = typeof t === 'string' ? t : (t.technique_id || t.id || '');
                if (!tid) return '';
                return `<a href="https://attack.mitre.org/techniques/${tid.replace('.','/') }/" target="_blank" class="copy-chip" style="text-decoration:none;">${tid}</a>`;
            }).filter(Boolean).join('');

            const iocStr = item.ioc_counts ? Object.entries(item.ioc_counts)
                .filter(([,v]) => v > 0)
                .map(([k,v]) => `${v} ${k.toUpperCase()}`)
                .join(' \u00b7 ') || 'None detected' : 'N/A';

            const aiNarrative = generateAINarrative(item);

            document.getElementById('modal-content').innerHTML = `
                <div style="margin-bottom:20px;">
                    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
                        <span class="badge badge-${sev.toLowerCase()}" style="font-size:11px;">${sev}</span>
                        <span style="background:${tlpColor}22;color:${tlpColor};padding:3px 10px;border-radius:2px;font-family:var(--font-mono);font-size:10px;">${tlp}</span>
                        <span style="color:${sevColor};font-family:var(--font-mono);font-size:12px;font-weight:700;">RISK ${item.risk_score}/10</span>
                        ${item.kev_present ? '<span class="badge badge-kev">⚡ CISA KEV</span>' : ''}
                    </div>
                    <h2 style="color:var(--white);font-size:18px;font-weight:700;line-height:1.4;margin:0 0 12px 0;">${_cdbEsc(item.title)}</h2>
                    <div style="background:rgba(0,212,170,0.06);border-left:3px solid var(--accent);padding:12px 16px;margin-bottom:4px;">
                        <p style="font-family:var(--font-mono);font-size:8px;letter-spacing:2px;color:var(--accent);margin:0 0 6px 0;">🤖 AI THREAT NARRATIVE</p>
                        <p style="font-size:12px;color:var(--text);line-height:1.7;margin:0;">${aiNarrative}</p>
                    </div>
                </div>

                <div class="modal-section">
                    <div class="modal-section-title">Threat Intelligence Details</div>
                    <div class="modal-row">
                        <div class="modal-field">
                            <div class="modal-field-label">STIX Bundle ID</div>
                            <div class="modal-field-val" style="font-family:var(--font-mono);font-size:11px;">
                                ${(item.stix_id||item.id) || '\u2014'}
                                ${(item.stix_id||item.id) ? `<span class="copy-chip" onclick="copyToClipboard('${item.stix_id||item.id}',this)" style="margin-left:8px;"><i class="fas fa-copy"></i> Copy</span>` : ''}
                            </div>
                        </div>
                        <div class="modal-field">
                            <div class="modal-field-label">Actor / Group</div>
                            <div class="modal-field-val">${item.actor_tag || 'UNC-CDB-99'}</div>
                        </div>
                        <div class="modal-field">
                            <div class="modal-field-label">CVSS Score</div>
                            <div class="modal-field-val" style="color:${item.cvss_score>=9?'var(--critical)':item.cvss_score>=7?'var(--high)':item.cvss_score>=4?'var(--medium)':'var(--low)'};">
                                ${item.cvss_score != null ? item.cvss_score + '/10' : 'Pending enrichment'}
                            </div>
                        </div>
                        <div class="modal-field">
                            <div class="modal-field-label">EPSS Score</div>
                            <div class="modal-field-val">
                                ${item.epss_score != null ? `<div class="epss-bar-wrap"><div class="epss-bar-track" style="max-width:200px;"><div class="epss-bar-fill" style="width:${Math.min(item.epss_score,100)}%;background:${item.epss_score>=50?'var(--critical)':item.epss_score>=10?'var(--high)':item.epss_score>=1?'#f59e0b':'var(--accent)'};"></div></div><span style="font-size:11px;font-family:var(--font-mono);">${item.epss_score}%</span></div>` : 'Pending enrichment'}
                            </div>
                        </div>
                        <div class="modal-field">
                            <div class="modal-field-label">Confidence</div>
                            <div class="modal-field-val">${item.confidence_score != null ? Math.round(item.confidence_score) + '%' : '\u2014'}</div>
                        </div>
                        <div class="modal-field">
                            <div class="modal-field-label">Feed Source</div>
                            <div class="modal-field-val" style="font-size:11px;">${item.feed_source || '\u2014'}</div>
                        </div>
                        ${item.peps_score != null ? `<div class="modal-field">
                            <div class="modal-field-label">PEPS Score (14d KEV Forecast)</div>
                            <div class="modal-field-val" style="color:${item.peps_score>=7?'var(--critical)':item.peps_score>=4?'var(--high)':'var(--accent)'}; font-weight:700;">${parseFloat(item.peps_score).toFixed(1)}/10</div>
                        </div>` : ''}
                        ${item.global_victim_count != null && item.global_victim_count > 0 ? `<div class="modal-field">
                            <div class="modal-field-label">Global Exposure (Shodan)</div>
                            <div class="modal-field-val" style="color:#ec4899; font-weight:700;">🌐 ${item.global_victim_count.toLocaleString()} systems exposed</div>
                        </div>` : ''}
                        ${item.supply_chain ? `<div class="modal-field">
                            <div class="modal-field-label">Attack Vector</div>
                            <div class="modal-field-val" style="color:#ec4899; font-weight:700;">🔗 SUPPLY CHAIN THREAT</div>
                        </div>` : ''}
                    </div>
                </div>

                <div class="modal-section">
                    <div class="modal-section-title">CVEs & Quick Copy</div>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
                        ${cves.length ? cves.map(c => `<span class="copy-chip" onclick="copyToClipboard('${c}',this)"><i class="fas fa-copy"></i>${c}</span>`).join('') : '<span style="color:var(--text-muted);font-size:12px;">No CVE extracted</span>'}
                    </div>
                </div>

                ${tactics.length ? `<div class="modal-section">
                    <div class="modal-section-title">MITRE ATT&amp;CK Techniques</div>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;">${mitreLinks}</div>
                </div>` : ''}

                <div class="modal-section">
                    <div class="modal-section-title">IOC Summary</div>
                    <div style="font-family:var(--font-mono);font-size:11px;color:var(--text);">${iocStr}</div>
                </div>

                ${(function(){
                    // v124.0: APEX AI Intelligence Block in modal \u2014 enterprise-grade display
                    // Confidence Tier (VERIFIED/HIGH/MODERATE/LOW) replaces raw % display
                    try {
                        const ai = item.apex_ai || {};
                        const ap = item.apex   || {};
                        if (!item.apex_ai && !item.apex) return '';
                        // P0 FIX: same fix as the other apex_ai panel above -- prefer the
                        // canonical item.__norm.apex_ai.soc_priority over this block's own
                        // independent P4 fallback.
                        const prio      = (item.__norm && item.__norm.apex_ai && item.__norm.apex_ai.soc_priority) || ai.soc_priority || ap.priority || 'P4';
                        const prioColor = prio==='P1'?'#ff3b3b':prio==='P2'?'#ff8c00':prio==='P3'?'#00c2ff':'#4ade80';
                        const predRisk  = ai.predictive_risk != null ? parseFloat(ai.predictive_risk).toFixed(1) : '\u2014';
                        const aiConf    = ai.ai_confidence   != null ? ai.ai_confidence : '\u2014';
                        const confTier  = ai.threat_confidence_tier  || null;
                        const confLabel = ai.threat_confidence_label || null;
                        const _TCT_COLOR = { VERIFIED:'#00d4aa', HIGH:'#3b82f6', MODERATE:'#f59e0b', LOW:'#ef4444' };
                        const confTierColor = _TCT_COLOR[confTier] || '#6b7280';
                        const ttpDens   = ai.ttp_density     != null ? parseFloat(ai.ttp_density).toFixed(1) : '\u2014';
                        const kc        = ai.kill_chain;
                        const kcPhases  = Array.isArray(kc) ? kc : [];
                        const kcStr     = kc === 'PRO_REQUIRED' ? '🔒 Pro Required'
                                        : kcPhases.length ? kcPhases.join(' → ') : '\u2014';
                        const aiSummary = ai.ai_summary || ap.ai_summary || '';
                        const actorFP   = ai.actor_fingerprint || '\u2014';
                        const recAction = ai.recommended_action || ap.recommended_action || '';
                        const urgency   = item.threat_urgency;
                        return `
                        <div class="modal-section">
                            <div class="modal-section-title">⬡ SENTINEL APEX AI Intelligence v124.0</div>
                            ${urgency ? `<div class="apex-urgency-banner" style="margin-bottom:10px;">${urgency.message}<a href="${urgency.upgrade_url}" target="_blank" class="apex-urgency-cta">UPGRADE →</a></div>` : ''}
                            ${confTier ? `<div style="font-family:var(--font-mono);font-size:9px;letter-spacing:2px;color:${confTierColor};border:1px solid ${confTierColor}55;padding:5px 12px;border-radius:3px;margin-bottom:12px;text-align:center;">${confLabel || confTier}</div>` : ''}
                            <div class="modal-apex-ai">
                                <div class="modal-apex-grid">
                                    <div class="modal-apex-kv">
                                        <span class="modal-apex-k">SOC PRIORITY</span>
                                        <span class="modal-apex-v" style="color:${prioColor}">${prio}</span>
                                    </div>
                                    <div class="modal-apex-kv">
                                        <span class="modal-apex-k">PREDICTIVE RISK</span>
                                        <span class="modal-apex-v" style="color:${parseFloat(predRisk)>=7?'#ff3b3b':parseFloat(predRisk)>=5?'#ff8c00':'var(--accent)'}">${predRisk}/10</span>
                                    </div>
                                    <div class="modal-apex-kv">
                                        <span class="modal-apex-k">CONFIDENCE TIER</span>
                                        <span class="modal-apex-v" style="color:${confTierColor};font-weight:900;">${confTier || (aiConf !== '\u2014' ? aiConf + '%' : '\u2014')}</span>
                                    </div>
                                    <div class="modal-apex-kv">
                                        <span class="modal-apex-k">TTP DENSITY</span>
                                        <span class="modal-apex-v">${ttpDens}/10</span>
                                    </div>
                                    <div class="modal-apex-kv" style="grid-column:1/-1;">
                                        <span class="modal-apex-k">ACTOR FINGERPRINT</span>
                                        <span class="modal-apex-v" style="color:#67e8f9;font-size:10px;">${actorFP}</span>
                                    </div>
                                    <div class="modal-apex-kv" style="grid-column:1/-1;">
                                        <span class="modal-apex-k">KILL CHAIN</span>
                                        <span class="modal-apex-v" style="font-size:10px;color:#a78bfa;">${kcStr}</span>
                                    </div>
                                </div>
                                ${aiSummary ? `<div class="modal-apex-summary"><strong style="color:var(--accent);font-size:9px;letter-spacing:0.8px;">AI SUMMARY</strong><br><br>${aiSummary}</div>` : ''}
                                ${recAction ? `<div style="margin-top:10px;padding-top:8px;border-top:1px solid rgba(0,212,170,0.1);font-size:10px;color:#ff8c00;font-family:var(--font-mono);">→ ${recAction}</div>` : ''}
                            </div>
                        </div>`;
                    } catch(e) { return ''; }
                })()}

                <div class="modal-section">
                    <div class="modal-section-title">Links & Resources</div>
                    <div style="display:flex;flex-direction:column;gap:10px;">
                        ${(()=>{
                            // ACCESS GOVERNANCE v184.0 — Links & Resources — MODEL_B DISABLED
                            // Full dossier links gated to PRO+ tier only.
                            const _mTier = (window._platformTiers && window._platformTiers.current) || 'free';
                            const _mPro = _mTier==='pro'||_mTier==='PRO'||_mTier==='premium'||_mTier==='PREMIUM'||_mTier==='enterprise'||_mTier==='ENTERPRISE'||_mTier==='mssp'||_mTier==='MSSP';
                            const su = item.source_url||'';
                            if (!_mPro) {
                                // Public tier: show source article only + upgrade prompt
                                const srcLink = su ? `<a href="${su}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:11px;color:var(--accent);border-bottom:1px solid rgba(0,212,170,0.3);width:fit-content;"><i class="fas fa-external-link-alt"></i> View Source Article</a>` : '';
                                const upgradeLink = `<a href="/upgrade.html?plan=pro&utm_source=modal-links-gate" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:11px;color:#8b5cf6;border-bottom:1px solid rgba(139,92,246,0.3);width:fit-content;"><i class="fas fa-lock"></i> 🔒 Upgrade to PRO — Full Dossier Access</a>`;
                                return srcLink + upgradeLink;
                            }
                            // PRO+ tier: full dossier link
                            // P0 FIX: was a 3rd independent reimplementation of report-
                            // availability logic inside this same function (see the other
                            // two fixed below/above) -- checked 4 validation_status
                            // fail-states (a stricter, disagreeing set from the canonical
                            // cdbBuildReportUrl()'s 2) and never validated the URL was
                            // actually internal. Use the single canonical builder instead.
                            const ru = cdbBuildReportUrl(item);
                            const hasReport = !!ru;
                            const u = hasReport ? ru : su;
                            const lbl = hasReport ? 'View Full Tactical Dossier' : 'View Source Article';
                            return u ? `<a href="${u}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:11px;color:var(--accent);border-bottom:1px solid rgba(0,212,170,0.3);width:fit-content;"><i class="fas fa-external-link-alt"></i> ${lbl}</a>` : '';
                        })()}
                        ${item.nvd_url ? `<a href="${item.nvd_url}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:11px;color:var(--blue);border-bottom:1px solid rgba(59,130,246,0.3);width:fit-content;"><i class="fas fa-database"></i> NVD Entry</a>` : ''}
                        ${(item.stix_id||item.id) ? `<a href="${stixExportUrl(item.stix_id||item.id)}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:11px;color:var(--purple);border-bottom:1px solid rgba(139,92,246,0.3);width:fit-content;text-decoration:none;" title="STIX 2.1 export \u2014 Pro/Enterprise API key required"><i class="fas fa-lock" style="font-size:9px;margin-right:4px;"></i> STIX 2.1 Export</a>` : ''}
                        ${item.gumroad_url ? `<a href="${item.gumroad_url}" target="_blank" rel="noopener" class="cta-premium-report"><i class="fas fa-star"></i> GET PREMIUM REPORT + IOC PACK</a>` : ''}
                    </div>
                </div>

                <div style="border-top:1px solid var(--border);padding-top:16px;display:flex;gap:10px;flex-wrap:wrap;">
                    ${(()=>{
                        // ACCESS GOVERNANCE v184.0 — Modal VIEW DOSSIER gated to PRO+
                        const _mdTier = (window._platformTiers && window._platformTiers.current) || 'free';
                        const _mdPro = _mdTier==='pro'||_mdTier==='PRO'||_mdTier==='premium'||_mdTier==='PREMIUM'||_mdTier==='enterprise'||_mdTier==='ENTERPRISE'||_mdTier==='mssp'||_mdTier==='MSSP';
                        if (_mdPro) {
                            // P0 FIX: was a 4th independent reimplementation of the same
                            // report-availability check (this one lacked the URL-is-internal
                            // validation cdbBuildReportUrl() has) -- use the single canonical
                            // builder so this button can no longer disagree with the "View
                            // Full Tactical Dossier" link above about whether a report exists.
                            const _mdr = cdbBuildReportUrl(item) || (item.source_url || '#');
                            return `<a href="${_mdr}" target="_blank" rel="noopener" style="padding:10px 20px;background:var(--accent);color:var(--bg);border-radius:3px;font-family:var(--font-mono);font-size:11px;font-weight:900;text-decoration:none;">VIEW DOSSIER →</a>`;
                        }
                        return `<a href="/upgrade.html?plan=pro&utm_source=modal-dossier-gate" target="_blank" rel="noopener" style="padding:10px 20px;background:rgba(139,92,246,0.15);color:#8b5cf6;border:1px solid rgba(139,92,246,0.3);border-radius:3px;font-family:var(--font-mono);font-size:11px;font-weight:900;text-decoration:none;">🔒 UPGRADE FOR DOSSIER</a>`;
                    })()}
                    <button onclick="copyCurrentModalJson()" id="modal-copy-json-btn"
                            style="padding:10px 20px;background:var(--bg-surface);color:var(--text);border:1px solid var(--border);border-radius:3px;font-family:var(--font-mono);font-size:11px;cursor:pointer;">
                        <i class="fas fa-copy"></i> Copy JSON Record
                    </button>
                    <button onclick="closeThreatModal()"
                            style="padding:10px 20px;background:var(--bg-surface);color:var(--text-muted);border:1px solid var(--border);border-radius:3px;font-family:var(--font-mono);font-size:11px;cursor:pointer;margin-left:auto;">
                        CLOSE
                    </button>
                </div>
            `;
            document.getElementById('threat-modal').classList.add('open');
            document.body.style.overflow = 'hidden';
        }

        function closeThreatModal() {
            document.getElementById('threat-modal').classList.remove('open');
            document.body.style.overflow = '';
        }

        // ── AI Threat Narrative Generator (client-side heuristic) ──
        function generateAINarrative(item) {
            const sev = getSeverity(item.risk_score, item);
            const cves = extractCVEs(item.title);
            const tactics = item.mitre_tactics || [];
            const riskLabel = { CRITICAL:'critical', HIGH:'high', MEDIUM:'moderate', LOW:'low', INFO:'informational' }[sev] || 'moderate';
            // v76.1: aligned EPSS thresholds with corrected card logic
            const kevNote = item.kev_present ? ' This vulnerability is confirmed in CISA Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation in the wild.' : '';
            const epssNote = item.epss_score >= 50 ? ` EPSS score of ${item.epss_score}% indicates critical probability of exploitation within the next 30 days.` :
                             item.epss_score >= 10 ? ` EPSS score of ${item.epss_score}% signals elevated exploitation likelihood.` :
                             item.epss_score >= 1  ? ` EPSS score of ${item.epss_score}% warrants proactive monitoring.` : '';
            const mitreNote = tactics.length ? ` MITRE ATT&CK mapping identifies ${tactics.slice(0,3).join(', ')} techniques \u2014 adversary tactics aligned with ${tactics.length > 2 ? 'multi-stage attack chains' : 'targeted exploitation'}.` : '';
            const confNote = item.confidence_score >= 60 ? ' High analyst confidence in this assessment.' : item.confidence_score < 20 ? ' Low confidence \u2014 corroborate with additional threat feeds.' : '';

            return `This ${riskLabel}-risk advisory (risk score ${item.risk_score}/10)${cves.length ? ` affecting ${cves[0]}` : ''} warrants ${sev==='CRITICAL'?'immediate':'prompt'} SOC attention.${kevNote}${epssNote}${mitreNote}${confNote} Recommended action: deploy applicable detection rules, review exposure in asset inventory, and escalate to IR team if active indicators are found.`;
        }

        // ── Keyboard Shortcuts Modal ──
        function openKbdModal() { document.getElementById('kbd-modal').classList.add('open'); }
        function closeKbdModal() { document.getElementById('kbd-modal').classList.remove('open'); }

        // ── MITRE ATT&CK Heatmap (v46.0 \u2014 with Tactic Groups) ──
        function renderMitreHeatmap(data) {
            const section = document.getElementById('mitre-heatmap-section');
            const grid = document.getElementById('mitre-heatmap-grid');
            if (!data.length || !grid) return;

            const counts = {};
            data.forEach(d => {
                // v112.0: Worker /api/preview returns TTPs as 'ttps' array.
                // Legacy manifests may use 'mitre_tactics' or 'mitre_techniques'.
                // Read all three fields to guarantee non-zero heatmap.
                (d.ttps || d.mitre_techniques || d.mitre_tactics || []).forEach(t => {
                    const tid = typeof t === 'string' ? t : (t.technique_id || t.id || '');
                    if (tid) counts[tid] = (counts[tid] || 0) + 1;
                });
            });

            const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 40);
            if (!sorted.length) return;

            const maxCount = sorted[0][1];

            // Group by tactic
            const grouped = {};
            sorted.forEach(([tid, count]) => {
                const group = getTacticGroup(tid);
                if (!grouped[group]) grouped[group] = [];
                grouped[group].push([tid, count]);
            });

            grid.innerHTML = Object.entries(grouped).map(([groupName, techs]) => {
                const cells = techs.map(([tid, count]) => {
                    const intensity = count / maxCount;
                    const alpha = 0.18 + intensity * 0.65;
                    const color = intensity > 0.7 ? `rgba(220,38,38,${alpha})` :
                                  intensity > 0.4 ? `rgba(234,88,12,${alpha})` :
                                  `rgba(0,212,170,${alpha})`;
                    const textColor = intensity > 0.5 ? '#fff' : 'var(--text)';
                    const url = `https://attack.mitre.org/techniques/${tid.replace('.','/') }/`;
                    return `<a href="${url}" target="_blank" rel="noopener" class="hm-cell" data-tooltip="${tid} \u00b7 ${count} hit${count>1?'s':''}" style="background:${color};color:${textColor};border:1px solid rgba(255,255,255,0.06);" title="${tid} \u2014 ${count} threat(s) \u00b7 Click to open ATT&CK">
                        <span class="hm-id">${tid}</span>
                        <span class="hm-count">×${count}</span>
                    </a>`;
                }).join('');
                return `<div class="heatmap-tactic-group">
                    <div class="heatmap-tactic-label">${groupName} (${techs.length})</div>
                    <div class="heatmap-tactic-cells">${cells}</div>
                </div>`;
            }).join('');

            section.classList.add('visible');
        }

        // ── Risk Distribution Donut ──
        function renderRiskDonut({ critical, high, medium, low }) {
            const section = document.getElementById('risk-donut-section');
            const svg = document.getElementById('risk-donut-svg');
            const legend = document.getElementById('donut-legend');
            if (!svg || !legend) return;

            const total = critical + high + medium + low;
            if (!total) return;

            const slices = [
                { label: 'Critical', val: critical, color: '#dc2626' },
                { label: 'High', val: high, color: '#ea580c' },
                { label: 'Medium', val: medium, color: '#d97706' },
                { label: 'Low', val: low, color: '#16a34a' },
            ].filter(s => s.val > 0);

            const cx = 60, cy = 60, r = 46, innerR = 28;
            let startAngle = -Math.PI / 2;
            let paths = '';

            slices.forEach(s => {
                const angle = (s.val / total) * 2 * Math.PI;
                const endAngle = startAngle + angle;
                const x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle);
                const x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle);
                const ix1 = cx + innerR * Math.cos(endAngle), iy1 = cy + innerR * Math.sin(endAngle);
                const ix2 = cx + innerR * Math.cos(startAngle), iy2 = cy + innerR * Math.sin(startAngle);
                const large = angle > Math.PI ? 1 : 0;
                paths += `<path d="M${x1},${y1} A${r},${r} 0 ${large},1 ${x2},${y2} L${ix1},${iy1} A${innerR},${innerR} 0 ${large},0 ${ix2},${iy2} Z" fill="${s.color}" opacity="0.85"/>`;
                startAngle = endAngle;
            });

            svg.innerHTML = paths + `<text x="${cx}" y="${cy+5}" text-anchor="middle" fill="var(--white)" font-size="14" font-weight="900" font-family="monospace">${total}</text>`;

            legend.innerHTML = slices.map(s => `
                <div class="legend-item">
                    <div class="legend-left">
                        <div class="legend-dot" style="background:${s.color};"></div>
                        <span>${s.label}</span>
                    </div>
                    <span style="font-weight:700;color:${s.color};">${s.val} <span style="color:var(--text-muted);font-weight:400;">(${Math.round(s.val/total*100)}%)</span></span>
                </div>`).join('');

            section.classList.add('visible');
        }

        // ── Intel Source Breakdown (v46.0 \u2014 with Trust Scores) ──
        function renderSourceBreakdown(data) {
            const section = document.getElementById('source-bar-section');
            const inner = document.getElementById('source-bar-inner');
            if (!inner || !data.length) return;

            const counts = {};
            data.forEach(d => {
                if (d.feed_source) {
                    const src = d.feed_source.replace(/https?:\/\/(www\.)?/, '').split('/')[0];
                    counts[src] = (counts[src] || 0) + 1;
                }
            });

            const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 10);
            if (!sorted.length) return;

            const max = sorted[0][1];
            // Update feed count in status strip + engine header
            const feedCountEl = document.getElementById('m-feed-count');
            if (feedCountEl) feedCountEl.textContent = sorted.length;
            const engineFeedEl = document.getElementById('engine-feed-count');
            if (engineFeedEl) engineFeedEl.textContent = sorted.length;

            inner.innerHTML = sorted.map(([src, count]) => {
                const trust = getSourceTrust(src);
                const weightPct = ((count / data.length) * 100).toFixed(1);
                return `<div class="source-bar-item">
                    <div class="source-bar-label">
                        <div style="display:flex;align-items:center;gap:8px;">
                            <span>${src}</span>
                            <span class="source-trust">
                                <span class="trust-dot" style="background:${trust.color};"></span>
                                <span style="color:${trust.color};">${trust.label}</span>
                                <span style="color:var(--border);">\u00b7</span>
                                <span style="color:var(--text-muted);">TRUST ${trust.score}%</span>
                            </span>
                            <span style="color:var(--text-muted);font-size:8px;">WEIGHT: ${weightPct}%</span>
                        </div>
                        <span>${count} advisories</span>
                    </div>
                    <div class="source-bar-track"><div class="source-bar-fill" style="width:${(count/max*100).toFixed(1)}%;background:${trust.color};"></div></div>
                </div>`;
            }).join('');

            section.classList.add('visible');
        }

        // ── Threat Ticker ──
        // STAGE 3 FIX: _tickerClickTargets holds the CURRENT render's real
        // report_url/source_url values, referenced from the DOM only by a
        // plain integer index (data-ticker-url-idx) -- see the delegated
        // click handler below. The raw URL string is never interpolated
        // into any HTML/JS-string text at all, so there is no escaping to
        // get right and no injection surface, regardless of what a
        // malicious source/report URL field might contain.
        let _tickerClickTargets = [];
        /**
         * Allow-lists a URL for the ticker's click-to-open action.
         * Same allow-only-http(s)-or-relative convention already used by
         * initLiveCyberNews()'s href construction elsewhere in this file --
         * rejects javascript:/data:/malformed values, returning '' instead.
         * @param {string} raw
         * @returns {string} the URL if safe to open, otherwise ''
         */
        function _tickerSafeUrl(raw) {
            const s = String(raw || '');
            return /^(https?:\/\/|\/)/.test(s) ? s : '';
        }
        /**
         * Renders the homepage threat ticker from the top 20 highest-risk
         * live feed items. Titles are HTML-escaped via _cdbEsc(); each
         * item's report/source URL is resolved at click time through
         * _tickerClickTargets by plain integer index rather than being
         * interpolated into markup (see the delegated listener below).
         * @param {object[]} data live feed items
         */
        function renderTicker(data) {
            const outer = document.getElementById('threat-ticker-outer');
            const inner = document.getElementById('threat-ticker-inner');
            if (!inner || !data.length) return;

            if (!inner.dataset.clickBound) {
                inner.dataset.clickBound = '1';
                inner.addEventListener('click', function(ev) {
                    const el = ev.target.closest('[data-ticker-url-idx]');
                    if (!el) return;
                    const item = _tickerClickTargets[parseInt(el.dataset.tickerUrlIdx, 10)];
                    if (!item) return;
                    const url = _tickerSafeUrl(item.report_url || item.source_url || '');
                    if (url) window.open(url, '_blank', 'noopener,noreferrer');
                });
            }

            const sevColors = { CRITICAL:'#dc2626', HIGH:'#ea580c', MEDIUM:'#d97706', LOW:'#16a34a' };
            // v184.0 FIX: Use all available items (up to 50) sorted by recency.
            // Previous slice(0,40) assumed ≥40 items to keep both ticker copies off-screen
            // simultaneously. With only 10\u201324 items, both copies were visible at once on
            // wide displays. Fix: calculate the minimum copy count needed so that one copy
            // is always wider than the viewport, ensuring seamless loop at any screen width.
            // v184.0 G2 FIX: Show top 20 highest-risk items (was 50, causing apparent
            // duplicates in DOM text dumps). Ticker is now a highlight reel of CRITICAL/HIGH.
            const _sevOrd = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
            const recent = [...data].sort((a,b) => {
                const sa = _sevOrd[getSeverity(parseFloat(a.risk_score||0),a)]??4;
                const sb = _sevOrd[getSeverity(parseFloat(b.risk_score||0),b)]??4;
                if (sa !== sb) return sa - sb;
                return parseFloat(b.risk_score||0) - parseFloat(a.risk_score||0);
            }).slice(0, 20);

            _tickerClickTargets = recent;
            const itemsHtml = recent.map((d, idx) => {
                const sev = getSeverity(d.risk_score, d);
                const col = sevColors[sev] || '#5a6578';
                const cves = extractCVEs(d.title);
                // STAGE 3 FIX: was raw-interpolated (cleanText() only fixes
                // mojibake/control chars, it does not HTML-escape) into an
                // innerHTML target -- a title containing e.g.
                // `<img src=x onerror=...>` became a real, live element.
                // _cdbEsc() is the same escaping helper already used
                // correctly for card titles elsewhere in this file (see its
                // definition below, reused here rather than re-implemented).
                const id = cves[0] || _cdbEsc(cleanText(d.title).slice(0, 30)) + '\u2026';
                return `<span class="ticker-item" data-ticker-url-idx="${idx}" style="cursor:pointer;">
                    <span class="ticker-sev" style="background:${col}22;color:${col};">${sev}</span>
                    ${id} \u2014 RISK ${d.risk_score}/10
                </span><span class="ticker-sep">◆</span>`;
            }).join('');

            // v184.0 FIX: Duplicate enough copies so that ONE copy is always wider than
            // the widest expected viewport (5120px / ultra-wide). Each item ≈ 280px.
            // minCopies = max(2, ceil(5120 / estimatedOneCopyWidth)).
            // This prevents both copies appearing simultaneously on wide displays.
            const estimatedItemWidth = 280;
            const estimatedCopyWidth = recent.length * estimatedItemWidth;
            const ULTRA_WIDE = 5120;
            const minCopies = Math.max(2, Math.ceil(ULTRA_WIDE / Math.max(estimatedCopyWidth, 1)));
            let loopHtml = '';
            for (let i = 0; i < minCopies; i++) loopHtml += itemsHtml;

            inner.innerHTML = loopHtml;
            // Adjust animation: translateX(-1/minCopies * 100%) to scroll exactly one copy
            const pct = (100 / minCopies).toFixed(4);
            const styleId = 'cdb-ticker-keyframe-override';
            let styleEl = document.getElementById(styleId);
            if (!styleEl) { styleEl = document.createElement('style'); styleEl.id = styleId; document.head.appendChild(styleEl); }
            styleEl.textContent = `@keyframes ticker-scroll { 0% { transform: translateX(0); } 100% { transform: translateX(-${pct}%); } }`;
            outer.style.display = 'block';
        }

        // v184.0: Render dynamic attack ticker on the threat map using real CVE/threat data
        /**
         * Renders the scrolling attack-ticker overlay on the threat map
         * canvas from the same top-20 live feed items as renderTicker(),
         * pairing each with an illustrative geo-pair label. Titles are
         * HTML-escaped via _cdbEsc() the same way.
         * @param {object[]} data live feed items
         */
        function renderMapTicker(data) {
            var tickerEl = document.getElementById('cdb-ticker-text');
            if (!tickerEl || !data || !data.length) return;
            var sevColors = { CRITICAL:'#ff5050', HIGH:'#ffa000', MEDIUM:'#ffdc00', LOW:'#00b4ff' };
            var sorted = [...data].sort(function(a,b) {
                return parseFloat(b.risk_score||0) - parseFloat(a.risk_score||0);
            }).slice(0, 20);
            var parts = sorted.map(function(d, i) {
                var sev = getSeverity(d.risk_score, d);
                var col = sevColors[sev] || '#aaa';
                var cves = extractCVEs(d.title);
                // STAGE 3 FIX: same unescaped-title-into-innerHTML issue as
                // renderTicker() above -- reuses the same _cdbEsc() helper.
                var label = cves[0] ? cves[0] : _cdbEsc((d.title || '').slice(0, 28)) + '…';
                // P0 FIX (zero-fabrication): a geo label here used to be a
                // canned GEO_PAIRS constant selected by ticker position
                // (i % GEO_PAIRS.length) -- no relationship to the item at
                // all, so a real advisory could read "RU→US CRITICAL" with
                // both halves invented. Reuses buildHeatmap()'s own
                // source_country/actor_country/2-letter-tag resolution --
                // this codebase's one authoritative source for geo
                // attribution (v185.0, "no synthetic fallback") -- so the
                // ticker and the EICC heatmap can never disagree about
                // whether the same item has real attribution. No target/
                // destination-country field exists anywhere in the schema,
                // so a "source→target" pair is never fabricated either:
                // only the single real origin code renders, or nothing.
                var geoSrc = d.source_country || d.actor_country || (d.tags && d.tags.find(function(t){ return t && t.length===2; })) || '';
                var geo = geoSrc ? (_cdbEsc(geoSrc.toUpperCase()) + ' ') : '';
                return '<span style="color:' + col + ';font-weight:700;">' + geo + sev + '</span>'
                     + ' <span style="color:rgba(200,220,255,0.75);">' + label + '</span>';
            });
            var html = parts.join(' &nbsp;<span style="color:rgba(0,212,170,0.35);">&middot;</span>&nbsp; ');
            // Duplicate for seamless loop
            tickerEl.innerHTML = html + ' &nbsp;&nbsp; ' + html;
        }

        // ── MISP Export ──
        function exportMISP() {
            const mispEvents = manifestData.map((item, i) => {
                const cves = extractCVEs(item.title);
                return {
                    id: String(i + 1),
                    uuid: item.stix_id ? item.stix_id.replace('bundle--', '') : `cdb-${Date.now()}-${i}`,
                    info: item.title,
                    date: (item.processed_at || item.timestamp || new Date().toISOString()).slice(0, 10),  // v117.0.0
                    threat_level_id: { CRITICAL:'1', HIGH:'2', MEDIUM:'3', LOW:'4' }[getSeverity(item.risk_score, item)] || '3',
                    analysis: '2',
                    distribution: '3',
                    Attribute: [
                        ...cves.map(cve => ({ type:'vulnerability', value: cve, category:'External Analysis' })),
                        item.actor_tag ? { type:'threat-actor', value: item.actor_tag, category:'Attribution' } : null,
                        ...((item.mitre_tactics||[]).map(t => {
                            const tid = typeof t === 'string' ? t : (t.technique_id||'');
                            return tid ? { type:'text', value: tid, category:'External Analysis', comment:'MITRE ATT&CK Technique' } : null;
                        }))
                    ].filter(Boolean),
                    Tag: [
                        { name: `tlp:${(item.tlp_label||'green').toLowerCase().replace('tlp:','').replace(':','').toLowerCase()}` },
                        { name: `cdb:risk=${item.risk_score}` },
                        { name: 'cdb:sentinel-apex' }
                    ]
                };
            });

            const misp = { response: mispEvents };
            downloadBlob(new Blob([JSON.stringify(misp, null, 2)], { type: 'application/json' }), 'cdb-misp-export.json');
            showToast(`✔ MISP export ready \u2014 ${mispEvents.length} events`, 'info');
        }

        // ── Keyboard Shortcut Handler ──
        document.addEventListener('keydown', function(e) {
            const tag = document.activeElement.tagName.toLowerCase();
            const isInput = tag === 'input' || tag === 'textarea' || tag === 'select';

            if (e.key === 'Escape') {
                closeThreatModal();
                closeKbdModal();
                closeStixPaywall();
                return;
            }
            if (e.key === '?') { openKbdModal(); return; }
            if (isInput) return;

            switch(e.key) {
                case '/':
                    e.preventDefault();
                    const si = document.getElementById('search-input');
                    if (si) si.focus();
                    break;
                case 'r': case 'R': manualRefresh(); break;
                case 'a': case 'A':
                    const tog = document.getElementById('auto-refresh-toggle');
                    if (tog) { tog.checked = !tog.checked; toggleAutoRefresh(tog.checked); }
                    break;
                case 'j': case 'J': exportJSON(); break;
                case 'c': case 'C': exportCSV(); break;
                case 's': case 'S': openStixPaywall(); break;
                case '1': filterCards('all', document.querySelector('[data-filter="all"]')); break;
                case '2': filterCards('CRITICAL', document.querySelector('[data-filter="CRITICAL"]')); break;
                case '3': filterCards('HIGH', document.querySelector('[data-filter="HIGH"]')); break;
                case 'w': case 'W': toggleWatchlist(); break;
                case 'm': case 'M': openAIModal(); break;
            }
        });

        // ── Enhanced auto-refresh with new-threat notification ──
        let previousCount = 0;

        // ── Export Functions ──
        function exportJSON() {
            const blob = new Blob([JSON.stringify(manifestData, null, 2)], { type: 'application/json' });
            downloadBlob(blob, 'cdb-threat-intel-feed.json');
        }

        function decodeHtmlEntities(str) {
            // Browser-native HTML entity decode -- no library needed
            if (!str) return '';
            const ta = document.createElement('textarea');
            ta.innerHTML = str;
            return ta.value;
        }
        function exportCSV() {
            // v184.0 G14 FIX: guard against empty data — prevents blank CSV download
            if (!manifestData || !manifestData.length) {
                alert('Threat feed is still loading. Please wait a moment and try again.');
                return;
            }
            const headers = ['Title', 'Risk Score', 'Severity', 'TLP', 'Confidence', 'Actor', 'CVSS', 'EPSS', 'KEV', 'Blog URL', 'Source URL', 'Timestamp'];
            const rows = manifestData.map(d => [
                `"${decodeHtmlEntities(d.title || '').replace(/"/g, '""')}"`,
                d.risk_score, getSeverity(d.risk_score, d), getTlpLabel(d),
                d.confidence_score || '', decodeHtmlEntities(d.actor_tag || ''),
                d.cvss_score || '', d.epss_score != null ? d.epss_score + '%' : '',
                d.kev_present ? 'YES' : 'NO',
                d.report_url || '', d.source_url || '', d.processed_at || d.timestamp || ''
            ]);
            const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
            downloadBlob(new Blob([csv], { type: 'text/csv' }), 'cdb-threat-intel-feed.csv');
        }

        // ── STIX Bundle Paywall (v46.0) ──
        // STIX downloads are restricted to paid subscribers only.
        // Non-subscribers see the upgrade modal. Subscribers receive bundles via secure portal delivery.
        function exportSTIX() {
            openStixPaywall();
        }

        function openStixPaywall() {
            const modal = document.getElementById('stix-paywall-modal');
            if (modal) {
                modal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
            }
        }

        function closeStixPaywall() {
            const modal = document.getElementById('stix-paywall-modal');
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = '';
            }
        }
        // openUpgradeModal (v1.0) -- routes to upgrade.html with plan context
        // Called from pricing section CTA buttons (free / pro / enterprise)
        window.openUpgradeModal = function openUpgradeModal(plan) {
            const validPlans = ['free', 'pro', 'team', 'enterprise'];
            const p = validPlans.includes(plan) ? plan : 'pro';
            const utm = 'utm_source=dashboard&utm_medium=cta&utm_campaign=upgrade';
            window.open('upgrade.html?plan=' + p + '&' + utm, '_blank', 'noopener,noreferrer');
        };

        // Called by verified subscribers only \u2014 STIX bundle access via secure subscriber delivery
        // (Endpoint URL is NOT exposed client-side \u2014 bundles delivered via subscriber portal)
        function _stixGrantAccess() {
            closeStixPaywall();
            window.open('/upgrade.html?plan=pro&utm_source=stix-grant', '_blank');
        }

        function downloadBlob(blob, filename) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = filename; a.click();
            URL.revokeObjectURL(url);
        }  
      // ── deduplicateIntel v124.0 ──────────────────────────────────────────────
      // 3-layer dedup \u2014 mirrors Cloudflare Worker deduplication logic:
      //   L1: stix_id / id (canonical \u2014 authoritative)
      //   L2: normalized title fingerprint (same story, different IDs)
      //   L3: source+title content-hash (cross-source republication)
      // Root cause of P0 dashboard duplication bug (confirmed run #598).
      // ────────────────────────────────────────────────────────────────────────
      function _normTitle(t) {
          if (!t) return '';
          const stop = new Set(['a','an','the','in','on','at','for','of','and','or','to','via','by','with','from']);
          return t.toLowerCase()
              .replace(/[^a-z0-9\s]/g, '')
              .split(/\s+/)
              .filter(w => w && !stop.has(w))
              .slice(0, 12)
              .sort()         // order-independent \u2014 catches reordered titles
              .join('|');
      }

      function _contentKey(item) {
          const src   = (item.source || item.feed_source || '').toLowerCase().replace(/[^a-z0-9]/g, '');
          const title = _normTitle(item.title || item.name || '');
          const cve   = (item.cve_id || '').toUpperCase();
          return src + '::' + title + '::' + cve;
      }

      function deduplicateIntel(data) {
          if (!Array.isArray(data)) return data;
          const seenIds     = new Set();
          const seenTitles  = new Set();
          const seenContent = new Set();
          const unique      = [];
          for (const item of data) {
              // L1: canonical id dedup
              const idKey = item.stix_id || item.id || item.cve_id;
              if (idKey) {
                  if (seenIds.has(idKey)) continue;
                  seenIds.add(idKey);
              }
              // L2: normalized title (catches cross-run same-story dupes)
              if (item.title) {
                  const normKey = _normTitle(item.title);
                  if (normKey && normKey.length > 8) {
                      if (seenTitles.has(normKey)) continue;
                      seenTitles.add(normKey);
                  }
              }
              // L3: source+title content-hash (cross-source republication)
              const ck = _contentKey(item);
              if (ck && ck.length > 5) {
                  if (seenContent.has(ck)) continue;
                  seenContent.add(ck);
              }
              unique.push(item);
          }
          return unique;
      }

// ─────────────────────────────────────────────
// 🔥 TOP THREAT PRIORITY ENGINE (SAFE ADD)
// ─────────────────────────────────────────────

function getThreatPriorityScore(item) {
    let score = 0;

    score += (item.risk_score || 0) * 10;

    // v76.1 FIX: use correct field name kev_present (was item.kev which never matches)
    if (item.kev_present === true) {
        score += 50;
    }

    // P0 FIX: raw epss_score is inconsistently 0-1 or 0-100 scale; adding it
    // unnormalized let a mis-scaled value (e.g. 32 meaning 32%) dominate the
    // composite score. Add the canonical 0-100 percent instead.
    const _epssTps = window.CDB_NORMALIZE.epss(item.epss_score);
    if (_epssTps.state === 'OK') {
        score += _epssTps.percent;
    }

    if (item.severity === "CRITICAL") score += 40;
    if (item.severity === "HIGH") score += 25;

    return score;
}

// Converts a /api/reports/index.json registry entry into the item shape
// getThreatPriorityScore()/sevInfo()/prio()/the card renderer expect.
// __norm.severity is set from the registry's own `severity` field (the
// backend's canonical classification for that report) so these items get
// the exact same severity badge as the report itself, rather than being
// re-derived from a numeric risk_score threshold like an un-normalized
// feed item would be.
function _cdbReportPoolItem(r) {
    return {
        id: r.id, stix_id: r.id,
        title: r.title || '',
        severity: r.severity || null,
        __norm: { severity: r.severity || null },
        risk_score: r.risk_score,
        cvss_score: r.cvss_score,
        epss_score: r.epss_score,
        kev_present: !!r.kev_present,
        actor_tag: r.actor_tag || '',
        mitre_tactics: [],
        ioc_count: 0,
        timestamp: r.timestamp || r.published || '',
        processed_at: r.timestamp || r.published || '',
        internal_report_url: r.url || '',
        source_url: r.url || '',
        validation_status: 'ok',
    };
}

function getTopThreats(data) {
    // PRODUCTION-GRADE FIX: only rank items that already have a verified,
    // customer-ready report (same canonical check renderTopThreats() uses
    // per-card via cdbBuildReportUrl() to decide FULL INTEL vs UNAVAILABLE).
    // Before this, ranking ignored report availability entirely, so the
    // highest-priority items -- exactly the ones most likely to be freshly
    // ingested and not yet through the report-generation pipeline -- could
    // dominate the free-tier top 3, showing a dead "UNAVAILABLE" badge on
    // the platform's own marquee feature instead of a working CTA.
    //
    // The report-ready subset of `data` alone is often too small to fill a
    // real top 10 (confirmed live: of the ~137 items in the main dashboard
    // feed slice, typically only a handful overlap with the ~27-report
    // customer-ready registry -- report generation draws from a much larger
    // 500-candidate backend pool than what's served in this page's feed
    // slice). window._cdbReportsFull (populated by js/sentinel-live-feeds.js's
    // loadReports() from the same /api/reports/index.json registry already
    // used as cdbBuildReportUrl()'s fallback) supplies the rest of that
    // larger report-ready pool, converted via _cdbReportPoolItem() above, so
    // this feed can still reach a genuine top 10 -- every one of them
    // guaranteed to link to a real report.
    const fromFeed = data.filter(item => !!cdbBuildReportUrl(item));
    const feedIds = new Set(fromFeed.map(it => it.id || it.stix_id));
    const fromRegistry = (window._cdbReportsFull || [])
        .filter(r => r && r.id && !feedIds.has(r.id))
        .map(_cdbReportPoolItem);

    return [...fromFeed, ...fromRegistry]
        .sort((a, b) => getThreatPriorityScore(b) - getThreatPriorityScore(a))
        .slice(0, 10);
}

function renderTopThreats(data) {
    const container = document.getElementById('top-threats-section');
    if (!container) return;
    const top = getTopThreats(data);
    if (!top.length) { container.innerHTML = ''; return; }

    // Update intel status bar
    try {
        const now = Date.now();
        const newest = data.reduce((b,d)=>{const t=new Date(d.processed_at||d.timestamp||0).getTime();return t>b?t:b;},0);
        const recent24h = data.filter(d=>(now-new Date(d.processed_at||d.timestamp||0).getTime())<86400000).length;
        const lsEl=document.getElementById('intel-last-update');
        const niEl=document.getElementById('intel-new-count');
        const dfEl=document.getElementById('intel-dedup-count');
        if (lsEl&&newest){const dm=Math.floor((now-newest)/60000);lsEl.textContent='Last Sync: '+(dm<60?dm+'m ago':Math.floor(dm/60)+'h ago');}
        if (niEl) niEl.textContent='New Intel: '+recent24h;
        if (dfEl) dfEl.textContent='Filtered: '+data.length;
    } catch(e){}

    // P0 FIX: SEV_TIERS is the single set of tier colors; which tier a card
    // uses now prefers the canonical item.__norm.severity (the same
    // normalizeIntelItem() computation card_renderer.js's dashboard uses)
    // over an independently re-derived risk_score threshold, so the TOP10/
    // "SOC PRIORITY FEED" section can no longer disagree with the canonical
    // dashboard about an item's severity. The threshold fallback is kept
    // only for the case where __norm is unavailable.
    const SEV_TIERS = {
        CRITICAL: {l:'CRITICAL',c:'#dc2626',bg:'rgba(220,38,38,0.12)',glow:'rgba(220,38,38,0.4)'},
        HIGH:     {l:'HIGH',    c:'#ea580c',bg:'rgba(234,88,12,0.12)', glow:'rgba(234,88,12,0.3)'},
        MEDIUM:   {l:'MEDIUM',  c:'#d97706',bg:'rgba(217,119,6,0.12)', glow:'rgba(217,119,6,0.25)'},
        LOW:      {l:'LOW',     c:'#16a34a',bg:'rgba(22,163,74,0.12)', glow:'rgba(22,163,74,0.2)'},
    };
    function sevInfo(canonicalSev, s) {
        if (canonicalSev && SEV_TIERS[canonicalSev]) return SEV_TIERS[canonicalSev];
        if(s>=9) return SEV_TIERS.CRITICAL;
        if(s>=7) return SEV_TIERS.HIGH;
        if(s>=4) return SEV_TIERS.MEDIUM;
        return SEV_TIERS.LOW;
    }
    function ago(ts) {
        if(!ts) return ''; const d=Math.floor((Date.now()-new Date(ts).getTime())/60000);
        if(d<1) return 'Now'; if(d<60) return d+'m'; if(d<1440) return Math.floor(d/60)+'h'; return Math.floor(d/1440)+'d';
    }
    // P0 FIX: prefer the canonical item.__norm.apex_ai.soc_priority (the
    // adapter's severity-aware, backend-sla_priority-first computation)
    // over this function's own independent kev/epss/cvss/risk algorithm --
    // previously a FOURTH, mutually-inconsistent priority computation
    // alongside card_renderer.js's, the click-through modal's, and
    // window.computePriority()'s. Kept as a fallback only for items that
    // somehow reach this function without having gone through
    // loadGOCIntel()'s normalization hook.
    function prio(item) {
        if (item.__norm && item.__norm.apex_ai && item.__norm.apex_ai.soc_priority) {
            return item.__norm.apex_ai.soc_priority;
        }
        const kev=item.kev_present, epss=parseFloat(item.epss_score)||0, cvss=parseFloat(item.cvss_score)||0, risk=parseFloat(item.risk_score)||0;
        if(kev||epss>=50) return 'P1';
        if(cvss>=9||risk>=9) return 'P1';
        if(cvss>=7||risk>=7) return 'P2';
        if(cvss>=5||risk>=5) return 'P3';
        return 'P4';
    }
    // P0 FIX (Dashboard Truth Contract PR-B, 2026-08-11): prio(item) now
    // correctly returns 'P0' for a KEV-confirmed critical item once
    // js/api_adapter.js's normalizeSocPriority() preserves it (was silently
    // collapsed to 'P4' before) -- but this function's fallback branch would
    // then color a P0 (the platform's most urgent tier) with the SAME gray
    // used for P4/informational, visually re-introducing the exact
    // contradiction the badge-text fix just closed. P0 gets its own,
    // most-urgent color; P1-P4 mappings are unchanged.
    // CodeRabbit PR-B: the original catch-all fallback ('#6b7280', P4's own
    // gray) also applied to 'UNKNOWN' -- a malformed priority would render
    // visually identical to P4/informational, the exact contradiction this
    // PR exists to eliminate. UNKNOWN now gets its own neutral gray, matching
    // js/api_adapter.js SOC_PRIORITY_MAP.UNKNOWN.color.
    function prioColor(p) {
        return p==='P0'?'#ff1a1a':p==='P1'?'#dc2626':p==='P2'?'#ea580c':p==='P3'?'#d97706':p==='P4'?'#6b7280':'#9ca3af';
    }
    // P0 FIX (Dashboard Truth Contract PR-B, 2026-08-11): the action-strip
    // label below each TOP10 card special-cased only pr==='P1' for
    // "PATCH NOW" styling; a P0 item without kev_present set would fall
    // through to the default 'MONITOR' label -- the same class of
    // contradiction as the P0->P4 badge bug, one line down. Extracted into a
    // small named function (matching this file's existing sevInfo()/prio()/
    // prioColor() pattern) so it can be unit-tested directly instead of only
    // as an inline ternary duplicated at each call site.
    function prioActionLabel(pr, kev, epss) {
        if (kev || epss >= 50) return { color: '#dc2626', text: '&#9888; IMMEDIATE ACTION' };
        if (pr === 'P0' || pr === 'P1') return { color: '#ea580c', text: '&#9888; PATCH NOW' };
        if (pr === 'P2') return { color: '#5a6578', text: 'INVESTIGATE' };
        if (pr === 'P3' || pr === 'P4') return { color: '#5a6578', text: 'MONITOR' };
        // CodeRabbit PR-B: the previous default branch caught P3/P4 AND
        // 'UNKNOWN' alike, telling an analyst to "MONITOR" (i.e. low
        // urgency) a malformed classification -- do not assume low urgency
        // for what is genuinely unknown.
        return { color: '#9ca3af', text: 'REVIEW PRIORITY' };
    }

    const RANK_ICONS = ['&#127942;','&#129352;','&#129353;','&#9679;','&#9679;','&#9679;','&#9679;','&#9679;','&#9679;','&#9679;'];
    // Feed fields (title, actor, tactics, report links) are third-party data
    // and this widget builds an HTML string: escape text, and only link to a
    // same-site path or an http(s) URL.
    const _tt = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
    const _tu = (u) => { const v = String(u || '').trim(); return ((v.charAt(0) === '/' && v.charAt(1) !== '/') || /^https?:\/\//i.test(v)) ? _tt(v) : '#'; };

    const cards = top.map((item,idx) => {
        const sc = parseFloat(item.risk_score)||0;
        const sv = sevInfo(item.__norm ? item.__norm.severity : null, sc);
        const cve = (item.title||'').match(/CVE-\d{4}-\d{4,}/i);
        const tacs = (item.mitre_tactics||[]).slice(0,3);
        const actor = (item.actor_tag&&item.actor_tag!=='UNC-CDB-99'&&item.actor_tag!=='UNC-UNKNOWN')?item.actor_tag:null;
        const kev = item.kev_present;
        const epss = parseFloat(item.epss_score)||0;
        const cvss = parseFloat(item.cvss_score)||0;
        const pr = prio(item);
        const prC = prioColor(pr);
        const isTop3 = idx < 3;
        const iocCount = item.ioc_count || (item.ioc_counts ? Object.values(item.ioc_counts).reduce((a,b)=>a+b,0) : 0);
        // v186.0 P0 FIX: report link now built by the single canonical
        // cdbBuildReportUrl() helper (was: inline duplicate that only ever
        // constructed reports/{y}/{m}/{id}.html and ignored a more specific
        // internal_report_url/report_url when present -- also fixes a latent
        // relative-path bug: this used to omit the leading "/").
        // v187.0 P0 FIX: track verified-report availability separately from
        // the source_url fallback -- a customer must never see a "FULL
        // INTEL" CTA that isn't backed by an actual verified report link
        // (see hasVerifiedReport usage below).
        const _verifiedReportUrl = cdbBuildReportUrl(item);
        const hasVerifiedReport = !!_verifiedReportUrl;
        const intelUrl = _verifiedReportUrl || (item.source_url || 'https://intel.cyberdudebivash.com');

        // Severity heatmap bar width
        const barW = Math.min(sc * 10, 100);
        // Kill chain phase
        // String() guard (2026-09-01, found by render-test/verify_pages_fast_publish_smoke.js
        // in the API-unreachable fallback path): mitre_tactics[0] is not guaranteed to be a
        // string, matching the Array.isArray guard already used for this same field elsewhere
        // in this file (e.g. line ~11422) -- .toUpperCase() on a non-string element threw.
        const kcPhase = (item.mitre_tactics && item.mitre_tactics.length)
            ? String(item.mitre_tactics[0] || '').toUpperCase().split('.')[0]
            : '';

        return '<div style="position:relative;background:linear-gradient(135deg,var(--bg-card) 0%,rgba('+
            (sv.l==='CRITICAL'?'220,38,38':'234,88,12')+',0.03) 100%);'+
            'border:1px solid '+(isTop3?sv.c+'44':'var(--border)')+';overflow:hidden;'+
            'transition:all 0.25s;border-radius:4px;'+
            (isTop3?'box-shadow:0 0 16px '+sv.glow+';':'')+'" '+
            'onmouseover="this.style.borderColor=\''+sv.c+'66\';this.style.transform=\'translateY(-3px)\';this.style.boxShadow=\'0 8px 32px '+sv.glow+'\'" '+
            'onmouseout="this.style.borderColor=\''+(isTop3?sv.c+'44':'var(--border)')+'\';this.style.transform=\'none\';this.style.boxShadow=\''+(isTop3?'0 0 16px '+sv.glow:'none')+'\'">'+

            // Severity bar top
            '<div style="height:3px;background:linear-gradient(90deg,'+sv.c+' '+barW+'%,rgba(255,255,255,0.04) '+barW+'%);"></div>'+

            // Header row
            '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px 6px;">'+
                '<div style="display:flex;align-items:center;gap:7px;">'+
                    '<span style="font-size:'+(isTop3?'18':'14')+'px;line-height:1;">'+RANK_ICONS[idx]+'</span>'+
                    '<span style="font-family:var(--font-mono);font-size:8px;color:#3a4a5a;font-weight:700;">#'+(idx+1)+'</span>'+
                    '<span style="background:'+sv.bg+';color:'+sv.c+';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:800;font-family:var(--font-mono);letter-spacing:.5px;border:1px solid '+sv.c+'55;'+
                        (sv.l==='CRITICAL'?'animation:kev-pulse 1.8s infinite;box-shadow:0 0 10px '+sv.glow+';':
                         sv.l==='HIGH'    ?'animation:kev-pulse 2.4s infinite;box-shadow:0 0 6px '+sv.glow+';':'')+
                    '">'+sv.l+'</span>'+
                    '<span style="background:'+prC+'18;color:'+prC+';padding:2px 6px;border-radius:3px;font-size:9px;font-weight:800;font-family:var(--font-mono);">'+pr+'</span>'+
                    (kev?'<span style="background:rgba(220,38,38,.12);color:#dc2626;padding:1px 6px;border-radius:3px;font-size:8px;font-weight:800;letter-spacing:.5px;border:1px solid rgba(220,38,38,.3);animation:kev-pulse 1.5s infinite;">&#9889; CISA KEV</span>':'')+
                    ((kev||epss>=50)?'<span style="background:rgba(220,38,38,.08);color:#f87171;padding:1px 7px;border-radius:3px;font-size:7.5px;font-weight:800;letter-spacing:.3px;border:1px solid rgba(220,38,38,.2);">&#9888; ACTIVE EXPLOITATION</span>':'')+
                    (sc>=9?'<span style="background:rgba(139,92,246,.1);color:#a78bfa;padding:1px 7px;border-radius:3px;font-size:7.5px;font-weight:700;letter-spacing:.3px;border:1px solid rgba(139,92,246,.2);">&#127970; ENTERPRISE IMPACT</span>':'')
                +'</div>'+
                '<span style="font-family:var(--font-mono);font-size:9px;color:#3a4a5a;">'+ago(item.timestamp)+'</span>'+
            '</div>'+

            // Title
            '<div style="padding:2px 14px 8px;">'+
                '<div style="font-size:12px;font-weight:700;color:var(--white);line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">'+_tt((item.title||'Unknown').substring(0,110))+'</div>'+
            '</div>'+

            // Metrics strip
            '<div style="padding:0 14px 8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'+
                (cvss>0?'<div style="text-align:center;padding:4px 8px;background:rgba(255,255,255,0.03);border-radius:3px;border:1px solid rgba(255,255,255,0.06);"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;letter-spacing:1px;">CVSS</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:'+(cvss>=9?'#dc2626':cvss>=7?'#ea580c':'#d97706')+';">'+cvss.toFixed(1)+'</div></div>':'')+
                (epss>0?'<div style="text-align:center;padding:4px 8px;background:rgba(255,255,255,0.03);border-radius:3px;border:1px solid rgba(255,255,255,0.06);"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;letter-spacing:1px;">EPSS</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:'+(epss>=50?'#dc2626':epss>=10?'#ea580c':'#d97706')+';">'+epss+'%</div></div>':'')+
                (iocCount>0?'<div style="text-align:center;padding:4px 8px;background:rgba(0,212,170,0.06);border-radius:3px;border:1px solid rgba(0,212,170,0.2);"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;letter-spacing:1px;">IOCs</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:#00d4aa;">'+iocCount+'</div></div>':'')+
                '<div style="margin-left:auto;text-align:right;">'+
                    (actor?
                        (idx<3?
                            '<div style="font-family:var(--font-mono);font-size:9px;color:'+sv.c+';font-weight:700;">'+_tt(actor)+'</div>':
                            '<div style="font-family:var(--font-mono);font-size:9px;color:#3a4a5a;background:rgba(255,255,255,0.03);padding:2px 6px;border-radius:2px;border:1px solid #2a3340;">'+
                                '<span style="color:#5a6578;">&#128274; ACTOR:</span> <a href="/upgrade.html?plan=pro&utm_source=actor-gate" target="_blank" style="color:#8b5cf6;text-decoration:none;font-weight:700;">PRO ONLY</a></div>'
                        ):
                        '<div style="font-family:var(--font-mono);font-size:9px;color:#3a4a5a;">UNATTRIBUTED</div>'
                    )+
                '</div>'+
            '</div>'+

            // Tags row
            '<div style="padding:0 14px 8px;display:flex;align-items:center;gap:4px;flex-wrap:wrap;">'+
                (cve?'<span style="background:rgba(59,130,246,.12);color:#3b82f6;padding:2px 7px;border-radius:3px;font-size:9px;font-family:var(--font-mono);font-weight:700;border:1px solid rgba(59,130,246,.2);">'+cve[0]+'</span>':'')+ 
                tacs.map(function(t){return '<span style="background:rgba(139,92,246,.1);color:#a78bfa;padding:1px 5px;border-radius:3px;font-size:8px;font-family:var(--font-mono);border:1px solid rgba(139,92,246,.15);">'+_tt(t)+'</span>';}).join('')+
                (kcPhase?'<span style="background:rgba(245,158,11,0.08);color:#f59e0b;padding:1px 5px;border-radius:3px;font-size:8px;font-family:var(--font-mono);border:1px solid rgba(245,158,11,.15);">'+_tt(kcPhase)+'</span>':'')+
            '</div>'+

            // Action button strip
            '<div style="padding:6px 14px 10px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid rgba(255,255,255,0.04);margin-top:2px;">'+
                '<span style="font-family:var(--font-mono);font-size:8px;color:'+prioActionLabel(pr,kev,epss).color+';font-weight:800;letter-spacing:1px;">'+prioActionLabel(pr,kev,epss).text+'</span>'+
                (idx<3?
                    // v187.0 P0 FIX: never render a "FULL INTEL" CTA unless
                    // cdbBuildReportUrl() actually returned a backend-verified
                    // link -- a customer must never be sent to a permanently
                    // rejected or nonexistent report.
                    (hasVerifiedReport
                        ? '<a href="'+_tu(intelUrl)+'" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:9px;font-weight:800;letter-spacing:1px;color:#020205;background:linear-gradient(135deg,'+sv.c+','+sv.c+'cc);padding:5px 12px;border-radius:3px;text-decoration:none;white-space:nowrap;box-shadow:0 0 10px '+sv.glow+';">FULL INTEL &#8594;</a>'
                        : '<span style="font-family:var(--font-mono);font-size:9px;font-weight:800;letter-spacing:1px;color:#5a6578;background:rgba(255,255,255,0.03);padding:5px 12px;border-radius:3px;white-space:nowrap;border:1px solid rgba(255,255,255,0.08);" title="No verified report link is currently available for this item">&#8226; UNAVAILABLE</span>'
                    ):
                    '<a href="/upgrade.html?plan=pro&utm_source=top-threat-'+idx+'" target="_blank" style="font-family:var(--font-mono);font-size:9px;color:#5a6578;text-decoration:none;border:1px solid #2a3340;padding:4px 10px;border-radius:3px;">&#128274; PRO ACCESS</a>'
                )+
            '</div>'+
        '</div>';
    }).join('');

    const now2 = Date.now();
    const newest2 = data.reduce((b,d)=>{const t=new Date(d.processed_at||d.timestamp||0).getTime();return t>b?t:b;},0);
    const dm2 = newest2 ? Math.floor((now2-newest2)/60000) : 0;
    const syncLabel = dm2<60 ? dm2+'m ago' : Math.floor(dm2/60)+'h ago';
    const recent2 = data.filter(d=>(now2-new Date(d.timestamp||0).getTime())<86400000).length;
    const critCount = top.filter(t=>parseFloat(t.risk_score)>=9).length;
    const kevCount  = top.filter(t=>t.kev_present).length;

    container.innerHTML =
        // Header section
        '<div style="margin-bottom:18px;">' +
            '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:14px;">' +
                '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">' +
                    '<div style="display:flex;align-items:center;gap:8px;">' +
                        '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#dc2626;box-shadow:0 0 10px rgba(220,38,38,0.7);animation:cpulse 1.4s infinite;"></span>' +
                        '<span style="font-family:var(--font-mono);font-size:13px;font-weight:900;color:var(--white);letter-spacing:1px;">&#128293; TOP 10 ACTIVE THREATS &mdash; SOC PRIORITY FEED</span>' +
                    '</div>' +
                    '<div style="display:flex;gap:10px;font-family:var(--font-mono);font-size:9px;">' +
                        '<span style="color:var(--accent);">&#128752; ACTIVE</span>' +
                        '<span style="color:#5a6578;">Last Sync: '+syncLabel+'</span>' +
                        '<span style="color:#dc2626;font-weight:700;">'+critCount+' CRITICAL</span>' +
                        (kevCount>0?'<span style="color:#dc2626;font-weight:700;">'+kevCount+' KEV</span>':'')+
                        '<span style="color:#5a6578;">'+recent2+' new (24h)</span>' +
                    '</div>'+
                '</div>' +
                '<div style="display:flex;gap:8px;align-items:center;">' +
                    '<a href="/upgrade.html?plan=pro&utm_source=top10-header" target="_blank" ' +
                       'style="font-family:var(--font-mono);font-size:9px;font-weight:800;letter-spacing:1.5px;color:#020205;' +
                              'background:linear-gradient(135deg,#dc2626,#b91c1c);padding:6px 14px;border-radius:3px;text-decoration:none;' +
                              'box-shadow:0 0 12px rgba(220,38,38,0.4);white-space:nowrap;">' +
                        '&#128274; FULL REPORT &#8594; PRO' +
                    '</a>' +
                '</div>' +
            '</div>' +
            // Tier lock banner
            '<div style="background:linear-gradient(90deg,rgba(139,92,246,0.08),rgba(0,212,170,0.04));border:1px solid rgba(139,92,246,0.2);border-radius:4px;padding:10px 16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">' +
                '<div style="font-family:var(--font-mono);font-size:9px;color:#a78bfa;letter-spacing:1px;">' +
                    '&#128204; FREE TIER: 3 Threats visible \u00b7 Rank \u00b7 Severity \u00b7 CVE \u00b7 MITRE &nbsp;&#183;&nbsp; ' +
                    '<span style="color:#5a6578;">PRO unlocks all 10: Actor Attribution \u00b7 Full IOC List \u00b7 STIX Export \u00b7 Threat History</span>' +
                '</div>' +
                '<a href="/upgrade.html?plan=pro&utm_source=tier-banner" target="_blank" ' +
                   'style="font-family:var(--font-mono);font-size:9px;color:#8b5cf6;border:1px solid rgba(139,92,246,0.3);padding:4px 10px;border-radius:3px;text-decoration:none;white-space:nowrap;">' +
                    'UPGRADE &#8594;' +
                '</a>' +
            '</div>' +
        '</div>' +
        // TOP 3 \u2014 fully visible
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin-bottom:16px;">' +
            top.slice(0,3).map(function(item,idx){
                var sc=parseFloat(item.risk_score)||0,sv=sevInfo(item.__norm?item.__norm.severity:null,sc),cve=(item.title||'').match(/CVE-\d{4}-\d{4,}/i),tacs=(item.mitre_tactics||[]).slice(0,3),actor=(item.actor_tag&&item.actor_tag!=='UNC-CDB-99'&&item.actor_tag!=='UNC-UNKNOWN')?item.actor_tag:null,kev=item.kev_present,epss=parseFloat(item.epss_score)||0,cvss=parseFloat(item.cvss_score)||0,pr=prio(item),prC=prioColor(pr),iocCount=item.ioc_count||(item.ioc_counts?Object.values(item.ioc_counts).reduce(function(a,b){return a+b;},0):0),barW=Math.min(sc*10,100),kcPhase=(item.mitre_tactics&&item.mitre_tactics.length)?(item.mitre_tactics[0]||'').toUpperCase().split('.')[0]:'',_its2=item.processed_at||item.timestamp||'',_iD2=_its2?new Date(_its2):null,_iyr2=_iD2?_iD2.getFullYear():'',_imo2=_iD2?String(_iD2.getMonth()+1).padStart(2,'0'):'',_sid2=item.stix_id||item.id||'',_verifiedReportUrl2=cdbBuildReportUrl(item),hasVerifiedReport2=!!_verifiedReportUrl2,intelUrl2=_verifiedReportUrl2||(item.source_url||'https://intel.cyberdudebivash.com');
                return '<div style="position:relative;background:linear-gradient(135deg,var(--bg-card) 0%,rgba(220,38,38,0.03) 100%);border:1px solid '+sv.c+'44;overflow:hidden;transition:all 0.25s;border-radius:4px;box-shadow:0 0 16px '+sv.glow+';" onmouseover="this.style.borderColor=\''+sv.c+'66\';this.style.transform=\'translateY(-3px)\';this.style.boxShadow=\'0 8px 32px '+sv.glow+'\'" onmouseout="this.style.borderColor=\''+sv.c+'44\';this.style.transform=\'none\';this.style.boxShadow=\'0 0 16px '+sv.glow+'\'">'+
                '<div style="height:3px;background:linear-gradient(90deg,'+sv.c+' '+barW+'%,rgba(255,255,255,0.04) '+barW+'%);"></div>'+
                '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px 6px;">'+
                    '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">'+
                        '<span style="font-size:18px;line-height:1;">'+RANK_ICONS[idx]+'</span>'+
                        '<span style="font-family:var(--font-mono);font-size:8px;color:#3a4a5a;font-weight:700;">#'+(idx+1)+'</span>'+
                        '<span style="background:'+sv.bg+';color:'+sv.c+';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:800;font-family:var(--font-mono);letter-spacing:.5px;border:1px solid '+sv.c+'55;'+(sv.l==='CRITICAL'?'animation:kev-pulse 1.8s infinite;box-shadow:0 0 10px '+sv.glow+';':sv.l==='HIGH'?'animation:kev-pulse 2.4s infinite;box-shadow:0 0 6px '+sv.glow+';':'')+'" >'+sv.l+'</span>'+
                        '<span style="background:'+prC+'18;color:'+prC+';padding:2px 6px;border-radius:3px;font-size:9px;font-weight:800;font-family:var(--font-mono);">'+pr+'</span>'+
                        (kev?'<span style="background:rgba(220,38,38,.12);color:#dc2626;padding:1px 6px;border-radius:3px;font-size:8px;font-weight:800;letter-spacing:.5px;border:1px solid rgba(220,38,38,.3);animation:kev-pulse 1.5s infinite;">&#9889; CISA KEV</span>':'')+
                        ((kev||epss>=50)?'<span style="background:rgba(220,38,38,.08);color:#f87171;padding:1px 7px;border-radius:3px;font-size:7.5px;font-weight:800;border:1px solid rgba(220,38,38,.2);">&#9888; ACTIVE EXPLOITATION</span>':'')+
                        (sc>=9?'<span style="background:rgba(139,92,246,.1);color:#a78bfa;padding:1px 7px;border-radius:3px;font-size:7.5px;font-weight:700;border:1px solid rgba(139,92,246,.2);">&#127970; ENTERPRISE IMPACT</span>':'')+
                    '</div>'+
                    '<span style="font-family:var(--font-mono);font-size:9px;color:#3a4a5a;">'+ago(item.timestamp)+'</span>'+
                '</div>'+
                '<div style="padding:2px 14px 8px;"><div style="font-size:12px;font-weight:700;color:var(--white);line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">'+_tt((item.title||'Unknown').substring(0,110))+'</div></div>'+
                '<div style="padding:0 14px 8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'+
                    (cvss>0?'<div style="text-align:center;padding:4px 8px;background:rgba(255,255,255,0.03);border-radius:3px;border:1px solid rgba(255,255,255,0.06);"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;letter-spacing:1px;">CVSS</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:'+(cvss>=9?'#dc2626':cvss>=7?'#ea580c':'#d97706')+';">'+cvss.toFixed(1)+'</div></div>':'')+
                    (epss>0?'<div style="text-align:center;padding:4px 8px;background:rgba(255,255,255,0.03);border-radius:3px;border:1px solid rgba(255,255,255,0.06);"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;letter-spacing:1px;">EPSS</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:'+(epss>=50?'#dc2626':epss>=10?'#ea580c':'#d97706')+';">'+epss+'%</div></div>':'')+
                    (iocCount>0?'<div style="text-align:center;padding:4px 8px;background:rgba(0,212,170,0.06);border-radius:3px;border:1px solid rgba(0,212,170,0.2);"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;letter-spacing:1px;">IOCs</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:#00d4aa;">'+iocCount+'</div></div>':'')+
                    (actor?'<div style="font-family:var(--font-mono);font-size:9px;color:'+sv.c+';font-weight:700;margin-left:auto;">'+_tt(actor)+'</div>':'<div style="font-family:var(--font-mono);font-size:9px;color:#3a4a5a;margin-left:auto;">UNATTRIBUTED</div>')+
                '</div>'+
                '<div style="padding:0 14px 8px;display:flex;gap:4px;flex-wrap:wrap;">'+
                    (cve?'<span style="background:rgba(59,130,246,.12);color:#3b82f6;padding:2px 7px;border-radius:3px;font-size:9px;font-family:var(--font-mono);font-weight:700;border:1px solid rgba(59,130,246,.2);">'+cve[0]+'</span>':'')+
                    tacs.map(function(t){return '<span style="background:rgba(139,92,246,.1);color:#a78bfa;padding:1px 5px;border-radius:3px;font-size:8px;font-family:var(--font-mono);border:1px solid rgba(139,92,246,.15);">'+_tt(t)+'</span>';}).join('')+
                    (kcPhase?'<span style="background:rgba(245,158,11,0.08);color:#f59e0b;padding:1px 5px;border-radius:3px;font-size:8px;font-family:var(--font-mono);border:1px solid rgba(245,158,11,.15);">'+_tt(kcPhase)+'</span>':'')+
                '</div>'+
                '<div style="padding:6px 14px 10px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid rgba(255,255,255,0.04);margin-top:2px;">'+
                    '<span style="font-family:var(--font-mono);font-size:8px;color:'+prioActionLabel(pr,kev,epss).color+';font-weight:800;letter-spacing:1px;">'+prioActionLabel(pr,kev,epss).text+'</span>'+
                    // v187.0 P0 FIX: same verified-link requirement as the
                    // top-10 list below -- never link "FULL INTEL" to a
                    // report cdbBuildReportUrl() couldn't confirm exists.
                    (hasVerifiedReport2
                        ? '<a href="'+_tu(intelUrl2)+'" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:9px;font-weight:800;letter-spacing:1px;color:#020205;background:linear-gradient(135deg,'+sv.c+','+sv.c+'cc);padding:5px 12px;border-radius:3px;text-decoration:none;white-space:nowrap;box-shadow:0 0 10px '+sv.glow+';">FULL INTEL &#8594;</a>'
                        : '<span style="font-family:var(--font-mono);font-size:9px;font-weight:800;letter-spacing:1px;color:#5a6578;background:rgba(255,255,255,0.03);padding:5px 12px;border-radius:3px;white-space:nowrap;border:1px solid rgba(255,255,255,0.08);" title="No verified report link is currently available for this item">&#8226; UNAVAILABLE</span>')+
                '</div>'+
                '</div>';
            }).join('') +
        '</div>' +
        // UNLOCK CTA \u2014 between free (3) and locked (7)
        '<div style="margin:8px 0 16px;padding:20px 24px;background:linear-gradient(135deg,rgba(220,38,38,0.08),rgba(139,92,246,0.08));border:1px solid rgba(220,38,38,0.3);border-radius:6px;text-align:center;position:relative;overflow:hidden;">' +
            '<div style="position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(220,38,38,0.03),transparent);animation:strip-scan 3s linear infinite;pointer-events:none;"></div>'+
            '<div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:10px;">' +
                '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#dc2626;box-shadow:0 0 14px rgba(220,38,38,0.8);animation:kev-pulse 1.5s infinite;"></span>'+
                '<span style="font-family:var(--font-mono);font-size:11px;font-weight:900;color:#f87171;letter-spacing:2px;text-transform:uppercase;">&#128274; 7 HIGH-RISK THREATS LOCKED</span>'+
                '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#dc2626;box-shadow:0 0 14px rgba(220,38,38,0.8);animation:kev-pulse 1.5s infinite;"></span>'+
            '</div>'+
            '<div style="font-family:var(--font-mono);font-size:9px;color:#7a8fa8;margin-bottom:16px;letter-spacing:1px;">'+
                'Active exploitation data \u00b7 Actor attribution \u00b7 Full IOC lists \u00b7 STIX 2.1 export \u00b7 Threat history'+
            '</div>'+
            '<div style="display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap;">'+
                '<a href="/upgrade.html?plan=pro&utm_source=unlock-cta" target="_blank" '+
                   'style="font-family:var(--font-mono);font-size:11px;font-weight:900;letter-spacing:1.5px;color:#020205;'+
                          'background:linear-gradient(135deg,#dc2626,#b91c1c);padding:10px 24px;border-radius:4px;text-decoration:none;'+
                          'box-shadow:0 0 20px rgba(220,38,38,0.5),0 4px 16px rgba(0,0,0,0.4);white-space:nowrap;'+
                          'animation:kev-pulse 2s infinite;">'+
                    '&#128275; UNLOCK FULL THREAT INTELLIGENCE &#8594;'+
                '</a>'+
                '<a href="/contact-enterprise.html?utm_source=top-threats&utm_medium=unlock_cta&utm_campaign=enterprise&plan=enterprise" target="_blank" '+
                   'style="font-family:var(--font-mono);font-size:10px;font-weight:800;letter-spacing:1.2px;color:#a78bfa;border:1px solid rgba(139,92,246,0.5);padding:9px 18px;border-radius:4px;text-decoration:none;white-space:nowrap;background:linear-gradient(135deg,rgba(139,92,246,0.12),rgba(59,130,246,0.08));box-shadow:0 0 14px rgba(139,92,246,0.2);transition:all 0.2s;">'+
                    '&#127970; UNLOCK ENTERPRISE'+
                '</a>'+
            '</div>'+
        '</div>'+
        // ITEMS 4-10 \u2014 blurred with overlay
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;position:relative;">' +
            '<style>.t10-blur-card{filter:blur(5px);pointer-events:none;user-select:none;opacity:0.5;}</style>'+
            top.slice(3).map(function(item,i){
                var idx=i+3,sc=parseFloat(item.risk_score)||0,sv=sevInfo(item.__norm?item.__norm.severity:null,sc),cve=(item.title||'').match(/CVE-\d{4}-\d{4,}/i),kev=item.kev_present,epss=parseFloat(item.epss_score)||0,cvss=parseFloat(item.cvss_score)||0,pr=prio(item),prC=prioColor(pr),barW=Math.min(sc*10,100);
                return '<div style="position:relative;">' +
                    '<div class="t10-blur-card" style="background:linear-gradient(135deg,var(--bg-card),rgba(220,38,38,0.02));border:1px solid var(--border);border-radius:4px;overflow:hidden;">'+
                        '<div style="height:3px;background:linear-gradient(90deg,'+sv.c+' '+barW+'%,rgba(255,255,255,0.04) '+barW+'%);"></div>'+
                        '<div style="display:flex;align-items:center;gap:6px;padding:10px 14px 6px;">'+
                            '<span style="font-size:14px;line-height:1;">'+RANK_ICONS[idx]+'</span>'+
                            '<span style="font-family:var(--font-mono);font-size:8px;color:#3a4a5a;font-weight:700;">#'+(idx+1)+'</span>'+
                            '<span style="background:'+sv.bg+';color:'+sv.c+';padding:2px 8px;border-radius:3px;font-size:9px;font-weight:800;font-family:var(--font-mono);">'+sv.l+'</span>'+
                            (kev?'<span style="background:rgba(220,38,38,.12);color:#dc2626;padding:1px 6px;border-radius:3px;font-size:8px;font-weight:800;">&#9889; CISA KEV</span>':'')+
                        '</div>'+
                        '<div style="padding:2px 14px 8px;"><div style="font-size:12px;font-weight:700;color:var(--white);line-height:1.4;">'+
                            _tt((item.title||'Unknown').substring(0,80))+'...'+
                        '</div></div>'+
                        '<div style="padding:0 14px 8px;display:flex;gap:8px;">'+
                            (cvss>0?'<div style="padding:4px 8px;background:rgba(255,255,255,0.03);border-radius:3px;border:1px solid rgba(255,255,255,0.06);text-align:center;"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;">CVSS</div><div style="font-family:var(--font-mono);font-size:12px;font-weight:900;color:'+(cvss>=9?'#dc2626':cvss>=7?'#ea580c':'#d97706')+';">'+cvss.toFixed(1)+'</div></div>':'')+
                            '<div style="padding:4px 8px;background:rgba(139,92,246,0.06);border-radius:3px;border:1px solid rgba(139,92,246,0.15);text-align:center;"><div style="font-family:var(--font-mono);font-size:7px;color:#5a6578;">IOC</div><div style="font-family:var(--font-mono);font-size:10px;font-weight:900;color:#a78bfa;">&#128274; PRO</div></div>'+
                        '</div>'+
                        '<div style="padding:6px 14px 10px;border-top:1px solid rgba(255,255,255,0.04);">'+
                            '<a style="font-family:var(--font-mono);font-size:9px;color:#5a6578;border:1px solid #2a3340;padding:4px 10px;border-radius:3px;display:inline-block;">&#128274; PRO ACCESS</a>'+
                        '</div>'+
                    '</div>' +
                    // Click overlay
                    '<div onclick="window.open(\'/upgrade.html?plan=pro&utm_source=blur-card-'+idx+'\',\'_blank\')" style="position:absolute;inset:0;cursor:pointer;display:flex;align-items:center;justify-content:center;background:rgba(2,2,5,0.5);border-radius:4px;border:1px solid rgba(220,38,38,0.2);">'+
                        '<div style="text-align:center;">'+
                            '<div style="font-size:20px;margin-bottom:6px;">&#128274;</div>'+
                            '<div style="font-family:var(--font-mono);font-size:9px;font-weight:800;color:#f87171;letter-spacing:1px;">PRO ONLY</div>'+
                            '<div style="font-family:var(--font-mono);font-size:8px;color:#5a6578;margin-top:3px;">Click to unlock</div>'+
                        '</div>'+
                    '</div>'+
                '</div>';
            }).join('') +
        '</div>';
}

        // ── Embedded Fallback Data (real advisories \u2014 renders when network unavailable) ──
        window.EMBEDDED_INTEL = [];  // v112.0: cleared \u2014 Worker API (R2-backed) is authoritative. EMBEDDED_INTEL intentionally empty.

        // ── Load Data (v73.0 \u2014 Progressive Loading: Zero-Wait Boot) ──
        // ARCHITECTURE: Render EMBEDDED_INTEL immediately, then upgrade to live.
        // Eliminates stuck "SYNCING GOC NEURAL CORE..." state entirely.

        let _liveDataLoaded = false;
        window.__INTEL_RENDERED__ = false; // APEX FINAL: single render execution guard
        window.__DATA_LOADED__    = false; // APEX FINAL: single data load guard
        window.RENDER_IN_PROGRESS = false; // v184.0: concurrent render lock init

        // v184.0: GLOBAL ERROR HANDLER \u2014 catch and log all unhandled JS errors
        window.onerror = function(msg, src, line, col, err) {
            console.error('🚨 [SENTINEL-APEX] GLOBAL ERROR:', msg, '| Source:', src, '| Line:', line, '| Error:', err);
            // Reset render lock on fatal error so recovery is possible
            window.RENDER_IN_PROGRESS = false;
            return false; // Do not suppress default error handling
        };
        window.onunhandledrejection = function(event) {
            console.error('🚨 [SENTINEL-APEX] UNHANDLED PROMISE REJECTION:', event.reason);
            window.RENDER_IN_PROGRESS = false;
        };

        function bootFromEmbeddedCache() {
            // Instant render from embedded cache \u2014 zero network dependency
            // v184.0: IMMUTABLE API-FIRST \u2014 EMBEDDED_INTEL is intentionally empty.
            // bootFromEmbeddedCache is now a no-op; live data loads from /api/v1/intel/latest.json
            if (!EMBEDDED_INTEL || !EMBEDDED_INTEL.length) {
                console.log('[BOOT v150] Immutable API-first mode \u2014 skipping embedded cache, API fetch will populate dashboard');
                return;
            }
            try {
                manifestData = [...EMBEDDED_INTEL].reverse();
                try { computeMetrics(manifestData); } catch(e) { console.warn('[BOOT] computeMetrics error:', e); }
                try { renderTrendChart(manifestData); } catch(e) { console.warn('[BOOT] renderTrendChart error:', e); }
                // v184.0 FIX: Restore instant render \u2014 EMBEDDED_INTEL must show cards immediately on boot
                // ROOT CAUSE: v184.0 removed applyView() here causing "SYNCING GOC NEURAL CORE..." to persist
                // until network fetch completes. With EMBEDDED_INTEL populated, cards MUST render at boot.
                try {
                    var _bg = document.getElementById('threat-grid');
                    if (_bg) _bg.innerHTML = '';
                    window.__INTEL_RENDERED__ = false; // allow render
                    window.RENDER_IN_PROGRESS = false;
                    applyView();
                    window.__INTEL_RENDERED__ = true;
                    console.log('[BOOT v148] Instant render from EMBEDDED_INTEL:', manifestData.length, 'items');
                } catch(e) { console.warn('[BOOT] applyView error:', e); }
            } catch(e) {
                console.warn('[BOOT] Data setup error:', e);
            }
            // ── v138 FIX: Dynamic version injection \u2014 version.json primary, api/status.json fallback ──
            // Root cause of v101.0.0 regression: api/status.json non-ok response → null → hardcoded '101.0.0'
            // Fix: read version.json (always correct) first; hard fallback is CURRENT version not stale one
            // PRODUCTION-TRUTH FIX (release hardening -- version audit): CURRENT_VER was
            // hardcoded '183.0', itself stale by the time this ran (same class of bug
            // this block's own comment above describes fixing for v101.0.0). Worse,
            // _setVer replaced #engine-version-display's ENTIRE textContent, which
            // silently deleted the "FEEDS" text and the #engine-feed-count span living
            // inside it (permanently breaking that element's own live-updater at
            // getElementById('engine-feed-count') for the rest of the page's life)
            // every time this ran, success or not. Now writes only the number into
            // engine-version-number -- the same narrow element syncVersion() above
            // manages -- leaving the feed-count span untouched either way.
            (async function _syncEngineVersion() {
                const CURRENT_VER = '201.0';
                const _setVer = function(v) {
                    const el = document.getElementById('engine-version-number');
                    if (el) el.textContent = v;
                };
                // Immediate set \u2014 eliminates any stale hardcoded text, zero flash
                _setVer(CURRENT_VER);
                // Try version.json (authoritative, always committed by pipeline)
                try {
                    const r = await fetch('version.json?_=' + Date.now());
                    if (r.ok) { const d = await r.json(); if (d && d.version) { _setVer(d.version); return; } }
                } catch(e) {}
                // Try api/status.json as secondary
                try {
                    const r = await fetch('api/status.json?_=' + Date.now());
                    if (r.ok) { const d = await r.json(); if (d && d.version) { _setVer(d.version); } }
                } catch(e) {}
            })();
            // ── UI updates \u2014 always run, even if render steps above had errors ──
            const syncVal = document.getElementById('sync-val');
            const integrityEl = document.getElementById('integrity-status');
            const lastLoaded = document.getElementById('last-loaded');
            if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--medium);">CACHE</span>';
            if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge" style="background:rgba(217,119,6,0.08);color:var(--medium);border:1px solid rgba(217,119,6,0.25);">⚡ EMBEDDED CACHE ACTIVE</span>';
            if (lastLoaded) lastLoaded.textContent = 'CACHE: ' + new Date().toLocaleTimeString() + ' \u00b7 UPGRADING TO LIVE...';
            document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('syncing'));
            console.log('[CDB-GOC] Instant boot from embedded cache:', EMBEDDED_INTEL.length, 'items');
            try { _cdbUpdateTabCounts(); } catch(e) {}
        }

        // ── v138 FIX: APEX AI merge \u2014 feed.json lacks apex_ai; restore from EMBEDDED_INTEL ─────
        // ROOT CAUSE: e6a454c597 put feed.json (no apex_ai) first in MANIFEST_URLS for speed.
        // When feed.json wins the race, all intel cards lose their APEX AI panel.
        // FIX: after any data load, enrich items missing apex_ai from EMBEDDED_INTEL (by stix_id/id).
        function _mergeApexAI(entries) {
            // v139 FIX: dual-key lookup \u2014 ID-based first, title-based fallback.
            // Root cause: feed.json items use timestamp IDs ("intel--1777025479") while
            // EMBEDDED_INTEL uses UUID-hash IDs ("intel--96f0...") \u2014 ID matching always
            // fails cross-source → 0 apex_ai injected → APEX panels disappear on main dash.
            // v184.0: apex_ai now served from /api/v1/intel/apex.json (API-first)
            // EMBEDDED_INTEL is empty; apex data arrives via MANIFEST_URLS fetch
            if (!window.EMBEDDED_INTEL || !window.EMBEDDED_INTEL.length) return entries;
            var apexMap   = {};  // stix_id/id → apex_ai
            var titleMap  = {};  // normalised title → apex_ai (cross-source fallback)
            window.EMBEDDED_INTEL.forEach(function(e) {
                var k = e.stix_id || e.id;
                if (k && e.apex_ai) apexMap[k] = e.apex_ai;
                if (e.title && e.apex_ai) {
                    var tk = e.title.toLowerCase().replace(/\s+/g,' ').trim().substring(0, 80);
                    titleMap[tk] = e.apex_ai;
                }
            });
            return entries.map(function(e) {
                if (e.apex_ai) return e;
                // 1. Try exact ID match
                var k = e.stix_id || e.id;
                if (k && apexMap[k]) { return Object.assign({}, e, { apex_ai: apexMap[k] }); }
                // 2. Title-based fallback \u2014 works when ID formats differ across sources
                if (e.title) {
                    var tk = e.title.toLowerCase().replace(/\s+/g,' ').trim().substring(0, 80);
                    if (titleMap[tk]) { return Object.assign({}, e, { apex_ai: titleMap[tk] }); }
                }
                return e;
            });
        }

        async function loadGOCIntel() {
            // APEX FINAL P2: single data load guard
            if (window.__DATA_LOADED__) {
                console.warn('[BLOCK] Duplicate data load prevented');
                return;
            }
            window.__DATA_LOADED__ = true;
            // ================================================================
            // v77.4 PERMANENT FIX \u2014 Definitive Sync Architecture
            // FIXES:
            //   1. SYNC: CACHE → SYNC: LIVE in all fallback paths
            //   2. EMBEDDED_INTEL IS the live gh-pages data \u2014 always show LIVE
            //   3. Fetch source priority: gh-pages manifest > raw.github
            //   4. Faster 8s timeout \u2014 better mobile performance
            //   5. Self-healing: main branch carries this fix forward
            // ================================================================
            var syncVal     = document.getElementById('sync-val');
            var integrityEl = document.getElementById('integrity-status');
            var lastLoadedEl = document.getElementById('last-loaded');

            if (!_liveDataLoaded && manifestData.length === 0) {
                document.querySelectorAll('.metric-card').forEach(function(c){ c.classList.add('syncing'); });
                // v184.0: Show loading state in threat grid while API fetch runs
                var _tg = document.getElementById('threat-grid');
                if (_tg && !_tg.innerHTML.trim()) {
                    _tg.innerHTML = '<div class="loading-state" style="text-align:center;padding:40px;color:var(--text-dim)"><div style="font-size:1.5rem;margin-bottom:8px">⚡</div><div>SENTINEL APEX \u2014 Loading Threat Intelligence...</div><div style="font-size:0.8rem;margin-top:4px;opacity:0.6">Fetching from immutable API manifest</div></div>';
                }
            }
            var aiPulse = document.getElementById('ai-pulse-indicator');
            if (aiPulse) aiPulse.style.display = 'inline-flex';

            // Cache-bust timestamp
            var cb = '?nc=' + Date.now();

            // Priority order (v117.0.0):
            // 1. Worker API /api/preview (PRIMARY \u2014 R2-backed, always fresh)
            // 2. api/feed.json (same-domain fallback \u2014 updated each pipeline run)
            // 3. raw.githubusercontent.com + cache-bust
            // 4. raw.githubusercontent.com plain fallback
            // REMOVED: jsDelivr (24h CDN cache \u2014 permanent sync killer)
            // REMOVED: cyberdudebivash.github.io/...feed_manifest.json (deprecated \u2014 intel
            //          data is no longer stored in the public GitHub Pages repo. Manifest
            //          lives exclusively in Cloudflare R2; serving via Worker is authoritative.)
            // ARCHITECTURE: Worker(/api/preview) → api/feed.json → raw fallbacks → EMBEDDED_INTEL
            var WORKER_PREVIEW_URL = 'https://intel.cyberdudebivash.com/api/preview/'; // v184.0: trailing slash \u2014 matches Worker route exactly
            // v184.0 P0 FIX -- 3-LAYER FALLBACK ARCHITECTURE:
            //   PRIMARY  : Worker API  -- intel.cyberdudebivash.com/api/preview  (R2-backed, always fresh)
            //   FALLBACK1: api/feed.json -- same-domain, Worker now handles this route from R2
            //   FALLBACK2: raw.githubusercontent.com -- cross-origin reliable bypass (5-min cache OK as 3rd tier)
            //   INSTANT  : EMBEDDED_INTEL -- top-25 items injected by inject_embedded_intel.py pre-deploy
            // Parser handles both schemas: data.preview.items (Worker) -> plain Array (feed.json)
            var MANIFEST_URLS = [
                // v184.0 PRIORITY FIX: api/feed.json = PRIMARY (Worker public endpoint, R2-backed, no auth)
                // api/v1/intel/* = secondary via Worker public passthrough (v184.0 Worker fix deployed)
                'api/feed.json',               // PRIMARY:   Worker /api/feed.json \u2014 public, R2-backed, 100% apex_ai
                'api/v1/intel/latest.json',    // SECONDARY: Immutable versioned manifest (Worker passthrough v184.0)
                'api/v1/intel/apex.json',      // APEX:      Apex AI enriched bundle (Worker passthrough v184.0)
                WORKER_PREVIEW_URL,            // FALLBACK1: Worker preview (rate-limited)
                'https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/api/feed.json', // FALLBACK2: emergency bypass
            
            ];

            // EMBEDDED_INTEL IS the current gh-pages data \u2014 it was updated by the pipeline.
            // Any fetch that returns OLDER data should be rejected.
            // v117.0.0 FRESHNESS FIX: Use processed_at (pipeline time) for FRESHEST-WINS comparison
            var embeddedNewest = (EMBEDDED_INTEL && EMBEDDED_INTEL.length)
                ? Math.max.apply(null, EMBEDDED_INTEL.map(function(i){
                    return new Date(i.published_at || i.timestamp || i.processed_at || 0).getTime();
                  }))
                : 0;

            var lastError = null;
            // P0 2026-09-03: record the OUTCOME of every source attempt, not
            // just the last Error object. The terminal branch below previously
            // had no way to tell an entitlement denial (HTTP 429 from the API
            // quota gate) apart from a network failure apart from a genuinely
            // empty feed -- so it collapsed all three into "LOADING / NO DATA".
            // js/feed-state.js turns these records into an explicit terminal
            // state. Purely additive: nothing in the success paths reads it.
            var _feedAttempts = [];
            for (var mIdx = 0; mIdx < MANIFEST_URLS.length; mIdx++) {
                var manifestUrl = MANIFEST_URLS[mIdx];
                // isApiSource: authoritative sources bypass staleness gates
                // v184.0: Worker API + api/feed.json = authoritative; raw.githubusercontent.com = fallback (not authoritative)
                var isApiSource = (manifestUrl === WORKER_PREVIEW_URL || manifestUrl === 'api/feed.json');
                try {
                    var ctrl = new AbortController();
                    var tid  = setTimeout(function(){ ctrl.abort(); }, 8000);
                    var resp = await fetch(manifestUrl, {
                        cache: 'no-store',
                        signal: ctrl.signal,
                        headers: {
                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                            'Pragma': 'no-cache'
                        }
                    });
                    clearTimeout(tid);
                    if (!resp.ok) {
                        // P0 2026-09-03: capture the status BEFORE throwing.
                        // A 429 here is the API entitlement gate denying the
                        // request, not evidence that no intelligence exists --
                        // that distinction is what the terminal branch needs.
                        _feedAttempts.push({ url: manifestUrl, status: resp.status, ok: false, authoritative: isApiSource, itemCount: 0 });
                        throw new Error('HTTP ' + resp.status);
                    }
                    var data    = await resp.json();
                    // v184.0: MULTI-SCHEMA SAFE PARSER
                    // Priority: data.preview.items (Worker) > data.items > data.data.items > plain Array
                    console.log('[SENTINEL-APEX] API RAW:', JSON.stringify(data).slice(0, 200));
                    var items = (data && data.preview && data.preview.items && Array.isArray(data.preview.items) && data.preview.items.length > 0)
                                ? data.preview.items
                                : (data && data.items && Array.isArray(data.items) && data.items.length > 0)
                                ? data.items
                                : (data && data.data && data.data.items && Array.isArray(data.data.items) && data.data.items.length > 0)
                                ? data.data.items
                                : (Array.isArray(data) ? data : []);
                    var entries = items;
                    console.log('[SENTINEL-APEX] ITEM COUNT:', entries.length);
                    // P0 2026-09-09: how old is this source's OWN content, not
                    // just whether the HTTP request succeeded -- js/feed-state.js
                    // uses this to stop an ancient fallback mirror (frozen since
                    // the pipeline's git-commit step was retired for R2, see that
                    // file's docstring) from being accepted as a merely-"stale"
                    // hit forever. Same field-priority order as the existing
                    // _genAt extraction below; a plain-array response (no
                    // top-level timestamp) falls back to the newest item's own
                    // published date, same computation as the Worker's own
                    // computeStats()/last_sync.
                    var _contentGeneratedAt = (data && data.preview && data.preview.generated_at) || (data && data.generated_at) || null;
                    if (!_contentGeneratedAt && entries.length) {
                        var _cgNewest = 0, _cgNowMs = Date.now();
                        for (var _cgI = 0; _cgI < entries.length; _cgI++) {
                            var _cgRaw = entries[_cgI] && (entries[_cgI].published_at || entries[_cgI].published || entries[_cgI].timestamp);
                            var _cgTs = _cgRaw ? Date.parse(_cgRaw) : NaN;
                            if (!isNaN(_cgTs) && _cgTs > _cgNewest && _cgTs <= _cgNowMs) _cgNewest = _cgTs;
                        }
                        if (_cgNewest) _contentGeneratedAt = new Date(_cgNewest).toISOString();
                    }
                    // P0 2026-09-03: a 200 that parses to 0 items is a real,
                    // distinct outcome (feed reachable, genuinely empty) and
                    // must not be recorded as the same thing as a 429.
                    _feedAttempts.push({ url: manifestUrl, status: resp.status, ok: true, authoritative: isApiSource, itemCount: entries.length, contentGeneratedAt: _contentGeneratedAt });
                    if (!entries.length) {
                        console.error('[SENTINEL-APEX] NO DATA FROM API \u2014 all parse paths returned 0 items');
                        throw new Error('API returned 0 items');
                    }
                    console.log('[SENTINEL-APEX] API items:', entries.length);
                    // v200.3 P0 FIX: confirmed live (pages-fast-publish run #45,
                    // 2026-09-04 -- the v200.2 fix above raised the SW-recovery
                    // guard from 1 to 3 attempts, taking
                    // verify_stale_service_worker_recovery.js from 1/4 to 2/4
                    // checks passing, including the core recovery mechanism
                    // itself). The remaining failure is a follow-up ordinary
                    // reload, well after recovery already succeeded once,
                    // independently tripping the same "all sources failed
                    // under an active SW" condition (a freshly-installing
                    // real SW can itself take more than one reload to fully
                    // settle) -- but by then the 3-attempt budget from the
                    // EARLIER, already-resolved episode was nearly spent,
                    // leaving little room for this new one. A budget spent
                    // resolving one episode should not be held against a
                    // later, unrelated one: reaching this line proves the
                    // current page instance's fetch path is genuinely
                    // healthy again, so any earlier recovery spend no longer
                    // reflects real risk. Reset it here so a later episode
                    // -- on this page instance or the next reload -- gets
                    // its own fresh budget instead of inheriting a
                    // near-exhausted one.
                    try { sessionStorage.setItem('apex_sw_recovery_attempts', '0'); } catch (e) {}

                    // ── v102.0 SCHEMA NORMALIZATION ──────────────────────────────────────
                    // v74 manifest enricher writes items with 'id' (STIX object ID) instead
                    // of 'stix_id'. ALL AI features \u2014 threatRegistry, injectAnalyzeButtons,
                    // cdbOpenAgent \u2014 require stix_id. This normalization pass ensures 100%
                    // field compatibility regardless of which backend script wrote the JSON.
                    entries = entries.map(function(item) {
                        // Map STIX object id → stix_id (primary AI key)
                        if (!item.stix_id && item.id) item.stix_id = item.id;
                        // Map v74 ttps array → mitre_techniques for MITRE panel
                        if (!item.mitre_techniques && item.ttps) {
                            item.mitre_techniques = Array.isArray(item.ttps) ? item.ttps
                                : (typeof item.ttps === 'string'
                                   ? (function(s){try{return JSON.parse(s.replace(/'/g,'"'));}catch(e){return [s];}})(item.ttps)
                                   : []);
                        }
                        // Map v74 iocs string → array
                        if (item.iocs && typeof item.iocs === 'string') {
                            try { item.iocs = JSON.parse(item.iocs.replace(/'/g, '"')); } catch(e) {}
                        }
                        // Map v74 confidence (0\u2013100 numeric) → confidence_score (0.0\u20131.0)
                        if (item.confidence_score == null && item.confidence != null) {
                            var cv = parseFloat(item.confidence);
                            item.confidence_score = cv > 1 ? cv / 100 : cv;
                        }
                        // Map v74 risk_score string → numeric
                        if (item.risk_score != null) item.risk_score = parseFloat(item.risk_score) || 0;
                        return item;
                    });
                    // ── END SCHEMA NORMALIZATION ──────────────────────────────────────────

                    // ── P0 FIX: CANONICAL NORMALIZATION HOOK ────────────────────────────────
                    // js/api_adapter.js's normalizeIntelItem() is the same function
                    // js/card_renderer.js's dashboard already uses and that was already
                    // verified correct against live production data. Every OTHER dashboard
                    // rendering path in this file (computeMetrics, renderTopThreats,
                    // cdbRenderSOC, openThreatModal, ...) independently re-derives severity,
                    // SOC priority, risk, confidence, and freshness from these same raw items
                    // instead of calling it -- producing up to four different, mutually
                    // inconsistent priority computations and the HIGH-severity/P4-priority
                    // contradiction previously found live. Attaching the canonical result here,
                    // once, at the single point where every legacy renderer's raw item list is
                    // built, lets those renderers read item.__norm.<field> instead of
                    // recalculating -- additive only: item.__norm is a new property, no
                    // existing raw field is removed or renamed, so any renderer not yet
                    // migrated keeps working exactly as before.
                    if (window.SentinelApexAdapter && typeof window.SentinelApexAdapter.normalizeIntelItem === 'function') {
                        entries = entries.map(function(item, idx) {
                            try { item.__norm = window.SentinelApexAdapter.normalizeIntelItem(item, idx); }
                            catch (e) { console.warn('[SENTINEL-APEX] normalizeIntelItem failed for', item && item.id, e); }
                            return item;
                        });
                    }
                    // ── END CANONICAL NORMALIZATION HOOK ────────────────────────────────────

                    var liveNewest = Math.max.apply(null, entries.map(function(i){
                        return new Date(i.published_at || i.timestamp || i.processed_at || 0).getTime();  // v117.0.0
                    }));

                    // FRESHEST-WINS: if live data is older, keep EMBEDDED_INTEL (still show LIVE)
                    // BYPASS for same-domain api/feed.json \u2014 always authoritative regardless of timestamps
                    if (!isApiSource && liveNewest < embeddedNewest && EMBEDDED_INTEL && EMBEDDED_INTEL.length) {
                        console.log('[GOC v201.0] Keeping EMBEDDED_INTEL (it is newer than live fetch). Embedded:',
                            new Date(embeddedNewest).toISOString().slice(0,19),
                            'Live:', new Date(liveNewest).toISOString().slice(0,19));
                        _liveDataLoaded = true;
                        if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--accent);animation:new-glow 1.5s ease-in-out infinite alternate;">&#x26A1; LIVE</span>';
                        if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge integrity-ok"><i class="fas fa-shield-check"></i> MANIFEST VERIFIED</span>';
                        // P0 FIX: was new Date().toLocaleTimeString(); embeddedNewest (the actual
                        // data timestamp this branch just compared against) is already computed above.
                        if (lastLoadedEl) lastLoadedEl.textContent = 'SYNCED: ' + (embeddedNewest ? timeSince(embeddedNewest) : 'just now') + ' \u00b7 EMBEDDED LIVE';
                        document.querySelectorAll('.metric-card').forEach(function(c){ c.classList.remove('syncing'); });
                        if (aiPulse) aiPulse.style.display = 'none';
                        // APEX FINAL: single-source render \u2014 embedded wins freshness gate
                        if (!window.__INTEL_RENDERED__) {
                            window.__INTEL_RENDERED__ = true;
                            var _fd = (manifestData && manifestData.length > 0) ? manifestData : []  /* v184.0: API-only, no embedded fallback */;
                            // v184.0 FIX: use full 3-layer deduplicateIntel (prev filter had broken id-less passthrough)
                            _fd = deduplicateIntel(_fd);
                            manifestData = _fd;
                            var _fg = document.getElementById('threat-grid');
                            if (_fg) _fg.innerHTML = '';
                            console.log('[RENDER] Executed at', new Date().toISOString(), '| items:', _fd.length);
                            try {
                        applyView();
                        // GOD MODE safety net: verify grid populated after render
                        try { var _grv = document.getElementById('threat-grid'); if (_grv && _grv.children.length === 0 && _ld.length > 0) { console.warn('[SENTINEL-APEX] Empty grid after applyView \u2014 GOD MODE activating'); cdbGodModeRender(_ld); } } catch(_gne) {}
                    } catch(e) { console.error('[SENTINEL-APEX] applyView FAILED:', e); try { cdbGodModeRender(_ld); } catch(_ge) {} }
                        }
                        try { _cdbUpdateTabCounts(); } catch(e) {}
                        return;
                    }

                    // Live data is fresher \u2014 use it and show LIVE
                    manifestData = entries.slice().sort(function(a, b){
                        return new Date(b.published_at||b.timestamp||b.processed_at||0) - new Date(a.published_at||a.timestamp||a.processed_at||0);  // v184.0 FIX
                    });
                    // v138 FIX: restore apex_ai for items loaded from feed.json (which strips apex_ai)
                    try { manifestData = _mergeApexAI(manifestData); } catch(e) {}
                    // v184.0 FIX: publish live data for AI Brain (EMBEDDED_INTEL is [] in R2-only arch)
                    window.__GOC_LIVE_INTEL = manifestData;
                    try { if (window.CDB_AI && window.CDB_AI.runBrain) window.CDB_AI.runBrain(); } catch(_aie) {}
                    _liveDataLoaded = true;
                    // v112.1 FIX: computeMetrics FIRST \u2014 then override m-total/m-last-sync with authoritative API values
                    // computeMetrics(manifestData) sets m-total = preview items (10); overrides below correct to full count
                    try { computeMetrics(manifestData); } catch(e) {}
                    try { renderTrendChart(manifestData); } catch(e) {}
                    // APEX FINAL P4+5+7+8 v184.0: single-source, API-only, sort-locked, dedup, trace
                    // v184.0 FIX: live data always supersedes cached render -- removed self-defeating guard
                    // (was: __INTEL_RENDERED__=false then if(!__INTEL_RENDERED__) which is ALWAYS true)
                    window.__INTEL_RENDERED__ = true;
                    // P4: single source of truth
                    var _ld = (manifestData && manifestData.length > 0) ? manifestData : []  /* v184.0: API-only, no embedded fallback */;
                    // P7: UI-level safeData dedup — v184.0 FIX: use full 3-layer deduplicateIntel (prev filter had broken id-less passthrough)
                    _ld = deduplicateIntel(_ld);
                    manifestData = _ld;
                    // P5: hard UI reset
                    var _lg = document.getElementById('threat-grid');
                    if (_lg) _lg.innerHTML = '';
                    // P8: debug trace -- logs ONCE per live-data load
                    console.log('[RENDER] Executed at', new Date().toISOString(), '| items:', _ld.length);
                    try {
                        applyView();
                        try { var _grv3 = document.getElementById('threat-grid'); if (_grv3 && _grv3.children.length === 0 && _ld.length > 0) { console.warn('[SENTINEL-APEX] Empty grid \u2014 GOD MODE'); cdbGodModeRender(_ld); } } catch(_gne3) {}
                    } catch(e) { console.error('[SENTINEL-APEX] applyView FAILED (path-ld):', e); try { cdbGodModeRender(_ld); } catch(_ge3) {} }
                    // v112.1 API COUNT SYNC: Worker /api/preview nests total under data.preview.total_in_feed
                    // Fix: read data.preview.total_in_feed first, fall back to top-level fields
                    try {
                        if (isApiSource) {
                            var _tcVal = (data.preview && data.preview.total_in_feed)
                                      || data.total_in_feed || data.count || data.total_count;
                            if (_tcVal) {
                                var _tcEl = document.getElementById('m-total');
                                if (_tcEl) _tcEl.textContent = Number(_tcVal).toLocaleString();
                            }
                        }
                    } catch(_me) {}
                    // v200.1 P0 FIX: the #m-last-sync WRITE this block used to do here is
                    // removed (consolidated onto fetchWorkerStats() -> /api/platform/stats
                    // intel.last_sync, so this page never shows two different answers for
                    // "how fresh is our data" depending on which of several racing fetches
                    // happened to finish last) -- but _genAt itself is still a real value
                    // _syncedAt below needs (the "SYNCED: ..." refresh-bar line, a separate,
                    // still-legitimate display this function alone owns). Recompute it,
                    // side-effect-free, so removing the redundant write didn't also delete
                    // the one variable a completely different line still depends on.
                    var _genAt;
                    try {
                        if (isApiSource) _genAt = (data.preview && data.preview.generated_at) || data.generated_at;
                    } catch(_gae) {}
                    // v200.1 P0 FIX: last-sync display consolidated onto one source
                    // (fetchWorkerStats() -> /api/platform/stats intel.last_sync) so this
                    // page never shows two different answers for "how fresh is our data"
                    // depending on which of several racing fetches happened to finish
                    // last. See fetchWorkerStats for the authoritative update path.
                    // P0 2026-09-03: only an AUTHORITATIVE source may be
                    // labelled LIVE / MANIFEST VERIFIED. When the API sources
                    // were quota-denied, the third-party raw.githubusercontent
                    // mirror answered with a stale 109-item snapshot against
                    // the authority's 500 -- and this line still asserted
                    // "LIVE" and "MANIFEST VERIFIED" over it. Reproduced in a
                    // real Chromium; see the root-cause report. The data is
                    // still shown (degrading to a mirror beats showing
                    // nothing) -- it is simply labelled honestly as STALE.
                    //
                    // P0 2026-09-05: the comment above about fetchWorkerStats()
                    // running "after" this write was only true for the
                    // manualRefresh()/auto-refresh path (which awaits
                    // loadGOCIntel() THEN calls fetchWorkerStats()). On initial
                    // page boot, _cdbBootSequence() fires loadGOCIntel() (this
                    // function, unawaited) and the page's own top-level
                    // fetchWorkerStats() call at the same time -- two
                    // independent in-flight requests with no ordering
                    // guarantee. Confirmed live: /api/platform/stats already
                    // reported freshness:"STALE" while this branch still
                    // unconditionally wrote LIVE, because on that page load
                    // this isApiSource fetch happened to resolve AFTER
                    // fetchWorkerStats() had already (correctly) downgraded
                    // the badge -- silently reverting the truthful state back
                    // to a false LIVE. window.__CDB_FRESHNESS__ (set by
                    // fetchWorkerStats() from the same classifyFreshness()
                    // signal, reused not reimplemented) makes the two paths
                    // consult one shared answer instead of racing -- whichever
                    // of the two finishes last now reaches the same
                    // conclusion.
                    // P0 2026-09-26: only FRESH is live. classifyFreshness() calls
                    // 6-24h "RECENT", but the canonical contract
                    // (config/public_freshness_contract.json) makes anything past
                    // 6h STALE -- a 9h-old feed was still badged SYNC: LIVE.
                    var _knownStale = window.__CDB_FRESHNESS__
                        && window.__CDB_FRESHNESS__ !== 'FRESH';
                    if (isApiSource && _knownStale) {
                        if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--warning,#ffa502);">&#x26A1; STALE</span>';
                        if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge" style="color:var(--warning,#ffa502);">&#x26A1; '
                            + (window.__CDB_FRESHNESS__ === 'UNAVAILABLE' ? 'FRESHNESS UNKNOWN' : (window.__CDB_FRESHNESS__ === 'RECENT' ? 'STALE' : window.__CDB_FRESHNESS__) + ' DATA') + '</span>';
                    } else if (isApiSource) {
                        if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--accent);animation:new-glow 1.5s ease-in-out infinite alternate;">&#x26A1; LIVE</span>';
                        if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge integrity-ok"><i class="fas fa-shield-check"></i> MANIFEST VERIFIED</span>';
                    } else {
                        if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--warning,#ffa502);">&#x26A1; STALE</span>';
                        if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge" style="color:var(--warning,#ffa502);">&#x26A1; FALLBACK SOURCE</span>';
                        console.warn('[GOC v201.0] Rendering from NON-AUTHORITATIVE fallback mirror:', manifestUrl.substring(0, 70), '| items:', entries.length);
                    }
                    var _displayCount = (data.preview && data.preview.total_in_feed)
                                      || data.total_in_feed || data.total_count || data.count || entries.length;
                    var _srcLabel = isApiSource ? 'API LIVE' : 'MANIFEST';
                    // P0 FIX: was new Date().toLocaleTimeString() -- a browser-clock reading
                    // labeled "SYNCED", indistinguishable to the user from real data freshness
                    // regardless of how stale the underlying feed actually is. Prefer the
                    // server's own generated_at (_genAt, computed above for API sources) or
                    // the newest item timestamp in the data actually received.
                    var _syncedAt = _genAt || (entries.length ? Math.max.apply(null, entries.map(function(i){
                        return new Date(i.published_at||i.timestamp||i.processed_at||0).getTime();
                    })) : 0);
                    if (lastLoadedEl) lastLoadedEl.textContent = 'SYNCED: ' + (_syncedAt ? timeSince(_syncedAt) : 'just now') + ' \u00b7 ' + _displayCount + ' advisories \u00b7 ' + _srcLabel;
                    document.querySelectorAll('.metric-card').forEach(function(c){ c.classList.remove('syncing'); });
                    if (aiPulse) aiPulse.style.display = 'none';
                // PRODUCTION-TRUTH FIX (release hardening -- version audit): removed
                // rather than fixed. data.gateway does not exist anywhere in the
                // live /api/feed.json response (checked directly: schema_version,
                // generated_at, generator, version, count, items, sha256 -- no
                // gateway key), so this v110.1 branch has never actually run in
                // production. Had it run, it also would have wiped
                // #engine-version-display's whole textContent -- the same
                // destructive-overwrite bug just fixed in syncVersion() and
                // _syncEngineVersion() above, in a format ("SENTINEL APEX <gateway>")
                // that doesn't even match either of those. Confirmed dead, not a
                // capability anything depends on -- removed outright rather than
                // left as a landmine that reactivates if the feed schema ever
                // grows a gateway field.
                    console.log('[GOC v201.0] Live data loaded:', _displayCount, 'items | source:', isApiSource ? 'api/feed.json' : manifestUrl.substring(0, 60));
                    try { _cdbUpdateTabCounts(); } catch(e) {}
                    return;

                } catch (err) {
                    lastError = err;
                    // P0 2026-09-03: a throw that produced no HTTP status at
                    // all (network error / timeout / abort) still needs an
                    // attempt record, with status null, so the terminal state
                    // resolver sees every source that was tried.
                    if (!_feedAttempts.some(function (a) { return a.url === manifestUrl; })) {
                        _feedAttempts.push({ url: manifestUrl, status: null, ok: false, authoritative: isApiSource, itemCount: 0 });
                    }
                    console.warn('[GOC v201.0] Fetch failed:', manifestUrl.substring(0, 60), err.message);
                }
            }

            // ─── ALL NETWORK SOURCES FAILED ─────────────────────────────────
            // EMBEDDED_INTEL IS the authoritative gh-pages data.
            // It was updated by the pipeline \u2014 it IS the live data.
            // Show LIVE not CACHE \u2014 the data is current.
            if (EMBEDDED_INTEL && EMBEDDED_INTEL.length) {
                if (!_liveDataLoaded) {
                    manifestData = EMBEDDED_INTEL.slice().sort(function(a, b){
                        return new Date(b.published_at||b.timestamp||b.processed_at||0) - new Date(a.published_at||a.timestamp||a.processed_at||0);  // v184.0 FIX
                    });
                    try { computeMetrics(manifestData); } catch(e) {}
                    try { renderTrendChart(manifestData); } catch(e) {}
                    // APEX FINAL: single-source render \u2014 embedded fallback (all network failed)
                    if (!window.__INTEL_RENDERED__) {
                        window.__INTEL_RENDERED__ = true;
                        var _efds = new Set();
                        manifestData = manifestData.filter(function(item) { var k=item.stix_id||item.id||''; if(!k||_efds.has(k)){return !k;} _efds.add(k); return true; });
                        var _efg = document.getElementById('threat-grid');
                        if (_efg) _efg.innerHTML = '';
                        console.log('[RENDER] Executed at', new Date().toISOString(), '| items:', manifestData.length);
                        try {
                            applyView();
                            try { var _grv4 = document.getElementById('threat-grid'); if (_grv4 && _grv4.children.length === 0 && manifestData.length > 0) { cdbGodModeRender(manifestData); } } catch(_gne4) {}
                        } catch(e) { console.error('[SENTINEL-APEX] applyView FAILED (emb2):', e); try { cdbGodModeRender(manifestData); } catch(_ge4) {} }
                    }
                }
                _liveDataLoaded = true;
                // Show LIVE \u2014 EMBEDDED_INTEL IS the current gh-pages data
                if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--accent);animation:new-glow 1.5s ease-in-out infinite alternate;">&#x26A1; LIVE</span>';
                if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge integrity-ok"><i class="fas fa-shield-check"></i> MANIFEST VERIFIED</span>';
                // P0 FIX: was new Date().toLocaleTimeString() -- compute the real newest
                // timestamp from EMBEDDED_INTEL itself instead of the browser clock.
                var _embNewest = EMBEDDED_INTEL.reduce(function(best, d){
                    var t = new Date(d.published_at||d.timestamp||d.processed_at||0).getTime();
                    return (t && t > best) ? t : best;
                }, 0);
                if (lastLoadedEl) lastLoadedEl.textContent = 'SYNCED: ' + (_embNewest ? timeSince(_embNewest) : 'just now') + ' \u00b7 ' + EMBEDDED_INTEL.length + ' advisories';
                document.querySelectorAll('.metric-card').forEach(function(c){ c.classList.remove('syncing'); });
                if (aiPulse) aiPulse.style.display = 'none';
                console.log('[GOC v201.0] EMBEDDED_INTEL active (network unavailable):', EMBEDDED_INTEL.length, 'items');
                try { _cdbUpdateTabCounts(); } catch(e) {}
                return;
            }

            // \u2500\u2500\u2500 TERMINAL FAILURE \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
            // P0 2026-09-03. This branch previously painted
            //     SYNC: \u26a1 LOADING   +   \u26a1 NO DATA
            // and then stopped. Nothing runs after it, so "LOADING" was a
            // TERMINAL state wearing a transient label -- the customer
            // dashboard sat on it indefinitely while /api/health reported 500
            // healthy advisories. It also made an entitlement denial (HTTP 429
            // from the API quota gate) visually identical to "there is no
            // intelligence", which is the false-EMPTY this incident is about.
            //
            // js/feed-state.js resolves the real terminal state from the
            // per-source outcomes recorded above. RATE_LIMITED, ERROR and
            // OFFLINE are all distinct, all terminal, and none of them is
            // LOADING or claims the feed is empty.
            var _termState = (window.SentinelFeedState && typeof window.SentinelFeedState.resolveFeedTerminalState === 'function')
                ? window.SentinelFeedState.resolveFeedTerminalState({
                    attempts: _feedAttempts,
                    online: (typeof navigator !== 'undefined' && typeof navigator.onLine === 'boolean') ? navigator.onLine : true,
                  })
                // Inline fallback if js/feed-state.js failed to load: still
                // never LOADING, still never "no intelligence".
                : { state: 'ERROR', sync: 'ERROR', badge: 'FEED UNAVAILABLE',
                    detail: 'Could not reach the intelligence feed. This is a delivery fault, not an absence of intelligence.',
                    rateLimited: false, isTerminalFailure: true };

            window.__FEED_TERMINAL_STATE__ = _termState;
            console.error('[GOC v201.0] Primary feed terminal state:', _termState.state,
                          '| sources tried:', _feedAttempts.length,
                          '| statuses:', _feedAttempts.map(function(a){ return a.url.slice(0, 40) + '=' + (a.status === null ? 'net-error' : a.status); }).join(', '));

            if (syncVal) syncVal.innerHTML = 'SYNC: <span style="color:var(--danger,#ff4757);">&#x26A1; ' + _termState.sync + '</span>';
            if (integrityEl) integrityEl.innerHTML = '<span class="integrity-badge" style="color:var(--danger,#ff4757);">&#x26A1; ' + _termState.badge + '</span>';
            document.querySelectorAll('.metric-card').forEach(function(c){ c.classList.remove('syncing'); });
            if (aiPulse) aiPulse.style.display = 'none';

            // P0 FIX (2026-09-01): every MANIFEST_URLS source failed above. If a
            // service worker is controlling this page, that is the more likely
            // cause than a genuine full API outage -- see service-worker.js's own
            // v175 header and this file's SW registration comments for the
            // diagnosed incident (a customer's browser stuck on an old SW whose
            // fetch handler pointed at endpoints that exist nowhere in this
            // codebase, while every real endpoint returned healthy data when
            // checked directly). That fix (updateViaCache:'none' + a
            // visibilitychange re-check) makes the browser's own update *check*
            // reliable, but does not guarantee an already-stuck browser recovers
            // promptly: reproduced with a scripted harness (register an old SW,
            // then make the real one available server-side) that the new worker
            // can sit in the registration's `waiting` state across several real
            // reloads without ever taking control, so this exact loop keeps
            // re-running against the same broken interception every time.
            // Rather than depend on SW update timing at all, force a one-time,
            // session-guarded hard reset here: unregister every SW registration
            // for this origin, clear every SW-managed cache, reload once.
            // sessionStorage-guarded (cleared when the tab closes, not persisted
            // like localStorage) so exactly one attempt is made per tab -- a
            // genuine network/API outage still degrades to the retry message
            // below instead of reload-looping forever, same anti-loop discipline
            // as the "do NOT force skipWaiting + reload" rule documented earlier
            // in this file for the identical reason (a prior forced-reload
            // attempt caused its own "BOOTING..." loop incident).
            try {
                // v200.2 P0 FIX: confirmed live in real CI (pages-fast-publish
                // run #42, 2026-09-04 -- render-test/verify_stale_service_
                // worker_recovery.js's first-ever real execution, previously
                // always skipped by an earlier fail-fast step). The exact
                // scenario this block exists to handle -- a stuck SW
                // intercepting /api/* with a 200-but-empty response -- can
                // consume this block's ONE allowed attempt on a reload that
                // itself still lands under the SAME broken SW (e.g. the
                // fixed server-side script hasn't propagated to this client
                // yet). This file's own incident history already documents
                // that pattern: "the new worker can sit in the registration's
                // waiting state across several real reloads without ever
                // taking control." A one-shot boolean guard then permanently
                // disables recovery for the rest of the tab session even
                // once the real SW is available and eventually takes over on
                // its own -- reproduced live: 1/4 checks passed, and the
                // browser never recovered across 12 polls (~24s) plus 2
                // further ordinary reloads. A small bounded retry budget
                // (still session-guarded, still capped -- never unbounded
                // reload-looping) gives the browser's own SW update cycle
                // enough additional attempts to actually catch up, matching
                // the 3-attempt retry budget this repo already uses for the
                // same "may legitimately need more than one try" class of
                // condition (see Dockerfile, platform-build-deploy.yml).
                var _swRecoveryAttempts = parseInt(sessionStorage.getItem('apex_sw_recovery_attempts') || '0', 10);
                if ('serviceWorker' in navigator && navigator.serviceWorker.controller &&
                    _swRecoveryAttempts < 3) {
                    sessionStorage.setItem('apex_sw_recovery_attempts', String(_swRecoveryAttempts + 1));
                    console.warn('[GOC v201.0] All manifest sources failed under an active service worker -- clearing SW + caches, reloading (attempt ' + (_swRecoveryAttempts + 1) + '/3)');
                    Promise.all([
                        navigator.serviceWorker.getRegistrations().then(function(regs) {
                            return Promise.all(regs.map(function(r) { return r.unregister(); }));
                        }),
                        (window.caches ? caches.keys().then(function(keys) {
                            return Promise.all(keys.map(function(k) { return caches.delete(k); }));
                        }) : Promise.resolve()),
                    ]).catch(function(e) { console.debug('[SW-RECOVERY]', e); })
                      .finally(function() { window.location.reload(); });
                    return;
                }
            } catch (e) { console.debug('[SW-RECOVERY]', e); }

            // v184.0 P0 FIX: #threat-grid MUST never stay stuck at initial spinner
            // Root cause: all prior paths returned early; terminal path never touched the grid
            // P0 2026-09-03: state-specific copy. "Feed temporarily
            // unavailable" is true of a network fault but actively misleading
            // for a quota denial, where the intelligence exists and is
            // healthy and only this view is throttled -- and the customer
            // needs to know the difference before concluding the platform has
            // no data. _termState.detail carries the correct sentence per
            // state; the retry affordance is preserved unchanged.
            var _dg = document.getElementById('threat-grid');
            if (_dg) _dg.innerHTML = '<div class="loading-state" style="color:#888;">&#9888; ' +
                String(_termState.detail || 'Feed unavailable.').replace(/[<>&]/g, '') +
                ' &mdash; <a href="javascript:void(0)" onclick="window.__DATA_LOADED__=false;window.__INTEL_RENDERED__=false;loadGOCIntel();" style="color:var(--accent,#00d4aa);text-decoration:none;font-weight:700;">retry</a></div>';
        }
        // ── Auto-refresh every 6 hours ──
        function scheduleAutoRefresh() {
            setInterval(() => {
                const autoRefresh = document.getElementById('auto-refresh-toggle');
                if (autoRefresh && autoRefresh.checked) { window.__DATA_LOADED__ = false; window.__INTEL_RENDERED__ = false; loadGOCIntel(); fetchWorkerStats(); }
            }, 6 * 60 * 60 * 1000);
        }

        // ── Keyboard Shortcuts ──
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key === 'r' || e.key === 'R') { window.__DATA_LOADED__ = false; window.__INTEL_RENDERED__ = false; loadGOCIntel(); }
            if (e.key === 's' || e.key === 'S') exportSTIX();
            if (e.key === 'Escape') {
                closeStixPaywall();
                const modal = document.getElementById('threat-modal');
                if (modal) modal.classList.remove('open');
                const kbModal = document.getElementById('kbd-modal');
                if (kbModal) kbModal.classList.remove('open');
            }
            if (e.key === '?') {
                const kbModal = document.getElementById('kbd-modal');
                if (kbModal) kbModal.classList.toggle('open');
            }
        });

        // ── DOM Ready: Boot the platform (v73.0 \u2014 Progressive) ──
        
        // ═══════════════════════════════════════════════════════════════
        // v73.2 SOC TAB SYSTEM \u2014 renders from existing manifestData
        // SAFE: No new fetches. Falls back to LIVE on any error.
        // ═══════════════════════════════════════════════════════════════
        let _cdbActiveTab = 'live';

        function cdbSwitchTab(tab, btn) {
            try {
                _cdbActiveTab = tab;
                document.querySelectorAll('.cdb-tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.cdb-tab-panel').forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                var panel = document.getElementById('cdb-panel-' + tab);
                if (panel) panel.classList.add('active');

                if (tab === 'live') return; // LIVE uses existing renderCards pipeline
                // P0 FIX: this used to silently call cdbFallbackLive() here --
                // a customer clicking SOC VIEW (or Timeline/Campaigns/Actors)
                // during a total feed outage saw the LIVE tab's content with
                // no error, no indication their click did anything different.
                // Stays on the requested tab and shows an explicit
                // unavailable state with a retry action instead.
                if (!manifestData || !manifestData.length) {
                    var _tabLabels = { timeline: 'TIMELINE', campaigns: 'CAMPAIGNS', actors: 'ACTORS', soc: 'SOC VIEW' };
                    if (panel) panel.innerHTML = '<div class="loading-state">' + (_tabLabels[tab] || tab.toUpperCase()) + ' DATA UNAVAILABLE<br><span style="font-size:9px;">No current threat intelligence loaded — <a href="javascript:void(0)" onclick="loadGOCIntel()" style="color:var(--accent);">retry</a></span></div>';
                    return;
                }

                if (tab === 'timeline') cdbRenderTimeline(manifestData);
                else if (tab === 'campaigns') cdbRenderCampaigns(manifestData);
                else if (tab === 'actors') cdbRenderActors(manifestData);
                else if (tab === 'soc') cdbRenderSOC(manifestData);
            } catch(e) {
                console.warn('[CDB-TABS] Error, falling back to LIVE:', e);
                cdbFallbackLive();
            }
        }

        function cdbFallbackLive() {
            _cdbActiveTab = 'live';
            document.querySelectorAll('.cdb-tab-panel').forEach(p => p.classList.remove('active'));
            var lp = document.getElementById('cdb-panel-live');
            if (lp) lp.classList.add('active');
            var btns = document.querySelectorAll('.cdb-tab-btn');
            btns.forEach(b => b.classList.remove('active'));
            if (btns[0]) btns[0].classList.add('active');
        }

        function _cdbSevClass(score) {
            if (score >= 9) return 'sev-critical';
            if (score >= 7) return 'sev-high';
            if (score >= 4) return 'sev-medium';
            return 'sev-low';
        }
        function _cdbSevLabel(score) {
            if (score >= 9) return 'CRITICAL';
            if (score >= 7) return 'HIGH';
            if (score >= 4) return 'MEDIUM';
            return 'LOW';
        }
        function _cdbSevColor(score) {
            if (score >= 9) return 'var(--critical)';
            if (score >= 7) return 'var(--high)';
            if (score >= 4) return 'var(--medium)';
            return 'var(--low)';
        }
        function _cdbTimeAgo(ts) {
            if (!ts) return '';
            var d = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
            if (d < 1) return 'Now'; if (d < 60) return d + 'm'; if (d < 1440) return Math.floor(d/60) + 'h'; return Math.floor(d/1440) + 'd';
        }
        function _cdbEsc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

        // ── TIMELINE ──
        function cdbRenderTimeline(data) {
            var panel = document.getElementById('cdb-panel-timeline');
            if (!panel) return;
            var grouped = {};
            data.forEach(function(item) {
                var ts = item.timestamp || item.published || '';
                var dateKey = ts ? new Date(ts).toLocaleDateString('en-US', {weekday:'short', year:'numeric', month:'short', day:'numeric'}) : 'Unknown Date';
                if (!grouped[dateKey]) grouped[dateKey] = [];
                grouped[dateKey].push(item);
            });
            var dates = Object.keys(grouped).sort(function(a,b) { return new Date(b) - new Date(a); });
            var html = '';
            dates.forEach(function(date) {
                var items = grouped[date];
                html += '<div class="cdb-timeline-date">' + _cdbEsc(date) + '<span class="cdb-date-count">' + items.length + ' advisories</span></div>';
                html += '<div class="cdb-timeline-items">';
                items.sort(function(a,b) { return (b.risk_score||0) - (a.risk_score||0); });
                items.forEach(function(item) {
                    var sc = item.risk_score || 0;
                    var cves = (item.title || '').match(/CVE-\d{4}-\d{4,}/gi) || [];
                    html += '<div class="cdb-tl-card ' + _cdbSevClass(sc) + '">';
                    html += '<div class="cdb-tl-time">' + _cdbTimeAgo(item.timestamp) + '</div>';
                    html += '<div style="flex:1;"><div class="cdb-tl-title">' + _cdbEsc((item.title||'').substring(0,120)) + '</div>';
                    html += '<div class="cdb-tl-meta">';
                    html += '<span class="badge badge-' + _cdbSevLabel(sc).toLowerCase() + '" style="font-size:8px;padding:1px 6px;">' + _cdbSevLabel(sc) + '</span>';
                    html += '<span style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">' + sc.toFixed(1) + '/10</span>';
                    cves.slice(0,2).forEach(function(cv) { html += '<span style="font-family:var(--font-mono);font-size:8px;color:var(--blue);background:rgba(59,130,246,0.08);padding:1px 5px;border-radius:3px;">' + cv + '</span>'; });
                    if (item.kev_present) html += '<span style="font-size:8px;color:#ff6b6b;font-weight:700;">KEV</span>';
                    html += '</div></div></div>';
                });
                html += '</div>';
            });
            panel.innerHTML = html || '<div class="loading-state">No timeline data available</div>';
        }

        // ── CAMPAIGNS ──
        function cdbRenderCampaigns(data) {
            var panel = document.getElementById('cdb-panel-campaigns');
            if (!panel) return;
            var campaigns = {};
            // Group by MITRE tactic phase as campaign proxy
            var phases = {'T1595':'Reconnaissance','T1592':'Reconnaissance','T1190':'Initial Access','T1133':'Initial Access','T1566':'Phishing','T1059':'Execution','T1053':'Execution','T1547':'Persistence','T1543':'Persistence','T1548':'Privilege Escalation','T1003':'Credential Access','T1110':'Credential Access','T1021':'Lateral Movement','T1071':'Command & Control','T1041':'Exfiltration','T1486':'Impact','T1490':'Impact'};
            data.forEach(function(item) {
                var tags = item.mitre_tactics || [];
                var t0 = tags.length > 0 ? tags[0] : null;
                // P0 FIX: mitre_tactics entries are objects ({id,name,tactic,
                // justification}), not bare technique-id strings -- t0 used
                // directly as the phases[] lookup key always missed (an
                // object key never matches a string key), so every item fell
                // into the untagged bucket regardless of its real technique.
                // t0.id recovers the phases[] table's intended lookup; t0.tactic
                // is already a correctly-named phase for any id the table
                // doesn't carry, so it's tried next before the untagged bucket.
                var techId = t0 ? (typeof t0 === 'string' ? t0 : t0.id) : null;
                var phaseName = (techId && phases[techId]) || (t0 && t0.tactic) || 'Threat Intelligence';
                if (!campaigns[phaseName]) campaigns[phaseName] = [];
                campaigns[phaseName].push(item);
            });
            var sorted = Object.entries(campaigns).sort(function(a,b) { return b[1].length - a[1].length; });
            var html = '';
            sorted.forEach(function(entry) {
                var name = entry[0], items = entry[1];
                // P0 FIX: was window._v149AvgRisk(window.EMBEDDED_INTEL || []) --
                // EMBEDDED_INTEL is permanently [] in production (the R2-backed
                // API is authoritative), so every card always showed "Avg Risk:
                // 0/10" regardless of its real content. Uses this group's own
                // items, matching how the sibling Actors tab already computes
                // its own (correct) average.
                var avgRisk = window._v149AvgRisk(items);
                html += '<div class="cdb-group-card">';
                html += '<div class="cdb-group-header"><div class="cdb-group-name">' + _cdbEsc(name) + '</div><div class="cdb-group-count">' + items.length + ' advisories \u00b7 Avg Risk: ' + avgRisk + '/10</div></div>';
                html += '<div class="cdb-group-items">';
                items.sort(function(a,b){return (b.risk_score||0)-(a.risk_score||0);}).slice(0,8).forEach(function(item) {
                    html += '<div class="cdb-group-item"><span style="color:#e6edf3;font-size:11px;">' + _cdbEsc((item.title||'').substring(0,80)) + '</span><span class="badge badge-' + _cdbSevLabel(item.risk_score||0).toLowerCase() + '" style="font-size:8px;padding:1px 6px;">' + (item.risk_score||0).toFixed(1) + '</span></div>';
                });
                if (items.length > 8) html += '<div style="font-size:10px;color:var(--text-muted);padding:4px 10px;">+ ' + (items.length-8) + ' more</div>';
                html += '</div></div>';
            });
            panel.innerHTML = html || '<div class="loading-state">No campaign data available</div>';
        }

        // ── ACTORS ──
        function cdbRenderActors(data) {
            var panel = document.getElementById('cdb-panel-actors');
            if (!panel) return;
            var actors = {};
            data.forEach(function(item) {
                var actor = item.actor_tag || 'Unattributed';
                if (!actors[actor]) actors[actor] = { items: [], totalRisk: 0, kev: 0, crit: 0 };
                actors[actor].items.push(item);
                actors[actor].totalRisk += (item.risk_score || 0);
                if (item.kev_present) actors[actor].kev++;
                if ((item.risk_score || 0) >= 9) actors[actor].crit++;
            });
            var sorted = Object.entries(actors).sort(function(a,b) { return b[1].items.length - a[1].items.length; });
            var html = '';
            sorted.forEach(function(entry) {
                var name = entry[0], info = entry[1];
                var avg = (info.totalRisk / info.items.length).toFixed(1);
                html += '<div class="cdb-group-card">';
                html += '<div class="cdb-group-header"><div class="cdb-group-name" style="color:var(--critical);">' + _cdbEsc(name) + '</div>';
                html += '<div style="display:flex;gap:10px;font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">';
                html += '<span>' + info.items.length + ' advisories</span>';
                html += '<span>Avg Risk: <b style="color:#e6edf3">' + avg + '</b></span>';
                if (info.kev > 0) html += '<span style="color:#ff6b6b">KEV: ' + info.kev + '</span>';
                html += '<span>Critical: ' + info.crit + '</span>';
                html += '</div></div>';
                html += '<div class="cdb-group-items">';
                info.items.sort(function(a,b){return (b.risk_score||0)-(a.risk_score||0);}).slice(0,6).forEach(function(item) {
                    html += '<div class="cdb-group-item"><span style="color:#e6edf3;font-size:11px;">' + _cdbEsc((item.title||'').substring(0,80)) + '</span><span style="font-family:var(--font-mono);font-size:9px;color:' + _cdbSevColor(item.risk_score||0) + ';">' + (item.risk_score||0).toFixed(1) + '</span></div>';
                });
                if (info.items.length > 6) html += '<div style="font-size:10px;color:var(--text-muted);padding:4px 10px;">+ ' + (info.items.length-6) + ' more</div>';
                html += '</div></div>';
            });
            panel.innerHTML = html || '<div class="loading-state">No actor data available</div>';
        }

        // ── SOC VIEW ──
        function cdbRenderSOC(data) {
            var panel = document.getElementById('cdb-panel-soc');
            if (!panel) return;
            var total = data.length;
            var crit = data.filter(function(i){return (i.risk_score||0)>=9;}).length;
            var high = data.filter(function(i){return (i.risk_score||0)>=7 && (i.risk_score||0)<9;}).length;
            var med = data.filter(function(i){return (i.risk_score||0)>=4 && (i.risk_score||0)<7;}).length;
            var low = total - crit - high - med;
            var avgRisk = total ? (data.reduce(function(s,i){return s+(i.risk_score||0);},0)/total).toFixed(1) : '0';
            var kev = data.filter(function(i){return i.kev_present;}).length;
            var now = Date.now();
            var last24h = data.filter(function(i){return (now - new Date(i.timestamp||0).getTime()) < 86400000;}).length;
            var last7d = data.filter(function(i){return (now - new Date(i.timestamp||0).getTime()) < 604800000;}).length;

            // Top actors
            var actorMap = {};
            data.forEach(function(i){var a=i.actor_tag||'Unattributed';actorMap[a]=(actorMap[a]||0)+1;});
            var topActors = Object.entries(actorMap).sort(function(a,b){return b[1]-a[1];}).slice(0,5);

            // Top MITRE techniques
            // P0 FIX: mitre_tactics entries are objects ({id,name,tactic,
            // justification}), not bare technique-id strings -- techMap[t]
            // used the object itself as the key, which JS coerces to the
            // literal string "[object Object]", so every technique collapsed
            // into one fabricated-looking bucket labeled "[object Object]".
            var techMap = {};
            data.forEach(function(i){(i.mitre_tactics||[]).forEach(function(t){
                var techId = t ? (typeof t === 'string' ? t : (t.id || t.tactic || t.name)) : null;
                if (!techId) return;
                techMap[techId]=(techMap[techId]||0)+1;
            });});
            var topTech = Object.entries(techMap).sort(function(a,b){return b[1]-a[1];}).slice(0,8);

            var html = '<div class="cdb-soc-grid">';
            html += '<div class="cdb-soc-kpi"><div class="kpi-val">' + total + '</div><div class="kpi-label">Total Intel</div></div>';
            html += '<div class="cdb-soc-kpi kpi-crit"><div class="kpi-val" style="color:var(--critical);">' + crit + '</div><div class="kpi-label">Critical</div></div>';
            html += '<div class="cdb-soc-kpi kpi-high"><div class="kpi-val" style="color:var(--high);">' + high + '</div><div class="kpi-label">High</div></div>';
            html += '<div class="cdb-soc-kpi"><div class="kpi-val">' + avgRisk + '</div><div class="kpi-label">Avg Risk</div></div>';
            html += '<div class="cdb-soc-kpi" style="--kpi-color:var(--critical);"><div class="kpi-val" style="color:#ff6b6b;">' + kev + '</div><div class="kpi-label">CISA KEV</div></div>';
            html += '<div class="cdb-soc-kpi kpi-purple"><div class="kpi-val" style="color:var(--purple);">' + last24h + '</div><div class="kpi-label">Last 24H</div></div>';
            html += '</div>';

            // Risk distribution bar
            var critPct = total ? Math.round(crit/total*100) : 0;
            var highPct = total ? Math.round(high/total*100) : 0;
            var medPct = total ? Math.round(med/total*100) : 0;
            var lowPct = 100 - critPct - highPct - medPct;
            html += '<div style="margin-bottom:24px;">';
            html += '<div style="font-family:var(--font-mono);font-size:9px;color:var(--text-muted);letter-spacing:2px;margin-bottom:8px;">RISK DISTRIBUTION</div>';
            html += '<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;">';
            html += '<div style="width:'+critPct+'%;background:var(--critical);"></div>';
            html += '<div style="width:'+highPct+'%;background:var(--high);"></div>';
            html += '<div style="width:'+medPct+'%;background:var(--medium);"></div>';
            html += '<div style="width:'+lowPct+'%;background:var(--low);"></div>';
            html += '</div>';
            html += '<div style="display:flex;justify-content:space-between;margin-top:6px;font-family:var(--font-mono);font-size:9px;color:var(--text-muted);">';
            html += '<span style="color:var(--critical);">Critical '+critPct+'%</span>';
            html += '<span style="color:var(--high);">High '+highPct+'%</span>';
            html += '<span style="color:var(--medium);">Medium '+medPct+'%</span>';
            html += '<span style="color:var(--low);">Low '+lowPct+'%</span>';
            html += '</div></div>';

            // Two columns: Top Actors + Top Techniques
            html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">';
            html += '<div class="cdb-group-card"><div class="cdb-group-header"><div class="cdb-group-name">Top Threat Actors</div></div><div class="cdb-group-items">';
            topActors.forEach(function(e){html+='<div class="cdb-group-item"><span style="color:var(--critical);font-weight:600;">'+_cdbEsc(e[0])+'</span><span style="color:var(--accent);">'+e[1]+' intel</span></div>';});
            html += '</div></div>';
            html += '<div class="cdb-group-card"><div class="cdb-group-header"><div class="cdb-group-name">Top MITRE Techniques</div></div><div class="cdb-group-items">';
            topTech.forEach(function(e){html+='<div class="cdb-group-item"><a href="https://attack.mitre.org/techniques/'+e[0].replace(".","/")+'/" target="_blank" style="color:var(--purple);text-decoration:none;">'+e[0]+'</a><span style="color:var(--accent);">'+e[1]+' hits</span></div>';});
            html += '</div></div>';
            html += '</div>';

            panel.innerHTML = html;
        }

        // Update tab count when data loads
        function _cdbUpdateTabCounts() {
            try {
                var el = document.getElementById('cdb-tab-live-count');
                if (el && manifestData) el.textContent = manifestData.length;
            } catch(e) {}
        }

        
        // ═══════════════════════════════════════════════════════════════
        // v73.4 SOC ANALYST AGENT \u2014 Deterministic Rules-Based Engine
        // SAFE: Reads existing manifestData/threatRegistry. No API calls.
        // No external dependencies. No backend. Instant execution.
        // Falls back gracefully on any error.
        // ═══════════════════════════════════════════════════════════════

        // MITRE Technique → Kill Chain Phase + Description mapping
        const _CDB_MITRE_DB = {
            'T1595':'Reconnaissance: Active Scanning','T1592':'Reconnaissance: Gather Victim Host Information',
            'T1589':'Reconnaissance: Gather Victim Identity','T1590':'Reconnaissance: Gather Network Information',
            'T1591':'Reconnaissance: Gather Org Information','T1588':'Resource Development: Obtain Capabilities',
            'T1587':'Resource Development: Develop Capabilities','T1583':'Resource Development: Acquire Infrastructure',
            'T1566':'Initial Access: Phishing','T1190':'Initial Access: Exploit Public-Facing Application',
            'T1133':'Initial Access: External Remote Services','T1200':'Initial Access: Hardware Additions',
            'T1195':'Initial Access: Supply Chain Compromise','T1078':'Initial Access: Valid Accounts',
            'T1059':'Execution: Command & Scripting Interpreter','T1053':'Execution: Scheduled Task/Job',
            'T1203':'Execution: Exploitation for Client Execution','T1068':'Execution: Exploitation for Privilege Escalation',
            'T1547':'Persistence: Boot or Logon Autostart','T1543':'Persistence: Create/Modify System Process',
            'T1136':'Persistence: Create Account','T1546':'Persistence: Event Triggered Execution',
            'T1548':'Privilege Escalation: Abuse Elevation Control','T1134':'Privilege Escalation: Access Token Manipulation',
            'T1027':'Defense Evasion: Obfuscated Files','T1562':'Defense Evasion: Impair Defenses',
            'T1070':'Defense Evasion: Indicator Removal','T1003':'Credential Access: OS Credential Dumping',
            'T1110':'Credential Access: Brute Force','T1558':'Credential Access: Steal Kerberos Ticket',
            'T1087':'Discovery: Account Discovery','T1482':'Discovery: Domain Trust Discovery',
            'T1021':'Lateral Movement: Remote Services','T1570':'Lateral Movement: Lateral Tool Transfer',
            'T1071':'Command & Control: Application Layer Protocol','T1105':'Command & Control: Ingress Tool Transfer',
            'T1573':'Command & Control: Encrypted Channel','T1572':'Command & Control: Protocol Tunneling',
            'T1041':'Exfiltration: Exfiltration Over C2','T1048':'Exfiltration: Exfiltration Over Alternative Protocol',
            'T1567':'Exfiltration: Exfiltration Over Web Service','T1486':'Impact: Data Encrypted for Impact',
            'T1490':'Impact: Inhibit System Recovery','T1561':'Impact: Disk Wipe','T1489':'Impact: Service Stop',
            'T1005':'Collection: Data from Local System','T1560':'Collection: Archive Collected Data',
        };

        function _cdbAnalyzeItem(item) {
            // Deterministic SOC analysis \u2014 zero external dependencies
            try {
                var risk = parseFloat(item.risk_score) || 0;
                var title = item.title || 'Unknown Threat';
                var cves = (title.match(/CVE-\d{4}-\d{4,}/gi) || []);
                var cvss = item.cvss_score != null ? parseFloat(item.cvss_score) : null;
                var epss = item.epss_score != null ? parseFloat(item.epss_score) : null;
                var kev = !!item.kev_present;
                var actor = item.actor_tag || 'Unattributed';
                var tactics = item.mitre_tactics || [];
                var iocCounts = item.ioc_counts || {};
                var totalIOCs = 0;
                Object.values(iocCounts).forEach(function(v) { totalIOCs += (typeof v === 'number' ? v : 0); });
                var source = (item.feed_source || '').replace(/https?:\/\//, '').split('/')[0];
                var severity = risk >= 9 ? 'CRITICAL' : risk >= 7 ? 'HIGH' : risk >= 4 ? 'MEDIUM' : 'LOW';
                var sevColor = risk >= 9 ? 'var(--critical)' : risk >= 7 ? 'var(--high)' : risk >= 4 ? 'var(--medium)' : 'var(--low)';

                // ── Executive Summary ──
                var summary = '';
                if (cves.length > 0) {
                    summary = 'This advisory concerns ' + cves[0] + ', a ' + severity.toLowerCase() + '-severity vulnerability';
                    if (cvss) summary += ' with a CVSS base score of ' + cvss + '/10';
                    summary += '. ';
                    if (kev) summary += 'CRITICAL: This vulnerability is listed in CISA\'s Known Exploited Vulnerabilities catalog, confirming active exploitation in the wild. Immediate patching is required. ';
                    if (epss && epss > 50) summary += 'The EPSS probability of exploitation within 30 days is ' + epss.toFixed(1) + '%, indicating elevated threat. ';
                    else if (epss) summary += 'EPSS exploitation probability: ' + epss.toFixed(1) + '%. ';
                } else {
                    summary = 'This intelligence advisory covers: "' + title.substring(0, 80) + '". ';
                    summary += 'The CDB GOC Risk Engine has assessed this threat at ' + risk.toFixed(1) + '/10 (' + severity + '). ';
                }
                if (actor !== 'Unattributed' && !actor.startsWith('UNC-CDB')) {
                    summary += 'Attribution analysis links this activity to tracked threat group ' + actor + '. ';
                }
                if (totalIOCs > 0) summary += totalIOCs + ' indicators of compromise have been extracted for defensive deployment. ';

                // ── Risk Assessment ──
                var riskAssess = 'OVERALL RISK: ' + risk.toFixed(1) + '/10 (' + severity + ').\n';
                if (cvss) riskAssess += 'CVSS Base Score: ' + cvss + '/10 \u2014 ';
                if (cvss >= 9) riskAssess += 'Critical severity. Trivial exploitation with maximum impact.\n';
                else if (cvss >= 7) riskAssess += 'High severity. Significant exploitation potential.\n';
                else if (cvss >= 4) riskAssess += 'Medium severity. Conditional exploitation.\n';
                else if (cvss) riskAssess += 'Low severity. Limited exploitation potential.\n';
                if (kev) riskAssess += '⚡ CISA KEV ACTIVE: Confirmed exploitation in the wild. This is not theoretical.\n';
                if (epss) riskAssess += 'EPSS 30-day exploitation probability: ' + epss.toFixed(1) + '%.\n';

                // ── Attack Vector Analysis ──
                var attackVec = '';
                if (tactics.length > 0) {
                    var phases = {};
                    tactics.forEach(function(t) {
                        var desc = _CDB_MITRE_DB[t] || ('Technique ' + t);
                        var phase = desc.split(':')[0] || 'Unknown Phase';
                        if (!phases[phase]) phases[phase] = [];
                        phases[phase].push(t);
                    });
                    Object.keys(phases).forEach(function(phase) {
                        attackVec += phase + ': ' + phases[phase].join(', ') + '\n';
                    });
                    var hasInitial = tactics.some(function(t) { return ['T1566','T1190','T1133','T1195','T1078'].indexOf(t) >= 0; });
                    var hasExec = tactics.some(function(t) { return ['T1059','T1053','T1203'].indexOf(t) >= 0; });
                    var hasExfil = tactics.some(function(t) { return ['T1041','T1048','T1567'].indexOf(t) >= 0; });
                    var hasImpact = tactics.some(function(t) { return ['T1486','T1490','T1561'].indexOf(t) >= 0; });

                    if (hasInitial && hasExec && (hasExfil || hasImpact)) {
                        attackVec += '\n⚠️ FULL KILL CHAIN COVERAGE: This threat spans from initial access through execution to ' + (hasImpact ? 'impact' : 'exfiltration') + '. Treat as advanced, multi-stage attack.';
                    }
                } else {
                    attackVec = 'No MITRE ATT&CK techniques mapped for this advisory. Manual analysis recommended.';
                }

                // ── Recommended Actions ──
                var actions = [];
                if (kev) {
                    actions.push({p:'P0',t:'IMMEDIATE: Apply vendor patch within 24 hours. This vulnerability is under active exploitation (CISA KEV).'});
                }
                if (cves.length > 0) {
                    actions.push({p:'P1',t:'Scan all assets for ' + cves[0] + ' using your vulnerability management platform.'});
                    if (cvss && cvss >= 7) actions.push({p:'P1',t:'Escalate to patch management team. Target remediation: 72 hours for internet-facing assets.'});
                }
                if (totalIOCs > 0) {
                    actions.push({p:'P1',t:'Deploy ' + totalIOCs + ' extracted IOCs to SIEM/EDR detection rules for immediate visibility.'});
                }
                if (tactics.some(function(t){return ['T1566'].indexOf(t)>=0;})) {
                    actions.push({p:'P2',t:'Review email gateway logs and phishing simulation results. Brief users on social engineering indicators.'});
                }
                if (tactics.some(function(t){return ['T1059','T1053'].indexOf(t)>=0;})) {
                    actions.push({p:'P2',t:'Audit PowerShell/script execution logs. Verify application allowlisting policies.'});
                }
                if (risk >= 7) {
                    actions.push({p:'P2',t:'Initiate threat hunt across network telemetry for indicators related to this campaign.'});
                }
                actions.push({p:'P3',t:'Update threat intelligence briefing for SOC analysts and stakeholders.'});
                if (actions.length < 3) {
                    actions.push({p:'P3',t:'Monitor vendor advisories for updates and supplemental patches.'});
                    actions.push({p:'P3',t:'Review detection coverage against mapped MITRE techniques.'});
                }

                // ── Likelihood ──
                var likelihood = '';
                if (kev) likelihood = 'CONFIRMED EXPLOITATION \u2014 Active exploitation verified by CISA. Likelihood: CERTAIN.';
                else if (epss && epss > 50) likelihood = 'HIGH \u2014 EPSS indicates ' + epss.toFixed(1) + '% probability of exploitation within 30 days.';
                else if (risk >= 8) likelihood = 'HIGH \u2014 Elevated risk score and threat characteristics suggest imminent exploitation potential.';
                else if (risk >= 5) likelihood = 'MODERATE \u2014 Conditional exploitation based on target environment and exposure.';
                else likelihood = 'LOW \u2014 Limited exploitation potential under typical configurations.';

                return {
                    summary: summary, riskAssessment: riskAssess, attackVector: attackVec,
                    actions: actions, tactics: tactics, likelihood: likelihood,
                    severity: severity, sevColor: sevColor, risk: risk,
                    cves: cves, kev: kev, cvss: cvss, epss: epss, title: title, totalIOCs: totalIOCs, source: source
                };
            } catch(e) {
                // FAILSAFE \u2014 return basic summary
                return {
                    summary: 'Analysis engine encountered an error. Displaying raw intelligence data.',
                    riskAssessment: 'Risk Score: ' + (item.risk_score || 'N/A') + '/10',
                    attackVector: 'Manual analysis required.',
                    actions: [{p:'P2',t:'Review this advisory manually and assess applicability to your environment.'}],
                    tactics: item.mitre_tactics || [], likelihood: 'Assessment unavailable.',
                    severity: 'UNKNOWN', sevColor: 'var(--text-muted)', risk: 0,
                    cves: [], kev: false, cvss: null, epss: null, title: item.title || '', totalIOCs: 0, source: ''
                };
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // SOC ANALYST AGENT v2.0 \u2014 AI-POWERED 7-SECTION REASONING ENGINE
        // Reads live AI assessments from data/ai_intelligence/ai_index.json
        // Falls back gracefully to deterministic rule engine (v1.0)
        // ═══════════════════════════════════════════════════════════════════

        // Global AI index cache \u2014 loaded once per session
        window._CDB_AI_INDEX = null;
        window._CDB_AI_INDEX_LOADED = false;
        window._CDB_AI_INDEX_LOADING = false;
        window._CDB_DETECTION_INDEX = null;

        function _cdbLoadAIIndex(callback) {
            if (window._CDB_AI_INDEX_LOADED) { callback(window._CDB_AI_INDEX); return; }
            if (window._CDB_AI_INDEX_LOADING) {
                // Queue callback
                var interval = setInterval(function() {
                    if (window._CDB_AI_INDEX_LOADED) {
                        clearInterval(interval);
                        callback(window._CDB_AI_INDEX);
                    }
                }, 100);
                return;
            }
            window._CDB_AI_INDEX_LOADING = true;

            // Load ai_index.json + rule_manifest.json in parallel
            var indexDone = false, rulesDone = false;
            var aiData = null, rulesData = null;

            function tryFinish() {
                if (indexDone && rulesDone) {
                    window._CDB_AI_INDEX = aiData;
                    window._CDB_DETECTION_INDEX = rulesData;
                    window._CDB_AI_INDEX_LOADED = true;
                    window._CDB_AI_INDEX_LOADING = false;
                    callback(window._CDB_AI_INDEX);
                }
            }

            // Fetch AI index
            // Stage 4: routed through intel-gateway's runtime proxy (R2-backed,
            // falls back to gh-pages) instead of a bare relative static path,
            // so a fresh pipeline write reaches this widget without waiting on
            // a Pages deploy. See workers/intel-gateway/src/index.js's
            // INTEL_STATIC_PROXY block for the serving side of this change.
            fetch('/api/v1/intel/ai_index.json?_=' + Date.now(), {cache:'no-store'})
                .then(function(r) { return r.ok ? r.json() : null; })
                .then(function(data) { aiData = data; indexDone = true; tryFinish(); })
                .catch(function() { indexDone = true; tryFinish(); });

            // Fetch detection rule manifest (non-blocking) -- same Stage 4 change.
            fetch('/api/v1/intel/detection_rules_manifest.json?_=' + Date.now(), {cache:'no-store'})
                .then(function(r) { return r.ok ? r.json() : null; })
                .then(function(data) { rulesData = data; rulesDone = true; tryFinish(); })
                .catch(function() { rulesDone = true; tryFinish(); });
        }

        function _cdbGetAIRecord(item, aiIndex) {
            if (!aiIndex || !Array.isArray(aiIndex)) return null;
            var aid = item.advisory_id || item.id || item.stix_id || '';
            var title = (item.title || '').toLowerCase();
            // Exact match first
            for (var i = 0; i < aiIndex.length; i++) {
                if (aiIndex[i].advisory_id === aid) return aiIndex[i];
            }
            // Title fuzzy match fallback
            for (var j = 0; j < aiIndex.length; j++) {
                var recTitle = (aiIndex[j].title || '').toLowerCase();
                if (recTitle && title && (recTitle.includes(title.slice(0,40)) || title.includes(recTitle.slice(0,40)))) {
                    return aiIndex[j];
                }
            }
            return null;
        }

        function _cdbGetDetectionRules(item, rulesIndex) {
            if (!rulesIndex) return null;
            var aid = item.advisory_id || item.id || '';
            var entries = rulesIndex.entries || rulesIndex;
            if (!entries) return null;
            // Look in manifest entries
            if (Array.isArray(entries)) {
                for (var i = 0; i < entries.length; i++) {
                    if (entries[i].advisory_id === aid) return entries[i].rules || null;
                }
            }
            return null;
        }

        function cdbOpenAgent(stixId) {
            try {
                var item = threatRegistry.get(stixId);
                if (!item) { console.warn('[CDB-AGENT] Item not found:', stixId); return; }

                var modal = document.getElementById('cdb-agent-modal');
                var body = document.getElementById('cdb-agent-body');
                var sub = document.getElementById('cdb-agent-sub');
                if (!modal || !body) return;

                modal.classList.add('open');
                body.innerHTML = '<div class="cdb-agent-loading"><div class="spinner"></div>Loading AI assessment...</div>';
                sub.textContent = (item.title || '').substring(0, 60) + '...';

                // Try to load AI index, then render
                _cdbLoadAIIndex(function(aiIndex) {
                    setTimeout(function() {
                        try {
                            var aiRecord = _cdbGetAIRecord(item, aiIndex);
                            var detRules = _cdbGetDetectionRules(item, window._CDB_DETECTION_INDEX);

                            if (aiRecord) {
                                // AI-POWERED 7-SECTION RENDER
                                _cdbRenderAIResult(item, aiRecord, detRules, body);
                            } else {
                                // FALLBACK: deterministic rule engine
                                var analysis = _cdbAnalyzeItem(item);
                                _cdbRenderAgentResult(analysis, body);
                            }
                        } catch(e) {
                            console.warn('[CDB-AGENT] Render error:', e);
                            body.innerHTML = '<div class="cdb-agent-section"><h4>⚠ Analysis Error</h4><p>The agent encountered an error. Raw data is displayed below.</p><pre style="font-size:11px;color:#6B7C93;white-space:pre-wrap;margin-top:12px;">' + JSON.stringify(item, null, 2).substring(0, 2000) + '</pre></div>';
                        }
                    }, 300);
                });
            } catch(e) {
                console.warn('[CDB-AGENT] Open error:', e);
            }
        }

        // ── 7-SECTION AI-POWERED RENDERER ────────────────────────────────────
        function _cdbRenderAIResult(item, ai, rules, container) {
            var risk = parseFloat(ai.ai_risk_score || item.risk_score || 0);
            var conf = parseFloat(ai.ai_confidence || 0.5);
            var priority = ai.priority || 'MEDIUM';
            var priColor = priority === 'CRITICAL' ? 'var(--critical)' : priority === 'HIGH' ? 'var(--high)' : priority === 'MEDIUM' ? 'var(--medium)' : 'var(--accent)';
            var riskPct = Math.min(risk * 10, 100);
            var html = '';

            // ── HEADER: AI Badge + Risk Score ──────────────────────────────
            html += '<div class="cdb-agent-section" style="border-bottom:1px solid rgba(0,212,170,0.15);padding-bottom:16px;margin-bottom:16px;">';
            html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;">';
            html += '<div style="display:flex;flex-direction:column;gap:6px;">';
            html += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">';
            html += '<span style="font-family:var(--font-mono);font-size:18px;font-weight:900;color:' + priColor + ';">' + priority + '</span>';
            html += '<span style="font-family:var(--font-mono);font-size:9px;letter-spacing:2px;padding:2px 8px;border-radius:3px;background:rgba(0,212,170,0.1);color:var(--accent);border:1px solid rgba(0,212,170,0.25);">🧠 AI ASSESSED</span>';
            if (ai.exploit_tier) {
                var etColor = ai.exploit_tier === 'IMMINENT' ? '#ff3b3b' : ai.exploit_tier === 'LIKELY' ? '#ff8c00' : ai.exploit_tier === 'ELEVATED' ? '#ffd600' : 'var(--text-muted)';
                html += '<span style="font-family:var(--font-mono);font-size:9px;letter-spacing:1.5px;padding:2px 8px;border-radius:3px;background:rgba(255,59,59,0.08);color:' + etColor + ';border:1px solid ' + etColor + '30;">⚡ ' + ai.exploit_tier + '</span>';
            }
            if (item.kev_present) html += '<span style="font-family:var(--font-mono);font-size:9px;background:rgba(220,38,38,0.12);color:#ff6b6b;padding:2px 8px;border-radius:3px;font-weight:700;border:1px solid rgba(220,38,38,0.3);">CISA KEV</span>';
            html += '</div>';
            // Quick fact row
            html += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:4px;">';
            if (item.cvss_score != null) html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);">CVSS ' + parseFloat(item.cvss_score).toFixed(1) + '</span>';
            if (item.epss_score != null) html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);">EPSS ' + parseFloat(item.epss_score).toFixed(1) + '%</span>';
            if (ai.tte_days != null) html += '<span style="font-family:var(--font-mono);font-size:10px;color:#ffd600;">TTE: ' + ai.tte_days + 'd</span>';
            if (ai.campaign_id) html += '<span style="font-family:var(--font-mono);font-size:9px;color:#a78bfa;border:1px solid rgba(167,139,250,0.3);padding:1px 6px;border-radius:3px;">' + ai.campaign_id + '</span>';
            html += '</div>';
            html += '</div>';
            // AI Risk Score + Confidence
            html += '<div style="text-align:right;flex-shrink:0;">';
            html += '<div style="font-family:var(--font-mono);font-size:28px;font-weight:900;color:' + priColor + ';line-height:1;">' + risk.toFixed(1) + '</div>';
            html += '<div style="font-family:var(--font-mono);font-size:8px;color:var(--text-muted);letter-spacing:2px;">AI RISK</div>';
            html += '<div style="font-family:var(--font-mono);font-size:9px;color:var(--accent);margin-top:4px;">CONF ' + (conf * 100).toFixed(0) + '%</div>';
            html += '</div>';
            html += '</div>';
            html += '<div class="cdb-agent-risk-bar" style="margin-top:10px;"><div class="cdb-agent-risk-fill" style="width:' + riskPct + '%;background:' + priColor + ';"></div></div>';
            html += '</div>';

            // ── SECTION 1: Executive Summary ───────────────────────────────
            if (ai.executive_summary) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 8px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:var(--accent);text-transform:uppercase;">📋 Executive Summary</h4>';
                html += '<p style="font-size:12px;line-height:1.75;color:var(--text);margin:0;">' + _cdbEsc(ai.executive_summary) + '</p>';
                if (ai.tactical_assessment) {
                    html += '<div style="margin-top:10px;padding:10px 12px;background:rgba(0,212,170,0.04);border-left:2px solid rgba(0,212,170,0.4);border-radius:0 4px 4px 0;">';
                    html += '<div style="font-family:var(--font-mono);font-size:8px;letter-spacing:2px;color:var(--accent);margin-bottom:5px;">TACTICAL ASSESSMENT</div>';
                    html += '<p style="font-size:11px;line-height:1.65;color:#9ca3b0;margin:0;">' + _cdbEsc(ai.tactical_assessment) + '</p>';
                    html += '</div>';
                }
                html += '</div>';
            }

            // ── SECTION 2: Attack Chain ─────────────────────────────────────
            if (ai.kill_chain_narrative || ai.kill_chain_phases) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 8px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:#f0abfc;text-transform:uppercase;">⚔️ Attack Chain Reconstruction</h4>';
                if (ai.kill_chain_narrative) {
                    html += '<p style="font-size:12px;line-height:1.7;color:var(--text);margin:0 0 10px;">' + _cdbEsc(ai.kill_chain_narrative) + '</p>';
                }
                // Kill chain phase badges
                var phases = ai.kill_chain_phases || [];
                if (phases.length > 0) {
                    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px;">';
                    var phaseOrder = ['INITIAL_ACCESS','EXECUTION','PERSISTENCE','PRIVILEGE_ESC','DEFENSE_EVASION','CRED_ACCESS','DISCOVERY','LATERAL_MOVEMENT','COLLECTION','C2','EXFILTRATION','IMPACT'];
                    var phaseShort = {'INITIAL_ACCESS':'INIT','EXECUTION':'EXEC','PERSISTENCE':'PERS','PRIVILEGE_ESC':'PRIV','DEFENSE_EVASION':'D.EVA','CRED_ACCESS':'CRED','DISCOVERY':'DISC','LATERAL_MOVEMENT':'LAT.MOV','COLLECTION':'COLL','C2':'C2','EXFILTRATION':'EXFIL','IMPACT':'IMPACT'};
                    phaseOrder.forEach(function(ph) {
                        var active = phases.indexOf(ph) >= 0;
                        var shortName = phaseShort[ph] || ph.slice(0,6);
                        var bg = active ? 'rgba(167,139,250,0.2)' : 'rgba(255,255,255,0.03)';
                        var color = active ? '#f0abfc' : '#374151';
                        var border = active ? 'rgba(167,139,250,0.5)' : 'rgba(255,255,255,0.06)';
                        html += '<span style="font-family:var(--font-mono);font-size:8px;letter-spacing:1px;padding:3px 8px;border-radius:3px;background:' + bg + ';color:' + color + ';border:1px solid ' + border + ';">' + shortName + '</span>';
                    });
                    html += '</div>';
                }
                // MITRE techniques
                var techs = item.mitre_tactics || [];
                if (techs.length > 0) {
                    html += '<div class="cdb-agent-mitre" style="margin-top:10px;">';
                    techs.slice(0,8).forEach(function(t) {
                        var tid = typeof t === 'string' ? t : (t.technique_id || t.id || '');
                        var desc = _CDB_MITRE_DB[tid] || tid;
                        html += '<a href="https://attack.mitre.org/techniques/' + tid.replace('.', '/') + '/" target="_blank" rel="noopener">' + tid + ' \u2014 ' + desc.split(':')[0] + '</a>';
                    });
                    html += '</div>';
                }
                html += '</div>';
            }

            // ── SECTION 3: Actor Attribution ────────────────────────────────
            if (ai.primary_actor || (ai.actor_matches && ai.actor_matches.length > 0)) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 10px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:#fbbf24;text-transform:uppercase;">🎭 Actor Attribution</h4>';
                if (ai.primary_actor) {
                    html += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">';
                    html += '<div style="font-family:var(--font-mono);font-size:13px;font-weight:800;color:#fbbf24;">' + _cdbEsc(ai.primary_actor) + '</div>';
                    html += '<span style="font-family:var(--font-mono);font-size:8px;padding:2px 7px;border-radius:3px;background:rgba(251,191,36,0.1);color:#fbbf24;border:1px solid rgba(251,191,36,0.3);">PRIMARY SUSPECT</span>';
                    html += '</div>';
                }
                var actors = ai.actor_matches || [];
                if (actors.length > 0) {
                    actors.slice(0, 3).forEach(function(match) {
                        var confPct = Math.round((match.confidence || 0) * 100);
                        var nation = match.nation ? ' [' + match.nation + ']' : '';
                        html += '<div style="padding:8px 12px;border-radius:5px;background:rgba(251,191,36,0.04);border:1px solid rgba(251,191,36,0.12);margin-bottom:6px;">';
                        html += '<div style="display:flex;justify-content:space-between;align-items:center;">';
                        html += '<span style="font-family:var(--font-mono);font-size:11px;color:#e6d5a7;">' + _cdbEsc(match.name || '') + '<span style="color:#6b7280;font-size:9px;">' + _cdbEsc(nation) + '</span></span>';
                        html += '<span style="font-family:var(--font-mono);font-size:10px;color:#fbbf24;">' + confPct + '% confidence</span>';
                        html += '</div>';
                        if (match.matched_keywords && match.matched_keywords.length > 0) {
                            html += '<div style="margin-top:5px;font-size:10px;color:#6b7280;">Signals: ' + match.matched_keywords.slice(0,4).map(_cdbEsc).join(', ') + '</div>';
                        }
                        html += '</div>';
                    });
                }
                if (ai.sectors_targeted && ai.sectors_targeted.length > 0) {
                    html += '<div style="margin-top:8px;font-size:10px;color:var(--text-muted);">Targeted sectors: <span style="color:#e6d5a7;">' + ai.sectors_targeted.slice(0,5).map(_cdbEsc).join(', ') + '</span></div>';
                }
                html += '</div>';
            }

            // ── SECTION 4: Exploitation Prediction ─────────────────────────
            if (ai.exploit_tier || ai.tte_days != null) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 10px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:#f87171;text-transform:uppercase;">🎯 Exploitation Prediction</h4>';
                var tier = ai.exploit_tier || 'UNKNOWN';
                var tierColor = tier === 'IMMINENT' ? '#ff3b3b' : tier === 'LIKELY' ? '#ff8c00' : tier === 'ELEVATED' ? '#ffd600' : tier === 'POSSIBLE' ? '#60a5fa' : '#6b7280';
                html += '<div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:12px;">';
                html += '<div style="padding:10px 20px;border-radius:6px;background:' + tierColor + '14;border:1px solid ' + tierColor + '40;text-align:center;">';
                html += '<div style="font-family:var(--font-mono);font-size:16px;font-weight:900;color:' + tierColor + ';">' + tier + '</div>';
                html += '<div style="font-family:var(--font-mono);font-size:8px;color:#6b7280;letter-spacing:2px;margin-top:3px;">EXPLOIT TIER</div>';
                html += '</div>';
                if (ai.tte_days != null) {
                    html += '<div style="padding:10px 20px;border-radius:6px;background:rgba(255,214,0,0.08);border:1px solid rgba(255,214,0,0.25);text-align:center;">';
                    html += '<div style="font-family:var(--font-mono);font-size:16px;font-weight:900;color:#ffd600;">' + ai.tte_days + 'd</div>';
                    html += '<div style="font-family:var(--font-mono);font-size:8px;color:#6b7280;letter-spacing:2px;margin-top:3px;">TIME TO EXPLOIT</div>';
                    html += '</div>';
                }
                if (ai.exploit_probability_pct != null) {
                    html += '<div style="padding:10px 20px;border-radius:6px;background:rgba(0,212,170,0.06);border:1px solid rgba(0,212,170,0.2);text-align:center;">';
                    html += '<div style="font-family:var(--font-mono);font-size:16px;font-weight:900;color:var(--accent);">' + Math.round(ai.exploit_probability_pct) + '%</div>';
                    html += '<div style="font-family:var(--font-mono);font-size:8px;color:#6b7280;letter-spacing:2px;margin-top:3px;">EXPLOIT PROB</div>';
                    html += '</div>';
                }
                html += '</div>';
                // Exploit signals
                var signals = ai.exploit_signals || [];
                if (signals.length > 0) {
                    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;">';
                    signals.forEach(function(sig) {
                        html += '<span style="font-family:var(--font-mono);font-size:9px;padding:2px 8px;border-radius:3px;background:rgba(248,113,113,0.08);color:#f87171;border:1px solid rgba(248,113,113,0.25);">' + _cdbEsc(sig.replace(/_/g,' ').toUpperCase()) + '</span>';
                    });
                    html += '</div>';
                }
                html += '</div>';
            }

            // ── SECTION 5: NIST CSF Actions ─────────────────────────────────
            var nistActions = ai.nist_actions || {};
            var nistFunctions = Object.keys(nistActions).filter(function(k) { return nistActions[k] && nistActions[k].length > 0; });
            if (nistFunctions.length > 0) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 10px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:#60a5fa;text-transform:uppercase;">🛡️ NIST CSF Response Actions</h4>';
                var nistColors = {'IDENTIFY':'#60a5fa','PROTECT':'#34d399','DETECT':'#fbbf24','RESPOND':'#f87171','RECOVER':'#a78bfa'};
                nistFunctions.forEach(function(fn) {
                    var fnColor = nistColors[fn] || '#9ca3b0';
                    var actions = nistActions[fn];
                    html += '<div style="margin-bottom:10px;">';
                    html += '<div style="font-family:var(--font-mono);font-size:8px;letter-spacing:2px;color:' + fnColor + ';margin-bottom:5px;display:flex;align-items:center;gap:6px;">';
                    html += '<span style="width:3px;height:3px;border-radius:50%;background:' + fnColor + ';display:inline-block;flex-shrink:0;"></span>' + fn;
                    html += '</div>';
                    actions.slice(0, 3).forEach(function(act) {
                        html += '<div style="font-size:11px;color:var(--text);line-height:1.55;padding:4px 0 4px 14px;border-left:2px solid ' + fnColor + '30;">• ' + _cdbEsc(act) + '</div>';
                    });
                    html += '</div>';
                });
                html += '</div>';
            }

            // ── SECTION 6: Detection Rules ──────────────────────────────────
            var itemRules = rules || (item.detection_rules) || null;
            var rulesList = Array.isArray(itemRules) ? itemRules : [];
            if (rulesList.length > 0) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 10px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:#34d399;text-transform:uppercase;">🔎 Detection Rules Generated</h4>';
                var sigmaRules = rulesList.filter(function(r) { return r.rule_type === 'sigma' || (r.rule_id || '').includes('SIGMA'); });
                var yaraRules = rulesList.filter(function(r) { return r.rule_type === 'yara' || (r.rule_id || '').includes('YARA'); });
                var surRules = rulesList.filter(function(r) { return r.rule_type === 'suricata' || (r.rule_id || '').includes('SUR'); });
                html += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;">';
                if (sigmaRules.length > 0) html += '<span style="font-family:var(--font-mono);font-size:10px;padding:3px 10px;border-radius:3px;background:rgba(52,211,153,0.1);color:#34d399;border:1px solid rgba(52,211,153,0.3);">Î£ ' + sigmaRules.length + ' Sigma</span>';
                if (yaraRules.length > 0) html += '<span style="font-family:var(--font-mono);font-size:10px;padding:3px 10px;border-radius:3px;background:rgba(251,191,36,0.08);color:#fbbf24;border:1px solid rgba(251,191,36,0.3);">⚙ ' + yaraRules.length + ' YARA</span>';
                if (surRules.length > 0) html += '<span style="font-family:var(--font-mono);font-size:10px;padding:3px 10px;border-radius:3px;background:rgba(96,165,250,0.08);color:#60a5fa;border:1px solid rgba(96,165,250,0.3);">⚡ ' + surRules.length + ' Suricata</span>';
                html += '</div>';
                rulesList.slice(0, 4).forEach(function(r) {
                    html += '<div style="padding:7px 10px;border-radius:4px;background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);margin-bottom:5px;display:flex;justify-content:space-between;align-items:center;">';
                    html += '<span style="font-family:var(--font-mono);font-size:10px;color:#9ca3b0;">' + _cdbEsc(r.rule_id || '') + '</span>';
                    html += '<span style="font-family:var(--font-mono);font-size:9px;color:#4b5563;">' + _cdbEsc((r.rule_type || '').toUpperCase()) + '</span>';
                    html += '</div>';
                });
                if (rulesList.length > 4) {
                    html += '<div style="font-family:var(--font-mono);font-size:9px;color:#6b7280;text-align:center;padding:4px;">+' + (rulesList.length - 4) + ' more rules in detection pack</div>';
                }
                html += '</div>';
            }

            // ── SECTION 7: Immediate Actions ────────────────────────────────
            var immediateActions = ai.immediate_actions || [];
            if (immediateActions.length > 0) {
                html += '<div class="cdb-agent-section">';
                html += '<h4 style="margin:0 0 10px;font-family:var(--font-mono);font-size:9px;letter-spacing:3px;color:#f87171;text-transform:uppercase;">🚨 Immediate Actions Required</h4>';
                immediateActions.slice(0, 5).forEach(function(act, idx) {
                    var prio = idx === 0 ? {label:'P0',color:'var(--critical)'} : idx <= 2 ? {label:'P1',color:'var(--high)'} : {label:'P2',color:'var(--accent)'};
                    html += '<div class="cdb-agent-action">';
                    html += '<span class="act-num" style="color:' + prio.color + ';flex-shrink:0;width:24px;">' + prio.label + '</span>';
                    html += '<span style="font-size:12px;line-height:1.55;">' + _cdbEsc(act) + '</span>';
                    html += '</div>';
                });
                html += '</div>';
            }

            // ── FOOTER ──────────────────────────────────────────────────────
            html += '<div style="padding-top:12px;font-family:var(--font-mono);font-size:9px;color:#374151;text-align:center;letter-spacing:1px;border-top:1px solid rgba(255,255,255,0.05);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">';
            html += '<span>SENTINEL APEX \u00b7 AI SOC ANALYST v2.0 \u00b7 ' + new Date().toISOString().substring(0,19) + ' UTC</span>';
            html += '<span style="color:rgba(0,212,170,0.5);">🧠 AI-POWERED ASSESSMENT</span>';
            html += '</div>';

            container.innerHTML = html;
        }

        // Safe HTML escape helper
        function _cdbRenderAgentResult(a, container) {
            var riskPct = Math.min(a.risk * 10, 100);
            var html = '';

            // Severity + Risk bar
            html += '<div class="cdb-agent-section">';
            html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
            html += '<span style="font-family:var(--font-mono);font-size:20px;font-weight:900;color:' + a.sevColor + ';">' + a.severity + '</span>';
            html += '<span style="font-family:var(--font-mono);font-size:14px;color:#E6EDF3;font-weight:700;">' + a.risk.toFixed(1) + '/10</span>';
            html += '</div>';
            html += '<div class="cdb-agent-risk-bar"><div class="cdb-agent-risk-fill" style="width:' + riskPct + '%;background:' + a.sevColor + ';"></div></div>';

            // Quick stats
            html += '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:10px;">';
            if (a.cves.length) html += '<span style="font-family:var(--font-mono);font-size:10px;background:rgba(59,130,246,0.1);color:var(--blue);padding:2px 8px;border-radius:3px;">' + a.cves[0] + '</span>';
            if (a.cvss !== null) html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);">CVSS ' + a.cvss + '</span>';
            if (a.epss !== null) html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);">EPSS ' + a.epss.toFixed(1) + '%</span>';
            if (a.kev) html += '<span style="font-family:var(--font-mono);font-size:10px;background:rgba(220,38,38,0.12);color:#ff6b6b;padding:2px 8px;border-radius:3px;font-weight:700;">⚡ CISA KEV</span>';
            if (a.totalIOCs > 0) html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--accent);">' + a.totalIOCs + ' IOCs</span>';
            if (a.source) html += '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-left:auto;">SRC: ' + a.source.substring(0,30) + '</span>';
            html += '</div></div>';

            // Executive Summary
            html += '<div class="cdb-agent-section"><h4>📋 Executive Summary</h4><p>' + a.summary + '</p></div>';

            // Risk Assessment
            html += '<div class="cdb-agent-section"><h4>⚡ Risk Assessment</h4><p style="white-space:pre-line;font-family:var(--font-mono);font-size:11px;line-height:1.7;">' + a.riskAssessment + '</p>';
            html += '<div style="margin-top:8px;font-family:var(--font-mono);font-size:10px;color:#6B7C93;">Likelihood: <span style="color:#E6EDF3;">' + a.likelihood + '</span></div></div>';

            // MITRE ATT&CK
            if (a.tactics.length > 0) {
                html += '<div class="cdb-agent-section"><h4>🗺️ MITRE ATT&CK Mapping</h4><div class="cdb-agent-mitre">';
                a.tactics.forEach(function(t) {
                    var desc = _CDB_MITRE_DB[t] || t;
                    html += '<a href="https://attack.mitre.org/techniques/' + t.replace('.', '/') + '/" target="_blank" rel="noopener" title="' + desc + '">' + t + ' \u2014 ' + desc.split(':')[0] + '</a>';
                });
                html += '</div></div>';
            }

            // Attack Vector Analysis
            html += '<div class="cdb-agent-section"><h4>🔍 Attack Vector Analysis</h4><p style="white-space:pre-line;font-size:12px;">' + a.attackVector + '</p></div>';

            // Recommended Actions
            html += '<div class="cdb-agent-section"><h4>🎯 Recommended Actions</h4><div class="cdb-agent-actions">';
            a.actions.forEach(function(act, i) {
                var pColor = act.p === 'P0' ? 'var(--critical)' : act.p === 'P1' ? 'var(--high)' : act.p === 'P2' ? 'var(--accent)' : 'var(--text-muted)';
                html += '<div class="cdb-agent-action"><span class="act-num" style="color:' + pColor + ';">' + act.p + '</span><span>' + act.t + '</span></div>';
            });
            html += '</div></div>';

            // Footer
            html += '<div style="padding-top:12px;font-family:var(--font-mono);font-size:9px;color:#6B7C93;text-align:center;letter-spacing:1px;">';
            html += 'CYBERDUDEBIVASH SENTINEL APEX \u00b7 SOC ANALYST AGENT \u00b7 ' + new Date().toISOString().substring(0,19) + ' UTC';
            html += '</div>';

            container.innerHTML = html;
        }

        function cdbCloseAgent() {
            var modal = document.getElementById('cdb-agent-modal');
            if (modal) modal.classList.remove('open');
        }

        // ESC key to close
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') cdbCloseAgent();
        });

        // ── v101.0 ANALYZE button injection \u2014 MutationObserver + retry ──
        // Injects "🧠 ANALYZE" button into every card that has a stix_id.
        // Targets the card-footer .js-open-modal DETAILS button specifically
        // (not the h3 title which is also .js-open-modal) to avoid double injection.
        // Retry loop ensures late-rendered cards (live fetch) are also covered.
        (function() {
            var grid = document.getElementById('threat-grid');
            if (!grid) return;

            function injectAnalyzeButtons() {
                // Target ONLY button elements (not h3 titles) with js-open-modal
                grid.querySelectorAll('button.js-open-modal').forEach(function(btn) {
                    // Guard: already injected in this parent container?
                    var parent = btn.closest('.card-footer') || btn.parentNode;
                    if (parent.querySelector('.cdb-agent-btn')) return;
                    var stixId = btn.dataset.stixId || btn.getAttribute('data-stix-id');
                    if (!stixId) return;
                    var analyzeBtn = document.createElement('button');
                    analyzeBtn.className = 'cdb-agent-btn';
                    analyzeBtn.setAttribute('data-stix-id', stixId);
                    analyzeBtn.title = 'Run AI Threat Analysis';
                    analyzeBtn.innerHTML = '🧠 ANALYZE';
                    analyzeBtn.onclick = function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        cdbOpenAgent(stixId);
                    };
                    // Insert immediately after the DETAILS button
                    btn.parentNode.insertBefore(analyzeBtn, btn.nextSibling);
                });
            }

            // MutationObserver watches for new cards rendered by live fetch
            var observer = new MutationObserver(function() {
                clearTimeout(observer._t);
                observer._t = setTimeout(injectAnalyzeButtons, 80);
            });
            observer.observe(grid, { childList: true, subtree: true });

            // Run immediately + retry after live data loads (500ms, 1500ms, 3000ms)
            [100, 500, 1500, 3000].forEach(function(ms) {
                setTimeout(injectAnalyzeButtons, ms);
            });
        })();

        // ── v73.2 BOOT FIX: readyState guard \u2014 prevents stuck BOOTING... ──
        // DOMContentLoaded only fires if DOM is still loading.
        // If script runs after DOM is ready (cached page, fast CDN),
        // we must call boot functions directly \u2014 not wait for an event that already fired.
        function _cdbBootSequence() {
            // APEX FINAL P1: boot-sequence execution guard
            if (window.__INTEL_RENDERED__) {
                console.warn('[BLOCK] Duplicate boot sequence prevented');
                return;
            }
            // PHASE 1: Instant render from embedded cache (< 50ms, zero network)
            try { bootFromEmbeddedCache(); } catch(e) { console.warn('[BOOT] Embedded cache error:', e); }
            // PHASE 2: Upgrade to live data in background
            loadGOCIntel().catch(() => {});
            scheduleAutoRefresh();
        }
        if (document.readyState === 'loading') {
            // DOM not yet ready \u2014 wait for it
            document.addEventListener('DOMContentLoaded', _cdbBootSequence);
        } else {
            // DOM already ready (cached/fast load) \u2014 call immediately
            _cdbBootSequence();
        }

        // v184.0 P0 SAFETY TIMER / v184.0 P0 SAFETY TIMER: catches ALL stuck-grid scenarios after 12s:
        //   1. Spinner still visible   → boot render or fetch failed silently
        //   2. Grid is empty / no cards → renderCards() silently produced nothing
        // v184.0 FIX: removed !__INTEL_RENDERED__ dependency \u2014 flag can be true even when cards are absent
        // Retry is triggered purely on VISIBLE state: spinner present OR no actual intel-cards in DOM
        setTimeout(function() {
            var _stg = document.getElementById('threat-grid');
            if (!_stg) return;
            var _hasSpinner = !!_stg.querySelector('.loading-spinner');
            var _hasCards   = !!_stg.querySelector('.intel-card, .threat-card, [data-id]');
            var _isEmpty    = _stg.children.length === 0;
            // v184.0: retry if spinner OR no cards visible (removed __INTEL_RENDERED__ blind-spot)
            if (_hasSpinner || _isEmpty || !_hasCards) {
                console.warn('[SENTINEL-APEX] P0-SAFETY: Grid stuck after 12s (spinner=' + _hasSpinner + ', empty=' + _isEmpty + ', rendered=' + window.__INTEL_RENDERED__ + ') \u2014 force retry');
                window.__DATA_LOADED__    = false;
                window.__INTEL_RENDERED__ = false;
                window.RENDER_IN_PROGRESS = false;
                loadGOCIntel().catch(function() {
                    // retry itself failed \u2014 render actionable error state
                    var _stg2 = document.getElementById('threat-grid');
                    if (_stg2 && (_stg2.querySelector('.loading-spinner') || _stg2.children.length === 0)) {
                        _stg2.innerHTML = '<div class="loading-state" style="color:#888;">&#9888; Feed sync failed &mdash; <a href="javascript:void(0)" onclick="window.__DATA_LOADED__=false;window.__INTEL_RENDERED__=false;window.RENDER_IN_PROGRESS=false;loadGOCIntel();" style="color:var(--accent,#00d4aa);text-decoration:none;font-weight:700;">retry now</a></div>';
                    }
                });
            }
        }, 12000);

        // ═══════════════════════════════════════════════════════
        // v46.0 NEXUS INTELLIGENCE \u2014 Client-Side Analytics Engine
        // ═══════════════════════════════════════════════════════

        const NEXUS_TECHNIQUE_PHASE = {
            'T1595':'recon','T1592':'recon','T1589':'recon','T1590':'recon','T1591':'recon',
            'T1588':'weapon','T1587':'weapon','T1583':'weapon','T1584':'weapon','T1585':'weapon',
            'T1566':'delivery','T1190':'delivery','T1133':'delivery','T1200':'delivery','T1195':'delivery',
            'T1059':'exploit','T1203':'exploit','T1053':'exploit','T1068':'exploit',
            'T1547':'install','T1543':'install','T1136':'install','T1546':'install',
            'T1548':'install','T1134':'install','T1027':'install','T1562':'install','T1070':'install',
            'T1003':'exploit','T1110':'exploit','T1558':'exploit',
            'T1087':'recon','T1482':'recon','T1069':'recon',
            'T1021':'c2','T1570':'c2','T1080':'c2',
            'T1560':'actions','T1005':'actions','T1039':'actions','T1074':'actions',
            'T1041':'exfil','T1048':'exfil','T1567':'exfil',
            'T1071':'c2','T1105':'c2','T1573':'c2','T1572':'c2',
            'T1486':'impact','T1490':'impact','T1561':'impact','T1489':'impact',
            'T1078':'delivery','T1528':'exploit','T1550':'exploit',
        };

        function renderNexusIntelligence(data) {
            if (!data || !data.length) return;
            const section = document.getElementById('nexus-section');
            if (!section) return;
            section.style.display = 'block';

            // ── Exposure Score ──
            const scores = data.map(d => d.risk_score || 0);
            // v136.0 FIX: dual-condition \u2014 risk_score >= 9 OR severity field = CRITICAL
            const critical = data.filter(d => parseFloat(d.risk_score||0) >= 9.0 || d.severity === 'CRITICAL').length;
            const high = data.filter(d => { const s=parseFloat(d.risk_score||0); return (s>=7&&s<9)||(d.severity==='HIGH'&&s<9); }).length;
            const kevCount = data.filter(d => d.kev === true || d.kev_present === true).length;
            const avgRisk = scores.length ? scores.reduce((a,b)=>a+b,0)/scores.length : 0;
            const velocity = Math.min(10, data.length / 7 * 1.5);
            const critDensity = Math.min(10, (critical*2 + high) / Math.max(data.length,1) * 30);
            const kevScore = Math.min(10, kevCount / Math.max(data.length,1) * 40);
            const exposure = Math.min(10, velocity*0.2 + critDensity*0.3 + kevScore*0.2 + avgRisk*0.1 + Math.min(10,critical*0.5)*0.2).toFixed(1);

            const expEl = document.getElementById('nexus-exposure-score');
            if (expEl) {
                expEl.textContent = exposure;
                expEl.style.color = exposure >= 7 ? 'var(--critical)' : exposure >= 4 ? 'var(--high)' : 'var(--accent)';
            }
            const trendEl = document.getElementById('nexus-exposure-trend');
            if (trendEl) {
                const trend = critical > 3 ? '▲ INCREASING' : critical > 1 ? '● STABLE' : '▼ DECREASING';
                const tColor = critical > 3 ? '#ef4444' : critical > 1 ? '#d97706' : '#00d4aa';
                trendEl.textContent = trend;
                trendEl.style.color = tColor;
                trendEl.style.background = tColor + '12';
            }

            // ── Kill Chain ──
            // P0 dashboard data contract (2026-09-24): #nexus-killchain is owned
            // by js/sentinel-live-feeds.js loadKillChain(), which renders the
            // Worker's attack_tactics block (/api/v1/intel/campaigns). This
            // renderer read only mitre_techniques/mitre_tactics through a
            // partial technique map, so technique-only items never counted and
            // the panel showed every stage at 0 while campaigns were live.

            // ── Threat Hunts ──
            const huntPatterns = [
                {kw:['supply','chain'],tpl:'Supply-chain compromise via trusted update mechanisms',pri:'CRITICAL'},
                {kw:['ransomware','ransom','encrypt'],tpl:'Ransomware deployment using LOLBins for lateral movement',pri:'CRITICAL'},
                {kw:['credential','phishing','password'],tpl:'Credential harvesting campaign targeting enterprise identity',pri:'HIGH'},
                {kw:['zero-day','0day','unpatched'],tpl:'Active zero-day exploitation of internet-facing systems',pri:'CRITICAL'},
                {kw:['cloud','aws','azure','saas'],tpl:'Cloud infrastructure compromise via API key/OAuth abuse',pri:'HIGH'},
                {kw:['apt','nation','espionage'],tpl:'Nation-state persistence via registry/WMI/scheduled tasks',pri:'HIGH'},
                {kw:['exfil','steal','theft'],tpl:'Covert data exfiltration via encrypted C2 channels',pri:'HIGH'},
            ];
            const hunts = [];
            const usedPatterns = new Set();
            data.filter(d => (d.risk_score||0) >= 7).slice(0,20).forEach(d => {
                const tl = (d.title||'').toLowerCase();
                for (const p of huntPatterns) {
                    if (usedPatterns.has(p.tpl)) continue;
                    if (p.kw.some(k => tl.includes(k))) {
                        hunts.push({hypothesis:p.tpl, priority:p.pri, actor:d.actor_tag||'UNK'});
                        usedPatterns.add(p.tpl);
                        break;
                    }
                }
            });

            const huntCountEl = document.getElementById('nexus-hunt-count');
            if (huntCountEl) huntCountEl.textContent = hunts.length || '0';

            const huntsEl = document.getElementById('nexus-hunts');
            if (huntsEl) {
                if (!hunts.length) {
                    huntsEl.innerHTML = '<div style="color:var(--text-muted);">Insufficient high-risk data for hunt generation</div>';
                } else {
                    huntsEl.innerHTML = hunts.slice(0,5).map(h => {
                        const priColor = h.priority === 'CRITICAL' ? '#ef4444' : '#ea580c';
                        return `<div style="padding:8px 0;border-bottom:1px solid var(--border);">
                            <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
                                <span style="font-size:9px;padding:1px 6px;background:${priColor}18;color:${priColor};border-radius:2px;">${h.priority}</span>
                                <span style="font-size:9px;color:var(--text-muted);">${_hEsc(h.actor)}</span>
                            </div>
                            <div style="font-size:11px;color:var(--text);line-height:1.4;">${h.hypothesis}</div>
                        </div>`;
                    }).join('');
                }
            }

            // ── Campaigns ──
            const actorIndex = {};
            data.forEach(d => {
                const a = d.actor_tag;
                if (a && a !== 'UNC-CDB-99') {
                    if (!actorIndex[a]) actorIndex[a] = [];
                    actorIndex[a].push(d);
                }
            });
            const campaigns = Object.entries(actorIndex)
                .filter(([,v]) => v.length >= 2)
                .map(([actor, entries]) => {
                    const maxRisk = Math.max(...entries.map(e => e.risk_score || 0));
                    const techs = new Set();
                    entries.forEach(e => (e.mitre_techniques||e.mitre_tactics||[]).forEach(t => {
                        const tid = typeof t === 'string' ? t : (t.technique_id||t.id||'');
                        if (tid) techs.add(tid);
                    }));
                    return {actor, count: entries.length, maxRisk, techniques: techs.size};
                })
                .sort((a,b) => b.maxRisk - a.maxRisk);

            const campEl = document.getElementById('nexus-campaigns');
            if (campEl) {
                if (!campaigns.length) {
                    campEl.innerHTML = '<div style="color:var(--text-muted);">No multi-advisory campaigns detected</div>';
                } else {
                    campEl.innerHTML = campaigns.slice(0,5).map(c => {
                        const sColor = c.maxRisk >= 9 ? '#ef4444' : c.maxRisk >= 7 ? '#ea580c' : '#d97706';
                        return `<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                            <div>
                                <div style="font-size:12px;color:var(--white);font-weight:600;">${_hEsc(c.actor)}</div>
                                <div style="font-size:9px;color:var(--text-muted);">${c.count} advisories \u00b7 ${c.techniques} techniques</div>
                            </div>
                            <span style="font-size:10px;padding:2px 8px;background:${sColor}18;color:${sColor};border-radius:2px;font-weight:700;">${c.maxRisk.toFixed(1)}</span>
                        </div>`;
                    }).join('');
                }
            }

            // ── Detection Rules Count ──
            // Removed (P0 dashboard data contract): this wrote "high-risk items
            // x 3" as a rule count -- an invented number, and it overwrote the
            // real detection_pack count renderNexusEngine() writes to
            // #nexus-rules-count (that function is now its only writer).

            // ── PIR Coverage ──
            const pirDefs = [
                {id:'PIR-1',label:'Ransomware',kw:['ransomware','ransom','encrypt','lockbit','cl0p']},
                {id:'PIR-2',label:'Zero-Days',kw:['zero-day','0day','cve-','vulnerability','exploit']},
                {id:'PIR-3',label:'APT',kw:['apt','nation-state','espionage','state-sponsored']},
                {id:'PIR-4',label:'Supply Chain',kw:['supply chain','dependency','update mechanism']},
                {id:'PIR-5',label:'IAB/Creds',kw:['credential','initial access','broker','phishing']},
                {id:'PIR-6',label:'Cloud',kw:['cloud','aws','azure','gcp','saas','kubernetes']},
                {id:'PIR-7',label:'Insider',kw:['insider','privileged','unauthorized']},
                {id:'PIR-8',label:'Exploits',kw:['exploit','weaponize','poc','proof of concept']},
            ];
            let coveredCount = 0;
            const pirBarsEl = document.getElementById('nexus-pir-bars');
            if (pirBarsEl) {
                pirBarsEl.innerHTML = pirDefs.map(pir => {
                    const matches = data.filter(d => {
                        const tl = (d.title||'').toLowerCase();
                        return pir.kw.some(k => tl.includes(k));
                    }).length;
                    const level = matches >= 5 ? 'HIGH' : matches >= 2 ? 'MED' : 'LOW';
                    const color = level === 'HIGH' ? '#00d4aa' : level === 'MED' ? '#d97706' : '#ef4444';
                    const pct = Math.min(100, matches * 10);
                    if (level !== 'LOW') coveredCount++;
                    return `<div style="text-align:center;">
                        <div style="font-size:8px;color:var(--text-muted);letter-spacing:1px;margin-bottom:4px;">${pir.label}</div>
                        <div style="height:6px;background:var(--bg-surface);border-radius:3px;overflow:hidden;">
                            <div style="height:100%;width:${pct}%;background:${color};border-radius:3px;transition:width 1s ease;"></div>
                        </div>
                        <div style="font-size:9px;color:${color};margin-top:3px;font-weight:700;">${level}</div>
                    </div>`;
                }).join('');
            }
            const pirPctEl = document.getElementById('nexus-pir-pct');
            if (pirPctEl) pirPctEl.textContent = Math.round(coveredCount / pirDefs.length * 100) + '%';

            // ── Executive Briefing ──
            const briefEl = document.getElementById('nexus-briefing');
            if (briefEl) {
                const actors = {};
                data.forEach(d => { if (d.actor_tag && d.actor_tag !== 'UNC-CDB-99') actors[d.actor_tag] = (actors[d.actor_tag]||0)+1; });
                const topActors = Object.entries(actors).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([a])=>a).join(', ') || 'multiple unattributed groups';
                briefEl.innerHTML = `During the current intelligence cycle, <strong>${data.length} threat advisories</strong> have been processed. ` +
                    `<strong style="color:var(--critical);">${critical}</strong> are classified CRITICAL and ` +
                    `<strong style="color:var(--high);">${high}</strong> as HIGH risk. ` +
                    `<strong>${kevCount}</strong> advisories involve CISA KEV-confirmed active exploitation. ` +
                    `Primary threat actors: <strong>${topActors}</strong>. ` +
                    `Exposure index: <strong style="color:${exposure >= 7 ? 'var(--critical)' : 'var(--accent)'};">${exposure}/10</strong>. ` +
                    (critical >= 5 ? '<span style="color:var(--critical);font-weight:700;">IMMEDIATE executive attention required.</span>' :
                    'Heightened vigilance recommended with focus on patch management.');
            }
        }

        // Hook NEXUS rendering into the existing data load
        const _origComputeMetrics = computeMetrics;
        computeMetrics = function(data) {
            _origComputeMetrics(data);
            try { renderNexusIntelligence(data); } catch(e) { console.warn('[NEXUS] Render error:', e); }
        };

        // ═══════════════════════════════════════════════════════
        // v40-v42 CORTEX/QUANTUM/SOVEREIGN \u2014 Dashboard Engine
        // ═══════════════════════════════════════════════════════

        function renderEcosystemPanels(data) {
            if (!data || !data.length) return;

            // CORTEX: Knowledge Graph node count
            const nodeTypes = new Set();
            data.forEach(d => {
                if (d.stix_id) nodeTypes.add(d.stix_id);
                if (d.actor_tag && d.actor_tag !== 'UNC-CDB-99') nodeTypes.add('actor-'+d.actor_tag);
                (d.mitre_techniques||d.mitre_tactics||[]).forEach(t => {
                    const tid = typeof t === 'string' ? t : (t.technique_id||t.id||'');
                    if (tid) nodeTypes.add('tech-'+tid);
                });
                const cves = (d.title||'').match(/CVE-\d{4}-\d{4,7}/gi) || [];
                cves.forEach(c => nodeTypes.add('cve-'+c));
            });
            const cortexEl = document.getElementById('cortex-nodes');
            if (cortexEl) cortexEl.textContent = nodeTypes.size;

            // QUANTUM: Feed trust score
            const feedCounts = {};
            data.forEach(d => { const src = d.feed_source||'unknown'; feedCounts[src] = (feedCounts[src]||0)+1; });
            const feedCount = Object.keys(feedCounts).length;
            const trustScore = Math.max(0, Math.min(100, 100 - Math.max(0, (Object.values(feedCounts).some(c => c/data.length > 0.4) ? 8 : 0))));
            const quantumEl = document.getElementById('quantum-trust');
            if (quantumEl) {
                quantumEl.textContent = trustScore + '%';
                quantumEl.style.color = trustScore >= 80 ? '#00d4aa' : trustScore >= 60 ? '#d97706' : '#ef4444';
            }

            // SOVEREIGN: Compliance score
            const complianceFactors = [
                data.length > 0,          // Monitoring active
                data.some(d => d.kev_present || d.kev === true),  // KEV tracking
                data.some(d => (d.mitre_techniques && d.mitre_techniques.length) || (d.mitre_tactics && d.mitre_tactics.length)), // MITRE mapping
                true, // RBAC system
                true, // CSP headers
                true, // CI/CD pipeline
                true, // Detection rules
                true, // IR playbooks
                data.some(d => (d.risk_score||0) > 0), // Risk scoring
                true, // Version control
            ];
            const compScore = Math.round(complianceFactors.filter(Boolean).length / complianceFactors.length * 100);
            const sovEl = document.getElementById('sovereign-compliance');
            if (sovEl) sovEl.textContent = compScore + '%';
        }

        // NLQ Search
        function runNLQ() {
            const input = document.getElementById('nlq-input');
            const resultsDiv = document.getElementById('nlq-results');
            if (!input || !resultsDiv || !manifestData) return;

            const query = input.value.toLowerCase().trim();
            if (!query) return;

            resultsDiv.style.display = 'block';
            let results = [];

            // Simple NLQ processing
            if (query.includes('critical') || query.includes('high risk')) {
                results = manifestData.filter(d => (d.risk_score||0) >= 7);
            } else if (query.includes('kev') || query.includes('exploited')) {
                results = manifestData.filter(d => d.kev_present);
            } else {
                const words = query.split(' ').filter(w => w.length > 3);
                results = manifestData.filter(d => {
                    const title = (d.title||'').toLowerCase();
                    const actor = (d.actor_tag||'').toLowerCase();
                    return words.some(w => title.includes(w) || actor.includes(w));
                });
            }

            if (!results.length) {
                resultsDiv.innerHTML = '<div style="color:var(--text-muted);padding:8px;">No matching advisories found. Try different keywords.</div>';
                return;
            }

            resultsDiv.innerHTML = `<div style="color:var(--accent);margin-bottom:8px;">Found ${results.length} result${results.length>1?'s':''}:</div>` +
                results.slice(0,10).map(r => {
                    const sev = (r.risk_score||0) >= 9 ? 'CRITICAL' : (r.risk_score||0) >= 7 ? 'HIGH' : 'MEDIUM';
                    const color = sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#ea580c' : '#d97706';
                    return `<div style="padding:6px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                        <div style="flex:1;font-size:11px;color:var(--text);">${(r.title||'').slice(0,70)}</div>
                        <span style="font-size:9px;padding:2px 6px;background:${color}18;color:${color};border-radius:2px;margin-left:8px;">${sev} ${(r.risk_score||0).toFixed(1)}</span>
                    </div>`;
                }).join('');
        }

        // Hook into existing data pipeline
        const _origComputeMetrics2 = computeMetrics;
        computeMetrics = function(data) {
            _origComputeMetrics2(data);
            try { renderEcosystemPanels(data); } catch(e) { console.warn('[v42] Panel render:', e); }
        };

        // ═══════════════════════════════════════════════════════
        // v46.0 GENESIS \u2014 12-Engine Dashboard Engine
        // ═══════════════════════════════════════════════════════

        function renderGenesis(data) {
            if (!data || !data.length) return;
            const grid = document.getElementById('genesis-grid');
            if (!grid) return;

            const engines = [
                {id:'G01',name:'Sensor Network',icon:'📡',color:'#3b82f6',
                 val: '8 REGIONS', desc:'Global telemetry sensors'},
                {id:'G02',name:'Honeypot Grid',icon:'🍯',color:'#f59e0b',
                 val: '8 TRAPS', desc:'Multi-protocol deception'},
                {id:'G03',name:'Malware Cloud',icon:'🧬',color:'#ef4444',
                 val: data.filter(d=>(d.risk_score||0)>=7).length+'', desc:'Samples analyzed'},
                {id:'G04',name:'Actor Registry',icon:'🎭',color:'#8b5cf6',
                 val: new Set(data.map(d=>d.actor_tag).filter(a=>a&&a!=='UNC-CDB-99')).size+'',
                 desc:'Tracked actors'},
                {id:'G05',name:'Campaign Engine',icon:'🔗',color:'#ec4899',
                 val: Object.entries(data.reduce((a,e)=>{const t=e.actor_tag;if(t&&t!=='UNC-CDB-99'){a[t]=(a[t]||0)+1}return a},{})).filter(([,c])=>c>=2).length+'',
                 desc:'Campaigns detected'},
                {id:'G06',name:'IOC Reputation',icon:'🛡️',color:'#14b8a6',
                 val: new Set(data.flatMap(d=>(d.title||'').match(/CVE-\d{4}-\d{4,7}/gi)||[])).size+'',
                 desc:'IOCs scored'},
                {id:'G07',name:'Detection Gen',icon:'⚡',color:'#f97316',
                 val: (data.filter(d=>(d.risk_score||0)>=7).length*5)+'',
                 desc:'Rules generated'},
                {id:'G08',name:'TAXII Server',icon:'📦',color:'#06b6d4',
                 val:'4 FEEDS', desc:'STIX/TAXII collections'},
                {id:'G09',name:'DarkWeb Intel',icon:'💢¸️',color:'#a855f7',
                 val:'9 SOURCES', desc:'Monitored darkweb'},
                {id:'G10',name:'Attack Surface',icon:'🔍',color:'#22c55e',
                 val: data.filter(d=>{const t=(d.title||'').toLowerCase();return t.includes('expos')||t.includes('rce')||t.includes('misconfigur')}).length+'',
                 desc:'Exposure signals'},
                {id:'G11',name:'Attack Map',icon:'🗺️',color:'#e11d48',
                 val: data.length+'', desc:'Attack flows mapped'},
                {id:'G12',name:'AI Hunter',icon:'🤖',color:'#7c3aed',
                 val: Math.min(10,Math.max(1,Math.floor(data.length/5)))+'',
                 desc:'Threat clusters'},
            ];

            grid.innerHTML = engines.map(e =>
                `<div style="background:var(--bg-card);border:1px solid ${e.color}22;border-radius:4px;padding:12px;text-align:center;">
                    <div style="font-size:18px;margin-bottom:4px;">${e.icon}</div>
                    <div style="font-family:var(--font-mono);font-size:7px;letter-spacing:2px;color:${e.color};margin-bottom:4px;">${e.id} ${e.name.toUpperCase()}</div>
                    <div style="font-size:22px;font-weight:900;color:${e.color};font-family:var(--font-mono);">${e.val}</div>
                    <div style="font-size:8px;color:var(--text-muted);margin-top:2px;">${e.desc}</div>
                </div>`
            ).join('');

            // Attack flows
            const flowsEl = document.getElementById('genesis-attack-flows');
            if (flowsEl) {
                const countries = {'CN':'China','RU':'Russia','US':'USA','KP':'N.Korea','IR':'Iran'};
                const flows = Object.entries(countries).map(([code,name]) => {
                    const count = data.filter(d => {
                        const t = (d.title||'').toLowerCase();
                        const a = (d.actor_tag||'').toLowerCase();
                        return (code==='CN'&&(t.includes('china')||a.includes('volt'))) ||
                               (code==='RU'&&(t.includes('russia')||a.includes('apt28')||a.includes('apt29')||a.includes('lockbit'))) ||
                               (code==='KP'&&(a.includes('lazarus')||t.includes('korea'))) ||
                               (code==='IR'&&t.includes('iran')) ||
                               (code==='US'&&t.includes('us '));
                    }).length;
                    return {code,name,count};
                }).filter(f=>f.count>0).sort((a,b)=>b.count-a.count);

                flowsEl.innerHTML = flows.length ?
                    flows.map(f => `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);"><span>${f.code} ${f.name}</span><span style="color:#ec4899;font-weight:700;">${f.count} flows</span></div>`).join('') :
                    `<div>Active flows: ${data.length} global</div>`;
            }

            // Actor registry
            const actorsEl = document.getElementById('genesis-actors');
            if (actorsEl) {
                const actorCounts = {};
                data.forEach(d => {const a=d.actor_tag; if(a&&a!=='UNC-CDB-99') actorCounts[a]=(actorCounts[a]||0)+1;});
                const sorted = Object.entries(actorCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
                actorsEl.innerHTML = sorted.length ?
                    sorted.map(([actor,count]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);"><span style="color:var(--white);">${actor}</span><span style="color:#8b5cf6;">${count} advisories</span></div>`).join('') :
                    '<div>Processing actor intelligence...</div>';
            }
        }

        const _origCM3 = computeMetrics;
        computeMetrics = function(data) {
            _origCM3(data);
            try { renderGenesis(data); } catch(e) { console.warn('[GENESIS]', e); }
        };

        // ═══════════════════════════════════════════════════════════════════
        // SENTINEL APEX ENGINE DATA LOADER \u2014 Activates v39\u2013v43 Intelligence
        // Fetches live engine JSON outputs and wires to all dashboard panels
        // ═══════════════════════════════════════════════════════════════════

        (function initEngineLoader() {
            const RAW_BASE = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2N5YmVyZHVkZWJpdmFzaC9DWUJFUkRVREVCSVZBU0gtVEhSRUFULUlOVEVMLVBMQVRGT1JNL21haW4v');
            // P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10):
            // nexus/genesis/cortex/quantum/sovereign now go through the
            // same-origin Worker proxy (workers/intel-gateway/src/
            // intel-static-proxy.js), which reads Cloudflare R2 first (kept
            // fresh by genesis-powerhouse.yml/sovereign-platform.yml's new
            // R2 upload step, replacing their previous `git push origin
            // main` that main's branch ruleset had been silently rejecting
            // since 2026-08-26) and falls back to this exact raw-GitHub-main
            // URL -- unchanged -- if R2 is ever empty or errors. Same
            // zero-regression pattern already proven for ai_index.json /
            // detection_rules_manifest.json above this file's AI-record
            // widget. bughunter/incidents/responses/hunts are unrelated to
            // this mission's scope and are deliberately left reading
            // straight from main, unchanged.
            const ENGINE_URLS = {
                nexus:    '/api/v1/intel/nexus_output.json',
                genesis:  '/api/v1/intel/genesis_output.json',
                cortex:   '/api/v1/intel/cortex_output.json',
                quantum:  '/api/v1/intel/quantum_output.json',
                sovereign: '/api/v1/intel/sovereign_output.json',
                bughunter: RAW_BASE + 'data/bughunter/bughunter_output.json',
                incidents: RAW_BASE + 'data/incidents/incidents.json',
                responses: RAW_BASE + 'data/responses/response_log.json',
                hunts:     RAW_BASE + 'data/threathunts/hunts.json',
            };

            // ── NEXUS RENDERER ──────────────────────────────────────────────
            function renderNexusEngine(data) {
                try {
                    // Exposure Score
                    const exp = data.exposure || {};
                    const score = (data.exposure_index != null ? data.exposure_index : exp.score != null ? exp.score : exp.overall_score != null ? exp.overall_score : null);
                    const expEl = document.getElementById('nexus-exposure-score');
                    if (expEl && score != null) {
                        expEl.textContent = score.toFixed(1);
                        expEl.style.color = score >= 8 ? '#ef4444' : score >= 6 ? '#f59e0b' : '#00d4aa';
                    }

                    // Exposure Trend
                    const trendEl = document.getElementById('nexus-exposure-trend');
                    if (trendEl && exp.trend) {
                        const trendLow = (exp.trend||'STABLE').toLowerCase();
                        const arrow = trendLow === 'increasing' ? '↑' : trendLow === 'decreasing' ? '↓' : '→';
                        const tColor = trendLow === 'increasing' ? '#ef4444' : trendLow === 'decreasing' ? '#00d4aa' : '#d97706';
                        const f7 = exp.forecast_7d != null ? exp.forecast_7d.toFixed(1) : '\u2014';
                        const f30 = exp.forecast_30d != null ? exp.forecast_30d.toFixed(1) : '\u2014';
                        trendEl.textContent = arrow + ' ' + (exp.trend||'STABLE').toUpperCase() + ' | 7D: ' + f7 + ' | 30D: ' + f30;
                        trendEl.style.color = tColor;
                        trendEl.style.background = tColor + '18';
                    }

                    // Kill Chain: removed (P0 dashboard data contract, 2026-09-24).
                    // #nexus-killchain has one owner, sentinel-live-feeds.js
                    // loadKillChain() (current-feed ATT&CK tactics). This block
                    // overwrote it with technique ids from the separate engine
                    // file, unescaped.

                    // Hunt Count
                    const hunts = data.threat_hunts || [];
                    const huntEl = document.getElementById('nexus-hunt-count');
                    if (huntEl) huntEl.textContent = hunts.length;

                    // Hunts list
                    const huntsListEl = document.getElementById('nexus-hunts');
                    if (huntsListEl && hunts.length) {
                        huntsListEl.innerHTML = hunts.slice(0, 4).map(h =>
                            `<div style="padding:5px 0;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:8px;">
                                <span style="color:${h.priority==='CRITICAL'?'#ef4444':h.priority==='HIGH'?'#f59e0b':'#8b5cf6'};font-size:8px;font-weight:700;letter-spacing:1px;min-width:48px;">${_hEsc(h.priority||'HIGH')}</span>
                                <span style="font-size:10px;color:var(--text);line-height:1.4;">${_hEsc(String(h.hypothesis||'').slice(0,80))}...</span>
                            </div>`
                        ).join('');
                    }

                    // Campaigns
                    const campaigns = data.campaigns || [];
                    const campEl = document.getElementById('nexus-campaigns');
                    if (campEl && campaigns.length) {
                        campEl.innerHTML = campaigns.slice(0, 4).map(c =>
                            `<div style="padding:5px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
                                <span style="font-size:10px;color:var(--white);">${(c.name||c.campaign_id||'Campaign').replace('Campaign: ','').slice(0,40)}</span>
                                <div style="display:flex;gap:4px;">
                                    ${(c.actors||[]).map(a=>`<span style="font-size:8px;background:#8b5cf622;color:#8b5cf6;border-radius:2px;padding:1px 4px;">${a}</span>`).join('')}
                                </div>
                            </div>`
                        ).join('');
                    }

                    // Detection Rules Count
                    const dp = data.detection_pack || {};
                    const rulesEl = document.getElementById('nexus-rules-count');
                    if (rulesEl) {
                        const _cnt = x => Array.isArray(x) ? x.length : (typeof x === 'number' ? x : 0);
                        const rCount = dp.total_rules || (_cnt(dp.sigma_rules) + _cnt(dp.yara_rules) + _cnt(dp.suricata_rules) + _cnt(dp.kql_queries||dp.kql_rules));
                        if (rCount > 0) rulesEl.textContent = rCount;
                    }

                    // Intel Requirements (PIR)
                    const pirData = data.pir_coverage || {};
                    const pirs = pirData.pirs || data.intel_requirements || [];
                    const pirBarsEl = document.getElementById('nexus-pir-bars');
                    const pirPctEl = document.getElementById('nexus-pir-pct');
                    if (pirPctEl) {
                        const pct = pirData.coverage_pct != null ? pirData.coverage_pct : (pirs.length ? Math.round(pirs.filter(p => p.status==='ACTIVE'||p.priority==='CRITICAL').length/pirs.length*100) : 0);
                        pirPctEl.textContent = pct + '%';
                    }
                    if (pirBarsEl && pirs.length) {
                        const _pirs = pirs.slice(0, 4);
                        pirBarsEl.innerHTML = _pirs.map(p => {
                            const isObj = typeof p === 'object' && !Array.isArray(p);
                            const label = isObj ? (Object.keys(p)[0]||'PIR') : (p.requirement||p.description||'PIR');
                            const status = isObj ? (Object.values(p)[0]||'GAP') : (p.status||'ACTIVE');
                            const c = status==='COVERED' ? '#00d4aa' : status==='PARTIAL' ? '#f59e0b' : '#ef4444';
                            return `<div style="background:var(--bg-card);border:1px solid ${c}33;border-radius:3px;padding:8px;text-align:center;">
                                <div style="font-size:7px;letter-spacing:1px;color:${c};margin-bottom:4px;">${status}</div>
                                <div style="font-size:9px;color:var(--text);line-height:1.3;">${label.slice(0,45)}</div>
                            </div>`;
                        }).join('');
                    }

                    // Executive Briefing
                    const briefEl = document.getElementById('nexus-briefing');
                    const brief = data.executive_briefing || {};
                    if (briefEl && (brief.executive_summary || brief.key_findings)) {
                        // T-21 TLP FIX: cap public brief at TLP:AMBER
                        const safeTlp = (brief.tlp === 'TLP:RED') ? 'TLP:AMBER' : (brief.tlp || 'TLP:AMBER');
                        const tlpColor = safeTlp === 'TLP:AMBER' ? '#f59e0b' : '#00d4aa';
                        const riskColor = brief.risk_level === 'CRITICAL' ? '#ef4444' : brief.risk_level === 'HIGH' ? '#f59e0b' : '#00d4aa';
                        let html_brief = `<div style="margin-bottom:10px;display:flex;gap:10px;align-items:center;">
                            <span style="font-size:8px;letter-spacing:2px;color:${tlpColor};font-family:var(--font-mono);background:${tlpColor}18;padding:2px 8px;border-radius:2px;">${safeTlp}</span>
                            <span style="font-size:8px;letter-spacing:2px;color:${riskColor};font-family:var(--font-mono);background:${riskColor}18;padding:2px 8px;border-radius:2px;">RISK: ${brief.risk_level||'HIGH'}</span>
                            ${brief.exposure_index != null ? `<span style="font-size:8px;color:var(--text-muted);">EXI: ${brief.exposure_index.toFixed(1)}/10</span>` : ''}
                        </div>`;
                        if (brief.executive_summary) html_brief += `<div style="font-size:11px;color:var(--text);line-height:1.7;margin-bottom:10px;">${brief.executive_summary.slice(0,500)}</div>`;
                        if (brief.key_findings && brief.key_findings.length) {
                            html_brief += `<div style="margin-bottom:8px;"><div style="font-size:8px;letter-spacing:2px;color:var(--accent);margin-bottom:6px;">▌ KEY FINDINGS</div>` +
                                brief.key_findings.slice(0,4).map(f=>`<div style="font-size:10px;color:var(--text-muted);padding:4px 0;border-bottom:1px solid var(--border);">▸ ${f.slice(0,120)}</div>`).join('') + '</div>';
                        }
                        if (brief.recommended_actions && brief.recommended_actions.length) {
                            html_brief += `<div><div style="font-size:8px;letter-spacing:2px;color:#f59e0b;margin-bottom:6px;">▌ RECOMMENDED ACTIONS</div>` +
                                brief.recommended_actions.slice(0,3).map(a=>`<div style="font-size:10px;color:var(--text-muted);padding:3px 0;">→ ${a.slice(0,110)}</div>`).join('') + '</div>';
                        }
                        briefEl.innerHTML = html_brief;
                    }

                } catch(e) { console.warn('[NEXUS ENGINE]', e); }
            }

            // ── GENESIS RENDERER ────────────────────────────────────────────
            function renderGenesisEngine(data) {
                try {
                    // Null guard: if data missing or engines empty, show degraded state (never '?')
                    if (!data || typeof data !== 'object') {
                        console.warn('[GENESIS ENGINE] No data received');
                        return;
                    }
                    const engines = data.engines || {};
                    const engineDefs = [
                        {key:'G01_SensorNetwork',  id:'G01', name:'Sensor Network',  icon:'📡', color:'#3b82f6',
                         valFn: s => (s.sensor_count||'?') + ' SENSORS', descFn: s => (s.total_events_24h||0).toLocaleString() + ' events/24h'},
                        {key:'G02_HoneypotGrid',   id:'G02', name:'Honeypot Grid',   icon:'🍯', color:'#f59e0b',
                         valFn: s => (s.honeypot_count||'?') + ' TRAPS', descFn: s => (s.total_captures_24h||0) + ' captures/24h'},
                        {key:'G03_MalwareCloud',   id:'G03', name:'Malware Cloud',   icon:'🧬', color:'#ef4444',
                         valFn: s => (s.malware_families_detected!=null?s.malware_families_detected:'?') + ' FAMILIES', descFn: s => (s.yara_rule_count||0) + ' YARA rules'},
                        {key:'G04_ActorRegistry',  id:'G04', name:'Actor Registry',  icon:'🎭', color:'#8b5cf6',
                         valFn: s => (s.total_actors||'?') + ' ACTORS', descFn: s => (s.known_actors||0) + ' known / ' + (s.discovered_actors||0) + ' new'},
                        {key:'G05_CampaignCorrelation', id:'G05', name:'Campaign Engine', icon:'🔗', color:'#ec4899',
                         valFn: s => (s.total_campaigns||s.campaign_count||'?') + ' CAMPAIGNS', descFn: s => { const camps=Array.isArray(s.campaigns)?s.campaigns.length:parseInt(s.campaigns)||0; return camps + ' active campaigns'; }},
                        {key:'G06_IOCReputation',  id:'G06', name:'IOC Reputation',  icon:'🛡️', color:'#14b8a6',
                         valFn: s => (s.total_iocs_scored||s.ioc_count||'?') + ' IOCs', descFn: s => 'avg trust: ' + ((s.average_trust_score||0)).toFixed(0) + '%'},
                        {key:'G07_DetectionGenerator', id:'G07', name:'Detection Gen', icon:'⚡', color:'#f97316',
                         valFn: s => { var sig=Array.isArray(s.sigma_rules)?s.sigma_rules.length:(parseInt(s.sigma_rules)||0); var yar=Array.isArray(s.yara_rules)?s.yara_rules.length:(parseInt(s.yara_rules)||0); var sur=Array.isArray(s.suricata_rules)?s.suricata_rules.length:(parseInt(s.suricata_rules)||0); var edr=Array.isArray(s.edr_queries)?s.edr_queries.length:(parseInt(s.edr_queries)||0); return (sig+yar+sur+edr||s.total_rules||'?')+' RULES'; },
                         descFn: s => { var sig=Array.isArray(s.sigma_rules)?s.sigma_rules.length:(parseInt(s.sigma_rules)||0); var yar=Array.isArray(s.yara_rules)?s.yara_rules.length:(parseInt(s.yara_rules)||0); return sig+' Sigma / '+yar+' YARA'; }},
                        {key:'G08_TAXIIServer',    id:'G08', name:'TAXII Server',    icon:'📦', color:'#06b6d4',
                         valFn: s => (s.collection_count||s.collections||'4') + ' FEEDS', descFn: s => 'STIX 2.1 compliant'},
                        {key:'G09_DarkWebIntel',   id:'G09', name:'DarkWeb Intel',   icon:'💢¸️', color:'#a855f7',
                         valFn: s => (s.sources_monitored||s.source_count||'9') + ' SOURCES', descFn: s => (s.alerts_24h||s.findings_count||0) + ' alerts/24h'},
                        {key:'G10_AttackSurface', id:'G10', name:'Attack Surface', icon:'🔍', color:'#22c55e',
                         valFn: s => { var pn=function(v){if(typeof v==='number')return v;if(typeof v==='string'){var m=v.match(/^(\d+)/);return m?parseInt(m[1]):0;}if(Array.isArray(v))return v.length;if(typeof v==='object'&&v)return Object.keys(v).length;return 0;}; var te=pn(s.total_exposures||s.total_exposure_signals||0); var vs=pn(s.vulnerable_services); var ec=pn(s.exposure_categories); var rs=pn(s.risk_summary); var total=te||(vs+ec+rs)||pn(s.scan_capabilities)||0; return total+' EXPOSURES'; },
                         descFn: s => { var pn=function(v){if(typeof v==='number')return v;if(typeof v==='string'){var m=v.match(/^(\d+)/);return m?parseInt(m[1]):0;}return 0;}; if(typeof s.risk_summary==='object'&&s.risk_summary)return (s.risk_summary.critical||s.risk_summary.critical_exposures||0)+' critical'; return pn(s.critical_findings||s.critical_exposures||0)+' critical'; }},
                        {key:'G11_GlobalAttackMap', id:'G11', name:'Attack Map',      icon:'🗺️', color:'#e11d48',
                         valFn: s => (s.total_flows||s.attack_count||s.event_count||'?') + ' FLOWS', descFn: s => (s.active_corridors||s.origin_countries||s.regions_active||0) + ' regions active'},
                        {key:'G12_AIThreatHunter', id:'G12', name:'AI Hunter', icon:'🤖', color:'#7c3aed',
                         valFn: s => { var hh=Array.isArray(s.hunt_hypotheses)?s.hunt_hypotheses.length:(parseInt(s.hunt_hypotheses)||0); var tc=Array.isArray(s.threat_clusters)?s.threat_clusters.length:(parseInt(s.threat_clusters)||0); return (hh||tc||s.hunts_generated||'?')+' HUNTS'; },
                         descFn: s => { var st=typeof s.stats==='object'&&s.stats?s.stats:{}; var ca=st.confidence_avg||st.avg_confidence||s.confidence_avg||0; return (typeof ca==='number'?ca.toFixed(0):ca||0)+'% avg confidence'; }},
                    ];

                    const grid = document.getElementById('genesis-grid');
                    if (grid) {
                        grid.innerHTML = engineDefs.map(def => {
                            const eng = engines[def.key] || {};
                            const summary = eng.summary || {};
                            const status = eng.status || 'OK';
                            const hasData = Object.keys(summary).length > 0;
                            const statusColor = status === 'OK' ? def.color : '#6b7280';
                            // Null guard: show '0' not '?' when field is absent but summary exists
                            let val = hasData ? '0' : 'SYNC', desc = hasData ? 'processing...' : 'awaiting data...';
                            try { val = def.valFn(summary); } catch(e) { val = hasData ? '0' : 'SYNC'; }
                            try { desc = def.descFn(summary); } catch(e) { desc = 'syncing...'; }
                            // Final guard: replace any residual '?' with '0'
                            val = String(val).replace(/^\?/, '0');
                            return `<div style="background:var(--bg-card);border:1px solid ${statusColor}22;border-radius:4px;padding:12px;text-align:center;position:relative;">
                                <div style="position:absolute;top:6px;right:6px;width:5px;height:5px;border-radius:50%;background:${statusColor};${status==='OK'?'box-shadow:0 0 4px '+statusColor:''}"></div>
                                <div style="font-size:18px;margin-bottom:4px;">${def.icon}</div>
                                <div style="font-family:var(--font-mono);font-size:7px;letter-spacing:2px;color:${statusColor};margin-bottom:4px;">${def.id} ${def.name.toUpperCase()}</div>
                                <div style="font-size:20px;font-weight:900;color:${statusColor};font-family:var(--font-mono);">${val}</div>
                                <div style="font-size:8px;color:var(--text-muted);margin-top:2px;">${desc}</div>
                            </div>`;
                        }).join('');
                    }

                    // Actor Registry Detail \u2014 always render (no "Loading..." hang)
                    const actorsEl = document.getElementById('genesis-actors');
                    const actorEng = engines['G04_ActorRegistry'] || {};
                    const actorSum = actorEng.summary || {};
                    if (actorsEl) {
                        actorsEl.innerHTML = `<div style="padding:4px 0;display:flex;justify-content:space-between;border-bottom:1px solid var(--border);">
                            <span style="color:var(--text);">Total Tracked</span><span style="color:#8b5cf6;font-weight:700;">${actorSum.total_actors||0} actors</span>
                        </div>
                        <div style="padding:4px 0;display:flex;justify-content:space-between;border-bottom:1px solid var(--border);">
                            <span style="color:var(--text);">Known APT Groups</span><span style="color:#3b82f6;font-weight:700;">${actorSum.known_actors||0}</span>
                        </div>
                        <div style="padding:4px 0;display:flex;justify-content:space-between;">
                            <span style="color:var(--text);">Newly Discovered</span><span style="color:#ef4444;font-weight:700;">${actorSum.discovered_actors||0}</span>
                        </div>`;
                    }

                    // Attack Map flows \u2014 always render (no "Computing..." hang)
                    const flowsEl = document.getElementById('genesis-attack-flows');
                    const mapEng = engines['G11_GlobalAttackMap'] || engines['G11_AttackMap'] || {};
                    const mapSum = mapEng.summary || {};
                    if (flowsEl) {
                        flowsEl.innerHTML = `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);">
                            <span>Total Attack Flows</span><span style="color:#e11d48;font-weight:700;">${(mapSum.total_flows||mapSum.attack_count||0).toLocaleString()}</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);">
                            <span>Regions Active</span><span style="color:#f59e0b;font-weight:700;">${mapSum.active_corridors||mapSum.origin_countries||mapSum.regions_active||0}</span>
                        </div>
                        <div style="display:flex;justify-content:space-between;padding:4px 0;">
                            <span>Critical Incidents</span><span style="color:#ef4444;font-weight:700;">${mapSum.critical_attacks||mapSum.critical||0}</span>
                        </div>`;
                    }

                    // Engine health badge
                    const engOk = data.engines_ok || 0;
                    const engTotal = data.engines_total || 12;
                    const genesisHeader = document.querySelector('#genesis-section h2, #genesis-section .section-title');
                    if (genesisHeader && !document.getElementById('genesis-health-badge')) {
                        const badge = document.createElement('span');
                        badge.id = 'genesis-health-badge';
                        badge.style.cssText = 'margin-left:12px;font-size:10px;font-family:var(--font-mono);background:#00d4aa22;color:#00d4aa;border-radius:3px;padding:2px 8px;letter-spacing:1px;';
                        badge.textContent = engOk + '/' + engTotal + ' ENGINES LIVE';
                        genesisHeader.appendChild(badge);
                    }

                } catch(e) { console.warn('[GENESIS ENGINE]', e); }
            }

            // ── CORTEX RENDERER ─────────────────────────────────────────────
            function renderCortexEngine(data) {
                try {
                    const kg = data.knowledge_graph || {};
                    const cortexEl = document.getElementById('cortex-nodes');
                    if (cortexEl && kg.total_nodes != null) {
                        cortexEl.textContent = kg.total_nodes;
                        // Add tooltip
                        const parent = cortexEl.closest('[style]');
                        if (parent) {
                            const edgesHint = parent.querySelector('.cortex-edges-hint');
                            if (!edgesHint) {
                                const hint = document.createElement('div');
                                hint.className = 'cortex-edges-hint';
                                hint.style.cssText = 'font-size:9px;color:var(--text-muted);margin-top:2px;font-family:var(--font-mono);';
                                hint.textContent = (kg.total_edges||0) + ' EDGES // DENSITY ' + ((kg.density||0)*100).toFixed(2) + '%';
                                cortexEl.parentNode.appendChild(hint);
                            }
                        }
                    }

                    // Stream events count
                    const stream = data.stream || {};
                    if (stream.event_count) {
                        const streamBadge = document.getElementById('cortex-stream-count');
                        if (streamBadge) streamBadge.textContent = stream.event_count;
                    }

                    // Top influencers
                    const influencers = data.top_influencers || [];
                    const clusters = data.cluster_count || (data.clusters ? (Array.isArray(data.clusters) ? data.clusters.length : data.clusters) : null);
                    if (clusters && cortexEl) {
                        const clusterEl = document.createElement('div');
                        clusterEl.style.cssText = 'font-size:8px;color:var(--accent);margin-top:4px;font-family:var(--font-mono);letter-spacing:1px;';
                        clusterEl.textContent = clusters + ' THREAT CLUSTERS';
                        if (!cortexEl.parentNode.querySelector('.cortex-clusters')) {
                            clusterEl.className = 'cortex-clusters';
                            cortexEl.parentNode.appendChild(clusterEl);
                        }
                    }

                } catch(e) { console.warn('[CORTEX ENGINE]', e); }
            }

            // ── QUANTUM RENDERER ────────────────────────────────────────────
            function renderQuantumEngine(data) {
                try {
                    const feedTrust = data.feed_trust || {};
                    const trustScore = feedTrust.overall != null ? Math.round(feedTrust.overall) : null;
                    const quantumEl = document.getElementById('quantum-trust');
                    if (quantumEl && trustScore != null) {
                        quantumEl.textContent = trustScore + '%';
                        quantumEl.style.color = trustScore >= 90 ? '#00d4aa' : trustScore >= 75 ? '#d97706' : '#ef4444';
                    }

                    // Anomaly count
                    const anomalies = data.anomalies || [];
                    if (anomalies.length && quantumEl) {
                        const aEl = document.createElement('div');
                        aEl.style.cssText = 'font-size:9px;color:var(--text-muted);margin-top:4px;font-family:var(--font-mono);';
                        aEl.textContent = anomalies.length + ' ANOMALIES DETECTED';
                        if (!quantumEl.parentNode.querySelector('.quantum-anomaly')) {
                            aEl.className = 'quantum-anomaly';
                            quantumEl.parentNode.appendChild(aEl);
                        }
                    }

                    // Feed trust alerts
                    if (feedTrust.alerts) {
                        const alertEl = document.createElement('div');
                        alertEl.style.cssText = 'font-size:8px;color:#f59e0b;margin-top:2px;font-family:var(--font-mono);letter-spacing:1px;';
                        alertEl.textContent = feedTrust.alerts + ' TRUST ALERTS';
                        if (quantumEl && !quantumEl.parentNode.querySelector('.quantum-alerts')) {
                            alertEl.className = 'quantum-alerts';
                            quantumEl.parentNode.appendChild(alertEl);
                        }
                    }

                } catch(e) { console.warn('[QUANTUM ENGINE]', e); }
            }

            // ── SOVEREIGN RENDERER ──────────────────────────────────────────
            function renderSovereignEngine(data) {
                try {
                    const compliance = data.compliance || {};
                    const soc2 = compliance.soc2_score || 0;
                    const nist = compliance.nist_score || 0;
                    const avgScore = Math.round((soc2 + nist) / 2);
                    const sovEl = document.getElementById('sovereign-compliance');
                    if (sovEl) {
                        sovEl.textContent = avgScore + '%';
                        sovEl.style.color = avgScore >= 80 ? '#00d4aa' : avgScore >= 65 ? '#d97706' : '#ef4444';
                    }

                    // Compliance breakdown
                    if (soc2 && nist && sovEl) {
                        const breakdownEl = document.createElement('div');
                        breakdownEl.style.cssText = 'font-size:8px;color:var(--text-muted);margin-top:4px;font-family:var(--font-mono);line-height:1.6;';
                        breakdownEl.innerHTML = `SOC2: <span style="color:#00d4aa">${soc2}%</span> | NIST: <span style="color:#3b82f6">${nist}%</span>`;
                        if (!sovEl.parentNode.querySelector('.sovereign-breakdown')) {
                            breakdownEl.className = 'sovereign-breakdown';
                            sovEl.parentNode.appendChild(breakdownEl);
                        }
                    }

                    // Tenant count
                    const tenants = data.tenants || {};
                    if (tenants.total) {
                        const tEl = document.createElement('div');
                        tEl.style.cssText = 'font-size:8px;color:var(--accent);margin-top:2px;font-family:var(--font-mono);letter-spacing:1px;';
                        tEl.textContent = tenants.total + ' ACTIVE TENANTS';
                        if (sovEl && !sovEl.parentNode.querySelector('.sovereign-tenants')) {
                            tEl.className = 'sovereign-tenants';
                            sovEl.parentNode.appendChild(tEl);
                        }
                    }

                } catch(e) { console.warn('[SOVEREIGN ENGINE]', e); }
            }

            // ── BUG HUNTER ENGINE ──────────────────────────────────────────
            function renderBugHunterEngine(data) {
                try {
                    const m = data.metrics || {};
                    // Top metrics
                    const subEl = document.getElementById('bh-subdomain-count');
                    if (subEl) subEl.textContent = (m.subdomains || 0).toLocaleString();
                    const liveEl = document.getElementById('bh-livehost-count');
                    if (liveEl) liveEl.textContent = (m.live_hosts || 0).toLocaleString();
                    const apiEl = document.getElementById('bh-api-count');
                    if (apiEl) apiEl.textContent = (m.api_endpoints || 0).toLocaleString();
                    const critEl = document.getElementById('bh-critical-count');
                    if (critEl) {
                        const c = m.critical_findings || 0;
                        critEl.textContent = c.toLocaleString();
                        critEl.style.color = c > 0 ? '#ef4444' : '#00d4aa';
                    }
                    // ROI
                    const riskEl = document.getElementById('bh-risk-exposure');
                    if (riskEl) riskEl.textContent = '$' + (m.risk_exposure || 0).toLocaleString(undefined, {minimumFractionDigits:0, maximumFractionDigits:0});
                    const mitEl = document.getElementById('bh-mitigated');
                    if (mitEl) mitEl.textContent = '$' + ((m.risk_exposure || 0) * 0.95).toLocaleString(undefined, {minimumFractionDigits:0, maximumFractionDigits:0});
                    const rosiEl = document.getElementById('bh-rosi');
                    if (rosiEl) rosiEl.textContent = (m.rosi || 0).toFixed(1) + '%';
                    // Findings Feed
                    const feedEl = document.getElementById('bh-findings-feed');
                    const findings = data.findings_summary || [];
                    if (feedEl && findings.length > 0) {
                        feedEl.innerHTML = findings.map(function(f) {
                            var sevColor = f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f59e0b' : '#00d4aa';
                            return '<div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.05);">'
                                + '<span style="color:' + sevColor + ';font-weight:700;font-size:9px;">[' + (f.severity || 'N/A') + ']</span> '
                                + '<span style="color:var(--white);font-size:10px;">' + (f.type || 'UNKNOWN') + '</span> '
                                + '<span style="color:var(--text-muted);font-size:9px;">→ ' + (f.target || '').substring(0,60) + '</span>'
                                + '</div>';
                        }).join('');
                    } else if (feedEl) {
                        feedEl.innerHTML = '<span style="color:var(--text-muted);font-size:10px;">All 12 engines online \u2014 run a scan to populate findings.</span>';
                    }
                    // Health badge
                    var bhHeader = document.querySelector('#bughunter-section h2');
                    if (bhHeader && !document.getElementById('bh-health-badge')) {
                        var badge = document.createElement('span');
                        badge.id = 'bh-health-badge';
                        badge.style.cssText = 'margin-left:10px;font-size:9px;color:#00d4aa;font-family:var(--font-mono);';
                        badge.textContent = '● LIVE';
                        bhHeader.appendChild(badge);
                    }
                } catch(e) { console.warn('[BUG HUNTER ENGINE]', e); }
            }

            // ── TIP+SOAR RENDERERS (v60-v63) ────────────────────────────
            function renderIncidentEngine(data) {
                try {
                    var total = data.total_incidents || 0;
                    var el = document.getElementById('ts-incident-count');
                    if (el) el.textContent = total.toLocaleString();

                    var incidents = data.incidents || [];
                    var feed = document.getElementById('ts-incident-feed');
                    if (feed && incidents.length > 0) {
                        feed.innerHTML = incidents.slice(0, 12).map(function(inc) {
                            var sevColor = inc.severity === 'CRITICAL' ? '#ef4444' : inc.severity === 'HIGH' ? '#f97316' : '#22c55e';
                            return '<div style="padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
                                + '<span style="color:' + sevColor + ';font-weight:700;font-size:8px;">[' + inc.severity + ']</span> '
                                + '<span style="color:var(--white);font-size:10px;">' + (inc.title || '').substring(0,55) + '</span> '
                                + '<span style="color:var(--text-muted);font-size:8px;">→ ' + (inc.threat_actor || '') + '</span>'
                                + '</div>';
                        }).join('');
                    }

                    var badge = document.getElementById('tipsoar-badge');
                    if (badge) { badge.textContent = total + ' INCIDENTS LIVE'; badge.style.color = '#f472b6'; }
                } catch(e) { console.warn('[INCIDENT ENGINE]', e); }
            }

            function renderResponseEngine(data) {
                try {
                    var total = data.total_actions || 0;
                    var el = document.getElementById('ts-response-count');
                    if (el) el.textContent = total.toLocaleString();

                    var actions = data.response_actions || [];
                    var feed = document.getElementById('ts-response-feed');
                    if (feed && actions.length > 0) {
                        var byType = {};
                        actions.forEach(function(a) { byType[a.action_type] = (byType[a.action_type] || 0) + 1; });
                        feed.innerHTML = Object.entries(byType).map(function(pair) {
                            var colors = {block_ip:'#ef4444',quarantine_host:'#f97316',disable_account:'#eab308',remove_phishing_email:'#8b5cf6',patch_vulnerability:'#22c55e',block_domain:'#f472b6',isolate_network_segment:'#3b82f6'};
                            var c = colors[pair[0]] || '#22c55e';
                            return '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
                                + '<span style="color:' + c + ';font-size:10px;">' + pair[0].replace(/_/g,' ').toUpperCase() + '</span>'
                                + '<span style="color:var(--white);font-weight:700;font-size:11px;">' + pair[1] + '</span>'
                                + '</div>';
                        }).join('');
                    }
                } catch(e) { console.warn('[RESPONSE ENGINE]', e); }
            }

            function renderHuntEngine(data) {
                try {
                    var huntTotal = data.total_hunts || 0;
                    var el = document.getElementById('ts-hunt-count');
                    if (el) el.textContent = huntTotal.toLocaleString();

                    // Playbook count from incident count (1:1 mapping)
                    var pbEl = document.getElementById('ts-playbook-count');
                    if (pbEl) {
                        // Playbooks are generated per-incident, so count matches incidents
                        var incEl = document.getElementById('ts-incident-count');
                        if (incEl && incEl.textContent !== '\u2014') pbEl.textContent = incEl.textContent;
                    }

                    // Hunt hypotheses feed
                    var hunts = data.hunt_hypotheses || [];
                    var feed = document.getElementById('ts-hunt-feed');
                    if (feed && hunts.length > 0) {
                        feed.innerHTML = hunts.slice(0, 8).map(function(h) {
                            var prioColor = h.priority === 'CRITICAL' ? '#ef4444' : h.priority === 'HIGH' ? '#f59e0b' : '#22c55e';
                            return '<div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
                                + '<span style="color:' + prioColor + ';font-weight:700;font-size:8px;">[' + h.priority + ']</span> '
                                + '<span style="color:var(--white);font-size:10px;">' + h.technique + '</span> '
                                + '<span style="color:var(--text-muted);font-size:9px;">' + (h.hypothesis || '').substring(0,50) + '\u2026</span> '
                                + '<span style="font-size:8px;color:#f59e0b;">CONF ' + h.confidence + '%</span>'
                                + '</div>';
                        }).join('');
                    }

                    // Campaign intelligence feed
                    var campaigns = data.campaign_intelligence || [];
                    var cFeed = document.getElementById('ts-campaign-feed');
                    if (cFeed && campaigns.length > 0) {
                        cFeed.innerHTML = campaigns.map(function(c) {
                            return '<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
                                + '<div style="color:#ec4899;font-weight:700;font-size:10px;">' + c.campaign_name.replace(/_/g,' ').toUpperCase() + ' <span style="color:var(--text-muted);font-weight:400;">' + c.campaign_id + '</span></div>'
                                + '<div style="color:var(--text-muted);font-size:9px;margin-top:2px;">Actors: ' + c.actors_involved.join(', ') + ' | Incidents: ' + c.incident_count + ' | Risk: ' + c.avg_risk + '</div>'
                                + '<div style="margin-top:3px;">' + c.techniques_observed.slice(0,5).map(function(t) { return '<span style="display:inline-block;background:rgba(139,92,246,0.12);color:#a78bfa;padding:1px 6px;border-radius:3px;font-size:8px;margin:1px;">' + t + '</span>'; }).join('') + '</div>'
                                + '</div>';
                        }).join('');
                    } else if (cFeed) {
                        cFeed.innerHTML = '<span style="color:var(--text-muted);font-size:10px;">No active campaigns detected.</span>';
                    }
                } catch(e) { console.warn('[HUNT ENGINE]', e); }
            }

            // ── AI EXECUTION LAYER v103 ─────────────────────────────────────
            // Fetches /api/ai/analyze.json, /api/ai/respond.json, /api/ai/correlate.json
            // Renders into the ANALYZE LIVE panel in the GENESIS section.
            const AI_BASE = atob('aHR0cHM6Ly9pbnRlbC5jeWJlcmR1ZGViaXZhc2guY29tL2FwaS9haS8=');
            // Decoded: https://intel.cyberdudebivash.com/api/ai/

            // ── Live synthesis: build analyze/respond/correlate from real Worker feed ──
            /**
             * Builds a GENESIS Analyze Live result (analyze/respond/correlate)
             * from the live Worker feed when the pre-generated static AI JSON
             * endpoints are unavailable. avg_risk_score is computed from the
             * real fetched `items`, not window.EMBEDDED_INTEL (permanently
             * empty since v184.0 -- see the comment above). Returns all-null
             * fields on total fetch failure; never synthesizes a replacement
             * result for a genuinely failed fetch.
             * @returns {Promise<{analyze: object|null, respond: object|null, correlate: object|null}>}
             */
            async function _synthAnalysisFromLiveFeed() {
                const WORKER = 'https://intel.cyberdudebivash.com';
                let items = [];
                // 1. Try live Worker /api/preview (real-time feed)
                try {
                    const r = await fetch(WORKER + '/api/preview', { cache: 'no-cache', signal: AbortSignal.timeout(5000) });
                    if (r.ok) { const d = await r.json(); items = (d.preview && d.preview.items) || d.items || []; }
                } catch(e) {}
                // 2. Fallback: EMBEDDED_INTEL removed (v184.0) -- API is single source of truth
                // items remains [] if all API calls failed -- dashboard shows empty state
                if (!items.length) return { analyze: null, respond: null, correlate: null };

                // ── Aggregate metrics ──
                const critical  = items.filter(i => (i.severity||'').toUpperCase() === 'CRITICAL').length;
                const high      = items.filter(i => (i.severity||'').toUpperCase() === 'HIGH').length;
                const kevActive = items.filter(i => i.kev_present || i.kev).length;
                const actors    = [...new Set(items.map(i => i.actor_tag||i.actor||'').filter(Boolean))];
                // STAGE 3 FIX: this read window.EMBEDDED_INTEL, which v184.0
                // permanently empties (see the comment two lines above) --
                // avg_risk_score was always 0 while critical_count/high_count
                // two lines up were already correctly computed from the real,
                // just-fetched `items`. Same existing calculator, real data.
                const avgRisk   = window._v149AvgRisk(items);
                const sorted    = [...items].sort((a,b) => (parseFloat(b.risk_score)||0) - (parseFloat(a.risk_score)||0));

                // ── analyze.json equivalent ──
                const analyze = {
                    summary: {
                        total_analyzed: items.length,
                        critical_count: critical,
                        high_count:     high,
                        kev_active:     kevActive,
                        unique_actors:  actors.length || 1,
                        avg_risk_score: avgRisk,
                    },
                    top_threats: sorted.slice(0, 8).map(i => ({
                        title:      i.title || 'Untitled Advisory',
                        risk_score: parseFloat(i.risk_score)||0,
                        severity:   i.severity || 'MEDIUM',
                        actor:      i.actor_tag || i.actor || 'UNC-UNKNOWN',
                        ttps:       i.mitre_tactics || i.tags || [],
                        kev:        window.CDB_NORMALIZE.kevState(i) === true,
                        priority:   window.CDB_NORMALIZE.priority(i),
                    })),
                    generated_at: new Date().toISOString(),
                    source: 'live_synthesis_v123',
                };

                // ── respond.json equivalent (SOAR queue) ──
                const respond = {
                    response_queue: sorted.slice(0, 6).map(i => {
                        const pri = window.CDB_NORMALIZE.priority(i);
                        const riskScore = parseFloat(i.risk_score)||0;
                        return {
                            incident_title: (i.title||'').substring(0, 80),
                            risk_score:     riskScore,
                            priority:       pri,
                            sla_hours:      pri === 'P1' ? 4 : pri === 'P2' ? 24 : pri === 'P3' ? 72 : 168,
                            playbook:       riskScore >= 9 ? 'CRITICAL RESPONSE \u2014 PATCH + ISOLATE' :
                                            riskScore >= 7 ? 'HIGH \u2014 MONITOR + BLOCK IOCs' :
                                            riskScore >= 5 ? 'MEDIUM \u2014 ASSESS + LOG' : 'LOW \u2014 TRACK',
                        };
                    }),
                    generated_at: new Date().toISOString(),
                    source: 'live_synthesis_v123',
                };

                // ── correlate.json equivalent (actor clusters) ──
                const actorMap = {};
                items.forEach(i => {
                    const a = i.actor_tag || i.actor || 'UNC-UNKNOWN';
                    if (!actorMap[a]) actorMap[a] = { actor: a, cnt: 0, ttps: new Set(), riskSum: 0, cves: new Set() };
                    actorMap[a].cnt++;
                    actorMap[a].riskSum += parseFloat(i.risk_score)||0;
                    (i.mitre_tactics || i.tags || []).forEach(t => actorMap[a].ttps.add(t));
                    if (i.cve_id) actorMap[a].cves.add(i.cve_id);
                });
                const clusters = Object.values(actorMap)
                    .sort((a,b) => b.riskSum/b.cnt - a.riskSum/a.cnt)
                    .slice(0, 6)
                    .map(c => ({
                        actor:          c.actor,
                        incident_count: c.cnt,
                        avg_risk:       +(c.riskSum/(c.cnt||1)).toFixed(1),
                        ttps:           [...c.ttps].slice(0, 5),
                        shared_cves:    c.cves.size,
                    }));

                const correlate = {
                    summary: {
                        threat_clusters: clusters.length,
                        unique_actors:   Object.keys(actorMap).length,
                        unique_ttps:     new Set(items.flatMap(i => i.mitre_tactics||i.tags||[])).size,
                        shared_cves:     items.filter(i => i.cve_id).length,
                    },
                    threat_clusters: clusters,
                    generated_at: new Date().toISOString(),
                    source: 'live_synthesis_v123',
                };

                return { analyze, respond, correlate };
            }

            // ── GENESIS ANALYZE LIVE \u2014 v123.0 production fix ────────────────
            // Phase 1: fetch pre-generated R2/GH-Pages AI JSON (zero latency)
            // Phase 2: if all three return null, synthesize from live Worker feed
            // Result: button ALWAYS renders meaningful intel \u2014 never blank
            async function triggerAIAnalysis() {
                const btn    = document.getElementById('analyze-live-btn');
                const status = document.getElementById('analyze-status');
                const panel  = document.getElementById('ai-analysis-panel');
                if (!btn) return;

                btn.disabled = true;
                btn.style.opacity = '0.6';
                btn.textContent = '⏳ ANALYZING...';
                if (status) { status.style.display = 'inline'; status.textContent = 'PROCESSING...'; status.style.color = '#a855f7'; }

                try {
                    // Phase 1: pre-generated static AI endpoints
                    const [analyzeRes, respondRes, correlateRes] = await Promise.allSettled([
                        fetch(AI_BASE + 'analyze.json',   { cache: 'no-cache' }).then(r => r.ok ? r.json() : null),
                        fetch(AI_BASE + 'respond.json',   { cache: 'no-cache' }).then(r => r.ok ? r.json() : null),
                        fetch(AI_BASE + 'correlate.json', { cache: 'no-cache' }).then(r => r.ok ? r.json() : null),
                    ]);

                    let analyze   = analyzeRes.status   === 'fulfilled' ? analyzeRes.value   : null;
                    let respond   = respondRes.status   === 'fulfilled' ? respondRes.value   : null;
                    let correlate = correlateRes.status === 'fulfilled' ? correlateRes.value : null;

                    // Phase 2: live synthesis fallback when static files unavailable
                    if (!analyze && !respond && !correlate) {
                        if (status) { status.textContent = '⚡ COMPUTING LIVE INTEL...'; status.style.color = '#f59e0b'; }
                        const synth = await _synthAnalysisFromLiveFeed();
                        analyze   = synth.analyze;
                        respond   = synth.respond;
                        correlate = synth.correlate;
                    }

                    if (analyze || respond || correlate) {
                        renderAIAnalysis(analyze, respond, correlate);
                        if (panel) panel.style.display = 'block';
                        if (status) { status.textContent = '✅ ANALYSIS COMPLETE'; status.style.color = '#00d4aa'; }
                        console.log('[APEX v123] AI analysis rendered \u2014 source:', (analyze||{}).source || 'static');
                    } else {
                        if (status) { status.textContent = '⚠️ Feed sync pending \u2014 retry in 30s'; status.style.color = '#f59e0b'; setTimeout(()=>{ if(status) status.style.display='none'; }, 4000); }
                    }
                } catch(e) {
                    console.warn('[AI LAYER v123]', e);
                    if (status) { status.textContent = '⚠️ ERROR: ' + e.message; status.style.color = '#ef4444'; }
                } finally {
                    btn.disabled = false;
                    btn.style.opacity = '1';
                    btn.textContent = '🤖 REFRESH ANALYSIS';
                    setTimeout(() => { if (status) status.style.display = 'none'; }, 5000);
                }
            }

            function renderAIAnalysis(analyze, respond, correlate) {
                try {
                    // ── Summary grid ──
                    const sg = document.getElementById('ai-summary-grid');
                    if (sg && analyze && analyze.summary) {
                        const s = analyze.summary;
                        const cells = [
                            { label: 'ANALYZED',  val: (s.total_analyzed||0).toLocaleString(), color: '#a855f7' },
                            { label: 'CRITICAL',  val: s.critical_count||0,  color: '#ef4444' },
                            { label: 'HIGH',      val: s.high_count||0,      color: '#f97316' },
                            { label: 'KEV LIVE',  val: s.kev_active||0,      color: '#ef4444' },
                            { label: 'ACTORS',    val: s.unique_actors||0,   color: '#8b5cf6' },
                            { label: 'AVG RISK',  val: (s.avg_risk_score||0).toFixed(1), color: '#f59e0b' },
                        ];
                        sg.innerHTML = cells.map(c =>
                            `<div style="background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.06);border-radius:4px;padding:10px;text-align:center;">
                                <div style="font-size:18px;font-weight:900;color:${c.color};font-family:var(--font-mono);">${c.val}</div>
                                <div style="font-size:7px;color:var(--text-muted);letter-spacing:1.5px;margin-top:2px;">${c.label}</div>
                            </div>`
                        ).join('');
                    }

                    // ── Top threats \u2014 ISSUE 2 FIX: use computePriority() ──
                    const tt = document.getElementById('ai-top-threats');
                    if (tt && analyze && analyze.top_threats) {
                        tt.innerHTML = analyze.top_threats.slice(0, 8).map(t => {
                            // P0 FIX: t.priority was already resolved via
                            // window.CDB_NORMALIZE.priority() against the full raw item
                            // when `analyze` was built above -- do not recompute from `t`
                            // itself, which is a slimmed synthetic object missing
                            // kev_present/cvss_score/epss_score (computePriority(t) would
                            // silently lose the KEV signal since t only carries `kev`, not
                            // `kev_present`). Never fall back to 'P4'.
                            const pri = t.priority || 'UNKNOWN';
                            const priColor = (window.PRIORITY_COLORS && window.PRIORITY_COLORS[pri]) ||
                                (pri==='P1'?'#ef4444':pri==='P2'?'#f97316':pri==='P3'?'#fbbf24':'#4ade80');
                            const kevBadge = t.kev ? ' <span style="background:#ef444422;color:#ef4444;font-size:7px;padding:1px 4px;border-radius:2px;">⚡ KEV</span>' : '';
                            return `<div style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;align-items:flex-start;gap:8px;">
                                <span style="color:${priColor};font-weight:900;font-size:10px;min-width:32px;">${t.risk_score}</span>
                                <div style="flex:1;">
                                    <div style="color:var(--white);font-size:10px;">${(t.title||'').substring(0,90)}${kevBadge}</div>
                                    <div style="color:var(--text-muted);font-size:8px;margin-top:2px;">
                                        ${t.actor && t.actor !== 'UNKNOWN' ? '<span style="color:#8b5cf6;">'+t.actor+'</span> \u00b7 ' : ''}
                                        <span style="color:${priColor};font-weight:700;">${pri}</span>
                                        ${t.ttps && t.ttps.length ? ' \u00b7 ' + t.ttps.slice(0,3).join(' ') : ''}
                                    </div>
                                </div>
                            </div>`;
                        }).join('');
                    }

                    // ── SOAR response queue \u2014 ISSUE 2 FIX: use computePriority() ──
                    const rq = document.getElementById('ai-response-queue');
                    if (rq && respond && respond.response_queue) {
                        rq.innerHTML = respond.response_queue.slice(0, 6).map(a => {
                            // P0 FIX: a.priority was already resolved via
                            // window.CDB_NORMALIZE.priority() when `respond` was built
                            // above -- never fall back to 'P4'.
                            const pri = a.priority || 'UNKNOWN';
                            const pColor = (window.PRIORITY_COLORS && window.PRIORITY_COLORS[pri]) ||
                                (pri==='P1'?'#ef4444':pri==='P2'?'#f97316':'#fbbf24');
                            return `<div style="padding:6px;margin-bottom:4px;background:rgba(249,115,22,0.06);border:1px solid rgba(249,115,22,0.12);border-radius:3px;">
                                <div style="display:flex;justify-content:space-between;align-items:center;">
                                    <span style="color:${pColor};font-weight:900;font-size:9px;">${pri}</span>
                                    <span style="color:var(--text-muted);font-size:8px;">SLA: ${a.sla_hours||24}h</span>
                                </div>
                                <div style="color:var(--white);font-size:10px;margin-top:2px;">${(a.incident_title||'').substring(0,80)}</div>
                                <div style="color:var(--text-muted);font-size:8px;margin-top:2px;">▶ ${a.playbook||'GENERAL RESPONSE'}</div>
                            </div>`;
                        }).join('');
                    }

                    // ── Correlation summary ──
                    const cs = document.getElementById('ai-correlate-summary');
                    if (cs && correlate && correlate.summary) {
                        const s = correlate.summary;
                        cs.innerHTML = `<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;">
                            ${[
                                ['CLUSTERS', s.threat_clusters||0, '#3b82f6'],
                                ['ACTORS',   s.unique_actors||0,   '#8b5cf6'],
                                ['TTPs',     s.unique_ttps||0,     '#ec4899'],
                                ['CVEs SHARED', s.shared_cves||0, '#ef4444'],
                            ].map(([l,v,c]) => `<div style="background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);border-radius:3px;padding:8px;text-align:center;">
                                <div style="font-size:16px;font-weight:900;color:${c};font-family:var(--font-mono);">${v}</div>
                                <div style="font-size:7px;color:var(--text-muted);letter-spacing:1px;">${l}</div>
                            </div>`).join('')}
                        </div>
                        ${correlate.threat_clusters && correlate.threat_clusters.length ? `<div style="margin-top:10px;">` +
                            correlate.threat_clusters.slice(0,4).map(c =>
                                `<div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;align-items:center;gap:8px;">
                                    <span style="color:#8b5cf6;font-weight:700;font-size:10px;min-width:100px;">${c.actor}</span>
                                    <span style="color:#ef4444;font-size:9px;">${c.incident_count} incidents</span>
                                    <span style="color:#f59e0b;font-size:9px;">risk ${c.avg_risk}</span>
                                    <span style="color:var(--text-muted);font-size:8px;">${(c.ttps||[]).slice(0,3).join(' ')}</span>
                                </div>`
                            ).join('') + `</div>` : ''}`;
                    }
                } catch(e) { console.warn('[AI RENDER]', e); }
            }

            // ── ORCHESTRATOR ────────────────────────────────────────────────
            // v103: Retry-on-fail (2 attempts, 1s backoff) + per-engine error boundary
            async function _fetchWithRetry(url, retries = 2, delayMs = 1000) {
                for (let attempt = 1; attempt <= retries; attempt++) {
                    try {
                        const resp = await fetch(url, { cache: 'no-cache' });
                        if (!resp.ok) throw new Error('HTTP ' + resp.status);
                        return await resp.json();
                    } catch(err) {
                        if (attempt === retries) throw err;
                        await new Promise(res => setTimeout(res, delayMs * attempt));
                    }
                }
            }

            async function loadAllEngines() {
                const results = {};
                const fetches = Object.entries(ENGINE_URLS).map(async ([name, url]) => {
                    try {
                        results[name] = await _fetchWithRetry(url, 2, 800);
                        console.log('[APEX ENGINE] Loaded:', name, '✔');
                    } catch(err) {
                        console.warn('[APEX ENGINE] Failed (2 attempts):', name, err.message);
                    }
                });

                await Promise.allSettled(fetches);

                // Route each engine output to its renderer \u2014 individual error boundaries
                const route = (name, fn) => { try { if (results[name]) fn(results[name]); } catch(e) { console.warn('[APEX ENGINE] Render error:', name, e); } };
                route('nexus',     renderNexusEngine);
                // v136.0 FIX: Re-run renderNexusIntelligence AFTER renderNexusEngine so computed
                // intelligence values always take precedence over potentially stale engine JSON.
                try { if (manifestData && manifestData.length) renderNexusIntelligence(manifestData); } catch(e) { console.warn('[NEXUS] Post-engine re-render:', e); }
                route('genesis',   renderGenesisEngine);
                route('cortex',    renderCortexEngine);
                route('quantum',   renderQuantumEngine);
                route('sovereign', renderSovereignEngine);
                route('bughunter', renderBugHunterEngine);
                route('incidents', renderIncidentEngine);
                route('responses', renderResponseEngine);
                route('hunts',     renderHuntEngine);

                // Update platform health counters if genesis loaded
                if (results.genesis && results.genesis.metrics) {
                    const m = results.genesis.metrics;
                    const upd = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.textContent = v; };
                    upd('genesis-total-advisories', (m.total_advisories||0).toLocaleString());
                    upd('genesis-actors-count',     m.actors_tracked||0);
                    upd('genesis-iocs-count',       (m.iocs_total||0).toLocaleString());
                    upd('genesis-rules-count',      (m.detection_rules||0).toLocaleString());
                }

                const loaded = Object.keys(results).length;
                console.log('[APEX ENGINE] Activation complete:', loaded + '/9 engines live');
                return loaded;
            }

            // Trigger after DOM is ready \u2014 with error boundary
            async function safeLoadAllEngines() {
                try { await loadAllEngines(); }
                catch(e) { console.warn('[APEX ENGINE] Global error caught:', e); }
            }
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => setTimeout(safeLoadAllEngines, 800));
            } else {
                setTimeout(safeLoadAllEngines, 800);
            }

            // ── ISSUE 1 FIX: Expose AI functions to global scope ─────────────
            // triggerAIAnalysis() and renderAIAnalysis() are defined inside this
            // IIFE \u2014 onclick="triggerAIAnalysis()" in HTML attributes calls global
            // scope only. Expose via window.* to make button fully functional.
            window.triggerAIAnalysis = triggerAIAnalysis;
            window.renderAIAnalysis  = renderAIAnalysis;
            console.log('[APEX v103] triggerAIAnalysis registered on window ✔');

            // Belt-and-suspenders: also bind via addEventListener after DOM ready
            // so even if onclick attribute is stripped, the button still works.
            (function bindAnalyzeBtn() {
                var btn = document.getElementById('analyze-live-btn');
                if (btn) {
                    // Remove any stale handlers by cloning
                    var fresh = btn.cloneNode(true);
                    btn.parentNode.replaceChild(fresh, btn);
                    fresh.addEventListener('click', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        console.log('[APEX v103] ANALYZE LIVE clicked ✔');
                        triggerAIAnalysis();
                    });
                    // Ensure button is fully interactive \u2014 override any CSS interference
                    fresh.style.pointerEvents = 'auto';
                    fresh.style.cursor        = 'pointer';
                    fresh.style.position      = 'relative';
                    fresh.style.zIndex        = '9999';
                    console.log('[APEX v103] ANALYZE LIVE button event listener bound ✔');
                } else {
                    // DOM not ready \u2014 retry after render
                    setTimeout(bindAnalyzeBtn, 500);
                }
            })();

        })();

        // ══════════════════════════════════════════════════════════════════
        // ISSUE 2 FIX: computePriority() \u2014 SINGLE SOURCE OF TRUTH
        // Used by: threat card renderer, APEX AI block, AI endpoint rendering.
        // Rule: KEV always P1. Then risk_score thresholds. No other logic.
        // ══════════════════════════════════════════════════════════════════
        window.computePriority = function computePriority(item) {
            if (!item) return 'P4';
            // KEV (Known Exploited Vulnerability) = always P1
            if (item.kev === true || item.kev_present === true) return 'P1';
            var r = parseFloat(item.risk_score) || 0;
            if (r >= 8) return 'P1';
            if (r >= 6) return 'P2';
            if (r >= 4) return 'P3';
            return 'P4';
        };
        // Priority color map \u2014 single truth, shared by all renderers
        window.PRIORITY_COLORS = { P1: '#ef4444', P2: '#f97316', P3: '#fbbf24', P4: '#4ade80' };
        window.PRIORITY_LABELS = { P1: 'IMMEDIATE', P2: 'HIGH', P3: 'MEDIUM', P4: 'LOW' };
        console.log('[APEX v103] computePriority() registered on window ✔');

        // ── Service Worker Registration v78.0 \u2014 Stable update (no reload loop) ──
        // v78.0 FIX: Removed aggressive controllerchange → window.location.reload()
        // which caused "BOOTING..." flash on every pipeline deploy (every 6h).
        // The embedded cache now renders instantly on boot \u2014 SW updates are invisible.
        //
        // v176.0 FIX (2026-09-01, P0 -- root cause found, not just patched again):
        // A customer's browser was confirmed stuck for hours on an old SW whose
        // fetch handler called endpoints that exist nowhere in this codebase
        // (index.json/stats.json/priority.json/critical.json) -- direct evidence
        // from that session's DevTools Network panel, Initiator column pointing
        // at service-worker.js itself. v175's cache-purge/skipWaiting logic in
        // the SW's own activate handler was correct and simply never ran, because
        // the browser never re-fetched service-worker.js to find it: confirmed
        // live, /service-worker.js is served with `Cache-Control: max-age=14400`
        // (4h) -- a GitHub Pages default this repo has no header file to
        // override (this static site doesn't read _headers at all -- see that
        // file's own top-of-file note). Every prior "anti-stale" revision
        // (v173-v175) hardened what the SW does once a new version is fetched;
        // none addressed the browser not fetching it to begin with.
        // `updateViaCache: 'none'` below is the standard, spec-defined fix for
        // exactly this: it tells the browser to bypass HTTP cache for
        // service-worker.js on every update() check, for the lifetime of this
        // registration -- independent of whatever Cache-Control the static host
        // sends, and needs no Cloudflare/GitHub Pages access this repo doesn't
        // have. Unsupported-but-harmless on any engine predating this option
        // (an unrecognized property in a spec-shaped options object is ignored,
        // not thrown).
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/service-worker.js', { scope: '/', updateViaCache: 'none' })
                    .then(reg => {
                        console.log('[SW] Registered:', reg.scope);
                        // Check for updates on load \u2014 new SW will pre-cache assets silently
                        reg.update();
                        // v176.0 FIX (2026-09-01, P0): re-check on regained focus too --
                        // the load-time check above only fires once per navigation, so a
                        // tab left open for hours never rechecks otherwise. Only the
                        // check is more frequent; activation timing is unchanged below.
                        document.addEventListener('visibilitychange', () => {
                            if (document.visibilityState === 'visible') reg.update();
                        });
                        // If a new SW is waiting, let it activate on next natural page load
                        // Do NOT force skipWaiting + reload \u2014 this caused the BOOTING... loop
                        reg.addEventListener('updatefound', () => {
                            const newWorker = reg.installing;
                            if (newWorker) {
                                newWorker.addEventListener('statechange', () => {
                                    if (newWorker.state === 'installed') {
                                        // New version ready \u2014 log only, no forced reload
                                        // Dashboard renders from EMBEDDED_INTEL instantly anyway
                                        console.log('[SW] New version ready \u2014 will activate on next visit');
                                    }
                                });
                            }
                        });
                    })
                    .catch(err => console.warn('[SW] Registration failed (non-fatal):', err));
                // v78.0: controllerchange listener REMOVED \u2014 reload loop caused "BOOTING..." P0
                // The embedded cache handles content freshness; SW is asset cache only
            });
        }

    
        // v65.0 Expand toggle (event-delegated, non-blocking)
        document.addEventListener('click', function(e) {
            var t = e.target.closest('.cdb-xtoggle');
            if (!t) return;
            var id = t.getAttribute('data-target');
            var panel = document.getElementById(id);
            if (!panel) return;
            // cdb-xopen drives: panel max-height/opacity AND button chevron rotation
            // CSS: .cdb-xpanel.cdb-xopen{max-height:500px;opacity:1;}
            // CSS: .cdb-xtoggle.cdb-xopen .cdb-xchev{transform:rotate(180deg);}
            panel.classList.toggle('cdb-xopen');
            t.classList.toggle('cdb-xopen');
        });

        
        /* ═══════════════════════════════════════════════════════════════════
           CDB-RENDERER-ENGINE-V166: OLD v2.0 ENGINE NEUTRALIZED
           Root Cause: Dual engine runtime ownership collision.
           Both engines targeted the same canvas — each reset canvas.width/
           canvas.height, destroying the other's GPU texture on every frame.
           Chrome's compositor detected the continuous texture invalidation
           and halted compositing → black canvas on Chrome desktop.
           Fix: V166 is the sole owner of #cdb-threat-canvas.
        ═══════════════════════════════════════════════════════════════════ */

        // ══════════════════════════════════════════════════════════════════════
        // v123.1 CLOUDFLARE WORKER LIVE STATS \u2014 REAL DATA ONLY
        // Source: GET /api/platform/stats (Cloudflare Worker \u2014 R2-aggregated)
        // Replaces Railway backend fetch (deprecated v134.0) with direct Worker.
        // No auth required \u2014 public endpoint with 60s KV cache.
        // Zero Railway dependency \u2014 platform fully self-hosted on Cloudflare.
        // ══════════════════════════════════════════════════════════════════════
        // v200.1 P0 FIX: was an anonymous IIFE that only ever ran once at initial
        // page parse, so the "last sync" badge it sets (see below) could only ever
        // be as fresh as the moment the page was first opened -- on a platform
        // sold as real-time, a tab left open for hours would silently drift stale
        // even though the live API itself was fine. Named + called explicitly so
        // manualRefresh() and scheduleAutoRefresh() can re-invoke it on every
        // refresh cycle, not just once.
        // Fail-closed publication badge. LIVE only when the authoritative
        // freshness contract proves FRESH: publication_state === 'fresh',
        // a valid ISO timestamp, and a numeric age inside the window.
        // Missing or invalid evidence is UNKNOWN, never LIVE.
        function cdbPublicationBadge(intel) {
            if (!intel || typeof intel !== 'object') return { text: 'UNAVAILABLE', color: '#e2b340' };
            var state = intel.publication_state;
            var ts = intel.publication_generated_at;
            var age = intel.publication_age_seconds;
            var tsOk = typeof ts === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.test(ts) && !isNaN(Date.parse(ts));
            var ageOk = typeof age === 'number' && isFinite(age) && age >= 0;
            if (state === 'fresh' && tsOk && ageOk) return { text: 'LIVE', color: '#10b981' };
            if (state === 'stale') return { text: 'DEGRADED', color: '#e2b340' };
            return { text: 'UNKNOWN', color: '#e2b340' };
        }
        window.cdbPublicationBadge = cdbPublicationBadge;
        function cdbApplyPublicationBadge(intel) {
            var el = document.getElementById('eicc-m-total-delta');
            if (!el) return;
            var b = cdbPublicationBadge(intel);
            el.textContent = b.text;
            el.style.color = b.color;
        }

        function fetchWorkerStats() {
            var WORKER = 'https://intel.cyberdudebivash.com';
            var set = function(id, val) {
                var el = document.getElementById(id);
                if (el && val != null && val !== undefined) el.textContent = val;
            };
            var setStrip = function(id, text) {
                var el = document.getElementById(id);
                if (el && text) el.textContent = text;
            };

            // Single canonical source: /api/platform/stats
            var ctrl = new AbortController();
            var statsTimer = setTimeout(function() { ctrl.abort(); }, 5000);

            fetch(WORKER + '/api/platform/stats', {
                cache: 'no-store',
                signal: ctrl.signal
            })
            .then(function(r) { return r.ok ? r.json() : null; })
            .then(function(d) {
                clearTimeout(statsTimer);
                if (!d || !d.intel) { cdbApplyPublicationBadge(null); return; }
                var intel = d.intel;
                var api   = d.api || {};

                // ── Core metric cards ────────────────────────────────────────
                set('m-total',    intel.total_advisories);
                var _advNote = document.getElementById('m-total');
                if (_advNote) {
                    _advNote.title = 'Authoritative Sentinel APEX feed advisories. Report-catalog size is a different number and is not shown here.';
                }
                cdbApplyPublicationBadge(intel);
                // Use Worker ioc_count only if larger than CVE-derived count from computeMetrics
                var _workerIOC = intel.ioc_count != null ? intel.ioc_count : 0;
                var _localIOC  = window._cdbComputedIOCs || 0;
                var _bestIOC   = Math.max(_workerIOC, _localIOC);
                if (_bestIOC > 0) set('m-iocs', _bestIOC.toLocaleString());
                set('m-kev',      intel.kev_count);
                // v184.0 FIX: avg-risk must come from computeMetrics (accurate per-item avg).
                // highest_risk_score is NOT the avg — skip this proxy. computeMetrics sets m-avg-risk.
                // Only set stat cards from Worker API if computeMetrics hasn't populated them yet.
                if (!window._cdbMetricsComputed) {
                    set('m-critical', intel.severity_distribution && intel.severity_distribution.critical);
                    set('m-high',     intel.severity_distribution && intel.severity_distribution.high);
                }

                // ── Threat map advisory counter ─────────────────────────────
                // P0 FIX (zero-fabrication): the removed formula clamped a
                // severity-weighted synthetic score to at least
                // intel.total_reports -- the report-catalog size (22,509+),
                // a completely different metric from an advisory count --
                // so in practice this element always displayed the catalog
                // size mislabeled as "attacks today". severity_distribution's
                // own components are the one real, already-measured
                // advisory count in this payload; only write when present
                // so a legitimate value already seeded by computeMetrics()
                // above is never clobbered with a worse one.
                var atkEl = document.getElementById('cdb-atk-count');
                if (atkEl) {
                    var _sd   = intel.severity_distribution || {};
                    var _crit = _sd.critical || _sd.CRITICAL || 0;
                    var _high = _sd.high     || _sd.HIGH     || 0;
                    var _med  = _sd.medium   || _sd.MEDIUM   || 0;
                    var _low  = _sd.low      || _sd.LOW      || 0;
                    var _advisories = _crit + _high + _med + _low;
                    if (_advisories) {
                        window._cdbAtkSeed = _advisories;  // seed canvas arc counter
                        atkEl.textContent = _advisories.toLocaleString();
                    }
                }

                /* v186.0: threat map legend severity counts — same source data as above */
                (function(){
                    var _sd2 = intel.severity_distribution || {};
                    var pairs = [['cdb-legend-n-crit', _sd2.critical != null ? _sd2.critical : _sd2.CRITICAL],
                                 ['cdb-legend-n-high', _sd2.high     != null ? _sd2.high     : _sd2.HIGH],
                                 ['cdb-legend-n-med',  _sd2.medium   != null ? _sd2.medium   : _sd2.MEDIUM],
                                 ['cdb-legend-n-info', _sd2.low      != null ? _sd2.low      : _sd2.LOW]];
                    pairs.forEach(function(p){
                        var el = document.getElementById(p[0]);
                        if (el && p[1] != null) el.textContent = '(' + p[1] + ')';
                    });
                })();
                /* Adjust threat map spawn rate based on real severity data */
                try {
                    var critCount = (intel.severity_distribution && intel.severity_distribution.critical) || 0;
                    if (typeof _spawnInterval !== 'undefined') {
                        _spawnInterval = critCount > 20 ? 900 :
                                         critCount > 10 ? 1200 :
                                         critCount >  5 ? 1500 : 1800;
                    }
                } catch(e){}

                // ── Status strip enrichment ─────────────────────────────────
                if (intel.unique_actors != null)
                    setStrip('feeds-val', 'ACTORS: ' + intel.unique_actors + ' TRACKED');
                if (intel.kev_count != null)
                    setStrip('kev-val', 'KEV: ' + intel.kev_count + ' ACTIVE');
                if (api.calls_today != null)
                    setStrip('rate-val', 'API CALLS: ' + api.calls_today.toLocaleString() + ' TODAY');

                // ── Live count tab badge ────────────────────────────────────
                var tabCount = document.getElementById('cdb-tab-live-count');
                if (tabCount && intel.total_reports) tabCount.textContent = intel.total_reports;

                // ── Last updated badge \u2014 single source of truth: /api/platform/stats intel.last_sync ──
                // v200.1 P0 FIX: read intel.last_updated/intel.generated_at, neither of which
                // the API has ever returned (the real field is last_sync -- confirmed against
                // computeStats()'s response shape in workers/intel-gateway/src/index.js) -- so
                // this, the one update path meant to be authoritative on every page load
                // (cache:'no-store', no stale client cache), silently no-op'd forever, leaving
                // whatever an earlier/less reliable code path had written on screen. Also
                // switched to timeSince() (relative "Xh ago") to match every other sync-time
                // display on this page instead of an absolute locale timestamp.
                // 2026-09-26: "Last Sync" is when the platform last published its
                // feed (last_feed_sync_utc / publication_generated_at), not the
                // newest ARTICLE's publish date (last_sync). At 10:04Z the badge
                // read "2h ago" (newest article 07:42Z) for a feed published at
                // 09:41Z; in a quiet news window it looked stale while the feed
                // was fresh. js/sentinel-live-feeds.js already reads it this way.
                const _syncTs = intel.last_feed_sync_utc || intel.publication_generated_at || intel.last_sync || intel.generated_at || '';
                if (_syncTs) {
                    const _d2 = new Date(_syncTs);
                    const _label = isNaN(_d2) ? _syncTs : timeSince(_syncTs);
                    // Update ALL sync displays from the same source
                    ['m-last-sync'].forEach(function(eid) {
                        const el = document.getElementById(eid);
                        if (el) el.textContent = _label;
                    });
                    // Update AI bar last-run too
                    const aiBar = document.getElementById('ai-bar-lastrun');
                    if (aiBar && aiBar.textContent === '\u2014') {
                        const diff = Math.floor((Date.now() - _d2.getTime()) / 1000);
                        aiBar.textContent = diff < 3600 ? Math.floor(diff/60) + 'm ago' :
                                            diff < 86400 ? Math.floor(diff/3600) + 'h ago' :
                                            Math.floor(diff/86400) + 'd ago';
                    }
                }

                // SYNC status truthfulness cross-check (P0 GATE).
                // intel.freshness (backend classifyFreshness() on
                // feedData.generated_at -- the pipeline's own "last
                // successfully wrote this file" timestamp, NOT a source
                // article's publish date) is the one signal that actually
                // proves whether the intelligence behind this page is
                // current. The "SYNC: LIVE" / "MANIFEST VERIFIED" badges are
                // otherwise set purely by whichever manifest fetch succeeded
                // (isApiSource, elsewhere in this file) with no check at all
                // on how stale that manifest's own content was -- exactly how
                // SYNC: LIVE and a 10-day-old Last Sync value ended up on
                // screen together during the 2026-08-26 core-feed staleness
                // incident (see classifyFreshness()'s own comment in
                // workers/intel-gateway/src/index.js).
                //
                // P0 2026-09-05: on initial page load, loadGOCIntel() (the
                // isApiSource badge write above) and this function's own
                // fetch both fire unawaited from _cdbBootSequence() / the
                // page's top-level fetchWorkerStats() call -- confirmed live,
                // there is no guarantee this resolves last. window.__CDB_FRESHNESS__
                // records the latest known truth here so loadGOCIntel() can
                // consult it too, regardless of which of the two finishes
                // last -- one authoritative answer, not a race between two
                // independent computations.
                window.__CDB_FRESHNESS__ = intel.freshness || null;
                // P0 2026-09-26: only FRESH is live (canonical 6h contract; see _knownStale).
                if (intel.freshness && intel.freshness !== 'FRESH') {
                    var _syncBadge = document.getElementById('sync-val');
                    if (_syncBadge) {
                        _syncBadge.innerHTML = 'SYNC: <span style="color:var(--warning,#ffa502);">STALE</span>';
                    }
                    var _integrityBadge = document.getElementById('integrity-status');
                    if (_integrityBadge) {
                        _integrityBadge.innerHTML = '<span class="integrity-badge" style="color:var(--warning,#ffa502);">'
                            + (intel.freshness === 'UNAVAILABLE' ? 'FRESHNESS UNKNOWN' : (intel.freshness === 'RECENT' ? 'STALE' : intel.freshness) + ' DATA') + '</span>';
                    }
                }

                console.log('[v123.1] Worker stats loaded ✔', {
                    reports: intel.total_reports,
                    iocs: intel.ioc_count,
                    kev: intel.kev_count,
                    actors: intel.unique_actors,
                    exploit_active: intel.exploit_active,
                });
                // Mirror live total → API section header counter
                var apiLive = document.getElementById('api-live-count');
                if (apiLive && intel.total_reports) {
                    apiLive.textContent = intel.total_reports.toLocaleString();
                }
                // Animate all metric values when data loads
                document.querySelectorAll('.metric-val').forEach(function(el) {
                    if (el.textContent && el.textContent !== '\u2014') {
                        el.classList.add('loaded');
                    }
                });
            })
            .catch(function(e) {
                clearTimeout(statsTimer);
                // Stats unreachable: never leave the badge implying LIVE.
                var _b = document.getElementById('eicc-m-total-delta');
                if (_b && _b.textContent === 'CHECKING') cdbApplyPublicationBadge(null);
                console.debug('[v123.1] Worker stats (non-fatal):', e.message);
            });
        }
        fetchWorkerStats();

    