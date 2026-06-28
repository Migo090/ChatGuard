'use strict';

// ══════════════════════════════════════════════════
// events.js — All DOM event bindings
//
// No inline onclick/oninput/onchange in HTML.
// Every handler is wired here after DOMContentLoaded.
// This is required for script-src 'self' CSP compliance.
// ══════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

  // ── Helper: bind click on element by id ──────────────────────────────
  function on(id, handler) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', handler);
  }

  function onAll(selector, handler) {
    document.querySelectorAll(selector).forEach(el => el.addEventListener('click', handler));
  }

  // ══════════════════════════════════════════════════
  // INTRO SPLASH — simulated signature init, then fade to dashboard
  // (CSP-compliant: wired here, no inline script/handlers)
  // ══════════════════════════════════════════════════
  (function introSplash() {
    const splash = document.getElementById('introSplash');
    if (!splash) return;

    // Guaranteed dismissal: no matter what happens below, the overlay is
    // removed from the layout so it can never strand the dashboard behind a
    // stuck splash. Mirrors the pure-CSS introSafetyHide fallback in main.css.
    const hardHide = () => {
      splash.classList.add('intro-hide');
      splash.classList.add('intro-done');
    };

    try {
      const status = document.getElementById('introStatus');
      const steps = [
        'Initializing detection signatures…',
        'Loading Intercom IDOR heuristics…',
        'Loading Pylon misconfiguration rules…',
        'Calibrating scanner engine…',
        'Ready.'
      ];
      let i = 0;
      const stepTimer = setInterval(() => {
        i += 1;
        if (status && i < steps.length) status.textContent = steps[i];
        if (i >= steps.length - 1) clearInterval(stepTimer);
      }, 460);

      // After the simulated init delay, fade out and uncover the dashboard.
      setTimeout(() => {
        splash.classList.add('intro-hide');
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          splash.classList.add('intro-done');
        };
        splash.addEventListener('transitionend', finish, { once: true });
        // Fallback in case transitionend never fires (reduced-motion, etc.)
        setTimeout(finish, 800);
      }, 2200);
    } catch (err) {
      // Any unexpected error must not leave the splash covering the app.
      hardHide();
    }
  })();

  // ══════════════════════════════════════════════════
  // NAV TABS (desktop)
  // ══════════════════════════════════════════════════
  document.querySelectorAll('.nav-tab').forEach(btn => {
    const page = btn.textContent.trim().toLowerCase();
    btn.addEventListener('click', () => {
      showPage(page, btn);
      closeDrawer();
    });
  });

  // ── Hamburger ──────────────────────────────────────────────────────
  on('navHamburger', () => toggleDrawer());

  // ── Mobile drawer tabs ─────────────────────────────────────────────
  document.querySelectorAll('.nav-drawer-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const page = btn.textContent.trim().toLowerCase();
      showPage(page, btn);
      syncDesktopTab(page);
      closeDrawer();
    });
  });

  // ══════════════════════════════════════════════════
  // SCANNER PAGE
  // ══════════════════════════════════════════════════
  on('scanBtn',    () => ScannerEngine.run());
  on('demoBtn',    () => ScannerEngine.runDemo());
  on('logCopyBtn', () => ScannerEngine.copyLog());
  on('openInspectorBtn', () => Inspector.openFromScan());
  on('generateReportBtn', () => ReportManager.generateReport());
  on('clearScanBtn', () => ScannerEngine.clearScan());

  // URL input: Enter key triggers scan
  const urlInput = document.getElementById('targetUrl');
  if (urlInput) {
    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        e.stopImmediatePropagation();
        ScannerEngine.run();
      }
    });
  }

  // ══════════════════════════════════════════════════
  // INSPECTOR — live param inputs
  // ══════════════════════════════════════════════════
  function bindLiveInput(id, extra) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', () => {
      el.dataset.manuallyEdited = '1';
      if (extra) extra(el.value);
      Inspector.render();
    });
  }

  bindLiveInput('liveAppId', val => Inspector.onAppIdInput(val));
  bindLiveInput('liveUserId');
  bindLiveInput('liveEmail');
  bindLiveInput('liveIssueId');
  bindLiveInput('liveBlocks');

  on('resetToScanBtn', () => Inspector.resetToScanValues());

  // ── Vulnerability chips ─────────────────────────────────────────────
  const vulnChips = document.querySelectorAll('.vuln-chip');
  const vulnIds   = ['a01', 'a02', 'a03'];
  vulnChips.forEach((btn, i) => {
    btn.addEventListener('click', () => Inspector.setVuln(vulnIds[i], btn));
  });

  // ── Step tabs (Pylon A03) ───────────────────────────────────────────
  const stepTabs = document.querySelectorAll('.step-tab');
  stepTabs.forEach((btn, i) => {
    btn.addEventListener('click', () => Inspector.setStep(i + 1, btn));
  });

  // ── Request format tabs ─────────────────────────────────────────────
  const reqFmts  = ['raw', 'curl', 'python'];
  document.querySelectorAll('.req-fmt-tab').forEach((btn, i) => {
    btn.addEventListener('click', () => Inspector.setReqFormat(reqFmts[i], btn));
  });

  // ── Response format tabs ────────────────────────────────────────────
  document.querySelectorAll('.resp-fmt-tab').forEach(btn => {
    btn.addEventListener('click', () => Inspector.setRespFormat(btn.dataset.fmt || 'pretty', btn));
  });

  // ── Send request ────────────────────────────────────────────────────
  on('sendReqBtn', () => RequestSender.send());

  // ══════════════════════════════════════════════════
  // HISTORY PAGE
  // ══════════════════════════════════════════════════
  const histSearch = document.getElementById('historySearch');
  if (histSearch) histSearch.addEventListener('input', () => Storage.renderHistory());

  // Inspect buttons are re-rendered on every history update, so delegate from
  // the static tbody (CSP-safe — replaces the old inline onclick handlers).
  const historyBody = document.getElementById('historyBody');
  if (historyBody) {
    historyBody.addEventListener('click', e => {
      const btn = e.target.closest('.js-inspect-scan');
      if (!btn) return;
      const id = Number(btn.dataset.scanId);
      if (!Number.isNaN(id)) Inspector.loadScan(id);
    });
  }

  on('clearHistoryBtn', () => Storage.clearAll());

  // ══════════════════════════════════════════════════
  // SETTINGS PAGE
  // ══════════════════════════════════════════════════
  const settingBindings = [
    ['settingA01',          'change', el => Storage.saveSetting('a01',       el.checked)],
    ['settingA02',          'change', el => Storage.saveSetting('a02',       el.checked)],
    ['settingA03',          'change', el => Storage.saveSetting('a03',       el.checked)],
    ['settingUuidNote',     'change', el => Storage.saveSetting('uuidNote',  el.checked)],
    ['settingReqFmt',       'change', el => Storage.saveSetting('reqFmt',    el.value)],
    ['settingEmail',        'change', el => Storage.saveSetting('email',     el.value)],
    ['settingUserIdType',   'change', el => Storage.saveSetting('userIdType',el.value)],
  ];
  settingBindings.forEach(([id, evt, handler]) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(evt, () => handler(el));
  });

  on('clearHistoryBtn2', () => Storage.clearAll());
  on('exportJsonBtn',    () => Storage.exportJSON());

  // ══════════════════════════════════════════════════
  // REPORT MODAL
  // ══════════════════════════════════════════════════
  const closeModal = () => {
    document.getElementById('reportModal')?.classList.remove('open');
  };

  on('closeModalBtn',     closeModal);
  on('closeModalBtn2',    closeModal);
  on('downloadMdBtn',     () => ReportManager.downloadMd());
  on('printReportBtn',    () => window.print());

  // ══════════════════════════════════════════════════
  // CUSTOM MODAL (cgAlert/cgConfirm backdrop click)
  // ══════════════════════════════════════════════════
  const cgBackdrop = document.getElementById('cgModalBackdrop');
  if (cgBackdrop) {
    cgBackdrop.addEventListener('click', e => {
      // Only close if clicking the backdrop itself, not the box
      if (e.target === cgBackdrop) cgBackdrop.classList.remove('open');
    });
  }

});
