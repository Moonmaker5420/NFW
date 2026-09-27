/* NFW app.js — all client-side behavior, single source of truth */
window.nfw = window.nfw || {};

(function () {
  var SIDEBAR_KEY = 'nfw-sidebar-collapsed';
  var MOBILE_BP = 900;

  function isMobile() { return window.innerWidth <= MOBILE_BP; }
  function bodyHas(c) { return document.body.classList.contains(c); }
  function bodyAdd(c) { document.body.classList.add(c); }
  function bodyRm(c)  { document.body.classList.remove(c); }

  /* ---------------- Sidebar toggle ---------------- */
  function sidebarCollapsed() { return bodyHas('sidebar-collapsed'); }
  function applySidebar(collapsed) {
    if (collapsed) bodyAdd('sidebar-collapsed');
    else           bodyRm('sidebar-collapsed');
    try { localStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0'); } catch (e) {}
  }
  function toggleSidebar() { applySidebar(!sidebarCollapsed()); }

  /* ---------------- Theme toggle ---------------- */
  /* The CSS selector is :root.light → class must be on <html> */
  function currentTheme() {
    try { return localStorage.getItem('nfw-theme') || 'dark'; } catch (e) { return 'dark'; }
  }
  function applyTheme(theme) {
    var root = document.documentElement;   // <html>
    if (theme === 'light') root.classList.add('light');
    else                    root.classList.remove('light');
    try { localStorage.setItem('nfw-theme', theme); } catch (e) {}
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = theme === 'light' ? '\u263E' : '\u2600';
  }
  function toggleTheme() { applyTheme(currentTheme() === 'light' ? 'dark' : 'light'); }

  /* ---------------- Logout ---------------- */
  function doLogout() {
    var p = (window.nfw && nfw.api)
      ? nfw.api.post('/api/auth/logout').catch(function () {})
      : Promise.resolve();
    p.then(function () { window.location.href = '/login'; });
  }

  /* ---------------- Initialization ---------------- */
  function init() {
    // Sidebar initial state
    var saved = null;
    try { saved = localStorage.getItem(SIDEBAR_KEY); } catch (e) {}
    var startCollapsed = (saved === '1') ? true
                       : (saved === '0') ? false
                       : isMobile();
    applySidebar(startCollapsed);

    // Theme initial state
    applyTheme(currentTheme());

    // Delegated click handler — handles all three buttons reliably
    document.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.closest) return;

      var sidebarBtn = t.closest('#sidebar-toggle');
      if (sidebarBtn) {
        e.preventDefault();
        toggleSidebar();
        return;
      }

      var themeBtn = t.closest('#theme-toggle');
      if (themeBtn) {
        e.preventDefault();
        toggleTheme();
        return;
      }

      var logoutBtn = t.closest('#logout-btn');
      if (logoutBtn) {
        e.preventDefault();
        doLogout();
        return;
      }
    }, true);   // capture phase — fires before anything else

    // Ctrl+B / Cmd+B
    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebar();
      }
    });

    // Mark active sidebar link (single longest match)
    var path = location.pathname;
    var links = Array.prototype.slice.call(
      document.querySelectorAll('aside.sidebar a')
    );
    var bestHref = null;
    links.forEach(function (a) {
      var href = a.getAttribute('href');
      if (!href) return;
      var match = (href === '/')
        ? (path === '/')
        : (path === href || path.indexOf(href + '/') === 0);
      if (match && (bestHref === null || href.length > bestHref.length)) {
        bestHref = href;
      }
    });
    if (bestHref !== null) {
      links.forEach(function (a) {
        if (a.getAttribute('href') === bestHref) a.classList.add('active');
      });
    }
  }

  // ---- Collapsible nav groups --------------------------------------
  (function navGroups() {
    var NAV_KEY = 'nfw-nav-expanded';
    var expanded = {};
    try {
      var stored = localStorage.getItem(NAV_KEY);
      if (stored) expanded = JSON.parse(stored) || {};
    } catch (e) {}

    function saveNav() {
      try { localStorage.setItem(NAV_KEY, JSON.stringify(expanded)); } catch (e) {}
    }

    var groups = document.querySelectorAll('aside.sidebar .group');
    groups.forEach(function (g) {
      var h = g.querySelector('h3');
      if (!h) return;
      var key = h.textContent.trim().toLowerCase();
      var hasActive = !!g.querySelector('a.active');

      // initial state: saved preference if any, else expand only active
      var wantExpanded;
      if (Object.prototype.hasOwnProperty.call(expanded, key)) {
        wantExpanded = !!expanded[key];
      } else {
        wantExpanded = hasActive;
      }
      if (!wantExpanded) g.classList.add('collapsed');

      h.addEventListener('click', function (ev) {
        ev.preventDefault();
        g.classList.toggle('collapsed');
        expanded[key] = !g.classList.contains('collapsed');
        saveNav();
      });
      h.setAttribute('role', 'button');
      h.setAttribute('tabindex', '0');
      h.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          h.click();
        }
      });
    });
  })();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
