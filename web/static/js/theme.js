/* Theme toggle with localStorage persistence. */
(function () {
  const KEY = 'nfw-theme';
  function apply(t) {
    document.documentElement.classList.toggle('light', t === 'light');
    localStorage.setItem(KEY, t);
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = t === 'light' ? '☾' : '☀';
  }
  function current() { return localStorage.getItem(KEY) || 'dark'; }
  window.nfw = window.nfw || {};
  nfw.theme = {
    init() { apply(current()); },
    toggle() { apply(current() === 'light' ? 'dark' : 'light'); },
    current,
  };
  document.addEventListener('DOMContentLoaded', () => nfw.theme.init());
})();
