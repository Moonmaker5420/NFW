/* Toast notifications. */
window.nfw = window.nfw || {};
nfw.toast = (function () {
  function container() {
    let c = document.querySelector('.toast-container');
    if (!c) {
      c = document.createElement('div');
      c.className = 'toast-container';
      document.body.appendChild(c);
    }
    return c;
  }
  function show(msg, kind = 'info', ms = 3500) {
    const el = document.createElement('div');
    el.className = 'toast ' + kind;
    el.textContent = msg;
    container().appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .2s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 220);
    }, ms);
  }
  return {
    info: (m) => show(m, 'info'),
    ok:   (m) => show(m, 'ok'),
    err:  (m) => show(m, 'err'),
    warn: (m) => show(m, 'warn'),
  };
})();
