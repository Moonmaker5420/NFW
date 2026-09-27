window.nfw = window.nfw || {};
nfw.modal = (function () {
  function open(opts) {
    var bg = document.createElement('div');
    bg.className = 'modal-bg';
    var m = document.createElement('div');
    m.className = 'modal';

    var title = document.createElement('h2');
    title.textContent = opts.title || '';
    m.appendChild(title);

    if (opts.body) {
      if (typeof opts.body === 'string') {
        var bodyEl = document.createElement('div');
        bodyEl.className = 'modal-body';
        bodyEl.innerHTML = opts.body;
        m.appendChild(bodyEl);
      } else if (opts.body instanceof Node) {
        var wrap = document.createElement('div');
        wrap.className = 'modal-body';
        wrap.appendChild(opts.body);
        m.appendChild(wrap);
      }
    }

    if (Array.isArray(opts.actions) && opts.actions.length) {
      var acts = document.createElement('div');
      acts.className = 'actions';
      opts.actions.forEach(function (a) {
        var b = document.createElement('button');
        b.type = 'button';
        b.textContent = a.label || '';
        if (a.className) b.className = a.className;
        if (a.onClick) b.addEventListener('click', function (ev) {
          ev.preventDefault();
          a.onClick(ev, close);
        });
        acts.appendChild(b);
      });
      m.appendChild(acts);
    }

    bg.appendChild(m);
    bg.addEventListener('click', function (e) { if (e.target === bg) close(); });
    document.body.appendChild(bg);

    function close() { bg.remove(); }
    return { close: close, modal: m, bg: bg };
  }
  return { open: open };
})();
