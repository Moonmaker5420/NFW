/* Table renderer: render(el, columns, rows) */
window.nfw = window.nfw || {};
nfw.table = (function () {
  function render(target, columns, rows, opts = {}) {
    const el = typeof target === 'string' ? document.querySelector(target) : target;
    if (!el) return;
    if (!rows || rows.length === 0) {
      el.innerHTML = `<div class="muted" style="padding:8px">${opts.empty || 'No data'}</div>`;
      return;
    }
    const thead = '<thead><tr>' + columns.map(c =>
      `<th>${c.label}</th>`).join('') + '</tr></thead>';
    const tbody = '<tbody>' + rows.map(r =>
      '<tr>' + columns.map(c => {
        const raw = c.get ? c.get(r) : r[c.key];
        const v = raw === null || raw === undefined ? '' : raw;
        const cls = c.className || '';
        return `<td class="${cls}">${escapeHtml(String(v))}</td>`;
      }).join('') + '</tr>').join('') + '</tbody>';
    el.innerHTML = `<table class="data">${thead}${tbody}</table>`;
  }
  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }
  return { render };
})();
