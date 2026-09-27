/* NFW API helper — fetch wrapper with JSON + error handling. */
window.nfw = window.nfw || {};

nfw.api = (function () {
  async function request(method, path, body) {
    const opts = {
      method,
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(path, opts);
    let data = null;
    try { data = await r.json(); } catch (_) {}
    if (!r.ok) {
      const msg = (data && (data.detail || data.error)) || `HTTP ${r.status}`;
      const err = new Error(msg);
      err.status = r.status;
      err.data = data;
      throw err;
    }
    return data;
  }
  return {
    get:  (p)      => request('GET', p),
    post: (p, b)   => request('POST', p, b ?? {}),
    put:  (p, b)   => request('PUT', p, b ?? {}),
    del:  (p)      => request('DELETE', p),
  };
})();
