/* WebSocket live stats. */
window.nfw = window.nfw || {};
nfw.ws = (function () {
  let sock = null;
  const handlers = {};

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}/api/ws/stats`;
    try {
      sock = new WebSocket(url);
    } catch (e) {
      console.error('WS connect failed:', e);
      setTimeout(connect, 3000);
      return;
    }
    sock.onopen = () => {
      console.info('WS connected');
      emit('open');
    };
    sock.onclose = () => {
      console.info('WS closed, retrying in 3s');
      emit('close');
      setTimeout(connect, 3000);
    };
    sock.onerror = (e) => console.warn('WS error', e);
    sock.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        emit('stats', data);
      } catch (e) { console.warn('bad ws message', e); }
    };
  }

  function on(event, fn) { (handlers[event] = handlers[event] || []).push(fn); }
  function emit(event, data) { (handlers[event] || []).forEach(fn => { try { fn(data); } catch(e){ console.error(e); } }); }

  return { connect, on };
})();
