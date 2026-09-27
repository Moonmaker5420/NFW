/* Minimal canvas line chart. */
window.nfw = window.nfw || {};
nfw.chart = (function () {
  function make(canvas, opts = {}) {
    const ctx = canvas.getContext('2d');
    const series = opts.series || [];
    const maxPoints = opts.maxPoints || 60;
    const color = opts.color || '#58a6ff';
    const fill = opts.fill || 'rgba(88,166,255,0.15)';
    const min = opts.min ?? 0;
    let max = opts.max ?? 100;

    function resize() {
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth, h = canvas.clientHeight;
      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr; canvas.height = h * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }
    }

    function draw() {
      resize();
      const w = canvas.clientWidth, h = canvas.clientHeight;
      ctx.clearRect(0, 0, w, h);

      // Grid
      ctx.strokeStyle = 'rgba(139,148,158,0.15)';
      ctx.lineWidth = 1;
      for (let i = 1; i < 4; i++) {
        const y = (h / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      if (series.length === 0) return;
      const n = series.length;
      const xStep = n > 1 ? w / (n - 1) : w;
      const yMax = Math.max(max, ...series) || 1;

      // Line
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      series.forEach((v, i) => {
        const x = i * xStep;
        const y = h - ((v - min) / (yMax - min)) * h;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();

      // Fill
      ctx.lineTo((n - 1) * xStep, h);
      ctx.lineTo(0, h);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
    }

    return {
      push(v) {
        series.push(v);
        if (series.length > maxPoints) series.shift();
        draw();
      },
      set(vals) {
        series.length = 0;
        vals.forEach(v => series.push(v));
        if (series.length > maxPoints) series.splice(0, series.length - maxPoints);
        draw();
      },
      draw,
      setMax(m) { max = m; },
    };
  }
  return { make };
})();
