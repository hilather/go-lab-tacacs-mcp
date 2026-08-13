(() => {
  const nav = document.querySelector(".nav");
  const toggle = document.querySelector(".nav-toggle");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  const tabs = document.querySelectorAll("[data-tab]");
  tabs.forEach((btn) => {
    btn.addEventListener("click", () => {
      const name = btn.getAttribute("data-tab");
      document.querySelectorAll("[data-tab]").forEach((b) => {
        b.setAttribute("aria-selected", String(b === btn));
      });
      document.querySelectorAll("[data-panel]").forEach((p) => {
        p.hidden = p.getAttribute("data-panel") !== name;
      });
    });
  });

  const canvas = document.getElementById("scope");
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext("2d");
  const dpr = Math.min(window.devicePixelRatio || 1, 2);

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.max(1, Math.floor(rect.width * dpr));
    canvas.height = Math.max(1, Math.floor(rect.height * dpr));
  };
  resize();
  window.addEventListener("resize", resize);

  const draw = (t) => {
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    ctx.strokeStyle = "rgba(43,179,168,0.12)";
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 28 * dpr) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 28 * dpr) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    const traces = [
      { color: "rgba(232,194,122,0.95)", amp: 0.18, freq: 2.1, phase: 0, thick: 1.6 },
      { color: "rgba(134,239,228,0.85)", amp: 0.12, freq: 3.4, phase: 1.2, thick: 1.3 },
      { color: "rgba(200,137,58,0.55)", amp: 0.07, freq: 6.1, phase: 2.4, thick: 1.1 },
    ];

    traces.forEach((tr, i) => {
      ctx.beginPath();
      ctx.strokeStyle = tr.color;
      ctx.lineWidth = tr.thick * dpr;
      for (let x = 0; x <= w; x += 2) {
        const nx = x / w;
        const pulse = Math.sin((nx * tr.freq + t * 0.00045 + tr.phase) * Math.PI * 2);
        const packet = Math.sin((nx * 18 - t * 0.004 + i) * Math.PI) ** 8;
        const y = h * 0.52 + pulse * h * tr.amp + packet * h * 0.08 * (i === 0 ? 1 : 0.45);
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
    });

    requestAnimationFrame(draw);
  };
  requestAnimationFrame(draw);
})();
