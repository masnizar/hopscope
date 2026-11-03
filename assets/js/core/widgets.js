/* SAP Troubleshooting Toolkit - shared UI widgets (used by every tool page) */
(function (TS) {
  'use strict';

  TS.esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  TS.debounce = function (fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  /* ---------- Severity pill: icon + label, never color alone ---------- */
  TS.SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  const SEV_ICON = {
    critical: '<svg width="12" height="12" viewBox="0 0 12 12"><path d="M6 .8 11.2 10.4H.8z" fill="currentColor"/></svg>',
    high: '<svg width="12" height="12" viewBox="0 0 12 12"><rect x="1.5" y="1.5" width="9" height="9" rx="1" transform="rotate(45 6 6)" fill="currentColor"/></svg>',
    medium: '<svg width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="5" fill="currentColor"/></svg>',
    low: '<svg width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" stroke-width="2"/></svg>',
    info: '<svg width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="5" fill="currentColor"/><rect x="5.2" y="5" width="1.6" height="4" fill="#fff"/><rect x="5.2" y="2.6" width="1.6" height="1.5" fill="#fff"/></svg>'
  };
  TS.sevPill = s => `<span class="sev ${s}">${SEV_ICON[s] || ''}${TS.SEV_LABEL[s] || s}</span>`;

  /* ---------- Preferences & theme ---------- */
  TS.readPref = function (k) { try { return localStorage.getItem('sapts.' + k); } catch (e) { return null; } };
  TS.writePref = function (k, v) { try { localStorage.setItem('sapts.' + k, v); } catch (e) { /* ignore */ } };
  TS.applyTheme = function (t, btn) {
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
    if (btn) btn.title = 'Theme: ' + (t || 'auto');
  };
  TS.initThemeButton = function (btn) {
    TS.applyTheme(TS.readPref('theme'), btn);
    btn.onclick = () => {
      const cur = document.documentElement.dataset.theme || 'auto';
      const next = cur === 'auto' ? 'light' : cur === 'light' ? 'dark' : 'auto';
      TS.applyTheme(next === 'auto' ? null : next, btn);
      TS.writePref('theme', next === 'auto' ? '' : next);
    };
  };

  /* ---------- Embedded in the Hopscope cockpit (index.html loads every tool with ?embed=1) ----------
   * The cockpit owns the incident: files dropped or picked inside a tool go up to it, it classifies them once and sends
   * each tool its share. A tool reports a one-line summary back for the rail. Messages: { hops: type, ... }. */
  const EMBED = typeof location !== 'undefined' && /[?&]embed=1\b/.test(location.search);
  const up = msg => { try { parent.postMessage(Object.assign({ hops: '' }, msg), '*'); } catch (e) { /* ignore */ } };
  // a tool page opened on its own → the cockpit, on that workspace (one entry point, one upload); ?standalone=1 keeps the page
  const VIEW = typeof document !== 'undefined' && document.querySelector ? document.querySelector('meta[name="hopscope-view"]') : null;
  if (VIEW && !EMBED && !/[?&]standalone=1\b/.test(location.search)) location.replace('index.html#' + (location.hash === '#example' ? 'example' : VIEW.content));
  TS.embed = {
    on: EMBED,
    tool: EMBED ? (/[?&]tool=([\w-]+)/.exec(location.search) || [])[1] || '' : '',
    srcOf: new Map(),   // path → source chosen in the cockpit ("Read as" in Evidence)
    // tool → cockpit: returns true when the files were handed over (the tool then waits for them to come back)
    forward(files) {
      if (!EMBED || !files || !files.length) return false;
      up({ hops: 'files', files: [...files].map(f => ({ path: f.webkitRelativePath || f.name, file: f })) });
      return true;
    },
    ask(type, extra) { if (EMBED) up(Object.assign({}, extra, { hops: type })); },
    report(summary) { if (EMBED) up({ hops: 'summary', tool: TS.embed.tool, summary }); },
    // cockpit → tool: { files: d => …, reset: () => …, visible: d => … }
    listen(handlers) {
      if (!EMBED) return;
      window.addEventListener('message', e => {
        if (e.source !== parent || !e.data || !e.data.hops) return;
        const h = handlers[e.data.hops];
        if (h) h(e.data);
      });
      up({ hops: 'ready', tool: TS.embed.tool });
    },
    toFiles: list => list.map(x => {
      if (x.src) TS.embed.srcOf.set(x.path, x.src);
      try { Object.defineProperty(x.file, 'webkitRelativePath', { value: x.path }); } catch (e) { /* read-only in some browsers */ }
      return x.file;
    })
  };
  // inside the cockpit a tool has no uploader of its own: its empty state points to Evidence, the one place to add files
  const EMPTY = {
    timeline: ['No logs in this incident yet', 'The timeline puts Cloud Connector, ICM, Web Dispatcher, work process traces, SM21, ST22, SM59 and certificates on one time line.'],
    logs: ['No Cloud Connector, ICM or Web Dispatcher log in this incident', 'Logs shows every entry of scc_core.trc / ljs_trace.log, dev_icm, dev_w* or dev_webdisp, with filters, patterns and the context in the file.'],
    traffic: ['No SCC traffic trace in this incident', 'Traffic decodes tunnel_traffic_*.trc (Cloud Connector payload trace) into HTTP requests and responses.'],
    certs: ['No certificate in this incident', 'Certificates reads .cer / .crt / .pem / .der, PSE files, Java keystores, STRUST or sapgenpse text, and the certificates referenced in SCC / ICM traces.']
  };
  function emptyState() {
    const ld = document.getElementById('loader'), e = EMPTY[TS.embed.tool];
    if (!ld || !e) return;
    ld.insertAdjacentHTML('afterbegin', `<div class="emb-empty"><svg viewBox="0 0 24 24" width="36" height="36" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z M14 3v5h5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
      <h2>${TS.esc(e[0])}</h2><p>${TS.esc(e[1])}</p><button class="btn primary" type="button">Open Evidence</button>
      <p class="muted small">All files of the incident are added in one place — Evidence — and every workspace uses them.</p></div>`);
    ld.querySelector('.emb-empty button').onclick = () => up({ hops: 'view', view: 'evidence' });
  }
  if (EMBED) {
    document.documentElement.classList.add('embedded');
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', emptyState); else emptyState();
    window.addEventListener('message', e => {
      if (e.source !== parent || !e.data) return;
      if (e.data.hops === 'theme') TS.applyTheme(e.data.theme);
      if (e.data.hops === 'visible' && e.data.on) window.dispatchEvent(new Event('resize'));   // charts measure their width again
    });
    // a file dragged over a tool: the cockpit shows its drop overlay above all tools
    document.addEventListener('dragenter', e => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) up({ hops: 'drag' }); });
  }

  /* ---------- Drag & drop: files and whole folders ---------- */
  TS.filesFromDrop = async function (dt) {
    const items = dt.items ? [...dt.items] : [];
    const entries = items.map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    if (!entries.length) return [...dt.files];
    const out = [];
    async function walk(entry, path) {
      if (entry.isFile) {
        const f = await new Promise((res, rej) => entry.file(res, rej));
        Object.defineProperty(f, 'webkitRelativePath', { value: path + f.name });
        out.push(f);
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        let batch;
        do {
          batch = await new Promise((res, rej) => reader.readEntries(res, rej));
          for (const c of batch) await walk(c, path + entry.name + '/');
        } while (batch.length);
      }
    }
    for (const en of entries) await walk(en, '');
    return out;
  };

  /* ---------- Dual-handle time range slider with a mini stacked histogram ----------
   * const s = TS.createTimeSlider(rootEl, { unit: ms per step, fmt: t => label, onChange(from, to) })
   * s.setData({ tMin, tMax, items, series: [{label, color}], seriesOf: item => series index | -1 })
   * s.setRange(from, to)   // sync from outside, does not fire onChange
   * from is inclusive, to is exclusive; null means "no bound".
   */
  TS.createTimeSlider = function (root, opts) {
    const unit = opts.unit || 1000, NB = opts.bins || 100, delay = opts.delay == null ? 150 : opts.delay;
    root.classList.add('time-filter');
    root.innerHTML = `
      <div class="tf-head">
        <span class="tf-title">${TS.esc(opts.title || 'Time range')}</span>
        <span class="tf-label"></span>
        <span class="spacer"></span>
        <span class="legend small tf-legend"></span>
        <button class="btn ghost tf-reset" type="button">All time</button>
      </div>
      <div class="tf-track">
        <svg class="tf-hist" preserveAspectRatio="none" aria-hidden="true"></svg>
        <div class="tf-rail"><div class="tf-sel"></div></div>
        <input type="range" class="tf-from" aria-label="Start time">
        <input type="range" class="tf-to" aria-label="End time">
      </div>
      <div class="tf-scale"><span class="tf-min"></span><span class="tf-max"></span></div>`;
    const q = s => root.querySelector(s);
    const a = q('.tf-from'), b = q('.tf-to');
    const st = { base: 0, max: 0, bins: [], series: [] };
    let timer = null;

    const range = () => {
      const va = +a.value, vb = +b.value;
      return { from: va <= 0 ? null : st.base + va * unit, to: vb >= st.max ? null : st.base + (vb + 1) * unit };
    };
    const emit = () => { clearTimeout(timer); timer = setTimeout(() => { const r = range(); opts.onChange(r.from, r.to); }, delay); };
    const onMove = which => {
      let va = +a.value, vb = +b.value;
      if (va > vb) { if (which === 'from') a.value = va = vb; else b.value = vb = va; }
      paint(); emit();
    };
    a.oninput = () => onMove('from');
    b.oninput = () => onMove('to');
    q('.tf-reset').onclick = () => { a.value = 0; b.value = st.max; paint(); clearTimeout(timer); opts.onChange(null, null); };

    function setData(d) {
      if (d.tMin == null || d.tMax == null || d.tMax - d.tMin < unit) { root.hidden = true; st.max = 0; return; }
      root.hidden = false;
      st.base = Math.floor(d.tMin / unit) * unit;
      st.max = Math.floor((d.tMax - st.base) / unit);
      [a, b].forEach(el => { el.min = 0; el.max = st.max; el.step = 1; });
      q('.tf-min').textContent = opts.fmt(d.tMin);
      q('.tf-max').textContent = opts.fmt(d.tMax);
      st.series = d.series;
      const span = (st.max + 1) * unit;
      st.bins = Array.from({ length: NB }, () => new Array(d.series.length).fill(0));
      for (const it of d.items) {
        if (it.t == null) continue;
        const s = d.seriesOf(it);
        if (s < 0) continue;
        st.bins[Math.max(0, Math.min(NB - 1, Math.floor((it.t - st.base) / span * NB)))][s]++;
      }
      q('.tf-legend').innerHTML = d.series.map(s => `<span><i style="background:${s.color}"></i>${TS.esc(s.label)}</span>`).join('');
      a.value = 0; b.value = st.max;
      paint();
    }

    function setRange(from, to) {
      if (root.hidden) return;
      const clamp = v => Math.max(0, Math.min(st.max, v));
      a.value = from == null ? 0 : clamp(Math.floor((from - st.base) / unit));
      b.value = to == null ? st.max : clamp(Math.ceil((to - st.base) / unit) - 1);
      paint();
    }

    function paint() {
      const va = +a.value, vb = +b.value, mx = st.max || 1;
      const sel = q('.tf-sel');
      sel.style.left = (va / mx * 100) + '%';
      sel.style.width = ((vb - va) / mx * 100) + '%';
      // When both handles sit at the right end, the "from" handle must be on top to stay draggable
      a.style.zIndex = va > mx / 2 ? 3 : 2;
      const all = va <= 0 && vb >= st.max;
      const t0 = st.base + va * unit, t1 = st.base + vb * unit;
      q('.tf-label').innerHTML = all ? '<span class="muted">All time — drag the handles to narrow down</span>'
        : `<b>${TS.esc(opts.fmt(t0))}</b> → <b>${TS.esc(opts.fmt(t1))}</b> <span class="muted">(${TS.fmtDuration(t1 - t0 + unit)})</span>`;
      q('.tf-reset').disabled = all;

      const H = 36, N = st.bins.length;
      const tot = bin => bin.reduce((x, y) => x + y, 0);
      const max = Math.max(1, ...st.bins.map(tot));
      const lo = va / (st.max + 1) * N, hi = (vb + 1) / (st.max + 1) * N;
      let s = '';
      st.bins.forEach((bin, i) => {
        const cls = i + 1 <= lo || i >= hi ? ' class="out"' : '', x = i * 10 + 1;
        let acc = 0;
        bin.forEach((v, si) => {
          if (!v) return;
          const y0 = acc / max * (H - 2);
          acc += v;
          const y1 = Math.max(acc / max * (H - 2), y0 + 1.5);
          s += `<rect${cls} x="${x}" y="${(H - y1).toFixed(2)}" width="8" height="${(y1 - y0).toFixed(2)}" fill="${st.series[si].color}"/>`;
        });
      });
      s += `<line class="base" x1="0" x2="${N * 10}" y1="${H - 0.5}" y2="${H - 0.5}"/>`;
      const svg = q('.tf-hist');
      svg.setAttribute('viewBox', `0 0 ${N * 10} ${H}`);
      svg.innerHTML = s;
    }

    return { setData, setRange };
  };
})(window.TS);
