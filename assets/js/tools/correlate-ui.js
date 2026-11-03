/* Correlation dashboard UI */
(function (TS) {
  'use strict';
  const C = TS.corr, esc = TS.esc, $ = id => document.getElementById(id);
  const fmtN = n => (n || 0).toLocaleString('en-US');
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const ft = (t, ms) => TS.fmtTime(t, null, ms);
  const PAGE = 200;
  const lvlBadge = l => `<span class="lvl ${l}">${l}</span>`;

  const S = {
    files: [], skipped: [], data: null, incidents: [], findings: [], from: null, to: null,
    win: 120000, datefmt: 'auto', tz: 'auto', sort: 'score', page: 0,
    ev: { srcs: null, level: 'bad', q: '', from: null, to: null, label: '' }
  };
  let slider = null;

  /* ================= Init ================= */
  function init() {
    TS.initThemeButton($('btnTheme'));
    const dz = $('dropzone');
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
    dz.addEventListener('drop', async e => addFiles(await TS.filesFromDrop(e.dataTransfer)));
    document.addEventListener('dragover', e => e.preventDefault());
    document.addEventListener('drop', async e => { if (!dz.contains(e.target)) { e.preventDefault(); addFiles(await TS.filesFromDrop(e.dataTransfer)); } });
    $('btnPickFiles').onclick = () => $('inputFiles').click();
    $('btnPickFolder').onclick = () => $('inputFolder').click();
    $('btnAdd').onclick = () => $('inputFiles').click();
    $('inputFiles').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('inputFolder').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('btnReset').onclick = reset;
    $('btnReport').onclick = exportReport;

    $('optWindow').onchange = () => { S.win = +$('optWindow').value * 1000; refresh(); };
    $('optDate').onchange = () => { S.datefmt = $('optDate').value; rebuild(); };
    const offs = [];
    for (let h = -12; h <= 14; h++) offs.push(h * 60);
    offs.push(-210, 210, 270, 330, 345, 390, 525, 570, 630);
    $('optTz').innerHTML = '<option value="auto">Auto (from traces)</option>' + offs.sort((a, b) => a - b).map(o => `<option value="${o}">${TS.fmtOffset(o)}</option>`).join('');
    $('optTz').onchange = () => { S.tz = $('optTz').value; rebuild(); };
    $('findings').addEventListener('click', e => { const b = e.target.closest('[data-find]'); if (b) { const f = S.findings[+b.dataset.find]; showEventsFor({ srcs: f.srcs.length === 1 ? f.srcs : null, q: f.q, from: null, to: null, label: '', level: 'all' }); } });
    $('optSort').onchange = () => { S.sort = $('optSort').value; renderIncidents(); };
    $('evLevel').onchange = () => { S.ev.level = $('evLevel').value; S.page = 0; renderEvents(); };
    $('evText').oninput = TS.debounce(() => { S.ev.q = $('evText').value; S.page = 0; renderEvents(); }, 200);
    $('evClear').onclick = () => { S.ev = { srcs: null, level: 'bad', q: '', from: null, to: null, label: '' }; $('evLevel').value = 'bad'; $('evText').value = ''; S.page = 0; renderEvents(); };
    $('evPrev').onclick = () => { if (S.page > 0) { S.page--; renderEvents(); } };
    $('evNext').onclick = () => { S.page++; renderEvents(); };
    $('evTable').querySelector('tbody').addEventListener('click', e => { const tr = e.target.closest('tr[data-id]'); if (tr) showEvent(+tr.dataset.id); });
    $('incidents').addEventListener('click', onIncidentClick);
    $('modalClose').onclick = closeModal;
    $('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

    slider = TS.createTimeSlider($('timeFilter'), {
      unit: 1000, fmt: t => ft(t), title: 'Analysis time range',
      onChange(from, to) { S.from = from; S.to = to; refresh(); }
    });
    let rt;
    window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => S.data && renderLanes(), 150); });
    // the cockpit focuses the timeline on the minutes the map analyzes ("All time" on the slider widens it again)
    TS.embed.listen({ files: d => addFiles(TS.embed.toFiles(d.files), true), reset, range: d => { S.focus = { from: d.from, to: d.to }; if (S.data) { applyFocus(); refresh(); } } });
  }
  function applyFocus() {
    if (!S.focus) return;
    S.from = S.focus.from; S.to = S.focus.to;
    slider.setRange(S.from, S.to);
  }

  function setStatus(msg, isErr) { const s = $('status'); s.textContent = msg || ''; s.classList.toggle('error', !!isErr); }

  /* ================= Loading ================= */
  async function addFiles(list, fromCockpit) {
    if (!list || !list.length) return;
    if (!fromCockpit && TS.embed.forward(list)) return;
    $('loader').hidden = false; $('app').hidden = true;
    try {
      const { out, skipped } = await TS.readInputs(list, msg => setStatus(msg));
      S.skipped.push(...skipped);
      for (const f of out) {
        if (S.files.some(x => x.name === f.name && x.size === f.size)) continue;
        S.files.push({ name: f.name, text: f.text, size: f.size, mtime: f.mtime, src: TS.embed.srcOf.get(f.name) || C.classify(f.name, f.text), shiftH: 0 });
      }
      if (!S.files.length) { setStatus('No readable files. ' + skipped.map(s => `${base(s.name)}: ${s.reason}`).join('; '), true); TS.embed.report({ status: 'empty', badge: '0', line: 'No readable files' }); return; }
      setStatus('Correlating…');
      await new Promise(r => setTimeout(r, 0));
      rebuild();
      setStatus('');
      $('loader').hidden = true; $('app').hidden = false;
      ['btnAdd', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = false));
      renderLanes();
    } catch (err) {
      console.error(err);
      setStatus('Failed to process files: ' + err.message, true);
    }
  }

  function reset() {
    Object.assign(S, { files: [], skipped: [], data: null, incidents: [], from: null, to: null, page: 0, focus: null });
    S.ev = { srcs: null, level: 'bad', q: '', from: null, to: null, label: '' };
    ['btnAdd', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = true));
    $('app').hidden = true; $('loader').hidden = false; setStatus('');
  }

  function rebuild() {
    S.data = C.build(S.files, { datefmt: S.datefmt, tz: S.tz });
    S.from = S.to = null;
    renderTz();
    slider.setData({
      tMin: S.data.tMin, tMax: S.data.tMax, items: S.data.events,
      series: [{ label: 'ERROR', color: 'var(--lvl-error)' }, { label: 'WARN', color: 'var(--lvl-warn)' }],
      seriesOf: e => (e.level === 'ERROR' || e.level === 'FATAL' ? 0 : e.level === 'WARN' ? 1 : -1)
    });
    applyFocus();
    renderSources();
    refresh();
  }

  // Everything that depends on the selected time range / correlation window
  function refresh() {
    if (!S.data) return;
    S.incidents = C.incidents(S.data, S.win, S.from, S.to);
    S.findings = C.findings(S.data, S.from, S.to);
    renderKpis(); renderFindings(); renderLanes(); renderIncidents(); renderCerts(); renderTests(); renderTop(); renderEventSources(); renderEvents();
    const act = S.findings.filter(f => f.sev !== 'info'), top = act[0];
    TS.embed.report({
      status: !top ? 'ok' : top.sev === 'critical' || top.sev === 'high' ? 'fail' : 'warn', badge: fmtN(act.length),
      line: top ? top.title : `${fmtN(S.incidents.length)} correlated incident(s), no finding`
    });
  }
  const inRange = t => t != null && (S.from == null || t >= S.from) && (S.to == null || t < S.to);
  const refTime = () => (S.to != null ? S.to : S.data.tMax != null ? S.data.tMax : Date.now());

  /* ================= Sources ================= */
  function renderSources() {
    // inside the cockpit the files are managed in Evidence (source, remove); only the time tuning stays here
    const managed = TS.embed.on;
    if (managed) $('srcHint').textContent = 'Wrong source or a file to remove? Change it in Evidence. A single file in another time zone? Use “Shift (h)”.';
    const opts = sel => C.SOURCES.map(s => `<option value="${s.id}"${s.id === sel ? ' selected' : ''}>${esc(s.label)}${s.hint ? ' (' + esc(s.hint) + ')' : ''}</option>`).join('');
    $('srcTable').innerHTML = `<thead><tr><th>File</th><th>Source</th><th>Result</th><th class="num">Events</th><th class="num">Errors</th><th>Time range</th><th>Shift (h)</th><th></th></tr></thead><tbody>${S.files.map((f, i) => `
      <tr><td class="mono" title="${esc(f.name)}">${esc(base(f.name))}</td>
      <td>${managed ? esc(C.label(f.src)) : `<select data-src="${i}" aria-label="Source of ${esc(base(f.name))}">${opts(f.src)}</select>`}</td>
      <td class="small muted">${esc(f.note || '')}</td>
      <td class="num">${fmtN(f.eventCount)}</td><td class="num">${fmtN(f.errCount)}</td>
      <td class="mono small">${f.tMin != null ? esc(ft(f.tMin)) + '<br>' + esc(ft(f.tMax)) : '-'}${f.tzConverted ? '<br><span class="muted" style="font-family:var(--sans)">converted to server time</span>' : ''}</td>
      <td><input type="number" step="0.5" value="${f.shiftH || 0}" data-shift="${i}" class="num-input" aria-label="Time shift in hours"></td>
      <td>${managed ? '' : `<button class="btn ghost icon" data-del="${i}" aria-label="Remove file" title="Remove">✕</button>`}</td></tr>`).join('')}
      ${S.skipped.length ? `<tr><td colspan="8" class="small muted">Skipped: ${S.skipped.map(s => esc(base(s.name) + ' — ' + s.reason)).join('; ')}</td></tr>` : ''}</tbody>`;
    $('srcTable').querySelectorAll('[data-src]').forEach(s => (s.onchange = () => { S.files[+s.dataset.src].src = s.value; rebuild(); }));
    $('srcTable').querySelectorAll('[data-shift]').forEach(s => (s.onchange = () => { S.files[+s.dataset.shift].shiftH = +s.value || 0; rebuild(); }));
    $('srcTable').querySelectorAll('[data-del]').forEach(b => (b.onclick = () => { S.files.splice(+b.dataset.del, 1); if (S.files.length) rebuild(); else reset(); }));
  }

  /* ================= Time base ================= */
  function renderTz() {
    const tz = S.data.tz, auto = $('optTz').querySelector('option[value="auto"]');
    auto.textContent = tz.off != null && tz.how.startsWith('detected') ? `Auto (detected ${TS.fmtOffset(tz.off)})` : 'Auto (from traces)';
    $('optTz').value = S.tz;
    const conv = tz.converted.length ? ` Converted from their own time zone: ${tz.converted.map(esc).join(', ')}.` : '';
    $('tzNote').innerHTML = tz.off != null
      ? `<b>Time base:</b> SAP server local time ${esc(TS.fmtOffset(tz.off))} — ${esc(tz.how)}.${conv}`
      : tz.how === 'unknown'
        ? `<span class="cst c-expiring">Time zone unknown</span> ${esc(tz.unconverted.join(', '))} contain an explicit time zone (Cloud Connector: UTC), the SAP traces do not, and no HTTP Date header was found to detect the server offset — choose the <b>Server time zone</b>.`
        : '<b>Time base:</b> times as written in the files.';
  }

  /* ================= Findings & solutions ================= */
  function renderFindings() {
    const F = S.findings;
    $('cntFind').textContent = F.filter(f => f.sev !== 'info').length;
    if (!F.length) { $('findings').innerHTML = '<div class="empty">No known problem pattern in the selected range. Check the incidents and the event list below.</div>'; return; }
    $('findings').innerHTML = `<div class="findings">${F.map((f, i) => `
      <article class="finding ${f.sev}">
        <div class="finding-head">${TS.sevPill(f.sev)}<h3>${esc(f.title)}</h3><span class="cat">· ${f.srcs.map(s => esc(C.label(s))).join(' + ') || 'all sources'} · ${fmtN(f.count)}×${f.t0 != null ? ' · ' + esc(ft(f.t0)) + (f.t1 != null && f.t1 !== f.t0 ? ' – ' + esc(ft(f.t1).slice(11)) : '') : ''}</span></div>
        <p>${esc(f.why)}</p>
        ${f.evidence.length ? `<b class="small">Evidence</b><ul class="small">${f.evidence.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
        ${f.fix.length ? `<b class="small">Solution</b><ol class="small">${f.fix.map(x => `<li>${esc(x)}</li>`).join('')}</ol>` : ''}
        ${f.q ? `<div style="margin-top:6px"><button class="btn ghost" data-find="${i}" type="button">Show events</button></div>` : ''}
      </article>`).join('')}</div>`;
  }

  /* ================= KPIs ================= */
  function renderKpis() {
    const present = C.SOURCES.filter(s => S.files.some(f => f.src === s.id));
    const ref = refTime();
    $('kpis').innerHTML = present.map(s => {
      let v, sub;
      if (s.id === 'strust') {
        const st = S.data.certs.map(c => TS.x509.status(c, ref).key);
        v = fmtN(S.data.certs.length) + ' certs';
        sub = `${st.filter(k => k === 'expired').length} expired · ${st.filter(k => k === 'expiring').length} expiring ≤30 d`;
      } else if (s.id === 'sm59') {
        v = fmtN(S.data.tests.length) + ' tests';
        sub = `${S.data.tests.filter(t => !t.ok).length} failed`;
      } else {
        const ev = S.data.events.filter(e => e.src === s.id && (e.t == null || inRange(e.t)));
        const err = ev.filter(e => e.level === 'ERROR' || e.level === 'FATAL').length;
        v = fmtN(err) + ' errors';
        sub = `${fmtN(ev.filter(e => e.level === 'WARN').length)} warnings · ${fmtN(ev.length)} events`;
      }
      return `<div class="kpi"><div class="k">${esc(s.label)}</div><div class="v" style="font-size:20px">${v}</div><div class="s">${sub}</div></div>`;
    }).join('');
  }

  /* ================= Swimlane timeline ================= */
  function renderLanes() {
    const host = $('lanes');
    if (!host || !host.offsetParent || !S.data) return;
    const a = S.from != null ? S.from : S.data.tMin, b = S.to != null ? S.to : (S.data.tMax != null ? S.data.tMax + 1000 : null);
    $('laneLegend').innerHTML = '<span><i style="background:var(--lvl-error)"></i>ERROR</span><span><i style="background:var(--lvl-warn)"></i>WARN</span><span><i style="background:var(--muted)"></i>Event</span><span><i style="background:var(--select);border:1px solid var(--accent)"></i>Incident</span><span><i style="background:none;border-left:2px dashed var(--critical);border-radius:0"></i>Certificate expiry</span>';
    if (a == null || b == null || b <= a) { host.innerHTML = '<p class="muted">No events with timestamps — check the date format of the exports.</p>'; $('lanesNote').textContent = ''; return; }
    const lanes = C.SOURCES.filter(s => s.id !== 'strust' && S.data.events.some(e => e.src === s.id && e.t != null)).map(s => s.id);
    const W = Math.max(360, host.clientWidth), LW = W < 640 ? 96 : 150, PW = W - LW - 8, LH = 30, TOP = 22;
    const H = TOP + lanes.length * LH + 4;
    const N = Math.max(20, Math.floor(PW / 6)), bw = PW / N, span = b - a;
    const x = t => LW + (t - a) / span * PW;
    const bins = lanes.map(() => Array.from({ length: N }, () => ({ e: 0, w: 0, i: 0, titles: [] })));
    S.data.events.forEach(ev => {
      if (ev.t == null || ev.t < a || ev.t >= b) return;
      const li = lanes.indexOf(ev.src); if (li < 0) return;
      const bin = bins[li][Math.min(N - 1, Math.floor((ev.t - a) / span * N))];
      if (ev.level === 'ERROR' || ev.level === 'FATAL') bin.e++; else if (ev.level === 'WARN') bin.w++; else bin.i++;
      if (bin.titles.length < 3 && ev.level !== 'INFO') bin.titles.push(ev.title);
    });
    const max = Math.max(1, ...bins.flat().map(c => c.e + c.w + c.i));
    let svg = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Events per source over time">`;
    // incident bands
    S.incidents.forEach(inc => {
      if (inc.t1 < a || inc.t0 >= b) return;
      const x0 = x(Math.max(a, inc.t0)), x1 = Math.max(x0 + 3, x(Math.min(b, inc.t1 + 1000)));
      svg += `<rect class="inc-band" x="${x0}" y="${TOP - 4}" width="${x1 - x0}" height="${H - TOP + 4}" data-inc="${inc.id}"><title>Incident #${inc.id + 1}</title></rect>`;
      if (x1 - x0 > 14 || S.incidents.length < 40) svg += `<text class="tick inc-no" x="${x0 + 2}" y="${TOP - 8}">#${inc.id + 1}</text>`;
    });
    // axis ticks
    const nt = Math.max(2, Math.floor(PW / 150));
    for (let k = 0; k <= nt; k++) {
      const t = a + span * k / nt, xx = LW + PW * k / nt;
      svg += `<line class="gridline" x1="${xx}" x2="${xx}" y1="${TOP}" y2="${H}"/>`;
      if (k < nt) svg += `<text class="tick" x="${xx + 2}" y="10">${esc(span > 2 * 864e5 ? ft(t).slice(5, 16) : ft(t).slice(11, 19))}</text>`;
    }
    lanes.forEach((id, li) => {
      const y0 = TOP + li * LH, yb = y0 + LH - 4;
      const n = S.data.events.filter(e => e.src === id && e.t != null && e.t >= a && e.t < b && e.level !== 'INFO').length;
      svg += `<line class="baseline" x1="${LW}" x2="${W - 8}" y1="${yb + 0.5}" y2="${yb + 0.5}"/>`;
      svg += `<text class="lane-label" x="4" y="${y0 + LH / 2 + 2}">${esc(C.label(id))}</text><text class="tick" x="${LW - 6}" y="${y0 + LH / 2 + 2}" text-anchor="end">${compact(n)}</text>`;
      bins[li].forEach((c, bi) => {
        const tot = c.e + c.w + c.i;
        if (!tot) return;
        const h = Math.max(3, (LH - 8) * Math.sqrt(tot / max)), bx = LW + bi * bw + 0.5, w = Math.max(1.5, bw - 1);
        let yy = yb;
        [[c.e, 'var(--lvl-error)'], [c.w, 'var(--lvl-warn)'], [c.i, 'var(--muted)']].forEach(([v, col]) => {
          if (!v) return;
          const sh = Math.max(1.5, h * v / tot);
          yy -= sh;
          svg += `<rect x="${bx}" y="${yy.toFixed(1)}" width="${w}" height="${sh.toFixed(1)}" fill="${col}"/>`;
        });
        svg += `<rect class="hit" x="${LW + bi * bw}" y="${y0}" width="${bw}" height="${LH}" data-l="${li}" data-b="${bi}"/>`;
      });
    });
    // certificate expiry markers
    S.data.certs.forEach(c => {
      if (c.notAfter == null || c.notAfter < a || c.notAfter >= b) return;
      const xx = x(c.notAfter);
      svg += `<line class="cert-line" x1="${xx}" x2="${xx}" y1="${TOP - 4}" y2="${H}"><title>Certificate expires: ${esc(c.cn)} (${esc(ft(c.notAfter))})</title></line>`;
    });
    svg += '</svg>';
    host.innerHTML = svg;
    $('lanesNote').textContent = `${ft(a)} – ${ft(b)} · bar height ∝ √(events) · hover for details, click a bar to list its events, click a shaded band to open the incident.`;

    const tip = $('tooltip');
    host.querySelectorAll('.hit').forEach(el => {
      const li = +el.dataset.l, bi = +el.dataset.b, c = bins[li][bi];
      const t0 = a + span * bi / N, t1 = a + span * (bi + 1) / N;
      el.addEventListener('mousemove', ev => {
        tip.innerHTML = `<div style="font-weight:600;margin-bottom:4px">${esc(C.label(lanes[li]))} · ${esc(ft(t0))} – ${esc(ft(t1).slice(11))}</div>` +
          [['ERROR', c.e, 'var(--lvl-error)'], ['WARN', c.w, 'var(--lvl-warn)'], ['Event', c.i, 'var(--muted)']].filter(r => r[1])
            .map(([l, v, col]) => `<div class="tt-row"><span><i style="background:${col}"></i>${l}</span><b>${fmtN(v)}</b></div>`).join('') +
          (c.titles.length ? `<div class="muted" style="margin-top:4px">${c.titles.map(esc).join('<br>')}</div>` : '');
        tip.hidden = false;
        const tw = tip.offsetWidth, th = tip.offsetHeight;
        let lx = ev.clientX + 14, ly = ev.clientY + 14;
        if (lx + tw > window.innerWidth - 8) lx = ev.clientX - tw - 14;
        if (ly + th > window.innerHeight - 8) ly = ev.clientY - th - 14;
        tip.style.left = lx + 'px'; tip.style.top = ly + 'px';
      });
      el.addEventListener('mouseleave', () => (tip.hidden = true));
      el.addEventListener('click', () => { tip.hidden = true; showEventsFor({ srcs: [lanes[li]], from: t0, to: t1, label: `${C.label(lanes[li])} ${ft(t0).slice(11)}–${ft(t1).slice(11)}`, level: 'all' }); });
    });
    host.querySelectorAll('.inc-band').forEach(el => el.addEventListener('click', () => {
      const card = document.getElementById('inc-' + el.dataset.inc);
      if (card) { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); card.classList.add('flash'); setTimeout(() => card.classList.remove('flash'), 1500); }
    }));
  }
  const compact = v => v >= 1e6 ? (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M' : v >= 1e3 ? (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'k' : String(v);

  /* ================= Incidents ================= */
  function renderIncidents() {
    const list = S.incidents.slice();
    if (S.sort === 'score') list.sort((x, y) => y.score - x.score || x.t0 - y.t0);
    $('cntInc').textContent = fmtN(list.length);
    if (!list.length) { $('incidents').innerHTML = '<div class="empty">No error clusters in the selected range. Widen the time range or the correlation window.</div>'; return; }
    const shown = list.slice(0, 40);
    $('incidents').innerHTML = `<div class="findings">${shown.map(inc => {
      const key = keyEvents(inc);
      return `<article class="finding incident ${inc.sev}" id="inc-${inc.id}">
        <div class="finding-head">${TS.sevPill(inc.sev)}<h3>#${inc.id + 1} · ${esc(ft(inc.t0))}${inc.t1 > inc.t0 ? ' – ' + esc(ft(inc.t1).slice(11)) : ''}</h3>
          <span class="cat">· ${TS.fmtDuration(inc.t1 - inc.t0 + 1000)} · ${inc.bySrc.size} source${inc.bySrc.size === 1 ? '' : 's'} · ${fmtN(inc.events.length)} events (${fmtN(inc.errors)} errors)</span></div>
        <div class="inc-srcs">${[...inc.bySrc.entries()].map(([s, n]) => `<span class="badge">${esc(C.label(s))} ${fmtN(n)}</span>`).join('')}
          ${[...inc.codes.entries()].sort((x, y) => y[1] - x[1]).slice(0, 4).map(([c, n]) => `<span class="badge mono">${esc(c)}${n > 1 ? ' ×' + n : ''}</span>`).join('')}</div>
        ${inc.hints.length ? `<ul class="tt-hints">${inc.hints.map(h => `<li>${TS.sevPill(h.sev)}<span><b>${esc(h.title)}</b> — ${esc(h.text)}</span></li>`).join('')}</ul>`
          : '<p class="muted small">No cross-source pattern recognized — see the key events.</p>'}
        <details><summary>Key events (${key.length})</summary>
          <table class="simple inc-ev"><tbody>${key.map(e => `<tr class="clickable" data-ev="${e.id}"><td class="mono small">${esc(ft(e.t, true).slice(11))}</td><td class="small">${esc(C.label(e.src))}</td><td>${lvlBadge(e.level)}</td><td class="small">${esc(e.title)}</td></tr>`).join('')}</tbody></table>
        </details>
        <div style="margin-top:8px"><button class="btn" data-inc-ev="${inc.id}">Show all ${fmtN(inc.events.length)} events</button> <button class="btn ghost" data-inc-zoom="${inc.id}">Zoom timeline</button></div>
      </article>`;
    }).join('')}</div>${list.length > shown.length ? `<p class="muted small">Showing ${shown.length} of ${fmtN(list.length)} incidents.</p>` : ''}`;
  }
  // first event of every source plus the first errors, max 15
  function keyEvents(inc) {
    const out = [], seen = new Set();
    for (const e of inc.events) if (!seen.has(e.src)) { seen.add(e.src); out.push(e); }
    for (const e of inc.events) { if (out.length >= 15) break; if (e.level !== 'WARN' && !out.includes(e)) out.push(e); }
    return out.sort((x, y) => x.t - y.t);
  }
  function onIncidentClick(e) {
    const ev = e.target.closest('[data-ev]');
    if (ev) { showEvent(+ev.dataset.ev); return; }
    const b1 = e.target.closest('[data-inc-ev]');
    if (b1) { const inc = S.incidents[+b1.dataset.incEv]; showEventsFor({ from: inc.t0, to: inc.t1 + 1000, label: `Incident #${inc.id + 1}`, level: 'all' }); return; }
    const b2 = e.target.closest('[data-inc-zoom]');
    if (b2) {
      const inc = S.incidents[+b2.dataset.incZoom], pad = Math.max(S.win, (inc.t1 - inc.t0) * 0.5, 60000);
      S.from = inc.t0 - pad; S.to = inc.t1 + pad;
      slider.setRange(S.from, S.to);
      refresh();
      $('lanes').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  /* ================= Certificates & SM59 ================= */
  const ST_CLS = { expired: 'c-expired', notyet: 'c-notyet', expiring: 'c-expiring', soon: 'c-soon', ok: 'c-ok', unknown: 'c-notyet' };
  const stPill = st => `<span class="cst ${ST_CLS[st.key] || 'c-notyet'}">${esc(st.label)}</span>`;
  // PSE / file, or for certificates seen in a trace: where and how (own certificate of PSE x, client certificate received, …)
  const certWhere = c => {
    if (!c.observed || !c.observed.length) return c.pse || base(c.source);
    const what = [...new Set(c.observed.map(o => `${o.what}${o.pse ? ' · PSE ' + base(o.pse) : ''}`))].slice(0, 2).join('; ');
    return `${[...new Set(c.observed.map(o => base(o.source)))].join(', ')}: ${what}`;
  };
  function renderCerts() {
    const certs = S.data.certs.slice().sort((a, b) => (a.notAfter || 0) - (b.notAfter || 0));
    if (!certs.length) { $('certs').innerHTML = '<p class="muted">No certificates loaded. Export them from STRUST (.cer/.crt/.pem) or copy the certificate list into a .txt file.</p>'; return; }
    const ref = refTime(), now = Date.now();
    $('certs').innerHTML = `<p class="muted small">Status at the end of the analysis range (${esc(ft(ref))}) and today.</p><div class="table-wrap"><table class="simple"><thead><tr><th>Certificate</th><th>PSE / file</th><th>Valid to</th><th>At incident time</th><th>Today</th></tr></thead><tbody>${certs.map(c => {
      const iss = /(?:^|,\s*)CN=([^,]+)/i.exec(c.issuer || '');
      return `<tr><td title="${esc(c.subject)}"><b>${esc(c.cn)}</b>${c.san && c.san.length ? `<br><span class="small muted">SAN: ${esc(c.san.slice(0, 4).join(', '))}${c.san.length > 4 ? '…' : ''}</span>` : ''}<br><span class="small muted">Issuer: ${esc(iss ? iss[1] : c.issuer || '-')}${c.selfSigned ? ' (self-signed)' : ''}</span></td>
        <td class="small">${esc(certWhere(c))}</td><td class="mono small">${esc(ft(c.notAfter) || '-')}</td><td>${stPill(TS.x509.status(c, ref))}</td><td>${stPill(TS.x509.status(c, now))}</td></tr>`;
    }).join('')}</tbody></table></div>`;
  }
  function renderTests() {
    const tests = S.data.tests;
    if (!tests.length) { $('tests').innerHTML = '<p class="muted">No SM59 connection test results loaded.</p>'; return; }
    $('tests').innerHTML = `<div class="table-wrap"><table class="simple"><thead><tr><th>Destination</th><th>Result</th><th>Details</th><th>Time</th></tr></thead><tbody>${tests.map((t, i) => `
      <tr class="clickable" data-test="${i}"><td class="mono">${esc(t.dest)}</td><td><span class="stp ${t.ok ? 's2xx' : 's5xx'}">${t.ok ? 'OK' : 'Failed'}</span>${t.status ? ' <span class="small muted">HTTP ' + t.status + '</span>' : ''}</td>
      <td class="small">${esc([...t.codes, ...t.errors.slice(0, 2)].join(' · ') || t.durations.slice(0, 3).join(', '))}</td>
      <td class="mono small">${t.t != null ? esc(ft(t.t)) + (t.timeFrom === 'file date' ? '<br><span class="muted">(file date)</span>' : '') : '-'}</td></tr>`).join('')}</tbody></table></div>`;
    $('tests').querySelectorAll('[data-test]').forEach(tr => (tr.onclick = () => { const t = tests[+tr.dataset.test]; openModal(`SM59 — ${t.dest}`, `<pre class="big">${esc(t.raw)}</pre>`); }));
  }

  /* ================= Tops ================= */
  function groupTop(evs, keyFn, n) {
    const m = new Map();
    for (const e of evs) {
      const k = keyFn(e); if (!k) continue;
      const g = m.get(k) || { k, n: 0, first: e.t, last: e.t, src: e.src, sample: e };
      g.n++; if (e.t != null) { if (g.first == null || e.t < g.first) g.first = e.t; if (g.last == null || e.t > g.last) g.last = e.t; }
      m.set(k, g);
    }
    return [...m.values()].sort((a, b) => b.n - a.n).slice(0, n);
  }
  function renderTop() {
    const evs = S.data.events.filter(e => e.t == null || inRange(e.t));
    const dumps = groupTop(evs.filter(e => e.src === 'st22'), e => e.code, 12);
    $('topDumps').innerHTML = dumps.length ? `<table class="simple"><thead><tr><th>Runtime error</th><th class="num">Count</th><th>First – last</th></tr></thead><tbody>${dumps.map(g =>
      `<tr class="clickable" data-q="${esc(g.k)}" data-s="st22"><td class="mono">${esc(g.k)}</td><td class="num">${fmtN(g.n)}</td><td class="mono small">${esc(ft(g.first))}<br>${esc(ft(g.last))}</td></tr>`).join('')}</tbody></table>`
      : '<p class="muted">No ST22 dumps loaded (or none in the selected range).</p>';
    const codes = groupTop(evs.filter(e => e.src !== 'st22' && e.level !== 'INFO'), e => e.src + '\u0000' + (e.code || e.title), 15);
    $('topCodes').innerHTML = codes.length ? `<table class="simple"><thead><tr><th>Source</th><th>Code / message</th><th class="num">Count</th></tr></thead><tbody>${codes.map(g => {
      const k = g.k.split('\u0000')[1];
      return `<tr class="clickable" data-q="${esc(k)}" data-s="${g.src}"><td class="small">${esc(C.label(g.src))}</td><td class="mono small">${esc(k.slice(0, 160))}</td><td class="num">${fmtN(g.n)}</td></tr>`;
    }).join('')}</tbody></table>` : '<p class="muted">No errors in the selected range.</p>';
    [$('topDumps'), $('topCodes')].forEach(el => el.querySelectorAll('[data-q]').forEach(tr => (tr.onclick = () => showEventsFor({ srcs: [tr.dataset.s], q: tr.dataset.q, label: '', level: 'all' }))));
  }

  /* ================= Events ================= */
  function renderEventSources() {
    const present = C.SOURCES.filter(s => S.data.events.some(e => e.src === s.id));
    $('evSrc').innerHTML = present.map(s => `<label><input type="checkbox" value="${s.id}" ${!S.ev.srcs || S.ev.srcs.has(s.id) ? 'checked' : ''}>${esc(s.label)}</label>`).join('');
    $('evSrc').querySelectorAll('input').forEach(cb => (cb.onchange = () => {
      S.ev.srcs = new Set([...$('evSrc').querySelectorAll('input:checked')].map(x => x.value));
      S.page = 0; renderEvents();
    }));
  }
  function showEventsFor(o) {
    S.ev = { srcs: o.srcs ? new Set(o.srcs) : null, level: o.level || 'bad', q: o.q || '', from: o.from != null ? o.from : null, to: o.to != null ? o.to : null, label: o.label || '' };
    $('evLevel').value = S.ev.level; $('evText').value = S.ev.q; S.page = 0;
    renderEventSources(); renderEvents();
    $('eventsCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function filteredEvents() {
    const f = S.ev, q = f.q.trim().toLowerCase();
    return S.data.events.filter(e => {
      if (f.srcs && !f.srcs.has(e.src)) return false;
      if (f.level === 'bad' && e.level === 'INFO') return false;
      if (f.level === 'err' && !(e.level === 'ERROR' || e.level === 'FATAL')) return false;
      if (f.from != null || f.to != null) { if (e.t == null || (f.from != null && e.t < f.from) || (f.to != null && e.t >= f.to)) return false; }
      else if (e.t != null && !inRange(e.t)) return false;
      if (q && !`${e.code} ${e.title} ${e.text} ${e.who}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }
  function renderEvents() {
    const list = filteredEvents(), pages = Math.max(1, Math.ceil(list.length / PAGE));
    if (S.page >= pages) S.page = pages - 1;
    $('evChips').innerHTML = S.ev.label || S.ev.from != null ? `<span class="chip"><span>${esc(S.ev.label || 'Time filter')}</span><button aria-label="Remove filter" id="evChipX">✕</button></span>` : '';
    const x = $('evChipX'); if (x) x.onclick = () => { S.ev.from = S.ev.to = null; S.ev.label = ''; renderEvents(); };
    $('evCount').textContent = `${fmtN(list.length)} of ${fmtN(S.data.events.length)} events`;
    $('evPage').textContent = `${S.page + 1} / ${pages}`;
    $('evPrev').disabled = S.page === 0; $('evNext').disabled = S.page >= pages - 1;
    $('evTable').querySelector('tbody').innerHTML = list.slice(S.page * PAGE, (S.page + 1) * PAGE).map(e => `
      <tr class="clickable" data-id="${e.id}"><td>${esc(e.t != null ? ft(e.t, true) : '-')}</td><td class="small" style="font-family:var(--sans)">${esc(C.label(e.src))}</td><td>${lvlBadge(e.level)}</td>
      <td title="${esc(e.code)}">${esc(e.code)}</td><td class="msg"><b style="font-family:var(--sans)">${esc(e.title)}</b>${e.text && e.text !== e.title ? '<br>' + esc(e.text.slice(0, 400)) : ''}</td></tr>`).join('') ||
      '<tr><td colspan="5" class="muted" style="text-align:center;padding:24px">No events match the filter.</td></tr>';
  }

  function showEvent(id) {
    const e = S.data.events[id];
    const near = e.t == null ? [] : S.data.events.filter(x => x !== e && x.src !== e.src && x.t != null && Math.abs(x.t - e.t) <= S.win && x.level !== 'INFO').slice(0, 40);
    openModal(`${C.label(e.src)} — ${e.title.slice(0, 120)}`, `<div class="detail-box" style="padding:14px 16px">
      <div class="detail-meta"><span>Time: <b class="mono">${esc(e.t != null ? ft(e.t, true) : '-')}</b></span><span>Level: ${lvlBadge(e.level)}</span>${e.code ? `<span>Code: <b class="mono">${esc(e.code)}</b></span>` : ''}
      <span>File: <b class="mono">${esc(base(e.file))}</b>${e.line ? ' line ' + e.line : ''}</span>${e.who ? `<span>${esc(e.who)}</span>` : ''}${e.thread ? `<span>Thread: <b class="mono">${esc(e.thread)}</b></span>` : ''}</div>
      <pre>${esc(e.text + (e.detail ? '\n\n' + e.detail.slice(0, 20000) : ''))}</pre>
      <h4 style="margin:8px 0 0">Other sources within ±${TS.fmtDuration(S.win)} (${near.length})</h4>
      ${near.length ? `<table class="simple"><tbody>${near.map(x => `<tr><td class="mono small">${esc(ft(x.t, true).slice(11))}</td><td class="small">${esc(C.label(x.src))}</td><td>${lvlBadge(x.level)}</td><td class="small">${esc(x.title)}</td></tr>`).join('')}</tbody></table>` : '<p class="muted small">None.</p>'}
    </div>`);
  }
  function openModal(title, html) { $('modalTitle').textContent = title; $('modalBody').innerHTML = html; $('modal').hidden = false; }
  function closeModal() { $('modal').hidden = true; }

  /* ================= Report ================= */
  function exportReport() {
    const md = [], cell = s => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
    const ref = refTime();
    md.push('# SAP Correlation Report', '', `Generated: ${new Date().toLocaleString('en-US')} · Hopscope`, '');
    md.push(`Analysis range: ${ft(S.from != null ? S.from : S.data.tMin) || '-'} to ${ft(S.to != null ? S.to : S.data.tMax) || '-'} · correlation window ${TS.fmtDuration(S.win)}`, '');
    md.push('## Sources', '', '| File | Source | Events | Errors | Time range | Note |', '|---|---|---:|---:|---|---|');
    S.files.forEach(f => md.push(`| ${cell(base(f.name))} | ${cell(C.label(f.src))} | ${f.eventCount} | ${f.errCount} | ${f.tMin != null ? ft(f.tMin) + ' – ' + ft(f.tMax) : '-'} | ${cell(f.note)}${f.tzConverted ? ' (converted to server time)' : ''}${f.shiftH ? ` (shift ${f.shiftH} h)` : ''} |`));
    const tz = S.data.tz;
    md.push('', `Time base: ${tz.off != null ? `SAP server local time ${TS.fmtOffset(tz.off)} — ${tz.how}${tz.converted.length ? '; converted: ' + tz.converted.join(', ') : ''}` : tz.how === 'unknown' ? 'unknown — zone-aware logs not converted (' + tz.unconverted.join(', ') + ')' : 'times as written in the files'}.`);
    md.push('', '## Findings & solutions', '');
    if (!S.findings.length) md.push('_No known problem pattern in the selected range._', '');
    S.findings.forEach(f => {
      md.push(`### [${TS.SEV_LABEL[f.sev].toUpperCase()}] ${f.title}`, '', `${f.srcs.map(C.label).join(' + ') || 'All sources'} · ${f.count}×${f.t0 != null ? ' · ' + ft(f.t0) + (f.t1 != null && f.t1 !== f.t0 ? ' – ' + ft(f.t1).slice(11) : '') : ''}`, '', f.why, '');
      if (f.evidence.length) { md.push('**Evidence**', ''); f.evidence.forEach(x => md.push(`- ${x}`)); md.push(''); }
      if (f.fix.length) { md.push('**Solution**', ''); f.fix.forEach((x, i) => md.push(`${i + 1}. ${x}`)); md.push(''); }
    });
    md.push('## Correlated incidents', '');
    const list = S.incidents.slice().sort((a, b) => b.score - a.score).slice(0, 20);
    if (!list.length) md.push('_No error clusters in the selected range._', '');
    for (const inc of list) {
      md.push(`### #${inc.id + 1} [${TS.SEV_LABEL[inc.sev].toUpperCase()}] ${ft(inc.t0)} – ${ft(inc.t1).slice(11)}`, '');
      md.push(`- Sources: ${[...inc.bySrc.entries()].map(([s, n]) => `${C.label(s)} (${n})`).join(', ')}`);
      md.push(`- Events: ${inc.events.length} (${inc.errors} errors); codes: ${[...inc.codes.keys()].slice(0, 6).join(', ') || '-'}`);
      inc.hints.forEach(h => md.push(`- **${TS.SEV_LABEL[h.sev]} — ${h.title}:** ${h.text}`));
      md.push('', '| Time | Source | Level | Event |', '|---|---|---|---|');
      keyEvents(inc).forEach(e => md.push(`| ${ft(e.t, true).slice(11)} | ${C.label(e.src)} | ${e.level} | ${cell(e.title.slice(0, 160))} |`));
      md.push('');
    }
    if (S.data.certs.length) {
      md.push('## Certificates (STRUST & traces)', '', '| Certificate | Issuer | Where | Valid to | At incident time | Today |', '|---|---|---|---|---|---|');
      S.data.certs.forEach(c => md.push(`| ${cell(c.cn)} | ${cell(c.issuer)} | ${cell(certWhere(c))} | ${ft(c.notAfter) || '-'} | ${TS.x509.status(c, ref).label} | ${TS.x509.status(c, Date.now()).label} |`));
      md.push('');
    }
    if (S.data.tests.length) {
      md.push('## Connection tests (SM59)', '', '| Destination | Result | Details | Time |', '|---|---|---|---|');
      S.data.tests.forEach(t => md.push(`| ${cell(t.dest)} | ${t.ok ? 'OK' : 'Failed'}${t.status ? ' (HTTP ' + t.status + ')' : ''} | ${cell([...t.codes, ...t.errors.slice(0, 2)].join(' · '))} | ${t.t != null ? ft(t.t) + (t.timeFrom === 'file date' ? ' (file date)' : '') : '-'} |`));
      md.push('');
    }
    const evs = S.data.events.filter(e => e.t == null || inRange(e.t));
    const dumps = groupTop(evs.filter(e => e.src === 'st22'), e => e.code, 12);
    if (dumps.length) { md.push('## Top ABAP dumps (ST22)', '', '| Runtime error | Count |', '|---|---:|'); dumps.forEach(g => md.push(`| ${cell(g.k)} | ${g.n} |`)); md.push(''); }
    const codes = groupTop(evs.filter(e => e.src !== 'st22' && e.level !== 'INFO'), e => e.src + '\u0000' + (e.code || e.title), 15);
    if (codes.length) { md.push('## Top error codes / messages', '', '| Source | Code / message | Count |', '|---|---|---:|'); codes.forEach(g => md.push(`| ${C.label(g.src)} | ${cell(g.k.split('\u0000')[1].slice(0, 160))} | ${g.n} |`)); }
    TS.download(`sap-correlation-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')}.md`, md.join('\n'), 'text/markdown;charset=utf-8');
  }

  document.addEventListener('DOMContentLoaded', init);
})(window.TS);
