/* SAP Troubleshooting Toolkit - Log Analyzer UI */
(function (TS) {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = TS.esc, sevPill = TS.sevPill, SEV_LABEL = TS.SEV_LABEL, debounce = TS.debounce;
  const readPref = TS.readPref, writePref = TS.writePref;
  const fmtN = n => (n || 0).toLocaleString('en-US');
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const PAGE_SIZE = 200;

  const lvlBadge = l => `<span class="lvl ${l}">${l}</span>`;
  const sevOf = f => f.sev || f.rule.sev;   // severity of a finding, possibly adjusted by the module (review)

  const S = {
    module: null, files: [], skipped: [], entries: [], res: null, byFile: null,
    filter: null, filtered: [], page: 0, desc: false, open: new Set()
  };
  const freshFilter = () => ({ levels: new Set(TS.LEVELS), file: '', q: '', regex: false, from: null, to: null, rule: null, group: null, exc: null, logger: null, label: {} });
  S.filter = freshFilter();

  const off = () => (S.res ? S.res.offset : null);
  const ft = (t, ms) => TS.fmtTime(t, off(), ms);

  /* ================= Init ================= */
  function init() {
    const sel = $('moduleSelect');
    sel.innerHTML = TS.modules.map(m => `<option value="${m.id}">${esc(m.name)}</option>`).join('');
    sel.onchange = () => { setModule(sel.value); if (S.files.length) rebuild(); };
    setModule(TS.modules[0].id);

    const dz = $('dropzone');
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
    dz.addEventListener('drop', async e => addFiles(await TS.filesFromDrop(e.dataTransfer)));
    // Allow dropping onto the whole page once data is loaded
    document.addEventListener('dragover', e => e.preventDefault());
    document.addEventListener('drop', async e => { if (!dz.contains(e.target)) { e.preventDefault(); addFiles(await TS.filesFromDrop(e.dataTransfer)); } });

    $('btnPickFiles').onclick = () => $('inputFiles').click();
    $('btnPickFolder').onclick = () => $('inputFolder').click();
    $('btnAdd').onclick = () => $('inputFiles').click();
    $('inputFiles').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('inputFolder').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('btnReset').onclick = reset;
    $('btnReport').onclick = exportReport;
    TS.initThemeButton($('btnTheme'));

    document.querySelectorAll('#tabs button').forEach(b => (b.onclick = () => showTab(b.dataset.tab)));
    $('modalClose').onclick = closeModal;
    $('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

    initViewerControls();
    let rt;
    window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => S.res && renderChart(), 150); });
    // inside the cockpit: it sends the files of one component (module) at a time
    TS.embed.listen({
      files: d => { if (d.module && TS.getModule(d.module)) { S.lockModule = true; setModule(d.module); sel.value = d.module; } addFiles(TS.embed.toFiles(d.files), true); },
      reset: () => { S.lockModule = false; reset(); }
    });
  }

  function setModule(id) {
    S.module = TS.getModule(id);
    $('dzTitle').textContent = `Drop ${S.module.name} log / trace files here`;
    $('dzDesc').textContent = S.module.description;
    $('guidePreview').innerHTML = `<h2>Collecting logs — ${esc(S.module.short || S.module.name)}</h2>` + guideList(S.module);
  }
  const guideList = m => `<ul class="guide-list">${(m.guide || []).map(([k, v]) => `<li><b class="k">${esc(k)}</b><span>${v}</span></li>`).join('')}</ul>`;

  /* ---------- Loading ---------- */
  function setStatus(msg, isErr) {
    const s = $('status');
    s.textContent = msg || '';
    s.classList.toggle('error', !!isErr);
  }

  async function addFiles(fileList, fromCockpit) {
    if (!fileList || !fileList.length) return;
    if (!fromCockpit && TS.embed.forward(fileList)) return;
    showLoader(true);
    try {
      const { out, skipped } = await TS.readInputs(fileList, msg => setStatus(msg));
      S.skipped.push(...skipped);
      for (let i = 0; i < out.length; i++) {
        const f = out[i];
        if (S.files.some(x => x.name === f.name && x.size === f.size)) { S.skipped.push({ name: f.name, reason: 'already loaded (duplicate)' }); continue; }
        setStatus(`Parsing ${f.name} (${i + 1}/${out.length})…`);
        await new Promise(r => setTimeout(r, 0));
        S.files.push({ name: f.name, size: f.size, text: f.text });
      }
      if (!S.files.length) { setStatus('No readable log/trace files. ' + skipped.map(s => `${s.name}: ${s.reason}`).join('; '), true); TS.embed.report({ status: 'empty', badge: '0', line: 'No readable log files' }); return; }
      autoSelectModule();
      setStatus('Analyzing…');
      await new Promise(r => setTimeout(r, 0));
      rebuild();
      setStatus('');
      showLoader(false);
      renderChart(); // needs the panel to be visible to measure its width
    } catch (err) {
      console.error(err);
      setStatus('Failed to process files: ' + err.message, true);
    }
  }

  // Switch to the component whose file-name patterns match most loaded files (e.g. dev_icm → ICM).
  function autoSelectModule() {
    if (S.lockModule) return;   // chosen by the cockpit
    const score = m => S.files.filter(f => TS.fileTypeOf(m, f.name)).length;
    let best = S.module, bestScore = score(S.module);
    for (const m of TS.modules) { const s = score(m); if (s > bestScore) { best = m; bestScore = s; } }
    if (best !== S.module) { setModule(best.id); $('moduleSelect').value = best.id; }
  }

  function showLoader(on) {
    const has = S.files.length > 0;
    $('loader').hidden = !on && has;
    $('app').hidden = on || !has;
    ['btnAdd', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = !has));
  }

  function reset() {
    S.files = []; S.skipped = []; S.entries = []; S.res = null; S.byFile = null;
    S.filter = freshFilter(); S.open.clear(); S.page = 0;
    setStatus('');
    showLoader(true);
  }

  // (Re)parse all files with the current module and re-run the analysis.
  function rebuild() {
    const all = [];
    for (const f of S.files) {
      const p = TS.parseText(f.text, f.name, S.module);
      const ftype = TS.fileTypeOf(S.module, f.name);
      let tMin = null, tMax = null; const lv = {};
      for (const e of p.entries) {
        lv[e.level] = (lv[e.level] || 0) + 1;
        if (e.t != null) { if (tMin === null || e.t < tMin) tMin = e.t; if (tMax === null || e.t > tMax) tMax = e.t; }
      }
      Object.assign(f, { parser: p.parser, ratio: p.ratio, lineCount: p.lineCount, entryCount: p.entries.length, tMin, tMax, lv, typeLabel: ftype ? ftype.label : '-' });
      for (const e of p.entries) all.push(e);
    }
    all.sort((a, b) => (a.t == null ? 1 : 0) - (b.t == null ? 1 : 0) || (a.t || 0) - (b.t || 0) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line);
    all.forEach((e, i) => { e.id = i; });
    S.entries = all;
    S.byFile = null;
    S.res = TS.analyze(all, S.module);
    S.filter = freshFilter(); S.open.clear(); S.page = 0;
    renderAll();
    const r = S.res, top = r.findings.find(f => sevOf(f) !== 'info'), errs = r.levels.FATAL + r.levels.ERROR;
    const worst = top ? sevOf(top) : null;
    TS.embed.report({
      status: worst === 'critical' || worst === 'high' ? 'fail' : worst ? 'warn' : 'ok', module: S.module.id,
      badge: String(r.findings.filter(f => sevOf(f) !== 'info').length),
      line: top ? `${top.rule.title} (${fmtN(top.count)}×)` : `${fmtN(errs)} errors, no known pattern`
    });
  }

  /* ================= Rendering ================= */
  function renderAll() {
    const r = S.res;
    const actionable = r.findings.filter(f => sevOf(f) !== 'info').length;
    $('cntFindings').textContent = actionable;
    $('cntGroups').textContent = fmtN(r.groups.length);
    $('cntExc').textContent = fmtN(r.exceptions.length);
    $('lblExc').textContent = S.module.exceptionsLabel || 'Exceptions';
    $('cntFiles').textContent = S.files.length;
    renderSummary(); renderFindings(); renderGroups(); renderExceptions(); renderInfo(); renderFiles(); renderGuide();
    renderLevelFilter(); renderFileFilter(); renderTimeSlider(); applyFilter();
  }

  function showTab(name) {
    document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
    if (name === 'summary') renderChart();
    window.scrollTo({ top: 0 });
  }

  /* ---------- Summary ---------- */
  function renderSummary() {
    const r = S.res, L = r.levels;
    const bad = L.FATAL + L.ERROR;
    const crit = r.findings.filter(f => sevOf(f) === 'critical' || sevOf(f) === 'high').length;
    const span = r.tMin != null ? r.tMax - r.tMin : null;
    const topFind = r.findings.filter(f => sevOf(f) !== 'info').slice(0, 6);
    const topGroups = r.groups.filter(g => g.level !== 'WARN').slice(0, 6);
    const topWarn = r.groups.filter(g => g.level === 'WARN').slice(0, 4);
    const topLog = TS.topN(r.loggersBad, 8);
    const maxLog = topLog.length ? topLog[0][1] : 1;

    $('tab-summary').innerHTML = `
      <div class="kpis">
        <div class="kpi"><div class="k">Total entries</div><div class="v">${fmtN(r.total)}</div><div class="s">${S.files.length} file(s)</div></div>
        <div class="kpi"><div class="k">${lvlBadge('ERROR')} FATAL + ERROR</div><div class="v">${fmtN(bad)}</div><div class="s">${r.total ? ((bad / r.total) * 100).toFixed(2) : 0}% of total</div></div>
        <div class="kpi"><div class="k">${lvlBadge('WARN')}</div><div class="v">${fmtN(L.WARN)}</div><div class="s">${fmtN(r.groups.filter(g => g.level === 'WARN').length)} distinct patterns</div></div>
        <div class="kpi"><div class="k">Critical / high findings</div><div class="v">${crit}</div><div class="s">${r.findings.filter(f => sevOf(f) !== 'info').length} findings in total</div></div>
        <div class="kpi"><div class="k">Time range</div><div class="v" style="font-size:16px">${r.tMin != null ? esc(ft(r.tMin)) : '-'}</div><div class="s">to ${r.tMax != null ? esc(ft(r.tMax)) : '-'} · ${TS.fmtDuration(span)}</div></div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Distribution over time</h2>
          <div class="legend" id="chartLegend"></div><span class="spacer"></span>
          <label class="chk small"><input type="checkbox" id="chkInfo"> Show INFO &amp; others</label>
        </div>
        <div class="chart" id="chart"></div>
        <div class="muted small" id="chartNote"></div>
      </div>

      <div class="two-col">
        <div class="card">
          <div class="card-head"><h2>Top findings</h2><span class="spacer"></span><button class="btn link" data-goto="findings">View all →</button></div>
          ${topFind.length ? `<ul class="mini-list">${topFind.map(f => `<li data-rule="${f.rule.id}">${sevPill(sevOf(f))}<span>${esc(f.rule.title)}</span><span class="n">${fmtN(f.count)}×</span></li>`).join('')}</ul>` : '<p class="muted">No known problem patterns detected. Check the Error Groups tab for errors not yet covered by the knowledge base.</p>'}
        </div>
        <div class="card">
          <div class="card-head"><h2>${esc(S.module.loggerLabel || 'Loggers with most WARN/ERROR')}</h2></div>
          ${topLog.length ? `<table class="simple"><tbody>${topLog.map(([k, n]) => `<tr class="clickable" data-logger="${esc(k)}"><td class="mono" title="${esc(k)}">${esc(shortLogger(k))}</td><td class="num"><div class="meter"><span class="bar" style="width:${Math.max(4, (n / maxLog) * 80)}px"></span>${fmtN(n)}</div></td></tr>`).join('')}</tbody></table>` : '<p class="muted">None.</p>'}
        </div>
      </div>

      <div class="card" style="margin-top:14px">
        <div class="card-head"><h2>Most frequent errors</h2><span class="spacer"></span><button class="btn link" data-goto="groups">All groups →</button></div>
        ${groupTable(topGroups.concat(topWarn))}
      </div>`;

    const p = $('tab-summary');
    $('chkInfo').checked = readPref('chartInfo') === '1';
    $('chkInfo').onchange = e => { writePref('chartInfo', e.target.checked ? '1' : '0'); renderChart(); };
    p.querySelectorAll('[data-goto]').forEach(b => (b.onclick = () => showTab(b.dataset.goto)));
    p.querySelectorAll('[data-rule]').forEach(li => (li.onclick = () => gotoViewer({ rule: li.dataset.rule })));
    p.querySelectorAll('[data-logger]').forEach(tr => (tr.onclick = () => gotoViewer({ logger: tr.dataset.logger, levels: ['FATAL', 'ERROR', 'WARN'] })));
    bindGroupRows(p);
    renderChart();
  }

  const shortLogger = l => { const parts = String(l).split('.'); return parts.length > 3 ? '…' + parts.slice(-2).join('.') : l; };

  /* ---------- Histogram (stacked bars, SVG) ---------- */
  function renderChart() {
    const host = $('chart');
    if (!host || !host.offsetParent) return;
    const r = S.res;
    if (!r.hist) { host.innerHTML = '<p class="muted">No recognizable timestamps.</p>'; $('chartLegend').innerHTML = ''; return; }
    const showInfo = $('chkInfo').checked;
    const series = [
      { key: 'ERROR', label: 'FATAL + ERROR', color: 'var(--lvl-error)', val: b => b.FATAL + b.ERROR },
      { key: 'WARN', label: 'WARN', color: 'var(--lvl-warn)', val: b => b.WARN }
    ];
    if (showInfo) series.push({ key: 'INFO', label: 'INFO / DEBUG / other', color: 'var(--lvl-info)', val: b => b.INFO + b.DEBUG + b.TRACE + b.OTHER });
    $('chartLegend').innerHTML = series.map(s => `<span><i style="background:${s.color}"></i>${s.label}</span>`).join('');

    const bins = r.hist.bins;
    const W = Math.max(320, host.clientWidth), H = 200, padL = 44, padR = 8, padT = 8, padB = 24;
    const iw = W - padL - padR, ih = H - padT - padB;
    const totals = bins.map(b => series.reduce((a, s) => a + s.val(b), 0));
    const max = Math.max(1, ...totals);
    const ticks = niceTicks(max);
    const yMax = ticks[ticks.length - 1];
    const bw = iw / bins.length, gap = bw > 6 ? 2 : bw > 3 ? 1 : 0;
    const y = v => padT + ih - (v / yMax) * ih;

    let svg = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Entries per ${bucketLabel(r.hist.bucket)}">`;
    for (const t of ticks) {
      svg += `<line class="${t === 0 ? 'baseline' : 'gridline'}" x1="${padL}" x2="${W - padR}" y1="${y(t)}" y2="${y(t)}"/>`;
      svg += `<text class="tick" x="${padL - 6}" y="${y(t) + 4}" text-anchor="end">${compact(t)}</text>`;
    }
    bins.forEach((b, i) => {
      const x = padL + i * bw + gap / 2, w = Math.max(1, bw - gap);
      let acc = 0;
      const segs = series.map(s => ({ s, v: s.val(b) })).filter(o => o.v > 0);
      segs.forEach((o, j) => {
        const y0 = y(acc), y1 = y(acc + o.v);
        acc += o.v;
        let h = y0 - y1;
        const isTop = j === segs.length - 1;
        const g = j > 0 && h > 3 ? 2 : 0; // surface gap between stacked segments
        h = Math.max(1, h - g);
        svg += isTop && w >= 6 && h >= 4 ? `<path d="${roundTop(x, y1, w, h, Math.min(4, w / 2, h))}" fill="${o.s.color}"/>`
          : `<rect x="${x}" y="${y1}" width="${w}" height="${h}" fill="${o.s.color}"/>`;
      });
      svg += `<rect class="hit" data-i="${i}" x="${padL + i * bw}" y="${padT}" width="${bw}" height="${ih}"/>`;
    });
    // x ticks
    const nx = Math.min(bins.length, Math.max(2, Math.floor(iw / 120)));
    const step = Math.max(1, Math.round(bins.length / nx));
    for (let i = 0; i < bins.length; i += step) {
      svg += `<text class="tick" x="${padL + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${esc(axisTime(bins[i].t0, r.hist.bucket))}</text>`;
    }
    svg += '</svg>';
    host.innerHTML = svg;
    $('chartNote').textContent = `Per ${bucketLabel(r.hist.bucket)} · time zone: ${TS.fmtOffset(r.offset)} · click a bar to open the entries in that range.`;

    const tip = $('tooltip');
    host.querySelectorAll('.hit').forEach(el => {
      const b = bins[+el.dataset.i];
      el.addEventListener('mousemove', ev => {
        tip.innerHTML = `<div style="font-weight:600;margin-bottom:4px">${esc(ft(b.t0))} – ${esc(ft(b.t1).slice(11))}</div>` +
          series.map(s => `<div class="tt-row"><span><i style="background:${s.color}"></i>${s.label}</span><b>${fmtN(s.val(b))}</b></div>`).join('');
        tip.hidden = false;
        const tw = tip.offsetWidth, th = tip.offsetHeight;
        let lx = ev.clientX + 14, ly = ev.clientY + 14;
        if (lx + tw > window.innerWidth - 8) lx = ev.clientX - tw - 14;
        if (ly + th > window.innerHeight - 8) ly = ev.clientY - th - 14;
        tip.style.left = lx + 'px'; tip.style.top = ly + 'px';
      });
      el.addEventListener('mouseleave', () => (tip.hidden = true));
      el.addEventListener('click', () => { tip.hidden = true; gotoViewer({ from: b.t0, to: b.t1, levels: showInfo ? null : ['FATAL', 'ERROR', 'WARN'] }); });
    });
  }
  function roundTop(x, y, w, h, r) {
    return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
  }
  function niceTicks(max) {
    const raw = max / 4, mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const stepv = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= raw) || raw;
    const st = Math.max(1, Math.ceil(stepv));
    const out = [];
    for (let v = 0; v < max + st; v += st) { out.push(v); if (v >= max) break; }
    return out;
  }
  const compact = v => v >= 1e6 ? (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M' : v >= 1e3 ? (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'k' : String(v);
  const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
  const bucketLabel = b => b < 3600e3 ? plural(b / 60e3, 'minute') : b < 864e5 ? plural(b / 3600e3, 'hour') : plural(b / 864e5, 'day');
  const axisTime = (t, b) => { const s = ft(t); return b >= 864e5 ? s.slice(5, 10) : s.slice(5, 16); };

  /* ---------- Findings ---------- */
  function renderFindings() {
    const fs = S.res.findings;
    const act = fs.filter(f => sevOf(f) !== 'info'), info = fs.filter(f => sevOf(f) === 'info');
    const card = f => {
      const r = f.rule, sample = S.entries[f.sample];
      return `<article class="finding ${sevOf(f)}">
        <div class="finding-head">${sevPill(sevOf(f))}<h3>${esc(r.title)}</h3><span class="cat">· ${esc(r.cat)}</span></div>
        <div class="finding-meta"><span><b>${fmtN(f.count)}</b> entries</span><span>First: <b>${esc(ft(f.first)) || '-'}</b></span><span>Last: <b>${esc(ft(f.last)) || '-'}</b></span><span>${f.files.size} file(s)</span></div>
        <p>${esc(r.why)}</p>${f.note ? `<p class="ls-note">${esc(f.note)}</p>` : ''}
        ${r.fix && r.fix.length ? `<b class="small">Recommended actions</b><ul>${r.fix.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
        <div class="sample">${esc(sample ? sample.message.slice(0, 400) : '')}</div>
        <div style="margin-top:8px"><button class="btn" data-rule="${r.id}">View ${fmtN(f.count)} entries →</button></div>
      </article>`;
    };
    $('tab-findings').innerHTML =
      (act.length ? `<div class="findings">${act.map(card).join('')}</div>`
        : `<div class="empty">No problem patterns from the ${esc(S.module.short)} knowledge base matched. Check the <b>Error Groups</b> and <b>Exceptions</b> tabs for other errors.</div>`) +
      (info.length ? `<h3 class="section-title">Informational events</h3><div class="findings">${info.map(card).join('')}</div>` : '');
    $('tab-findings').querySelectorAll('[data-rule]').forEach(b => (b.onclick = () => gotoViewer({ rule: b.dataset.rule })));
  }

  /* ---------- Groups ---------- */
  function groupTable(groups) {
    if (!groups.length) return '<p class="muted">No WARN/ERROR entries.</p>';
    return `<div class="table-wrap"><table class="simple"><thead><tr><th>Level</th><th class="num">Count</th><th>Logger</th><th>Message pattern</th><th>First</th><th>Last</th></tr></thead><tbody>${groups.map(g =>
      `<tr class="clickable" data-group="${esc(g.key)}"><td>${lvlBadge(g.level)}</td><td class="num">${fmtN(g.count)}</td><td class="mono" title="${esc(g.logger)}">${esc(shortLogger(g.logger))}</td><td class="mono">${esc(g.sig.slice(0, 220))}</td><td class="mono small">${esc(ft(g.first))}</td><td class="mono small">${esc(ft(g.last))}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function bindGroupRows(root) {
    root.querySelectorAll('[data-group]').forEach(tr => (tr.onclick = () => gotoViewer({ group: tr.dataset.group })));
  }
  function renderGroups() {
    const p = $('tab-groups');
    p.innerHTML = `<div class="card-head"><h2>Error &amp; warning groups</h2><span class="muted small">Messages with the same pattern (numbers, IPs, UUIDs normalized) are merged. Click a row to see its entries.</span><span class="spacer"></span><input type="search" id="gSearch" placeholder="Filter groups…"></div><div id="gTable"></div>`;
    const draw = () => {
      const q = $('gSearch').value.toLowerCase();
      const list = S.res.groups.filter(g => !q || (g.sig + ' ' + g.logger).toLowerCase().includes(q));
      $('gTable').innerHTML = groupTable(list.slice(0, 500)) + (list.length > 500 ? `<p class="muted small">Showing 500 of ${fmtN(list.length)} groups.</p>` : '');
      bindGroupRows($('gTable'));
    };
    $('gSearch').oninput = debounce(draw, 200);
    draw();
  }

  /* ---------- Exceptions ---------- */
  function renderExceptions() {
    const ex = S.res.exceptions;
    const m = S.module;
    $('tab-exceptions').innerHTML = `<div class="card-head"><h2>${esc(m.exceptionsTitle || 'Exceptions (root cause)')}</h2><span class="muted small">${esc(m.exceptionsHint || 'Taken from the last "Caused by:" in the stack trace of WARN/ERROR entries.')}</span></div>` +
      (ex.length ? `<div class="table-wrap"><table class="simple"><thead><tr><th>${esc(m.exceptionsLabel ? 'Code' : 'Exception')}</th><th class="num">Count</th><th>Sample message</th><th>First</th><th>Last</th></tr></thead><tbody>${ex.slice(0, 300).map(x =>
        `<tr class="clickable" data-exc="${esc(x.name)}"><td class="mono">${esc(x.name)}</td><td class="num">${fmtN(x.count)}</td><td class="mono small">${esc(x.msg.slice(0, 240))}</td><td class="mono small">${esc(ft(x.first))}</td><td class="mono small">${esc(ft(x.last))}</td></tr>`).join('')}</tbody></table></div>`
        : `<div class="empty">No ${esc((m.exceptionsLabel || 'exceptions').toLowerCase())} in WARN/ERROR entries.</div>`);
    $('tab-exceptions').querySelectorAll('[data-exc]').forEach(tr => (tr.onclick = () => gotoViewer({ exc: tr.dataset.exc })));
  }

  /* ---------- Info ---------- */
  function renderInfo() {
    const ins = S.res.insights;
    const r = S.res;
    let html = `<div class="grid">`;
    html += `<div class="card"><h2>System info (extracted from logs)</h2><table class="kv simple"><tbody>
      ${(ins && ins.kv ? ins.kv : []).map(([k, v]) => `<tr><th>${esc(k)}</th><td class="mono">${esc(v)}</td></tr>`).join('')}
      <tr><th>Log time zone</th><td class="mono">${esc(TS.fmtOffset(r.offset))}</td></tr>
      <tr><th>Unique threads</th><td class="mono">${fmtN(r.threads.size)}</td></tr>
      <tr><th>Unique loggers</th><td class="mono">${fmtN(r.loggers.size)}</td></tr>
    </tbody></table></div>`;
    (ins && ins.tables || []).forEach(t => {
      const numCol = t.cols.map((c, i) => t.rows.length && t.rows.every(r => typeof r[i] === 'number'));
      html += `<div class="card"><h2>${esc(t.title)}</h2>${t.rows.length ? `<div class="table-wrap"><table class="simple"><thead><tr>${t.cols.map((c, i) => `<th class="${numCol[i] ? 'num' : ''}">${esc(c)}</th>`).join('')}</tr></thead><tbody>${t.rows.map(row =>
        `<tr class="clickable" data-q="${esc(row[t.filterCol || 0])}">${row.map((c, i) => `<td class="${numCol[i] ? 'num' : 'mono'}">${esc(typeof c === 'number' ? fmtN(c) : c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : '<p class="muted">No data.</p>'}</div>`;
    });
    const lv = TS.LEVELS.filter(l => r.levels[l]);
    html += `<div class="card"><h2>Level distribution</h2><table class="simple"><tbody>${lv.map(l => `<tr><td>${lvlBadge(l)}</td><td class="num">${fmtN(r.levels[l])}</td></tr>`).join('')}</tbody></table></div>`;
    html += `</div>`;
    $('tab-info').innerHTML = html;
    $('tab-info').querySelectorAll('[data-q]').forEach(tr => (tr.onclick = () => gotoViewer({ q: tr.dataset.q, levels: ['FATAL', 'ERROR', 'WARN'] })));
  }

  /* ---------- Files ---------- */
  function renderFiles() {
    const rows = S.files.map(f => `<tr class="clickable" data-file="${esc(f.name)}">
      <td class="mono" title="${esc(f.name)}">${esc(f.name)}</td><td>${esc(f.typeLabel)}</td><td class="small">${esc(f.parser.label)}</td>
      <td class="num">${Math.round(f.ratio * 100)}%</td><td class="num">${fmtN(f.lineCount)}</td><td class="num">${fmtN(f.entryCount)}</td>
      <td class="num">${fmtN((f.lv.FATAL || 0) + (f.lv.ERROR || 0))}</td><td class="num">${fmtN(f.lv.WARN || 0)}</td>
      <td class="mono small">${esc(ft(f.tMin))}<br>${esc(ft(f.tMax))}</td></tr>`).join('');
    $('tab-files').innerHTML = `<div class="card-head"><h2>Analyzed files</h2><span class="muted small">"Recognized" = percentage of sampled lines matching the detected format.</span></div>
      <div class="table-wrap"><table class="simple"><thead><tr><th>File</th><th>Type</th><th>Detected format</th><th class="num">Recognized</th><th class="num">Lines</th><th class="num">Entries</th><th class="num">ERROR</th><th class="num">WARN</th><th>Time range</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${S.skipped.length ? `<h3 class="section-title">Skipped (${S.skipped.length})</h3><div class="table-wrap"><table class="simple"><tbody>${S.skipped.map(s => `<tr><td class="mono">${esc(s.name)}</td><td class="muted">${esc(s.reason)}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
    $('tab-files').querySelectorAll('[data-file]').forEach(tr => (tr.onclick = () => gotoViewer({ file: tr.dataset.file })));
  }

  function renderGuide() {
    $('tab-guide').innerHTML = `<div class="grid">
      <div class="card"><h2>Collecting logs — ${esc(S.module.name)}</h2>${guideList(S.module)}</div>
      <div class="card"><h2>How to use this toolkit</h2><ul class="guide-list">
        <li><b class="k">Summary</b><span>Start with the time distribution chart to see when errors spike; click a bar to open the entries in that range.</span></li>
        <li><b class="k">Findings</b><span>Problem patterns recognized from the knowledge base, with common causes and recommended actions.</span></li>
        <li><b class="k">Error Groups / Exceptions</b><span>Errors not yet covered by the knowledge base still show up here, grouped by message pattern and root cause.</span></li>
        <li><b class="k">Log Viewer</b><span>Filter by level, text/regex, file and time range. Click a row for details &amp; stack trace, then “Context” to see the surrounding lines in the original file.</span></li>
        <li><b class="k">Export</b><span>“Export report (.md)” creates a summary for tickets/incidents; “Export CSV” exports the filtered Log Viewer results.</span></li>
        <li><b class="k">Privacy</b><span>All processing happens in this browser. No data is sent to any server.</span></li>
      </ul></div></div>`;
  }

  /* ================= Viewer ================= */
  function initViewerControls() {
    const upd = debounce(() => { S.filter.q = $('fText').value; S.page = 0; applyFilter(); }, 250);
    $('fText').oninput = upd;
    $('fRegex').onchange = () => { S.filter.regex = $('fRegex').checked; S.page = 0; applyFilter(); };
    $('fFile').onchange = () => { S.filter.file = $('fFile').value; S.page = 0; applyFilter(); };
    initTimeSlider();
    $('btnClearFilter').onclick = () => { S.filter = freshFilter(); syncControls(); S.page = 0; applyFilter(); };
    $('btnSort').onclick = () => { S.desc = !S.desc; $('btnSort').textContent = S.desc ? 'Sort: newest → oldest' : 'Sort: oldest → newest'; S.page = 0; applyFilter(); };
    $('btnCsv').onclick = exportCsv;
    $('pgPrev').onclick = () => { if (S.page > 0) { S.page--; renderRows(); } };
    $('pgNext').onclick = () => { if ((S.page + 1) * PAGE_SIZE < S.filtered.length) { S.page++; renderRows(); } };
    $('logTable').querySelector('tbody').addEventListener('click', onRowClick);
  }

  function renderLevelFilter() {
    $('lvlFilter').innerHTML = TS.LEVELS.filter(l => S.res.levels[l]).map(l =>
      `<label><input type="checkbox" value="${l}" ${S.filter.levels.has(l) ? 'checked' : ''}>${lvlBadge(l)}<span class="n">${compact(S.res.levels[l])}</span></label>`).join('');
    $('lvlFilter').querySelectorAll('input').forEach(cb => (cb.onchange = () => {
      cb.checked ? S.filter.levels.add(cb.value) : S.filter.levels.delete(cb.value);
      S.page = 0; applyFilter();
    }));
  }
  function renderFileFilter() {
    $('fFile').innerHTML = '<option value="">All files</option>' + S.files.map(f => `<option value="${esc(f.name)}">${esc(base(f.name))}</option>`).join('');
  }
  function syncControls() {
    const f = S.filter;
    $('fText').value = f.q; $('fRegex').checked = f.regex; $('fFile').value = f.file;
    $('lvlFilter').querySelectorAll('input').forEach(cb => (cb.checked = f.levels.has(cb.value)));
    syncTimeSlider();
  }

  /* ---------- Time range slider (shared widget, 1-second steps) ---------- */
  let slider = null;
  function initTimeSlider() {
    slider = TS.createTimeSlider($('timeFilter'), {
      unit: 1000, fmt: t => ft(t),
      onChange(from, to) { S.filter.from = from; S.filter.to = to; S.page = 0; applyFilter(); }
    });
  }
  function renderTimeSlider() {
    const L = S.res.levels, bad = L.FATAL + L.ERROR + L.WARN > 0;
    slider.setData({
      tMin: S.res.tMin, tMax: S.res.tMax, items: S.entries,
      series: bad ? [{ label: 'ERROR', color: 'var(--lvl-error)' }, { label: 'WARN', color: 'var(--lvl-warn)' }]
        : [{ label: 'All entries', color: 'var(--lvl-info)' }],
      seriesOf: bad ? (e => (e.level === 'FATAL' || e.level === 'ERROR' ? 0 : e.level === 'WARN' ? 1 : -1)) : (() => 0)
    });
  }
  function syncTimeSlider() { if (slider) slider.setRange(S.filter.from, S.filter.to); }

  function gotoViewer(opts) {
    const f = freshFilter();
    if (opts.levels) f.levels = new Set(opts.levels);
    if (opts.rule) { f.rule = opts.rule; const r = S.module.rules.find(x => x.id === opts.rule); f.label.rule = r ? r.title : opts.rule; }
    if (opts.group) { f.group = opts.group; const g = S.res.groups.find(x => x.key === opts.group); f.label.group = g ? g.sig : opts.group; }
    if (opts.exc) f.exc = opts.exc;
    if (opts.logger) f.logger = opts.logger;
    if (opts.file) f.file = opts.file;
    if (opts.q) f.q = opts.q;
    if (opts.from != null) f.from = opts.from;
    if (opts.to != null) f.to = opts.to;
    S.filter = f; S.page = 0; S.open.clear();
    syncControls(); applyFilter(); showTab('viewer');
  }

  function applyFilter() {
    const f = S.filter;
    let re = null, ql = null;
    $('fText').style.borderColor = '';
    if (f.q) {
      if (f.regex) { try { re = new RegExp(f.q, 'i'); } catch (e) { $('fText').style.borderColor = 'var(--critical)'; } }
      else ql = f.q.toLowerCase();
    }
    const allLv = f.levels.size === TS.LEVELS.length;
    const out = [];
    for (const e of S.entries) {
      if (!allLv && !f.levels.has(e.level)) continue;
      if (f.file && e.file !== f.file) continue;
      if (f.from != null && (e.t == null || e.t < f.from)) continue;
      if (f.to != null && (e.t == null || e.t >= f.to)) continue;
      if (f.rule && !(e.rules && e.rules.includes(f.rule))) continue;
      if (f.group && e.gk !== f.group) continue;
      if (f.exc && e.exn !== f.exc) continue;
      if (f.logger && e.logger !== f.logger) continue;
      if (re || ql) {
        const hay = e.message + '\n' + e.logger + '\n' + e.thread + (e.detail ? '\n' + e.detail : '');
        if (re ? !re.test(hay) : !hay.toLowerCase().includes(ql)) continue;
      }
      out.push(e);
    }
    if (S.desc) out.reverse();
    S.filtered = out;
    renderChips();
    renderRows();
  }

  function renderChips() {
    const f = S.filter, chips = [];
    if (f.rule) chips.push(['rule', 'Finding: ' + f.label.rule]);
    if (f.group) chips.push(['group', 'Group: ' + f.label.group]);
    if (f.exc) chips.push(['exc', 'Exception: ' + f.exc]);
    if (f.logger) chips.push(['logger', 'Logger: ' + f.logger]);
    $('chips').innerHTML = chips.map(([k, l]) => `<span class="chip"><span title="${esc(l)}">${esc(l)}</span><button data-k="${k}" aria-label="Remove filter">✕</button></span>`).join('');
    $('chips').querySelectorAll('button').forEach(b => (b.onclick = () => { S.filter[b.dataset.k] = null; S.page = 0; applyFilter(); }));
  }

  function highlight(text) {
    const s = esc(text);
    const f = S.filter;
    if (!f.q || f.regex) return s;
    const q = esc(f.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    try { return s.replace(new RegExp(q, 'gi'), m => `<mark>${m}</mark>`); } catch (e) { return s; }
  }

  function renderRows() {
    const tot = S.filtered.length, pages = Math.max(1, Math.ceil(tot / PAGE_SIZE));
    if (S.page >= pages) S.page = pages - 1;
    const slice = S.filtered.slice(S.page * PAGE_SIZE, (S.page + 1) * PAGE_SIZE);
    $('viewerCount').textContent = `${fmtN(tot)} of ${fmtN(S.entries.length)} entries`;
    $('pgInfo').textContent = `${S.page + 1} / ${pages}`;
    $('pgPrev').disabled = S.page === 0; $('pgNext').disabled = S.page >= pages - 1;
    const rows = [];
    for (const e of slice) {
      const open = S.open.has(e.id);
      const msg = e.message.length > 600 ? e.message.slice(0, 600) + '…' : e.message;
      const more = e.detail ? ` <span class="trunc-note">[+${e.detail.split('\n').length} lines]</span>` : '';
      rows.push(`<tr class="clickable${open ? ' open' : ''}" data-id="${e.id}">
        <td title="${esc(e.tsText)}">${esc(e.t != null ? ft(e.t, true) : e.tsText)}</td>
        <td>${lvlBadge(e.level)}</td>
        <td title="${esc(e.file)}:${e.line}">${esc(base(e.file))}<span class="sub">line ${e.line}</span></td>
        <td title="${esc(e.logger)}\n${esc(e.thread)}">${esc(shortLogger(e.logger)) || '&nbsp;'}<span class="sub">${esc(e.thread)}</span></td>
        <td class="msg">${highlight(msg)}${more}</td></tr>`);
      if (open) rows.push(detailRow(e));
    }
    $('logTable').querySelector('tbody').innerHTML = rows.join('') || `<tr><td colspan="5" class="muted" style="text-align:center;padding:24px">No entries match the filter.</td></tr>`;
  }

  function detailRow(e) {
    const rules = (e.rules || []).map(id => S.module.rules.find(r => r.id === id)).filter(Boolean);
    return `<tr class="detail" data-detail="${e.id}"><td colspan="5"><div class="detail-box">
      <div class="detail-meta"><span>File: <b class="mono">${esc(e.file)}</b> line <b>${e.line}</b></span><span>Original timestamp: <b class="mono">${esc(e.tsText || '-')}</b></span>
      ${e.logger ? `<span>Logger: <b class="mono">${esc(e.logger)}</b></span>` : ''}${e.thread ? `<span>Thread: <b class="mono">${esc(e.thread)}</b></span>` : ''}${e.exn ? `<span>Root cause: <b class="mono">${esc(e.exn)}</b></span>` : ''}</div>
      ${rules.length ? `<div>${rules.map(r => `${sevPill(r.sev)} <a href="#" data-gorule="${r.id}">${esc(r.title)}</a>`).join(' &nbsp; ')}</div>` : ''}
      <pre>${highlight(e.message + (e.detail ? '\n' + e.detail : ''))}${e.truncated ? '\n… (truncated)' : ''}</pre>
      <div><button class="btn" data-ctx="${e.id}">Context in file (±25 entries)</button> <button class="btn ghost" data-copy="${e.id}">Copy</button></div>
    </div></td></tr>`;
  }

  function onRowClick(ev) {
    const ctx = ev.target.closest('[data-ctx]');
    if (ctx) { showContext(+ctx.dataset.ctx); return; }
    const cp = ev.target.closest('[data-copy]');
    if (cp) {
      const e = S.entries[+cp.dataset.copy];
      const text = `${e.tsText} ${e.level} ${e.logger} [${e.thread}] ${e.message}${e.detail ? '\n' + e.detail : ''}`;
      navigator.clipboard && navigator.clipboard.writeText(text).then(() => { cp.textContent = 'Copied ✓'; setTimeout(() => (cp.textContent = 'Copy'), 1500); });
      return;
    }
    const gr = ev.target.closest('[data-gorule]');
    if (gr) { ev.preventDefault(); gotoViewer({ rule: gr.dataset.gorule }); return; }
    if (ev.target.closest('tr.detail')) return;
    const tr = ev.target.closest('tr[data-id]');
    if (!tr || window.getSelection().toString()) return;
    const id = +tr.dataset.id;
    S.open.has(id) ? S.open.delete(id) : S.open.add(id);
    renderRows();
  }

  function showContext(id) {
    if (!S.byFile) {
      S.byFile = new Map();
      for (const e of S.entries) { let a = S.byFile.get(e.file); if (!a) S.byFile.set(e.file, a = []); a.push(e); }
      S.byFile.forEach(a => a.sort((x, y) => x.line - y.line));
    }
    const e = S.entries[id], arr = S.byFile.get(e.file), idx = arr.indexOf(e);
    const from = Math.max(0, idx - 25), to = Math.min(arr.length, idx + 26);
    const html = arr.slice(from, to).map(x => {
      const head = `${x.tsText} ${x.level !== 'OTHER' ? x.level + ' ' : ''}${x.logger ? x.logger + ' ' : ''}${x.thread ? '[' + x.thread + '] ' : ''}`;
      const body = x.message + (x.detail ? '\n' + x.detail.split('\n').slice(0, x === e ? 400 : 6).join('\n') + (x !== e && x.detail.split('\n').length > 6 ? '\n  …' : '') : '');
      return `<div class="${x === e ? 'cur' : ''}" ${x === e ? 'id="ctxCur"' : ''}><span class="ln">${x.line}</span>${esc(head)}${esc(body)}</div>`;
    }).join('');
    openModal(`${base(e.file)} — around line ${e.line}`, `<div class="ctx">${html}</div>`);
    const cur = $('ctxCur'); if (cur) cur.scrollIntoView({ block: 'center' });
  }

  function openModal(title, html) { $('modalTitle').textContent = title; $('modalBody').innerHTML = html; $('modal').hidden = false; }
  function closeModal() { $('modal').hidden = true; }

  /* ================= Export ================= */
  function csvCell(v) { const s = String(v == null ? '' : v); return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
  function exportCsv() {
    const head = ['timestamp', 'original_timestamp', 'level', 'file', 'line', 'logger', 'thread', 'message', 'detail', 'findings'];
    const lines = [head.join(',')];
    for (const e of S.filtered) {
      lines.push([ft(e.t, true), e.tsText, e.level, e.file, e.line, e.logger, e.thread, e.message, (e.detail || '').slice(0, 4000), (e.rules || []).join(' ')].map(csvCell).join(','));
    }
    TS.download(`${S.module.id}-log-filter-${stamp()}.csv`, '﻿' + lines.join('\r\n'), 'text/csv;charset=utf-8');
  }
  const stamp = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
  const mdCell = s => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

  function exportReport() {
    const r = S.res, L = r.levels, m = S.module;
    const out = [];
    out.push(`# Log Analysis Report — ${m.name}`, '');
    out.push(`Generated: ${new Date().toLocaleString('en-US')} · Hopscope`, '');
    out.push('## Summary', '');
    out.push(`- Files analyzed: ${S.files.length}`);
    out.push(`- Time range: ${ft(r.tMin) || '-'} to ${ft(r.tMax) || '-'} (${r.tMin != null ? TS.fmtDuration(r.tMax - r.tMin) : '-'}, ${TS.fmtOffset(r.offset)})`);
    out.push(`- Total entries: ${fmtN(r.total)} — FATAL ${fmtN(L.FATAL)}, ERROR ${fmtN(L.ERROR)}, WARN ${fmtN(L.WARN)}, INFO ${fmtN(L.INFO)}`);
    if (r.insights && r.insights.kv) r.insights.kv.forEach(([k, v]) => out.push(`- ${k}: ${v}`));
    out.push('');
    const act = r.findings.filter(f => sevOf(f) !== 'info');
    out.push('## Findings', '');
    if (!act.length) out.push('_No problem patterns from the knowledge base matched._', '');
    for (const f of act) {
      const s = S.entries[f.sample];
      out.push(`### [${SEV_LABEL[sevOf(f)].toUpperCase()}] ${f.rule.title}`, '');
      out.push(`- Category: ${f.rule.cat}`, `- Count: ${fmtN(f.count)} entries (${ft(f.first)} to ${ft(f.last)})`);
      out.push(`- Explanation: ${f.rule.why}`);
      if (f.rule.fix.length) { out.push('- Recommended actions:'); f.rule.fix.forEach(x => out.push(`  - ${x}`)); }
      if (s) out.push('', '```', `${s.tsText} ${s.level} ${s.logger}`, s.message.slice(0, 600), '```');
      out.push('');
    }
    const info = r.findings.filter(f => sevOf(f) === 'info');
    if (info.length) {
      out.push('## Informational events', '', '| Event | Count | First | Last |', '|---|---:|---|---|');
      info.forEach(f => out.push(`| ${mdCell(f.rule.title)} | ${f.count} | ${ft(f.first)} | ${ft(f.last)} |`));
      out.push('');
    }
    out.push('## Top 20 error & warning groups', '', '| Level | Count | Logger | Message pattern | First | Last |', '|---|---:|---|---|---|---|');
    r.groups.slice(0, 20).forEach(g => out.push(`| ${g.level} | ${g.count} | ${mdCell(g.logger)} | ${mdCell(g.sig.slice(0, 200))} | ${ft(g.first)} | ${ft(g.last)} |`));
    out.push('');
    if (r.exceptions.length) {
      out.push('## Top exceptions (root cause)', '', '| Exception | Count | Sample message |', '|---|---:|---|');
      r.exceptions.slice(0, 15).forEach(x => out.push(`| ${mdCell(x.name)} | ${x.count} | ${mdCell(x.msg.slice(0, 160))} |`));
      out.push('');
    }
    if (r.insights && r.insights.tables) r.insights.tables.forEach(t => {
      if (!t.rows.length) return;
      out.push(`## ${t.title}`, '', '| ' + t.cols.join(' | ') + ' |', '|' + t.cols.map(() => '---').join('|') + '|');
      t.rows.forEach(row => out.push('| ' + row.map(mdCell).join(' | ') + ' |'));
      out.push('');
    });
    out.push('## Files', '', '| File | Format | Entries | Time range |', '|---|---|---:|---|');
    S.files.forEach(f => out.push(`| ${mdCell(f.name)} | ${mdCell(f.parser.label)} | ${f.entryCount} | ${ft(f.tMin)} to ${ft(f.tMax)} |`));
    TS.download(`${m.id}-report-${stamp()}.md`, out.join('\n'), 'text/markdown;charset=utf-8');
  }

  document.addEventListener('DOMContentLoaded', init);
})(window.TS);
