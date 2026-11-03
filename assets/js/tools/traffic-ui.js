/* SAP Cloud Connector - Traffic Trace Analyzer UI */
(function (TS) {
  'use strict';
  const TT = TS.traffic, esc = TS.esc;
  const $ = id => document.getElementById(id);
  const fmtN = n => (n || 0).toLocaleString('en-US');
  const fmtBytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const LIST_PAGE = 300, MAX_BODY_CHARS = 300000, MAX_HEX_LINES = 20000;

  const STATUS_FILTERS = [
    ['all', 'All'], ['2xx', '2xx'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx'], ['none', 'No response']
  ];

  const S = {
    files: [], skipped: [], infos: [], msgs: [], pairs: [], filtered: [], off: null, sameDay: true,
    sel: null, part: null, mode: 'parsed', pretty: false, mask: true, shown: LIST_PAGE,
    f: { q: '', method: '', status: 'all', sort: 'time', from: null, to: null }
  };
  const ft = (t, ms = true) => TS.fmtTime(t, S.off, ms);
  const ftShort = t => (S.sameDay ? ft(t).slice(11) : ft(t));
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
    $('btnAdd').onclick = () => $('inputFiles').click();
    $('inputFiles').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('btnReset').onclick = reset;
    $('btnCsv').onclick = exportCsv;
    $('btnHar').onclick = exportHar;

    $('fUrl').oninput = TS.debounce(() => { S.f.q = $('fUrl').value; applyFilter(); }, 200);
    $('fMethod').onchange = () => { S.f.method = $('fMethod').value; applyFilter(); };
    $('fSort').onchange = () => { S.f.sort = $('fSort').value; applyFilter(); };
    $('fMask').onchange = () => { S.mask = $('fMask').checked; renderDetail(); };
    slider = TS.createTimeSlider($('timeFilter'), {
      unit: 1, fmt: t => ft(t), title: 'Request time range',
      onChange(from, to) { S.f.from = from; S.f.to = to; applyFilter(); }
    });

    $('ttList').addEventListener('click', e => {
      if (e.target.closest('.tt-more')) { S.shown += LIST_PAGE; renderList(); return; }
      const it = e.target.closest('.tt-item');
      if (it) select(+it.dataset.id);
    });
    $('ttDetail').addEventListener('click', onDetailClick);
    document.addEventListener('keydown', onKey);
    $('modalClose').onclick = closeModal;
    $('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
    TS.embed.listen({ files: d => addFiles(TS.embed.toFiles(d.files), true), reset });
  }

  function setStatus(msg, isErr) {
    const s = $('status');
    s.textContent = msg || '';
    s.classList.toggle('error', !!isErr);
  }
  const tick = () => new Promise(r => setTimeout(r, 0));

  /* ================= Loading ================= */
  async function addFiles(list, fromCockpit) {
    if (!list || !list.length) return;
    if (!fromCockpit && TS.embed.forward(list)) return;
    $('loader').hidden = false; $('app').hidden = true;
    try {
      const { out, skipped } = await TS.readInputs(list, msg => setStatus(msg));
      S.skipped.push(...skipped);
      const newMsgs = [];
      for (const f of out) {
        if (S.files.some(x => x.name === f.name && x.size === f.size)) continue;
        setStatus(`Parsing ${base(f.name)}…`); await tick();
        const r = TT.parseTrace(f.text, f.name);
        if (!r.blockCount) { S.skipped.push({ name: f.name, reason: 'not a traffic trace (no "Request/Response data for connection" blocks)' }); continue; }
        S.files.push({ name: f.name, size: f.size, blocks: r.blockCount, msgs: r.msgs.length, lines: r.lineCount });
        S.infos.push(r.info);
        newMsgs.push(...r.msgs);
      }
      for (let i = 0; i < newMsgs.length; i++) {
        if (i % 200 === 0) { setStatus(`Decoding HTTP ${fmtN(i)} / ${fmtN(newMsgs.length)} messages…`); await tick(); }
        await TT.parseHttp(newMsgs[i]);
      }
      S.msgs.push(...newMsgs);
      if (!S.msgs.length) {
        setStatus('No readable traffic trace data. ' + S.skipped.map(s => `${base(s.name)}: ${s.reason}`).join('; '), true);
        TS.embed.report({ status: 'empty', badge: '0', line: 'No request / response blocks in the trace' });
        return;
      }
      rebuild();
      setStatus('');
      $('loader').hidden = true; $('app').hidden = false;
      ['btnAdd', 'btnHar', 'btnCsv', 'btnReset'].forEach(id => ($(id).hidden = false));
    } catch (err) {
      console.error(err);
      setStatus('Failed to process files: ' + err.message, true);
    }
  }

  function reset() {
    Object.assign(S, { files: [], skipped: [], infos: [], msgs: [], pairs: [], filtered: [], sel: null, part: null, shown: LIST_PAGE });
    S.f = { q: '', method: '', status: 'all', sort: 'time', from: null, to: null };
    $('fUrl').value = ''; $('fSort').value = 'time';
    ['btnAdd', 'btnHar', 'btnCsv', 'btnReset'].forEach(id => ($(id).hidden = true));
    $('app').hidden = true; $('loader').hidden = false; setStatus('');
  }

  function rebuild() {
    S.pairs = TT.buildPairs(S.msgs);
    const withOff = S.msgs.find(m => m.off != null);
    S.off = withOff ? withOff.off : null;
    const ts = S.pairs.map(p => p.t).filter(t => t != null);
    const tMin = ts.length ? Math.min(...ts) : null, tMax = ts.length ? Math.max(...ts) : null;
    S.tMin = tMin; S.tMax = tMax;
    S.sameDay = tMin == null || ft(tMin).slice(0, 10) === ft(tMax).slice(0, 10);
    S.f.from = S.f.to = null;
    S.sel = null; S.part = null;

    renderSysInfo();
    renderDiag();
    renderKpis();
    $('fMethod').innerHTML = '<option value="">All methods</option>' +
      [...new Set(S.pairs.map(p => p.method))].sort().map(m => `<option${m === S.f.method ? ' selected' : ''}>${esc(m)}</option>`).join('');
    renderStatusFilter();
    slider.setData({
      tMin, tMax, items: S.pairs,
      series: [{ label: 'Error / no response', color: 'var(--lvl-error)' }, { label: 'Success', color: 'var(--lvl-info)' }],
      seriesOf: p => (isErr(p) ? 0 : 1)
    });
    applyFilter();
    if (S.filtered.length) select(S.filtered[0].id);
    const red = S.pairs.filter(p => p.loginRedirect).length, errs = S.pairs.filter(isErr).length;
    TS.embed.report({
      status: red || S.pairs.some(p => p.statusClass === '5xx') ? 'fail' : errs ? 'warn' : 'ok', badge: fmtN(S.pairs.length),
      line: red ? `${fmtN(red)} of ${fmtN(S.pairs.length)} requests redirected to the IdP (not logged on)` : errs ? `${fmtN(errs)} of ${fmtN(S.pairs.length)} requests failed or unanswered` : `${fmtN(S.pairs.length)} requests, all answered`
    });
  }
  const isErr =p => p.statusClass === 'none' || p.statusClass === '4xx' || p.statusClass === '5xx' || p.loginRedirect;

  /* ================= Header sections ================= */
  function uniq(arr) { return [...new Set(arr.filter(Boolean))]; }

  function agentVersion() {
    for (const p of S.pairs) {
      if (!/\/deploymentInfo/i.test(p.url)) continue;
      const fin = TT.finalResponse(p);
      try { const j = JSON.parse(fin && fin.h.bodyText || ''); if (j.version) return String(j.version); } catch (e) { /* not JSON */ }
    }
    return '';
  }

  function renderSysInfo() {
    const subs = uniq(S.infos.map(i => i.subaccount));
    const regions = uniq(subs.map(s => (s.split('_on_')[1] || '')));
    const rows = [
      ['File', S.files.map(f => base(f.name)).join(', ')],
      ['Cloud Connector version', uniq(S.infos.map(i => i.version)).join(', ')],
      ['Host', uniq(S.infos.map(i => i.host)).join(', ')],
      ['Subaccount', subs.map(s => s.split('_on_')[0]).join(', ')],
      ['BTP region', regions.join(', ')],
      ['Cloud agent version', agentVersion()],
      ['Time range', S.tMin != null ? `${ft(S.tMin)} to ${ft(S.tMax)} (${TS.fmtDuration(S.tMax - S.tMin)})` : ''],
      ['Time zone', TS.fmtOffset(S.off)]
    ].filter(r => r[1]);
    const skipped = S.skipped.length ? `<p class="muted small" style="margin:8px 0 0">Skipped: ${S.skipped.map(s => esc(base(s.name) + ' — ' + s.reason)).join('; ')}</p>` : '';
    $('sysInfo').innerHTML = `<dl class="kvgrid">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>${skipped}`;
  }

  /* Whole-trace diagnosis: requests the backend did not authenticate (redirect to the IdP), esp. with a propagated cloud user */
  function renderDiag() {
    const box = $('ttDiag'), red = S.pairs.filter(p => p.loginRedirect);
    box.hidden = !red.length;
    if (!red.length) { box.innerHTML = ''; return; }
    const sso = S.pairs.filter(p => p.sso), ssoRed = red.filter(p => p.sso);
    const idps = uniq(red.map(p => p.idpHost)).join(', ') || '-', hosts = uniq(red.map(p => p.host)).join(', ') || '-';
    const svc = uniq(red.map(p => (/\/sap\/opu\/odata\/[^/]+\/[^/?]+|\/sap\/[^/?]+\/[^/?]+/.exec(p.pathNoQuery) || [p.pathNoQuery])[0])).slice(0, 5).join(', ');
    const steps = ssoRed.length ? [
      'Cloud Connector scc_core.trc (loggers on ALL + TLS trace, then "Check availability of internal host"): Log Analyzer → "Backend asked for a client certificate, the Cloud Connector sent none" and the table of accepted CAs per backend.',
      'Certificates: load scc_core.trc + sys_cert.der (SCC system certificate) → card "Client certificate vs. CA list of the server" shows whether the backend accepts it, down to the serial number.',
      'Backend (SM51 → the instance of the internal host → SMICM, trace level 2): "intermediary is NOT trusted" → SCC system certificate into the SSL server PSE of the HTTPS port + icm/trusted_reverse_proxy_<n>, ICM restart; trusted but still redirected → CERTRULE / user mapping.',
      'Repeat the call and capture a new traffic trace: the responses must be 2xx without sap-authenticated: pending.'
    ] : [
      'The requests carry no propagated user (no SAP-Connectivity-SSOToken): check the authentication of the BTP destination (user / password, OAuth) or the principal type of the SCC system mapping.',
      'Repeat the call and capture a new traffic trace: the responses must be 2xx.'
    ];
    box.innerHTML = `<article class="finding high"><div class="finding-head">${TS.sevPill('high')}<h3>${ssoRed.length
      ? `${fmtN(ssoRed.length)} of ${fmtN(sso.length)} requests with a propagated cloud user were not logged on by the backend`
      : `${fmtN(red.length)} requests were redirected to a login page / IdP`}</h3><span class="cat">· ${esc(hosts)}</span></div>
      <p>${ssoRed.length
        ? `The BTP application sent the user (SAP-Connectivity-SSOToken) and the Cloud Connector forwards it as a short-lived X.509 certificate, but the backend answered with a redirect to <b>${esc(idps)}</b>${red.some(p => /pending/i.test((TT.finalResponse(p).h.hmap['sap-authenticated']) || '')) ? ' (sap-authenticated: pending)' : ''} — it did not accept the certificate. Usually the backend does not trust the Cloud Connector as reverse proxy (system certificate not in the SSL server PSE of the HTTPS port, so SCC sends no client certificate; icm/trusted_reverse_proxy_&lt;n&gt;), or CERTRULE maps the certificate to no user. OData consumers such as Group Reporting Data Collection cannot follow the login and report 302 / 405.`
        : `The backend answered with a redirect to <b>${esc(idps)}</b> — the requests were not authenticated.`}${svc ? ` Affected: <span class="mono">${esc(svc)}</span>.` : ''}</p>
      <b class="small">Recommended actions</b><ol>${steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol></article>`;
  }

  function percentile(sorted, q) { return sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(q * (sorted.length - 1) + 0.5))] : null; }

  function renderKpis() {
    const P = S.pairs, reqs = P.filter(p => p.req);
    const cnt = c => P.filter(p => p.statusClass === c).length;
    const durs = P.map(p => p.dur).filter(d => d != null).sort((a, b) => a - b);
    const conns = new Set(S.msgs.map(m => m.file + '|' + m.conn)).size;
    const tls = P.filter(p => p.kind === 'tls').length;
    const kpi = (k, v, s) => `<div class="kpi"><div class="k">${k}</div><div class="v">${v}</div>${s ? `<div class="s">${s}</div>` : ''}</div>`;
    $('kpis').innerHTML =
      kpi('Requests', fmtN(reqs.length), `${fmtN(conns)} connections${tls ? ` · ${fmtN(tls)} TLS` : ''}`) +
      kpi('Responses', fmtN(S.msgs.filter(m => m.type === 'response').length), `${fmtN(cnt('2xx'))} successful (2xx)`) +
      (P.some(p => p.loginRedirect) ? kpi('<span class="stp s4xx">Login redirect</span>', fmtN(P.filter(p => p.loginRedirect).length), `not logged on${P.some(p => p.sso) ? ` · ${fmtN(P.filter(p => p.sso).length)} with SSO token` : ''}`) : '') +
      kpi('<span class="stp snone">No response</span>', fmtN(cnt('none')), 'timeout / connection closed / trace cut off') +
      kpi('<span class="stp s4xx">4xx</span>', fmtN(cnt('4xx')), 'client-side / authorization errors') +
      kpi('<span class="stp s5xx">5xx</span>', fmtN(cnt('5xx')), 'backend errors') +
      kpi('Duration (median)', durs.length ? TS.fmtDuration(percentile(durs, 0.5)) : '-', durs.length ? `p95 ${TS.fmtDuration(percentile(durs, 0.95))} · max ${TS.fmtDuration(durs[durs.length - 1])}` : '');
  }

  function renderStatusFilter() {
    const count = k => k === 'all' ? S.pairs.length : S.pairs.filter(p => p.statusClass === k).length;
    $('fStatus').innerHTML = STATUS_FILTERS.map(([k, l]) => {
      const n = count(k);
      if (k !== 'all' && !n) return '';
      return `<button type="button" data-st="${k}" class="${S.f.status === k ? 'active' : ''}">${esc(l)}<span class="n">${fmtN(n)}</span></button>`;
    }).join('');
    $('fStatus').querySelectorAll('button').forEach(b => (b.onclick = () => { S.f.status = b.dataset.st; renderStatusFilter(); applyFilter(); }));
  }

  /* ================= Filtering & list ================= */
  function haystack(p) {
    if (p._hay) return p._hay;
    const parts = [p.url, p.conn];
    for (const m of [p.req, ...p.resps]) {
      if (!m) continue;
      const h = m.h;
      if (h.startLine) parts.push(h.startLine);
      h.headers.forEach(([n, v]) => parts.push(n + ': ' + v));
      if (h.bodyText) parts.push(h.bodyText.slice(0, 20000));
    }
    return (p._hay = parts.join('\n').toLowerCase());
  }

  function applyFilter() {
    const f = S.f, q = f.q.trim().toLowerCase();
    let out = S.pairs.filter(p =>
      (!f.method || p.method === f.method) &&
      (f.status === 'all' || p.statusClass === f.status) &&
      (f.from == null || (p.t != null && p.t >= f.from)) &&
      (f.to == null || (p.t != null && p.t < f.to)) &&
      (!q || haystack(p).includes(q)));
    if (f.sort === 'dur') out = out.slice().sort((a, b) => (b.dur == null ? -1 : b.dur) - (a.dur == null ? -1 : a.dur));
    else if (f.sort === 'size') out = out.slice().sort((a, b) => b.respSize - a.respSize);
    S.filtered = out;
    S.shown = LIST_PAGE;
    renderList();
  }

  const statusPill = p => {
    const label = p.statusClass === 'none' ? 'No response' : p.status ? String(p.status) : p.resps.length ? 'non-HTTP' : '—';
    return `<span class="stp s${p.statusClass}">${esc(label)}</span>`;
  };

  function renderList() {
    const list = S.filtered.slice(0, S.shown);
    const html = list.map(p => `
      <div class="tt-item st-${p.statusClass}${p.id === S.sel ? ' sel' : ''}" data-id="${p.id}">
        <div class="tt-l1"><span class="mth">${esc(p.method)}</span><span class="tt-path" title="${esc(p.url)}">${esc(p.pathNoQuery || p.url || '(response without request)')}</span></div>
        <div class="tt-l2">${statusPill(p)}<span>${esc(ftShort(p.t))}</span><span class="mono">${esc(p.conn)}</span>${p.dur != null ? `<span>${TS.fmtDuration(p.dur)}</span>` : ''}${p.resps.length > 1 ? `<span>${p.resps.length} responses</span>` : ''}${p.badges.map(b => `<span class="badge">${esc(b)}</span>`).join('')}</div>
      </div>`).join('');
    $('ttList').innerHTML = `<div class="tt-count">${fmtN(S.filtered.length)} of ${fmtN(S.pairs.length)} requests</div>` +
      (html || '<div class="tt-empty">No requests match the filter.</div>') +
      (S.filtered.length > S.shown ? `<button class="btn ghost tt-more" type="button">Show ${fmtN(Math.min(LIST_PAGE, S.filtered.length - S.shown))} more</button>` : '');
  }

  function select(id, scroll) {
    if (S.sel !== id) { S.part = null; S.pretty = false; }
    S.sel = id;
    $('ttList').querySelectorAll('.tt-item.sel').forEach(el => el.classList.remove('sel'));
    const el = $('ttList').querySelector(`.tt-item[data-id="${id}"]`);
    if (el) { el.classList.add('sel'); if (scroll) el.scrollIntoView({ block: 'nearest' }); }
    renderDetail();
  }

  function onKey(e) {
    if (e.key === 'Escape') { closeModal(); return; }
    if (!$('modal').hidden || $('app').hidden) return;
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) return;
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const idx = S.filtered.findIndex(p => p.id === S.sel);
    const next = S.filtered[Math.max(0, Math.min(S.filtered.length - 1, idx + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (!next) return;
    e.preventDefault();
    if (S.filtered.indexOf(next) >= S.shown) { S.shown += LIST_PAGE; renderList(); }
    select(next.id, true);
  }

  /* ================= Detail ================= */
  function partsOf(p) {
    const parts = [];
    if (p.req) parts.push({ key: 'req', label: 'Request', m: p.req });
    p.extraReq.forEach((m, i) => parts.push({ key: 'x' + i, label: 'Request (continued)', m }));
    p.resps.forEach((m, i) => parts.push({ key: 'r' + i, label: `Response ${i + 1}${m.h.status ? ' · ' + m.h.status : ''}`, m }));
    return parts;
  }

  function currentView() {
    const p = S.pairs[S.sel];
    if (!p) return null;
    const parts = partsOf(p);
    let part = parts.find(x => x.key === S.part);
    if (!part) { part = parts[0]; S.part = part && part.key; }
    return { p, parts, part };
  }

  function renderDetail() {
    const v = currentView();
    if (!v) { $('ttDetail').innerHTML = '<div class="tt-empty">Select a request on the left to view its details.</div>'; return; }
    const { p, parts, part } = v, m = part.m, h = m.h;
    const hints = TT.hints(p);
    const fin = TT.finalResponse(p);
    const isText = !!(h.bodyText && h.bodyText.length);
    const isHtml = isText && (/html/.test(h.contentType || '') || /<html[\s>]/i.test(h.bodyText.slice(0, 2000)));
    const canFormat = isText && /^\s*[[{<]/.test(h.bodyText);
    $('ttDetail').innerHTML = `
      <div class="tt-title"><span class="mth">${esc(p.method)}</span><span class="mono tt-url">${esc(p.url || '(response without request)')}</span></div>
      <div class="tt-meta">
        ${statusPill(p)}${p.status && fin.h.statusText ? `<span>${esc(fin.h.statusText)}</span>` : ''}
        <span>Duration <b>${p.dur != null ? TS.fmtDuration(p.dur) : '-'}</b></span>
        <span>Connection <b class="mono">${esc(p.conn)}</b></span>
        <span>Time <b>${esc(ft(p.t))}</b></span>
        <span>Request <b>${fmtBytes(p.reqSize)}</b> · Response <b>${fmtBytes(p.respSize)}</b></span>
        ${p.badges.map(b => `<span class="badge">${esc(b)}</span>`).join('')}
      </div>
      ${hints.length ? `<ul class="tt-hints">${hints.map(([s, t]) => `<li>${TS.sevPill(s)}<span>${esc(t)}</span></li>`).join('')}</ul>` : ''}
      <div class="tt-tabs">
        <div class="seg" role="group" aria-label="Message">${parts.map(x => `<button type="button" data-part="${x.key}" class="${x.key === part.key ? 'active' : ''}">${esc(x.label)}</button>`).join('')}</div>
        <div class="seg" role="group" aria-label="View">${[['parsed', 'Parsed'], ['raw', 'Raw'], ['hex', 'Hex']].map(([k, l]) => `<button type="button" data-mode="${k}" class="${S.mode === k ? 'active' : ''}">${l}</button>`).join('')}</div>
        <span class="spacer"></span>
        ${canFormat && S.mode !== 'hex' ? `<button class="btn ghost" data-act="pretty" type="button">${S.pretty ? 'Original text' : 'Format JSON/XML'}</button>` : ''}
        ${isHtml ? '<button class="btn ghost" data-act="html" type="button" title="Render HTML in a sandbox (scripts disabled)">Preview HTML</button>' : ''}
        ${h.body && h.body.length ? '<button class="btn ghost" data-act="download" type="button">Download body</button>' : ''}
        <button class="btn ghost" data-act="copy" type="button">Copy</button>
        <button class="btn ghost" data-act="max" type="button">Maximize</button>
      </div>
      <div class="tt-part-meta">${m.type === 'request' ? 'REQUEST' : 'RESPONSE'} · ${esc(ft(m.t))} · ${fmtBytes(m.bytes.length)}${m.blocks > 1 ? ` · ${m.blocks} blocks` : ''} · ${esc(base(m.file))} line ${m.line}</div>
      <div class="tt-body">${S.mode === 'hex' ? hexHtml(m) : S.mode === 'raw' ? `<pre class="tt-pre">${esc(cap(rawText(h)))}</pre>` : parsedHtml(h)}</div>`;
  }

  const cap = s => (s.length > MAX_BODY_CHARS ? s.slice(0, MAX_BODY_CHARS) + `\n\n… (truncated, ${fmtN(s.length)} characters — use Download body)` : s);
  const hv = (n, v) => (S.mask ? TT.mask(n, v) : v);

  function bodyText(h) {
    const t = h.bodyText || '';
    return S.pretty ? prettify(t) : t;
  }

  function parsedHtml(h) {
    const notes = h.notes.length ? `<ul class="tt-notes">${h.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : '';
    if (h.kind !== 'http') return notes + (h.kind === 'text' ? `<pre class="tt-pre">${esc(cap(bodyText(h)))}</pre>` : '');
    const headers = h.headers.length ? `<table class="simple tt-headers"><tbody>${h.headers.map(([n, v]) =>
      `<tr><th class="mono">${esc(n)}</th><td class="mono">${esc(hv(n, v))}${S.mask && TT.isSensitive(n) && hv(n, v) !== v ? '<span class="masked-tag">masked</span>' : ''}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No headers.</p>';
    let body;
    if (!h.body || !h.body.length) body = '<p class="muted">No body.</p>';
    else if (h.compressed) body = `<p class="muted">Body is still compressed (${esc(h.compressed)}), ${fmtBytes(h.body.length)}.</p>`;
    else if (h.binary) body = `<p class="muted">Binary body (${esc(h.contentType || 'no content-type')}), ${fmtBytes(h.body.length)} — use Download body or the Hex view.</p>`;
    else body = `<pre class="tt-pre">${esc(cap(bodyText(h)))}</pre>`;
    return `<div class="tt-startline mono">${esc(h.startLine)}</div>${notes}
      <h4>Headers <span class="muted small">(${h.headers.length})</span></h4>${headers}
      <h4>Body <span class="muted small">${esc(h.contentType || '')}${h.body && h.body.length ? ' · ' + fmtBytes(h.body.length) : ''}${h.wireBodySize != null && h.body && h.wireBodySize !== h.body.length ? ` (on the wire ${fmtBytes(h.wireBodySize)})` : ''}</span></h4>${body}`;
  }

  function rawText(h) {
    if (h.kind !== 'http') return (h.notes.join('\n') + (h.bodyText ? '\n\n' + bodyText(h) : '')).trim();
    const head = [h.startLine].concat(h.headers.map(([n, v]) => `${n}: ${hv(n, v)}`)).join('\n');
    const b = !h.body || !h.body.length ? '' : h.bodyText ? bodyText(h) : `[${h.compressed ? 'compressed body ' + h.compressed : 'binary body'} — ${fmtBytes(h.body.length)}]`;
    return head + '\n\n' + b;
  }

  function hexHtml(m) {
    const lines = TT.hexText(m).split('\n');
    const note = lines.length > MAX_HEX_LINES ? `<p class="muted small">Showing ${fmtN(MAX_HEX_LINES)} of ${fmtN(lines.length)} lines.</p>` : '';
    return `<p class="muted small">Original hex dump from the trace file (not masked).</p>${note}<pre class="tt-pre">${esc(lines.slice(0, MAX_HEX_LINES).join('\n'))}</pre>`;
  }

  function viewText() {
    const v = currentView();
    if (!v) return '';
    const h = v.part.m.h;
    return S.mode === 'hex' ? TT.hexText(v.part.m) : rawText(h);
  }

  function prettify(t) {
    const s = t.trim();
    if (/^[[{]/.test(s)) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return t; } }
    if (s.startsWith('<')) return prettyXml(s);
    return t;
  }
  function prettyXml(x) {
    let pad = 0;
    return x.replace(/>\s*</g, '>\n<').split('\n').map(l => {
      if (/^<\/[\w:]/.test(l)) pad = Math.max(0, pad - 1);
      const s = '  '.repeat(pad) + l;
      if (/^<[\w:][^>]*[^/]>$/.test(l) || /^<[\w:]+>$/.test(l)) pad++;
      return s;
    }).join('\n');
  }

  function onDetailClick(e) {
    const pb = e.target.closest('[data-part]');
    if (pb) { S.part = pb.dataset.part; S.pretty = false; renderDetail(); return; }
    const mb = e.target.closest('[data-mode]');
    if (mb) { S.mode = mb.dataset.mode; renderDetail(); return; }
    const ab = e.target.closest('[data-act]');
    if (!ab) return;
    const v = currentView(); if (!v) return;
    const m = v.part.m, h = m.h;
    switch (ab.dataset.act) {
      case 'pretty': S.pretty = !S.pretty; renderDetail(); break;
      case 'copy':
        if (navigator.clipboard) navigator.clipboard.writeText(viewText()).then(() => { ab.textContent = 'Copied ✓'; setTimeout(() => (ab.textContent = 'Copy'), 1500); });
        break;
      case 'download': {
        const ct = h.contentType || '';
        const ext = h.compressed ? (h.compressed === 'br' ? 'br' : 'gz') : /json/.test(ct) ? 'json' : /html/.test(ct) ? 'html' : /xml/.test(ct) ? 'xml' : /text/.test(ct) ? 'txt' : 'bin';
        const blob = new Blob([h.body], { type: 'application/octet-stream' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob); a.download = `${m.conn}-${v.part.key}-${m.line}.${ext}`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
        break;
      }
      case 'html': {
        openModal('HTML preview (sandboxed, scripts disabled)', '<iframe sandbox="" referrerpolicy="no-referrer" title="HTML preview"></iframe>');
        $('modalBody').querySelector('iframe').srcdoc = h.bodyText;
        break;
      }
      case 'max':
        openModal(`${m.type === 'request' ? 'Request' : 'Response'} — ${v.p.method} ${v.p.pathNoQuery}`, `<pre class="big">${esc(viewText())}</pre>`);
        break;
    }
  }

  function openModal(title, html) { $('modalTitle').textContent = title; $('modalBody').innerHTML = html; $('modal').hidden = false; }
  function closeModal() { $('modal').hidden = true; $('modalBody').innerHTML = ''; }

  /* ================= Export ================= */
  const stamp = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
  const csvCell = v => { const s = String(v == null ? '' : v); return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

  function exportCsv() {
    const head = ['time', 'connection', 'method', 'url', 'status', 'duration_ms', 'request_bytes', 'response_bytes', 'responses', 'badges', 'file', 'line'];
    const rows = S.filtered.map(p => [ft(p.t), p.conn, p.method, p.url, p.status || (p.statusClass === 'none' ? 'no response' : ''), p.dur, p.reqSize, p.respSize, p.resps.length, p.badges.join(' '), base(p.file), p.req ? p.req.line : p.resps[0].line]);
    TS.download(`scc-traffic-${stamp()}.csv`, '﻿' + [head].concat(rows).map(r => r.map(csvCell).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
  }

  // HAR 1.2 — opens in Chrome/Edge DevTools (Network tab → Import HAR). Sensitive values follow the mask toggle.
  function exportHar() {
    const hdrs = h => h.headers.map(([name, value]) => ({ name, value: hv(name, value) }));
    const entries = S.filtered.filter(p => p.req && p.req.h.kind === 'http').map(p => {
      const rq = p.req.h, fin = TT.finalResponse(p), rs = fin && fin.h.kind === 'http' ? fin.h : null;
      const url = /^[a-z][\w+.-]*:\/\//i.test(rq.url) ? rq.url : 'http://' + (rq.hmap.host || 'unknown-host') + rq.url;
      let qs = [];
      try { qs = [...new URL(url).searchParams].map(([name, value]) => ({ name, value })); } catch (e) { /* invalid URL */ }
      const entry = {
        startedDateTime: new Date(p.req.t != null ? p.req.t : 0).toISOString(),
        time: p.dur != null ? p.dur : 0,
        request: {
          method: rq.method, url, httpVersion: rq.version, cookies: [], headers: hdrs(rq), queryString: qs,
          headersSize: -1, bodySize: rq.body ? rq.body.length : 0
        },
        response: rs ? {
          status: rs.status || 0, statusText: rs.statusText || '', httpVersion: rs.version || '', cookies: [], headers: hdrs(rs),
          content: { size: rs.body ? rs.body.length : 0, mimeType: rs.hmap['content-type'] || '', text: rs.bodyText || undefined },
          redirectURL: rs.hmap.location || '', headersSize: -1, bodySize: fin.bytes.length
        } : {
          status: 0, statusText: p.resps.length ? 'non-HTTP response' : 'no response in trace', httpVersion: '', cookies: [], headers: [],
          content: { size: 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: -1
        },
        cache: {},
        timings: { send: 0, wait: p.dur != null ? p.dur : -1, receive: 0 },
        connection: p.conn,
        comment: `${base(p.file)} line ${p.req.line}`
      };
      if (rq.body && rq.body.length) entry.request.postData = { mimeType: rq.hmap['content-type'] || '', text: rq.bodyText || '' };
      return entry;
    });
    const har = { log: { version: '1.2', creator: { name: 'Hopscope', version: '0.3' }, pages: [], entries } };
    TS.download(`scc-traffic-${stamp()}.har`, JSON.stringify(har, null, 1), 'application/json');
  }

  document.addEventListener('DOMContentLoaded', init);
})(window.TS);
