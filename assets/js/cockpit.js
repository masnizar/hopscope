/* Hopscope cockpit (index.html): one page for the whole incident.
 * Evidence is the one place where files enter (drop zone, file / folder picker, pasted text, example; a file dropped anywhere
 * on the page lands there too) and where they are managed ("Read as", remove). The cockpit reads every file once, classifies
 * it and sends each workspace its share; the workspaces are the tool pages in frames (<page>?embed=1&tool=<id>) and have no
 * uploader of their own (TS.embed in widgets.js). Each workspace reports a one-line summary for the rail and the top bar. */
(function (TS) {
  'use strict';
  const C = TS.corr, esc = TS.esc, $ = id => document.getElementById(id);
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const fmtN = n => (n || 0).toLocaleString('en-US');
  const fmtBytes = n => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB');

  const ICON = {
    evidence: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M12 17v-6m0 0-2.5 2.5M12 11l2.5 2.5"/>',
    map: '<circle cx="5" cy="18" r="2.2"/><circle cx="12" cy="6" r="2.2"/><circle cx="19" cy="15" r="2.2"/><path d="M6.1 16.1 10.9 7.9M13.5 7.7l4.1 5.5"/>',
    timeline: '<path d="M3 6h18M3 12h18M3 18h18" opacity=".45"/><path d="M8 3v18M16 3v18"/>',
    logs: '<path d="M4 5h16M4 10h10M4 15h13M4 20h7"/>',
    traffic: '<path d="M3 7h13m0 0-3-3m3 3-3 3M21 17H8m0 0 3-3m-3 3 3 3"/>',
    certs: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M7 8h10M7 11h6"/><path d="M14 16v5l2-1.2 2 1.2v-5"/>'
  };
  const icon = (k, s) => `<svg viewBox="0 0 24 24" width="${s || 20}" height="${s || 20}" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICON[k]}</g></svg>`;

  // workspaces = tool pages; Evidence is the cockpit's own view
  const TOOLS = [
    { id: 'map', page: 'landscape.html', title: 'Map', sub: 'Where the request breaks and the fix' },
    { id: 'timeline', page: 'correlation.html', title: 'Timeline', sub: 'All sources on one time line: incidents, events' },
    { id: 'logs', page: 'log-analyzer.html', title: 'Logs', sub: 'Every entry: filters, patterns, context' },
    { id: 'traffic', page: 'scc-traffic.html', title: 'Traffic', sub: 'SCC HTTP requests & responses' },
    { id: 'certs', page: 'certificates.html', title: 'Certificates', sub: 'Trust, chains, expiry' }
  ];
  const VIEWS = ['evidence'].concat(TOOLS.map(t => t.id));
  const OLD_VIEW = { findings: 'timeline' };

  /* What each source shows and how to collect it — the evidence checklist */
  const EVIDENCE = [
    { src: 'scc', title: 'Cloud Connector logs', shows: 'Tunnel, access control, principal propagation, TLS to the backend', how: 'SCC → Log and Trace Files → loggers ALL (+ TLS trace) → reproduce → Download All (.zip)' },
    { src: 'traffic', title: 'SCC traffic trace', shows: 'Every HTTP request / response through the tunnel (302 to the IdP, 4xx, 5xx)', how: 'SCC → Log and Trace Files → payload trace on → reproduce → tunnel_traffic_*.trc' },
    { src: 'icm', title: 'ICM trace (dev_icm)', shows: 'TLS, client certificates, trusted reverse proxy, ICM resources', how: 'SM51 → instance of the internal host → SMICM → trace level 2 → reset → reproduce → download' },
    { src: 'wdp', title: 'Web Dispatcher trace', shows: 'Routing, backend servers, SSL re-encryption', how: 'dev_webdisp from the Web Dispatcher work directory (trace level 2)' },
    { src: 'sm21', title: 'System log (SM21)', shows: 'Logon failures, SSL / ICM / communication errors', how: 'SM21 → time range → Export → Spreadsheet or Text with Tabs' },
    { src: 'st22', title: 'ABAP dumps (ST22)', shows: 'Runtime errors behind HTTP 500 / timeouts', how: 'ST22 → time range → Export → Spreadsheet or Text with Tabs' },
    { src: 'sm59', title: 'Connection test (SM59)', shows: 'Outbound calls from S/4: SSL, network, HTTP status', how: 'SM59 → destination → Connection Test → save the result as text (or paste it below)' },
    { src: 'strust', title: 'Certificates', shows: 'Expiry, chains, trust, SCC system certificate vs. CA list', how: 'STRUST export (.cer / .crt / .pem), PSE files, SCC sys_cert.der — or paste PEM / sapgenpse output below' },
    { src: 'wp', title: 'Work process traces', shows: 'dev_w* / dev_disp: work process restarts, DB, memory', how: 'SM50 → work process → Trace → Display File, or AL11 → DIR_HOME' },
    { src: 'http', title: 'HTTP access logs', shows: 'Status codes per request (401 / 403 / 5xx)', how: 'icm/HTTP/logging_<n> or Web Dispatcher access log' }
  ];
  const READ_AS = C.SOURCES.map(s => ({ id: s.id, label: s.label })).concat({ id: 'traffic', label: 'SCC traffic trace' });
  const labelOf = src => (READ_AS.find(s => s.id === src) || { label: src }).label;
  const MODULE_OF = { scc: 'scc', icm: 'icm', wp: 'icm', wdp: 'wdp' };
  const MODULE_LABEL = { scc: 'SCC', icm: 'ICM', wdp: 'WDP' };
  const CERT_BIN = /\.(pse|jks|ks|p12|pfx|der|cer|crt|p7b|p7c)$/i, KEYSTORE = /\.(jks|ks|p12|pfx)$/i;

  const S = { entries: [], skipped: [], view: 'evidence', ready: {}, queue: {}, sums: {}, module: null, frames: {}, pasted: 0 };

  /* ================= Frames & messages ================= */
  function buildFrames() {
    for (const t of TOOLS) {
      const f = document.createElement('iframe');
      f.className = 'hs-frame';
      f.title = `${t.title} — ${t.sub}`;
      f.src = `${t.page}?embed=1&tool=${t.id}`;
      $('stage').appendChild(f);
      S.frames[t.id] = f;
    }
  }
  function post(tool, msg) {
    const f = S.frames[tool];
    if (S.ready[tool] && f.contentWindow) f.contentWindow.postMessage(msg, '*');
    else (S.queue[tool] = S.queue[tool] || []).push(msg);
  }
  const theme = () => document.documentElement.dataset.theme || null;
  function onMessage(e) {
    const d = e.data;
    if (!d || !d.hops) return;
    const t = TOOLS.find(x => S.frames[x.id].contentWindow === e.source);
    if (!t) return;
    switch (d.hops) {
      case 'ready':
        S.ready[t.id] = true;
        e.source.postMessage({ hops: 'theme', theme: theme() }, '*');
        e.source.postMessage({ hops: 'visible', on: S.view === t.id }, '*');
        (S.queue[t.id] || []).forEach(m => e.source.postMessage(m, '*'));
        S.queue[t.id] = [];
        break;
      case 'files': addFiles(TS.embed.toFiles(d.files)); break;   // dropped onto a workspace: same intake
      case 'example': loadExample(); break;
      case 'view': setView(d.view); break;
      case 'drag': showDrop(true); break;
      case 'summary':
        S.sums[t.id] = Object.assign({}, d.summary, { busy: false });
        // the timeline looks at the same minutes as the map (request flow, analysis window)
        if (t.id === 'map' && d.summary.win && String(d.summary.win) !== String(S.win)) { S.win = d.summary.win; post('timeline', { hops: 'range', from: S.win[0], to: S.win[1] }); }
        renderRail(); renderTop();
        break;
    }
  }

  /* ================= Intake: read once, classify, share ================= */
  function setStatus(msg, isErr) {
    const s = $('status');
    s.hidden = !msg;
    s.textContent = msg || '';
    s.classList.toggle('error', !!isErr);
  }
  async function addFiles(list) {
    list = [...(list || [])];
    if (!list.length) return;
    const first = !S.entries.length;
    setStatus(`Reading ${list.length} file${list.length === 1 ? '' : 's'}…`);
    try {
      const { out, skipped } = await TS.readInputs(list, msg => setStatus(msg));
      const fresh = [];
      for (const f of out) {
        if (S.entries.some(x => x.name === f.name && x.size === f.size)) continue;
        const traffic = /tunnel_traffic/i.test(base(f.name)) || /(Request|Response) data for connection 0x/.test(f.text.slice(0, 200000));
        // Excel exports arrive as tab-separated text: give them a name the workspaces read as text
        const name = /\.xlsx$/i.test(f.name) ? f.name + '.tsv' : f.name;
        const e = { name, size: f.size, src: traffic ? 'traffic' : C.classify(f.name, f.text), file: new File([f.text], base(name), { lastModified: f.mtime || Date.now() }) };
        const raw = list.find(x => CERT_BIN.test(x.name) && (x.webkitRelativePath || x.name) === f.name);
        if (raw) e.raw = raw;   // the certificate analyzer reads the original bytes (PSE, DER)
        fresh.push(e);
      }
      // Java keystores / PKCS#12 are not text: only the certificate analyzer reads them
      for (const x of list) {
        const n = x.webkitRelativePath || x.name;
        if (KEYSTORE.test(n) && !S.entries.some(e => e.name === n)) fresh.push({ name: n, size: x.size, src: 'strust', raw: x });
      }
      S.skipped.push(...skipped.filter(s => !KEYSTORE.test(s.name)));
      if (!fresh.length) {
        setStatus(skipped.length ? 'No new readable files. ' + skipped.map(s => `${base(s.name)}: ${s.reason}`).join('; ') : 'These files are already in the incident.', !!skipped.length);
        setTimeout(() => setStatus(''), 6000);
        renderAll();
        return;
      }
      S.entries.push(...fresh);
      if (!S.module) S.module = pickModule();
      deliver(fresh);
      setStatus('');
      renderAll();
      if (first) setView('map');   // the first upload of an incident: straight to the verdict
    } catch (err) {
      console.error(err);
      setStatus('Failed to read files: ' + err.message, true);
    }
  }
  function share(tool, list) {
    switch (tool) {
      case 'map': case 'timeline': return list.filter(e => e.file && e.src !== 'traffic');
      case 'traffic': return list.filter(e => e.src === 'traffic');
      case 'certs': return list.filter(e => ['strust', 'scc', 'icm', 'wdp'].includes(e.src));
      case 'logs': return list.filter(e => e.file && MODULE_OF[e.src] === S.module);
    }
    return [];
  }
  function deliver(list, only) {
    for (const t of TOOLS) {
      if (only && t.id !== only) continue;
      const part = share(t.id, list);
      if (!part.length) continue;
      S.sums[t.id] = Object.assign({}, S.sums[t.id], { busy: true });
      post(t.id, { hops: 'files', module: t.id === 'logs' ? S.module : undefined, files: part.map(e => ({ path: e.name, src: e.src, file: t.id === 'certs' && e.raw ? e.raw : e.file })) });
    }
  }
  function pickModule() {
    const n = { scc: 0, icm: 0, wdp: 0 };
    S.entries.forEach(e => { if (MODULE_OF[e.src]) n[MODULE_OF[e.src]]++; });
    const best = Object.keys(n).sort((a, b) => n[b] - n[a])[0];
    return n[best] ? best : null;
  }
  function setModule(m) {
    if (m === S.module) return;
    S.module = m;
    post('logs', { hops: 'reset' });
    delete S.sums.logs;
    deliver(S.entries, 'logs');
    setView('logs');
  }
  // every workspace starts over with the current file list (after "Read as" / remove) — or empty for a new incident
  function resetAll(keep) {
    TOOLS.forEach(t => post(t.id, { hops: 'reset' }));
    S.sums = {}; S.win = null;
    if (!keep) { S.entries = []; S.skipped = []; }
    S.module = pickModule();
    if (S.entries.length) deliver(S.entries);
    renderAll();
  }
  function loadExample() {
    if (!TS.landscapeUi) return;
    resetAll();
    addFiles(TS.landscapeUi.exampleFiles().map(f => new File([f.text], base(f.name), { lastModified: f.mtime })));
  }
  function addPasted() {
    const box = $('pasteBox'), t = box ? box.value.trim() : '';
    if (!t) return;
    S.pasted++;
    addFiles([new File([t], `pasted-${S.pasted}.txt`, { lastModified: Date.now() })]);
    box.value = '';
  }

  /* ================= Views ================= */
  function setView(v) {
    v = OLD_VIEW[v] || v;
    if (!VIEWS.includes(v)) v = 'evidence';
    S.view = v;
    TOOLS.forEach(t => {
      S.frames[t.id].classList.toggle('on', t.id === v);
      if (S.ready[t.id]) S.frames[t.id].contentWindow.postMessage({ hops: 'visible', on: t.id === v }, '*');
    });
    $('evidence').hidden = v !== 'evidence';
    if (v === 'evidence') renderEvidence();
    try { history.replaceState(null, '', '#' + v); } catch (e) { /* file:// in some browsers */ }
    renderRail();
  }

  /* ================= Rail & top bar ================= */
  const BADGE = { fail: '✕', warn: '!', ok: '✓', empty: '–' };
  function itemState(id) {
    const s = S.sums[id];
    if (s && s.busy) return { st: 'busy', line: 'Analyzing…', badge: '' };
    if (s && s.status) return { st: s.status, line: s.line, badge: s.badge };
    return { st: 'idle', line: null, badge: '' };
  }
  function railItem(id, title, line, st, badge, extra, dim) {
    const key = VIEWS.indexOf(id) + 1;
    return `<button class="hs-item is-${st}${S.view === id ? ' on' : ''}${dim ? ' dim' : ''}" data-view="${id}" aria-current="${S.view === id ? 'page' : 'false'}" title="${esc(title)} (key ${key})">
      <span class="hs-ico">${icon(id)}</span>
      <span class="hs-txt"><b>${esc(title)}</b><small>${esc(line)}</small>${extra || ''}</span>
      ${st === 'busy' ? '<span class="hs-spin" aria-label="analyzing"></span>' : badge ? `<span class="hs-badge is-${st}">${st in BADGE && st !== 'ok' ? `<i>${BADGE[st]}</i>` : ''}${esc(badge)}</span>` : ''}
    </button>`;
  }
  function renderRail() {
    const has = S.entries.length > 0;
    const loaded = new Set(S.entries.map(e => e.src)), got = EVIDENCE.filter(x => loaded.has(x.src)).length;
    const mods = { scc: 0, icm: 0, wdp: 0 };
    S.entries.forEach(e => { if (MODULE_OF[e.src]) mods[MODULE_OF[e.src]]++; });
    let h = railItem('evidence', 'Evidence', has ? `${fmtN(S.entries.length)} file${S.entries.length === 1 ? '' : 's'} · ${got} of ${EVIDENCE.length} sources` : 'Add the incident files here',
      'idle', '', `<span class="hs-meter" aria-hidden="true"><i style="width:${Math.round(got / EVIDENCE.length * 100)}%"></i></span>`);
    h += '<div class="hs-rail-sep"></div>';
    for (const t of TOOLS) {
      const s = itemState(t.id), shared = has && share(t.id, S.entries).length > 0;
      const line = s.line || (has && !shared ? (t.id === 'traffic' ? 'No traffic trace in the incident' : t.id === 'certs' ? 'No certificate source in the incident' : 'No matching logs') : t.sub);
      const pills = t.id === 'logs' && Object.values(mods).filter(Boolean).length > 1
        ? `<span class="hs-mods">${Object.keys(mods).filter(m => mods[m]).map(m => `<span role="button" tabindex="0" class="hs-mod${m === S.module ? ' on' : ''}" data-module="${m}" title="Analyze the ${MODULE_LABEL[m]} files">${MODULE_LABEL[m]} <i>${mods[m]}</i></span>`).join('')}</span>` : '';
      h += railItem(t.id, t.title, line, s.st, s.badge, pills, has && !shared);
    }
    $('rail').innerHTML = h + '<div class="hs-rail-foot">100% local · nothing leaves this browser<br><a href="docs.html">Docs</a> · <a href="privacy.html">Privacy</a> · <a href="disclaimer.html">Disclaimer</a></div>';
  }
  function renderTop() {
    const has = S.entries.length > 0, m = S.sums.map;
    $('btnNew').hidden = !has;
    const v = $('verdict');
    if (has && m && !m.busy && m.status) {
      v.hidden = false;
      v.className = 'hs-verdict is-' + m.status;
      v.innerHTML = `<i aria-hidden="true">${BADGE[m.status] || '?'}</i><span><b>${esc(m.status === 'fail' ? `Breaks at ${m.badge}` : m.status === 'warn' ? `Warning at ${m.badge}` : m.status === 'ok' ? 'No failing hop' : 'No request path')}</b><span>${esc(m.status === 'fail' || m.status === 'warn' ? m.line : m.path || '')}</span></span>`;
      v.title = [m.path, m.cause].filter(Boolean).join(' — ');
    } else if (has) {
      v.hidden = false; v.className = 'hs-verdict is-busy';
      v.innerHTML = '<span class="hs-spin" aria-hidden="true"></span><span><b>Checking every hop…</b></span>';
    } else v.hidden = true;
    const inc = $('incident');
    inc.hidden = !has;
    if (has) inc.innerHTML = [`${fmtN(S.entries.length)} file${S.entries.length === 1 ? '' : 's'}`, m && m.range, m && m.target].filter(Boolean).map(x => `<span>${esc(x)}</span>`).join('');
  }

  /* ================= Evidence: the one place for files ================= */
  const usedBy = e => TOOLS.filter(t => share(t.id, [e]).length).map(t => t.title);
  function renderEvidence() {
    const has = S.entries.length > 0, keepPaste = $('pasteBox') ? $('pasteBox').value : '';
    const loaded = new Map();
    S.entries.forEach(e => loaded.set(e.src, (loaded.get(e.src) || 0) + 1));
    const missing = EVIDENCE.filter(x => !loaded.has(x.src));
    const card = x => {
      const n = loaded.get(x.src) || 0;
      return `<article class="hs-ev${n ? ' got' : ''}"><span class="hs-ev-st" aria-hidden="true">${n ? '✓' : ''}</span>
        <div><h3>${esc(x.title)}${n ? ` <span class="badge">${n} file${n === 1 ? '' : 's'}</span>` : ''}</h3><p>${esc(x.shows)}</p>${n ? '' : `<p class="hs-how"><b>Collect:</b> ${esc(x.how)}</p>`}</div></article>`;
    };
    const readAs = (e, i) => `<select data-src="${i}" aria-label="Read ${esc(base(e.name))} as">${READ_AS.map(s => `<option value="${s.id}"${s.id === e.src ? ' selected' : ''}>${esc(s.label)}</option>`).join('')}</select>`;
    const rows = S.entries.map((e, i) => `<tr><td class="mono" title="${esc(e.name)}">${esc(base(e.name))}${e.name.includes('!/') ? `<br><span class="muted small">from ${esc(base(e.name.split('!/')[0]))}</span>` : ''}</td>
      <td>${e.file ? readAs(e, i) : esc(labelOf(e.src))}</td><td class="num">${esc(fmtBytes(e.size || 0))}</td>
      <td>${usedBy(e).map(u => `<span class="badge">${esc(u)}</span>`).join(' ') || '<span class="muted">—</span>'}</td>
      <td><button class="btn ghost icon" data-del="${i}" aria-label="Remove ${esc(base(e.name))}" title="Remove from the incident">✕</button></td></tr>`).join('');
    $('evidence').innerHTML = `<div class="hs-ev-wrap">
      <header class="hs-ev-head"><div class="v-kick">Evidence · the one place for the incident files</div>
        <h1>${has ? 'What this incident is based on' : 'Start with the evidence of one incident'}</h1>
        <p class="muted">Add everything you collected — logs, traces, exports, certificates, folders or a .zip. Each file is read once and used by every workspace: Map, Timeline, Logs, Traffic and Certificates. You can also drop files anywhere on the page.</p></header>
      <section class="hs-intake" aria-label="Add files">
        <button class="hs-dz" type="button" data-pick="files">
          ${icon('evidence', 40)}
          <b>Drop files, a folder or a .zip — or click to choose files</b>
          <span>SCC Download All · dev_icm · dev_webdisp · dev_w* · SM21 / ST22 export (.xlsx / .txt) · SM59 result · .cer / .pem / .pse / .jks · tunnel_traffic</span>
        </button>
        <div class="hs-intake-side">
          <div class="hs-intake-btns"><button class="btn" type="button" data-pick="folder">Choose a folder…</button>${has ? '' : '<button class="btn ghost" type="button" data-example>Try the example</button>'}</div>
          <label class="hs-paste-l" for="pasteBox">Paste text <span class="muted">(PEM, sapgenpse output, SM59 result, copied log lines)</span></label>
          <textarea id="pasteBox" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;…"></textarea>
          <button class="btn" type="button" data-paste>Add pasted text</button>
        </div>
      </section>
      ${has ? `<h2 class="hs-h">Files in this incident <span class="count">${S.entries.length}</span></h2>
        <div class="table-wrap"><table class="simple hs-files"><thead><tr><th>File</th><th>Read as</th><th class="num">Size</th><th>Used by</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
        <p class="muted small">Recognized wrongly? Change “Read as” — every workspace analyzes the file again.${S.skipped.length ? ` Skipped: ${S.skipped.map(s => esc(base(s.name) + ' — ' + s.reason)).join('; ')}` : ''}</p>` : ''}
      <h2 class="hs-h">${has ? (missing.length ? `Still missing — ${missing.length} of ${EVIDENCE.length} sources` : 'All sources covered') : 'What to collect'}</h2>
      <div class="hs-ev-grid">${(has ? missing.concat(EVIDENCE.filter(x => loaded.has(x.src))) : EVIDENCE).map(card).join('')}</div>
    </div>`;
    if (keepPaste) $('pasteBox').value = keepPaste;
  }

  function renderAll() { renderRail(); renderTop(); if (S.view === 'evidence') renderEvidence(); }

  /* ================= Drop overlay (files dropped anywhere go to Evidence) ================= */
  function showDrop(on) { $('drop').hidden = !on; }

  /* ================= Init ================= */
  function init() {
    buildFrames();
    window.addEventListener('message', onMessage);
    TS.initThemeButton($('btnTheme'));
    $('btnTheme').addEventListener('click', () => TOOLS.forEach(t => S.ready[t.id] && S.frames[t.id].contentWindow.postMessage({ hops: 'theme', theme: theme() }, '*')));
    $('btnNew').onclick = () => { if (confirm('Start a new incident? All files are removed from every workspace.')) { resetAll(); setView('evidence'); } };
    $('inputFiles').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('inputFolder').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('verdict').onclick = () => setView('map');
    $('rail').addEventListener('click', e => {
      const m = e.target.closest('[data-module]');
      if (m) { e.stopPropagation(); setModule(m.dataset.module); return; }
      const b = e.target.closest('[data-view]');
      if (b) setView(b.dataset.view);
    });
    $('rail').addEventListener('keydown', e => { const m = e.target.closest('[data-module]'); if (m && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); e.stopPropagation(); setModule(m.dataset.module); } });
    const ev = $('evidence');
    ev.addEventListener('click', e => {
      const d = e.target.closest('[data-del]');
      if (d) { S.entries.splice(+d.dataset.del, 1); resetAll(true); return; }
      const p = e.target.closest('[data-pick]');
      if (p) { $(p.dataset.pick === 'folder' ? 'inputFolder' : 'inputFiles').click(); return; }
      if (e.target.closest('[data-paste]')) { addPasted(); return; }
      if (e.target.closest('[data-example]')) loadExample();
    });
    ev.addEventListener('change', e => {
      const s = e.target.closest('[data-src]');
      if (s) { S.entries[+s.dataset.src].src = s.value; resetAll(true); }
    });
    // drag & drop anywhere: over the cockpit itself, or announced by a workspace frame
    window.addEventListener('dragenter', e => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) showDrop(true); });
    const drop = $('drop');
    drop.addEventListener('dragover', e => e.preventDefault());
    drop.addEventListener('dragleave', e => { if (!e.relatedTarget || !drop.contains(e.relatedTarget)) showDrop(false); });
    drop.addEventListener('drop', async e => { e.preventDefault(); showDrop(false); addFiles(await TS.filesFromDrop(e.dataTransfer)); });
    drop.addEventListener('click', () => showDrop(false));
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') showDrop(false);
      if (e.altKey || e.ctrlKey || e.metaKey || /input|select|textarea/i.test(e.target.tagName || '')) return;
      const i = '123456'.indexOf(e.key);
      if (i >= 0) setView(VIEWS[i]);
    });
    const h = (location.hash || '').slice(1);
    setView(h && h !== 'example' ? h : 'evidence');
    renderAll();
    if (h === 'example') loadExample();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(window.TS);
