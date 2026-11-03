/* Certificate analyzer UI */
(function (TS) {
  'use strict';
  const X = TS.x509, A = TS.certs, esc = TS.esc, $ = id => document.getElementById(id);
  const fmtN = n => (n || 0).toLocaleString('en-US');
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const d10 = t => (t == null ? '-' : TS.fmtTime(t, 0).slice(0, 10));
  const dFull = t => (t == null ? '-' : TS.fmtTime(t, 0) + ' UTC');
  const MAX_ROWS = 80;

  const S = { files: [], raw: [], hs: [], certs: [], findings: [], ref: Date.now(), host: '', q: '', store: '', serial: '', serialIss: '', acl: [], seq: 0 };
  const sn = A.sn;

  const STATUS_CLS = { expired: 'c-expired', expiring: 'c-expiring', soon: 'c-soon', ok: 'c-ok', notyet: 'c-notyet', unknown: 'c-notyet' };
  const statusPill = c => { const st = X.status(c, S.ref); return `<span class="cst ${STATUS_CLS[st.key]}">${esc(st.label)}</span>`; };

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
    $('btnPaste').onclick = () => {
      const t = $('pasteBox').value.trim();
      if (!t) return;
      ingest([{ name: `pasted-${S.files.length + 1}.txt`, bytes: new TextEncoder().encode(t) }]);
      $('pasteBox').value = '';
    };
    $('btnReset').onclick = reset;
    $('btnCsv').onclick = exportCsv;
    $('btnReport').onclick = exportReport;
    $('btnPem').onclick = exportPem;
    const today = new Date();
    $('optRef').value = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
    $('optRef').onchange = () => {
      const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec($('optRef').value);
      S.ref = m ? Date.UTC(+m[1], m[2] - 1, +m[3], 12) : Date.now();
      analyze();
    };
    $('optHost').oninput = TS.debounce(() => { S.host = $('optHost').value.trim(); analyze(); }, 300);
    $('optQ').oninput = TS.debounce(() => { S.q = $('optQ').value.trim().toLowerCase(); renderTable(); }, 200);
    $('optStore').onchange = () => { S.store = $('optStore').value; renderTrust(); renderSerial(); };
    $('optSerial').oninput = $('optSerialIss').oninput = TS.debounce(() => { S.serial = $('optSerial').value.trim(); S.serialIss = $('optSerialIss').value.trim(); renderSerial(); }, 250);
    $('btnAcl').onclick = () => { S.acl = A.parseAcl($('aclBox').value); renderAcl(); };
    document.body.addEventListener('click', e => { const b = e.target.closest('[data-cert]'); if (b) { e.preventDefault(); showCert(+b.dataset.cert); } });
    $('modalClose').onclick = closeModal;
    $('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
    let rt;
    window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => S.certs.length && renderGantt(), 150); });
    TS.embed.listen({ files: d => addFiles(TS.embed.toFiles(d.files), true), reset });
  }

  function setStatus(msg, isErr) { const s = $('status'); s.textContent = msg || ''; s.classList.toggle('error', !!isErr); }

  /* ================= Loading ================= */
  async function addFiles(list, fromCockpit) {
    if (!list || !list.length) return;
    if (!fromCockpit && TS.embed.forward(list)) return;
    const items = [];
    async function expand(name, u8) {
      if (/\.zip$/i.test(name)) {
        for (const it of TS.unzip(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength))) {
          try { await expand(name + '!/' + it.name, await it.read()); } catch (e) { S.files.push({ name: name + '!/' + it.name, kind: '-', pse: '', note: e.message, count: 0 }); }
        }
      } else items.push({ name, bytes: u8 });
    }
    try {
      for (const f of list) { setStatus(`Reading ${f.name}…`); await expand(f.webkitRelativePath || f.name, new Uint8Array(await f.arrayBuffer())); }
      ingest(items);
    } catch (err) { console.error(err); setStatus('Failed to read files: ' + err.message, true); }
  }

  async function ingest(items) {
    for (const it of items) {
      if (S.files.some(f => f.name === it.name)) continue;
      let r;
      try { r = X.fromBytes(it.bytes, it.name); } catch (e) { r = { certs: [], kind: '-', pse: '', note: 'error: ' + e.message }; }
      S.files.push({ name: it.name, kind: r.kind, pse: r.pse, note: r.note, count: r.certs.length });
      S.raw.push(...r.certs);
      S.hs.push(...(r.handshakes || []));
    }
    if (!S.raw.length) {
      setStatus('No certificates found. ' + S.files.map(f => `${base(f.name)}: ${f.note}`).join('; '), true); renderFiles();
      TS.embed.report({ status: 'empty', badge: '0', line: 'No certificate in the loaded files' });
      return;
    }
    const seq = ++S.seq;
    setStatus('Verifying certificate signatures…');
    const certs = A.dedupe(S.raw);
    try { await A.verify(certs); } catch (e) { console.error(e); }
    if (seq !== S.seq) return;   // newer files arrived meanwhile
    S.certs = certs;
    A.link(S.certs);
    setStatus('');
    $('loader').hidden = true; $('app').hidden = false;
    ['btnAdd', 'btnPem', 'btnCsv', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = false));
    // default trust store: an SSL server PSE, else the first PSE
    if (!S.files.some(f => f.name === S.store)) {
      const pick = S.files.find(f => f.count && /SSL server/i.test(f.pse)) || S.files.find(f => f.count && f.kind === 'SAP PSE');
      S.store = pick ? pick.name : '';
    }
    analyze();
  }

  function reset() {
    Object.assign(S, { files: [], raw: [], hs: [], certs: [], findings: [], seq: S.seq + 1 });
    ['btnAdd', 'btnPem', 'btnCsv', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = true));
    $('app').hidden = true; $('loader').hidden = false; setStatus('');
  }

  function analyze() {
    S.findings = A.analyze(S.certs, { ref: S.ref, host: S.host, handshakes: S.hs });
    renderKpis(); renderFindings(); renderTrust(); renderHs(); renderSerial(); renderAcl(); renderGantt(); renderTable(); renderChains(); renderFiles();
    const top = S.findings.filter(f => f.sev !== 'info').sort((a, b) => TS.SEV_RANK[a.sev] - TS.SEV_RANK[b.sev])[0];
    TS.embed.report({
      status: !top ? 'ok' : top.sev === 'critical' || top.sev === 'high' ? 'fail' : 'warn', badge: fmtN(S.certs.length),
      line: top ? `${top.title}${top.certs && top.certs.length ? ` (${top.certs.length})` : ''}` : `${fmtN(S.certs.length)} certificates, no findings`
    });
  }

  /* ================= Client certificate vs. CA list of the server (TLS handshake) ================= */
  const HS_CLS = { ok: 'c-ok', rejected: 'c-expired', notsent: 'c-expiring', nocert: 'c-notyet' };
  function renderHs() {
    const res = A.clientCertCheck(S.certs, S.hs);
    $('hsCard').hidden = !res.length;
    if (!res.length) { $('hsRes').innerHTML = ''; return; }
    $('hsRes').innerHTML = `<div class="table-wrap"><table class="simple"><thead><tr><th>Result</th><th>Server · handshakes</th><th>Accepted issuers (CA list)</th><th>Loaded client certificates</th><th>What to do</th></tr></thead><tbody>${res.map(r => `
      <tr><td><span class="cst ${HS_CLS[r.key]}">${esc(r.label)}</span></td>
      <td class="small"><span class="mono">${esc(r.peer)}</span><br>${r.n} handshake${r.n === 1 ? '' : 's'}${r.none ? `<br><span class="cst c-expired">no client certificate sent ${r.none}×</span>` : ''}${r.sent ? `<br><span class="cst c-ok">client certificate sent ${r.sent}×</span>` : ''}
        <br><span class="muted">${esc(r.first)}${r.last !== r.first ? ' – ' + esc(r.last) : ''}<br>${esc(r.refs.join(', '))}</span></td>
      <td class="small mono">${r.cas.map(esc).join('<br>')}</td>
      <td class="small">${r.cands.length ? r.cands.map(x => `${chip(x.cert)} <span class="cst ${x.ok ? 'c-ok">accepted' : 'c-expired">not accepted'}</span><br><span class="muted">${esc(x.role || base(x.cert.where[0].source))} · issuer ${esc(x.cert.issuer)} · SN <span class="mono">${esc(sn(x.cert.serial))}</span></span>`).join('<br>') : '<span class="muted">none loaded</span>'}</td>
      <td class="small">${esc(r.text)}${r.fix.length ? `<ol style="margin:6px 0 0;padding-left:18px">${r.fix.map(f => `<li>${esc(f)}</li>`).join('')}</ol>` : ''}</td></tr>`).join('')}</tbody></table></div>`;
  }

  /* ================= Trust check ================= */
  function renderTrust() {
    const files = S.files.filter(f => f.count);
    $('trustCard').hidden = files.length < 2;
    $('optStore').innerHTML = '<option value="">— choose a PSE / file —</option>' + files.map(f =>
      `<option value="${esc(f.name)}"${f.name === S.store ? ' selected' : ''}>${esc((f.pse && f.pse !== base(f.name) ? f.pse + ' — ' : '') + base(f.name))} (${f.count})</option>`).join('');
    if (!S.store) { $('trust').innerHTML = '<p class="muted">Choose the PSE whose certificate list should be checked.</p>'; return; }
    const res = A.trustCheck(S.certs, S.store, S.ref);
    const cls = { trusted: 'c-ok', invalid: 'c-expired', untrusted: 'c-expiring' };
    $('trust').innerHTML = res.length ? `<div class="table-wrap"><table class="simple"><thead><tr><th>Result</th><th>Certificate</th><th>Chain — serial number and verification of every link</th><th>What to do</th></tr></thead><tbody>${res.map(r => `
      <tr><td><span class="cst ${cls[r.key]}">${esc(r.label)}</span></td><td>${chip(r.cert)}<br><span class="small muted">SN ${esc(sn(r.cert.serial))}<br>${esc(where(r.cert))}</span></td>
      <td class="small">${stepsHtml(r.steps, r.required)}</td>
      <td class="small">${esc(r.text)}</td></tr>`).join('')}</tbody></table></div>`
      : '<p class="muted">No end-entity certificates outside the selected PSE. Load the client (or server) certificate to check it against this PSE.</p>';
  }

  /* Chain as a list: certificate · serial · in PSE, and between two levels the evidence of the link */
  const EV_CLS = { valid: 'c-ok', match: 'c-ok', invalid: 'c-expired', mismatch: 'c-expired', 'n/a': 'c-notyet' };
  const EV_TXT = { valid: 'verified', match: 'match', invalid: 'INVALID', mismatch: 'MISMATCH', 'n/a': 'not checked' };
  const evPills = ev => [['Name', ev.dn ? 'match' : 'mismatch'], ['Key ID', ev.keyId], ['Issuer serial', ev.serial], ['Signature', ev.sig]]
    .map(([k, v]) => `<span class="cst ${EV_CLS[v]}" title="${esc(k)}">${esc(k)}: ${esc(EV_TXT[v])}</span>`).join(' ');
  function stepsHtml(steps, required) {
    const inPse = S.store ? '<span class="cst c-ok">in PSE</span>' : '';
    let h = '<ol class="chain-path">' + steps.map(s => {
      const st = X.status(s.cert, S.ref).key;
      return `<li><button class="link-btn" data-cert="${s.cert.id}" type="button"><span class="dot ${STATUS_CLS[st]}"></span>${esc(s.cert.cn)}</button>
        <span class="muted"> SN <span class="mono">${esc(sn(s.cert.serial))}</span>${s.cert.ski ? ` · SKI <span class="mono">${esc(s.cert.ski.slice(0, 23))}${s.cert.ski.length > 23 ? '…' : ''}</span>` : ''}</span>
        ${s.inStore ? inPse : ''}${['expired', 'notyet'].includes(st) ? ` ${statusPill(s.cert)}` : ''}
        ${s.ev ? `<div style="margin:2px 0 0">↳ issued by the next: ${evPills(s.ev)}${s.ev.warn ? ` <span class="cst c-soon">AKI serial</span>` : ''}</div>` : ''}</li>`;
    }).join('');
    if (required && !required.self) h += `<li><span class="missing">Required issuer: ${esc(required.dn)}${required.keyId ? ` · key ID ${esc(required.keyId)}` : ''}${required.serial ? ` · serial ${esc(sn(required.serial))}` : ''}</span></li>`;
    return h + '</ol>';
  }

  /* ================= Serial lookup ================= */
  function renderSerial() {
    const box = $('serialRes');
    if (!S.serial) { box.innerHTML = ''; return; }
    const r = A.findSerial(S.certs, S.serial, S.serialIss);
    if (!r.keys.length) { box.innerHTML = '<p class="muted">Not a serial number (hex digits with optional ":" / blanks, or a decimal number).</p>'; return; }
    const forms = r.keys.map(k => X.serialForms(k)).map(f => `hex <span class="mono">${esc(f.colon)}</span> = decimal <span class="mono">${esc(f.dec || '-')}</span>`).join(' &nbsp;or&nbsp; ');
    const one = c => {
      const path = A.path(c), top = path[path.length - 1];
      const steps = path.map((p, i) => ({ cert: p, inStore: !!S.store && p.where.some(w => w.source === S.store), ev: i < path.length - 1 ? p.linkEv : null }));
      const obs = obsSummary(c);
      return `<article class="finding info"><div class="finding-head">${statusPill(c)}<h3>${chip(c)}</h3><span class="cat">· ${esc(c.role)} · ${esc(where(c))}</span></div>
        <p class="small">Subject <span class="mono">${esc(c.subject)}</span><br>Issuer <span class="mono">${esc(c.issuer || '-')}</span>${obs.length ? '<br>Seen in: ' + obs.map(esc).join('; ') : ''}</p>
        ${stepsHtml(steps, top.missingIssuer ? A.required(top) : null)}</article>`;
    };
    box.innerHTML = `<p class="small">Interpreted as ${forms}</p>` +
      (r.hits.length ? `<div class="findings">${r.hits.map(one).join('')}</div>` : '<p class="muted">No loaded certificate has this serial number' + (S.serialIss ? ' with this issuer' : '') + '. Load the PSE / certificate the serial comes from.</p>') +
      (r.issuedBy.length ? `<p class="small" style="margin-top:10px"><b>Certificates whose AKI names a CA certificate with this serial:</b></p><div class="inc-srcs">${r.issuedBy.map(chip).join('')}</div>` : '');
  }

  /* ================= STRUSTSSO2 ACL ================= */
  function renderAcl() {
    const box = $('aclRes');
    if (!S.acl.length) { box.innerHTML = $('aclBox').value.trim() ? '<p class="muted">No ACL rows recognized — each row needs at least the subject DN (and the issuer DN + serial number).</p>' : ''; return; }
    const cls = { ok: 'c-ok', invalid: 'c-expired', serial: 'c-expired', subject: 'c-expiring', missing: 'c-notyet' };
    const lbl = { ok: 'Matches', invalid: 'Certificate not valid', serial: 'Serial mismatch', subject: 'Subject differs', missing: 'Not loaded' };
    const res = A.aclCheck(S.certs, S.acl, S.ref);
    box.innerHTML = `<div class="table-wrap"><table class="simple"><thead><tr><th>Result</th><th>System / client</th><th>ACL subject · issuer · serial</th><th>Loaded certificate</th><th>What to do</th></tr></thead><tbody>${res.map(x => `
      <tr><td><span class="cst ${cls[x.key]}">${lbl[x.key]}</span></td><td class="mono small">${esc(x.row.sid || '-')} / ${esc(x.row.client || '-')}</td>
      <td class="small">${esc(x.row.subject)}<br><span class="muted">${esc(x.row.issuer || '-')}</span><br><span class="mono">${esc(sn(x.row.serial))}</span></td>
      <td class="small">${x.cert ? `${chip(x.cert)}<br><span class="mono">${esc(sn(x.cert.serial))}</span> · ${statusPill(x.cert)}` : '-'}</td>
      <td class="small">${esc(x.text)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  const obsSummary = c => {
    const m = new Map();
    (c.observed || []).forEach(o => { const k = `${base(o.source)}: ${o.what}${o.pse ? ' — PSE ' + base(o.pse) : ''}`; m.set(k, (m.get(k) || []).concat(o.line)); });
    return [...m].map(([k, ls]) => `${k} (${ls.length}×, line ${ls.slice(0, 3).join(', ')}${ls.length > 3 ? ', …' : ''})`);
  };

  /* ================= KPIs & findings ================= */
  function renderKpis() {
    const st = S.certs.map(c => X.status(c, S.ref).key);
    const cnt = k => st.filter(x => x === k).length;
    const fid = id => (S.findings.find(f => f.id === id) || { certs: [] }).certs.length;
    const kpi = (k, v, s) => `<div class="kpi"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
    $('kpis').innerHTML =
      kpi('Certificates', fmtN(S.certs.length), `${S.files.length} file(s) · ${S.certs.filter(c => /CA/.test(c.role)).length} CA`) +
      kpi('<span class="cst c-expired">Expired</span>', fmtN(cnt('expired')), `at ${d10(S.ref)}`) +
      kpi('<span class="cst c-expiring">≤ 30 days</span>', fmtN(cnt('expiring')), 'renew now') +
      kpi('<span class="cst c-soon">≤ 90 days</span>', fmtN(cnt('soon')), 'plan renewal') +
      kpi('Weak algorithms', fmtN(fid('weak-sig') + fid('weak-key')), 'SHA-1/MD5 signature, short keys') +
      kpi('Chain issues', fmtN(fid('missing-issuer') + fid('wrong-issuer') + fid('ca-flag') + fid('serial-conflict')), 'missing / wrong issuer (key, serial), CA flag');
  }

  const chip = c => `<button class="badge cert-chip" data-cert="${c.id}" type="button">${X.status(c, S.ref).key === 'expired' ? '⚠ ' : ''}${esc(c.cn)}</button>`;
  function renderFindings() {
    $('cntFind').textContent = S.findings.filter(f => f.sev !== 'info').length;
    $('findings').innerHTML = S.findings.length ? `<div class="findings">${S.findings.map(f => `
      <article class="finding ${f.sev}">
        <div class="finding-head">${TS.sevPill(f.sev)}<h3>${esc(f.title)}</h3>${f.certs.length ? `<span class="cat">· ${f.certs.length} certificate${f.certs.length === 1 ? '' : 's'}</span>` : ''}</div>
        <p>${esc(f.why)}</p>
        ${f.fix.length ? `<b class="small">Recommended actions</b><ul>${f.fix.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
        ${f.certs.length ? `<div class="inc-srcs">${f.certs.slice(0, 30).map(chip).join('')}${f.certs.length > 30 ? `<span class="muted small">+${f.certs.length - 30} more</span>` : ''}</div>` : ''}
      </article>`).join('')}</div>` : '<div class="empty">No problems found for the loaded certificates.</div>';
  }

  /* ================= Validity timeline ================= */
  function renderGantt() {
    const host = $('gantt');
    if (!host || !host.offsetParent) return;
    $('ganttLegend').innerHTML = [['c-expired', 'Expired'], ['c-expiring', '≤ 30 days'], ['c-soon', '≤ 90 days'], ['c-ok', 'Valid'], ['c-notyet', 'Not yet valid / unknown']]
      .map(([c, l]) => `<span><i class="${c}"></i>${l}</span>`).join('');
    const rows = S.certs.filter(c => c.notAfter != null).sort((a, b) => a.notAfter - b.notAfter).slice(0, MAX_ROWS);
    if (!rows.length) { host.innerHTML = '<p class="muted">No validity dates.</p>'; return; }
    const W = Math.max(360, host.clientWidth), LW = W < 640 ? 120 : 230, PW = W - LW - 12, RH = 20, TOP = 20;
    const H = TOP + rows.length * RH + 4;
    const Y = 365.25 * 864e5;
    let lo = Math.min(...rows.map(c => (c.notBefore != null ? c.notBefore : c.notAfter - Y))), hi = Math.max(...rows.map(c => c.notAfter), S.ref);
    lo = Math.max(lo, S.ref - 10 * Y); hi = Math.min(Math.max(hi, S.ref + 0.5 * Y), S.ref + 15 * Y);
    const x = t => LW + (Math.min(Math.max(t, lo), hi) - lo) / (hi - lo) * PW;
    let svg = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Certificate validity periods">`;
    const y0 = new Date(lo).getUTCFullYear(), y1 = new Date(hi).getUTCFullYear();
    const step = Math.max(1, Math.ceil((y1 - y0 + 1) / Math.max(2, Math.floor(PW / 70))));
    for (let yr = y0 + 1; yr <= y1; yr += step) {
      const xx = x(Date.UTC(yr, 0, 1));
      svg += `<line class="gridline" x1="${xx}" x2="${xx}" y1="${TOP - 4}" y2="${H}"/><text class="tick" x="${xx}" y="12" text-anchor="middle">${yr}</text>`;
    }
    rows.forEach((c, i) => {
      const yy = TOP + i * RH, st = X.status(c, S.ref).key;
      const x0 = x(c.notBefore != null ? c.notBefore : lo), x1 = Math.max(x0 + 3, x(c.notAfter));
      svg += `<text class="lane-label" x="4" y="${yy + 14}">${esc(c.cn.length > (LW < 200 ? 16 : 32) ? c.cn.slice(0, LW < 200 ? 15 : 31) + '…' : c.cn)}</text>`;
      svg += `<rect class="${STATUS_CLS[st]}" x="${x0}" y="${yy + 4}" width="${x1 - x0}" height="${RH - 8}" rx="3"/>`;
      svg += `<rect class="hit" x="${LW}" y="${yy}" width="${PW}" height="${RH}" data-i="${i}"/>`;
    });
    const xr = x(S.ref);
    svg += `<line class="ref-line" x1="${xr}" x2="${xr}" y1="${TOP - 6}" y2="${H}"/><text class="tick ref-label" x="${xr + 3}" y="${TOP - 8}">${esc(d10(S.ref))}</text>`;
    svg += '</svg>';
    host.innerHTML = svg;
    $('ganttNote').textContent = `${rows.length} of ${S.certs.length} certificates, sorted by expiry · vertical line = reference date · click a bar for details.`;
    const tip = $('tooltip');
    host.querySelectorAll('.hit').forEach(el => {
      const c = rows[+el.dataset.i];
      el.addEventListener('mousemove', ev => {
        tip.innerHTML = `<div style="font-weight:600;margin-bottom:4px">${esc(c.cn)}</div><div class="tt-row"><span>Valid from</span><b>${esc(d10(c.notBefore))}</b></div><div class="tt-row"><span>Valid to</span><b>${esc(d10(c.notAfter))}</b></div><div style="margin-top:4px">${statusPill(c)}</div>`;
        tip.hidden = false;
        const tw = tip.offsetWidth, th = tip.offsetHeight;
        let lx = ev.clientX + 14, ly = ev.clientY + 14;
        if (lx + tw > window.innerWidth - 8) lx = ev.clientX - tw - 14;
        if (ly + th > window.innerHeight - 8) ly = ev.clientY - th - 14;
        tip.style.left = lx + 'px'; tip.style.top = ly + 'px';
      });
      el.addEventListener('mouseleave', () => (tip.hidden = true));
      el.addEventListener('click', () => { tip.hidden = true; showCert(c.id); });
    });
  }

  /* ================= Inventory ================= */
  const keyText = c => (c.keyAlg ? `${c.keyAlg}${c.keyCurve ? ' ' + c.keyCurve : c.keyBits ? ' ' + c.keyBits : ''}` : '-');
  const where = c => [...new Set(c.where.map(w => w.pse || base(w.source)))].join(', ');
  function renderTable() {
    const q = S.q, qKeys = q ? X.serialKeys(q) : [];
    const list = S.certs.filter(c => !q || qKeys.includes(c.serialKey) || [c.subject, c.issuer, c.serial, (c.san || []).join(' '), where(c)].join(' ').toLowerCase().includes(q))
      .sort((a, b) => (a.notAfter || 0) - (b.notAfter || 0));
    $('cntCerts').textContent = fmtN(S.certs.length);
    $('certTable').innerHTML = `<thead><tr><th>Status</th><th>Certificate</th><th>Role</th><th>Issuer</th><th>Serial</th><th>Valid to</th><th>Key</th><th>Signature</th><th>PSE / file</th></tr></thead><tbody>${list.map(c => {
      const iss = /(?:^|,\s*)CN=([^,]+)/i.exec(c.issuer || '');
      const link = c.selfSigned ? (c.selfSig === false ? '<br><span class="cst c-expired">own signature invalid</span>' : '')
        : c.missingIssuer ? `<br><span class="cst c-expiring">${c.wrongIssuer.length ? 'issuer key/serial mismatch' : 'issuer missing'}</span>`
          : c.linkEv && c.linkEv.sig === 'valid' ? '<br><span class="cst c-ok">signature verified</span>' : '';
      const s = sn(c.serial);
      return `<tr class="clickable" data-cert="${c.id}"><td>${statusPill(c)}</td>
        <td><b>${esc(c.cn)}</b>${c.san && c.san.length ? `<br><span class="small muted">${esc(c.san.slice(0, 3).join(', '))}${c.san.length > 3 ? ' +' + (c.san.length - 3) : ''}</span>` : ''}</td>
        <td class="small">${esc(c.role)}${link}</td>
        <td class="small">${esc(iss ? iss[1] : c.issuer || '-')}</td><td class="mono small" title="${esc(s)}">${esc(s.length > 23 ? s.slice(0, 23) + '…' : s)}</td><td class="mono small">${esc(d10(c.notAfter))}</td>
        <td class="small">${esc(keyText(c))}</td><td class="small">${esc(c.sigAlg || '-')}</td><td class="small">${esc(where(c))}</td></tr>`;
    }).join('') || '<tr><td colspan="9" class="muted" style="text-align:center;padding:20px">No certificates match the filter.</td></tr>'}</tbody>`;
  }

  /* ================= Chains ================= */
  function renderChains() {
    const node = c => `<li><button class="link-btn" data-cert="${c.id}" type="button"><span class="dot ${STATUS_CLS[X.status(c, S.ref).key]}"></span>${esc(c.cn)}</button>
      <span class="muted small"> ${esc(c.role)} · until ${esc(d10(c.notAfter))}</span>${c.children.length ? `<ul>${c.children.map(node).join('')}</ul>` : ''}</li>`;
    const roots = S.certs.filter(c => !c.parent && !c.missingIssuer);
    const missing = new Map();
    S.certs.filter(c => c.missingIssuer).forEach(c => { const k = c.issuer; missing.set(k, (missing.get(k) || []).concat(c)); });
    $('chains').innerHTML = `<ul class="chain-tree">${roots.map(node).join('')}${[...missing.entries()].map(([iss, cs]) =>
      `<li><span class="missing">Issuer not loaded: ${esc(iss)}</span><ul>${cs.map(node).join('')}</ul></li>`).join('')}</ul>`;
  }

  function renderFiles() {
    $('files').innerHTML = `<div class="table-wrap"><table class="simple"><thead><tr><th>File</th><th>Type</th><th>Result</th></tr></thead><tbody>${S.files.map(f =>
      `<tr><td class="mono small" title="${esc(f.name)}">${esc(base(f.name))}</td><td class="small">${esc(f.kind)}${f.pse && f.pse !== base(f.name) ? '<br><span class="muted">' + esc(f.pse) + '</span>' : ''}</td><td class="small ${f.count ? '' : 'muted'}">${esc(f.note)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  /* ================= Detail ================= */
  function showCert(id) {
    const c = S.certs[id];
    if (!c) return;
    const row = (k, v) => (v == null || v === '' || (Array.isArray(v) && !v.length) ? '' : `<tr><th>${esc(k)}</th><td class="mono">${Array.isArray(v) ? v.map(esc).join('<br>') : esc(v)}</td></tr>`);
    const path = A.path(c);
    const top = path[path.length - 1];
    const hostRes = S.host ? (X.matchesHost(c, S.host) ? `matches ${S.host}` : `does not match ${S.host}`) : '';
    const f = X.serialForms(c.serial);
    const req = A.required(c);
    $('modalTitle').textContent = c.cn;
    $('modalBody').innerHTML = `<div style="padding:14px 16px">
      <div class="detail-meta" style="margin-bottom:10px">${statusPill(c)}<span>${esc(c.role)}</span>${c.missingIssuer ? `<span class="cst c-expiring">${c.wrongIssuer && c.wrongIssuer.length ? 'issuer key / serial mismatch' : 'issuer not loaded'}</span>` : ''}${c.serialConflict ? '<span class="cst c-expired">serial conflict</span>' : ''}</div>
      <table class="simple kv"><tbody>
        ${row('Subject', c.subject)}${row('Issuer', c.issuer)}
        ${row('Serial number', f ? [`${f.colon}  (hex — STRUST / sapgenpse / ICM trace)`, `${f.plain}  (hex without separators)`, `${f.dec}  (decimal — SAML / XML signature / Java)`] : c.serial)}
        ${row('Version', c.version ? 'v' + c.version : '')}
        ${row('Valid from', dFull(c.notBefore))}${row('Valid to', dFull(c.notAfter))}
        ${row('Public key', keyText(c))}${row('Signature algorithm', c.sigAlg)}
        ${row('Subject Alternative Names', (c.san || []).concat(c.sanIp || [], c.emails || []))}
        ${row('Key usage', (c.ku || []).join(', '))}${row('Extended key usage', (c.eku || []).join(', '))}
        ${row('Basic constraints', c.ca == null ? '' : `CA=${c.ca}${c.pathLen != null ? ', pathLen=' + c.pathLen : ''}`)}
        ${row('Subject key identifier', c.ski)}
        ${row('Authority key identifier', [c.aki && 'key ID ' + c.aki, c.akiIssuer && 'issuer ' + c.akiIssuer, c.akiSerial && 'issuer serial ' + sn(c.akiSerial)].filter(Boolean))}
        ${row('CRL distribution points', c.crl)}${row('OCSP', c.ocsp)}${row('CA issuers', c.caIssuers)}
        ${row('Critical extensions', c.critical)}
        ${row('Host name check', hostRes)}
        ${row('Found in', c.where.map(w => `${w.pse ? w.pse + ' — ' : ''}${base(w.source)} (${w.container || '-'})`))}
        ${row('Seen in traces', obsSummary(c))}
        <tr><th>SHA-1 fingerprint</th><td class="mono" id="fp1">${c.der ? 'calculating…' : '-'}</td></tr>
        <tr><th>SHA-256 fingerprint</th><td class="mono" id="fp256">${c.der ? 'calculating…' : '-'}</td></tr>
      </tbody></table>
      <h4 style="margin:14px 0 6px">Issuer verification</h4>
      ${issuerHtml(c, req)}
      <h4 style="margin:14px 0 6px">Chain (serial number per level)</h4>
      <div class="small">${stepsHtml(path.map((p, i) => ({ cert: p, inStore: !!S.store && p.where.some(w => w.source === S.store), ev: i < path.length - 1 ? p.linkEv : null })), top.missingIssuer ? A.required(top) : null)}</div>
      ${c.der ? `<div style="margin-top:12px"><button class="btn" id="dlCert" type="button">Download .crt (PEM)</button> <button class="btn ghost" id="cpCert" type="button">Copy PEM</button></div>` : '<p class="muted small">Loaded from text — no binary certificate available for download.</p>'}
    </div>`;
    $('modal').hidden = false;
    if (c.der) {
      X.fingerprints(c).then(fp => { const a = $('fp1'), b = $('fp256'); if (a) a.textContent = fp.sha1 || 'not available'; if (b) b.textContent = fp.sha256 || 'not available'; });
      $('dlCert').onclick = () => TS.download(`${c.cn.replace(/[^\w.-]+/g, '_')}.crt`, X.toPem(c.der), 'application/x-pem-file');
      $('cpCert').onclick = e => navigator.clipboard && navigator.clipboard.writeText(X.toPem(c.der)).then(() => { e.target.textContent = 'Copied ✓'; });
    }
  }
  function closeModal() { $('modal').hidden = true; }

  /* All certificates that could be the issuer, with the evidence for / against each */
  function issuerHtml(c, req) {
    if (c.selfSigned) {
      const v = c.selfSig === true ? 'valid' : c.selfSig === false ? 'invalid' : 'n/a';
      return `<p class="small">Self-signed (trust anchor): own signature <span class="cst ${EV_CLS[v]}">${EV_TXT[v]}</span>. A partner trusts it only if exactly this certificate (serial ${esc(sn(c.serial))}) is in its PSE / trust store.</p>`;
    }
    const rows = [];
    if (c.parent) rows.push({ p: c.parent, ev: c.linkEv, res: '<span class="cst c-ok">issuer</span>' });
    (c.altIssuers || []).forEach(p => rows.push({ p, ev: A.evidence(c, p), res: '<span class="cst c-soon">alternative</span>' }));
    (c.wrongIssuer || []).forEach(w => rows.push({ p: w.cert, ev: w.ev, res: `<span class="cst c-expired">not the issuer</span><br><span class="muted">${esc(w.ev.why)}</span>` }));
    const need = `<p class="small">Required issuer (from this certificate): <span class="mono">${esc(req.dn || '-')}</span>${req.keyId ? ` · key ID <span class="mono">${esc(req.keyId)}</span>` : ''}${req.serial ? ` · serial <span class="mono">${esc(sn(req.serial))}</span>` : ''}</p>`;
    if (!rows.length) return need + '<p class="small"><span class="missing">No certificate with this issuer name is loaded.</span></p>';
    return need + `<div class="table-wrap"><table class="simple"><thead><tr><th>Candidate</th><th>Serial</th><th>Checks</th><th>Result</th></tr></thead><tbody>${rows.map(x => `
      <tr><td>${chip(x.p)}<br><span class="small muted">${esc(where(x.p))} · until ${esc(d10(x.p.notAfter))}</span></td><td class="mono small">${esc(sn(x.p.serial))}</td>
      <td class="small">${evPills(x.ev)}${x.ev.warn ? `<br>${esc(x.ev.warn)}` : ''}</td><td class="small">${x.res}</td></tr>`).join('')}</tbody></table></div>`;
  }

  /* ================= Export ================= */
  const stamp = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
  const csvCell = v => { const s = String(v == null ? '' : v); return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  function exportCsv() {
    const head = ['common_name', 'subject', 'issuer', 'serial_hex', 'serial_decimal', 'valid_from', 'valid_to', 'days_left', 'status', 'role', 'key', 'signature', 'san', 'key_usage', 'ext_key_usage',
      'ski', 'aki_key_id', 'aki_issuer_serial', 'issuer_loaded', 'issuer_serial', 'issuer_link', 'locations', 'seen_in_traces'];
    const rows = S.certs.map(c => { const f = X.serialForms(c.serial) || {}; return [c.cn, c.subject, c.issuer, f.colon || c.serial, f.dec || '', d10(c.notBefore), d10(c.notAfter), c.notAfter != null ? Math.floor((c.notAfter - S.ref) / 864e5) : '',
      X.status(c, S.ref).label, c.role, keyText(c), c.sigAlg || '', (c.san || []).join(' '), (c.ku || []).join(' '), (c.eku || []).join(' '),
      c.ski || '', c.aki || '', c.akiSerial ? sn(c.akiSerial) : '',
      c.selfSigned ? 'self-signed' : c.missingIssuer ? (c.wrongIssuer.length ? 'name only (key/serial mismatch)' : 'no') : 'yes', c.parent ? sn(c.parent.serial) : '',
      c.selfSigned ? 'own signature ' + (c.selfSig === true ? 'verified' : c.selfSig === false ? 'INVALID' : 'not checked') : c.linkEv ? c.linkEv.proof : '', where(c), obsSummary(c).join(' | ')]; });
    TS.download(`certificates-${stamp()}.csv`, '﻿' + [head].concat(rows).map(r => r.map(csvCell).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
  }
  function exportPem() {
    const out = S.certs.filter(c => c.der).map(c => `# ${c.subject}\n# valid to ${d10(c.notAfter)} · ${where(c)}\n` + X.toPem(c.der)).join('\n');
    TS.download(`certificates-${stamp()}.pem`, out, 'application/x-pem-file');
  }
  function exportReport() {
    const md = [], cell = s => String(s == null ? '' : s).replace(/\|/g, '\\|');
    md.push('# SAP Certificate Report', '', `Generated: ${new Date().toLocaleString('en-US')} · reference date ${d10(S.ref)}${S.host ? ` · host name check: ${S.host}` : ''}`, '');
    md.push(`Files: ${S.files.map(f => `${base(f.name)} (${f.note})`).join(', ')}`, '');
    md.push('## Findings', '');
    if (!S.findings.length) md.push('_No problems found._', '');
    S.findings.forEach(f => {
      md.push(`### [${TS.SEV_LABEL[f.sev].toUpperCase()}] ${f.title}`, '', f.why, '');
      f.fix.forEach(x => md.push(`- ${x}`));
      if (f.certs.length) { md.push('', 'Certificates:'); f.certs.forEach(c => md.push(`- ${c.cn} — valid to ${d10(c.notAfter)} (${where(c)})`)); }
      md.push('');
    });
    if (S.store) {
      const tr = A.trustCheck(S.certs, S.store, S.ref);
      md.push(`## Trust check — trust store ${base(S.store)}`, '');
      if (!tr.length) md.push('_No end-entity certificates outside the selected PSE._', '');
      tr.forEach(r => {
        md.push(`### [${r.label.toUpperCase()}] ${r.cert.cn} — serial ${sn(r.cert.serial)}`, '', r.text, '', '| Level | Certificate | Serial | In PSE | Name | Key ID | Issuer serial | Signature |', '|---|---|---|---|---|---|---|---|');
        r.steps.forEach((s, i) => md.push(`| ${i} | ${cell(s.cert.subject)} | ${sn(s.cert.serial)} | ${s.inStore ? 'yes' : ''} | ${s.ev ? (s.ev.dn ? 'match' : 'MISMATCH') : ''} | ${s.ev ? s.ev.keyId : ''} | ${s.ev ? s.ev.serial : ''} | ${s.ev ? s.ev.sig : ''} |`));
        if (r.required && !r.required.self) md.push(`| — | required: ${cell(r.required.dn)} | ${r.required.serial ? sn(r.required.serial) : '-'} | | | ${r.required.keyId || ''} | | |`);
        md.push('');
      });
    }
    const hs = A.clientCertCheck(S.certs, S.hs);
    if (hs.length) {
      md.push('## Client certificate vs. CA list of the server (TLS handshake)', '');
      hs.forEach(r => {
        md.push(`### [${r.label.toUpperCase()}] ${r.peer} — ${r.n} handshake(s)${r.none ? `, no client certificate sent ${r.none}×` : ''}${r.sent ? `, sent ${r.sent}×` : ''}`, '',
          `Time: ${r.first}${r.last !== r.first ? ' – ' + r.last : ''} (${r.refs.join(', ')})`, '', 'Accepted issuers:', '');
        r.cas.forEach(d => md.push(`- \`${d}\``));
        md.push('', '| Client certificate | Role / file | Issuer | Serial | Accepted |', '|---|---|---|---|---|');
        r.cands.forEach(x => md.push(`| ${cell(x.cert.subject)} | ${cell(x.role || base(x.cert.where[0].source))} | ${cell(x.cert.issuer)} | ${sn(x.cert.serial)} | ${x.ok ? 'yes, via ' + cell(x.via) : 'NO'} |`));
        md.push('', r.text, '');
        r.fix.forEach((f, i) => md.push(`${i + 1}. ${f}`));
        md.push('');
      });
    }
    if (S.acl.length) {
      md.push('## STRUSTSSO2 ACL check', '', '| System / client | ACL subject | ACL serial | Result |', '|---|---|---|---|');
      A.aclCheck(S.certs, S.acl, S.ref).forEach(x => md.push(`| ${x.row.sid || '-'} / ${x.row.client || '-'} | ${cell(x.row.subject)} | ${sn(x.row.serial)} | ${cell(x.text)} |`));
      md.push('');
    }
    md.push('## Inventory', '', '| Certificate | Role | Issuer | Serial | Valid to | Status | Key | Signature | PSE / file |', '|---|---|---|---|---|---|---|---|---|');
    S.certs.slice().sort((a, b) => (a.notAfter || 0) - (b.notAfter || 0)).forEach(c =>
      md.push(`| ${cell(c.cn)} | ${c.role} | ${cell((/(?:^|,\s*)CN=([^,]+)/i.exec(c.issuer || '') || [])[1] || c.issuer)} | ${sn(c.serial)} | ${d10(c.notAfter)} | ${X.status(c, S.ref).label} | ${keyText(c)} | ${c.sigAlg || '-'} | ${cell(where(c))} |`));
    TS.download(`certificate-report-${stamp()}.md`, md.join('\n'), 'text/markdown;charset=utf-8');
  }

  document.addEventListener('DOMContentLoaded', init);
})(window.TS);
