/* Certificate analysis for SAP (STRUST / PSE): inventory, roles, chains and findings */
(function (TS) {
  'use strict';
  const X = TS.x509, A = TS.certs = {};
  const DAY = 864e5;

  const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const sn = s => { const f = X.serialForms(s); return f ? f.colon : '-'; };
  const d10 = t => (t == null ? '-' : new Date(t).toISOString().slice(0, 10));
  const base = p => String(p || '').split(/[\\/]|!\//).pop();
  A.sn = sn;

  /* Cloud Connector certificates by their download file name (Configuration → On Premise / User Interface) */
  const SCC_FILES = [[/sys_cert/i, 'SCC system certificate'], [/ca_cert/i, 'SCC CA certificate (principal propagation)'], [/ui_cert/i, 'SCC UI certificate']];
  A.sccRole = c => { for (const w of c.where || []) for (const [re, label] of SCC_FILES) if (re.test(base(w.source))) return label; return ''; };

  /* Same certificate from several files / PSEs / traces → one entry with all locations.
   * Identity = issuer DN + serial number (RFC 5280: unique per CA), so a certificate referenced in an ICM trace
   * ("Issuer DN / SerialNum") or in sapgenpse output is matched to the binary certificate from STRUST / a PSE. */
  A.dedupe = function (list) {
    const map = new Map();
    for (const c0 of list) {
      const c = Object.assign({}, c0);   // raw entries stay untouched (dedupe runs again when files are added)
      const iss = X.normDn(c.issuer);
      let key = c.serialKey && iss ? 'i|' + iss + '|' + c.serialKey : 't|' + X.normDn(c.subject) + '|' + c.notAfter;
      let e = map.get(key);
      if (e && e.der && c.der && !sameBytes(e.der, c.der)) {
        // same issuer + serial but a different certificate: never merge, flag both
        const base = e;
        let n = 2;
        for (; (e = map.get(key + '#' + n)) && !sameBytes(e.der, c.der); n++);
        key += '#' + n;
        base.serialConflict = c.serialConflict = true;
      }
      const loc = { source: c.source, pse: c.pse, container: c.container };
      if (e) {
        if (!e.where.some(w => w.source === loc.source && w.pse === loc.pse)) e.where.push(loc);
        const where = e.where, observed = (e.observed || []).concat(c.observed || []), conflict = e.serialConflict || c.serialConflict;
        if (!e.der && c.der) Object.assign(e, c);
        else for (const k in c) if (e[k] == null || e[k] === '' || (Array.isArray(e[k]) && !e[k].length)) e[k] = c[k];
        e.where = where; e.observed = observed.length ? observed : undefined; e.serialConflict = conflict;
      } else { c.where = [loc]; map.set(key, c); }
    }
    // text references with neither serial nor validity (e.g. a trace line with only the subject) → the one entry with that subject
    for (const [key, c] of map) {
      if (c.der || c.serialKey || c.notAfter != null) continue;
      const same = [...map.values()].filter(o => o !== c && X.normDn(o.subject) === X.normDn(c.subject));
      if (same.length !== 1) continue;
      const t = same[0];
      c.where.forEach(w => { if (!t.where.some(x => x.source === w.source && x.pse === w.pse)) t.where.push(w); });
      if (c.observed) t.observed = (t.observed || []).concat(c.observed);
      map.delete(key);
    }
    const out = [...map.values()];
    out.forEach((c, i) => { c.id = i; });
    return out;
  };

  A.role = function (c) {
    const caLike = c.ca === true || (c.ku || []).includes('keyCertSign');
    // self-signed without CA flag: a root CA (often v1 without extensions) unless it is known as an end entity (trace reference, SCC system / UI certificate)
    if (c.selfSigned) return c.ca === false || (c.ca == null && ((!c.der && c.observed) || /system|UI/.test(A.sccRole(c)))) ? 'Self-signed' : 'Root CA';
    if (caLike) return 'Intermediate CA';
    if (c.fromText && !c.issuer) return 'Unknown';
    return 'End entity';
  };

  /* Possible issuers of each certificate: same DN as its issuer, or SKI = its AKI key identifier */
  function candidateIndex(certs) {
    const bySki = new Map(), bySub = new Map();
    const add = (m, k, c) => { if (!k) return; const a = m.get(k) || []; a.push(c); m.set(k, a); };
    certs.forEach(c => { add(bySki, c.ski, c); add(bySub, X.normDn(c.subject), c); });
    return c => { const s = new Set([...((c.aki && bySki.get(c.aki)) || []), ...(bySub.get(X.normDn(c.issuer)) || [])]); s.delete(c); return [...s]; };
  }

  /* Verify the signature of every certificate against each possible issuer (async, WebCrypto) */
  A.verify = async function (certs) {
    const cands = candidateIndex(certs), jobs = [];
    for (const c of certs) {
      c.sigBy = new Map();
      if (!c.der) continue;
      for (const p of c.selfSigned ? [c] : cands(c)) if (p.der) jobs.push(X.verifySignature(c, p).then(r => c.sigBy.set(p, r)));
    }
    await Promise.all(jobs);
  };

  /* Evidence that p issued c: name chaining, key identifier, issuer serial (AKI), signature */
  A.evidence = function (c, p) {
    const ev = { dn: X.normDn(c.issuer) === X.normDn(p.subject) };
    ev.keyId = c.aki && p.ski ? (c.aki === p.ski ? 'match' : 'mismatch') : 'n/a';
    ev.serial = c.akiSerial && p.serialKey ? (X.serialKey(c.akiSerial) === p.serialKey && (!c.akiIssuer || X.normDn(c.akiIssuer) === X.normDn(p.issuer)) ? 'match' : 'mismatch') : 'n/a';
    const s = c.sigBy && c.sigBy.has(p) ? c.sigBy.get(p) : null;
    ev.sig = s === true ? 'valid' : s === false ? 'invalid' : 'n/a';
    ev.ok = ev.dn && (ev.sig === 'valid' || (ev.sig === 'n/a' && (ev.keyId === 'match' || (ev.keyId === 'n/a' && ev.serial !== 'mismatch'))));
    if (ev.ok && ev.serial === 'mismatch')
      ev.warn = `The AKI of "${c.cn}" names issuer certificate serial ${sn(c.akiSerial)}, but "${p.cn}" has serial ${sn(p.serial)} (same key, re-issued CA certificate). OpenSSL-based partners reject this (AKID issuer serial mismatch) — use the CA certificate with serial ${sn(c.akiSerial)}.`;
    ev.proof = ev.sig === 'valid' ? 'signature' : ev.keyId === 'match' ? 'key identifier' : ev.serial === 'match' ? 'issuer serial' : 'name only';
    ev.score = (ev.sig === 'valid' ? 8 : 0) + (ev.serial === 'match' ? 4 : 0) + (ev.keyId === 'match' ? 2 : 0) + (ev.dn ? 1 : 0);
    ev.why = !ev.dn ? 'issuer name differs'
      : ev.sig === 'invalid' ? `the signature of "${c.cn}" does not verify with the public key of this certificate`
        : ev.keyId === 'mismatch' ? `authority key identifier ${c.aki} ≠ subject key identifier ${p.ski}`
          : ev.serial === 'mismatch' ? `the issuer serial in the AKI is ${sn(c.akiSerial)}, this certificate has ${sn(p.serial)}` : '';
    return ev;
  };

  /* Link every certificate to its issuer within the loaded set (best evidence wins; same-name certificates that
   * provably did not sign it are kept in wrongIssuer) */
  A.link = function (certs) {
    const cands = candidateIndex(certs);
    certs.forEach(c => { c.children = []; c.parent = null; c.missingIssuer = false; c.wrongIssuer = []; c.altIssuers = []; c.linkEv = null; c.role = A.role(c); });
    for (const c of certs) {
      if (c.selfSigned) { c.selfSig = c.sigBy && c.sigBy.has(c) ? c.sigBy.get(c) : null; continue; }
      const scored = cands(c).map(p => ({ p, ev: A.evidence(c, p) })).filter(x => x.ev.dn || x.ev.keyId === 'match');
      const good = scored.filter(x => x.ev.ok).sort((a, b) => b.ev.score - a.ev.score || (b.p.notAfter || 0) - (a.p.notAfter || 0));
      c.wrongIssuer = scored.filter(x => !x.ev.ok).map(x => ({ cert: x.p, ev: x.ev }));
      if (!good.length) { c.missingIssuer = !!c.issuer; continue; }
      c.parent = good[0].p; c.linkEv = good[0].ev; c.altIssuers = good.slice(1).map(x => x.p);
      c.parent.children.push(c);
    }
  };
  A.path = function (c) {
    const out = [], seen = new Set();
    for (let x = c; x && !seen.has(x); x = x.parent) { seen.add(x); out.push(x); }
    return out;
  };

  /* What the issuer of c must look like (from the certificate itself) */
  A.required = c => (c.selfSigned ? { dn: c.subject, keyId: c.ski, serial: c.serial, self: true } : { dn: c.issuer, keyId: c.aki, serial: c.akiSerial });

  /* Would the certificate list of one PSE (trust store) accept the other loaded end-entity certificates?
   * Mirrors the check behind SSSLERR_CLIENT_CERT_UNTRUSTED (inbound) / SSSLERR_PEER_CERT_UNTRUSTED (outbound):
   * a certificate is trusted when it or one of its issuers is in the PSE and every certificate up to that point is valid.
   * Every link is checked down to the serial number / key: a PSE entry with the right name but another key or serial
   * (renewed CA, old certificate left in STRUST) is reported as such. */
  A.trustCheck = function (certs, store, ref) {
    const inStore = c => c.where.some(w => w.source === store);
    const storeCerts = certs.filter(inStore);
    const bad = list => list.filter(p => ['expired', 'notyet'].includes(X.status(p, ref).key));
    const say = list => list.map(p => `"${p.cn}" (serial ${sn(p.serial)}) is ${X.status(p, ref).label.toLowerCase()}`).join(', ');
    const out = [];
    for (const c of certs) {
      if (c.where.every(w => w.source === store)) continue;
      if (c.role !== 'End entity' && c.role !== 'Self-signed') continue;
      const path = A.path(c), top = path[path.length - 1];
      const steps = path.map((p, i) => ({ cert: p, inStore: inStore(p), ev: i < path.length - 1 ? p.linkEv : null }));
      const ai = path.findIndex(inStore);
      let r;
      if (ai >= 0) {
        const b = bad(path.slice(0, ai + 1));
        const inter = path.slice(1, ai).filter(p => !inStore(p));
        const links = path.slice(0, ai).map(p => p.linkEv).filter(Boolean);
        const proof = !links.length ? 'certificate itself in the PSE' : links.every(e => e.proof === 'signature') ? 'signatures verified' : 'name / key identifier only — signature not checked';
        const warns = links.filter(e => e.warn).map(e => e.warn);
        r = b.length
          ? { key: 'invalid', label: 'Not valid', text: `The chain reaches "${path[ai].cn}" (serial ${sn(path[ai].serial)}) in the PSE, but ${say(b)}.` }
          : { key: 'trusted', label: 'Trusted', proof,
            text: `Trusted via "${path[ai].cn}" (serial ${sn(path[ai].serial)}) in the PSE — ${proof}.` +
              (inter.length ? ` Intermediate ${inter.map(p => `"${p.cn}"`).join(', ')} is not in the PSE — the partner must send it in the handshake, or import it as well.` : '') +
              (warns.length ? ' ' + warns.join(' ') : '') };
      } else {
        const need = A.required(top);
        const look = storeCerts.filter(s => s !== top && X.normDn(s.subject) === X.normDn(need.dn));
        const reason = s => { const w = (top.wrongIssuer || []).find(x => x.cert === s); return w ? w.ev.why : need.self ? `different certificate (serial ${sn(s.serial)} instead of ${sn(need.serial)})` : 'it is not the issuer'; };
        const needTxt = `"${need.dn}"${need.keyId ? `, key identifier ${need.keyId}` : ''}${need.serial ? `, serial ${sn(need.serial)}` : ''}`;
        r = { key: 'untrusted', label: 'Not trusted', need: need.dn, required: need, lookalikes: look,
          text: (need.self
            ? `The chain ends at "${top.cn}", which is not in the PSE. Import exactly this CA certificate (${needTxt}) into the certificate list of the PSE in STRUST.`
            : `No certificate of the chain is in the PSE. Import the issuing CA ${needTxt} (plus its root and intermediates) into the certificate list of the PSE in STRUST.`) +
            (look.length ? ` The PSE does contain ${look.map(s => `"${s.cn}" serial ${sn(s.serial)} (valid to ${d10(s.notAfter)})`).join(', ')} with the same name, but ${look.map(reason).join('; ')} — typically a CA renewed with a new key, or an old CA certificate left in STRUST.` : '') +
            (bad(path).length ? ` Note: ${say(bad(path))}.` : '') };
      }
      out.push(Object.assign({ cert: c, path, steps }, r));
    }
    const order = { untrusted: 0, invalid: 1, trusted: 2 };
    return out.sort((a, b) => order[a.key] - order[b.key]);
  };

  /* Client certificate vs. the CA list a TLS server sends with its certificate request ("Accepted certificate authorities" in the
   * Cloud Connector TLS trace). A client only offers a certificate whose chain is issued by one of these CAs; otherwise it sends
   * none ("No client certificate available") and ICM cannot authenticate it — for principal propagation the backend then does not
   * trust the Cloud Connector as reverse proxy (icm/trusted_reverse_proxy_<n>) and ignores the short-lived user certificate.
   * One result per server + CA list; the SCC system certificate (sys_cert.*) is the one that matters when it is loaded. */
  A.clientCertCheck = function (certs, handshakes) {
    const groups = new Map();
    for (const h of handshakes || []) {
      if (!h.cas.length) continue;
      const k = h.peer + '|' + h.cas.map(X.normDn).join(';');
      let g = groups.get(k);
      if (!g) groups.set(k, (g = { peer: h.peer || '(server not named in the trace)', cas: h.cas, n: 0, none: 0, sent: 0, first: h.ts, last: h.ts, refs: [] }));
      g.n++; g.last = h.ts;
      if (h.client === 'none') g.none++; else if (h.client === 'sent') g.sent++;
      if (g.refs.length < 4) g.refs.push(`${base(h.source)} line ${h.line}`);
    }
    const clients = certs.filter(c => c.der && c.ca !== true && !c.children.length && (c.role === 'End entity' || c.selfSigned) && !/^SCC (CA|UI)/.test(A.sccRole(c)) &&
      (!(c.eku || []).length || c.eku.includes('clientAuth') || c.eku.includes('anyExtendedKeyUsage')));
    return [...groups.values()].map(g => {
      const acc = new Set(g.cas.map(X.normDn));
      const port = (/:(\d+)$/.exec(g.peer) || [])[1] || '<port>', host = g.peer.replace(/:\d+$/, '');
      const cands = clients.map(c => {
        const hit = A.path(c).find(p => acc.has(X.normDn(p.issuer)));
        return { cert: c, ok: !!hit, via: hit ? hit.issuer : '', role: A.sccRole(c) };
      }).sort((a, b) => (!!b.role - !!a.role) || (b.ok - a.ok));
      const sys = cands.filter(x => x.role === 'SCC system certificate');
      const focus = sys.length ? sys : cands;
      const r = { peer: g.peer, cas: g.cas, n: g.n, none: g.none, sent: g.sent, first: g.first, last: g.last, refs: g.refs, cands, fix: [] };
      const sent = g.none ? ` The client sent no certificate in ${g.none} of ${g.n} handshake${g.n === 1 ? '' : 's'} ("No client certificate available", ${g.first}${g.last !== g.first ? ' – ' + g.last : ''}).` : g.sent ? ` A client certificate was sent in ${g.sent} of ${g.n} handshakes.` : '';
      const verify = dn => `Verify: Cloud Connector → Cloud To On-Premise → Check availability of internal host for ${g.peer} (TLS trace on) → load the new scc_core.trc here: the CA list must contain "${dn}" and "No client certificate available" must be gone. Then repeat the business call — no more redirect to the IdP.`;
      const proxyParam = c => `icm/trusted_reverse_proxy_<n> = SUBJECT="${c.subject}", ISSUER="${c.issuer}"`;
      if (!focus.length) {
        return Object.assign(r, { key: 'nocert', label: 'Client certificate not loaded',
          text: `${g.peer} requests a client certificate issued by one of the listed CAs.${sent} Load the client certificate to check it — for the Cloud Connector: Configuration → On Premise → System Certificate → download (sys_cert.der).` });
      }
      const ok = focus.filter(x => x.ok), best = focus[0].cert;
      const label = sys.length ? 'SCC system certificate' : 'client certificate';
      if (!ok.length) {
        const alt = cands.filter(x => x.ok && !focus.includes(x));
        const self = best.selfSigned, need = self ? best.subject : best.issuer;
        r.fix.push(`STRUST on ${host} → the SSL server PSE of port ${port} (SSL server Standard, unless the port has its own SSL server identity — see SMICM → Goto → Services) → Import Certificate: ${self
          ? `exactly this certificate${best.where.length ? ' (' + base(best.where[0].source) + ')' : ''}, subject "${best.subject}", serial ${sn(best.serial)}`
          : `its issuing CA "${best.issuer}"${best.aki ? ', key ID ' + best.aki : ''}${best.akiSerial ? ', serial ' + sn(best.akiSerial) : ''} (plus the root CA)`} → Add to Certificate List → Save. Instances with an instance-specific PSE: repeat on each of them.`);
        r.fix.push('SMICM → Administration → ICM → Exit Soft → Global, so that ICM sends the new CA list.');
        r.fix.push(`Profile (all instances): ${proxyParam(best)} — exactly as in the certificate${self ? ' (self-signed: SUBJECT = ISSUER)' : ''}; ICM restart after a profile change. Check the active value in SMICM → Goto → Parameters → Display.`);
        if (alt.length) r.fix.push(`Alternative without changing the PSE: make "${alt[0].cert.subject}" (${base(alt[0].cert.where[0].source)}, already accepted via "${alt[0].via}") the ${sys.length ? 'Cloud Connector system certificate (Configuration → On Premise → System Certificate → Import, PKCS#12 with private key)' : 'client certificate'} and set ${proxyParam(alt[0].cert)}.`);
        r.fix.push(verify(need));
        return Object.assign(r, { key: 'rejected', label: 'Not accepted', need,
          text: `${g.peer} only accepts client certificates issued by the listed CAs. The ${label} "${best.subject}" (issuer "${best.issuer}", serial ${sn(best.serial)}${self ? ', self-signed' : ''}) is not among them${self ? ' — a self-signed certificate is only accepted when exactly this certificate is in the PSE certificate list' : ''}.${sent} Consequence for principal propagation: the backend cannot recognise the Cloud Connector as trusted reverse proxy, ignores the short-lived user certificate and treats the request as anonymous (redirect to the SAML IdP / 401).` +
            (alt.length ? ` "${alt[0].cert.cn}" (${base(alt[0].cert.where[0].source)}) would be accepted via "${alt[0].via}".` : '') });
      }
      if (g.none && !g.sent) {
        r.fix.push(`Check that the loaded file is the active system certificate (Configuration → On Premise → System Certificate: compare subject and serial ${sn(ok[0].cert.serial)}).`);
        r.fix.push(verify(ok[0].via));
        return Object.assign(r, { key: 'notsent', label: 'Accepted, but not sent',
          text: `The ${label} "${ok[0].cert.subject}" is issued by "${ok[0].via}", which is in the CA list.${sent} Either another certificate was the active system certificate at that time, or the trace is older than the change — repeat the check.` });
      }
      r.fix.push(`Next check on the backend: ${proxyParam(ok[0].cert)} must be active, and the SMICM trace (level 2) of the instance behind ${g.peer} must show the intermediary as trusted; then CERTRULE maps the forwarded user certificate.`);
      return Object.assign(r, { key: 'ok', label: 'Accepted',
        text: `The ${label} "${ok[0].cert.subject}" is accepted via "${ok[0].via}".${sent}` });
    });
  };

  /* Serial number lookup (any notation) → certificates with this serial, and certificates issued by a CA certificate with it */
  A.findSerial = function (certs, q, issuer) {
    const keys = X.serialKeys(q), iss = X.normDn(issuer);
    if (!keys.length) return { keys, hits: [], issuedBy: [] };
    const issOk = c => !iss || X.normDn(c.issuer).includes(iss) || X.normDn(c.subject).includes(iss);
    return {
      keys,
      hits: certs.filter(c => keys.includes(c.serialKey) && issOk(c)),
      issuedBy: certs.filter(c => c.akiSerial && keys.includes(X.serialKey(c.akiSerial)))
    };
  };

  /* STRUSTSSO2 access control list (logon tickets / assertion tickets): the accepting system trusts a ticket when
   * system ID + client + certificate subject + issuer + serial number of the signing certificate are in the ACL.
   * Input: rows copied from STRUSTSSO2 / SE16 TWPSSO2ACL (tab, "|" or ";" separated). */
  A.parseAcl = function (text) {
    const rows = [];
    for (const line of String(text || '').split(/\r?\n/)) {
      const cells = line.split(/\t|\||;/).map(s => s.trim().replace(/^"(.*)"$/, '$1')).filter(Boolean);
      const dns = cells.filter(s => /(?:^|,\s*)(?:CN|OU|O|C)\s*=/i.test(s));
      if (!dns.length) continue;
      const rest = cells.filter(s => !dns.includes(s));
      const sid = rest.find(s => /^[A-Z][A-Z0-9]{2}$/.test(s)) || '';
      const client = rest.find(s => /^\d{3}$/.test(s)) || '';
      const serial = rest.filter(s => s !== sid && s !== client && X.serialKey(s)).pop() || '';
      rows.push({ sid, client, subject: dns[0], issuer: dns[1] || '', serial, raw: line.trim() });
    }
    return rows;
  };
  A.aclCheck = function (certs, rows, ref) {
    return rows.map(r => {
      const keys = X.serialKeys(r.serial);
      const issOk = c => !r.issuer || X.normDn(c.issuer) === X.normDn(r.issuer);
      const hit = keys.length ? certs.find(c => keys.includes(c.serialKey) && issOk(c)) : null;
      const same = certs.filter(c => X.normDn(c.subject) === X.normDn(r.subject));
      const who = `${r.sid || 'the issuing system'}${r.client ? '/' + r.client : ''}`;
      if (hit) {
        const st = X.status(hit, ref);
        const subjOk = X.normDn(hit.subject) === X.normDn(r.subject);
        return { row: r, cert: hit, key: st.key === 'expired' || st.key === 'notyet' ? 'invalid' : subjOk ? 'ok' : 'subject',
          text: !subjOk ? `Serial matches "${hit.subject}", but the ACL subject is "${r.subject}".`
            : st.key === 'expired' || st.key === 'notyet' ? `ACL entry matches the certificate, but it is ${st.label.toLowerCase()} — tickets signed with it are rejected. Renew the System PSE of ${who} and re-import its certificate in STRUSTSSO2.`
              : `ACL entry matches the loaded certificate (issuer + serial ${sn(hit.serial)}).` };
      }
      if (same.length) {
        const cur = same.slice().sort((a, b) => (b.notAfter || 0) - (a.notAfter || 0))[0];
        return { row: r, cert: cur, key: 'serial',
          text: `Serial mismatch: the ACL expects serial ${sn(r.serial) || '-'}, the loaded certificate "${cur.cn}" has serial ${sn(cur.serial)} (valid to ${d10(cur.notAfter)}). The System PSE of ${who} was probably renewed — tickets fail with "certificate not in ACL". In STRUSTSSO2 of the accepting system: delete the old entry, Import Certificate (new SAPSYS certificate of ${who}) → Add to Certificate List + Add to ACL → Save.` };
      }
      return { row: r, cert: null, key: 'missing', text: `No loaded certificate with this subject. Load the System PSE certificate of ${who} (STRUST → System PSE → own certificate → Export) to check the serial.` };
    });
  };

  const STRUST_RENEW = [
    'Own certificate (SSL server / SSL client / System PSE): STRUST → select the PSE → Create Certificate Request → let the CA sign it → Import Certificate Response (including the CA chain) → Save.',
    'Trusted CA in the certificate list: STRUST → Import Certificate → Add to Certificate List → Save; remove the old one after all partners have switched.',
    'If ICM still uses the old certificate: SMICM → Administration → ICM → Exit Soft → Global. Web Dispatcher / other hosts: update the PSE with sapgenpse or the web administration.'
  ];

  A.analyze = function (certs, opts) {
    const ref = opts.ref, F = [];
    const add = (sev, id, title, why, fix, list) => { if (list.length) F.push({ sev, id, title, why, fix, certs: list }); };
    const ee = certs.filter(c => c.role === 'End entity' || c.role === 'Self-signed');
    const st = c => X.status(c, ref).key;

    add('critical', 'expired', 'Expired certificates',
      'Expired certificates make SSL handshakes fail (e.g. SSSLERR_PEER_CERT_EXPIRED, ICM_HTTP_SSL_ERROR in SM59) and break SNC or signature checks that rely on them.',
      STRUST_RENEW, certs.filter(c => st(c) === 'expired'));
    add('high', 'expiring30', 'Certificates expiring within 30 days', 'Renew now — CA signing, import and distribution to partners usually take several days.',
      STRUST_RENEW, certs.filter(c => st(c) === 'expiring'));
    add('medium', 'expiring90', 'Certificates expiring within 90 days', 'Plan the renewal (certificate request, CA signing, partner communication).',
      STRUST_RENEW, certs.filter(c => st(c) === 'soon'));
    add('high', 'notyet', 'Certificates not yet valid', 'The validity starts in the future (wrong system clock or a certificate imported too early).',
      ['Check the system time of the server and the "valid from" date of the certificate.'], certs.filter(c => st(c) === 'notyet'));

    add('high', 'missing-issuer', 'Issuer certificate not in the loaded set',
      'The CA that signed these certificates is not among the loaded certificates. If the files represent a complete PSE, partners (or SAP itself) cannot build the chain → SSSLERR_PEER_CERT_UNTRUSTED / "unable to get issuer certificate".',
      ['Import the missing root / intermediate CA certificate into the PSE certificate list in STRUST (SSL client PSE for outbound HTTPS, SSL server PSE for partners logging on with client certificates).',
        'For the own certificate: import the CA response with the full chain, so ICM sends the intermediates to clients.',
        'The issuer names are listed in the Chains view.'],
      certs.filter(c => c.missingIssuer && !c.wrongIssuer.length && !(c.observed && !c.der)));   // trace-only references: see "observed-unmatched"

    add('high', 'wrong-issuer', 'Issuer name matches, but the key / serial does not',
      'A certificate with the issuer\'s name is loaded, but it did not sign these certificates (signature does not verify, authority key identifier ≠ subject key identifier, or issuer serial in the AKI differs). Typical after a CA was renewed with a new key while STRUST still holds the old CA certificate → SSSLERR_PEER_CERT_UNTRUSTED / SSSLERR_CLIENT_CERT_UNTRUSTED although "the CA is imported". Details per certificate: open it → Issuer verification.',
      ['Get the CA certificate whose subject key identifier equals the AKI of the certificate (and, if the AKI names one, with exactly that serial number) — e.g. from the CA Issuers URL or the CA team.',
        'STRUST → PSE → Import Certificate → Add to Certificate List → Save; remove the outdated CA certificate once no partner uses it. SMICM → Exit Soft → Global.'],
      certs.filter(c => c.missingIssuer && c.wrongIssuer.length));
    add('critical', 'serial-conflict', 'Different certificates with the same issuer and serial number',
      'A CA must never issue two certificates with the same serial number. Either the CA is misconfigured, or one of the certificates is forged / manipulated. SAP and partners identify certificates by issuer + serial (CRL, logon ticket ACL, X.509 user mapping) — this leads to unpredictable results.',
      ['Compare the SHA-256 fingerprints of both certificates and clarify with the CA team which one is genuine; remove the other one from all PSEs.'],
      certs.filter(c => c.serialConflict));
    add('high', 'self-sig-invalid', 'Self-signed certificate whose own signature does not verify',
      'The certificate is corrupt or was modified after signing. It cannot serve as a trust anchor.',
      ['Export the certificate again from the original source (CA, STRUST of the partner system) and re-import it.'],
      certs.filter(c => c.selfSigned && c.selfSig === false));
    add('low', 'akid-serial', 'AKI names another serial of the issuing CA certificate',
      'The issuer is the right key (signature verified), but the authority key identifier of the certificate references a different serial number of the CA certificate (CA certificate re-issued with the same key). SAP CommonCryptoLib accepts this; OpenSSL-based partners reject the chain ("AKID issuer serial mismatch").',
      ['Use / distribute the CA certificate with the serial number named in the AKI, or have the certificate re-issued.'],
      certs.filter(c => c.linkEv && c.linkEv.warn));
    add('medium', 'observed-unmatched', 'Certificates seen in traces that are not among the loaded files',
      'The trace only shows subject, issuer and serial number of these certificates. Without the certificate itself (or its CA) the chain and the trust anchor cannot be checked down to the serial number.',
      ['Load the certificate (client team, SCC, Web Dispatcher, browser export) and the PSE that should trust it, then use the Trust check. The serial from the trace identifies the exact certificate.'],
      certs.filter(c => c.observed && !c.der));
    add('info', 'observed-matched', 'Certificates from traces matched by issuer + serial number',
      'These handshake certificates from the trace are the same certificates (issuer + serial) as in the loaded PSE / certificate files.',
      [], certs.filter(c => c.observed && c.der));

    // TLS handshakes with a client certificate request (Cloud Connector TLS trace)
    const cc = A.clientCertCheck(certs, opts.handshakes);
    const ccFinding = (sev, id, title, why, list) => {
      if (!list.length) return;
      F.push({ sev, id, title, why: why + ' ' + list.map(r => r.text).join(' '), fix: list[0].fix, certs: [...new Set([].concat(...list.map(r => r.cands.slice(0, 3).map(x => x.cert))))] });
    };
    ccFinding('high', 'client-ca-list', 'Client certificate not in the CA list the server accepts',
      'In the TLS handshake the server asked for a client certificate and named the CAs it accepts ("Accepted certificate authorities"). See the card "Client certificate vs. CA list of the server" for each server.',
      cc.filter(r => r.key === 'rejected'));
    ccFinding('medium', 'client-cert-none', 'Server asked for a client certificate, none was sent',
      'The trace shows a certificate request without a client certificate in the answer ("No client certificate available").',
      cc.filter(r => (r.key === 'nocert' || r.key === 'notsent') && r.none));

    add('high', 'weak-sig', 'Weak signature algorithm (MD5 / SHA-1)',
      'Certificates signed with MD5 or SHA-1 are rejected by current TLS clients and CommonCryptoLib security settings. (Self-signed root CAs are not affected — their own signature is not checked.)',
      ['Request a new certificate signed with SHA-256 (STRUST → Create Certificate Request; the CA decides the signature algorithm).'],
      certs.filter(c => !c.selfSigned && /md5|sha1|SHA1/i.test(c.sigAlg || '')));
    add('high', 'weak-key', 'Weak key (RSA < 2048 bit, EC < 256 bit, DSA)',
      'Short keys are not accepted by modern partners and do not meet current security requirements.',
      ['Create a new key pair with RSA 2048/4096 or ECDSA P-256/P-384: STRUST → Replace / Create PSE with the new algorithm, then request and import a new certificate.'],
      certs.filter(c => (c.keyAlg === 'RSA' && c.keyBits && c.keyBits < 2048) || (c.keyAlg === 'EC' && c.keyBits && c.keyBits < 256) || c.keyAlg === 'DSA'));

    add('high', 'ca-flag', 'Issuing certificate without CA flag',
      'These certificates issued other loaded certificates but are not marked as CA (BasicConstraints CA=false or missing). Chain validation will fail.',
      ['Use the real CA certificate as issuer; ask the CA team to check the issued chain.'],
      certs.filter(c => c.der && c.children.length && c.ca !== true && !c.selfSigned));

    add('medium', 'no-san', 'Server certificate without Subject Alternative Name',
      'Browsers and modern clients ignore the CN and only check the SAN. Without SAN the host name check fails (SSSLERR_SERVER_CERT_MISMATCH / NET::ERR_CERT_COMMON_NAME_INVALID).',
      ['Create a new certificate request in STRUST with all DNS names (host, FQDN, virtual host / Web Dispatcher / load balancer names) as Subject Alternative Names.'],
      ee.filter(c => c.der && !(c.san || []).length && !(c.sanIp || []).length && (!c.eku.length || c.eku.includes('serverAuth')) && A.sccRole(c) !== 'SCC system certificate'));

    add('medium', 'selfsigned', 'Self-signed end-entity certificates',
      'Partners only trust these certificates after importing them explicitly. Typical for freshly created PSEs that were never signed by a CA.',
      ['For productive SSL server PSEs create a certificate request in STRUST and have it signed by your (or a public) CA.'],
      certs.filter(c => c.role === 'Self-signed'));

    add('low', 'eku', 'End-entity certificates not usable as SSL server certificate',
      'The Extended Key Usage does not contain serverAuth — fine for client / signing certificates, but they cannot be used in an SSL server PSE.',
      ['Check the certificate template used by the CA if this certificate should serve HTTPS.'],
      ee.filter(c => c.der && c.eku.length && !c.eku.includes('serverAuth') && !c.eku.includes('anyExtendedKeyUsage')));

    add('low', 'long', 'End-entity certificates valid longer than 398 days',
      'Public CAs and browsers limit TLS server certificates to 398 days. For certificates of an internal CA this is only informational.',
      [], ee.filter(c => !c.selfSigned && c.notBefore != null && c.notAfter - c.notBefore > 398 * DAY && (!c.eku || !c.eku.length || c.eku.includes('serverAuth'))));

    // renewed certificates (same subject, several validity periods)
    const bySub = new Map();
    certs.forEach(c => { const k = X.normDn(c.subject); bySub.set(k, (bySub.get(k) || []).concat(c)); });
    add('info', 'renewed', 'Several certificates with the same subject',
      'Usually an old and a renewed certificate. Keep the old one only until all partners use the new one.',
      ['Remove outdated certificates from the certificate list in STRUST once they are no longer needed.'],
      [].concat(...[...bySub.values()].filter(a => a.length > 1)));

    if (opts.host) {
      const match = certs.filter(c => (c.role === 'End entity' || c.role === 'Self-signed') && X.matchesHost(c, opts.host));
      if (!match.length) F.push({ sev: 'high', id: 'host', title: `No end-entity certificate matches "${opts.host}"`, why: 'None of the loaded server certificates contains this host name in its SAN (or CN without SAN). Clients will report a host name mismatch.', fix: ['Request a certificate that includes this DNS name as Subject Alternative Name, or make clients use a name that is in the certificate (SM59 target host / SNI).'], certs: [] });
      else F.push({ sev: 'info', id: 'host', title: `Certificates matching "${opts.host}"`, why: 'These certificates are valid for the host name (SAN / wildcard).', fix: [], certs: match });
    }
    return F.sort((a, b) => TS.SEV_RANK[a.sev] - TS.SEV_RANK[b.sev]);
  };
})(window.TS);
