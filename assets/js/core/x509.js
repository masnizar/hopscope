/* Certificates (X.509) for SAP analysis
 * - DER / PEM certificates (.cer, .crt, .der, .pem), PKCS#7 bundles (.p7b) and SAP PSE files (.pse):
 *   binary containers are scanned for embedded DER certificates (works when they are stored unencrypted;
 *   password-protected PKCS#12 / encrypted parts cannot be read)
 * - Text: STRUST certificate details copied from SAP GUI, "sapgenpse maintain_pk -l" / "get_my_name -v" output,
 *   openssl -text output, and certificate references in SAP kernel traces (dev_icm / dev_webdisp: "Subject DN =",
 *   "Issuer DN =", "SerialNum =", CCL[SSL] error blocks) → certificates with observed[] = where they were seen
 * Certificate object: { subject, issuer, cn, serial, serialKey, notBefore, notAfter (epoch ms UTC), san[], aki, akiSerial, ... , der? }
 */
(function (TS) {
  'use strict';
  const X = TS.x509 = {};

  /* ---------- ASN.1 DER (strict, bounds-checked) ---------- */
  function tlv(b, p, limit) {
    if (p + 2 > limit) throw new Error('asn1: truncated');
    const tag = b[p];
    let len = b[p + 1], hl = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n < 1 || n > 4 || p + 2 + n > limit) throw new Error('asn1: bad length');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + b[p + 2 + i];
      hl = 2 + n;
    }
    const end = p + hl + len;
    if (end > limit) throw new Error('asn1: length exceeds data');
    return { tag, pos: p, start: p + hl, end };
  }
  function children(b, n) {
    const out = [];
    for (let p = n.start; p < n.end;) { const c = tlv(b, p, n.end); out.push(c); p = c.end; }
    return out;
  }
  const expect = (n, tag) => { if (!n || n.tag !== tag) throw new Error('asn1: unexpected tag'); return n; };
  const hex = (u8, sep) => [...u8].map(x => x.toString(16).padStart(2, '0')).join(sep == null ? ':' : sep).toUpperCase();
  function oid(b, n) {
    const v = b.subarray(n.start, n.end);
    const parts = [Math.floor(v[0] / 40), v[0] % 40];
    let x = 0;
    for (let i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { parts.push(x); x = 0; } }
    return parts.join('.');
  }
  function str(b, n) {
    const v = b.subarray(n.start, n.end);
    if (n.tag === 0x1e) { let s = ''; for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]); return s; }
    return new TextDecoder(n.tag === 0x0c ? 'utf-8' : 'latin1').decode(v);
  }
  function time(b, n) {
    const s = new TextDecoder().decode(b.subarray(n.start, n.end));
    const m = n.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s) : n.tag === 0x18 ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z?$/.exec(s) : null;
    if (!m) throw new Error('asn1: bad time');
    let y = +m[1]; if (n.tag === 0x17) y += y < 50 ? 2000 : 1900;
    return Date.UTC(y, m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  }
  // collect all nodes with a given tag below n
  function findTags(b, n, tag, out) {
    out = out || [];
    let kids;
    try { kids = children(b, n); } catch (e) { return out; }
    for (const c of kids) {
      if (c.tag === tag) out.push(c);
      else if (c.tag & 0x20) findTags(b, c, tag, out);   // constructed
    }
    return out;
  }

  const NAME_OID = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '1.2.840.113549.1.9.1': 'E', '2.5.4.5': 'SERIALNUMBER', '0.9.2342.19200300.100.1.25': 'DC', '2.5.4.9': 'STREET', '2.5.4.17': 'POSTALCODE' };
  function name(b, n) {
    const parts = [];
    for (const set of children(b, expect(n, 0x30))) for (const atv of children(b, set)) {
      const [o, v] = children(b, atv);
      parts.push(`${NAME_OID[oid(b, o)] || oid(b, o)}=${str(b, v)}`);
    }
    return parts.reverse().join(', ');
  }

  X.SIG_ALG = {
    '1.2.840.113549.1.1.4': 'md5WithRSA', '1.2.840.113549.1.1.5': 'sha1WithRSA', '1.2.840.113549.1.1.11': 'sha256WithRSA',
    '1.2.840.113549.1.1.12': 'sha384WithRSA', '1.2.840.113549.1.1.13': 'sha512WithRSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512', '1.2.840.10040.4.3': 'dsa-with-SHA1', '2.16.840.1.101.3.4.3.2': 'dsa-with-SHA256',
    '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448'
  };
  const KEY_ALG = { '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.2.840.10040.4.1': 'DSA', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448', '1.2.840.113549.1.1.10': 'RSA-PSS' };
  const CURVE = { '1.2.840.10045.3.1.7': ['P-256', 256], '1.3.132.0.34': ['P-384', 384], '1.3.132.0.35': ['P-521', 521], '1.3.132.0.10': ['secp256k1', 256], '1.3.36.3.3.2.8.1.1.7': ['brainpoolP256r1', 256], '1.3.36.3.3.2.8.1.1.11': ['brainpoolP384r1', 384] };
  const EKU = { '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth', '1.3.6.1.5.5.7.3.3': 'codeSigning', '1.3.6.1.5.5.7.3.4': 'emailProtection', '1.3.6.1.5.5.7.3.8': 'timeStamping', '1.3.6.1.5.5.7.3.9': 'OCSPSigning', '2.5.29.37.0': 'anyExtendedKeyUsage' };
  const KU = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];

  function spki(b, n, c) {
    const [alg, key] = children(b, expect(n, 0x30));
    const ap = children(b, alg);
    const ao = oid(b, ap[0]);
    c.keyAlg = KEY_ALG[ao] || ao;
    if (c.keyAlg === 'RSA' || c.keyAlg === 'RSA-PSS') {
      try {
        const seq = tlv(b, key.start + 1, key.end);           // BIT STRING: skip "unused bits" byte
        const mod = children(b, seq)[0];
        let i = mod.start; while (i < mod.end && b[i] === 0) i++;
        c.keyBits = (mod.end - i) * 8 - Math.clz32(b[i]) + 24;
      } catch (e) { /* ignore */ }
    } else if (c.keyAlg === 'EC' && ap[1] && ap[1].tag === 0x06) {
      const cv = CURVE[oid(b, ap[1])];
      c.keyCurve = cv ? cv[0] : oid(b, ap[1]); c.keyBits = cv ? cv[1] : null;
    } else if (c.keyAlg === 'Ed25519') c.keyBits = 256;
  }

  function extensions(b, n, c) {
    for (const e of children(b, children(b, n)[0])) {
      const parts = children(b, e);
      const id = oid(b, parts[0]);
      const critical = parts.length > 2 && parts[1].tag === 0x01 && b[parts[1].start] !== 0;
      const os = parts[parts.length - 1];
      if (critical) c.critical.push(id);
      let v;
      try { v = tlv(b, os.start, os.end); } catch (err) { continue; }
      switch (id) {
        case '2.5.29.17':   // subjectAltName
          for (const g of children(b, v)) {
            if (g.tag === 0x82) c.san.push(new TextDecoder().decode(b.subarray(g.start, g.end)));
            else if (g.tag === 0x87) { const ip = b.subarray(g.start, g.end); c.sanIp.push(ip.length === 4 ? [...ip].join('.') : hex(ip, '').replace(/(.{4})(?!$)/g, '$1:').toLowerCase()); }
            else if (g.tag === 0x81) c.emails.push(new TextDecoder().decode(b.subarray(g.start, g.end)));
          }
          break;
        case '2.5.29.15': { // keyUsage (BIT STRING)
          const bytes = b.subarray(v.start + 1, v.end);
          KU.forEach((k, i) => { if (bytes[i >> 3] & (0x80 >> (i & 7))) c.ku.push(k); });
          break;
        }
        case '2.5.29.37':   // extKeyUsage
          for (const o of children(b, v)) { const x = oid(b, o); c.eku.push(EKU[x] || x); }
          break;
        case '2.5.29.19': { // basicConstraints
          const k = children(b, v);
          c.ca = !!(k[0] && k[0].tag === 0x01 && b[k[0].start] !== 0);
          const pl = k.find(x => x.tag === 0x02);
          if (pl) c.pathLen = b[pl.start];
          break;
        }
        case '2.5.29.14': c.ski = hex(b.subarray(v.start, v.end)); break;
        case '2.5.29.35':   // authorityKeyIdentifier: [0] keyIdentifier, [1] authorityCertIssuer, [2] authorityCertSerialNumber
          for (const k of children(b, v)) {
            if (k.tag === 0x80) c.aki = hex(b.subarray(k.start, k.end));
            else if (k.tag === 0x82) c.akiSerial = hex(b.subarray(k.start, k.end));
            else if (k.tag === 0xa1) { const dn = children(b, k).find(g => g.tag === 0xa4); if (dn) c.akiIssuer = name(b, children(b, dn)[0]); }
          }
          break;
        case '2.5.29.31': findTags(b, v, 0x86).forEach(u => c.crl.push(new TextDecoder().decode(b.subarray(u.start, u.end)))); break;
        case '1.3.6.1.5.5.7.1.1':
          for (const ad of children(b, v)) {
            const [m, loc] = children(b, ad);
            if (loc && loc.tag === 0x86) (oid(b, m) === '1.3.6.1.5.5.7.48.1' ? c.ocsp : c.caIssuers).push(new TextDecoder().decode(b.subarray(loc.start, loc.end)));
          }
          break;
      }
    }
  }

  X.parseDer = function (b) {
    const cert = expect(tlv(b, 0, b.length), 0x30);
    const top = children(b, cert);
    const tbs = expect(top[0], 0x30);
    if (!top[1] || top[1].tag !== 0x30 || !top[2] || top[2].tag !== 0x03) throw new Error('not a certificate');
    const f = children(b, tbs);
    let i = 0, version = 1;
    if (f[0].tag === 0xa0) { version = b[children(b, f[0])[0].start] + 1; i++; }
    const serialN = expect(f[i++], 0x02);
    const sigN = expect(f[i++], 0x30);
    const issuer = name(b, f[i++]);
    const val = children(b, expect(f[i++], 0x30));
    if (val.length !== 2) throw new Error('bad validity');
    const subject = name(b, f[i++]);
    const der = b.slice(0, cert.end);
    const outerAlg = children(b, top[1]);
    const c = {
      version, serial: hex(b.subarray(serialN.start, serialN.end)), subject, issuer,
      notBefore: time(b, val[0]), notAfter: time(b, val[1]),
      sigAlg: (s => X.SIG_ALG[s] || s)(oid(b, children(b, sigN)[0])),
      keyAlg: '', keyBits: null, keyCurve: '', san: [], sanIp: [], emails: [], ku: [], eku: [], ca: null, pathLen: null,
      ski: '', aki: '', akiIssuer: '', akiSerial: '', crl: [], ocsp: [], caIssuers: [], critical: [],
      der,
      // raw parts for signature verification (views into der)
      tbs: der.subarray(top[0].pos, top[0].end), sigOid: oid(b, outerAlg[0]),
      sigParams: outerAlg[1] ? der.subarray(outerAlg[1].pos, outerAlg[1].end) : null,
      sigValue: der.subarray(top[2].start + 1, top[2].end), spki: der.subarray(f[i].pos, f[i].end)
    };
    spki(b, f[i++], c);
    const ext = f.find(x => x.tag === 0xa3);
    if (ext) extensions(b, ext, c);
    return c;
  };

  /* Scan any binary (PSE, PKCS#7, PKCS#12 with clear-text bags, …) for embedded DER certificates */
  X.carve = function (u8) {
    const out = [], seen = new Set();
    for (let p = 0; p + 8 < u8.length; p++) {
      if (u8[p] !== 0x30 || u8[p + 1] < 0x81 || u8[p + 1] > 0x83) continue;
      const hl = u8[p + 1] - 0x7e;                                    // 0x81 → 3, 0x82 → 4, 0x83 → 5 header bytes
      const len = hl === 3 ? u8[p + 2] : hl === 4 ? (u8[p + 2] << 8) | u8[p + 3] : (u8[p + 2] << 16) | (u8[p + 3] << 8) | u8[p + 4];
      if (len < 120 || p + hl + len > u8.length) continue;
      if (u8[p + hl] !== 0x30) continue;
      try {
        const c = X.parseDer(u8.subarray(p, p + hl + len));
        const key = c.issuer + '|' + c.serial;
        if (!seen.has(key)) { seen.add(key); out.push(c); }
        p += hl + len - 1;
      } catch (e) { /* not a certificate at this offset */ }
    }
    return out;
  };

  const b64 = s => { const bin = atob(s.replace(/[^A-Za-z0-9+/=]/g, '')); const u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i); return u8; };
  X.toPem = function (der) {
    let s = ''; for (let i = 0; i < der.length; i += 0x8000) s += String.fromCharCode.apply(null, der.subarray(i, i + 0x8000));
    return '-----BEGIN CERTIFICATE-----\n' + btoa(s).replace(/.{64}/g, '$&\n').replace(/\n$/, '') + '\n-----END CERTIFICATE-----\n';
  };

  /* ---------- Text (STRUST copy / sapgenpse output) ---------- */
  const MONTHS = 'jan feb mar apr may jun jul aug sep oct nov dec'.split(' ');
  function textDate(s) {
    let m;
    // sapgenpse "(311110000000Z)", CCL / ICM trace "Not after  : 260801142311Z" (UTCTime / GeneralizedTime)
    if ((m = /\((\d{12}|\d{14})Z\)/.exec(s)) || (m = /(?:^|[\s:=])(\d{12}|\d{14})Z\b/.exec(s))) {
      const v = m[1], y = v.length === 12 ? 2000 + +v.slice(0, 2) - (+v.slice(0, 2) >= 50 ? 100 : 0) : +v.slice(0, 4), r = v.slice(v.length - 10);
      return Date.UTC(y, r.slice(0, 2) - 1, +r.slice(2, 4), +r.slice(4, 6), +r.slice(6, 8), +r.slice(8, 10));
    }
    if ((m = /(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\s+[A-Z]{2,5})?\s+(\d{4})/.exec(s))) {   // also Java "Fri Oct 16 06:23:01 UTC 2026"
      const mo = MONTHS.indexOf(m[2].toLowerCase());
      if (mo >= 0) return Date.UTC(+m[7], mo, +m[3], +m[4], +m[5], +m[6]);
    }
    if ((m = /\b(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/.exec(s))) {   // openssl: "Jan 10 12:00:00 2025 GMT"
      const mo = MONTHS.indexOf(m[1].toLowerCase());
      if (mo >= 0) return Date.UTC(+m[6], mo, +m[2], +m[3], +m[4], +m[5]);
    }
    if ((m = /(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})(?:\s+(\d{1,2}:\d{2}(?::\d{2})?))?/.exec(s)) && TS.tables) return TS.tables.parseDateTime(m[1], m[2] || '', 'auto');
    return null;
  }
  const PSE_LINE = /^\s*(SSL (?:client|server) [\w ()-]+|System PSE|SNC SAPCryptolib|SNC \(SAPCryptolib\)|WS Security [\w ]+|SMIME [\w ]+|(?:PSE )?File\s*:?\s*\S+\.pse|PSE\s*:?\s*\S+)\s*$/i;
  // Cloud Connector trace line "2026-11-02 03:29:00,274 +0000#DEBUG#logger#thread#conn id#message" → [time stamp, thread]
  const SCC_LINE = /^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?\s*(?:[+-]\d{2}:?\d{2}|Z)?)#[^#]*#[^#]*#([^#]*)#[^#]*#/;

  /* ---------- TLS handshakes of the Cloud Connector as client (backend connections) ----------
   * From the TLS trace (ssl_debug, logger com.sap.scc.rt) and the endpoint check ("SCCEndpointValidator"):
   * peer, the CA list the server accepts for client certificates ("Accepted certificate authorities") and whether SCC sent one.
   * Input: records { ts, thread, msg, line } (one per trace line) → [{ peer, cas[], requested, client: 'sent'|'none'|null, ts, thread, line, source }] */
  X.parseHandshakes = function (recs, source) {
    const out = [], byId = new Map(), byThread = new Map();
    let list = null, validator = null, m;
    const splitDns = s => s.trim().replace(/^\[|\]$/g, '').split(/,\s+(?=[A-Za-z][\w.-]{0,30}=)/).map(x => x.trim()).filter(Boolean);
    for (const r of recs) {
      const d = /^ssl_debug\((\d+)\):\s?(.*)$/.exec(r.msg || ''), msg = d ? d[2] : (r.msg || '');
      if (list) {   // one accepted CA per line, directly below "Accepted certificate authorities:"
        if (d && d[1] === list.id && /^\s+[A-Za-z][\w.-]{0,30}=/.test(msg)) { list.hs.cas.push(msg.trim()); continue; }
        list = null;
      }
      if (validator) {   // "[CN=a,O=b, CN=c]" on the line after "received issuer certificates trusted by the server:"
        if (/^\s*\[/.test(msg) && !validator.cas.length) validator.cas = splitDns(msg);
        validator = null;
      }
      if (d && (m = /Sending v\d client_hello message to ([^,\s]+)/.exec(msg))) {
        const h = { source, line: r.line, ts: r.ts, thread: r.thread, peer: m[1], cas: [], requested: false, client: null };
        byId.set(d[1], h); byThread.set(r.thread, h); out.push(h);
        continue;
      }
      let hs = d ? byId.get(d[1]) : byThread.get(r.thread);
      if ((m = /received issuer certificates trusted by the server:\s*(.*)$/i.exec(msg))) {
        if (hs && !hs.validator && hs.cas.length && r.line - hs.line < 100) continue;   // same check, already read from the TLS trace
        hs = { source, line: r.line, ts: r.ts, thread: r.thread, peer: '', cas: [], requested: true, client: null, validator: true };
        byThread.set(r.thread, hs); out.push(hs);
        if (m[1].trim()) hs.cas = splitDns(m[1]); else validator = hs;
        continue;
      }
      if (!hs) continue;
      if (/Accepted certificate authorities:/.test(msg)) { hs.cas = []; hs.requested = true; list = { id: d && d[1], hs }; }
      else if (/Received certificate_request handshake message/.test(msg)) hs.requested = true;
      else if (/No client certificate available/.test(msg)) hs.client = 'none';
      else if (/Sending certificate_verify|certificate handshake message with client certificate/i.test(msg)) hs.client = 'sent';
      else if (!hs.peer && (m = /Opening connection \{s\}->https?:\/\/([^\s\]]+)/.exec(msg))) hs.peer = m[1];
    }
    return out.filter(h => h.requested || h.cas.length);
  };
  X.handshakesFromText = function (text, source) {
    if (!/Accepted certificate authorities|issuer certificates trusted by the server/.test(text)) return [];
    const recs = [];
    let ts = '', thread = '';
    text.split(/\r?\n/).forEach((l, i) => {
      const m = SCC_LINE.exec(l);
      if (m) { ts = m[1]; thread = m[2].trim(); }
      recs.push({ ts, thread, msg: m ? l.slice(m[0].length) : l, line: i + 1 });
    });
    return X.parseHandshakes(recs, source);
  };

  X.parseText = function (text, source) {
    const certs = [];
    // 1) embedded PEM blocks (certificates and PKCS#7 bundles)
    const re = /-----BEGIN ((?:TRUSTED |X509 )?CERTIFICATE|PKCS7|CMS)-----([\s\S]*?)-----END \1-----/g;
    let m;
    while ((m = re.exec(text))) {
      try {
        const der = b64(m[2]);
        if (/CERTIFICATE/.test(m[1])) { try { certs.push(X.parseDer(der)); continue; } catch (e) { /* fall through to carving */ } }
        certs.push(...X.carve(der));
      } catch (e) { /* invalid base64 */ }
    }
    if (certs.length) return finish(certs, source, '');
    // 2) bare base64 (DER exported as "Base64" without header lines)
    const compact = text.replace(/\s+/g, '');
    if (compact.length > 300 && /^[A-Za-z0-9+/]+=*$/.test(compact)) {
      try { const der = b64(compact); const cs = X.carve(der); if (cs.length) return finish(cs, source, ''); } catch (e) { /* not base64 */ }
    }
    // 3) text blocks: STRUST copy, sapgenpse output, openssl -text, SAP kernel traces (dev_icm / dev_webdisp / sec trace),
    //    Cloud Connector TLS trace (scc_core.trc: "ssl_debug(n): ServerCertChain[0]:", "SCCEndpointValidator received server certificate:")
    const raw = text.split(/\r?\n/);
    const isScc = /ssl_debug\(\d+\)|SCCEndpointValidator/.test(text);
    const lines = raw.map(l => l.replace(SCC_LINE, '').replace(/^ssl_debug\(\d+\):\s?/, '').replace(/^\[Thr [^\]]*\]\s?/, '').replace(/^\s*#?\d{1,3}\.\s+(?=[A-Za-z])/, ' '));
    const isTrace = isScc || /^\[Thr /m.test(text) || /CCL\[SSL\]/.test(text);
    const unq = s => s.trim().replace(/^"(.*)"$/, '$1').trim();
    let pse = '', cur = null, pendingValidity = false, pendingSerial = false, ctx = null, host = null, san = null, dn = null, thread = '';
    const sccHost = new Map();   // ssl_debug connection number / thread → "host:port" of its client_hello
    const flush = () => { if (cur && (cur.subject || cur.notAfter)) certs.push(cur); cur = null; dn = null; };
    const start = (li, subject, what) => {
      flush();
      cur = { subject, issuer: '', serial: '', san: san && li - san.li <= 6 ? san.names : [], notBefore: null, notAfter: null, pse, fromText: true };
      san = null; pendingValidity = pendingSerial = false;
      if (isTrace) {
        let usedPse = '';
        for (let j = li; j < Math.min(lines.length, li + 30) && !usedPse; j++) { const pm = /(?:(cli|srv) SSL session PSE|session uses PSE file)\s*"([^"]+)"/i.exec(lines[j]); if (pm) usedPse = pm[2]; }
        cur.observed = [{ source, what: what || (ctx && li - ctx.li <= 6 ? ctx.text : 'certificate in trace'), pse: usedPse, line: li + 1 }];
      }
    };
    lines.forEach((line, li) => {
      const pl = PSE_LINE.exec(line);
      if (pl) { pse = pl[1].trim(); return; }
      if (isScc) {   // certificate dumps follow a marker line; the next log entry (time stamp) ends them
        const sm = SCC_LINE.exec(raw[li]), id = (/ssl_debug\((\d+)\)/.exec(raw[li]) || [])[1];
        if (sm) thread = sm[2].trim();
        if ((m = /Sending v\d client_hello message to ([^,\s]+)/.exec(line))) { sccHost.set(id, m[1]); sccHost.set('t|' + thread, m[1]); }
        const mk = /^\s*(Server|Client)CertChain\[(\d+)\]:/.exec(line) || /received (server|client) certificate:/i.exec(line);
        if (mk) {
          const h = sccHost.get(id) || sccHost.get('t|' + thread);
          start(li, '', /server/i.test(mk[1]) ? `server certificate${h ? ' of ' + h : ''} (Cloud Connector → backend${mk[2] > 0 ? ', chain element ' + mk[2] : ''})` : 'client certificate (Cloud Connector handshake)');
          cur.block = true;
          return;
        }
        if (sm) { flush(); return; }
      } else if (isTrace) {   // what the trace says about the certificate that follows
        if ((m = /CCL\[SSL\]:.*?Error (0x[0-9A-F]+)\((.*)\):?\s*$/i.exec(line))) ctx = { li, text: `${m[2]} (${m[1]})` };
        else if ((m = /status\s*=\s*"[^"]*(received (?:client|server|peer) cert[^"]*)"/i.exec(line))) ctx = { li, text: `${m[1]} (inbound)` };
        else if (/status\s*=\s*"(?:new|resumed) SSL session/i.test(line)) ctx = { li, text: `server certificate${host && li - host.li < 12 ? ' of ' + host.name : ''} (outbound)` };
        else if ((m = /\*\*\* ERROR => (.*SSSLERR_\w+.*?)(?:\s*\[\w+\.\w+\s+\d+\])?$/.exec(line))) ctx = { li, text: m[1] };
        if ((m = /MatchTargetName\("([^"]+)"/.exec(line)) || (m = /Looking up entry="[^"]*?\s(\S+:\d+)\s/.exec(line))) host = { li, name: m[1] };
        if ((m = /^\s*Subject Alt(?:ernative)? Names?\s*:\s*(.+)$/i.exec(line))) { san = { li, names: [...m[1].matchAll(/dNSName="?([^",\s]+)/gi)].map(x => x[1]) }; return; }
      }
      if ((m = /^\s*(?:Subject(?!\s*(?:Alt|Public|Key))(?:\s*DN|\s*Name)?|Owner|Inhaber)\s*[:=]?\s+(.+)$/i.exec(line)) && /=/.test(m[1])) {
        if (cur && cur.block && !cur.subject) cur.subject = unq(m[1]);
        else start(li, unq(m[1]));
        dn = 'subject';
        return;
      }
      if (!cur) return;
      // DN continued on the next lines, one RDN per line (Java / iSaSiLk dump: "Issuer:  CN=x" + "           OU=y")
      if (dn && (m = /^\s{4,}([A-Za-z][\w.-]{0,30}\s*=.*\S)\s*$/.exec(line))) { cur[dn] += ', ' + m[1].trim(); return; }
      dn = null;
      if (pendingSerial && line.trim()) { if (X.serialKey(line)) cur.serial = line.trim(); pendingSerial = false; return; }
      if ((m = /^\s*(?:Issuer(?:\s*DN|\s*Name)?|Aussteller)\s*[:=]?\s+(.+)$/i.exec(line))) { cur.issuer = unq(m[1]); dn = 'issuer'; }
      else if ((m = /^\s*(?:Serial\s*(?:no|num(?:ber)?)?|Seriennummer)\s*(?:\(hex\))?\s*[:=]?\s*(.*)$/i.exec(line))) { cur.serial = unq(m[1]); pendingSerial = !cur.serial; }
      else if ((m = /^\s*KeyInfo\s*:?\s+(\w+)[, ]+(\d+)-bit/i.exec(line))) { cur.keyAlg = m[1].toUpperCase(); cur.keyBits = +m[2]; }
      else if ((m = /^\s*Public Key\s*:\s*(RSA|EC|DSA)\w*,\s*(\d+) bit/i.exec(line))) { cur.keyAlg = m[1].toUpperCase(); cur.keyBits = +m[2]; }
      else if ((m = /^\s*Signature Algorithm\s*:\s*(\S+)/i.exec(line))) { if (!cur.sigAlg) cur.sigAlg = m[1]; }
      else if (/Not ?Before/i.test(line) && !/Not ?After/i.test(line)) { cur.notBefore = textDate(line); pendingValidity = true; }
      else if (/Not ?After/i.test(line)) { cur.notAfter = textDate(line); pendingValidity = false; }
      else if ((m = /^\s*(?:Valid(?:ity)?|Gültig(?:keit)?)\s*(?:From|ab)?\s*:?\s*(.+?)\s+(?:to|until|-|bis)\s+(.+)$/i.exec(line))) { cur.notBefore = textDate(m[1]); cur.notAfter = textDate(m[2]); }
      else if ((m = /^\s*(?:Valid (?:to|until)|Gültig bis|Expires?(?: on)?)\s*:?\s*(.+)$/i.exec(line))) cur.notAfter = textDate(m[1]);
      else if ((m = /^\s*(?:Valid from|Gültig ab)\s*:?\s*(.+)$/i.exec(line))) cur.notBefore = textDate(m[1]);
      else if (pendingValidity && /\d/.test(line)) { const d = textDate(line); if (d) { cur.notAfter = d; pendingValidity = false; } }
    });
    flush();
    return finish(certs, source, null);
  };

  /* Binary or text input of any supported kind → { certs, kind, note } */
  const PSE_NAMES = { SAPSSLS: 'SSL server Standard', SAPSSLC: 'SSL client Standard', SAPSSLA: 'SSL client Anonymous', SAPSYS: 'System PSE', SAPSNCS: 'SNC SAPCryptolib', SAPSMIME: 'SMIME Standard', SAPDBTEST: 'Test PSE', SAPECCTE: 'WS Security', SAPSRV: 'HANA SSL server', SAPCLI: 'HANA SSL client' };
  X.kindOf = function (name) {
    const b = String(name).split(/[\\/]|!\//).pop();
    const ext = (/\.([a-z0-9]+)$/i.exec(b) || [])[1] || '';
    // Java keystores (Cloud Connector, AS Java, BTP): trusted certificate entries are stored unencrypted → readable by scanning
    const k = { pse: 'SAP PSE', p12: 'PKCS#12', pfx: 'PKCS#12', p7b: 'PKCS#7', p7c: 'PKCS#7', cer: 'Certificate', crt: 'Certificate', der: 'Certificate', pem: 'PEM', jks: 'Java keystore', keystore: 'Java keystore', ks: 'Java keystore', store: 'Java keystore', truststore: 'Java keystore' }[ext.toLowerCase()] || 'Text';
    const stem = b.replace(/\.[^.]+$/, '').toUpperCase();
    return { kind: k, pse: PSE_NAMES[stem] || (k === 'SAP PSE' ? b : '') };
  };
  X.fromBytes = function (u8, name) {
    let { kind, pse } = X.kindOf(name);
    const probe = u8.subarray(0, 2048);
    let binary = false;
    for (let i = 0; i < probe.length; i++) if (probe[i] === 0 || (probe[i] < 9)) { binary = true; break; }
    let certs = [], handshakes = [];
    if (!binary) {
      const text = new TextDecoder('utf-8').decode(u8);
      certs = X.parseText(text, name);
      handshakes = X.handshakesFromText(text, name);
    } else {
      try { certs = [X.parseDer(u8)]; } catch (e) { certs = X.carve(u8); }
      finish(certs, name, pse);
    }
    const trace = certs.length && certs.every(c => c.observed);
    if (trace) kind = 'SAP trace (handshake)';
    certs.forEach(c => { c.source = name; if (!c.pse) c.pse = pse; c.container = kind; });
    let note = `${certs.length} certificate${certs.length === 1 ? '' : 's'}`;
    if (trace) note = `${certs.length} certificate reference${certs.length === 1 ? '' : 's'} (subject / issuer / serial seen in handshakes)`;
    if (handshakes.length) note += ` · ${handshakes.length} handshake${handshakes.length === 1 ? '' : 's'} with a client certificate request`;
    if (!certs.length) {
      note = kind === 'PKCS#12' ? 'no readable certificate — PKCS#12 files are password-encrypted; export the certificates as .cer/.pem instead'
        : kind === 'SAP PSE' ? 'no unencrypted certificate found — export the certificates from STRUST, or run "sapgenpse maintain_pk -l -p <pse>" and load the output'
          : kind === 'Java keystore' ? 'no readable certificate — export the entries with "keytool -exportcert -rfc" (or from the Cloud Connector UI) and load the .pem'
            : 'no certificate found';
    }
    return { certs, kind, pse, note, handshakes };
  };

  function finish(certs, source, pse) {
    for (const c of certs) {
      const cn = /(?:^|,\s*)CN=([^,]+)/i.exec(c.subject || '');
      c.cn = cn ? cn[1].trim() : (c.subject || '').slice(0, 80) || '(no subject)';
      c.selfSigned = !!c.subject && X.normDn(c.subject) === X.normDn(c.issuer) && (!c.aki || !c.ski || c.aki === c.ski);
      if (source != null && !c.source) c.source = source;
      if (pse != null && c.pse == null) c.pse = pse;
      if (c.pse == null) c.pse = '';
      c.san = c.san || [];
      c.serialKey = X.serialKey(c.serial);
    }
    return certs;
  }
  // DN comparison: case / blanks around "=" and "," ignored; attribute aliases used by SAP, OpenSSL and Windows unified
  const DN_ALIAS = { s: 'st', sp: 'st', email: 'e', emailaddress: 'e', '1.2.840.113549.1.9.1': 'e', '2.5.4.5': 'serialnumber' };
  X.normDn = dn => String(dn || '').trim().replace(/^"(.*)"$/, '$1').replace(/=\s*"([^"]*)"/g, '=$1').toLowerCase().replace(/\s*([=,])\s*/g, '$1')
    .replace(/(^|,)([a-z0-9.]+)=/g, (m, p, k) => p + (DN_ALIAS[k] || k) + '=').trim();

  /* ---------- Serial numbers ----------
   * The same serial appears as "0A:20:25:11", "0a 20 25 11", "0A202511", "00:A1:…" (DER sign byte), "0x…",
   * openssl "4096 (0x1000)" or decimal (XML signatures / SAML X509SerialNumber, Java logs).
   * Canonical key = lowercase hex without separators and leading zeros. */
  const canonHex = h => h.toLowerCase().replace(/^0+(?=.)/, '');
  X.serialKeys = function (s) {
    s = String(s == null ? '' : s).trim();
    if (!s) return [];
    let m = /\(0x([0-9a-f]+)\)/i.exec(s);
    if (m) return [canonHex(m[1])];
    s = s.replace(/^serial\s*(?:no|num(?:ber)?)?\s*[:=]?\s*/i, '').replace(/^0x/i, '').trim();
    const compact = s.replace(/[\s:-]/g, '');
    if (!compact || !/^[0-9a-f]+$/i.test(compact)) return [];
    const out = [canonHex(compact)];
    // digits only and no byte separators: may also be decimal
    if (/^\d+$/.test(compact) && !/[\s:-]/.test(s) && typeof BigInt === 'function') out.push(BigInt(compact).toString(16));
    return [...new Set(out)];
  };
  X.serialKey = s => X.serialKeys(s)[0] || '';
  X.serialForms = function (s) {
    const k = X.serialKey(s);
    if (!k) return null;
    const even = (k.length % 2 ? '0' : '') + k.toUpperCase();
    let dec = '';
    try { dec = BigInt('0x' + k).toString(10); } catch (e) { /* no BigInt */ }
    return { key: k, colon: even.replace(/(..)(?!$)/g, '$1:'), plain: even, dec };
  };

  /* ---------- Signature verification (WebCrypto) ----------
   * true = issuer's public key verifies the certificate signature, false = it does not (wrong issuer / different CA key),
   * null = cannot be checked (no DER, unsupported algorithm, no WebCrypto). */
  const SIG_SPEC = {
    '1.2.840.113549.1.1.5': ['RSASSA-PKCS1-v1_5', 'SHA-1'], '1.2.840.113549.1.1.11': ['RSASSA-PKCS1-v1_5', 'SHA-256'],
    '1.2.840.113549.1.1.12': ['RSASSA-PKCS1-v1_5', 'SHA-384'], '1.2.840.113549.1.1.13': ['RSASSA-PKCS1-v1_5', 'SHA-512'],
    '1.2.840.113549.1.1.10': ['RSA-PSS', null],
    '1.2.840.10045.4.1': ['ECDSA', 'SHA-1'], '1.2.840.10045.4.3.2': ['ECDSA', 'SHA-256'], '1.2.840.10045.4.3.3': ['ECDSA', 'SHA-384'], '1.2.840.10045.4.3.4': ['ECDSA', 'SHA-512'],
    '1.3.101.112': ['Ed25519', null]
  };
  const HASH_OID = { '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
  const EC_SIZE = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };
  function pssParams(u8) {
    const p = { hash: 'SHA-1', salt: 20 };
    if (!u8) return p;
    for (const k of children(u8, tlv(u8, 0, u8.length))) {
      if (k.tag === 0xa0) p.hash = HASH_OID[oid(u8, children(u8, children(u8, k)[0])[0])] || p.hash;
      else if (k.tag === 0xa2) { const n = children(u8, k)[0]; p.salt = 0; for (let i = n.start; i < n.end; i++) p.salt = p.salt * 256 + u8[i]; }
    }
    return p;
  }
  function ecRaw(sig, size) {   // DER SEQUENCE { r, s } → r || s (WebCrypto format)
    const [r, s] = children(sig, tlv(sig, 0, sig.length)), out = new Uint8Array(size * 2);
    [r, s].forEach((n, i) => { let v = sig.subarray(n.start, n.end); while (v.length > size && v[0] === 0) v = v.subarray(1); out.set(v, i * size + size - v.length); });
    return out;
  }
  const sigCache = new Map();
  X.verifySignature = async function (c, issuer) {
    const spec = SIG_SPEC[c.sigOid];
    if (!c.tbs || !issuer.spki || !spec || !(window.crypto && crypto.subtle)) return null;
    const ck = c.serialKey + '|' + X.normDn(c.issuer) + '>' + issuer.serialKey + '|' + X.normDn(issuer.issuer) + '|' + issuer.ski;
    if (sigCache.has(ck)) return sigCache.get(ck);
    let res = null;
    try {
      let [name, hash] = spec, imp, ver, sig = c.sigValue;
      if (name === 'ECDSA') {
        if (issuer.keyAlg !== 'EC') res = issuer.keyAlg ? false : null;
        else if (EC_SIZE[issuer.keyCurve]) { imp = { name, namedCurve: issuer.keyCurve }; ver = { name, hash }; sig = ecRaw(sig, EC_SIZE[issuer.keyCurve]); }
      } else if (name === 'Ed25519') {
        if (issuer.keyAlg !== 'Ed25519') res = issuer.keyAlg ? false : null;
        else { imp = { name }; ver = { name }; }
      } else if (issuer.keyAlg !== 'RSA') res = issuer.keyAlg && issuer.keyAlg !== 'RSA-PSS' ? false : null;
      else if (name === 'RSA-PSS') { const p = pssParams(c.sigParams); imp = { name, hash: p.hash }; ver = { name, saltLength: p.salt }; }
      else { imp = { name, hash }; ver = { name }; }
      if (imp) {
        const key = await crypto.subtle.importKey('spki', issuer.spki, imp, false, ['verify']);
        res = await crypto.subtle.verify(ver, key, sig, c.tbs);
        if (res === false && imp.name === 'RSA-PSS') res = null;   // PSS parameter edge cases: never report a false "wrong issuer"
      }
    } catch (e) { res = null; }
    sigCache.set(ck, res);
    return res;
  };

  /* Status of a certificate at a reference time */
  X.status = function (c, ref) {
    if (c.notAfter == null) return { key: 'unknown', label: 'Unknown validity' };
    if (c.notBefore != null && ref < c.notBefore) return { key: 'notyet', label: 'Not yet valid' };
    if (ref > c.notAfter) return { key: 'expired', label: 'Expired' };
    const days = Math.floor((c.notAfter - ref) / 864e5);
    if (days <= 30) return { key: 'expiring', label: `Expires in ${days} day${days === 1 ? '' : 's'}` };
    if (days <= 90) return { key: 'soon', label: `${days} days left` };
    return { key: 'ok', label: `Valid (${days} days left)` };
  };

  /* SHA-1 / SHA-256 fingerprints (WebCrypto; empty when not available) */
  X.fingerprints = async function (c) {
    if (!c.der || !(window.crypto && crypto.subtle)) return { sha1: '', sha256: '' };
    const [a, b] = await Promise.all([crypto.subtle.digest('SHA-1', c.der), crypto.subtle.digest('SHA-256', c.der)]);
    return { sha1: hex(new Uint8Array(a)), sha256: hex(new Uint8Array(b)) };
  };

  /* Host name check against SAN (or CN when there is no SAN), wildcard = one label */
  X.matchesHost = function (c, host) {
    const h = String(host || '').toLowerCase().trim().replace(/\.$/, '');
    if (!h) return false;
    const names = (c.san && c.san.length ? c.san : [c.cn]).concat(c.sanIp || []);
    return names.some(n => {
      n = String(n).toLowerCase();
      if (n === h) return true;
      if (n.startsWith('*.')) { const rest = n.slice(2); return h.endsWith('.' + rest) && h.split('.').length === rest.split('.').length + 1; }
      return false;
    });
  };
})(window.TS);
