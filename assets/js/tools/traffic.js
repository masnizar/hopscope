/* SAP Cloud Connector - traffic trace (tunnel_traffic_*.trc) parser & analysis
 *
 * Trace layout:
 *   ... >>> Request data for connection 0xaf428af1 ... 2026-10-01 01:44:10,347 +0000 ...
 *   000000 | 47455420 68747470 3A2F2F76 ... | GET http://v...
 *   ...
 *   ... <<< Request data for connection 0xaf428af1 ...
 * The hex column is the text between the first and the second "|".
 * Everything runs locally; nothing is sent to a server.
 */
(function (TS) {
  'use strict';
  const TT = TS.traffic = {};

  const RE_BLOCK = /(Request|Response) data for connection (0x[0-9a-fA-F]+)/;
  const RE_TS = /(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[,.](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?/;
  const RE_HEX = /^[0-9A-Fa-f]{4,8}\s*\|([^|]*)/;
  const RE_INFO = /Cloud Connector ([\d.]+) running on host ([\w.-]+)/;
  const RE_SUB = /subaccount ([\w-]+_on_[\w.-]+)/;
  const RE_SUB_FILE = /tunnel_traffic_([\w-]+_on_[\w.-]+?)(?:\.trc|\.log|\.\d+|$)/i;
  const RE_REQ_LINE = /^([A-Z][A-Z_-]{2,15}) (\S+) (HTTP\/\d(?:\.\d)?)$/;
  const RE_RESP_LINE = /^(HTTP\/\d(?:\.\d)?) (\d{3})(?: (.*))?$/;

  const ascii = u8 => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return s; };
  const utf8 = new TextDecoder('utf-8');

  function concat(parts, total) {
    if (parts.length === 1) return parts[0];
    if (total == null) total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  function firstLine(u8) {
    const n = Math.min(u8.length, 4096);
    let e = 0;
    while (e < n && u8[e] !== 10 && u8[e] !== 13) e++;
    return ascii(u8.subarray(0, e));
  }
  const isStart = u8 => { const l = firstLine(u8); return RE_REQ_LINE.test(l) || RE_RESP_LINE.test(l); };
  // TLS record header: content type 0x14-0x17, version 0x03 0x0n
  const isTls = u8 => u8.length >= 5 && u8[0] >= 0x14 && u8[0] <= 0x17 && u8[1] === 3 && u8[2] <= 4;

  /* ---------- 1. Text -> blocks -> messages ---------- */
  TT.parseTrace = function (text, fileName) {
    const lines = text.split(/\r?\n/);
    const info = { file: fileName, version: '', host: '', subaccount: '' };
    const blocks = [];
    let cur = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (cur) {
        const hm = RE_HEX.exec(line);
        if (hm) {
          const groups = hm[1].trim().split(/\s+/);
          for (const g of groups) {
            if (!g || g.length % 2 || !/^[0-9A-Fa-f]+$/.test(g)) continue;
            for (let k = 0; k < g.length; k += 2) cur.bytes.push(parseInt(g.substr(k, 2), 16));
          }
          cur.hexTo = i;
          continue;
        }
      }
      const bm = RE_BLOCK.exec(line);
      if (bm) {
        if (line.includes('<<<')) { cur = null; continue; }
        const tm = RE_TS.exec(line);
        const t = tm ? TS.mkTime(tm[1], tm[2] - 1, tm[3], tm[4], tm[5], tm[6], tm[7], tm[8]) : { t: null, off: null };
        cur = { type: bm[1].toLowerCase(), conn: bm[2].toLowerCase(), t: t.t, off: t.off, tsText: tm ? tm[0] : '', line: i + 1, hexFrom: i + 1, hexTo: i, bytes: [] };
        blocks.push(cur);
        continue;
      }
      if (!info.version) { const m = RE_INFO.exec(line); if (m) { info.version = m[1]; info.host = m[2]; } }
      if (!info.subaccount) { const m = RE_SUB.exec(line); if (m) info.subaccount = m[1]; }
    }
    if (!info.subaccount) { const m = RE_SUB_FILE.exec(String(fileName).split(/[\\/]|!\//).pop()); if (m) info.subaccount = m[1]; }

    // Merge continuation blocks (body sent in several chunks) into one HTTP message per direction.
    const msgs = [], last = new Map();
    for (const b of blocks) {
      const u8 = Uint8Array.from(b.bytes);
      b.bytes = null;
      const hex = { from: b.hexFrom, to: b.hexTo, header: lines[b.line - 1] };
      const key = b.conn + '|' + b.type;
      const prev = last.get(key);
      if (prev && prev.isHttp && !isStart(u8) && !isTls(u8)) {
        prev.parts.push(u8); prev.hexRanges.push(hex); prev.blocks++; prev.tLast = b.t;
        continue;
      }
      const m = {
        type: b.type, conn: b.conn, file: fileName, t: b.t, tLast: b.t, off: b.off, tsText: b.tsText, line: b.line,
        parts: [u8], hexRanges: [hex], blocks: 1, tls: isTls(u8), isHttp: isStart(u8), lines
      };
      msgs.push(m);
      last.set(key, m);
      // a new request on the connection closes the previous response
      if (b.type === 'request') last.delete(b.conn + '|response');
    }
    for (const m of msgs) { m.bytes = concat(m.parts); m.parts = null; }
    return { info, msgs, blockCount: blocks.length, lineCount: lines.length };
  };

  TT.hexText = function (m) {
    return m.hexRanges.map(r => [r.header].concat(m.lines.slice(r.from, r.to + 1)).join('\n')).join('\n');
  };

  /* ---------- 2. HTTP parsing (async because of DecompressionStream) ---------- */
  function headerEnd(b) {
    const n = Math.min(b.length, 256 * 1024);
    for (let i = 0; i < n - 1; i++) {
      if (b[i] === 10) {
        if (b[i + 1] === 10) return { end: i, body: i + 2 };
        if (b[i + 1] === 13 && b[i + 2] === 10) return { end: i, body: i + 3 };
      }
    }
    return null;
  }

  function dechunk(b) {
    const out = []; let p = 0, total = 0;
    while (p < b.length) {
      let e = p;
      while (e < b.length && b[e] !== 10) e++;
      if (e >= b.length) break;
      const size = parseInt(ascii(b.subarray(p, e)).split(';')[0].trim(), 16);
      if (isNaN(size)) { if (!out.length) return { data: b, complete: true, chunked: false }; break; }
      p = e + 1;
      if (size === 0) return { data: concat(out.length ? out : [new Uint8Array(0)], total), complete: true, chunked: true };
      const chunk = b.subarray(p, Math.min(b.length, p + size));
      out.push(chunk); total += chunk.length;
      if (p + size > b.length) break;
      p += size;
      if (b[p] === 13) p++;
      if (b[p] === 10) p++;
    }
    return { data: concat(out.length ? out : [new Uint8Array(0)], total), complete: false, chunked: true };
  }

  // Decompress, keeping whatever could be decoded when the data is truncated.
  async function decompress(u8, format) {
    const ds = new DecompressionStream(format);
    const writer = ds.writable.getWriter();
    writer.write(u8).catch(() => {});
    writer.close().catch(() => {});
    const reader = ds.readable.getReader();
    const chunks = []; let total = 0, err = null;
    try {
      for (;;) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); total += value.length; }
    } catch (e) { err = e; }
    if (!total && err) throw err;
    return { data: concat(chunks.length ? chunks : [new Uint8Array(0)], total), partial: !!err };
  }
  const BROTLI_FORMATS = ['brotli', 'br'];

  const TEXT_CT = /text\/|json|xml|javascript|html|x-www-form-urlencoded|csv|multipart\/mixed|application\/http|yaml|ecmascript/i;
  function looksText(b) {
    const n = Math.min(b.length, 2048);
    if (!n) return true;
    let bad = 0;
    for (let i = 0; i < n; i++) { const c = b[i]; if (c < 9 || (c > 13 && c < 32) || c === 127) bad++; }
    return bad / n < 0.03;
  }

  TT.parseHttp = async function (m) {
    const b = m.bytes;
    const h = m.h = { kind: 'empty', headers: [], hmap: {}, body: null, bodyText: '', notes: [], size: b.length };
    if (!b.length) { h.notes.push('Block without data.'); return h; }
    if (m.tls) {
      h.kind = 'tls';
      h.notes.push(`TLS-encrypted data (${b.length} bytes). This connection is end-to-end HTTPS, so the request/response content cannot be read from the traffic trace.`);
      return h;
    }
    const sep = headerEnd(b);
    const head = utf8.decode(b.subarray(0, sep ? sep.end : Math.min(b.length, 8192)));
    const hl = head.split(/\r?\n/);
    const first = hl[0];
    let mm;
    if ((mm = RE_REQ_LINE.exec(first))) { h.kind = 'http'; h.method = mm[1]; h.url = mm[2]; h.version = mm[3]; }
    else if ((mm = RE_RESP_LINE.exec(first))) { h.kind = 'http'; h.version = mm[1]; h.status = +mm[2]; h.statusText = mm[3] || ''; }
    else {
      if (looksText(b)) { h.kind = 'text'; h.bodyText = utf8.decode(b); h.body = b; h.notes.push('Non-HTTP text data (probably a body continuation of a previous block).'); }
      else { h.kind = 'binary'; h.body = b; h.notes.push(`Non-HTTP binary data (${b.length} bytes), e.g. RFC/CPIC or another TCP protocol — see the Hex view.`); }
      return h;
    }
    h.startLine = first;
    if (!sep) h.notes.push('Incomplete HTTP header — the trace is probably cut off.');
    for (let i = 1; i < hl.length; i++) {
      const l = hl[i], c = l.indexOf(':');
      if (c <= 0) continue;
      const n = l.slice(0, c).trim(), v = l.slice(c + 1).trim(), k = n.toLowerCase();
      h.headers.push([n, v]);
      h.hmap[k] = h.hmap[k] != null ? h.hmap[k] + ', ' + v : v;
    }
    let body = sep ? b.subarray(sep.body) : new Uint8Array(0);
    h.wireBodySize = body.length;
    if (m.blocks > 1) h.notes.push(`Merged from ${m.blocks} trace blocks.`);

    if (body.length && /chunked/i.test(h.hmap['transfer-encoding'] || '')) {
      const r = dechunk(body);
      if (r.chunked) { body = r.data; if (!r.complete) h.notes.push('Incomplete chunked body (trace cut off or data still streaming).'); }
    }
    const cl = parseInt(h.hmap['content-length'], 10);
    if (!isNaN(cl) && body.length < cl) h.notes.push(`Incomplete body: ${body.length} of ${cl} bytes (Content-Length).`);

    const enc = (h.hmap['content-encoding'] || '').toLowerCase().trim();
    if (body.length && enc && enc !== 'identity') {
      const formats = enc === 'gzip' || enc === 'x-gzip' ? ['gzip'] : enc === 'deflate' ? ['deflate', 'deflate-raw'] : enc === 'br' ? BROTLI_FORMATS : [];
      let done = false, lastErr = null;
      for (const f of formats) {
        try {
          const r = await decompress(body, f);
          body = r.data; done = true;
          h.notes.push(`Body decompressed from ${enc}${r.partial ? ' (partially — data cut off)' : ''}.`);
          break;
        } catch (e) { lastErr = e; }
      }
      if (!done) {
        h.compressed = enc;
        h.notes.push(enc === 'br' && lastErr instanceof TypeError
          ? 'Body is Brotli-compressed and this browser does not support local Brotli decompression yet. Use "Download body" and decompress it with a local tool (e.g. brotli -d).'
          : formats.length ? `Failed to decompress ${enc}: ${lastErr && lastErr.message}` : `Unknown Content-Encoding: ${enc}`);
      }
    }
    h.body = body;
    h.contentType = (h.hmap['content-type'] || '').toLowerCase();
    if (body.length && !h.compressed) {
      if (TEXT_CT.test(h.contentType) || looksText(body)) {
        const cs = /charset="?([\w-]+)/.exec(h.contentType);
        try { h.bodyText = new TextDecoder(cs ? cs[1] : 'utf-8').decode(body); } catch (e) { h.bodyText = utf8.decode(body); }
      } else h.binary = true;
    }
    return h;
  };

  /* ---------- 3. Pairs (request + its responses on the same connection) ---------- */
  TT.finalResponse = p => {
    for (let i = p.resps.length - 1; i >= 0; i--) { const s = p.resps[i].h.status; if (s && s >= 200) return p.resps[i]; }
    return p.resps[0] || null;
  };

  TT.buildPairs = function (msgs) {
    const sorted = msgs.slice().sort((a, b) => (a.t == null) - (b.t == null) || (a.t || 0) - (b.t || 0) || a.line - b.line);
    const open = new Map(), pairs = [];
    for (const m of sorted) {
      const key = m.file + '|' + m.conn;
      if (m.type === 'request') {
        // body continuation of a request that was interrupted by e.g. "100 Continue"
        const p0 = open.get(key);
        if (p0 && p0.req && !m.isHttp && !m.tls && p0.req.isHttp && m.h.kind !== 'binary') { p0.extraReq.push(m); continue; }
        const p = { req: m, resps: [], extraReq: [], conn: m.conn, file: m.file, t: m.t };
        pairs.push(p); open.set(key, p);
      } else {
        let p = open.get(key);
        if (!p) { p = { req: null, resps: [], extraReq: [], conn: m.conn, file: m.file, t: m.t }; pairs.push(p); open.set(key, p); }
        p.resps.push(m);
      }
    }
    pairs.sort((a, b) => (a.t == null) - (b.t == null) || (a.t || 0) - (b.t || 0));
    pairs.forEach((p, i) => {
      p.id = i;
      const rq = p.req && p.req.h, fin = TT.finalResponse(p), rs = fin && fin.h;
      p.kind = rq ? rq.kind : 'orphan';
      p.method = rq && rq.method ? rq.method : rq ? (rq.kind === 'tls' ? 'TLS' : rq.kind === 'binary' ? 'BIN' : 'DATA') : '—';
      p.url = rq && rq.url || '';
      p.host = '';
      p.path = p.url;
      const um = /^([a-z][\w+.-]*:\/\/[^/?#]+)(.*)$/i.exec(p.url);
      if (um) { p.host = um[1]; p.path = um[2] || '/'; } else if (rq && rq.hmap && rq.hmap.host) p.host = rq.hmap.host;
      p.pathNoQuery = p.path.split('?')[0];
      p.status = rs && rs.status || null;
      p.statusClass = !p.resps.length ? 'none' : !p.status ? 'other' : Math.floor(p.status / 100) + 'xx';
      p.dur = p.req && fin && p.req.t != null && fin.t != null ? Math.max(0, fin.t - p.req.t) : null;
      p.reqSize = p.req ? p.req.bytes.length + p.extraReq.reduce((n, m) => n + m.bytes.length, 0) : 0;
      p.respSize = p.resps.reduce((n, m) => n + m.bytes.length, 0);
      const allText = [rq && rq.bodyText, rs && rs.bodyText, p.url, rs && rs.hmap && rs.hmap.location].filter(Boolean).join('\n');
      p.badges = [];
      // cloud user forwarded for principal propagation (CF: JWT in SAP-Connectivity-SSOToken*, Neo: SAML assertion in SAP-Connectivity-Authentication)
      p.sso = !!(rq && rq.hmap && (rq.hmap['sap-connectivity-ssotoken-base64'] || rq.hmap['sap-connectivity-ssotoken'] || rq.hmap['sap-connectivity-authentication']));
      // backend answered with a redirect to a login / IdP: the request was not authenticated
      const loc = rs && rs.hmap && rs.hmap.location || '';
      p.loginRedirect = !!(rs && rs.status >= 300 && rs.status < 400 && (/pending/i.test(rs.hmap['sap-authenticated'] || '') || /\/saml2\/idp\/|SAMLRequest=|accounts\.ondemand\.com|accounts\.cloud\.sap|\/oauth\/authorize|\/login\b/i.test(loc)));
      p.idpHost = p.loginRedirect ? (/^https?:\/\/([^/?#]+)/i.exec(loc) || [])[1] || '' : '';
      if (p.sso) p.badges.push('SSO token');
      if (p.loginRedirect) p.badges.push('Login redirect');
      if (/SAMLRequest|SAMLResponse|urn:oasis:names:tc:SAML/i.test(allText)) p.badges.push('SAML');
      if (rq && rq.hmap && /fetch/i.test(rq.hmap['x-csrf-token'] || '')) p.badges.push('CSRF fetch');
      if (rs && rs.hmap && /required/i.test(rs.hmap['x-csrf-token'] || '')) p.badges.push('CSRF required');
      if (/\$batch/.test(p.url)) p.badges.push('$batch');
      if (/\/ina\//i.test(p.url)) p.badges.push('InA');
      if (rq && rq.hmap && /websocket/i.test(rq.hmap.upgrade || '')) p.badges.push('WebSocket');
    });
    return pairs;
  };

  /* ---------- 4. Hints per pair ---------- */
  function backendMessage(text) {
    if (!text) return '';
    let m = /"message"\s*:\s*\{[^}]*?"value"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(text) || /"message"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(text) || /<message[^>]*>([^<]{3,})<\/message>/i.exec(text);
    if (m) return m[1].replace(/\\"/g, '"').slice(0, 400);
    m = /<title>([^<]{3,})<\/title>/i.exec(text);
    return m ? m[1].trim().slice(0, 200) : '';
  }

  TT.hints = function (p) {
    const out = [];
    const rq = p.req && p.req.h, fin = TT.finalResponse(p), rs = fin && fin.h;
    if (!p.req) out.push(['info', 'Response without a request in the trace (the trace started in the middle of the conversation on this connection).']);
    if (rq && rq.kind === 'tls') out.push(['info', 'Request is TLS-encrypted end-to-end — the content cannot be read from the traffic trace.']);
    if (p.req && !p.resps.length) out.push(['high', 'No response for this request in the trace: the backend did not respond (timeout), the connection was closed, or the trace stopped before the response arrived.']);
    if (rs && rs.status) {
      const s = rs.status, H = rs.hmap;
      const login = /saml|login|logon|idp|oauth|authorize/i;
      if (s === 401) out.push(['medium', 'HTTP 401 — the backend rejected authentication' + (H['www-authenticate'] ? ` (WWW-Authenticate: ${H['www-authenticate']})` : '') + '. Check the user/credentials in the destination or the principal propagation setup.']);
      if (s === 403) out.push(['medium', /required/i.test(H['x-csrf-token'] || '')
        ? 'HTTP 403 with x-csrf-token: Required — CSRF token missing/invalid. Fetch a token with the header x-csrf-token: Fetch and resend it together with the same session cookies.'
        : 'HTTP 403 — the user lacks authorization in the backend (check SU53 / trace ST01).']);
      if (s === 404) out.push(['medium', 'HTTP 404 — path not found in the backend (check the service in /IWFND/MAINT_SERVICE or that the SICF node is active).']);
      if (p.sso && p.loginRedirect) out.push(['high', `The request carries the cloud user for principal propagation (SAP-Connectivity-SSOToken), but the backend answered ${s}${H['sap-authenticated'] ? ' with sap-authenticated: ' + H['sap-authenticated'] : ''} and redirects to the IdP ${p.idpHost || H.location}: the user was NOT logged on. The backend ignored the short-lived X.509 certificate of the Cloud Connector — usually the backend does not trust the Cloud Connector as reverse proxy (SCC system certificate not in the SSL server PSE / not sent, icm/trusted_reverse_proxy_<n>) or CERTRULE maps the certificate to no user. Check scc_core.trc in the Log Analyzer ("Backend asked for a client certificate …") or load it with sys_cert.der in Certificates. Non-browser clients (e.g. Group Reporting Data Collection) then fail with 302 / 405.`]);
      else if (s >= 300 && s < 400 && H.location) out.push([login.test(H.location) ? 'medium' : 'info', `Redirect ${s} to ${H.location}` + (login.test(H.location) ? ' — the session is probably not authenticated and is sent to the login/IdP.' : '')]);
      if (s === 500) out.push(['high', 'HTTP 500 — backend error. Check ST22, SM21, and /IWFND/ERROR_LOG or /IWBEP/ERROR_LOG at the same time.']);
      if (s === 502 || s === 503 || s === 504) out.push(['high', `HTTP ${s} — gateway/backend unavailable or timed out (ICM / Web Dispatcher).`]);
      if (s >= 400) { const bm = backendMessage(rs.bodyText); if (bm) out.push(['info', 'Backend message: ' + bm]); }
      if (H['sap-message']) out.push(['info', 'sap-message: ' + H['sap-message'].slice(0, 400)]);
      if (s < 300 && /<title>[^<]*(logon|log on|login|anmeldung)/i.test(rs.bodyText || '')) out.push(['medium', 'Response contains an HTML login page — the request is not authenticated (check SSO / principal propagation).']);
    }
    if (p.dur != null && p.dur >= 10000) out.push(['medium', `Slow response: ${TS.fmtDuration(p.dur)}.`]);
    if (rq && rq.hmap && /fetch/i.test(rq.hmap['x-csrf-token'] || '')) out.push(['info', 'Request fetches a CSRF token (x-csrf-token: Fetch).']);
    return out;
  };

  /* ---------- 5. Sensitive values ---------- */
  const SENSITIVE = /^(authorization|proxy-authorization|cookie|set-cookie|x-csrf-token|mysapsso2|sap-xsrf|x-sap-security-session|sap-passport|x-api-key|apikey|x-auth-token|sap-connectivity-authentication|sap-connectivity-technical-authentication|sap-connectivity-ssotoken|sap-connectivity-ssotoken-base64)$/i;
  TT.isSensitive = name => SENSITIVE.test(name);
  TT.mask = function (name, value) {
    if (!SENSITIVE.test(name)) return value;
    if (/^x-csrf-token$/i.test(name) && /^(fetch|required)$/i.test(value)) return value;
    if (/^(authorization|proxy-authorization)$/i.test(name)) { const sp = value.indexOf(' '); return (sp > 0 ? value.slice(0, sp + 1) : '') + '•••• [masked]'; }
    if (/cookie/i.test(name)) return value.split(/;\s*/).map(c => { const e = c.indexOf('='); return e > 0 ? c.slice(0, e + 1) + '••••' : c; }).join('; ');
    return '•••• [masked]';
  };
})(window.TS);
