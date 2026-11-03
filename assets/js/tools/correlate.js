/* Correlation engine: combine SAP traces and transaction exports on one time line.
 * Sources: dev_webdisp (WDP), dev_icm (ICM), dev_w* / dev_disp (work processes), SM21 (system log export),
 * ST22 (dump list export), SM59 (connection test result), STRUST (certificates), HTTP log, Cloud Connector, other logs.
 * Every source is turned into events {t, src, level, code, title, text, ...}; error events are clustered into incidents
 * and cross-source rules explain how they relate.
 */
(function (TS) {
  'use strict';
  const C = TS.corr = {};
  const base = p => String(p).split(/[\\/]|!\//).pop();

  C.SOURCES = [
    { id: 'wdp', label: 'Web Dispatcher', hint: 'dev_webdisp' },
    { id: 'icm', label: 'ICM', hint: 'dev_icm (SMICM)' },
    { id: 'wp', label: 'Work processes', hint: 'dev_w*, dev_disp' },
    { id: 'sm21', label: 'System log', hint: 'SM21 export' },
    { id: 'st22', label: 'ABAP dumps', hint: 'ST22 export' },
    { id: 'sm59', label: 'Connection tests', hint: 'SM59 result' },
    { id: 'strust', label: 'Certificates', hint: 'STRUST' },
    { id: 'http', label: 'HTTP log', hint: 'ICM / WDP access log' },
    { id: 'scc', label: 'Cloud Connector', hint: 'ljs_trace.log, scc_core' },
    { id: 'other', label: 'Other log', hint: '' }
  ];
  C.label = id => (C.SOURCES.find(s => s.id === id) || { label: id }).label;

  /* ---------- Classification ---------- */
  const ACCESS = /^\S+ \S+ \S+ \[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/m;
  C.classify = function (name, text) {
    const b = base(name).toLowerCase(), head = text.slice(0, 30000);
    // names as downloaded or renamed per system, e.g. "DV1_dev_icm.txt", "WDP_tracefile.txt"
    if (/(^|[_\-. ])dev_webdisp/.test(b)) return 'wdp';
    if (/(^|[_\-. ])dev_icm/.test(b)) return 'icm';
    if (/(^|[_\-. ])dev_(w\d+|disp|ms|rd|enq|tp|smon)/.test(b)) return 'wp';
    if (/ljs_trace|scc_core|^scc_/.test(b) || /^\d{4}-\d{2}-\d{2} [\d:,.]+ [+-]\d{4}#(?:INFO|DEBUG|WARN|WARNING|ERROR|TRACE|ALL)#com\.sap\.(?:core\.connectivity|scc)/m.test(head)) return 'scc';
    // kernel traces before the certificate check: CCL blocks in dev_icm contain "Subject" / "Not after"
    if (/^\[Thr \d+\]/m.test(head)) return /webdisp|wdisp\//i.test(head) ? 'wdp' : /\bIcm[A-Z]/.test(head) ? 'icm' : 'wp';
    if (/\.(cer|crt|der|pem|pse|p7b|p7c)$/.test(b) || /-----BEGIN (TRUSTED )?CERTIFICATE-----/.test(head) ||
      (/NotAfter|Valid (to|until)|Gültig bis/i.test(head) && /Subject|Owner|Inhaber/i.test(head))) return 'strust';
    if (/sm59|connection.?test/.test(b) || /Connection Test|Status HTTP Response|Logon\s+\d+\s*msec|Connection Type\s+(ABAP|HTTP)/i.test(head)) return 'sm59';
    const tbl = TS.tables.parse(head);
    if (tbl) {
      const map = TS.tables.mapColumns(tbl.header);
      if (map.runtime != null || map.exception != null || /st22|dump/.test(b)) return 'st22';
      if (map.text != null || map.msgid != null || /sm21|syslog/.test(b)) return 'sm21';
    }
    if (/st22|dump/.test(b)) return 'st22';
    if (/sm21|syslog/.test(b)) return 'sm21';
    if (/access|http_?log/.test(b) || ACCESS.test(head)) return 'http';
    if (/\[Thr \d+\]/.test(head)) return /webdisp|wdisp\//i.test(head) ? 'wdp' : /\bIcm[A-Z]/.test(head) ? 'icm' : 'wp';
    return 'other';
  };

  /* ---------- Helpers ---------- */
  const RE_EP1 = /\b((?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z][a-z0-9-]{1,62}|\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b/gi;
  const RE_EP2 = /host\s*[=:]?\s*'?([A-Za-z0-9][\w.-]+)'?,?\s*(?:service|port)\s*[=:]?\s*'?(\d{2,5})'?/gi;
  C.endpoints = function (text) {
    const out = new Set();
    for (const re of [RE_EP1, RE_EP2]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) { const h = m[1].toLowerCase(); if (!/\.(c|cpp|h|java)$/.test(h)) out.add(h + ':' + m[2]); }
    }
    return [...out];
  };
  // file.lastModified is real time; trace timestamps are server wall-clock times stored "as UTC"
  const wallClock = ms => ms - new Date(ms).getTimezoneOffset() * 60000;

  function matchRule(rules, e, text) {
    for (const r of rules) {
      if (!TS.levelAtLeast(e.level, r.minLevel || 'WARN')) continue;
      if (r.re.test(text) && !(r.exclude && r.exclude.test(text))) return r;
    }
    return null;
  }

  /* ---------- Work process / dispatcher traces ---------- */
  const WP_RULES = [
    { id: 'wp-restart', sev: 'high', title: 'Work process terminated / restarted', re: /(work process|\bWP\b|process)\s*\d*[^\n]{0,40}(restart|terminat|died|ended abnormally|stopped)|ThIErrHandle|DpWpDynCreate|DpTraceWpStatus/i },
    { id: 'wp-db', sev: 'high', title: 'Database error', re: /(\bDB\b|database)[^\n]{0,40}(error|connect|lost|deadlock|failed)|SQL ?(error|code)|ORA-\d+|SQL\d{4,}|DBIF_/i },
    { id: 'wp-memory', sev: 'high', title: 'Memory bottleneck (roll / paging / extended memory / heap)', re: /(roll|paging|extended memory|heap|\bEM\b|shared memory)[^\n]{0,40}(full|exhausted|exceeded|no more|not enough|failed)|EsI\w+[^\n]{0,20}failed|ztta\/roll|abap\/heap_area/i },
    { id: 'wp-rfc', sev: 'medium', title: 'RFC / CPIC communication error', re: /CPIC|RFC_ERROR|RFC_COMMUNICATION|partner[^\n]{0,30}not reached|ThCPIC/i },
    { id: 'wp-timeout', sev: 'medium', title: 'Timeout', re: /TIME_OUT|max_wprun_time|time ?out/i },
    { id: 'wp-network', sev: 'medium', title: 'Network error (NI)', re: /NIE[A-Z_]{3,}/ },
    { id: 'wp-start', sev: 'info', minLevel: 'INFO', title: 'Instance / dispatcher start or stop', re: /(dispatcher|instance|server)[^\n]{0,30}(start(ed|ing)|stop(ped|ping)|shut(ting)? ?down)/i }
  ];
  const WP_MODULE = { id: 'wp', parsers: [TS.sapKernel.parser], rules: WP_RULES, rootCause: TS.sapKernel.rootCause };
  const OTHER_MODULE = { id: 'other', parsers: [], rules: [] };

  /* ---------- Facts from kernel traces (dev_icm / dev_webdisp) ----------
   * - server time zone: trace timestamps are server wall-clock time without zone; HTTP "date: … GMT" headers in the
   *   same trace are UTC → offset = wall − GMT (rounded to 15 min, median)
   * - coverage (first / last timestamp), trace level, own addresses, inbound peers, outbound targets, PSEs, CCL errors */
  const RE_KTS = /^\[Thr \d+\] \w{3} (\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d)(?::\d+)? (\d{4})\s*$/;
  const RE_GMT = /^\[Thr \d+\]\s+date:\s*\w{3}, (\d{1,2}) (\w{3}) (\d{4}) (\d\d):(\d\d):(\d\d) GMT/i;
  C.kernelFacts = function (text) {
    const f = { offs: [], tzOff: null, t0: null, t1: null, level: null, sid: null, locals: new Set(), inbound: new Map(), outbound: new Map(), pses: new Map(), ccl: new Map() };
    const lines = text.split(/\r?\n/);
    let wall = null, m;
    const hit = (map, k) => { const r = map.get(k) || { n: 0, t0: wall, t1: wall, extra: new Set() }; r.n++; if (wall != null) { if (r.t0 == null || wall < r.t0) r.t0 = wall; if (r.t1 == null || wall > r.t1) r.t1 = wall; } map.set(k, r); return r; };
    const lm = /trc level:?\s*(\d)|trace level\s*[:=]?\s*(\d)/i.exec(lines.slice(0, 60).join('\n'));
    if (lm) f.level = +(lm[1] || lm[2]);
    if ((m = /^\s*sid\s+([A-Z][A-Z0-9]{2})\s*$/m.exec(text.slice(0, 20000)))) f.sid = m[1];   // trace header "sid PR1"
    const srvPorts = new Set(), ni = [], niPeers = new Map();
    for (const line of lines) {
      if ((m = /Started service (\d+) for protocol|PORT=(\d+)\b/i.exec(line))) srvPorts.add(m[1] || m[2]);
      if (line.charCodeAt(0) !== 91) continue;                                  // "[Thr …]" lines only
      if ((m = RE_KTS.exec(line))) {
        wall = Date.UTC(+m[6], TS.monthIndex(m[1]), +m[2], +m[3], +m[4], +m[5]);
        if (f.t0 == null || wall < f.t0) f.t0 = wall;
        if (f.t1 == null || wall > f.t1) f.t1 = wall;
        continue;
      }
      if (wall != null && f.offs.length < 300 && (m = RE_GMT.exec(line))) {
        f.offs.push(Math.round((wall - Date.UTC(+m[3], TS.monthIndex(m[2]), +m[1], +m[4], +m[5], +m[6])) / 900000) * 15);
        continue;
      }
      if (line.includes('Connection Info: role=')) {
        if ((m = /role=Server, local=([^,]+?):(\d+), peer=([^,\s]+)/.exec(line))) { f.locals.add(m[1].toLowerCase()); srvPorts.add(m[2]); hit(f.inbound, m[3]).extra.add(`${m[1]}:${m[2]}`); }
        else if ((m = /role=Client, local=([^,]+?):\d+, peer=([^,\s]+)/.exec(line))) { f.locals.add(m[1].toLowerCase()); hit(f.outbound, m[2].toLowerCase()); }
      } else if (line.includes('SSL NI-hdl') && (m = /local=([\d.]+):(\d+)\s+peer=([\d.]+):(\d+)/.exec(line))) {
        f.locals.add(m[1]);
        ni.push({ local: m[1], port: m[2], peer: m[3], wall });
        const s = niPeers.get(m[2]) || new Set(); s.add(`${m[3]}:${m[4]}`); niPeers.set(m[2], s);
      } else if ((m = /SSL handshake with (\S+?):(\d+) failed/.exec(line))) hit(f.outbound, `${m[1].toLowerCase()}:${m[2]}`);
      else if ((m = /(cli|srv) SSL session PSE "([^"]+)"/.exec(line))) hit(f.pses, `${m[1] === 'cli' ? 'SSL client' : 'SSL server'}: ${m[2]}`);
      else if ((m = /CCL\[SSL\]:.*?Error (0x[0-9A-F]+)\((.*)\):?\s*$/i.exec(line))) hit(f.ccl, `${m[1]} ${m[2]}`);
    }
    // SSL handles: inbound only when the own port is a server port (ICM service, role=Server, or several different peers)
    for (const x of ni) {
      if (!srvPorts.has(x.port) && niPeers.get(x.port).size < 2) continue;
      wall = x.wall;
      hit(f.inbound, x.peer).extra.add(`${x.local}:${x.port}`);
    }
    if (f.offs.length) { const s = f.offs.slice().sort((a, b) => a - b); f.tzOff = s[s.length >> 1]; }
    return f;
  };

  function entryEvents(file, src, mod) {
    const p = TS.parseText(file.text, file.name, mod);
    const out = [];
    for (const e of p.entries) {
      const bad = e.level === 'FATAL' || e.level === 'ERROR' || e.level === 'WARN';
      const text = TS.entryText(e);
      const rule = matchRule(mod.rules || [], e, text);
      if (!bad && !rule) continue;
      if (e.t == null && !bad) continue;
      const rc = mod.rootCause ? mod.rootCause(e) : TS.rootException(e);
      out.push({
        t: e.t, off: e.off, src, file: file.name, line: e.line, level: bad ? e.level : 'INFO',
        code: rc ? rc.name : '', title: rule ? rule.title : e.message.slice(0, 220), rule: rule ? rule.id : '',
        sev: rule ? rule.sev : e.level === 'WARN' ? 'low' : 'medium',
        text: e.message, detail: e.detail || '', who: e.logger || '', thread: e.thread || ''
      });
    }
    const r = { events: out, note: `${p.parser.label}, ${p.entries.length} entries` };
    if (mod.proxyCerts) r.proxies = mod.proxyCerts(p.entries);
    if (mod.connFacts) {
      r.conns = mod.connFacts(p.entries);
      r.zoneAware = p.entries.some(e => e.off != null);
      const n = r.conns.filter(c => c.vhost).length;
      if (n) r.note += ` · ${n} backend request(s) to ${new Set(r.conns.map(c => c.vhost).filter(Boolean)).size} virtual host(s)`;
      else if (!p.entries.some(e => e.level === 'DEBUG')) r.note += ' · no DEBUG entries: set the SCC log level to "All"/"Debug" to see the backend requests';
    }
    return r;
  }

  function httpEvents(file) {
    const p = TS.parseText(file.text, file.name, OTHER_MODULE);
    const out = [];
    let total = 0;
    for (const e of p.entries) {
      if (!e.http) continue;
      total++;
      if (e.http.status < 400) continue;
      out.push({
        t: e.t, off: e.off, src: 'http', file: file.name, line: e.line, level: e.http.status >= 500 ? 'ERROR' : 'WARN',
        code: 'HTTP ' + e.http.status, title: `${e.http.status} ${e.http.request}`, rule: '', sev: e.http.status >= 500 ? 'medium' : 'low',
        text: e.message, detail: '', who: e.http.client, thread: ''
      });
    }
    return { events: out, note: `${total} requests, ${out.length} with status ≥ 400` };
  }

  /* ---------- SM21 ---------- */
  const SM21_RULES = [
    { id: 'sm21-dump', level: 'ERROR', title: 'ABAP runtime error (see ST22)', re: /runtime error|short dump|ABAP\/4 processor|^AB[0-9]$/i },
    { id: 'sm21-wp', level: 'ERROR', title: 'Work process terminated / restarted', re: /work process|\bWP\b[^\n]{0,30}(restart|terminat|died|ended)|process[^\n]{0,30}(terminated|died|restarted)/i },
    { id: 'sm21-memory', level: 'ERROR', title: 'Memory bottleneck', re: /(memory|roll|paging|heap|extended memory)[^\n]{0,40}(exhausted|full|exceeded|no more|bottleneck|not enough)/i },
    { id: 'sm21-db', level: 'ERROR', title: 'Database error', re: /database|\bDB\b[^\n]{0,20}(error|connect)|SQL|ORA-\d|deadlock|DBIF/i },
    { id: 'sm21-ssl', level: 'ERROR', title: 'SSL / certificate problem', re: /\bSSL\b|certificate|SSSLERR|\bPSE\b/i },
    { id: 'sm21-comm', level: 'ERROR', title: 'Communication / RFC error', re: /communication error|CPIC|connection[^\n]{0,20}(closed|lost|broken)|partner[^\n]{0,30}not reached|NIE[A-Z]|\bRFC\b/i },
    { id: 'sm21-logon', level: 'WARN', title: 'Logon failure / user locked', re: /log ?on|login|password|locked|sign ?on/i },
    { id: 'sm21-http', level: 'WARN', title: 'HTTP / ICM / ICF event', re: /\bHTTP\b|\bICM\b|\bICF\b/i },
    { id: 'sm21-start', level: 'WARN', title: 'Instance / server start or stop', re: /(server|instance|system)[^\n]{0,30}(start|stop|shut)/i }
  ];

  function tableEvents(file, src, opts) {
    const tbl = TS.tables.parse(file.text);
    if (!tbl) return { events: [], note: 'no table header found (export with column headers)' };
    const map = TS.tables.mapColumns(tbl.header);
    const col = (r, k) => (map[k] != null ? (r[map[k]] || '').trim() : '');
    const out = [];
    let noTime = 0;
    tbl.rows.forEach((r, i) => {
      const t = map.stamp != null ? TS.tables.parseDateTime(col(r, 'stamp'), '', opts.datefmt) : TS.tables.parseDateTime(col(r, 'date'), col(r, 'time'), opts.datefmt);
      if (t == null) noTime++;
      const ctx = { user: col(r, 'user'), host: col(r, 'host'), client: col(r, 'client'), program: col(r, 'program'), tcode: col(r, 'tcode') };
      const who = [ctx.user && 'user ' + ctx.user, ctx.client && 'client ' + ctx.client, ctx.host].filter(Boolean).join(' · ');
      if (src === 'st22') {
        const rt = col(r, 'runtime') || 'Runtime error', ex = col(r, 'exception');
        out.push({
          t, src, file: file.name, line: i + 1, level: 'ERROR', code: rt, title: `Dump ${rt}${ex ? ' (' + ex + ')' : ''}`, rule: 'st22',
          sev: 'high', text: [rt, ex, ctx.program && 'program ' + ctx.program, who].filter(Boolean).join(' · '), detail: tbl.header.map((h, k) => `${h}: ${r[k] || ''}`).join('\n'), who, thread: ''
        });
      } else {
        const text = col(r, 'text') || r.filter(Boolean).join(' '), id = col(r, 'msgid');
        const rule = SM21_RULES.find(x => x.re.test(text) || (id && x.re.test(id)));
        out.push({
          t, src, file: file.name, line: i + 1, level: rule ? rule.level : 'WARN', code: id ? 'SM21 ' + id : '', title: rule ? rule.title : text.slice(0, 220),
          rule: rule ? rule.id : '', sev: rule && rule.level === 'ERROR' ? 'medium' : 'low',
          text: text + (who ? ' · ' + who : ''), detail: tbl.header.map((h, k) => `${h}: ${r[k] || ''}`).join('\n'), who, thread: ''
        });
      }
    });
    return { events: out, note: `${tbl.rows.length} rows (${tbl.delim === '\t' ? 'tab' : tbl.delim} separated)${noTime ? `, ${noTime} without recognizable date/time — check the date format` : ''}` };
  }

  /* ---------- SM59 connection tests ---------- */
  const STOP = /^(ACTION|RESULT|HTTP|RFC|FOR|TYPE|DESTINATION|CONNECTION|TEST)$/i;
  C.parseSm59 = function (text, opts) {
    // a new test starts at "Connection Test <destination>" — not at the column header "Connection Test Action  Result"
    const chunks = text.split(/(?=^\s*Connection Test\b(?!\s+Action\b))/im).filter(c => c.trim());
    const tests = [];
    for (const ch of chunks) {
      let dest = '', m;
      const reD = /(?:RFC |HTTP |Logical )?Destination\s*:?\s+([A-Z0-9_\-\/.]{2,})/gi;
      while ((m = reD.exec(ch))) if (!STOP.test(m[1])) { dest = m[1]; break; }
      if (!dest) { const re2 = /Connection Test(?:\s+for)?((?:\s+[A-Z0-9_\-\/.]{2,})+)/i.exec(ch); if (re2) dest = re2[1].trim().split(/\s+/).find(w => !STOP.test(w)) || ''; }
      const status = (/(?:Status HTTP Response|HTTP Response|Status Code)\s*:?\s+(\d{3})\b/i.exec(ch) || [])[1];
      const codes = new Set();
      const reC = new RegExp(TS.sapKernel.RE_CODE.source, 'g');
      while ((m = reC.exec(ch))) codes.add(m[1]);
      const errors = ch.split(/\r?\n/).map(l => l.trim()).filter(l => /error|fail|not reached|incorrect|refused|denied|time ?out|unknown host|untrusted|SSSLERR|ICM_HTTP_|exception|not possible/i.test(l)).slice(0, 6);
      const durations = [];
      const reM = /([A-Za-z][A-Za-z ]{2,40}?)\s+(\d+(?:[.,]\d+)?)\s*msec/g;
      while ((m = reM.exec(ch))) durations.push(`${m[1].trim()} ${m[2]} ms`);
      const dt = /(\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})[ ,]+(\d{1,2}:\d{2}:\d{2})/.exec(ch);
      let t = dt ? TS.tables.parseDateTime(dt[1], dt[2], opts.datefmt) : null, timeFrom = dt ? 'result' : '';
      if (t == null && opts.mtime) { t = wallClock(opts.mtime); timeFrom = 'file date'; }
      if (!dest && !status && !codes.size && !errors.length && !durations.length) continue;
      const ok = !codes.size && !errors.length && (!status || +status < 400);
      tests.push({ dest: dest || '(unknown destination)', status: status ? +status : null, codes: [...codes], errors, durations, ok, t, timeFrom, raw: ch.trim() });
    }
    return tests;
  };

  /* ---------- Build all sources ---------- */
  /* opts.tz: 'auto' (default) or the UTC offset of the SAP servers in minutes. Time base of the dashboard = SAP server
   * local time (as in dev_* traces, SM21, ST22); logs with an explicit zone (Cloud Connector, access logs) are converted. */
  C.build = function (files, opts) {
    const events = [], certs = [], tests = [], conns = [], kernels = [], handshakes = [], proxies = [];
    const results = files.map(f => {
      let r = { events: [], note: '' };
      try {
        switch (f.src) {
          case 'icm': case 'wdp': {
            r = entryEvents(f, f.src, TS.getModule(f.src));
            r.facts = C.kernelFacts(f.text);
            // certificates referenced in the handshakes (subject / issuer / serial, CCL blocks with validity)
            try { r.certs = TS.x509.parseText(f.text, f.name).filter(c => c.observed); r.certs.forEach(c => { c.source = f.name; c.container = 'SAP trace (handshake)'; }); } catch (e) { r.certs = []; }
            const k = r.facts;
            r.note += `${k.level != null ? ` · trace level ${k.level}` : ''}${k.t0 != null ? ` · covers ${TS.fmtTime(k.t0)} – ${TS.fmtTime(k.t1).slice(11)}` : ''}${r.certs.length ? ` · ${r.certs.length} certificate reference(s)` : ''}`;
            break;
          }
          case 'wp': r = entryEvents(f, 'wp', WP_MODULE); break;
          case 'scc':
            r = entryEvents(f, 'scc', TS.getModule('scc'));
            // TLS trace: CA list of the backends and whether the system certificate was sent (certificates tool: client certificate check)
            try { r.handshakes = TS.x509.handshakesFromText(f.text, f.name); } catch (e) { r.handshakes = []; }
            break;
          case 'other': r = entryEvents(f, 'other', OTHER_MODULE); break;
          case 'http': r = httpEvents(f); break;
          case 'sm21': case 'st22': r = tableEvents(f, f.src, opts); break;
          case 'sm59': {
            const ts = C.parseSm59(f.text, { datefmt: opts.datefmt, mtime: f.mtime });
            ts.forEach(x => { x.file = f.name; tests.push(x); });
            r.events = ts.map((x, i) => ({
              t: x.t, src: 'sm59', file: f.name, line: i + 1, level: x.ok ? 'INFO' : 'ERROR', code: x.codes[0] || (x.status ? 'HTTP ' + x.status : ''),
              title: `SM59 test ${x.dest}: ${x.ok ? 'OK' : 'failed'}`, rule: 'sm59', sev: x.ok ? 'info' : 'high',
              text: [x.status && 'HTTP ' + x.status, ...x.codes, ...x.errors].filter(Boolean).join(' · ') || x.durations.join(', '), detail: x.raw, who: x.dest, thread: '', test: x
            }));
            r.note = `${ts.length} connection test(s)${ts.some(x => x.timeFrom === 'file date') ? ', time taken from the file date' : ''}`;
            break;
          }
          case 'strust': {
            r.certs = TS.x509.parseText(f.text, f.name);
            r.note = `${r.certs.length} certificate(s)`;
            break;
          }
        }
      } catch (err) { console.error(err); r = { events: [], note: 'error: ' + err.message }; }
      return r;
    });

    // server time zone
    const detected = files.map((f, i) => ({ f, off: results[i].facts && results[i].facts.tzOff })).filter(x => x.off != null);
    const zoneAware = files.filter((f, i) => results[i].zoneAware || results[i].events.some(e => e.off != null));
    let tz;
    if (opts.tz != null && opts.tz !== 'auto') tz = { off: +opts.tz, how: 'set manually' };
    else if (detected.length) {
      const offs = new Map(); detected.forEach(x => offs.set(x.off, (offs.get(x.off) || 0) + 1));
      tz = { off: [...offs].sort((a, b) => b[1] - a[1])[0][0], how: `detected from HTTP "Date: … GMT" headers in ${detected.map(x => base(x.f.name)).join(', ')}`, conflict: offs.size > 1 ? detected.map(x => `${base(x.f.name)} ${TS.fmtOffset(x.off)}`) : null };
    } else tz = { off: null, how: zoneAware.length && files.some(f => ['icm', 'wdp', 'wp', 'sm21', 'st22'].includes(f.src)) ? 'unknown' : 'not needed' };
    tz.converted = tz.off != null ? zoneAware.map(f => base(f.name)) : [];
    tz.unconverted = tz.off == null ? zoneAware.map(f => base(f.name)) : [];
    const conv = t => (t == null || tz.off == null ? t : t + tz.off * 60000);

    files.forEach((f, i) => {
      const r = results[i], shift = (+f.shiftH || 0) * 3600e3;
      r.events.forEach(e => { if (e.t != null) { if (e.off != null) e.t = conv(e.t); e.t += shift; } });
      if (r.conns) r.conns.forEach(c => { c.file = f.name; if (r.zoneAware) { c.t0 = conv(c.t0); c.t1 = conv(c.t1); } if (shift && c.t0 != null) { c.t0 += shift; c.t1 += shift; } conns.push(c); });
      if (r.facts) {
        const k = r.facts;
        if (shift && k.t0 != null) { k.t0 += shift; k.t1 += shift; [k.inbound, k.outbound, k.pses, k.ccl].forEach(mp => mp.forEach(x => { if (x.t0 != null) { x.t0 += shift; x.t1 += shift; } })); }
        kernels.push(Object.assign({ file: f.name, src: f.src }, k));
      }
      if (shift && f.src === 'sm59') tests.filter(x => x.file === f.name && x.t != null).forEach(x => { x.t += shift; });
      (r.certs || []).forEach(c => certs.push(c));
      (r.handshakes || []).forEach(h => handshakes.push(h));
      (r.proxies || []).forEach(p => proxies.push(Object.assign({ file: f.name }, p)));
      const ts = r.events.map(e => e.t).filter(t => t != null);
      Object.assign(f, {
        note: r.note, eventCount: r.events.length, tzConverted: r.zoneAware && tz.off != null,
        errCount: r.events.filter(e => e.level === 'ERROR' || e.level === 'FATAL').length,
        tMin: ts.length ? Math.min(...ts) : null, tMax: ts.length ? Math.max(...ts) : null
      });
      for (const e of r.events) { e.endpoints = C.endpoints(e.text); events.push(e); }
    });
    events.sort((a, b) => (a.t == null) - (b.t == null) || (a.t || 0) - (b.t || 0));
    events.forEach((e, i) => { e.id = i; });
    const ts = events.map(e => e.t).filter(t => t != null);
    return { events, certs: TS.certs ? TS.certs.dedupe(certs) : certs, tests, conns, kernels, handshakes, proxies, tz, tMin: ts.length ? Math.min(...ts) : null, tMax: ts.length ? Math.max(...ts) : null };
  };

  /* ---------- Findings & solutions (analysis range, all sources) ----------
   * 1. knowledge-base rules of every source (why + recommended actions from the modules), with evidence
   * 2. cross-source checks: Cloud Connector requests ↔ ICM / Web Dispatcher trace (reached? covered?), time zones */
  const rulesOf = src => (src === 'wp' ? WP_RULES : (TS.getModule(src) || {}).rules || []);
  const span = list => { const ts = list.filter(t => t != null); return ts.length ? [Math.min(...ts), Math.max(...ts)] : [null, null]; };
  const range = (a, b) => (a == null ? '-' : `${TS.fmtTime(a)}${b != null && b !== a ? ' – ' + TS.fmtTime(b).slice(TS.fmtTime(a).slice(0, 10) === TS.fmtTime(b).slice(0, 10) ? 11 : 0) : ''}`);
  C.findings = function (data, from, to) {
    const inR = t => t == null || ((from == null || t >= from) && (to == null || t < to));
    const evs = data.events.filter(e => inR(e.t));
    const F = [];

    // 1. knowledge base
    const grp = new Map();
    for (const e of evs) {
      if (!e.rule || !['scc', 'icm', 'wdp', 'wp'].includes(e.src)) continue;
      const k = e.src + '|' + e.rule;
      if (!grp.has(k)) grp.set(k, { src: e.src, rule: e.rule, events: [] });
      grp.get(k).events.push(e);
    }
    for (const g of grp.values()) {
      const r = rulesOf(g.src).find(x => x.id === g.rule);
      if (!r || r.sev === 'info') continue;
      const [t0, t1] = span(g.events.map(e => e.t));
      F.push({ id: `${g.src}:${r.id}`, sev: r.sev, title: r.title, srcs: [g.src], count: g.events.length, t0, t1, why: r.why || '', fix: r.fix || [], evidence: [], q: r.title });
    }
    const find = id => F.find(f => f.id === id);

    // evidence: Cloud Connector mappings that receive SSO tokens without principal propagation
    const pp = find('scc:pp-not-configured');
    if (pp) {
      const by = new Map();
      data.conns.filter(c => c.pp && inR(c.t0)).forEach(c => {
        const k = [c.vhost, c.target, c.mode, c.sub].join('|');
        const r = by.get(k) || { c, n: 0, ts: [], redirect: new Set(), paths: new Map() };
        r.n++; r.ts.push(c.t0, c.t1); if (c.redirect) r.redirect.add(c.redirect); if (c.path) { const p = c.path.split('/').slice(0, 6).join('/'); r.paths.set(p, (r.paths.get(p) || 0) + 1); }
        by.set(k, r);
      });
      [...by.values()].sort((a, b) => b.n - a.n).forEach(r => {
        const [a, b] = span(r.ts);
        pp.evidence.push(`${r.c.vhost || '?'}${r.c.target ? ' → ' + r.c.target : ''} · ${r.c.mode || 'principal type None'} · subaccount ${r.c.sub || '?'} · ${r.n} request(s) ${range(a, b)}` +
          (r.redirect.size ? ` · backend redirected to ${[...r.redirect].join(', ')} (SAML logon instead of the propagated user)` : '') +
          ` · ${[...r.paths].sort((x, y) => y[1] - x[1]).slice(0, 2).map(([p, n]) => `${p} (${n}×)`).join(', ')}`);
      });
      // only a failure when the backend then did not log the user on (redirect to the IdP)
      const n = [...by.values()].reduce((s, r) => s + r.n, 0);
      if (n && ![...by.values()].some(r => r.redirect.size)) {
        pp.sev = 'medium';
        pp.why += ` None of these ${n} request(s) was redirected to the IdP: the backend logged on in another way (technical user, basic / OAuth) — harmless when that is intended; configure principal propagation only when the backend must see the cloud user.`;
      }
    }
    // evidence: expired own certificate from the trace (subject, validity, PSE)
    for (const src of ['icm', 'wdp']) {
      const own = find(`${src}:ssl-own-cert-expired`);
      if (!own) continue;
      data.certs.filter(c => c.observed && c.notAfter != null && c.observed.some(o => /own certificate/i.test(o.what)))
        .forEach(c => {
          const pses = [...new Set(c.observed.map(o => o.pse).filter(Boolean))];
          own.evidence.push(`${c.subject} · valid ${c.notBefore != null ? TS.fmtTime(c.notBefore).slice(0, 10) : '?'} – ${TS.fmtTime(c.notAfter).slice(0, 10)} (UTC)${pses.length ? ' · PSE ' + pses.join(', ') : ''} · seen ${c.observed.length}×`);
        });
      data.kernels.filter(k => k.src === src).forEach(k => k.outbound.forEach((x, host) => { if (/:\d+$/.test(host)) own.evidence.push(`Failing target: ${host} (${x.n} handshake(s) ${range(x.t0, x.t1)})`); }));
      const sym = find(`${src}:ssl-no-response`);
      if (sym) {
        sym.sev = 'medium';
        sym.evidence.unshift(`Consequence, not the cause: the same handshakes fail because of "${own.title}" — fix that finding first; SSSLERR_SSL_READ / HTTP 500 "Native SSL Error" (ICM_HTTP_SSL_ERROR) then disappear.`);
      }
      // HTTP 500 "Native SSL Error" = ICM's own answer to the caller for the failed handshake
      const h5 = find(`${src}:http-5xx`);
      if (h5 && own.t0 != null && h5.t0 >= own.t0 - 2000 && h5.t1 <= own.t1 + 2000) {
        h5.sev = 'low';
        h5.evidence.unshift(`Consequence, not the cause: ICM answers the failed outbound handshakes with "HTTP 500 Native SSL Error" (ICM_HTTP_SSL_ERROR) to the calling ABAP program — see "${own.title}".`);
      }
    }

    // 2. Cloud Connector ↔ ICM / Web Dispatcher trace
    const conns = data.conns.filter(c => c.vhost && inR(c.t0));
    if (conns.length && data.kernels.length) {
      const sccIps = [...new Set(conns.map(c => c.sccIp).filter(Boolean))];
      let matchedAny = false;
      for (const k of data.kernels) {
        const host = h => String(h || '').split(':')[0].toLowerCase();
        const mine = conns.filter(c => (c.backendIp && k.locals.has(c.backendIp)) || (c.target && k.locals.has(host(c.target))));
        if (!mine.length) continue;
        matchedAny = true;
        const fn = base(k.file), lbl = C.label(k.src), tg = [...new Set(mine.map(c => c.target).filter(Boolean))].join(', ');
        const [a, b] = span([].concat(...mine.map(c => [c.t0, c.t1])));
        const seen = sccIps.filter(ip => k.inbound.has(ip));
        const inWin = mine.filter(c => c.t0 != null && k.t0 != null && c.t0 <= k.t1 + 1000 && c.t1 >= k.t0 - 1000);
        const ppN = mine.filter(c => c.pp).length;
        if (seen.length) {
          F.push({ id: `x:scc-reached:${fn}`, sev: 'info', title: `Cloud Connector requests reach the ${lbl} (${fn})`, srcs: ['scc', k.src], count: mine.length, t0: a, t1: b,
            why: `The SCC host (${seen.join(', ')}) appears as client in ${fn}. Handshake and logon of these requests can be checked in the trace.${ppN ? ` ${ppN} of them were sent without a user certificate (principal propagation not configured), so the backend cannot log on the cloud user.` : ''}`,
            fix: [], evidence: seen.map(ip => { const x = k.inbound.get(ip); return `${ip} → ${[...x.extra].join(', ')} · ${x.n} connection line(s) ${range(x.t0, x.t1)}`; }), q: seen[0] });
        } else if (inWin.length) {
          F.push({ id: `x:scc-missing:${fn}`, sev: 'high', title: `Cloud Connector requests to ${tg} are not visible in ${fn}`, srcs: ['scc', k.src], count: inWin.length, t0: a, t1: b,
            why: `${inWin.length} SCC request(s) to ${tg} fall into the trace window of ${fn} (${range(k.t0, k.t1)}), but no connection from the SCC host${sccIps.length ? ' (' + sccIps.join(', ') + ')' : ''} appears there. Either the requests reached another instance / went through a Web Dispatcher or load balancer (the peer is then that component), the connection was blocked before ICM (firewall, wrong port in the SCC mapping), or the ICM trace level is too low to log connections${k.level != null ? ` (trace level ${k.level})` : ''}.`,
            fix: ['Check the system mapping in the Cloud Connector (Cloud To On-Premise → Access Control): internal host and port must be the ICM HTTPS port of this instance (or the Web Dispatcher in front of it).',
              'Run "Check availability of internal host" in the SCC mapping; from the SCC host: curl -v https://<internal host>:<port>/sap/public/ping.',
              'Set the ICM trace level to 2 (SMICM → Goto → Trace Level), reset the trace, reproduce, and look for peer=<SCC IP> — on every application server instance if there are several.'],
            evidence: [`SCC backend connections: ${[...new Set(mine.map(c => `${c.target} (${c.backendIp || '?'})`))].join(', ')} from ${sccIps.join(', ') || '?'}`, `Clients seen in ${fn}: ${[...k.inbound.keys()].slice(0, 8).join(', ') || 'none'}`], q: '' });
        } else {
          F.push({ id: `x:scc-uncovered:${fn}`, sev: 'medium', title: `${fn} does not cover the time of the Cloud Connector requests`, srcs: ['scc', k.src], count: mine.length, t0: a, t1: b,
            why: `The Cloud Connector sent ${mine.length} request(s) to ${tg} between ${range(a, b)} (server time)${ppN ? `, ${ppN} of them without user certificate` : ''}, but ${fn} only covers ${range(k.t0, k.t1)}${k.level != null ? ` at trace level ${k.level}` : ''}. Whether these requests reached ICM, and how the backend answered, cannot be checked with this trace.`,
            fix: ['SMICM → Goto → Trace Level → Set to 2 (3 for TLS handshake details) → Goto → Trace File → Reset.',
              'Cloud Connector → Configuration → Log And Trace Files: set the Cloud Connector loggers to "All" (needed for the backend requests in scc_core / ljs_trace).',
              'Reproduce from SAP BTP with the same application / user, then download dev_icm and the SCC logs immediately (dev_icm rotates quickly at level 3) and reset both trace levels.',
              'Load both files here — the time zone is aligned automatically.'],
            evidence: [`SCC requests: ${range(a, b)} → ${tg}`, `${fn}: ${range(k.t0, k.t1)}`], q: '' });
        }
      }
      if (!matchedAny) {
        const targets = [...new Set(conns.map(c => `${c.target || c.vhost}${c.backendIp ? ' (' + c.backendIp + ')' : ''}`))];
        // requests that matter for logon problems (principal propagation, redirect to the IdP) make a trace of the wrong instance worth fixing first
        const auth = conns.filter(c => c.redirect || c.pp || c.x509);
        const authHosts = [...new Set(auth.map(c => `${(c.target || c.vhost || '').replace(/:\d+$/, '')}${c.backendIp ? ' / ' + c.backendIp : ''}`))].join(', ');
        F.push({ id: 'x:scc-other-hosts', sev: auth.length ? 'medium' : 'low', title: 'The loaded ICM / Web Dispatcher traces are from other hosts than the Cloud Connector backends', srcs: ['scc'].concat(data.kernels.map(k => k.src)), count: conns.length, t0: null, t1: null,
          why: 'None of the internal hosts the Cloud Connector connected to is an address of the loaded kernel traces, so requests cannot be followed from SCC into the backend.' +
            (auth.length ? ` This includes ${auth.length} request(s) with principal propagation / redirect to the IdP to ${authHosts} — their logon (trusted reverse proxy, forwarded certificate, CERTRULE) is only visible in the dev_icm of that instance.` : ''),
          fix: [`SM51 → the application server running on ${authHosts || 'the internal host of the SCC mapping'} → double-click: SMICM then works on that instance (the current SMICM / AL11 dev_icm belongs to the instance you are logged on to).`,
            'SMICM → Goto → Trace Level → Set → 2 → Goto → Trace File → Reset; reproduce from SAP BTP; Goto → Trace File → Display All (or download dev_icm from the work directory of that instance), then reset the trace level.',
            'Load that dev_icm here together with the SCC logs. If the internal host is a load balancer / Web Dispatcher, load its dev_webdisp and the dev_icm of the instance it forwarded to.'],
          evidence: [`SCC backends: ${targets.slice(0, 6).join(', ')}`].concat(data.kernels.map(k => `${base(k.file)}: ${[...k.locals].slice(0, 6).join(', ') || 'no own address found'}`)), q: '' });
      }
    }

    // 3. time zones
    if (data.tz && data.tz.off == null && data.tz.how === 'unknown')
      F.push({ id: 'x:tz', sev: 'medium', title: 'Time zones could not be aligned', srcs: [], count: data.tz.unconverted.length, t0: null, t1: null,
        why: `${data.tz.unconverted.join(', ')} log${data.tz.unconverted.length === 1 ? 's' : ''} with an explicit time zone (Cloud Connector: usually UTC), while the SAP traces / exports use the server's local time without zone, and the server offset could not be detected (no HTTP "Date" headers in the traces).`,
        fix: ['Select the SAP server time zone in the Sources card ("Server time zone"), or use "Shift (h)" for single files.'], evidence: [], q: '' });
    if (data.tz && data.tz.conflict)
      F.push({ id: 'x:tz-conflict', sev: 'low', title: 'Traces report different server time zones', srcs: [], count: data.tz.conflict.length, t0: null, t1: null,
        why: 'The HTTP Date headers give different offsets per trace — the servers run in different time zones, or a trace contains forwarded responses with stale Date headers.',
        fix: ['Check the offsets; set the server time zone manually and use "Shift (h)" for the trace of the other zone.'], evidence: data.tz.conflict, q: '' });

    return F.sort((a, b) => TS.SEV_RANK[a.sev] - TS.SEV_RANK[b.sev] || b.count - a.count);
  };

  /* ---------- Incidents ---------- */
  const isBad = e => e.level === 'ERROR' || e.level === 'FATAL' || e.level === 'WARN';
  C.incidents = function (data, windowMs, from, to) {
    const evs = data.events.filter(e => e.t != null && isBad(e) && (from == null || e.t >= from) && (to == null || e.t < to));
    const clusters = [];
    let cur = null;
    for (const e of evs) {
      if (!cur || e.t - cur.t1 > windowMs) { cur = { t0: e.t, t1: e.t, events: [] }; clusters.push(cur); }
      cur.events.push(e); cur.t1 = e.t;
    }
    const out = [];
    for (const c of clusters) {
      c.bySrc = new Map();
      c.codes = new Map();
      for (const e of c.events) {
        c.bySrc.set(e.src, (c.bySrc.get(e.src) || 0) + 1);
        if (e.code) c.codes.set(e.code, (c.codes.get(e.code) || 0) + 1);
      }
      c.errors = c.events.filter(e => e.level !== 'WARN').length;
      if (!c.errors && c.bySrc.size < 2) continue;
      c.hints = C.correlate(c, data);
      c.score = c.bySrc.size * 10 + Math.min(c.errors, 50) + c.hints.filter(h => h.sev === 'critical' || h.sev === 'high').length * 5;
      c.sev = c.hints.length ? c.hints.map(h => h.sev).sort((a, b) => TS.SEV_RANK[a] - TS.SEV_RANK[b])[0] : c.errors ? 'medium' : 'low';
      out.push(c);
    }
    out.forEach((c, i) => { c.id = i; });
    return out;
  };

  /* ---------- Cross-source correlation rules ---------- */
  const fmt = t => TS.fmtTime(t, null, false);
  const top = (arr, n) => { const m = new Map(); arr.forEach(x => x && m.set(x, (m.get(x) || 0) + 1)); return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n || 3).map(([k, v]) => (v > 1 ? `${k} (${v}×)` : k)); };
  const srcList = evs => [...new Set(evs.map(e => C.label(e.src)))].join(', ');

  C.correlate = function (inc, data) {
    const evs = inc.events, hints = [];
    const txt = e => `${e.code} ${e.title} ${e.text}`;
    const pick = (re, srcs) => evs.filter(e => (!srcs || srcs.includes(e.src)) && re.test(txt(e)));

    // 1. SSL errors vs. STRUST certificates
    const ssl = pick(/SSSLERR_|ICM_HTTP_SSL_ERROR|SSL handshake|PKIX|SSLHandshake|certificate|\bPSE\b/i);
    const ccu = ssl.filter(e => /SSSLERR_CLIENT_CERT_UNTRUSTED/.test(e.code + ' ' + e.text) || e.rule === 'ssl-client-untrusted');
    if (ccu.length) {
      const sccToo = evs.some(e => e.src === 'scc') || data.events.some(e => e.src === 'scc' && /principal-propagation|ssl-handshake|pkix/.test(e.rule));
      hints.push({ sev: 'high', title: 'Client certificate not trusted by the SSL server PSE', text: `${ccu.length} inbound handshake(s) in ${srcList(ccu)} were rejected because the CA of the client certificate is not in the SSL server PSE of the port. ` +
        (data.certs.length ? `${data.certs.length} certificate(s) are loaded — check them in the Certificates tool → Trust check (trust store = SSL server PSE, plus the client certificate). ` : 'Load the SSL server PSE (SAPSSLS.pse) and the client certificate into the Certificates tool → Trust check. ') +
        (sccToo ? 'Cloud Connector is involved: the backend must trust the CA of the SCC system certificate and the SCC CA certificate used for principal propagation.' : 'Import the client\'s root/intermediate CA via STRUST → SSL server PSE → Add to Certificate List, then ICM Exit Soft.'), events: ccu });
    }
    if (ssl.length) {
      const codes = top(ssl.map(e => e.code).filter(c => /SSSLERR|SSL/.test(c)), 3).join(', ');
      if (data.certs.length) {
        const invalid = data.certs.filter(c => ['expired', 'notyet'].includes(TS.x509.status(c, inc.t0).key));
        if (invalid.length) hints.push({ sev: 'critical', title: 'Certificate(s) not valid at the time of the SSL errors', text: `${invalid.length} certificate(s) (loaded, or seen in the trace handshakes) were not valid on ${fmt(inc.t0)}: ${invalid.slice(0, 4).map(c => { const p = [...new Set((c.observed || []).map(o => o.pse).filter(Boolean))].map(base); return `${c.cn} (until ${fmt(c.notAfter)}${p.length ? ', PSE ' + p.join(', ') : ''})`; }).join('; ')}. Renew them in STRUST (own certificate: create request → CA → import response; SAP BTP client certificates: via the service key / setup of that service) and run SMICM → Exit Soft.`, events: ssl });
        else hints.push({ sev: 'high', title: 'SSL errors while all loaded certificates are valid', text: `SSL errors in ${srcList(ssl)}${codes ? ' (' + codes + ')' : ''}, but the ${data.certs.length} loaded STRUST certificate(s) are valid. For SSSLERR_PEER_CERT_UNTRUSTED the CA of the peer is missing in the SSL client PSE; for SSSLERR_SERVER_CERT_MISMATCH check the host name / SNI; otherwise compare TLS versions and ciphers.`, events: ssl });
      } else {
        hints.push({ sev: 'medium', title: 'SSL errors — certificates not loaded', text: `SSL errors in ${srcList(ssl)}${codes ? ' (' + codes + ')' : ''}. Load the STRUST certificates (export as .cer/.pem or copy the certificate list) to check their validity.`, events: ssl });
      }
    }

    // 2. ABAP dumps together with HTTP / ICM failures
    const dumps = evs.filter(e => e.src === 'st22');
    const httpErr = pick(/HTTP\/1\.[01] 5\d\d|ICM_HTTP_|PROCTIMEOUT|processing time ?out|HTTP 5\d\d|\b50[0234]\b|Dispatching/i, ['icm', 'wdp', 'http']);
    if (dumps.length && httpErr.length) hints.push({ sev: 'high', title: 'ABAP dumps coincide with HTTP errors', text: `${dumps.length} dump(s) (${top(dumps.map(e => e.code)).join(', ')}) at the same time as ${httpErr.length} HTTP error(s) in ${srcList(httpErr)}. The HTTP requests most likely fail because the ABAP processing terminated — open the dumps in ST22 (user, program, "Information on where terminated").`, events: dumps.concat(httpErr) });
    else if (dumps.length) hints.push({ sev: 'medium', title: 'ABAP dumps in this period', text: `${dumps.length} dump(s): ${top(dumps.map(e => e.code), 4).join(', ')}.`, events: dumps });

    // 3. Memory
    const mem = evs.filter(e => (e.src === 'st22' && /TSV_|NO_ROLL|MEMORY|STORAGE_PARAMETERS|SYSTEM_NO_SHM|NO_MORE_PAGING/i.test(e.code)) ||
      /\bMPI\b|out of memory|ENOMEM|roll area|paging|heap|extended memory|memory (exhausted|bottleneck)|Memory bottleneck/i.test(txt(e)));
    if (mem.length) {
      const n = new Set(mem.map(e => e.src)).size;
      hints.push({ sev: n >= 2 ? 'critical' : 'high', title: 'Memory bottleneck', text: `Memory-related errors in ${srcList(mem)}. Check ST02 / SM04 (memory per user), ICM memory pipes (SMICM → Goto → Memory Pipes) and the dumps of type TSV_* / SYSTEM_NO_ROLL.`, events: mem });
    }

    // 4. Work process / dispatcher problems behind HTTP failures
    const wpProb = evs.filter(e => e.src === 'wp' || (e.src === 'sm21' && /sm21-wp|sm21-db|sm21-memory/.test(e.rule)));
    const front = pick(/time ?out|TIMEOUT|no (free )?work process|\b50[0234]\b|no (backend )?server|unavailable|Dispatching|backend/i, ['icm', 'wdp', 'http']);
    if (wpProb.length && front.length) hints.push({ sev: 'high', title: 'Work process / dispatcher problems behind the HTTP failures', text: `${front.length} HTTP-side error(s) in ${srcList(front)} while ${srcList(wpProb)} report: ${top(wpProb.map(e => e.title), 3).join('; ')}. Check SM50/SM66 and dev_w* of that time.`, events: wpProb.concat(front) });

    // 5. Network
    const net = pick(/NIE[A-Z_]{3,}|connection refused|host unknown|NIEHOST_UNKNOWN|unreachable|partner[^\n]{0,30}not reached|ICM_HTTP_CONNECTION_FAILED|connect(ion)? timed? ?out/i);
    if (net.length) {
      const eps = top([].concat(...net.map(e => e.endpoints)), 3);
      const n = new Set(net.map(e => e.src)).size;
      hints.push({ sev: n >= 2 ? 'high' : 'medium', title: `Network / connectivity problem${eps.length ? ' to ' + eps[0].replace(/ \(\d+×\)$/, '') : ''}`, text: `${net.length} network error(s) in ${srcList(net)}${eps.length ? '; endpoints: ' + eps.join(', ') : ''}; codes: ${top(net.map(e => e.code).filter(Boolean)).join(', ') || '-'}. Test from the application server (niping / curl / SM59) and check firewall, DNS and proxy.`, events: net });
    }

    // 6. SM59 tests with the same error code
    const incCodes = new Set(inc.codes.keys());
    for (const t of data.tests.filter(x => !x.ok)) {
      const same = t.codes.filter(c => incCodes.has(c));
      const near = t.t != null && t.t >= inc.t0 - 3600e3 && t.t <= inc.t1 + 3600e3;
      if (same.length || (near && t.codes.length && ssl.length && t.codes.some(c => /SSL/.test(c)))) {
        hints.push({ sev: 'high', title: `SM59 test of ${t.dest} fails with the same error`, text: `Connection test of ${t.dest} failed (${(same.length ? same : t.codes).join(', ')})${t.t != null ? ' at ' + fmt(t.t) + (t.timeFrom === 'file date' ? ' (file date)' : '') : ''}. The destination problem reproduces outside the application — fix the connection first.`, events: [] });
      }
    }

    // 7. Web Dispatcher: backend unavailable + backend restart/stop
    const wdpBack = evs.filter(e => e.src === 'wdp' && /wdp-backend-down|wdp-no-system|wdp-serverlist|webdisp-backend|message-server/.test(e.rule));
    const lifecycle = data.events.filter(e => e.t != null && e.t >= inc.t0 - 600e3 && e.t <= inc.t1 + 600e3 &&
      (/wp-start|sm21-start|icm-restart|icm-crash|sm21-wp|wp-restart/.test(e.rule)));
    if (wdpBack.length) hints.push({ sev: 'high', title: 'Web Dispatcher could not reach a backend server', text: lifecycle.length ? `The Web Dispatcher reports backend problems while backend components were restarted/stopped (${top(lifecycle.map(e => C.label(e.src) + ': ' + e.title), 3).join('; ')}).` : `The Web Dispatcher reports backend problems (${top(wdpBack.map(e => e.title), 2).join('; ')}). Load dev_icm / dev_disp / SM21 of the backend servers for the same time to see why.`, events: wdpBack.concat(lifecycle) });

    // 8. Authentication
    const auth = pick(/\b401\b|\b403\b|log ?on fail|login fail|password|locked|CERTRULE|unauthori[sz]ed|client certificate|sm21-logon/i);
    if (auth.length >= 2) hints.push({ sev: 'medium', title: 'Authentication / authorization failures', text: `${auth.length} event(s) in ${srcList(auth)}. Check SU53 / ST01 for the user, SM21 logon messages and, for certificate logon, CERTRULE and trusted reverse proxy settings.`, events: auth });

    // 9. Cloud Connector tunnel outage
    const scc = evs.filter(e => e.src === 'scc' && /tunnel-down|proxy|pkix|cert-expired/.test(e.rule));
    if (scc.length) hints.push({ sev: 'high', title: 'Cloud Connector problem in the same period', text: `${top(scc.map(e => e.title), 2).join('; ')} — requests from SAP BTP cannot reach the backend while the tunnel is down.`, events: scc });

    // 10. Cloud Connector: SSO token without principal propagation → backend gets no user
    const ppEv = evs.filter(e => e.src === 'scc' && e.rule === 'pp-not-configured');
    if (ppEv.length) {
      const cs = (data.conns || []).filter(c => c.pp && c.t0 != null && c.t0 >= inc.t0 - 1000 && c.t0 <= inc.t1 + 1000);
      const vh = top(cs.map(c => `${c.vhost}${c.target ? ' → ' + c.target : ''}`), 3).join(', ');
      const redir = [...new Set(cs.map(c => c.redirect).filter(Boolean))];
      hints.push({ sev: 'high', title: 'Cloud Connector forwards requests without the cloud user', text: `${ppEv.length} request(s) from SAP BTP carried an SSO token, but the system mapping${vh ? ' ' + vh : ''} has principal type None — SCC sends them without user certificate, so the backend cannot log on the user${redir.length ? ` and redirects to the SAML IdP (${redir.join(', ')})` : ' (SAML redirect, 401 or anonymous session)'}. Either configure principal propagation (SCC CA certificate + X.509 principal type + trusted IdP; backend: STRUST, icm/trusted_reverse_proxy_<n>, CERTRULE) or change the destination authentication — see Findings & solutions.`, events: ppEv });
    }

    return hints.sort((a, b) => TS.SEV_RANK[a.sev] - TS.SEV_RANK[b.sev]);
  };
})(window.TS);
