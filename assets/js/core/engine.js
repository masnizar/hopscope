/* SAP Troubleshooting Toolkit - core engine
 * Generic log model, parser framework, file loading (plain / .zip / .gz) and analysis.
 * Component-specific knowledge (formats, rules, insights) lives in assets/js/modules/<id>.js
 */
(function (global) {
  'use strict';
  const TS = global.TS = global.TS || {};

  /* ---------- Module registry ---------- */
  TS.modules = [];
  TS.registerModule = function (m) { TS.modules.push(m); };
  TS.getModule = id => TS.modules.find(m => m.id === id);

  /* ---------- Levels ---------- */
  TS.LEVELS = ['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', 'OTHER'];
  TS.LEVEL_RANK = { FATAL: 0, ERROR: 1, WARN: 2, INFO: 3, DEBUG: 4, TRACE: 5, OTHER: 6 };
  const LEVEL_MAP = {
    FATAL: 'FATAL', CRITICAL: 'FATAL', CRIT: 'FATAL', EMERG: 'FATAL', ALERT: 'FATAL',
    SEVERE: 'ERROR', ERROR: 'ERROR', ERR: 'ERROR', E: 'ERROR',
    WARNING: 'WARN', WARN: 'WARN', W: 'WARN',
    INFO: 'INFO', INFORMATION: 'INFO', NOTICE: 'INFO', I: 'INFO',
    DEBUG: 'DEBUG', CONFIG: 'DEBUG', FINE: 'DEBUG', D: 'DEBUG',
    TRACE: 'TRACE', FINER: 'TRACE', FINEST: 'TRACE', ALL: 'TRACE', PATH: 'TRACE', T: 'TRACE'
  };
  TS.normLevel = s => (s ? LEVEL_MAP[String(s).trim().toUpperCase()] || null : null);
  // "WARN or worse" etc. OTHER (no level information) is always treated as eligible.
  TS.levelAtLeast = (lvl, min) => lvl === 'OTHER' || TS.LEVEL_RANK[lvl] <= TS.LEVEL_RANK[min];

  // Level keyword in a header region (e.g. "[Error]", " WARNING ", "|INFO|")
  const RE_LEVEL_WORD = /(?:^|[\s\[#|:<(])(FATAL|SEVERE|CRITICAL|ERROR|ERR|WARNING|WARN|INFO|INFORMATION|NOTICE|DEBUG|TRACE|FINEST|FINER|FINE|CONFIG)(?=$|[\s\]#|:>)])/i;
  TS.detectLevel = function (s) {
    const m = RE_LEVEL_WORD.exec(s);
    return m ? TS.normLevel(m[1]) : null;
  };

  /* ---------- Time helpers ---------- */
  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  TS.monthIndex = s => MONTHS[String(s).slice(0, 3).toLowerCase()];
  TS.parseTz = function (tz) {
    if (!tz) return null;
    if (/^(Z|UTC|GMT)$/i.test(tz)) return 0;
    const m = /^([+-])(\d{2}):?(\d{2})$/.exec(tz);
    if (!m) return null;
    const v = (+m[2]) * 60 + (+m[3]);
    return m[1] === '-' ? -v : v;
  };
  // Returns {t: epoch ms, off: tz offset in minutes or null}. Naive timestamps are kept as wall time (off=null).
  TS.mkTime = function (y, mo, d, h, mi, s, frac, tz) {
    const ms = frac ? parseInt((frac + '000').slice(0, 3), 10) : 0;
    let t = Date.UTC(+y, mo, +d, +h, +mi, +s, ms);
    const off = TS.parseTz(tz);
    if (off !== null) t -= off * 60000;
    return { t, off };
  };
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  // Format epoch in a fixed offset (minutes) so that times read like the original log.
  TS.fmtTime = function (t, off, withMs) {
    if (t == null || isNaN(t)) return '';
    const d = new Date(t + (off || 0) * 60000);
    let s = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    if (withMs) s += '.' + pad(d.getUTCMilliseconds(), 3);
    return s;
  };
  TS.fmtOffset = function (off) {
    if (off == null) return 'log local time (no zone)';
    const sign = off < 0 ? '-' : '+', a = Math.abs(off);
    return `UTC${sign}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
  };
  TS.fmtDuration = function (ms) {
    if (ms == null || isNaN(ms)) return '-';
    if (ms < 1000) return Math.round(ms) + ' ms';
    if (ms < 60000) return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + ' s';
    const s = Math.round(ms / 1000);
    const m = Math.floor(s / 60);
    if (m < 60) return m + ' min';
    const h = Math.floor(m / 60);
    if (h < 48) return h + ' h ' + (m % 60) + ' min';
    return Math.floor(h / 24) + ' d ' + (h % 24) + ' h';
  };

  /* ---------- Generic header parsers ----------
   * A parser is {id, label, header(line) -> header|null}.
   * header = {t, off, tsText, level, logger, thread, message}
   * Lines that are not a header are appended to the previous entry (stack traces, hex dumps, ...).
   */
  const RE_ISO = /^\[?(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,:](\d{1,9}))?\s*(Z|UTC|[+-]\d{2}:?\d{2})?\]?/;
  const RE_DMY = /^\[?(\d{2})\.(\d{2})\.(\d{4})[ ,]+(\d{2}):(\d{2}):(\d{2})(?:[.,:](\d{1,9}))?\]?/;
  const RE_TOMCAT = /^(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?/;
  const RE_SAPTHR = /^(?:[A-Z]\s+)?\[Thr\s+(\d+)\]\s+\w{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?::(\d{1,3}))?\s+(\d{4})/;
  const RE_ACCESS = /^(\S+) (\S+) (\S+) \[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? ([+-]\d{4})\] "([^"]*)" (\d{3}) (\S+)(.*)$/;

  function restAfter(line, m) {
    let rest = line.slice(m[0].length);
    return rest.replace(/^[\s\]#|:-]+/, '');
  }
  function genericHeader(line, m, t) {
    const rest = restAfter(line, m);
    const head = rest.slice(0, 40);
    const level = TS.detectLevel(head) || 'OTHER';
    // "[thread]" right after timestamp/level is common in Java logs
    const thr = /\[([^\]]{1,80})\]/.exec(head);
    return { t: t.t, off: t.off, tsText: m[0].replace(/^\[|\]$/g, ''), level, logger: '', thread: thr ? thr[1] : '', message: rest };
  }

  TS.coreParsers = [
    {
      id: 'access', label: 'HTTP access log (Common/Combined Log Format)',
      header(line) {
        const m = RE_ACCESS.exec(line);
        if (!m) return null;
        const t = TS.mkTime(m[6], TS.monthIndex(m[5]), m[4], m[7], m[8], m[9], m[10], m[11]);
        const st = +m[13];
        const level = st >= 500 ? 'ERROR' : st >= 400 ? 'WARN' : 'INFO';
        return { t: t.t, off: t.off, tsText: `${m[4]}/${m[5]}/${m[6]}:${m[7]}:${m[8]}:${m[9]} ${m[11]}`, level, logger: m[1], thread: m[3] === '-' ? '' : m[3], message: `${st} ${m[12]}${m[14] !== '-' ? ' (' + m[14] + ' bytes)' : ''}${m[15] ? ' ' + m[15].trim() : ''}`, http: { status: st, request: m[12], client: m[1] } };
      }
    },
    {
      id: 'tomcat', label: 'Tomcat / java.util.logging (dd-MMM-yyyy)',
      header(line) {
        const m = RE_TOMCAT.exec(line);
        if (!m) return null;
        const mo = TS.monthIndex(m[2]);
        if (mo === undefined) return null;
        return genericHeader(line, m, TS.mkTime(m[3], mo, m[1], m[4], m[5], m[6], m[7], null));
      }
    },
    {
      id: 'sap-thr', label: 'SAP kernel developer trace ([Thr ...])',
      header(line) {
        const m = RE_SAPTHR.exec(line);
        if (!m) return null;
        const mo = TS.monthIndex(m[2]);
        if (mo === undefined) return null;
        const t = TS.mkTime(m[8], mo, m[3], m[4], m[5], m[6], m[7], null);
        const rest = restAfter(line, m);
        return { t: t.t, off: t.off, tsText: m[0].replace(/^.*?\]\s+/, ''), level: TS.detectLevel(line.slice(0, 3)) || TS.detectLevel(rest.slice(0, 30)) || 'OTHER', logger: '', thread: m[1], message: rest };
      }
    },
    {
      id: 'iso', label: 'Generic (timestamp ISO yyyy-MM-dd HH:mm:ss)',
      header(line) {
        const m = RE_ISO.exec(line);
        if (!m) return null;
        return genericHeader(line, m, TS.mkTime(m[1], m[2] - 1, m[3], m[4], m[5], m[6], m[7], m[8]));
      }
    },
    {
      id: 'dmy', label: 'Generic (timestamp dd.MM.yyyy HH:mm:ss)',
      header(line) {
        const m = RE_DMY.exec(line);
        if (!m) return null;
        return genericHeader(line, m, TS.mkTime(m[3], m[2] - 1, m[1], m[4], m[5], m[6], m[7], null));
      }
    }
  ];
  // Fallback: every non-empty line is one entry
  TS.plainParser = {
    id: 'plain', label: 'Plain text (no timestamp, 1 line = 1 entry)',
    header(line) {
      if (!line.trim()) return null;
      return { t: null, off: null, tsText: '', level: TS.detectLevel(line.slice(0, 40)) || 'OTHER', logger: '', thread: '', message: line };
    }
  };

  /* ---------- Parsing ----------
   * header(line, ctx) may keep per-file state in ctx (e.g. SAP kernel traces, where a timestamp line
   * applies to the lines that follow it) and may return TS.SKIP for lines that are consumed but are not entries.
   */
  const MAX_EXTRA_LINES = 400;
  TS.SKIP = Object.freeze({ skip: true });

  TS.detectParser = function (lines, module, fileName) {
    const parsers = (module.parsers || []).concat(TS.coreParsers);
    const ft = TS.fileTypeOf(module, fileName);
    const sample = [];
    for (let i = 0; i < lines.length && sample.length < 600; i++) if (lines[i].trim()) sample.push(lines[i]);
    if (!sample.length) return { parser: TS.plainParser, ratio: 0 };
    let best = null, bestHits = 0;
    for (const p of parsers) {
      let hits = 0;
      const ctx = {};
      for (const l of sample) { try { if (p.header(l, ctx)) hits++; } catch (e) { /* ignore */ } }
      // Prefer the parser suggested by the file type on ties / near-ties
      const bonus = ft && ft.parser === p.id ? 1.05 : 1;
      if (hits * bonus > bestHits) { best = p; bestHits = hits * bonus; }
    }
    const ratio = Math.min(1, bestHits / sample.length);
    if (!best || ratio < 0.01) return { parser: TS.plainParser, ratio: 0 };
    return { parser: best, ratio };
  };

  TS.fileTypeOf = function (module, fileName) {
    const base = String(fileName).split(/[\\/]/).pop();
    return (module.fileTypes || []).find(ft => ft.match.test(base)) || null;
  };

  TS.parseText = function (text, fileName, module) {
    const lines = text.split(/\r?\n/);
    const { parser, ratio } = TS.detectParser(lines, module, fileName);
    const entries = [];
    let cur = null, extra = null;
    const ctx = {};
    const flush = () => {
      if (!cur) return;
      while (extra.length && !extra[extra.length - 1].trim()) extra.pop();
      cur.detail = extra.join('\n');
      entries.push(cur);
    };
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let h = null;
      if (line) { try { h = parser.header(line, ctx); } catch (e) { h = null; } }
      if (h === TS.SKIP) continue;
      if (h) {
        flush();
        cur = h; cur.file = fileName; cur.line = i + 1; extra = [];
      } else if (cur) {
        if (extra.length < MAX_EXTRA_LINES) extra.push(line);
        else cur.truncated = true;
      } else if (line.trim()) {
        // Preamble before the first header line
        cur = { t: null, off: null, tsText: '', level: 'OTHER', logger: '', thread: '', message: line, file: fileName, line: i + 1 };
        extra = [];
      }
    }
    flush();
    return { entries, parser, ratio, lineCount: lines.length };
  };

  /* ---------- File loading (plain, .gz, .zip) ---------- */
  const TEXT_EXT = /\.(log|trc|txt|out|err|csv|tsv|trace|xml|json|old|bak|pem|cer|crt|der|pse|p7b|p7c)(\.\d+)?$|\.\d+$|^[^.]+$/i;
  TS.isTextCandidate = name => TEXT_EXT.test(String(name).split(/[\\/]/).pop()) || /\.xlsx$/i.test(name);
  // binary certificate containers are passed on as base64 text; x509.parseText decodes / scans them
  const CERT_EXT = /\.(cer|crt|der|pem|pse|p7b|p7c)$/i;

  function toBase64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  }

  async function streamThrough(u8, format) {
    const ds = new DecompressionStream(format);
    return new Uint8Array(await new Response(new Blob([u8]).stream().pipeThrough(ds)).arrayBuffer());
  }

  // Minimal ZIP reader (store + deflate, ZIP64 aware) using the browser's DecompressionStream.
  TS.unzip = function (buf) {
    const dv = new DataView(buf), u8 = new Uint8Array(buf);
    let eocd = -1;
    for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('Invalid ZIP file (End of Central Directory not found)');
    let count = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
    if (cdOff === 0xFFFFFFFF || count === 0xFFFF) {
      const loc = eocd - 20;
      if (loc >= 0 && dv.getUint32(loc, true) === 0x07064b50) {
        const z64 = Number(dv.getBigUint64(loc + 8, true));
        if (dv.getUint32(z64, true) === 0x06064b50) {
          count = Number(dv.getBigUint64(z64 + 32, true));
          cdOff = Number(dv.getBigUint64(z64 + 48, true));
        }
      }
    }
    const dec = new TextDecoder();
    const items = [];
    let p = cdOff;
    for (let n = 0; n < count; n++) {
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true);
      let csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
      const nlen = dv.getUint16(p + 28, true), xlen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
      let lho = dv.getUint32(p + 42, true);
      const name = dec.decode(u8.subarray(p + 46, p + 46 + nlen));
      if (csize === 0xFFFFFFFF || usize === 0xFFFFFFFF || lho === 0xFFFFFFFF) {
        let q = p + 46 + nlen; const end = q + xlen;
        while (q + 4 <= end) {
          const id = dv.getUint16(q, true), sz = dv.getUint16(q + 2, true);
          if (id === 1) {
            let r = q + 4;
            if (usize === 0xFFFFFFFF) { usize = Number(dv.getBigUint64(r, true)); r += 8; }
            if (csize === 0xFFFFFFFF) { csize = Number(dv.getBigUint64(r, true)); r += 8; }
            if (lho === 0xFFFFFFFF) { lho = Number(dv.getBigUint64(r, true)); r += 8; }
          }
          q += 4 + sz;
        }
      }
      p += 46 + nlen + xlen + clen;
      if (name.endsWith('/')) continue;
      items.push({
        name, size: usize, encrypted: !!(flags & 1), method,
        async read() {
          if (this.encrypted) throw new Error('Encrypted ZIP is not supported');
          const start = lho + 30 + dv.getUint16(lho + 26, true) + dv.getUint16(lho + 28, true);
          const data = u8.subarray(start, start + csize);
          if (method === 0) return data;
          if (method === 8) return streamThrough(data, 'deflate-raw');
          throw new Error('ZIP compression method ' + method + ' is not supported');
        }
      });
    }
    return items;
  };

  function decodeText(u8) {
    // Skip binary content (NUL bytes in the first KB)
    const probe = u8.subarray(0, 1024);
    for (let i = 0; i < probe.length; i++) if (probe[i] === 0) return null;
    return new TextDecoder('utf-8').decode(u8);
  }

  /* Expand a list of File objects into [{name, text, size, mtime}] and [{name, reason}] for skipped ones.
   * .xlsx sheets are converted to tab-separated text (needs tables.js), binary DER certificates to PEM text. */
  TS.readInputs = async function (files, onProgress) {
    const out = [], skipped = [];
    async function handle(name, u8, mtime) {
      const lower = name.toLowerCase();
      if (lower.endsWith('.xlsx')) {
        if (!TS.xlsxToTsv) { skipped.push({ name, reason: 'Excel files are not supported on this page' }); return; }
        try { out.push({ name, text: await TS.xlsxToTsv(u8), size: u8.byteLength, mtime }); }
        catch (e) { skipped.push({ name, reason: 'cannot read Excel file: ' + e.message }); }
        return;
      }
      if (CERT_EXT.test(lower) && decodeText(u8) === null) {
        out.push({ name, text: '-----BEGIN CERTIFICATE-----\n' + toBase64(u8) + '\n-----END CERTIFICATE-----\n', size: u8.byteLength, mtime });
        return;
      }
      if (lower.endsWith('.zip')) {
        let items;
        try { items = TS.unzip(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)); }
        catch (e) { skipped.push({ name, reason: e.message }); return; }
        for (const it of items) {
          const inner = name + '!/' + it.name;
          if (!/\.(zip|gz)$/i.test(it.name) && !TS.isTextCandidate(it.name)) { skipped.push({ name: inner, reason: 'not a log/trace file' }); continue; }
          try { await handle(inner, await it.read()); }
          catch (e) { skipped.push({ name: inner, reason: e.message }); }
        }
        return;
      }
      if (lower.endsWith('.gz')) {
        try { return handle(name.slice(0, -3), await streamThrough(u8, 'gzip')); }
        catch (e) { skipped.push({ name, reason: 'gzip decompression failed: ' + e.message }); return; }
      }
      const text = decodeText(u8);
      if (text === null) { skipped.push({ name, reason: 'binary file' }); return; }
      out.push({ name, text, size: u8.byteLength, mtime });
    }
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const name = f.webkitRelativePath || f.name;
      if (onProgress) onProgress(`Reading ${name} (${i + 1}/${files.length})…`);
      if (!/\.(zip|gz)$/i.test(name) && !TS.isTextCandidate(name)) { skipped.push({ name, reason: 'not a log/trace file' }); continue; }
      await handle(name, new Uint8Array(await f.arrayBuffer()), f.lastModified || null);
    }
    return { out, skipped };
  };

  /* ---------- Analysis helpers ---------- */
  TS.signature = function (msg) {
    return String(msg).slice(0, 300)
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>')
      .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, '<ip>')
      .replace(/\b0x[0-9a-f]+\b/gi, '<hex>')
      .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
      .replace(/\d+/g, '<n>')
      .replace(/\s+/g, ' ')
      .trim();
  };

  const RE_EXC = /((?:[a-zA-Z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Fault|Throwable))(?::\s*([^\n]*))?/;
  const RE_CAUSED = /Caused by:\s*((?:[a-zA-Z_$][\w$]*\.)*[A-Z][\w$]*)(?::\s*([^\n]*))?/g;
  // Root cause exception: last "Caused by:", else first exception class mentioned.
  TS.rootException = function (e) {
    let last = null, m;
    if (e.detail) {
      RE_CAUSED.lastIndex = 0;
      while ((m = RE_CAUSED.exec(e.detail))) last = m;
      if (last) return { name: last[1], msg: (last[2] || '').trim() };
    }
    m = RE_EXC.exec(e.message) || (e.detail ? RE_EXC.exec(e.detail.slice(0, 4000)) : null);
    return m ? { name: m[1], msg: (m[2] || '').trim() } : null;
  };

  TS.entryText = e => (e.detail ? e.message + '\n' + e.detail.slice(0, 4000) : e.message);

  const BUCKETS = [60e3, 5 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 864e5, 7 * 864e5, 30 * 864e5];
  TS.pickBucket = function (span) {
    for (const b of BUCKETS) if (span / b <= 120) return b;
    return BUCKETS[BUCKETS.length - 1];
  };

  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  TS.SEV_RANK = SEV_RANK;

  /* Full analysis over all entries (already sorted, ids assigned). */
  TS.analyze = function (entries, module) {
    const res = {
      total: entries.length, levels: {}, files: {}, loggers: new Map(), loggersBad: new Map(), threads: new Map(),
      tMin: null, tMax: null, offset: null, groups: [], exceptions: [], findings: [], insights: null, hist: null
    };
    TS.LEVELS.forEach(l => (res.levels[l] = 0));
    const offCount = new Map();
    const groups = new Map(), excs = new Map();
    const rules = (module.rules || []).map((r, idx) => ({ r, idx, hit: null }));

    for (const e of entries) {
      res.levels[e.level]++;
      res.files[e.file] = (res.files[e.file] || 0) + 1;
      if (e.t != null) {
        if (res.tMin === null || e.t < res.tMin) res.tMin = e.t;
        if (res.tMax === null || e.t > res.tMax) res.tMax = e.t;
      }
      if (e.off != null) offCount.set(e.off, (offCount.get(e.off) || 0) + 1);
      if (e.logger) res.loggers.set(e.logger, (res.loggers.get(e.logger) || 0) + 1);
      if (e.thread) res.threads.set(e.thread, (res.threads.get(e.thread) || 0) + 1);

      const bad = e.level === 'FATAL' || e.level === 'ERROR' || e.level === 'WARN';
      let text = null;
      if (bad) {
        if (e.logger) res.loggersBad.set(e.logger, (res.loggersBad.get(e.logger) || 0) + 1);
        const sig = TS.signature(e.message);
        const gk = e.level + '|' + e.logger + '|' + sig;
        e.gk = gk;
        let g = groups.get(gk);
        if (!g) groups.set(gk, g = { key: gk, level: e.level, logger: e.logger, sig, count: 0, first: e.t, last: e.t, sample: e.id, files: new Set() });
        g.count++; g.files.add(e.file);
        if (e.t != null) { if (g.first == null || e.t < g.first) g.first = e.t; if (g.last == null || e.t > g.last) g.last = e.t; }

        const ex = module.rootCause ? module.rootCause(e) : TS.rootException(e);
        if (ex) {
          e.exn = ex.name;
          let x = excs.get(ex.name);
          if (!x) excs.set(ex.name, x = { name: ex.name, count: 0, msg: ex.msg, sample: e.id, first: e.t, last: e.t });
          x.count++;
          if (e.t != null) { if (x.first == null || e.t < x.first) x.first = e.t; if (x.last == null || e.t > x.last) x.last = e.t; }
        }
      }
      for (const rr of rules) {
        const r = rr.r;
        if (!TS.levelAtLeast(e.level, r.minLevel || 'WARN')) continue;
        if (r.logger && !r.logger.test(e.logger)) continue;
        if (text === null) text = TS.entryText(e);
        if (!r.re.test(text) || (r.exclude && r.exclude.test(text))) continue;
        if (!rr.hit) rr.hit = { rule: r, count: 0, first: e.t, last: e.t, ids: [], files: new Set(), sample: e.id };
        const h = rr.hit;
        h.count++; h.ids.push(e.id); h.files.add(e.file);
        if (e.t != null) { if (h.first == null || e.t < h.first) h.first = e.t; if (h.last == null || e.t > h.last) h.last = e.t; }
        (e.rules || (e.rules = [])).push(r.id);
      }
    }

    let bestOff = null, bestN = 0;
    offCount.forEach((n, off) => { if (n > bestN) { bestN = n; bestOff = off; } });
    res.offset = bestOff;

    res.groups = [...groups.values()].sort((a, b) => TS.LEVEL_RANK[a.level] - TS.LEVEL_RANK[b.level] || b.count - a.count);
    res.exceptions = [...excs.values()].sort((a, b) => b.count - a.count);
    res.findings = rules.filter(rr => rr.hit).map(rr => rr.hit);
    // a module may adjust a finding with facts across entries: hit.sev (instead of rule.sev) and hit.note
    if (module.review) { try { module.review(res.findings, entries); } catch (err) { console.error(err); } }
    res.findings.sort((a, b) => SEV_RANK[a.sev || a.rule.sev] - SEV_RANK[b.sev || b.rule.sev] || b.count - a.count);

    // Histogram per level
    if (res.tMin != null && res.tMax != null) {
      const bucket = TS.pickBucket(Math.max(1, res.tMax - res.tMin));
      const start = Math.floor((res.tMin + (res.offset || 0) * 60000) / bucket) * bucket - (res.offset || 0) * 60000;
      const n = Math.floor((res.tMax - start) / bucket) + 1;
      const bins = [];
      for (let i = 0; i < n; i++) bins.push({ t0: start + i * bucket, t1: start + (i + 1) * bucket, FATAL: 0, ERROR: 0, WARN: 0, INFO: 0, DEBUG: 0, TRACE: 0, OTHER: 0 });
      for (const e of entries) if (e.t != null) bins[Math.floor((e.t - start) / bucket)][e.level]++;
      res.hist = { bucket, bins };
    }

    if (module.insights) {
      try { res.insights = module.insights(entries, res); } catch (err) { console.error(err); res.insights = null; }
    }
    return res;
  };

  /* ---------- Misc ---------- */
  TS.topN = (map, n) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  TS.download = function (name, content, type) {
    const blob = new Blob([content], { type: type || 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
})(window);
