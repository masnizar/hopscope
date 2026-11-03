/* Table exports from SAP GUI (SM21, ST22, ... ALV lists)
 * Supported: "Text with Tabs", CSV / semicolon, unconverted ALV lists with "|" separators, and .xlsx (first sheet).
 * Columns are recognized by their header text (English / German).
 */
(function (TS) {
  'use strict';

  /* ---------- .xlsx → TSV (first worksheet) ---------- */
  function colIndex(ref) {
    const m = /^([A-Z]+)/.exec(ref || '');
    if (!m) return -1;
    let n = 0;
    for (const ch of m[1]) n = n * 26 + (ch.charCodeAt(0) - 64);
    return n - 1;
  }
  TS.xlsxToTsv = async function (u8) {
    const items = TS.unzip(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength));
    const dec = new TextDecoder();
    const xml = async name => {
      const it = items.find(i => i.name.toLowerCase() === name.toLowerCase());
      return it ? new DOMParser().parseFromString(dec.decode(await it.read()), 'application/xml') : null;
    };
    const ss = await xml('xl/sharedStrings.xml');
    const strings = ss ? [...ss.getElementsByTagName('si')].map(si => [...si.getElementsByTagName('t')].map(t => t.textContent).join('')) : [];
    const sheet = items.map(i => i.name).filter(n => /^xl\/worksheets\/sheet\d+\.xml$/i.test(n))
      .sort((a, b) => parseInt(a.replace(/\D/g, ''), 10) - parseInt(b.replace(/\D/g, ''), 10))[0];
    if (!sheet) throw new Error('no worksheet found');
    const doc = await xml(sheet);
    const out = [];
    for (const r of doc.getElementsByTagName('row')) {
      const cells = [];
      let pos = 0;
      for (const c of r.getElementsByTagName('c')) {
        const idx = colIndex(c.getAttribute('r'));
        const col = idx >= 0 ? idx : pos;
        pos = col + 1;
        const type = c.getAttribute('t'), v = c.getElementsByTagName('v')[0];
        let val = '';
        if (type === 's') val = v ? strings[+v.textContent] || '' : '';
        else if (type === 'inlineStr') val = [...c.getElementsByTagName('t')].map(x => x.textContent).join('');
        else val = v ? v.textContent : '';
        cells[col] = val;
      }
      out.push(Array.from(cells, x => (x == null ? '' : String(x).replace(/[\t\r\n]+/g, ' '))).join('\t'));
    }
    return out.join('\n');
  };

  /* ---------- delimited text → rows ---------- */
  function splitCsv(line, d) {
    const out = []; let cur = '', q = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (q) {
        if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
        else cur += ch;
      } else if (ch === '"' && !cur.trim()) { q = true; cur = ''; }
      else if (ch === d) { out.push(cur); cur = ''; }
      else cur += ch;
    }
    out.push(cur);
    return out;
  }

  const HEADER_HINT = /^(date|datum|time|zeit|uhrzeit|user|benutzer|client|mandant|cl\.?|message|meldung|text|message text|meldungstext|msg\.? ?id|message id|program|programm|runtime error|laufzeitfehler|exception|ausnahme|instance|instanz|server|host|application server|tcode|transaction( code)?|t-code|transaktion|process|prozess|problem class|priority|work process|wp|terminal|time ?stamp|zeitstempel)$/i;

  TS.tables = {};
  TS.tables.parse = function (text) {
    let lines = text.split(/\r?\n/).filter(l => l.trim() && !/^[\s\-|+=_]+$/.test(l));
    if (!lines.length) return null;
    const probe = lines.slice(0, 30);
    let best = null, bestScore = 0;
    for (const d of ['\t', '|', ';', ',']) {
      const counts = probe.map(l => l.split(d).length - 1);
      const nz = counts.filter(c => c > 0);
      if (!nz.length) continue;
      const mode = nz.sort((a, b) => a - b)[Math.floor(nz.length / 2)];
      const score = nz.filter(c => c === mode).length * Math.min(mode, 8);
      if (score > bestScore) { best = d; bestScore = score; }
    }
    if (!best) return null;
    const split = l => {
      let cells = best === ',' || best === ';' ? splitCsv(l, best) : l.split(best);
      if (best === '|') { if (/^\s*\|/.test(l)) cells = cells.slice(1); if (/\|\s*$/.test(l)) cells = cells.slice(0, -1); }
      return cells.map(c => c.trim());
    };
    const rows = lines.map(split);
    // header = first row (within the first 15) with at least 2 known column names
    let hi = rows.slice(0, 15).findIndex(r => r.filter(c => HEADER_HINT.test(c)).length >= 2);
    if (hi < 0) return null;
    const header = rows[hi];
    const data = rows.slice(hi + 1).filter(r => r.some(c => c) && !(r.length === header.length && r.every((c, i) => c === header[i])));
    return { header, rows: data, delim: best };
  };

  /* Map logical fields to column indexes by header names */
  const FIELDS = {
    date: /^(date|datum|day|created on)$/i,
    time: /^(time|zeit|uhrzeit)$/i,
    stamp: /time ?stamp|zeitstempel|date\/time/i,
    text: /^(message text|text|meldungstext|short text|message|meldung|kurztext)$/i,
    msgid: /^(message id|msg\.? ?id|meldungs-?id|mno|id)$/i,
    user: /^(user|user name|benutzer|benutzername)$/i,
    client: /^(client|cl\.?|mandant|mdt\.?)$/i,
    tcode: /^(transaction( code)?|tcode|t-code|tcd|transaktion)$/i,
    program: /^(program|programm|report|terminated program|abgebrochenes programm)$/i,
    host: /^(instance|instanz|server|host|application server|app\.? server|rechner|server name)$/i,
    runtime: /^(runtime error|laufzeitfehler|error|short dump|dump)$/i,
    exception: /^(exception|ausnahme|exception class)$/i,
    pclass: /^(problem class|priority|severity|class|problemklasse)$/i,
    process: /^(process|process type|wp|work process|prozess|typ|process no\.?)$/i
  };
  TS.tables.mapColumns = function (header) {
    const map = {};
    header.forEach((h, i) => {
      for (const [k, re] of Object.entries(FIELDS)) if (map[k] == null && re.test(h.trim())) { map[k] = i; break; }
    });
    return map;
  };

  /* ---------- date & time ---------- */
  // fmt: 'auto' | 'DMY' | 'MDY' | 'YMD'
  TS.tables.parseDateTime = function (dateStr, timeStr, fmt) {
    let d = String(dateStr || '').trim(), tm = String(timeStr || '').trim();
    let y, mo, day, h = 0, mi = 0, s = 0;
    // combined "date time" in one field
    if (!tm) { const sp = /^(\S+)[ T]+(\d{1,2}:\d{2}(?::\d{2})?)/.exec(d); if (sp) { d = sp[1]; tm = sp[2]; } }
    let m;
    if ((m = /^(\d{5})(\.\d+)?$/.exec(d))) {
      // Excel serial date (days since 1899-12-30), optional time fraction
      const ms = Math.round((parseFloat(d) - 25569) * 864e5);
      const dt = new Date(ms);
      y = dt.getUTCFullYear(); mo = dt.getUTCMonth(); day = dt.getUTCDate();
      if (m[2] && !tm) { h = dt.getUTCHours(); mi = dt.getUTCMinutes(); s = dt.getUTCSeconds(); }
    } else if ((m = /^(\d{4})[-./]?(\d{2})[-./]?(\d{2})$/.exec(d))) { y = +m[1]; mo = m[2] - 1; day = +m[3]; }
    else if ((m = /^(\d{1,2})([./-])(\d{1,2})\2(\d{2,4})$/.exec(d))) {
      let a = +m[1], b = +m[3];
      y = +m[4]; if (y < 100) y += 2000;
      // SAP user date formats: DD.MM.YYYY, MM/DD/YYYY, MM-DD-YYYY → only "." is day-first by default
      const dayFirst = fmt === 'DMY' ? true : fmt === 'MDY' ? false : a > 12 ? true : b > 12 ? false : m[2] === '.';
      if (dayFirst) { day = a; mo = b - 1; } else { mo = a - 1; day = b; }
    } else return null;
    if (tm) {
      if ((m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?/.exec(tm))) { h = +m[1]; mi = +m[2]; s = +(m[3] || 0); }
      else if ((m = /^(\d{2})(\d{2})(\d{2})$/.exec(tm))) { h = +m[1]; mi = +m[2]; s = +m[3]; }
      else if ((m = /^0?\.\d+$/.exec(tm))) { const sec = Math.round(parseFloat(tm) * 86400); h = Math.floor(sec / 3600); mi = Math.floor(sec / 60) % 60; s = sec % 60; }
    }
    if (isNaN(y) || mo < 0 || mo > 11 || day < 1 || day > 31) return null;
    return Date.UTC(y, mo, day, h, mi, s);
  };
})(window.TS);
