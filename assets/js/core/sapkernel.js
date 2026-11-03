/* SAP kernel developer trace support (dev_icm, dev_webdisp, dev_w*, dev_disp, dev_ms, dev_rd, ...)
 *
 * Layout:
 *   trc file: "dev_icm", trc level: 1, release: "793"          <- header block (sid, relno, patchno, ...)
 *   [Thr 140032845678336] Mon Oct  2 10:15:23:123 2026          <- timestamp line, applies to the following lines
 *   [Thr 140032845678336] *** ERROR => IcmConnInitClientSSL: ... [icxxconn_mt.c 2034]
 *   M  [Thr 140032845678336] *** ERROR => ThHandleRequest: ...  <- work process traces use a component letter prefix
 *   M Mon Oct  2 10:15:23 2026
 *   A  ABAP runtime error ...
 * Lines without prefix (hex dumps, header blocks) are attached to the previous entry.
 */
(function (TS) {
  'use strict';

  const RE_THR = /^(?:([A-Z])\s{1,3})?\[Thr\s+(\d+)\]\s?(.*)$/;
  const RE_COMP = /^([A-Z])\s{1,3}(\S.*)$/;
  const RE_CLOCK = /^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?::(\d{1,6}))?\s+(\d{4})$/;
  const RE_ISO = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,:](\d{1,6}))?\s*/;
  const RE_LVL = /^\*{3}\s*(ERROR|WARNING|WARN|CRITICAL|PANIC|SEVERE|INFO|LOG)\b\s*(?:=>|:)?\s*/i;
  const RE_FUNC = /^([A-Za-z_][A-Za-z0-9_]{2,})(?:\([^)]*\))?:\s/;
  const RE_SRC = /\[([A-Za-z][\w.]*)\s+\d+\]\s*$/;
  // ***LOG lines are system log (SM21) entries written by the kernel -> treated as warnings
  const LVL = { ERROR: 'ERROR', SEVERE: 'ERROR', WARNING: 'WARN', WARN: 'WARN', CRITICAL: 'FATAL', PANIC: 'FATAL', INFO: 'INFO', LOG: 'WARN' };
  const COMPONENT = { A: 'ABAP', B: 'DB interface', C: 'DB layer', D: 'Dynpro', E: 'Enqueue', I: 'IPC', M: 'Taskhandler', N: 'Network', S: 'Spool', X: 'Ext. memory' };

  function setClock(ctx, c) {
    const mo = TS.monthIndex(c[1]);
    if (mo === undefined) return false;
    ctx.t = TS.mkTime(c[7], mo, c[2], c[3], c[4], c[5], c[6], null).t;
    ctx.tsText = `${c[7]}-${String(mo + 1).padStart(2, '0')}-${c[2].padStart(2, '0')} ${c[3]}:${c[4]}:${c[5]}${c[6] ? '.' + c[6] : ''}`;
    ctx.k = true;
    return true;
  }

  const parser = {
    id: 'sap-kernel', label: 'SAP kernel trace ([Thr …] / component prefix, with timestamp lines)',
    header(line, ctx) {
      let comp = '', thr = '', rest;
      let m = RE_THR.exec(line);
      if (m) { comp = m[1] || ''; thr = m[2]; rest = m[3].trim(); ctx.k = true; }
      else {
        const plain = line.trim();
        const c0 = RE_CLOCK.exec(plain);
        if (c0 && setClock(ctx, c0)) return TS.SKIP;
        m = RE_COMP.exec(line);
        if (!m) return null;
        rest = m[2].trim();
        // only accept "X  text" lines once the file is known to be a kernel trace (avoids false positives)
        if (!ctx.k && !RE_CLOCK.test(rest) && !RE_LVL.test(rest)) return null;
        comp = m[1];
      }
      if (!rest) return TS.SKIP;
      const c = RE_CLOCK.exec(rest);
      if (c && setClock(ctx, c)) return TS.SKIP;
      ctx.k = true;
      let t = ctx.t != null ? ctx.t : null, tsText = ctx.tsText || '';
      const iso = RE_ISO.exec(rest);
      if (iso) {
        t = TS.mkTime(iso[1], iso[2] - 1, iso[3], iso[4], iso[5], iso[6], iso[7], null).t;
        tsText = iso[0].trim();
        rest = rest.slice(iso[0].length);
      }
      let level = 'INFO', msg = rest;
      const lv = RE_LVL.exec(msg);
      if (lv) { level = LVL[lv[1].toUpperCase()] || 'INFO'; msg = msg.slice(lv[0].length); }
      else if (/\bERROR\s*=>/.test(msg)) level = 'ERROR';
      else if (/\bWARNING\s*=>/.test(msg)) level = 'WARN';
      const fn = RE_FUNC.exec(msg), src = RE_SRC.exec(msg);
      const logger = fn ? fn[1] : src ? src[1] : comp ? (COMPONENT[comp] || comp) : '';
      return { t, off: null, tsText, level, logger, thread: thr, message: msg };
    }
  };

  /* Error code used as "root cause" for WARN/ERROR entries */
  const RE_CODE = /\b(SSSLERR_[A-Z_]+|NIE[A-Z_]{3,}|ICM_HTTP_[A-Z_]+|MPI_E[A-Z_]+|DP_[A-Z_]{4,}|RFC_[A-Z_]{4,}|CPIC_[A-Z_]+|DBIF_[A-Z_]+|SQL\d{4,}|ORA-\d{4,5})\b/;
  function rootCause(e) {
    const m = RE_CODE.exec(e.message) || (e.detail ? RE_CODE.exec(e.detail.slice(0, 2000)) : null);
    if (m) return { name: m[1], msg: e.message.slice(0, 300) };
    const rc = /\brc\s*=\s*(-?\d+)/i.exec(e.message);
    if (rc && e.logger) return { name: `${e.logger} rc=${rc[1]}`, msg: e.message.slice(0, 300) };
    return null;
  }

  /* Header block of a kernel trace (trc file / sid / relno / patchno / profile ...) */
  const H_TRC = /trc file:\s*"([^"]+)",\s*trc level:\s*(\d+)(?:,\s*release:\s*"(\d+)")?/i;
  const H_FIELDS = [
    ['sid', /^\s*sid\s+(\w{3})\s*$/im], ['sysno', /^\s*sysno\s+(\d{2})\s*$/im],
    ['relno', /^\s*relno\s+(\d+)\s*$/im], ['patchno', /^\s*patchno\s+(\d+)\s*$/im],
    ['profile', /^\s*profile\s+(\S+)\s*$/im]
  ];
  function readHeader(text, hdr, trc) {
    let m;
    if ((m = H_TRC.exec(text))) { trc.set(`${m[1]} level ${m[2]}`, (trc.get(`${m[1]} level ${m[2]}`) || 0) + 1); if (m[3] && !hdr.release) hdr.release = m[3]; }
    for (const [k, re] of H_FIELDS) if (!hdr[k] && (m = re.exec(text))) hdr[k] = m[1];
  }

  TS.sapKernel = { parser, rootCause, RE_CODE, readHeader, COMPONENT };
})(window.TS);
