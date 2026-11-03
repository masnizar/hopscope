/* Landscape map engine: places the findings of all loaded logs on the SAP S/4HANA on-premise reference landscape (with SAP BTP)
 * and walks each request path hop by hop, so the hop where the request breaks is shown — not only the component that
 * logged the error (an IdP redirect logged by the Cloud Connector is located at the S/4 logon; its cause may be the ICM).
 * Input: TS.corr.build() data. L.diagnose(data, files, opts) →
 *   { target, viaWd, labels, paths: [{ id, title, relevant, steps: [{ id, def, status, items, oks, gaps }], fail, warn }], other, notes }
 * Hop status: fail (cause found here) · warn (symptom or lower severity) · ok (evidence that it worked) ·
 *             clear (covered by a loaded log, nothing found) · blocked (behind a failing hop) · unknown (no loaded log covers it)
 */
(function (TS) {
  'use strict';
  const C = TS.corr, L = TS.landscape = {};
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const host = h => String(h || '').replace(/:\d+$/, '').toLowerCase();
  const uniq = a => [...new Set(a.filter(Boolean))];
  const top = (arr, n) => { const m = new Map(); arr.forEach(x => x && m.set(x, (m.get(x) || 0) + 1)); return [...m].sort((a, b) => b[1] - a[1]).slice(0, n || 3).map(([k, v]) => (v > 1 ? `${k} (${v}×)` : k)); };

  /* ---------- Hops ----------
   * nodes: map elements to highlight ('wd' / 's4' = Web Dispatcher / S/4 of the target tier), layer: row inside the S/4 box,
   * covers: log sources that show this hop, collect: how to get such a log */
  L.STEPS = {
    user: { nodes: ['user'], title: 'User / browser', covers: [],
      what: 'The user opens the application and logs on at SAP Cloud Identity Services (IAS).',
      collect: 'Browser developer tools (F12 → Network, "Preserve log") → export HAR. Not analyzed here — the hops behind it show whether requests arrived.' },
    browser: { nodes: ['user'], title: 'User / browser', covers: [],
      what: 'The browser calls the Fiori launchpad URL (*.sap.<customerdomain>) and logs on via SAML at IAS.',
      collect: 'Browser developer tools (F12 → Network, "Preserve log") → export HAR. Not analyzed here — the Web Dispatcher trace shows whether requests arrived.' },
    app: { nodes: ['app'], title: 'BTP application + destination', covers: ['scc'],
      what: 'The application calls its destination: proxy type OnPremise, location ID of the Cloud Connector, authentication PrincipalPropagation (or basic / none).',
      collect: 'BTP cockpit → subaccount → Connectivity → Destinations → Check Connection; application logs (cockpit → application → Logs, or cf logs <app> --recent).' },
    tunnel: { nodes: ['conn', 'tunnel'], title: 'Connectivity service + secure tunnel', covers: ['scc'],
      what: 'The Connectivity service forwards the request through the TLS tunnel that the Cloud Connector opened to the subaccount (same location ID).',
      collect: 'SCC → Log and Trace Files → ljs_trace.log (tunnel connect / disconnect); BTP cockpit → Connectivity → Cloud Connectors (connected, location ID).' },
    scc: { nodes: ['scc'], title: 'Cloud Connector', covers: ['scc'],
      what: 'Access control: virtual host → internal host, allowed paths / RFC function modules, principal type, and the short-lived X.509 user certificate for principal propagation.',
      collect: 'SCC → Log and Trace Files: Cloud Connector loggers ALL → reproduce → Download All (scc_core.trc, ljs_trace.log) → reset the level.' },
    'scc-be': { nodes: ['scc'], title: 'Cloud Connector → backend (network + TLS)', covers: ['scc'],
      what: 'TCP connection to the internal host:port and TLS handshake: the Cloud Connector must trust the backend server certificate, and the backend must accept the SCC system certificate (CA list of its SSL server PSE).',
      collect: 'SCC: TLS trace on → Cloud To On-Premise → Check availability of internal host → Download All; plus sys_cert.der (Configuration → On Premise → System Certificate → download).' },
    wd: { nodes: ['wd'], title: 'Web Dispatcher', covers: ['wdp'],
      what: 'URL routing (wdisp/system_<n>), backend server list from the message server, SSL termination, client-certificate forwarding.',
      collect: 'dev_webdisp from the work directory of the Web Dispatcher (web administration → Monitor → Trace, level 2) → reproduce → download.' },
    'wd-be': { nodes: ['wd'], title: 'Web Dispatcher → ICM (re-encryption)', covers: ['wdp'],
      what: 'TLS from the Web Dispatcher to the application server: SSL client PSE of the Web Dispatcher, trust in the ICM server certificate, the Web Dispatcher certificate in icm/trusted_reverse_proxy_<n>.',
      collect: 'dev_webdisp (level 2) together with the dev_icm of the application server it forwards to.' },
    elb: { nodes: ['elb'], title: 'External load balancer / WAF', covers: [],
      what: '*.sap.<customerdomain>: DNS, TLS termination and WAF rules in front of the Web Dispatchers — operated by the network team, not visible in SAP logs.',
      collect: 'Check the DNS name of the URL; ask the network team for the load balancer / WAF log of the time of the error.' },
    icm: { nodes: ['s4'], layer: 'icm', title: 'S/4 · ICM (HTTPS port)', covers: ['icm'],
      what: 'SSL server PSE and client certificate check (icm/HTTPS/verify_client), the Cloud Connector / Web Dispatcher certificate in icm/trusted_reverse_proxy_<n>, ICM resources.',
      collect: 'SM51 → the instance of the internal host → SMICM → Goto → Trace Level → 2 → Trace File → Reset → reproduce → Display All (or dev_icm from the work directory) → level back to 1.' },
    logon: { nodes: ['s4'], layer: 'logon', title: 'S/4 · ICF logon', covers: ['icm', 'sm21', 'http'],
      what: 'Logon of the forwarded user: X.509 certificate → CERTRULE (login/certificate_mapping_rulebased = 1) → SAP user. Without a user the ICF service redirects to the SAML IdP (302) or answers 401.',
      collect: 'SMICM trace level 2 (logon of the forwarded certificate), SM21 export, STAUTHTRACE / ST01 for the user; CERTRULE → test with a sample certificate.' },
    abap: { nodes: ['s4'], layer: 'abap', title: 'S/4 · ABAP application', covers: ['st22', 'sm21', 'wp', 'http'],
      what: 'ICF service active (SICF), authorizations (SU53), OData / application processing, work processes and dumps.',
      collect: 'ST22 and SM21 export of the time (Spreadsheet or Text with Tabs), dev_w* of the work process, /IWFND/ERROR_LOG for OData.' },
    'abap-out': { nodes: ['s4'], layer: 'abap', title: 'S/4 · caller (SM59 destination)', covers: ['sm59', 'st22'],
      what: 'ABAP program or SM59 destination that calls an external service.',
      collect: 'SM59 → destination → Connection Test → save the result as text; ST22 of the time.' },
    'icm-out': { nodes: ['s4'], layer: 'icm', title: 'S/4 · ICM as HTTP client', covers: ['icm'],
      what: 'Outbound TLS: SSL client PSE (own certificate, CAs of the target), host name / SNI, DNS and network of the application server.',
      collect: 'SMICM trace level 2–3 on the calling instance → reproduce (SM59 test) → download dev_icm.' },
    egress: { nodes: ['elb'], title: 'Outbound proxy / firewall', covers: ['icm', 'sm59'],
      what: 'Outbound path of the customer network: HTTP proxy (SM59 proxy settings, icm/HTTP/proxy_*), NAT, firewall rules — operated by the network team.',
      collect: 'dev_icm (level 2) of the call; the network team for the proxy / firewall log.' },
    remote: { nodes: ['remote'], title: 'Remote service', covers: ['sm59'],
      what: 'Target of the call (SAP BTP service, external API) and its answer.',
      collect: 'SM59 connection test result; logs of the remote service.' }
  };

  L.PATHS = [
    { id: 'pp', title: 'BTP app → Cloud Connector → S/4', short: 'Cloud → on-premise', steps: ['user', 'app', 'tunnel', 'scc', 'scc-be', 'icm', 'logon', 'abap'] },
    { id: 'web', title: 'Browser → Web Dispatcher → S/4', short: 'Browser → Fiori', steps: ['browser', 'elb', 'wd', 'wd-be', 'icm', 'logon', 'abap'] },
    { id: 'out', title: 'S/4 → outbound call (SM59 / ICM client)', short: 'S/4 → outbound', steps: ['abap-out', 'icm-out', 'egress', 'remote'] }
  ];

  /* ---------- Where a knowledge-base finding is located (not where it was logged) ---------- */
  const PLACE = {
    'scc:tunnel-down': 'tunnel', 'scc:proxy': 'tunnel', 'scc:location-id': 'tunnel', 'scc:subaccount-auth': 'tunnel',
    'scc:access-denied': 'scc', 'scc:rfc-fm-denied': 'scc', 'scc:pp-not-configured': 'scc', 'scc:principal-propagation': 'scc',
    'scc:cert-expired': 'scc', 'scc:cert-expiring': 'scc', 'scc:port-in-use': 'scc', 'scc:oom': 'scc', 'scc:resources': 'scc', 'scc:java-version': 'scc',
    'scc:backend-no-client-cert': 'scc-be', 'scc:unknown-host': 'scc-be', 'scc:conn-refused': 'scc-be', 'scc:timeout': 'scc-be', 'scc:conn-reset': 'scc-be',
    'scc:pkix': 'scc-be', 'scc:ssl-handshake': 'scc-be', 'scc:rfc-comm': 'scc-be', 'scc:snc': 'scc-be',
    'scc:pp-idp-redirect': 'logon', 'scc:http-401': 'logon', 'scc:rfc-logon': 'logon',
    'scc:http-403': 'abap', 'scc:backend-5xx': 'abap', 'scc:rfc-abap': 'abap',
    'scc:admin-login': null, 'scc:ldap': null,
    'icm:reverse-proxy-untrusted': 'icm', 'icm:ssl-client-untrusted': 'icm', 'icm:ssl-client-cert': 'icm', 'icm:ssl-lib': 'icm', 'icm:port-bind': 'icm',
    'icm:mpi-buffers': 'icm', 'icm:threads': 'icm', 'icm:connections': 'icm', 'icm:memory': 'icm', 'icm:icm-crash': 'icm',
    'icm:request-size': 'icm', 'icm:permission': 'icm', 'icm:ni-broken': 'icm', 'icm:ssl-expired': 'icm', 'icm:ssl-handshake': 'icm',
    'icm:proc-timeout': 'abap', 'icm:dispatcher': 'abap', 'icm:http-5xx': 'abap',
    'icm:ssl-untrusted': 'icm-out', 'icm:ssl-mismatch': 'icm-out', 'icm:ssl-own-cert-expired': 'icm-out', 'icm:ssl-no-response': 'icm-out',
    'icm:ni-host-unknown': 'icm-out', 'icm:ni-refused': 'icm-out', 'icm:ni-timeout': 'icm-out', 'icm:icm-http-conn': 'icm-out', 'icm:proxy': 'egress',
    'icm:webdisp-backend': 'wd', 'icm:message-server': 'wd',
    'wdp:wdp-ssl-backend': 'wd-be', 'wdp:wdp-client-cert': 'wd-be', 'wdp:ssl-untrusted': 'wd-be', 'wdp:ssl-mismatch': 'wd-be', 'wdp:ssl-own-cert-expired': 'wd-be',
    'wdp:ssl-no-response': 'wd-be', 'wdp:ni-refused': 'wd-be', 'wdp:ni-timeout': 'wd-be', 'wdp:ni-host-unknown': 'wd-be',
    'wdp:http-5xx': 'abap', 'wdp:proc-timeout': 'abap'
  };
  // towards SAP BTP: tunnel / notification channel (often through the HTTPS proxy "R:proxy/<ip>:<port>")
  const CLOUD = /connectivitytunnel|connectivitynotification|connectivitycertsigning|hana\.ondemand\.com|cloud\.sap\b|connect(?:ing)? to (?:the )?cloud|tunnel processing|R:proxy\//i;
  // the web server of the Cloud Connector's own administration UI (Tomcat, port 8443): not on the path of any request
  const SCC_ADMIN = e => /org\.apache\.(tomcat|catalina)/.test(e.who || '');
  function placeOf(src, rule, evs) {
    const k = src + ':' + rule;
    if (src === 'scc' && evs.length && evs.every(SCC_ADMIN)) return null;
    // the same TLS / network errors happen towards SAP BTP (tunnel) or towards the backend
    if (src === 'scc' && /^(pkix|ssl-handshake|unknown-host|conn-refused|timeout|conn-reset|cert-expired)$/.test(rule) &&
      evs.filter(e => CLOUD.test(`${e.text}\n${e.detail}`) || /^notification-client/.test(e.thread)).length > evs.length / 2) return 'tunnel';
    // ICM: server-side handshake (inbound) or client-side (outbound call)
    if (src === 'icm' && /^(ssl-handshake|ssl-expired)$/.test(rule) && evs.length && evs.filter(e => /ClientSSL|ConnInitClient|SSL handshake with|cli SSL/i.test(`${e.who} ${e.text}`)).length > evs.length / 2) return 'icm-out';
    if (k in PLACE) return PLACE[k];
    if (src === 'wdp') return 'wd';
    if (src === 'wp') return 'abap';
    return undefined;
  }

  // logon results that are a consequence when an earlier hop of the same request failed
  const SYMPTOM = new Set(['scc:pp-idp-redirect', 'scc:http-401', 'http:401']);
  // connection-level errors that are only the cause while no request gets through (an SCC restart, a short proxy outage)
  const TRANSIENT = /^scc:(tunnel-down|proxy|ssl-handshake|pkix|timeout|conn-reset|conn-refused|unknown-host|location-id|subaccount-auth)$/;
  const STRONG = s => s === 'critical' || s === 'high';

  /* ---------- Target system (SID / tier) ----------
   * SID from the trace header ("sid PR1"), the file name (PR1_dev_icm.txt) or SAP HEC host names (vh<customer><sid>ci / ai<nn>) */
  const TIER = { P: 'prd', Q: 'qas', T: 'qas', A: 'qas', D: 'dev', S: 'dev', X: 'dev' };
  const NOT_SID = /^(SCC|ICM|WDP|DEV|QAS|PRD|LOG|SSL|TLS|CER|CRT|PEM|DER|SAP|ST2|SM2|SM5|TRC|TXT|NEW|OLD)$/;
  const RE_HEC = /^vh[a-z]{3}([a-z][a-z0-9]{2})(?:ci|ai\d*|cs|db\d*)\b/;
  L.detectTarget = function (files, data, force) {
    const votes = new Map(), hosts = new Map();
    const vote = (sid, how, w) => { if (!sid) return; sid = sid.toUpperCase(); const v = votes.get(sid) || { n: 0, how: new Set() }; v.n += w || 1; v.how.add(how); votes.set(sid, v); };
    data.kernels.forEach(k => vote(k.sid, 'trace header', 3));
    files.forEach(f => { const m = /(?:^|[\\/!])([A-Z][A-Z0-9]{2})[_-]/.exec(f.name); if (m && !NOT_SID.test(m[1])) vote(m[1], 'file name', 2); });
    const hostList = data.conns.map(c => host(c.target)).filter(Boolean).concat(...data.kernels.filter(k => k.src === 'icm').map(k => [...k.locals].filter(h => /[a-z]/.test(h))));
    hostList.forEach(h => { if (!h) return; hosts.set(h, (hosts.get(h) || 0) + 1); const m = RE_HEC.exec(h); if (m) vote(m[1], 'host name'); });
    const best = [...votes].sort((a, b) => b[1].n - a[1].n)[0];
    const sid = best ? best[0] : null;
    const hostTop = [...hosts].sort((a, b) => b[1] - a[1]).map(x => x[0])[0] || '';
    let tier = force && force !== 'auto' ? force : null, how = force && force !== 'auto' ? 'set manually' : '';
    if (!tier && sid && TIER[sid[0]]) { tier = TIER[sid[0]]; how = `SID ${sid} (${[...best[1].how].join(', ')})`; }
    if (!tier && hostTop) {
      const h = hostList.join(' ');
      tier = /pr[do]\b|prod|\bp\d{2}\b/.test(h) ? 'prd' : /qas|\bqa\d?\b|test/.test(h) ? 'qas' : /dev|sbx|sandbox/.test(h) ? 'dev' : null;
      if (tier) how = 'host name';
    }
    // internal host:port the Cloud Connector talks to — requests with a user (principal propagation, IdP redirect) first
    const named = data.conns.filter(c => /^[^:]/.test(c.target || ''));
    const auth = [c => c.x509, c => c.redirect, c => c.pp].map(fn => named.filter(fn)).find(l => l.length) || named;
    const ep = top(auth.map(c => c.target), 1)[0];
    return { sid, tier: tier || 'prd', assumed: !tier, how: how || 'not detected — choose the target system', host: hostTop, endpoint: ep ? ep.replace(/ \(\d+×\)$/, '') : '' };
  };

  /* ---------- Diagnosis ---------- */
  const WINDOW_PAD = 10 * 60e3;
  L.diagnose = function (data, files, opts) {
    opts = opts || {};
    const loaded = new Set(files.map(f => f.src));
    const target = L.detectTarget(files, data, opts.tier);
    // one request flow (application): its Cloud Connector requests and SCC entries; entries without connection ID (tunnel …) stay
    const flow = opts.flow ? L.flows(data.conns).find(f => f.key === opts.flow) || null : null;
    if (flow) {
      const own = e => { if (e.src !== 'scc') return true; const m = /^(0x[0-9a-f]+)#/i.exec(e.text || ''); return !m || flow.ids.has(m[1]); };
      data = Object.assign({}, data, { conns: data.conns.filter(c => flow.ids.has(c.id)), events: data.events.filter(own) });
    }
    // analysis window: the range chosen in the UI, else the minutes around the Cloud Connector requests — kernel traces often cover
    // weeks, and their old errors (scanners, other clients, other days) are not what breaks the request of this incident
    let from = opts.from, to = opts.to, auto = false;
    if (from == null && to == null && opts.window !== 'all') {
      const ts = [].concat(...data.conns.map(c => [c.t0, c.t1])).filter(t => t != null);
      if (ts.length) { from = Math.min(...ts) - WINDOW_PAD; to = Math.max(...ts) + WINDOW_PAD; auto = true; }
    }
    const inR = t => t == null || ((from == null || t >= from) && (to == null || t < to));
    const evs = data.events.filter(e => inR(e.t));
    const conns = data.conns.filter(c => inR(c.t0));
    const bag = {};
    Object.keys(L.STEPS).forEach(k => (bag[k] = { items: [], oks: [], gaps: [] }));
    const other = [], notes = [];
    // only: the paths an item / evidence belongs to (Cloud Connector facts → 'pp'); hops such as the ICM are shared by several paths
    const add = (step, it) => { if (step) bag[step].items.push(it); else other.push(it); };
    const ok = (step, text, only) => bag[step].oks.push({ text, only });
    const PP = ['pp'];

    // 1. knowledge-base findings of SCC / ICM / Web Dispatcher / work processes, placed on the hop where the error is
    // a selected flow whose internal host is not the host of a loaded ICM trace: that trace says nothing about its requests
    const icmOther = !!flow && !data.kernels.some(k => k.src === 'icm' && data.conns.some(c => (c.backendIp && k.locals.has(c.backendIp)) || k.locals.has(host(c.target))));
    const F = C.findings(data, from, to);
    for (const f of F) {
      if (f.id.startsWith('x:')) continue;
      const [src, rule] = f.id.split(':');
      if (icmOther && src === 'icm') continue;
      const step = placeOf(src, rule, evs.filter(e => e.src === src && e.rule === rule));
      // (an SSO token on a mapping without principal propagation and no redirect comes as "medium" from C.findings)
      add(step, { id: f.id, kind: 'cause', sev: f.sev, title: f.title, why: f.why, fix: f.fix.slice(), evidence: f.evidence.slice(), count: f.count, t0: f.t0, t1: f.t1, src, only: src === 'scc' ? PP : undefined });
    }

    // 2. cross-source checks (Cloud Connector ↔ ICM / Web Dispatcher trace), time zones
    for (const f of F) {
      if (!f.id.startsWith('x:')) continue;
      const kSrc = f.srcs.find(s => s === 'icm' || s === 'wdp') || 'icm', kStep = kSrc === 'wdp' ? 'wd' : 'icm';
      if (f.id.startsWith('x:scc-reached')) { ok('scc-be', f.title + (f.evidence[0] ? ` — ${f.evidence[0]}` : '')); ok(kStep, `The Cloud Connector host appears as client in ${f.title.replace(/^.*\(([^)]+)\)$/, '$1')}`, PP); }
      else if (f.id.startsWith('x:scc-missing')) add('scc-be', { id: f.id, kind: 'cause', sev: f.sev, title: f.title, why: f.why, fix: f.fix, evidence: f.evidence, count: f.count, t0: f.t0, t1: f.t1, src: 'scc' });
      else if (f.id.startsWith('x:scc-uncovered') || f.id === 'x:scc-other-hosts') bag[kStep].gaps.push({ title: f.title, why: f.why, fix: f.fix, evidence: f.evidence, only: PP });
      else notes.push({ sev: f.sev, title: f.title, why: f.why, fix: f.fix, evidence: f.evidence });
    }

    // 3. SCC TLS trace: CA list of the backend vs. the loaded system certificate
    const hs = data.handshakes || [];
    if (hs.length && TS.certs) {
      TS.certs.link(data.certs);
      for (const r of TS.certs.clientCertCheck(data.certs, hs)) {
        const ev = [`Accepted issuers of ${r.peer}: ${r.cas.join(' · ')}`].concat(r.refs.map(x => 'Trace: ' + x));
        if (r.key === 'rejected') add('scc-be', { id: 'cert:rejected', kind: 'cause', sev: 'high', title: `${r.peer} does not accept the SCC system certificate`, why: r.text, fix: r.fix, evidence: ev, count: r.n, src: 'scc' });
        else if (r.key === 'notsent' || (r.key === 'nocert' && r.none)) add('scc-be', { id: 'cert:' + r.key, kind: 'cause', sev: 'medium', title: r.key === 'nocert' ? `${r.peer} asks for a client certificate, the Cloud Connector sent none` : `SCC system certificate accepted by ${r.peer}, but not sent`, why: r.text, fix: r.fix, evidence: ev, count: r.n, src: 'scc' });
        else if (r.sent) ok('scc-be', `TLS: the Cloud Connector sent its system certificate to ${r.peer} (${r.sent}×)${r.key === 'ok' ? ' — accepted via the CA list' : ''}`);
      }
    }

    // 4. ICM trace level 2: the certificate the proxy really presented vs. icm/trusted_reverse_proxy_<n> (in the analysis window)
    const inWin = list => (list || []).filter(t => inR(t)).length;
    // only requests that forward a user certificate (principal propagation) depend on the reverse proxy trust
    const proxies = icmOther || (flow && !flow.x509) ? [] : (data.proxies || []).map(p => Object.assign({}, p, { nWin: inWin(p.times), rejWin: inWin(p.rtimes) }));
    if (flow && !flow.x509 && bag.icm.items.some(i => i.id === 'icm:reverse-proxy-untrusted')) bag.icm.items = bag.icm.items.filter(i => i.id !== 'icm:reverse-proxy-untrusted');
    // the proxy is the Cloud Connector when its address is the SCC host of the loaded SCC logs (or a Web Dispatcher when it is not)
    const sccIps = new Set(data.conns.map(c => c.sccIp).filter(Boolean));
    const bad = proxies.filter(p => !p.ok && p.rejWin);
    if (bad.length) {
      let it = bag.icm.items.find(i => i.id === 'icm:reverse-proxy-untrusted');
      if (!it) { it = { id: 'icm:reverse-proxy-untrusted', kind: 'cause', sev: 'high', title: 'Reverse proxy / Cloud Connector not trusted — forwarded user certificate rejected', why: '', fix: [], evidence: [], count: 0, src: 'icm' }; bag.icm.items.push(it); }
      it.params = [];
      const peers = [].concat(...bad.map(p => [...p.peers]));
      if (sccIps.size && peers.length) it.only = peers.every(x => sccIps.has(x)) ? PP : peers.every(x => !sccIps.has(x)) ? ['web'] : undefined;
      for (const p of bad) {
        const param = `icm/trusted_reverse_proxy_<n> = SUBJECT="${p.subject}", ISSUER="${p.issuer}"`;
        if (!it.params.includes(param)) it.params.push(param);
        it.evidence.unshift(`Presented by ${[...p.peers].join(', ') || 'the proxy'}: SUBJECT="${p.subject}", ISSUER="${p.issuer}" · forwarded user certificate rejected ${p.rejWin}× (${base(p.file)})` +
          (p.trusted.size ? ` · configured: ${[...p.trusted].join('; ')}` : '') +
          (p.fwd.size ? ` · forwarded users: ${TS.topN(p.fwd, 3).map(([k, n]) => `${k} (${n}×)`).join(', ')}` : ''));
      }
    }
    // trusted as reverse proxy: the forwarded user certificate reaches the logon
    proxies.filter(p => p.ok && p.nWin).forEach(p => {
      const scc = [...p.peers].some(x => sccIps.has(x));
      ok('icm', `ICM trusts ${p.subject} / ${p.issuer}${p.peers.size ? ` from ${[...p.peers].join(', ')}` : ''} as reverse proxy (icm/trusted_reverse_proxy) — ${p.nWin} request(s)` +
        (p.fwd.size ? `; forwarded user certificate accepted: ${TS.topN(p.fwd, 2).map(([k, n]) => `${k} (${n}×)`).join(', ')}` : '') + '.', scc ? PP : undefined);
    });

    // 5. SM21, ST22, HTTP access logs, SM59 tests
    const dumps = evs.filter(e => e.src === 'st22');
    if (dumps.length) {
      const it = { id: 'st22', kind: 'cause', sev: 'medium', title: `${dumps.length} ABAP dump${dumps.length === 1 ? '' : 's'} (ST22)`, why: `Runtime errors in the loaded ST22 export: ${top(dumps.map(e => e.code), 4).join(', ')}. Check whether user, program and time belong to the failing request.`,
        fix: ['ST22 → the dumps of the time → "Information on where terminated", user, transaction / ICF service.'], evidence: dumps.slice(0, 5).map(e => `${TS.fmtTime(e.t)} · ${e.text}`), count: dumps.length, t0: dumps[0].t, t1: dumps[dumps.length - 1].t, src: 'st22' };
      add('abap', it); add('abap-out', it);
    }
    const SM21_STEP = { 'sm21-ssl': 'icm', 'sm21-http': 'icm', 'sm21-logon': 'logon', 'sm21-comm': 'abap-out' };
    const sm21 = new Map();
    evs.filter(e => e.src === 'sm21' && e.level !== 'INFO').forEach(e => { const k = e.rule || 'sm21'; const g = sm21.get(k) || []; g.push(e); sm21.set(k, g); });
    for (const [rule, g] of sm21) {
      const err = g.some(e => e.level === 'ERROR');
      add(SM21_STEP[rule] || 'abap', { id: 'sm21:' + rule, kind: 'cause', sev: err ? 'medium' : 'low', title: `SM21: ${g[0].title}`, why: `${g.length} system log entr${g.length === 1 ? 'y' : 'ies'}: ${top(g.map(e => e.text.slice(0, 120)), 2).join(' · ')}`,
        fix: ['SM21 → the entries of the time → double-click for details (user, client, terminal, message ID).'], evidence: g.slice(0, 4).map(e => `${TS.fmtTime(e.t)} · ${e.text.slice(0, 200)}`), count: g.length, t0: g[0].t, t1: g[g.length - 1].t, src: 'sm21' });
    }
    const http = new Map();
    evs.filter(e => e.src === 'http').forEach(e => { const st = +(/\d{3}/.exec(e.code) || [0])[0]; const g = http.get(st) || []; g.push(e); http.set(st, g); });
    for (const [st, g] of http) {
      const step = st === 401 ? 'logon' : 'abap';
      add(step, { id: 'http:' + st, kind: 'cause', sev: st >= 500 ? 'medium' : 'low', title: `HTTP ${st} in the access log`, why: `${g.length} request(s) answered with ${st}: ${top(g.map(e => e.title.replace(/^\d{3} /, '').split(' ').slice(0, 2).join(' ')), 3).join(', ')}.`,
        fix: st === 401 ? ['401: the user was not logged on — see the ICF logon hop (certificate / SAML / basic).'] : st === 403 ? ['403: SU53 / STAUTHTRACE for the user, S_SERVICE / S_ICF of the service.'] : st === 404 ? ['404: SICF → service active? URL / alias correct?'] : ['5xx: ST22 / SM21 and the ICM trace of the time.'],
        evidence: g.slice(0, 4).map(e => `${TS.fmtTime(e.t)} · ${e.title}`), count: g.length, t0: g[0].t, t1: g[g.length - 1].t, src: 'http' });
    }
    for (const t of data.tests) {
      if (!inR(t.t)) continue;
      if (t.ok) { ['abap-out', 'icm-out', 'egress', 'remote'].forEach(s => ok(s, `SM59 test of ${t.dest} OK${t.status ? ' (HTTP ' + t.status + ')' : ''}`)); continue; }
      const codes = t.codes.join(' ');
      const step = /SSSLERR|SSL/.test(codes) ? 'icm-out' : /NIE|CONNECTION|PROXY|ICM_HTTP_(NO|TIMEOUT)/i.test(codes) ? 'egress' : t.status >= 400 ? 'remote' : 'abap-out';
      add(step, { id: 'sm59:' + t.dest, kind: 'cause', sev: 'high', title: `SM59 test of ${t.dest} failed`, why: [t.status && 'HTTP ' + t.status, ...t.codes, ...t.errors].filter(Boolean).join(' · ') || 'The connection test reported an error.',
        fix: ['SM59 → the destination → Connection Test; for SSL codes check the SSL client PSE in STRUST, for NI codes DNS / firewall / proxy of the application server.'], evidence: t.errors.slice(0, 4), count: 1, t0: t.t, t1: t.t, src: 'sm59' });
    }

    // 6. certificates that were not valid at the time (loaded or seen in trace handshakes)
    const ref = to != null ? to : data.tMax != null ? data.tMax : Date.now();
    for (const c of data.certs) {
      const st = TS.x509.status(c, ref).key;
      if (st !== 'expired' && st !== 'notyet') continue;
      const scc = TS.certs && TS.certs.sccRole(c);
      const out = (c.observed || []).some(o => /own certificate|server certificate of/i.test(o.what || ''));
      add(scc ? 'scc' : out ? 'icm-out' : 'icm', { id: 'cert:' + (c.serial || c.subject), kind: 'cause', sev: 'critical', title: `Certificate ${st === 'expired' ? 'expired' : 'not yet valid'}: ${c.cn || c.subject}`,
        why: `${c.subject} — valid ${c.notBefore != null ? TS.fmtTime(c.notBefore).slice(0, 10) : '?'} – ${c.notAfter != null ? TS.fmtTime(c.notAfter).slice(0, 10) : '?'}${scc ? ' (' + scc + ')' : ''}.`,
        fix: [scc ? 'Cloud Connector → Configuration → renew / import the certificate.' : 'STRUST → the PSE → renew (create request → CA → import response) → SMICM → Exit Soft.'], evidence: (c.where || []).map(w => `${base(w.source)}${w.pse ? ' · PSE ' + w.pse : ''}`), count: 1, src: 'strust' });
    }

    // 7. evidence that hops worked (Cloud Connector request facts, tunnel events, Web Dispatcher connections)
    if (conns.length) {
      const subs = uniq(conns.map(c => c.sub));
      const arrived = `${conns.length} request(s) arrived at the Cloud Connector${subs.length ? ' from ' + subs.join(', ') : ''}`;
      ok('user', `${arrived} — the user reached the application.`);
      ok('app', `${arrived} — destination and location ID work.`);
      ok('tunnel', `${arrived} through the tunnel.`);
      const mapped = conns.filter(c => c.vhost && /^[^:]/.test(c.target || ''));
      if (mapped.length) ok('scc', `Mapping ${top(mapped.map(c => `${c.vhost} → ${c.target}`), 2).join(', ')}.`);
      const x509 = conns.filter(c => c.x509);
      if (x509.length) ok('scc', `Principal propagation: short-lived X.509 certificate for ${top(x509.map(c => c.certSubject || c.principal || 'the user'), 2).join(', ')} (${x509.length} request(s)).`);
      const opened = conns.filter(c => c.backendIp);
      if (opened.length) ok('scc-be', `Backend connection opened to ${top(opened.map(c => `${/^[^:]/.test(c.target || '') ? c.target : c.vhost || c.target} (${c.backendIp})`), 2).join(', ')}.`);
      // a connection-level error before the last request that passed the same hop is not what breaks the current requests
      const last = list => list.reduce((m, c) => (c.t1 != null && (m == null || c.t1 > m) ? c.t1 : m), null);
      const passT = { tunnel: last(conns), scc: last(mapped), 'scc-be': last(opened) };
      for (const step of Object.keys(passT)) {
        if (passT[step] == null) continue;
        bag[step].items = bag[step].items.map(it => (TRANSIENT.test(it.id) && STRONG(it.sev) && it.t1 != null && it.t1 < passT[step]
          ? Object.assign({}, it, { sev: 'medium', note: `Earlier or intermittent: requests passed this hop afterwards (last at ${TS.fmtTime(passT[step])}), so this is not what breaks the current requests. Narrow the time range to the failing call to be sure.` }) : it));
      }
      const clean = x509.filter(c => !c.redirect);
      if (clean.length && !bag.logon.items.some(i => i.id === 'scc:pp-idp-redirect')) ok('logon', `${clean.length} request(s) with user certificate were not redirected to the IdP.`, PP);
    }
    const ups = evs.filter(e => e.src === 'scc' && e.rule === 'tunnel-up');
    if (ups.length) ok('tunnel', `Tunnel connected (${ups.length}×, last ${TS.fmtTime(ups[ups.length - 1].t)}).`);
    data.kernels.filter(k => k.src === 'wdp' && k.inbound.size).forEach(k => {
      const n = [...k.inbound.values()].reduce((s, x) => s + x.n, 0);
      ok('wd', `${n} client connection line(s) in ${base(k.file)}.`);
      ok('browser', `Requests from ${k.inbound.size} client address(es) reached the Web Dispatcher (${base(k.file)}).`);
    });

    // does the Cloud Connector reach the backend through a Web Dispatcher?
    const viaWd = data.kernels.some(k => k.src === 'wdp' && conns.some(c => (c.backendIp && k.locals.has(c.backendIp)) || k.locals.has(host(c.target))));

    // 8. walk every path in order
    const paths = L.PATHS.map(p => {
      let ids = p.steps.slice();
      if (p.id === 'pp' && viaWd) ids.splice(ids.indexOf('scc-be') + 1, 0, 'wd', 'wd-be');
      let fail = null;
      const mine = x => !x.only || x.only.includes(p.id);
      const steps = ids.map((id, i) => {
        const def = L.STEPS[id], b = { items: bag[id].items.filter(mine), oks: bag[id].oks.filter(mine).map(o => o.text), gaps: bag[id].gaps.filter(mine) };
        const items = b.items.map(it => {
          if (id !== 'logon' || !SYMPTOM.has(it.id)) return it;
          if (fail) return Object.assign({}, it, { kind: 'symptom', sev: 'medium', note: `Consequence of the failure at hop ${fail.n} "${fail.def.title}" — fix that hop first; this disappears with it.` });
          const icmSeen = loaded.has('icm') && !bag.icm.gaps.length;
          return Object.assign({}, it, { note: icmSeen
            ? 'The backend answered without logging on the user, and the loaded ICM trace shows no rejected certificate — check CERTRULE (rule for the issuer of the short-lived certificate, e-mail / CN → user), the user (exists, not locked, e-mail unique) and login/certificate_mapping_rulebased = 1.'
            : 'The backend answered without logging on the user. The cause is not in the loaded logs: load the dev_icm (trace level 2) of the instance behind the mapping — "Reverse proxy / Cloud Connector not trusted" then names the exact icm/trusted_reverse_proxy_<n> value; if the proxy is trusted, check CERTRULE and the user mapping.' });
        });
        items.sort((a, b) => (a.kind === 'symptom') - (b.kind === 'symptom') || TS.SEV_RANK[a.sev] - TS.SEV_RANK[b.sev] || (b.count || 0) - (a.count || 0));
        const covered = def.covers.some(s => loaded.has(s));
        let status = items.some(x => x.kind === 'cause' && STRONG(x.sev)) ? 'fail' : items.length ? 'warn' : b.gaps.length ? 'unknown' : b.oks.length ? 'ok' : covered ? 'clear' : 'unknown';
        if (fail && (status === 'clear' || status === 'unknown')) status = 'blocked';
        const st = { id, n: i + 1, def, status, items, oks: b.oks, gaps: b.gaps, covered };
        if (status === 'fail' && !fail) fail = st;
        return st;
      });
      const warn = steps.find(s => s.status === 'warn') || null;
      const hasItems = ids.some(id => ['app', 'tunnel', 'scc', 'scc-be', 'wd', 'wd-be', 'abap-out', 'icm-out', 'egress', 'remote'].includes(id) && bag[id].items.length);
      const relevant = p.id === 'pp' ? loaded.has('scc') || ['app', 'tunnel', 'scc', 'scc-be'].some(id => bag[id].items.length) || (data.proxies || []).length > 0
        : p.id === 'web' ? loaded.has('wdp') || loaded.has('http') || (!loaded.has('scc') && ['icm', 'logon', 'abap'].some(id => bag[id].items.length))
          : loaded.has('sm59') || ['abap-out', 'icm-out', 'egress', 'remote'].some(id => bag[id].items.length);
      return Object.assign({}, p, { steps, fail, warn, relevant: relevant || hasItems && p.id !== 'web' });
    });

    const labels = L.labels(data, files, target, conns);
    // 9. the journey of every Cloud Connector request of the window (map replay: each request stops where it stopped)
    const requests = L.journeys(conns, paths.find(p => p.id === 'pp'), evs, proxies, inR);
    return { target, viaWd, labels, paths, other, notes, loaded, tz: data.tz, flow, window: { from, to, auto }, requests };
  };

  /* Request flows of the Cloud Connector — one per subaccount / location and system mapping (virtual → internal host). The SCC logs of
   * a shared Cloud Connector hold the requests of several applications; a finding of one of them says nothing about the others. */
  L.flows = function (conns) {
    const m = new Map();
    for (const c of conns) {
      if (!c.vhost) continue;
      const k = `${c.sub || ''}|${c.vhost}|${c.target || ''}`;
      if (!m.has(k)) m.set(k, { key: k, sub: c.sub || '', vhost: c.vhost, target: c.target || '', n: 0, x509: 0, pp: 0, redirect: 0, ids: new Set(), paths: new Map(), t0: null, t1: null });
      const f = m.get(k);
      f.n++; f.ids.add(c.id);
      if (c.x509) f.x509++;
      if (c.pp) f.pp++;
      if (c.redirect) f.redirect++;
      if (c.path) { const p = c.path.split('/').slice(0, 6).join('/'); f.paths.set(p, (f.paths.get(p) || 0) + 1); }
      if (c.t0 != null && (f.t0 == null || c.t0 < f.t0)) f.t0 = c.t0;
      if (c.t1 != null && (f.t1 == null || c.t1 > f.t1)) f.t1 = c.t1;
    }
    return [...m.values()].sort((a, b) => b.n - a.n);
  };
  L.flowLabel = f => {
    const svc = TS.topN(f.paths, 1).map(([p]) => p.split('/').filter(Boolean).pop())[0];
    const user = f.x509 ? 'principal propagation' : f.pp ? 'SSO token not used' : 'no cloud user';
    return `${f.vhost} → ${f.target || '?'} · subaccount ${(f.sub.split(' / ')[0] || '?').slice(0, 8)}${svc ? ' · ' + svc : ''} · ${user} · ${f.n} request${f.n === 1 ? '' : 's'}`;
  };

  /* Request journeys for the map replay: each Cloud Connector request of the window and the hop where it stopped.
   * Request-level evidence first — its own SCC entries (connection ID), an ICM rejection of the forwarded user certificate at its
   * time, the IdP redirect of its response. A failing hop without request-level evidence stops the requests in the time of its
   * finding (all of them when the finding has no time). A request in the SCC log has passed the user, the application and the tunnel. */
  const SKEW = 3000;   // clock and precision differences between SCC and kernel traces
  const PASSED = new Set(['user', 'app', 'tunnel']);
  L.journeys = function (conns, path, evs, proxies, inR) {
    if (!path) return [];
    const times = ok => [].concat(...(proxies || []).filter(p => !!p.ok === ok).map(p => (ok ? p.times : p.rtimes) || [])).filter(t => inR(t));
    const rej = times(false), acc = times(true);
    const span = c => [c.t0 != null ? c.t0 : c.t1, c.t1 != null ? c.t1 : c.t0];
    const near = (list, c) => { const [a, b] = span(c); return a != null && list.some(t => t >= a - SKEW && t <= b + SKEW); };
    const own = new Map();
    for (const e of evs) {
      const m = e.src === 'scc' && /^(0x[0-9a-f]+)#/i.exec(e.text || '');
      const step = m && placeOf('scc', e.rule, [e]);
      if (!step) continue;
      if (!own.has(m[1])) own.set(m[1], new Set());
      own.get(m[1]).add(step);
    }
    // findings of the other logs (ICM, Web Dispatcher, ST22 …) stop the requests of their time
    const timed = (s, c) => {
      const [a, b] = span(c);
      return s.items.some(it => it.kind === 'cause' && STRONG(it.sev) && it.src !== 'scc' && it.id !== 'icm:reverse-proxy-untrusted' &&
        (it.t0 == null || a == null || (b >= it.t0 - SKEW && a <= (it.t1 != null ? it.t1 : it.t0) + SKEW)));
    };
    return conns.filter(c => c.vhost || c.target).sort((a, b) => (a.t0 || 0) - (b.t0 || 0)).map(c => {
      const mine = own.get(c.id) || new Set();
      let stop = null, why = '';
      for (const s of path.steps) {
        if (PASSED.has(s.id)) continue;
        if (s.id === 'icm' && c.x509) {
          if (near(rej, c)) { stop = s; why = 'the ICM rejected the forwarded user certificate'; break; }
          if (near(acc, c)) continue;   // trusted reverse proxy: the user certificate reached the logon
          if (s.status === 'fail' && s.items.some(it => it.id === 'icm:reverse-proxy-untrusted')) { stop = s; why = 'the ICM does not trust the Cloud Connector as reverse proxy'; break; }
        }
        if (s.id === 'logon' && c.redirect) { stop = s; why = `redirected to the IdP ${c.redirect} (302): the user was not logged on`; break; }
        if (s.id === 'scc-be' && s.status === 'fail' && !c.backendIp) { stop = s; why = 'no backend connection was opened'; break; }
        if (s.status === 'fail' && (mine.has(s.id) || timed(s, c))) { stop = s; why = mine.has(s.id) ? 'its own Cloud Connector log entry' : `${(s.items[0] || {}).title || 'failing hop'} at the time of the request`; break; }
      }
      const fate = !stop ? 'ok' : stop.id === 'logon' && c.redirect && stop.status !== 'fail' ? 'warn' : 'fail';
      return { id: c.id, t0: c.t0, t1: c.t1, stop: stop ? stop.id : null, n: stop ? stop.n : null, fate, why, user: c.certSubject || c.principal || '', path: c.path || '', redirect: c.redirect || '' };
    });
  };

  // best path to show first: relevant, failing, then warnings
  L.pickPath = function (diag) {
    const rank = p => (p.relevant ? 0 : 10) + (p.fail ? 0 : p.warn ? 1 : 2);
    return diag.paths.slice().sort((a, b) => rank(a) - rank(b))[0].id;
  };

  /* ---------- Dynamic labels for the map (what the logs say about each component) ---------- */
  L.labels = function (data, files, target, conns) {
    const lb = {};
    const locs = uniq(conns.map(c => (c.sub || '').split(' / ')[1]));
    if (locs.length) lb.app = 'location ' + locs.slice(0, 2).join(', ');
    const subs = uniq(conns.map(c => (c.sub || '').split(' / ')[0]));
    if (subs.length) lb.tunnel = 'subaccount ' + subs[0].slice(0, 8) + (subs.length > 1 ? ` +${subs.length - 1}` : '');
    const scc = uniq(conns.map(c => c.sccIp));
    if (scc.length) lb.scc = scc.slice(0, 2).join(', ');
    const idp = uniq(conns.map(c => c.redirect));
    if (idp.length) lb.ias = idp[0].split('.')[0] + (idp[0].includes('accounts.ondemand.com') || idp[0].includes('accounts.cloud.sap') ? ' (IAS)' : '');
    const s4 = [target.sid, target.endpoint || target.host].filter(Boolean);
    if (s4.length) lb.s4 = s4.join(' · ');
    const wd = files.filter(f => f.src === 'wdp').map(f => base(f.name));
    if (wd.length) lb.wd = wd[0];
    const dests = uniq(data.tests.map(t => t.dest));
    if (dests.length) lb.remote = dests.slice(0, 2).join(', ');
    return lb;
  };

  /* ---------- Markdown report ---------- */
  const ICON = { fail: '✖', warn: '▲', ok: '✔', clear: '✔', blocked: '–', unknown: '?' };
  L.STATUS_LABEL = { fail: 'Fails here', warn: 'Warning / symptom', ok: 'Works', clear: 'No errors in the logs', blocked: 'Not reached', unknown: 'No log loaded' };
  L.report = function (diag, files) {
    const t = diag.target, out = [];
    out.push('# SAP landscape — where the request breaks', '');
    out.push(`- Target system: ${t.sid || '?'} (${t.tier.toUpperCase()}${t.assumed ? ', assumed' : ''}; ${t.how})${t.endpoint ? ' · ' + t.endpoint : ''}`);
    if (diag.flow) out.push(`- Request flow: ${L.flowLabel(diag.flow)}`);
    const w = diag.window || {};
    if (w.from != null) out.push(`- Analysis window: ${TS.fmtTime(w.from)} – ${TS.fmtTime(w.to)}${w.auto ? ' (the minutes around the Cloud Connector requests; older and later log entries are not used)' : ''}`);
    out.push(`- Files: ${files.map(f => `${base(f.name)} (${C.label(f.src)})`).join(', ')}`, '');
    for (const p of diag.paths.filter(x => x.relevant)) {
      out.push(`## ${p.title}`, '');
      out.push(p.fail ? `**Breaks at hop ${p.fail.n}: ${p.fail.def.title}** — ${p.fail.items[0].title}` : p.warn ? `No failing hop; warnings at "${p.warn.def.title}".` : 'No failing hop in the loaded logs.', '');
      out.push('| # | Hop | Status | Finding |', '|---|---|---|---|');
      p.steps.forEach(s => out.push(`| ${s.n} | ${s.def.title} | ${ICON[s.status]} ${L.STATUS_LABEL[s.status]} | ${(s.items[0] && s.items[0].title) || (s.oks[0] || (s.gaps[0] && s.gaps[0].title) || '').replace(/\|/g, '/')} |`));
      out.push('');
      for (const s of p.steps.filter(x => x.items.length)) {
        out.push(`### Hop ${s.n} — ${s.def.title}`, '');
        for (const it of s.items) {
          out.push(`**${it.kind === 'symptom' ? 'Symptom' : 'Finding'} (${it.sev}): ${it.title}**${it.count ? ` — ${it.count}×` : ''}`, '');
          if (it.note) out.push(`> ${it.note}`, '');
          if (it.why) out.push(it.why, '');
          (it.params || []).forEach(x => out.push('```', x, '```'));
          if (it.evidence && it.evidence.length) { out.push('Evidence:'); it.evidence.slice(0, 6).forEach(e => out.push(`- ${e}`)); out.push(''); }
          if (it.fix && it.fix.length && it.kind !== 'symptom') { out.push('Fix:'); it.fix.forEach((f, i) => out.push(`${i + 1}. ${f}`)); out.push(''); }
        }
      }
    }
    return out.join('\n');
  };
})(window.TS);
