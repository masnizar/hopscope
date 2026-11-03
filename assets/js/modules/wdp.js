/* SAP Web Dispatcher (WDP) module — dev_webdisp traces and the Web Dispatcher HTTP log.
 * Uses the shared SAP kernel trace parser (core/sapkernel.js) and re-uses the ICM knowledge base (modules/icm.js),
 * because the Web Dispatcher runs the same ICM component. Web Dispatcher specific rules come first.
 */
(function (TS) {
  'use strict';

  const WDP_RULES = [
    {
      id: 'wdp-no-system', sev: 'high', cat: 'Routing',
      title: 'No backend system / server group for the request',
      re: /no (backend |target )?(system|server|server group) (found |available )?for (the )?(url|request|host|path)|no matching (system|server group)|could not (determine|find) (the )?(backend|target) system|ICM_HTTP_NO_SERVER|dispatching error|500 Dispatching/i,
      why: 'The Web Dispatcher could not map the request (host header, port or URL prefix) to a backend system or server group, so it answers with an error (often "500 Dispatching Error" or 503).',
      fix: [
        'Check the routing rules wdisp/system_<n> (SID, MSHOST/MSPORT, SRCSRV for host:port based routing, SRCURL for URL prefixes).',
        'Compare the host name and port used by the client with SRCSRV/SRCURL; check the Web Dispatcher administration (System Configuration / URL mapping).',
        'If only one system is used, check that its server list could be loaded (see the server-list finding).'
      ]
    },
    {
      id: 'wdp-backend-down', sev: 'high', cat: 'Backend servers',
      title: 'Backend application server unavailable / marked down',
      re: /server[^\n]{0,60}(marked|set|is) (as )?(down|inactive|unavailable|not active)|(connect(ion)?|request) to (backend |application )?server[^\n]{0,60}(failed|refused|timed out)|all servers[^\n]{0,40}(unavailable|down|inactive)|no (active|available|running) (application )?server/i,
      why: 'A backend server did not accept connections or failed its availability check; the Web Dispatcher stops sending requests to it until it is reachable again.',
      fix: [
        'Check the backend ICM (SMICM on the backend server) and that the HTTP(S) port is open from the Web Dispatcher host.',
        'Check SM51 for stopped application servers and dev_icm / dev_disp of the backend at the same time.',
        'Use the Correlation dashboard with the backend traces to see what happened on the backend.'
      ]
    },
    {
      id: 'wdp-serverlist', sev: 'high', cat: 'Backend servers',
      title: 'Server list / logon group information could not be read from the message server',
      re: /(server list|server info|group info|logon group info)[^\n]{0,60}(could not|cannot|failed|error|not (read|available|received))|wdisp\/server_info\w*|MsHttp\w*[^\n]{0,40}(fail|error)|message server[^\n]{0,60}(not|fail|lost|error|unreachable)/i,
      why: 'The Web Dispatcher periodically reads the list of application servers, ports and logon groups from the message server via HTTP(S). If this fails, it has no (current) backend servers.',
      fix: [
        'Check MSHOST/MSPORT in wdisp/system_<n> (or rdisp/mshost & ms/http_port) and that the message server HTTP(S) port is reachable from the Web Dispatcher host.',
        'Check the message server ACL (ms/acl_info) and dev_ms on the backend.',
        'If HTTPS is used for the server list (wdisp/server_info_protocol), check the SSL client PSE of the Web Dispatcher.'
      ]
    },
    {
      id: 'wdp-logon-group', sev: 'medium', cat: 'Backend servers',
      title: 'Logon group not found / without servers',
      re: /logon group[^\n]{0,60}(not found|unknown|empty|no (active )?server)|group\s+'?[\w-]+'?[^\n]{0,20}(has no|without) (active )?servers?/i,
      why: 'Requests are balanced via a logon group that does not exist or has no active servers for HTTP.',
      fix: ['Check the logon group in SMLG / RZ12 (group type and assigned instances) and the group used by the Web Dispatcher system configuration.']
    },
    {
      id: 'wdp-ssl-backend', sev: 'high', cat: 'SSL / TLS',
      title: 'SSL connection to the backend failed (re-encryption)',
      re: /(backend|application server|target server)[^\n]{0,80}SSSLERR_\w+|SSSLERR_\w+[^\n]{0,80}(backend|application server)|wdisp\/ssl_(encrypt|auth|cred)|re-?encrypt[^\n]{0,40}(fail|error)/i,
      why: 'With SSL re-encryption (wdisp/ssl_encrypt = 1/2) the Web Dispatcher acts as SSL client towards the backend; its SSL client PSE must trust the backend certificate (and present a client certificate if required).',
      fix: [
        'Import the CA of the backend SSL server certificate into the SSL client PSE of the Web Dispatcher (web administration → PSE Management, or sapgenpse maintain_pk -a).',
        'Check wdisp/ssl_encrypt, wdisp/ssl_auth and wdisp/ssl_cred, and the SSL server PSE of the backend (STRUST).',
        'Check the host name used for the backend against the certificate (SNI / SubjectAltName).'
      ]
    },
    {
      id: 'wdp-client-cert', sev: 'medium', cat: 'SSL / TLS',
      title: 'Client certificate forwarding / trust between Web Dispatcher and backend',
      re: /client cert[^\n]{0,60}(forward|header|not trusted|rejected)|SSL_CLIENT_CERT|X-SSL-Client-Cert|trusted_reverse_proxy|icm\/HTTPS\/trust_client_with/i,
      why: 'With SSL termination the Web Dispatcher forwards the client certificate to the backend in HTTP headers; the backend only accepts them from a trusted reverse proxy.',
      fix: [
        'Web Dispatcher: request client certificates on the HTTPS port (icm/HTTPS/verify_client).',
        'Backend: trust the Web Dispatcher as reverse proxy (icm/trusted_reverse_proxy_<n>, or icm/HTTPS/trust_client_with_issuer / _subject on older kernels) and map certificates to users (CERTRULE).'
      ]
    },
    {
      id: 'wdp-session', sev: 'medium', cat: 'Routing',
      title: 'Session stickiness lost',
      re: /(session|context)[^\n]{0,40}(lost|not found|expired|invalid)|sap-contextid[^\n]{0,40}(invalid|unknown|not found)|stateful[^\n]{0,30}(fail|lost)/i,
      why: 'Requests of a stateful session reached a different application server than the one holding the session, or the session expired.',
      fix: ['Check that the client sends the session cookie / sap-contextid back and that the backend server of the session is still available.', 'Check timeouts of the stateful application (SICF service settings).']
    },
    {
      id: 'wdp-admin', sev: 'low', cat: 'Administration',
      title: 'Web Dispatcher administration logon failed',
      re: /icmauth|icm\/authfile|admin(istration)?[^\n]{0,40}(logon|login|authentication)[^\n]{0,30}(fail|denied|invalid)/i,
      why: 'Logon to the Web Dispatcher web administration failed (users are kept in the file referenced by icm/authfile, default icmauth.txt).',
      fix: ['Maintain the admin users with wdispmon / icmon (or the web administration) and check icm/authfile.']
    },
    {
      id: 'wdp-rewrite', sev: 'medium', cat: 'Routing',
      title: 'Rewrite / modification rule error',
      re: /(rewrite|modification|mod) (rule|file|handler)[^\n]{0,60}(error|invalid|syntax|failed|not found)|icm\/HTTP\/mod_\d/i,
      why: 'A rewrite/modification file (icm/HTTP/mod_<n>) could not be loaded or contains an invalid rule.',
      fix: ['Check the syntax of the file referenced in icm/HTTP/mod_<n> and reload it via the web administration.']
    },
    {
      id: 'wdp-serverlist-change', sev: 'info', cat: 'Backend servers', minLevel: 'INFO',
      title: 'Server list changed',
      re: /server list[^\n]{0,40}(updated|changed|reloaded|refreshed)|(new|added|removed) (application )?server|server[^\n]{0,30}(added|removed)/i,
      why: 'Backend servers were added or removed (start/stop of application servers, logon group changes).',
      fix: []
    }
  ];

  // ICM rules that only make sense on an ABAP application server are left out
  const ICM_ONLY = new Set(['dispatcher']);
  const RULES = WDP_RULES.concat(TS.icm.rules.filter(r => !ICM_ONLY.has(r.id)));

  const RE_SYS = /wdisp\/system_\d+\s*=\s*([^\n]+)/gi;
  const RE_SID = /\bSID\s*=\s*(\w{3})/i;
  const RE_BACKEND = /\bserver[^\n]{0,40}?\b((?:[a-z0-9-]+\.)*[a-z][a-z0-9-]+|\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b/gi;

  function insights(entries, res) {
    const base = TS.icm.insights(entries, res);
    const systems = new Map(), backends = new Map();
    for (const e of entries) {
      const text = e.message + (e.t == null && e.detail ? '\n' + e.detail.slice(0, 6000) : '');
      let m;
      RE_SYS.lastIndex = 0;
      while ((m = RE_SYS.exec(text))) { const sid = RE_SID.exec(m[1]); systems.set(sid ? sid[1] : m[1].trim().slice(0, 60), 1); }
      if (/server/i.test(e.message)) {
        RE_BACKEND.lastIndex = 0;
        while ((m = RE_BACKEND.exec(e.message))) {
          const k = m[1].toLowerCase() + ':' + m[2];
          const b = backends.get(k) || { n: 0, bad: 0 };
          b.n++; if (TS.LEVEL_RANK[e.level] <= 2) b.bad++;
          backends.set(k, b);
        }
      }
    }
    base.kv = base.kv.map(([k, v]) => [k === 'ICM services' ? 'Web Dispatcher services' : k, v]);
    base.kv.splice(2, 0, ['Backend systems (wdisp/system_<n>)', [...systems.keys()].join(', ') || '-']);
    base.tables.unshift({
      title: 'Backend servers mentioned in the trace',
      cols: ['Server', 'Entries', 'WARN/ERROR'],
      rows: [...backends.entries()].sort((a, b) => b[1].bad - a[1].bad || b[1].n - a[1].n).slice(0, 30).map(([k, v]) => [k, v.n, v.bad]),
      filterCol: 0
    });
    return base;
  }

  TS.registerModule({
    id: 'wdp',
    name: 'SAP Web Dispatcher (WDP)',
    short: 'WDP',
    description: 'Analyze SAP Web Dispatcher traces (dev_webdisp, dev_webdisp.old) and the Web Dispatcher HTTP log: routing, backend availability, server list, SSL termination / re-encryption.',
    exceptionsLabel: 'Error codes',
    exceptionsTitle: 'Error codes (root cause)',
    exceptionsHint: 'SSSLERR_*, NI*, ICM_HTTP_* codes found in WARN/ERROR entries (or function + rc).',
    loggerLabel: 'Functions with most WARN/ERROR',
    fileTypes: [
      { match: /^dev_webdisp/i, label: 'Web Dispatcher trace (dev_webdisp)', parser: 'sap-kernel' },
      { match: /webdisp.*(access|http).*log|access_log/i, label: 'Web Dispatcher HTTP log', parser: 'access' },
      { match: /^sapwebdisp\.pfl|webdisp.*\.pfl/i, label: 'Web Dispatcher profile' }
    ],
    parsers: [TS.sapKernel.parser],
    rules: RULES,
    rootCause: TS.sapKernel.rootCause,
    insights,
    guide: [
      ['Trace file', '<code>dev_webdisp</code> (and <code>dev_webdisp.old</code>) in the work directory of the Web Dispatcher instance, e.g. <code>/usr/sap/&lt;SID&gt;/W&lt;nn&gt;/work</code>.'],
      ['Web administration', 'Open <code>https://&lt;wdp-host&gt;:&lt;port&gt;/sap/wdisp/admin</code> → <b>Monitor</b> → Trace file / Trace level, Servers, System configuration. On the OS: <code>wdispmon pf=&lt;profile&gt;</code>.'],
      ['Trace level', 'Set trace level 2 while reproducing (web administration → Trace level, or <code>icmon / wdispmon</code> menu) and set it back to 1 afterwards; level 3 includes payload data.'],
      ['HTTP log', 'If icm/HTTP/logging_&lt;n&gt; is active, load the Web Dispatcher HTTP log too — 5xx/4xx responses are shown with their timestamps.'],
      ['Backend side', 'Load dev_icm of the backend servers in the <a href="correlation.html">Correlation</a> dashboard together with dev_webdisp to follow a request end to end.']
    ]
  });
})(window.TS);
