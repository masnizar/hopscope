/* SAP ICM module (trace files from transaction SMICM: dev_icm)
 * Uses the shared SAP kernel trace parser (core/sapkernel.js).
 */
(function (TS) {
  'use strict';

  const kernelTrace = TS.sapKernel.parser;

  /* ---------- Knowledge base ---------- */
  const R = [
    /* ---------- SSL / TLS ---------- */
    {
      id: 'ssl-untrusted', sev: 'high', cat: 'SSL / TLS',
      title: 'Peer certificate not trusted (SSSLERR_PEER_CERT_UNTRUSTED)',
      re: /SSSLERR_PEER_CERT_UNTRUSTED|peer (certificate )?not trusted|certificate (chain )?verification failed|untrusted (server )?certificate/i,
      why: 'For an outbound HTTPS call (SM59 type G/H, SOAP, OData client), the server certificate of the target is not signed by a CA that is trusted in the SSL client PSE used by the connection.',
      fix: [
        'STRUST → SSL client PSE used by the destination (Anonymous or Standard) → import the root/intermediate CA of the target server → Add to Certificate List → Save.',
        'Check in SM59 (tab Logon & Security) which SSL client certificate (ANONYM / DFAULT / custom) the destination uses.',
        'Run the SM59 connection test again; if the new certificate is not picked up, perform an ICM soft restart (SMICM → Administration → ICM → Exit Soft → Global).'
      ]
    },
    {
      id: 'ssl-client-untrusted', sev: 'high', cat: 'SSL / TLS',
      title: 'Client certificate not trusted (SSSLERR_CLIENT_CERT_UNTRUSTED)',
      re: /SSSLERR_CLIENT_CERT_UNTRUSTED|ssl3_get_client_certificate[^\n]{0,120}(fail|not trusted|untrusted)|client certificate[^\n]{0,40}(untrusted|not trusted|verification failed)/i,
      why: 'Inbound HTTPS (SAP is the SSL server): the client presented a certificate whose issuing CA is not in the certificate list of the SSL server PSE used by the port, so the handshake is aborted. Typical clients: SAP Cloud Connector (system certificate / principal propagation), Web Dispatcher with re-encryption, middleware or partners using X.509 client authentication. If the same code appears in an outbound call, the remote server rejected the SSL client certificate of SAP.',
      fix: [
        'Find the client: open the entry → “Context in file” (peer IP / port, at trace level 3 also the certificate Subject / Issuer); see System Info → “Client certificates in untrusted errors”.',
        'Find the PSE: the SSL server PSE of the port (SAPSSLS.pse = SSL server Standard, or the SSL server identity set via SSLCONFIG / icm/ssl_config_<n> for that icm/server_port_<n>).',
        'STRUST → that SSL server PSE → Import Certificate (root CA and intermediate CA of the client certificate) → Add to Certificate List → Save. Repeat for every instance if instance-specific PSEs are used.',
        'Let ICM reload the PSE if needed: SMICM → Administration → ICM → Exit Soft → Global. Then reproduce with trace level 2/3.',
        'SAP Cloud Connector: import the CA of the SCC system certificate and the SCC CA certificate (signs the short-lived principal-propagation certificates); set icm/trusted_reverse_proxy_<n> for the SCC system certificate.',
        'Check the result with the Certificates tool → Trust check (load the SSL server PSE + the client certificate).'
      ]
    },
    {
      id: 'ssl-mismatch', sev: 'high', cat: 'SSL / TLS',
      title: 'Server certificate does not match the host name',
      re: /SSSLERR_SERVER_CERT_MISMATCH|host ?name[^\n]{0,40}(mismatch|does not match)|does not match (the )?(host|server) ?name/i,
      why: 'The certificate presented by the target does not contain the host name used in the connection (CN/SubjectAltName). Often caused by using an IP or alias, or by a server that needs SNI to return the right certificate.',
      fix: [
        'Use the exact host name contained in the certificate SAN in the SM59 destination.',
        'If the server hosts several certificates (cloud / load balancer), enable SNI: icm/HTTPS/client_sni_enabled = TRUE.',
        'Check the certificate with: openssl s_client -connect <host>:443 -servername <host>.'
      ]
    },
    {
      id: 'ssl-expired', sev: 'critical', cat: 'SSL / TLS',
      title: 'Certificate expired / not yet valid',
      re: /SSSLERR_(PEER_)?CERT_EXPIRED|SSSLERR_CERT_NOT_YET_VALID|certificate (has )?expired|validity period|not yet valid/i,
      why: 'An own certificate (SSL server/client PSE) or the certificate of the peer is outside its validity period.',
      fix: ['Check the own certificates in STRUST (SSL server / SSL client PSE) and renew them (create request → sign by CA → import response).', 'If the peer certificate has expired, the target system owner must renew it.']
    },
    {
      id: 'ssl-own-cert-expired', sev: 'critical', cat: 'SSL / TLS', minLevel: 'INFO',
      title: 'Own SSL client certificate expired (0xA0600299)',
      re: /CCL\[SSL\][^\n]{0,40}Error 0xA0600299/i,
      why: 'Outbound HTTPS with client-certificate authentication: the certificate in the SSL client PSE (e.g. SAPSSLC.pse or an SSL client identity such as SAPSSL21001D.pse) is expired, so ICM cannot send it when the server requests it. The handshake then aborts and is logged as SSSLERR_SSL_READ (-58), which looks like a network error but is not. The lines after the entry show Subject, Not before / Not after and the PSE name ("cli SSL session PSE").',
      fix: [
        'Open the entry → “Context in file”: note the PSE name and the certificate Subject / Not after.',
        'STRUST → that SSL client PSE → renew the own certificate (Create Certificate Request → let the CA sign it → Import Certificate Response) → Save.',
        'Certificates issued by SAP BTP (OU=SAP Cloud Platform Clients, e.g. SAP Cloud ALM / Focused Run) are short-lived: renew them via the service key or the setup report of that service.',
        'SMICM → Administration → ICM → Exit Soft → Global, then repeat the connection test (SM59).'
      ]
    },
    {
      id: 'ssl-no-response', sev: 'high', cat: 'SSL / TLS',
      title: 'No / broken SSL response from peer',
      re: /SSSLERR_NO_SSL_RESPONSE|SSSLERR_CONN_CLOSED|SSSLERR_SSL_READ|SSSLERR_SSL_CONNECT|SSL_read\(\) failed|connection closed during (the )?(SSL )?handshake/i,
      why: 'The peer closed the connection during the TLS handshake or did not answer with TLS. Typical causes: HTTPS used against an HTTP port, a proxy/firewall in between, or the peer rejecting the TLS version / cipher / client certificate.',
      fix: [
        'Verify that the target port really is an HTTPS port and that a proxy is configured if required (SM59 or SICF → Client → Proxy Settings).',
        'Increase the ICM trace level to 3 and reproduce to see the handshake details.',
        'Check TLS versions & ciphers: ssl/client_ciphersuites (outbound) and ssl/ciphersuites (inbound).'
      ]
    },
    {
      id: 'ssl-handshake', sev: 'high', cat: 'SSL / TLS',
      title: 'SSL handshake failed',
      re: /SSSLERR_\w+|SSL handshake[^\n]{0,60}failed|SapSSLSessionStart(NB)?[^\n]{0,60}failed|handshake failure|no (shared|common) cipher|protocol version/i,
      exclude: /SSSLERR_PEER_CERT_UNTRUSTED|SSSLERR_CLIENT_CERT_UNTRUSTED|SSSLERR_SERVER_CERT_MISMATCH|SSSLERR_(PEER_)?CERT_EXPIRED|SSSLERR_NO_SSL_RESPONSE|SSSLERR_CONN_CLOSED|SSSLERR_SSL_READ|SSSLERR_SSL_CONNECT|SSSLERR_LIB_NOT_FOUND/i,
      why: 'The TLS negotiation failed for another reason, e.g. no common TLS version / cipher suite, or a rejected client certificate.',
      fix: [
        'Check the SSSLERR_* code in the Error codes tab for the exact reason.',
        'Compare the TLS versions and ciphers of both sides; adjust ssl/client_ciphersuites or ssl/ciphersuites if needed.',
        'Keep CommonCryptoLib (sapcrypto) up to date — old versions lack current TLS versions/ciphers.'
      ]
    },
    {
      id: 'ssl-lib', sev: 'critical', cat: 'SSL / TLS',
      title: 'SSL library not loaded (CommonCryptoLib)',
      re: /SSSLERR_LIB_NOT_FOUND|sapcrypto[^\n]{0,60}(not found|could not be loaded|cannot be loaded|failed)|SapSSLInit[^\n]{0,40}failed|SSL (is )?not (active|available|initialized)/i,
      why: 'ICM cannot load the CommonCryptoLib, so no HTTPS ports or outbound SSL connections are available.',
      fix: ['Check the profile parameters ssl/ssl_lib and sec/libsapsecu and that the library exists in the kernel directory.', 'Check that the SSL PSEs exist in STRUST (SSL server / SSL client) and restart ICM.']
    },
    {
      id: 'ssl-client-cert', sev: 'medium', cat: 'SSL / TLS',
      title: 'Client certificate missing / rejected',
      re: /no client certificate|client certificate[^\n]{0,60}(missing|rejected|not (trusted|accepted|requested))|verify_client|SSSLERR_PEER_NO_CERT/i,
      why: 'X.509 client-certificate logon (e.g. principal propagation via SAP Cloud Connector, or reverse proxy forwarding) did not provide or trust the expected certificate.',
      fix: [
        'Inbound: check icm/HTTPS/verify_client (1 = request, 2 = require) on the HTTPS port.',
        'For a reverse proxy / SAP Cloud Connector in front: maintain icm/trusted_reverse_proxy_<n> (or icm/HTTPS/trust_client_with_issuer / trust_client_with_subject on older kernels).',
        'Map certificates to users with CERTRULE (login/certificate_mapping_rulebased = 1).'
      ]
    },
    {
      // trace level 2: the proxy's own TLS client certificate is compared with every icm/trusted_reverse_proxy_<n> entry. "does not
      // match trusted subject / issuer" is logged for each entry that does not match — a later entry may still match ("intermediary
      // is trusted"). Only "Reject untrusted forwarded certificate" means the forwarded user certificate (SSL_CLIENT_CERT) was removed.
      id: 'reverse-proxy-untrusted', sev: 'high', cat: 'Inbound HTTP', minLevel: 'INFO',
      title: 'Reverse proxy / Cloud Connector not trusted — forwarded user certificate rejected',
      re: /Reject untrusted forwarded certificate/i,   // one line per rejected request
      why: 'A reverse proxy (SAP Cloud Connector with principal propagation, or a Web Dispatcher terminating SSL) forwarded a user certificate in the SSL_CLIENT_CERT header, but the certificate the proxy itself presented in the TLS handshake matches no icm/trusted_reverse_proxy_<n> entry — SUBJECT and ISSUER must both match exactly. ICM removes the forwarded certificate, the request is anonymous and ICF redirects to the SAML IdP or answers 401 (for BTP apps: 302 / 405 / "remote OData service responded with status code …"). The table "Reverse proxy certificate vs. icm/trusted_reverse_proxy" shows the presented certificate, the configured values and the parameter to add.',
      fix: [
        'DEFAULT profile: add icm/trusted_reverse_proxy_<next free n> = SUBJECT="<subject of the proxy certificate>", ISSUER="<its issuer>" exactly as in the table (self-signed SCC system certificate: SUBJECT = ISSUER). Keep the entries other Cloud Connectors / Web Dispatchers still need.',
        'RZ10: first Utilities → Import profiles → Of active servers (so the DB copy equals the file), then change and activate. An "Automatically generated import profile" version after an unactivated change silently drops it — check the version history in RZ10 / table TPFHT.',
        'Activate: restart ICM on every instance (SMICM → Administration → ICM → Exit Soft → Global) and check the value per instance in SMICM → Goto → Parameters → Display.',
        'Without ICM restart (temporary, lost at the next restart — SAP Note 3385386): SE37 → ICM_SET_VECTOR_PARM → test, tick Case-sensitive, NAME = icm/trusted_reverse_proxy (no index), VALUE_TAB = ALL entries (_0, _1, …; missing ones are cleared), RFC Target = <host>_<SID>_<nr> of the instance or GLOBAL = X; check with ICM_GET_VECTOR_PARM. If the profile has restrict_admin/actions with ICM_CHANGE_PARAMS / ICM_RESTART / PFL_PARAM_CHANGE (SAP RISE), these actions only work in the clients of restrict_admin/admin_clients (usually 000) — otherwise ICM_AUTH_FAILED.',
        'Verify with SMICM trace level 2 on the instance the proxy connects to: no "does not match trusted subject", then "Forwarded Client certificate" and the logon of the user mapped by CERTRULE (login/certificate_mapping_rulebased = 1).'
      ]
    },

    /* ---------- Network (NI layer) ---------- */
    {
      id: 'ni-host-unknown', sev: 'high', cat: 'Network',
      title: 'Host name cannot be resolved (NIEHOST_UNKNOWN)',
      re: /NIEHOST_UNKNOWN|hostname '?[\w.-]+'? (not found|unknown)|NiHLGetNodeAddr[^\n]{0,60}(failed|not found)|getaddrinfo[^\n]{0,40}fail/i,
      why: 'The application server cannot resolve the target host name.',
      fix: ['Check the host name in the destination / configuration.', 'Test on OS level from the application server: nslookup <host> and check /etc/hosts or DNS.', 'Use niping -v -H <host> to test SAP name resolution.']
    },
    {
      id: 'ni-refused', sev: 'high', cat: 'Network',
      title: 'Connection refused (NIECONN_REFUSED)',
      re: /NIECONN_REFUSED|connection refused|ECONNREFUSED/i,
      why: 'The target host is reachable but nothing listens on the port, or a firewall actively rejects the connection.',
      fix: ['Check the target port in SM59 / the configuration.', 'Test from the application server OS: curl -v https://<host>:<port> or nc -vz <host> <port>.', 'Check firewall rules between the SAP server and the target.']
    },
    {
      id: 'ni-timeout', sev: 'medium', cat: 'Network',
      title: 'Network connect timeout (NIETIMEOUT)',
      re: /NIETIMEOUT|connect(ion)? timed? ?out|NiIConnect[^\n]{0,60}timeout/i,
      why: 'The connection could not be established in time — typically a firewall silently dropping packets or a missing route/proxy.',
      fix: ['Check whether a proxy is required for this target (SICF → Client → Proxy Settings or SM59).', 'Check firewall / routing from the application server to the target.']
    },
    {
      id: 'ni-broken', sev: 'medium', cat: 'Network',
      title: 'Connection closed / reset by peer',
      re: /NIECONN_BROKEN|connection reset by peer|ECONNRESET|connection (closed|broken) by (peer|partner)|broken pipe/i,
      why: 'The peer (client, load balancer, firewall or backend) closed the TCP connection unexpectedly, e.g. because of an idle timeout.',
      fix: ['Align idle timeouts of load balancers / firewalls with icm/keep_alive_timeout.', 'If it happens for long requests, compare with PROCTIMEOUT of the port (icm/server_port_<n>).']
    },
    {
      id: 'port-bind', sev: 'critical', cat: 'Network',
      title: 'ICM cannot open a service port',
      re: /NIESERV_USED|NiBufListen[^\n]{0,60}failed|NiListen[^\n]{0,60}failed|address already in use|could not (create|open)[^\n]{0,30}(listen|server) (socket|port)|bind[^\n]{0,30}failed/i,
      why: 'A port configured in icm/server_port_<n> is already in use by another process or instance, so the service is not available.',
      fix: ['Find the process using the port (netstat -anp | grep <port>).', 'Check for duplicate instance numbers / ports in the profiles (icm/server_port_<n>).', 'After fixing, activate the services in SMICM → Goto → Services or restart ICM.']
    },

    /* ---------- Resources ---------- */
    {
      id: 'mpi-buffers', sev: 'critical', cat: 'ICM resources',
      title: 'MPI buffers exhausted',
      re: /out of MPI|MPI[^\n]{0,40}(buffer|block)s?[^\n]{0,30}(exhausted|full|no more|not available)|no more (free )?MPI|MpiGetOutbuf[^\n]{0,30}failed|MPI_ENOMEM|temporarily out of MPI buffers/i,
      why: 'The shared memory buffers used by ICM to transfer requests/responses to the work processes are exhausted (large payloads, slow clients, many parallel requests).',
      fix: [
        'Monitor in SMICM → Goto → Memory Pipes → Current Use / Statistics (peak usage).',
        'Increase mpi/total_size_MB (and check mpi/buffer_size, mpi/max_pipes), then restart ICM.',
        'Look for very large requests/responses or clients that read slowly.'
      ]
    },
    {
      id: 'threads', sev: 'high', cat: 'ICM resources',
      title: 'ICM worker threads exhausted',
      re: /max(imum)?\.? (number of )?(worker )?threads|icm\/max_threads|no (more )?(free |idle )?(worker )?threads|all (worker )?threads (are )?busy|thread pool (exhausted|full)/i,
      why: 'All ICM worker threads are busy, new connections have to wait or are rejected.',
      fix: ['Check SMICM → Goto → Threads and the thread statistics (peak).', 'Increase icm/max_threads (and icm/min_threads); check for hanging backend calls that block threads.']
    },
    {
      id: 'connections', sev: 'high', cat: 'ICM resources',
      title: 'Maximum number of connections reached',
      re: /max(imum)?\.? (number of )?connections|icm\/max_conn|too many connections|connection (table|pool) (is )?full|no (more )?free connection/i,
      why: 'The ICM connection table is full; new client connections are refused.',
      fix: ['Check SMICM → Goto → Connections and the statistics (peak).', 'Increase icm/max_conn; reduce long-living idle connections via icm/keep_alive_timeout.']
    },
    {
      id: 'memory', sev: 'critical', cat: 'ICM resources',
      title: 'Out of memory',
      re: /out of memory|malloc[^\n]{0,30}failed|MemAlloc[^\n]{0,30}failed|ENOMEM|cannot allocate memory/i,
      exclude: /MPI/i,
      why: 'ICM could not allocate memory from the operating system.',
      fix: ['Check OS memory / swap and process limits (ulimit) of the <sid>adm user.', 'Check SMICM statistics and the HTTP server cache size (icm/HTTP/server_cache_0/...).']
    },

    /* ---------- Timeouts ---------- */
    {
      id: 'proc-timeout', sev: 'medium', cat: 'Timeouts',
      title: 'Request processing timeout (PROCTIMEOUT / ICM_HTTP_TIMEOUT)',
      re: /PROCTIMEOUT|processing time ?out|ICM_HTTP_TIMEOUT|request (processing )?timed out|timeout (while|during) (waiting|processing)/i,
      why: 'The request was not answered within the processing timeout — usually a long-running ABAP/backend process or a slow outbound target.',
      fix: [
        'Inbound: identify the long-running request (SM50 / SM66, ST12 / ST05) and optimize it; if justified, raise PROCTIMEOUT of the port in icm/server_port_<n>.',
        'Outbound: check the response time of the target and the timeout setting of the SM59 destination.',
        'Note: keep-alive timeouts (TIMEOUT / icm/keep_alive_timeout) concern idle connections, PROCTIMEOUT the processing time.'
      ]
    },

    /* ---------- Outbound HTTP (SM59) ---------- */
    {
      id: 'icm-http-conn', sev: 'high', cat: 'Outbound HTTP',
      title: 'Outbound HTTP connection failed (ICM_HTTP_CONNECTION_FAILED / BROKEN)',
      re: /ICM_HTTP_CONNECTION_(FAILED|BROKEN)|ICM_HTTP_NO_SERVER|ICM_HTTP_SSL_ERROR/i,
      why: 'An outbound HTTP(S) call from ABAP (SM59, CL_HTTP_CLIENT, SOAP/OData client) failed. The underlying NI/SSL error is usually logged in the lines before.',
      fix: ['Open the entry and use “Context in file” to see the preceding NI*/SSSLERR_* error.', 'Run the SM59 connection test and check proxy settings (SM59 / SICF → Client → Proxy Settings).']
    },
    {
      id: 'proxy', sev: 'high', cat: 'Outbound HTTP',
      title: 'HTTP proxy problem',
      re: /ICM_HTTP_PROXY\w*|proxy[^\n]{0,60}(refused|failed|error|unreachable|authentication|auth required)|407 Proxy/i,
      why: 'The outbound call goes through an HTTP proxy that rejects the connection or requires authentication.',
      fix: ['Check proxy host/port/user in SM59 (tab Advanced) or globally in SICF → Client → Proxy Settings.', 'Ask the network team whether the target host is allowed through the proxy.']
    },

    /* ---------- Inbound HTTP ---------- */
    {
      id: 'http-5xx', sev: 'medium', cat: 'Inbound HTTP', minLevel: 'INFO',
      title: 'HTTP 5xx responses',
      re: /HTTP\/1\.[01] (500|502|503|504)\b|ICM_HTTP_SERVICE_UNAVAILABLE|ICM_HTTP_INTERNAL_ERROR|status(code)?[ :=]+(500|502|503|504)\b/i,
      why: 'Server errors returned by the ABAP application, ICM or the backend behind the Web Dispatcher.',
      fix: ['Check ST22 (dumps), SM21 and the application logs at the same time; for OData /IWFND/ERROR_LOG.', '503 / SERVICE_UNAVAILABLE: check whether work processes / backend servers were available.']
    },
    {
      id: 'request-size', sev: 'medium', cat: 'Inbound HTTP',
      title: 'Request too large / header too long',
      re: /request (header |body )?too (large|long)|max_request_size|header[^\n]{0,30}too (long|large)|\b413\b/i,
      why: 'The request exceeds the configured maximum size.',
      fix: ['Check icm/HTTP/max_request_size_KB and, for headers, the related ICM header limits; increase only if the large requests are legitimate.']
    },
    {
      id: 'permission', sev: 'medium', cat: 'Inbound HTTP',
      title: 'Request blocked by ICM filter / permission rules',
      re: /permission (denied|table)|denied by (rule|filter)|blocked by[^\n]{0,30}(rule|filter|permission)|icm\/HTTP\/(auth|mod)_\d/i,
      why: 'The request was rejected by an ICM permission file (icm/HTTP/auth_<n>) or rewrite/filter rule (icm/HTTP/mod_<n>).',
      fix: ['Review the permission/rewrite files referenced in icm/HTTP/auth_<n> and icm/HTTP/mod_<n>.']
    },

    /* ---------- Work processes / dispatcher ---------- */
    {
      id: 'dispatcher', sev: 'high', cat: 'Work processes',
      title: 'Problem passing requests to the work processes',
      re: /(dispatcher|\bDP\b)[^\n]{0,60}(connection|link)[^\n]{0,30}(lost|broken|failed)|IcmMsg\w*[^\n]{0,60}failed|no free (dialog )?work process|DP_NO_FREE|request queue (is )?full|queue overflow/i,
      why: 'ICM could not hand the request over to the dispatcher / work processes (no free work process, full request queue or broken dispatcher link).',
      fix: ['Check SM50 / SM66 for blocked work processes and the dispatcher queue (dpmon or SM51 → Goto → Server Information → Queue Information).', 'Check dev_disp and dev_w* traces at the same time.']
    },
    {
      id: 'webdisp-backend', sev: 'high', cat: 'Web Dispatcher',
      title: 'No backend server available (Web Dispatcher)',
      re: /no (active|available|running) (application )?server|server[^\n]{0,60}(marked|set) (as )?(down|inactive|unavailable)|backend[^\n]{0,40}not reachable|no server (found|available) for/i,
      why: 'The Web Dispatcher found no available backend application server for the request (servers down, logon group empty, or message server connection lost).',
      fix: ['Check the Web Dispatcher administration (Monitor → Servers) and the message server connection.', 'Check logon groups (SMLG) and that the backend ICMs are running.']
    },
    {
      id: 'message-server', sev: 'high', cat: 'Web Dispatcher',
      title: 'Message server connection problem',
      re: /message server[^\n]{0,60}(not|fail|lost|error|unreachable)|MsAttach[^\n]{0,30}failed|MsI\w*[^\n]{0,40}failed|NIEROUT/i,
      why: 'The connection to the message server (used for load balancing / server lists) is lost or cannot be established.',
      fix: ['Check that the message server is running and reachable (host/port of rdisp/mshost and ms/http_port).', 'Check dev_ms of the message server.']
    },

    /* ---------- Process health ---------- */
    {
      id: 'icm-crash', sev: 'critical', cat: 'ICM process',
      title: 'ICM crash / signal received',
      re: /SIGSEGV|SIGABRT|segmentation fault|core dump|signal (6|11)\b|ICM (terminated|died|crashed) unexpectedly|emergency shutdown/i,
      why: 'The ICM process terminated abnormally.',
      fix: ['Check the kernel patch level and search the SAP Support Portal for the call stack in dev_icm.', 'Keep a copy of dev_icm.old (it contains the trace before the restart).']
    },
    {
      id: 'icm-restart', sev: 'info', cat: 'ICM process', minLevel: 'INFO',
      title: 'ICM start / stop / restart',
      re: /ICM[^\n]{0,30}(started|restart(ed|ing)?|shut(ting)? ?down|stopp(ed|ing)|terminat(ed|ing))|IcmMain[^\n]{0,30}start|exit (soft|hard)/i,
      exclude: /unexpectedly/i,
      why: 'Marks ICM restarts. Correlate errors with restarts and configuration changes.',
      fix: []
    },
    {
      id: 'trace-level', sev: 'info', cat: 'Trace', minLevel: 'INFO',
      title: 'Trace level changed',
      re: /trace level[^\n]{0,30}(set|changed|increased|decreased)|new trace level|trc level/i,
      why: 'The ICM trace level was changed. Level 1 only shows errors; level 2 adds HTTP headers and connection flow; level 3 includes data.',
      fix: ['Reset the trace level to 1 after the analysis (SMICM → Goto → Trace Level).']
    }
  ];

  /* ---------- Root cause (error code) per WARN/ERROR entry ---------- */
  const rootCause = TS.sapKernel.rootCause;

  /* ---------- Insights ---------- */
  const H_TRC = /trc file:\s*"([^"]+)",\s*trc level:\s*(\d+)(?:,\s*release:\s*"(\d+)")?/i;
  const H_FIELDS = [
    ['sid', /^\s*sid\s+(\w{3})\s*$/im], ['sysno', /^\s*sysno\s+(\d{2})\s*$/im],
    ['relno', /^\s*relno\s+(\d+)\s*$/im], ['patchno', /^\s*patchno\s+(\d+)\s*$/im],
    ['profile', /^\s*profile\s+(\S+)\s*$/im], ['make', /^\s*make\s+(.+?)\s*$/im]
  ];
  const RE_CRYPTO = /(?:CommonCryptoLib|SAPCRYPTOLIB|sapcrypto)[^\n]{0,60}?(?:version|Version)[:\s]+"?([\d.]+(?:\s*pl\s*\d+)?)/i;
  const RE_SERVICE = /started service (\d+) for protocol (\w+)/i;
  const RE_HOSTNAME = /(?:icm\/host_name_full|hostname|running on host)\s*[:=]?\s*'?([A-Za-z0-9][\w.-]+)'?/i;
  const RE_EP1 = /\b((?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z][a-z0-9-]{1,62}|\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b/gi;
  const RE_EP2 = /host\s*[=:]?\s*'?([A-Za-z0-9][\w.-]+)'?,?\s*(?:service|port)\s*[=:]?\s*'?(\d{2,5})'?/gi;

  function bump(map, k) { map.set(k, (map.get(k) || 0) + 1); }

  /* Client certificates involved in "client certificate untrusted" errors.
   * The peer address is taken from the last "peer=…"/"from …" line of the same thread; Subject / Issuer lines
   * (trace level 3) are collected from the error entry and the following entries. */
  const RE_CC_ERR = /SSSLERR_CLIENT_CERT_UNTRUSTED|ssl3_get_client_certificate|client certificate[^\n]{0,40}(untrusted|not trusted|verification failed)/i;
  const RE_PEER = /(?:peer|remote|client|from)\s*[=:]?\s*\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{6,}|[A-Za-z][\w.-]*\.[A-Za-z]{2,})\]?[:/](\d{2,5})\b/i;
  const RE_SUBJ = /\bSubject(?: ?name)?\s*[:=]\s*"?([^"\n]{3,200})/i;
  const RE_ISS = /\bIssuer(?: ?name)?\s*[:=]\s*"?([^"\n]{3,200})/i;
  const RE_PSE = /\b([A-Za-z0-9_-]+\.pse)\b/g;
  function clientCerts(entries, pses) {
    const out = new Map(), lastPeer = new Map();
    let cur = null, left = 0;
    const close = () => {
      if (cur && (cur.subject || cur.issuer || cur.peer)) {
        const k = `${cur.subject}\u0000${cur.issuer}\u0000${cur.peer}`;
        const r = out.get(k) || { subject: cur.subject || '(not in trace — use trace level 3)', issuer: cur.issuer || '-', peer: cur.peer || '-', n: 0 };
        r.n++; out.set(k, r);
      }
      cur = null; left = 0;
    };
    for (const e of entries) {
      const lines = [e.message].concat(e.detail ? e.detail.split('\n').slice(0, 120) : []);
      let m;
      for (const l of lines) {
        if ((m = RE_PEER.exec(l))) lastPeer.set(e.thread, m[1] + ':' + m[2]);
        RE_PSE.lastIndex = 0;
        while ((m = RE_PSE.exec(l))) bump(pses, m[1]);
      }
      if (RE_CC_ERR.test(e.message) || (e.detail && RE_CC_ERR.test(e.detail.slice(0, 4000)))) {
        close();
        cur = { subject: '', issuer: '', peer: lastPeer.get(e.thread) || '' };
        left = 40;
      }
      if (!cur) continue;
      for (const l of lines) {
        if (!cur.subject && (m = RE_SUBJ.exec(l))) cur.subject = m[1].trim();
        else if (!cur.issuer && (m = RE_ISS.exec(l))) cur.issuer = m[1].trim();
        if (!cur.peer && (m = RE_PEER.exec(l))) cur.peer = m[1] + ':' + m[2];
      }
      if ((cur.subject && cur.issuer) || --left <= 0) close();
    }
    close();
    return [...out.values()].sort((a, b) => b.n - a.n);
  }

  /* Trace level 2: proxy certificate vs. icm/trusted_reverse_proxy_<n>, per request (thread).
   * "does not match trusted subject / issuer" is logged for every configured entry that does not match; a later entry may still match
   * ("intermediate is trustworthy … matches" → "intermediary is trusted"). A request without client certificate (browser, load balancer:
   * "client did not sent any cert") is normal. Only "Reject untrusted forwarded certificate" means a forwarded user certificate was dropped.
   * → rows { subject, issuer, ok (trusted), n (requests), rejected, trusted (configured entries compared), fwd (user certificates), peers } */
  function proxyCerts(entries) {
    const rows = new Map(), cur = new Map(), last = new Map();
    const pair = c => `SUBJECT="${c.tSubject || '?'}", ISSUER="${c.tIssuer || '?'}"`;
    // times / rtimes: server time of each verdict / rejection, so a caller can count only those of its time range
    const row = (ok, subject, issuer) => {
      const k = (ok ? 'T|' : 'R|') + subject + '|' + issuer;
      if (!rows.has(k)) rows.set(k, { subject, issuer, ok, n: 0, rejected: 0, trusted: new Set(), fwd: new Map(), peers: new Set(), times: [], rtimes: [] });
      return rows.get(k);
    };
    const stamp = (list, t) => { if (t != null && list.length < 20000) list.push(t); };
    const state = thr => cur.get(thr) || { subject: '', issuer: '', tSubject: '', tIssuer: '', trusted: [] };
    let m;
    for (const e of entries) {
      const msg = e.message || '', thr = e.thread;
      if ((m = /intermediate cert (subject|issuer) "([^"]*)" does not match trusted (?:subject|issuer) "([^"]*)"/.exec(msg))) {
        last.delete(thr);
        const c = state(thr);
        if (m[1] === 'issuer') {
          if (c.tIssuer) { c.trusted.push(pair(c)); c.tSubject = ''; }   // next configured entry
          c.issuer = m[2]; c.tIssuer = m[3];
        } else { c.subject = m[2]; c.tSubject = m[3]; }
        cur.set(thr, c);
      } else if ((m = /^"(.+?):([A-Za-z][\w.-]*=[^"]*)" matches "/.exec(msg))) {   // the matching entry, "issuer:subject"
        const c = state(thr); c.issuer = m[1]; c.subject = m[2]; cur.set(thr, c);
      } else if (/HttpIsReverseProxyTrustworthy: intermediary is trusted/.test(msg)) {
        const c = state(thr); cur.delete(thr);
        const r = row(true, c.subject || '?', c.issuer || '?');
        r.n++; stamp(r.times, e.t); last.set(thr, r);
      } else if (/client did not sent any cert/.test(msg)) { cur.delete(thr); last.delete(thr); }
      else if (/HttpIsReverseProxyTrustworthy: intermediary is NOT trusted/.test(msg)) {
        const c = cur.get(thr); cur.delete(thr);
        if (!c) { last.delete(thr); continue; }   // nothing compared: no client certificate
        if (c.tIssuer || c.tSubject) c.trusted.push(pair(c));
        const r = row(false, c.subject, c.issuer);
        r.n++; stamp(r.times, e.t); c.trusted.forEach(t => r.trusted.add(t));
        last.set(thr, r);
      } else if (!last.has(thr)) continue;
      else if ((m = /Reject untrusted forwarded certificate[^:]*: subject="([^"]*)", issuer="([^"]*)"/.exec(msg))) { const r = last.get(thr); r.rejected++; stamp(r.rtimes, e.t); bump(r.fwd, `${m[1]} (issuer ${m[2]})`); }
      else if ((m = /Forwarded Client certificate: subject="([^"]*)", issuer="([^"]*)"/.exec(msg))) bump(last.get(thr).fwd, `${m[1]} (issuer ${m[2]})`);
      else if ((m = /Connection Info: role=Server, local=[^,]+, peer=([^,\s]+)/.exec(msg))) last.get(thr).peers.add(m[1]);
      else if (/HttpHandleCertificate|HttpParseRequestHeader: Version|HttpSrvHdlRequest/.test(msg)) last.delete(thr);   // next request / handler stage
    }
    // not trusted without a forwarded user certificate (e.g. an availability check) is not a problem
    return [...rows.values()].filter(r => r.ok || r.rejected).sort((a, b) => a.ok - b.ok || b.n - a.n);
  }

  function insights(entries) {
    const hdr = {}, trc = new Map(), crypto = new Map(), services = new Map(), hosts = new Map(), codes = new Map(), ep = new Map(), pses = new Map();
    const cc = clientCerts(entries, pses), pc = proxyCerts(entries).filter(r => !r.ok);
    let restarts = 0;
    for (const e of entries) {
      const headerish = e.t == null || (e.detail && e.detail.indexOf('trc file') >= 0) ||
        /trc file|relno|patchno|CommonCrypto|SAPCRYPTOLIB|sapcrypto|started service|host_name_full|running on host/i.test(e.message);
      if (headerish) {
        const text = e.message + (e.detail ? '\n' + e.detail.slice(0, 6000) : '');
        let m;
        if ((m = H_TRC.exec(text))) { bump(trc, `${m[1]} level ${m[2]}`); if (m[3] && !hdr.release) hdr.release = m[3]; }
        for (const [k, re] of H_FIELDS) if (!hdr[k] && (m = re.exec(text))) hdr[k] = m[1];
        if ((m = RE_CRYPTO.exec(text))) bump(crypto, m[1]);
        if ((m = RE_SERVICE.exec(text))) services.set(`${m[2].toUpperCase()}:${m[1]}`, 1);
        if ((m = RE_HOSTNAME.exec(text))) bump(hosts, m[1]);
        restarts += (text.match(/trc file:/gi) || []).length;
      }
      if (e.level === 'INFO' && !/ICM_HTTP_|SSSLERR_|NIE[A-Z]/.test(e.message)) continue;
      const g = /\b(SSSLERR_[A-Z_]+|NIE[A-Z_]{3,}|ICM_HTTP_[A-Z_]+|MPI_E[A-Z_]+)\b/g;
      let m;
      const seen = new Set();
      while ((m = g.exec(e.message))) if (!seen.has(m[1])) { seen.add(m[1]); bump(codes, m[1]); }
      if (TS.LEVEL_RANK[e.level] <= 2) {
        const t = e.message.slice(0, 1500), seenEp = new Set();
        for (const re of [RE_EP1, RE_EP2]) {
          re.lastIndex = 0;
          while ((m = re.exec(t))) {
            const host = m[1].toLowerCase();
            if (/\.(c|cpp|h)$/.test(host)) continue;
            const k = host + ':' + m[2];
            if (!seenEp.has(k)) { seenEp.add(k); bump(ep, k); }
          }
        }
      }
    }
    const list = map => TS.topN(map, 6).map(([k, n]) => (n > 1 ? `${k} (${n}×)` : k)).join(', ') || '-';
    return {
      kv: [
        ['SID / instance', [hdr.sid, hdr.sysno].filter(Boolean).join(' / ') || '-'],
        ['Kernel release / patch', [hdr.release || hdr.relno, hdr.patchno && 'patch ' + hdr.patchno].filter(Boolean).join(', ') || '-'],
        ['Trace file / level', list(trc)],
        ['CommonCryptoLib', list(crypto)],
        ['ICM services', [...services.keys()].join(', ') || '-'],
        ['Host', list(hosts)],
        ['Profile', hdr.profile || '-'],
        ['Trace headers in file (ICM starts / file switches)', restarts ? String(restarts) : '-'],
        ['PSE files mentioned', list(pses)]
      ],
      tables: [
        ...(cc.length ? [{ title: 'Client certificates in "untrusted" errors (import their issuer into the SSL server PSE)', cols: ['Subject', 'Issuer', 'Peer', 'Errors'], rows: cc.slice(0, 30).map(r => [r.subject, r.issuer, r.peer, r.n]), filterCol: 2 }] : []),
        ...(pc.length ? [{ title: 'Reverse proxy certificate vs. icm/trusted_reverse_proxy (forwarded user certificates rejected)',
          cols: ['Proxy certificate (subject / issuer)', 'Peer', 'Configured trusted proxies', 'Rejected requests', 'Forwarded user certificates', 'Parameter to add'],
          rows: pc.slice(0, 20).map(r => [`${r.subject || '?'} / ${r.issuer || '?'}`, [...r.peers].join(', ') || '-', [...r.trusted].join('; ') || '-', r.rejected,
            TS.topN(r.fwd, 3).map(([k, n]) => `${k} (${n}×)`).join(', ') || '-', `icm/trusted_reverse_proxy_<n> = SUBJECT="${r.subject}", ISSUER="${r.issuer}"`]), filterCol: 1 }] : []),
        { title: 'Error codes (SSSLERR_*, NI*, ICM_HTTP_*)', cols: ['Code', 'Entries'], rows: TS.topN(codes, 30).map(([k, n]) => [k, n]), filterCol: 0 },
        { title: 'Endpoints (host:port) in WARN/ERROR entries', cols: ['Endpoint', 'Entries'], rows: TS.topN(ep, 25).map(([k, n]) => [k, n]), filterCol: 0 }
      ]
    };
  }

  // shared with the Web Dispatcher module (WDP runs the same ICM kernel component)
  TS.icm = { rules: R, insights, proxyCerts };

  TS.registerModule({
    proxyCerts,
    id: 'icm',
    name: 'SAP ICM (SMICM)',
    short: 'ICM',
    description: 'Analyze ICM trace files from transaction SMICM (dev_icm, dev_icm.old), other kernel traces (dev_disp, dev_w*) and the ICM HTTP log.',
    exceptionsLabel: 'Error codes',
    exceptionsTitle: 'Error codes (root cause)',
    exceptionsHint: 'SSSLERR_*, NI*, ICM_HTTP_* codes found in WARN/ERROR entries (or function + rc).',
    loggerLabel: 'Functions with most WARN/ERROR',
    fileTypes: [
      { match: /^dev_icm/i, label: 'ICM trace (dev_icm)', parser: 'sap-kernel' },
      { match: /^dev_(disp|ms|w\d+|rd)/i, label: 'Kernel trace', parser: 'sap-kernel' },
      { match: /http_?log|access_log|icm.*\.log/i, label: 'ICM HTTP log', parser: 'access' }
    ],
    parsers: [kernelTrace],
    rules: R,
    rootCause,
    insights,
    guide: [
      ['Display in SMICM', 'SMICM → <b>Goto → Trace File → Display All</b> (or Display End). Save it locally via <b>System → List → Save → Local File</b> (unconverted).'],
      ['Download the file', 'File system: <code>/usr/sap/&lt;SID&gt;/&lt;INSTANCE&gt;/work/dev_icm</code> (and <code>dev_icm.old</code>). From SAP GUI: AL11 → DIR_HOME → dev_icm, or CG3Y. For the Web Dispatcher use the component “SAP Web Dispatcher (WDP)”.'],
      ['Clean trace', 'Before reproducing: SMICM → <b>Goto → Trace File → Reset</b>, so the file only contains the relevant period.'],
      ['Trace level', 'SMICM → <b>Goto → Trace Level → Set</b>: level 1 = errors only, <b>2</b> = HTTP headers & connection flow (good for most issues), 3 = including data/payload. Set it back to 1 afterwards — level 3 grows fast and may contain sensitive data.'],
      ['HTTP log', 'If icm/HTTP/logging_&lt;n&gt; is active, the HTTP access log (SMICM → Goto → HTTP Log) can be analyzed here too.'],
      ['Correlation', 'Combine with the SM59 connection test, STRUST, SM21, ST22 and dev_w* traces for the same time range in the <a href="correlation.html">Correlation</a> dashboard.']
    ]
  });
})(window.TS);
