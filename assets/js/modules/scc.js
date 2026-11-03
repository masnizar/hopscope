/* SAP Cloud Connector (SCC) module
 * - Parser for the SCC Java trace format (ljs_trace.log):
 *     2024-05-10 10:12:34,567 +0200#ERROR#com.sap.core.connectivity...#tunnel-client-1-1#          #Message text
 * - Knowledge base of common SCC problems (rules) with explanation + recommended actions
 * - Insights: version, Java, regions, subaccounts, backend endpoints with errors
 *
 * Rule fields: id, sev (critical|high|medium|low|info), cat, title, re, exclude?, minLevel? (default WARN),
 *              logger? (regex on logger), why, fix[]
 */
(function (TS) {
  'use strict';

  const RE_HASH_TS = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[,.](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?\s*#/;

  const sccHash = {
    id: 'scc-hash', label: 'SCC Java trace (timestamp#level#logger#thread#…#message)',
    header(line) {
      const m = RE_HASH_TS.exec(line);
      if (!m) return null;
      const parts = line.slice(m[0].length).split('#');
      if (parts.length < 3) return null;
      const level = TS.normLevel(parts[0]) || 'OTHER';
      const logger = parts[1].trim();
      const thread = (parts[2] || '').trim();
      const rest = parts.slice(3);
      // Skip empty / padding-only fields between thread and message
      while (rest.length > 1 && rest[0].trim() === '') rest.shift();
      const t = TS.mkTime(m[1], m[2] - 1, m[3], m[4], m[5], m[6], m[7], m[8]);
      return { t: t.t, off: t.off, tsText: m[0].slice(0, -1).trim(), level, logger, thread, message: rest.join('#').trim() };
    }
  };

  const R = [
    /* ---------- Certificates & TLS ---------- */
    {
      id: 'pkix', sev: 'high', cat: 'Certificates / TLS',
      title: 'Peer certificate not trusted (PKIX path building failed)',
      re: /PKIX path (building|validation) failed|unable to find valid certification path|SunCertPathBuilderException|CertPathValidatorException/i,
      why: 'SCC cannot validate the certificate chain of the target server. For backend connections: the backend CA is missing from the SCC Trust Store. For connections to BTP: usually a proxy/firewall performs SSL inspection and replaces the certificate.',
      fix: [
        'Backend HTTPS: import the backend Root/Intermediate CA into Configuration > On Premise > Trust Store.',
        'Connection to BTP: ask the network team to exclude *.hana.ondemand.com / *.cloud.sap from SSL inspection.',
        'Check the certificate chain from the SCC host: openssl s_client -connect <host>:<port> -showcerts.'
      ]
    },
    {
      id: 'cert-expired', sev: 'critical', cat: 'Certificates / TLS',
      title: 'Certificate expired / not yet valid',
      re: /CertificateExpiredException|CertificateNotYetValidException|certificate (has )?expired|certificate_expired|cert(ificate)? is not yet valid/i,
      why: 'One of the certificates (subaccount certificate, UI certificate, system certificate or the backend certificate) has expired, so the TLS handshake fails.',
      fix: [
        'Check the validity of the Subaccount Certificate on the SCC subaccount page and refresh/renew it if needed.',
        'Check the System Certificate & CA Certificate under Configuration > On Premise, and the UI Certificate under Configuration > User Interface.',
        'Check the backend SSL server certificate (STRUST on ABAP).'
      ]
    },
    {
      id: 'cert-expiring', sev: 'medium', cat: 'Certificates / TLS', minLevel: 'INFO',
      title: 'Certificate expiring soon',
      re: /certificate[^\n]{0,80}(will expire|expires (soon|in)|about to expire|is going to expire)/i,
      why: 'SCC warns that a certificate is approaching its expiry date.',
      fix: ['Schedule the certificate renewal before the expiry date (the subaccount certificate can be refreshed from the subaccount page).']
    },
    {
      id: 'ssl-handshake', sev: 'high', cat: 'Certificates / TLS',
      title: 'TLS handshake failed',
      re: /SSLHandshakeException|handshake_failure|bad_certificate|certificate_unknown|unknown_ca|protocol_version|no cipher suites in common|Received fatal alert|Remote host terminated the handshake|No appropriate protocol/i,
      exclude: /PKIX path|CertificateExpired/i,
      why: 'TLS negotiation failed: TLS version / cipher mismatch, or the client certificate (system certificate / principal propagation) was rejected by the peer.',
      fix: [
        'Compare the TLS versions & ciphers supported by the backend with SCC (Configuration > Advanced).',
        '"bad_certificate"/"unknown_ca" from the backend: make sure the CA of the SCC System Certificate is trusted by the backend (STRUST, SSL Server Standard).',
        'Temporarily enable the TLS trace under "Log and Trace Files" to see handshake details.'
      ]
    },
    {
      // iSaSiLk TLS trace (ssl_debug) of the availability check (thread notification-client, SCCEndpointValidator): the backend sent a
      // certificate request with its CA list, and no certificate of SCC fits it. Request connections themselves only log "HANDSHAKEN".
      id: 'backend-no-client-cert', sev: 'high', cat: 'Certificates / TLS', minLevel: 'DEBUG',
      title: 'Backend asked for a client certificate, the Cloud Connector sent none',
      re: /No client certificate available, sending empty certificate message/i,
      why: 'In the TLS handshake to an HTTPS backend the backend requested a client certificate and named the CAs it accepts ("Accepted certificate authorities" a few lines above = the certificate list of its SSL server PSE). The SCC system certificate is not issued by any of them — for a self-signed system certificate: this exact certificate is not in the list — so SCC sends an empty certificate. With principal propagation this breaks the logon: ICM cannot identify the Cloud Connector as trusted reverse proxy (icm/trusted_reverse_proxy_<n>), ignores the forwarded short-lived user certificate and the request is anonymous → redirect to the SAML IdP ("Location header represents unknown host …accounts.ondemand.com"), 401 or an anonymous session. Without principal propagation (basic authentication) it is harmless. The table "Client certificate requested by HTTPS backends" lists the CA list per backend.',
      fix: [
        'Compare the CA list with the SCC system certificate (Configuration → On Premise → System Certificate): its issuer — for a self-signed certificate its own subject — must be in the list. Automatic check down to the serial number: load scc_core.trc together with sys_cert.der (download of the system certificate) in Certificates.',
        'Self-signed system certificate: import exactly this certificate into the SSL server PSE of the backend HTTPS port (STRUST → SSL server Standard, or the SSL server identity assigned to the port in SMICM → Goto → Services) → Add to Certificate List → Save. CA-signed: import its issuing CA instead. Instances with an instance-specific PSE: repeat on each.',
        'Activate: SMICM → Administration → ICM → Exit Soft → Global (also needed after changing icm/trusted_reverse_proxy_<n> in the profile).',
        'Profile: icm/trusted_reverse_proxy_<n> = SUBJECT="<subject of the system certificate>", ISSUER="<issuer of the system certificate>" — exactly as in the certificate (self-signed: both identical). Check the active value in SMICM → Goto → Parameters → Display on the instance behind the mapping.',
        'Verify: Cloud To On-Premise → Check availability of internal host (TLS trace on) → download scc_core.trc → the CA list now contains the issuer / subject of the system certificate and this message is gone; then repeat the business call: no redirect to the IdP any more.'
      ]
    },

    /* ---------- Network to backend ---------- */
    {
      id: 'unknown-host', sev: 'high', cat: 'Network',
      title: 'Hostname cannot be resolved (DNS)',
      re: /UnknownHostException|Name or service not known|nodename nor servname|No such host is known|Temporary failure in name resolution/i,
      why: 'SCC cannot resolve a hostname (internal host in a mapping, BTP host, or proxy host).',
      fix: [
        'Check the spelling of the Internal Host in Cloud To On-Premise > Access Control.',
        'Test from the SCC host: nslookup <host> / ping <host>.',
        'For BTP hosts: make sure public DNS is reachable or use an HTTPS proxy.'
      ]
    },
    {
      id: 'conn-refused', sev: 'high', cat: 'Network',
      title: 'Connection refused',
      re: /Connection refused|ConnectException|ECONNREFUSED|WSAECONNREFUSED/i,
      why: 'The target host is reachable but the port is not listening, or a firewall rejects the connection.',
      fix: [
        'Verify the internal port in the mapping (HTTP ICM: 80NN/443NN, RFC gateway: 33NN/48NN, message server: 36NN).',
        'Test from the SCC host: Test-NetConnection <host> -Port <port> (Windows) or nc -vz <host> <port> (Linux).',
        'Use "Check availability of internal host" in Access Control.'
      ]
    },
    {
      id: 'timeout', sev: 'medium', cat: 'Network',
      title: 'Connect / read timeout',
      re: /SocketTimeoutException|Read timed out|connect timed out|ConnectTimeoutException|timed? ?out while|Connection timed out|timeout (occurred|expired)/i,
      why: 'The backend or network is slow / not responding within the time limit. Can also be caused by a firewall silently dropping packets.',
      fix: [
        'Correlate the timeouts with backend load/performance (ST03N, SM50/SM66, ICM trace).',
        'Check whether the timeouts only affect specific hosts (see System Info > Endpoints).',
        'Review the timeout settings of the BTP destination / calling application.'
      ]
    },
    {
      id: 'conn-reset', sev: 'medium', cat: 'Network',
      title: 'Connection closed by peer (reset / broken pipe)',
      re: /Connection reset|Broken pipe|EOFException|Connection closed by (peer|remote)|An existing connection was forcibly closed|Software caused connection abort/i,
      why: 'The TCP connection was terminated abruptly by the backend, a firewall, load balancer or proxy (e.g. idle timeout).',
      fix: [
        'Check the idle timeouts of firewalls / load balancers between SCC and the backend and towards the internet.',
        'If it happens on the tunnel to BTP, check the stability of the internet connection & proxy.'
      ]
    },
    {
      id: 'port-in-use', sev: 'high', cat: 'Network',
      title: 'Port already in use by another process',
      re: /Address already in use|BindException|JVM_Bind/i,
      why: 'SCC cannot open a port (default UI 8443) because another process uses it, often when two instances run at the same time.',
      fix: ['Find the process using the port: netstat -ano | findstr 8443 (Windows) or ss -ltnp (Linux).', 'Make sure there is no duplicate SCC instance.']
    },

    /* ---------- Connection to SAP BTP (tunnel) ---------- */
    {
      id: 'proxy', sev: 'high', cat: 'Connection to BTP',
      title: 'HTTPS proxy problem',
      re: /Proxy Authentication Required|HTTP\/1\.\d 407|\b407\b[^\n]{0,40}proxy|Unable to tunnel through proxy|proxy[^\n]{0,60}(refused|failed|error|unreachable|denied)/i,
      why: 'The outbound connection to BTP goes through a proxy that rejects it / requires authentication.',
      fix: [
        'Check host, port, user & password under Configuration > Cloud > HTTPS Proxy.',
        'Make sure the proxy allows CONNECT to the BTP region hosts (connectivitytunnel.*, connectivitynotification.*, connectivitycertsigning.*).'
      ]
    },
    {
      id: 'tunnel-down', sev: 'high', cat: 'Connection to BTP',
      title: 'Tunnel to BTP subaccount disconnected / failed to connect',
      re: /(tunnel|notification)[^\n]{0,80}(closed|disconnect|lost|broken|failed|could not|unable)|(could not|unable to|failed to) (connect|establish|open)[^\n]{0,60}(cloud|tunnel|subaccount|account)|Disconnected from/i,
      why: 'SCC lost the tunnel connection to SAP BTP. While disconnected, cloud applications cannot reach on-premise systems.',
      fix: [
        'Check for preceding proxy / DNS / TLS / certificate errors (Findings tab) as the root cause.',
        'Check the subaccount status in the SCC UI and connectivity to the region host (port 443).',
        'Compare the disconnect time with SAP BTP maintenance windows or network incidents.'
      ]
    },
    {
      id: 'location-id', sev: 'high', cat: 'Connection to BTP',
      title: 'Location ID mismatch / problem',
      re: /location ?id[^\n]{0,100}(not|invalid|already|mismatch|unknown|conflict|duplicate)|(no|not)[^\n]{0,40}location ?id/i,
      why: 'The Location ID in SCC must match the "Location ID" property (CloudConnectorLocationId) of the BTP destination; two SCCs with the same Location ID on one subaccount conflict.',
      fix: [
        'Align the Location ID in the SCC subaccount configuration with the destination in BTP Cockpit.',
        'Make sure no two (non-HA) SCCs use the same Location ID on the same subaccount.'
      ]
    },
    {
      id: 'subaccount-auth', sev: 'high', cat: 'Connection to BTP',
      title: 'Subaccount authentication / onboarding failed',
      re: /(subaccount|account)[^\n]{0,80}(not authorized|unauthorized|forbidden|not allowed|authentication failed|invalid credentials)|not (a member|authorized)[^\n]{0,40}(subaccount|Cloud Connector Administrator)/i,
      why: 'The user used to connect the subaccount lacks the required role, or the credentials are wrong.',
      fix: ['Make sure the user has the "Cloud Connector Administrator" (or Subaccount Administrator) role in the BTP subaccount.', 'Also verify the region host & subaccount ID.']
    },

    /* ---------- Access control ---------- */
    {
      id: 'access-denied', sev: 'high', cat: 'Access Control',
      title: 'Access to resource denied (not defined in Access Control)',
      re: /Access denied|access (is )?not allowed|not (exposed|permitted)|no (matching )?(access control|mapping|resource)|not found in (the )?access control|denied[^\n]{0,40}(resource|path|system)|virtual host[^\n]{0,60}not (found|exposed|mapped)/i,
      why: 'A request from BTP targets a virtual host/port or path/function module that is not defined in Cloud To On-Premise > Access Control. The request is blocked by SCC (not by the backend).',
      fix: [
        'Match the virtual host:port of the BTP destination with the mapping in Access Control (case & port must be identical).',
        'Add the path (HTTP) or function module name/prefix (RFC) in the Resources tab; tick "Path and all sub-paths" if needed.',
        'Make sure the resource is enabled and the protocol (HTTP/HTTPS/RFC/RFC SNC) matches.'
      ]
    },
    {
      id: 'rfc-fm-denied', sev: 'high', cat: 'Access Control',
      title: 'RFC function module not allowed',
      re: /function (module )?[^\n]{0,60}not (allowed|permitted|exposed|accessible)|RFC[^\n]{0,40}resource[^\n]{0,40}not|not authorized[^\n]{0,30}function/i,
      why: 'The called function module is not part of the Resources list of that RFC system.',
      fix: ['Add the function module name (or a prefix, e.g. BAPI_) to the Resources of the RFC mapping.']
    },

    /* ---------- Authentication to backend ---------- */
    {
      id: 'http-401', sev: 'medium', cat: 'Authentication',
      title: 'Backend rejected authentication (HTTP 401)',
      re: /\b401\b[^\n]{0,40}Unauthori[sz]ed|HTTP[^\n]{0,20}\b401\b|status(code)?[ :=]*401\b/i,
      why: 'The backend received the request but the credentials/token are invalid (wrong basic auth, locked user, or principal propagation produced no user).',
      fix: ['Check user/password in the BTP destination.', 'For principal propagation: see the "Principal propagation" finding and SMICM / SM21 / ST01 logs in the backend.']
    },
    {
      id: 'http-403', sev: 'medium', cat: 'Authentication',
      title: 'Access denied by backend (HTTP 403)',
      re: /\b403\b[^\n]{0,40}Forbidden|HTTP[^\n]{0,20}\b403\b|status(code)?[ :=]*403\b/i,
      why: 'The user logged on to the backend but lacks authorization, or the CSRF token was rejected.',
      fix: ['Check the user authorizations in the backend (SU53 / trace ST01).', 'For OData writes: make sure the x-csrf-token flow is correct.']
    },
    {
      // HttpNoAuthenticationHandler: the request carries the cloud user (SSO token), but the system mapping has Principal Type "None"
      // (SSOClientProcessor logs "authentication mode is set to 'NONE_…'") → SCC sends no user certificate ("Injecting empty certificate"),
      // the backend gets an anonymous request → SAML2 redirect to the IdP / 401 / anonymous session (SID:ANON).
      id: 'pp-not-configured', sev: 'high', cat: 'Authentication',
      title: 'SSO token received, but principal propagation is not configured for this system',
      re: /not been configured for principal propagation|discontinue sending the SSO token/i,
      why: 'The BTP application / destination sends the logged-on cloud user (destination Authentication = PrincipalPropagation, SAP Analytics Cloud tunnel connection with SSO, Group Reporting Data Collection, …), but the Cloud Connector does not turn it into a short-lived X.509 certificate: the system mapping has Principal Type "None" and/or no CA certificate / trusted IdP is configured. The backend receives the request without a user: it redirects to the SAML IdP (SCC log: "Location header represents unknown host: <tenant>.accounts.ondemand.com"), answers 401, or opens an anonymous session (sap(…SID:ANON…) in the URL). Search the log for "authentication mode is set to" to see the virtual host / port of the affected mapping.',
      fix: [
        'Decide per virtual host: should the cloud user be propagated? If NOT (technical user is enough): change the BTP destination Authentication from PrincipalPropagation to BasicAuthentication / OAuth2SAMLBearerAssertion etc. (or the SAC connection authentication), then the warning disappears.',
        'If YES: Cloud Connector → Cloud To On-Premise → Access Control → edit the system mapping → Protocol HTTPS (principal propagation needs HTTPS to an ICM HTTPS port, e.g. 443xx) → Principal Type "X.509 Certificate (General Usage)" or "(Strict Usage)" → Save.',
        'Cloud Connector → Configuration → On Premise: (1) System Certificate (client certificate SCC uses towards the backend, signed by a CA the backend trusts), (2) CA Certificate for principal propagation (signs the short-lived certificates; import a PKCS#12 from your CA or generate one), (3) Principal Propagation subject pattern, e.g. CN=${name} or CN=${email}.',
        'Cloud Connector → Cloud To On-Premise → Principal Propagation → Synchronize, and mark the IdP of the subaccount (e.g. the SAP Cloud Identity tenant) as trusted. Repeat for every subaccount / location ID that sends SSO tokens.',
        'ABAP backend (each instance): STRUST → SSL server PSE → import the issuer of the SCC system certificate and the SCC CA certificate → Save. Profile: icm/HTTPS/verify_client = 1, icm/trusted_reverse_proxy_0 = SUBJECT="<subject of SCC system certificate>", ISSUER="<its issuer>" (older kernels: icm/HTTPS/trust_client_with_issuer / _subject), login/certificate_mapping_rulebased = 1 → restart ICM.',
        'ABAP backend: transaction CERTRULE → import a sample short-lived certificate (SCC → On Premise → Principal Propagation → Create Sample Certificate) → rule: CN (or e-mail) → user ID / alias → Save. Check that the cloud user exists in the backend with the same ID / e-mail.',
        'Verify: repeat the call; the SCC log must show the X.509 handler instead of "Injecting empty certificate", no redirect to the IdP, and in the backend SMICM trace (level 2) / ST01 / SM20 the logon of the propagated user. Certificate details: load the SCC system / CA certificate and the SSL server PSE in Certificates → Trust check.'
      ]
    },
    {
      // HttpLocationHeaderHandler: the backend response is a redirect to an IdP host that is not mapped in SCC → the user was not logged on
      id: 'pp-idp-redirect', sev: 'high', cat: 'Authentication', minLevel: 'DEBUG',
      title: 'Backend redirected the request to the SAML / OAuth IdP (user not logged on)',
      re: /Location header represents unknown host: \S*(?:accounts\.ondemand\.com|accounts\.cloud\.sap|accounts400\.ondemand\.com|\.authentication\.)|Location header represents unknown host:.*\/saml2\/idp\//i,
      why: 'The backend answered with a redirect to the identity provider (SAML2 / SAP Cloud Identity). For calls from BTP this means the backend did not log on the user. With principal propagation ("Will use X.509 certificate for authentication to backend" for the same connection ID) the short-lived certificate was not accepted: the backend does not trust the Cloud Connector as reverse proxy (see "Backend asked for a client certificate, the Cloud Connector sent none"), or CERTRULE maps the certificate to no user. Without principal propagation ("injecting empty certificate") no credentials reached the backend. OData clients such as Group Reporting Data Collection, SAP Analytics Cloud or Integration Suite cannot follow the login and show 302 / 405 / "The remote OData service responded with status code …". The table "Principal propagation requests (per system mapping)" shows the affected mappings and users.',
      fix: [
        'Check the authentication of the connection ID in this log: "Will use X.509 certificate for authentication to backend" (principal propagation active, certificate subject in "Generated X.509 certificate with subject …") or "injecting empty certificate" (no user).',
        'X.509 active → first the reverse proxy trust: SCC system certificate in the SSL server PSE of the backend port + icm/trusted_reverse_proxy_<n> (finding "Backend asked for a client certificate …", or load scc_core.trc + sys_cert.der in Certificates).',
        'Then the user mapping: CERTRULE with a sample certificate (SCC → Configuration → On Premise → Principal Propagation → Create Sample Certificate, same subject pattern as in "Generated X.509 certificate with subject …") → rule maps CN / e-mail to the ABAP user (login/certificate_mapping_rulebased = 1).',
        'Backend SMICM trace level 2 on the instance that received the request (SM51 → that instance → SMICM): "intermediary is NOT trusted" → reverse proxy trust; trusted, but still redirected / 401 → CERTRULE / user (SEC_TRACE_ANALYZER, ST01 logon trace, SM20).',
        'If the SICF service has its own logon procedure: allow logon with SSL client certificate (before SAML).'
      ]
    },
    {
      id: 'principal-propagation', sev: 'high', cat: 'Authentication',
      title: 'Principal propagation / short-lived certificate problem',
      re: /principal propagation|short[- ]lived (x\.?509 )?certificate|no user (found|mapped)[^\n]{0,40}certificate|certificate[^\n]{0,40}(mapping|user) (failed|not found)|(SAML|JWT)[^\n]{0,60}(invalid|expired|failed|not valid|signature)/i,
      exclude: /not been configured for principal propagation|discontinue sending the SSO token/i,
      why: 'SCC failed to create/forward the short-lived X.509 certificate for the cloud user, or the backend cannot map the certificate to a user.',
      fix: [
        'Check the CA Certificate & Principal Propagation subject pattern under Configuration > On Premise.',
        'Make sure the Trust Configuration (IdP) is synced in Cloud To On-Premise > Principal Propagation.',
        'ABAP backend: CERTRULE (rule-based mapping), login/certificate_mapping_rulebased=1, icm/HTTPS/verify_client, and trust of the SCC system certificate (icm/trusted_reverse_proxy_<x> or icm/HTTPS/trust_client_with_issuer/subject).'
      ]
    },
    {
      id: 'admin-login', sev: 'low', cat: 'Security', minLevel: 'INFO',
      title: 'Failed logon to the SCC administration UI',
      re: /(login|logon|authentication) (failed|unsuccessful|denied)|invalid (user(name)?|credentials|password)|LoginException/i,
      exclude: /RFC_|subaccount/i,
      why: 'Logon attempt to the SCC UI (port 8443) failed. A high number in a short time may indicate brute force.',
      fix: ['Check source IP & user in the SCC Audit Log.', 'If LDAP is used, check the LDAP configuration (Configuration > User Interface > Authentication).']
    },
    {
      id: 'ldap', sev: 'medium', cat: 'Security',
      title: 'LDAP error',
      re: /javax\.naming\.|LDAP[^\n]{0,60}(error|failed|exception|refused|invalid)/i,
      why: 'Connection or bind to the LDAP server (used for SCC UI logon) failed.',
      fix: ['Check LDAP host/port, bind user and LDAPS certificate in the SCC UI authentication configuration.']
    },

    /* ---------- RFC ---------- */
    {
      id: 'rfc-comm', sev: 'high', cat: 'RFC',
      title: 'RFC: partner not reached / communication failure',
      re: /partner[^\n]{0,60}not reached|RFC_COMMUNICATION_FAILURE|RFC_ERROR_COMMUNICATION|CPIC-CALL|NiIConnect|NIECONN_REFUSED|NiPConnect|connection to partner[^\n]{0,40}(broken|failed)/i,
      why: 'SCC cannot connect to the gateway / message server of the ABAP system.',
      fix: [
        'Check host & instance number / gateway port (sapgwNN = 33NN, SNC 48NN) or message server (sapmsSID / 36NN) in the RFC mapping.',
        'For load balancing: make sure the logon group exists (SMLG) and the message server port is open.',
        'Check the gateway trace (SMGW) and dev_rd in the backend.'
      ]
    },
    {
      id: 'rfc-logon', sev: 'high', cat: 'RFC',
      title: 'RFC: logon failed',
      re: /RFC_LOGON_FAILURE|RFC_ERROR_LOGON_FAILURE|Name or password is incorrect|User is locked|password logon no longer possible|user[^\n]{0,20}locked/i,
      why: 'The RFC user in the BTP destination has a wrong password, is locked, or has an unsuitable user type.',
      fix: ['Check the user in the backend (SU01: lock status, type System/Communication).', 'Check SM21 / security audit log (SM20/RSAU_READ_LOG) in the backend.']
    },
    {
      id: 'rfc-abap', sev: 'medium', cat: 'RFC',
      title: 'RFC: error on the ABAP side',
      re: /RFC_ABAP_(EXCEPTION|RUNTIME_FAILURE|MESSAGE)|RFC_ERROR_SYSTEM_FAILURE|SYSTEM_FAILURE|ABAP runtime error|short dump/i,
      why: 'The function module ran but raised an exception / dump in the backend.',
      fix: ['Check ST22 (short dumps) and SM21 in the backend at the same time.']
    },
    {
      id: 'snc', sev: 'high', cat: 'RFC',
      title: 'SNC problem',
      re: /\bSNC\b[^\n]{0,80}(error|fail|not|invalid)|GSS-API|SncPEstablish|sapcrypto[^\n]{0,40}(error|not|fail)|SNC_ERROR/i,
      why: 'Secure Network Communication configuration (library, own name, PSE, or partner trust) is incorrect.',
      fix: ['Check SNC library path, My Name and Quality of Protection under Configuration > On Premise > SNC.', 'Make sure the SCC SNC name is known in the backend (SNC0 / ACL) and the PSEs trust each other.']
    },

    /* ---------- HTTP backend ---------- */
    {
      id: 'backend-5xx', sev: 'medium', cat: 'Backend',
      title: 'Backend returned HTTP 5xx',
      re: /HTTP\/1\.\d (500|502|503|504)\b|status(code)?[ :=]*(500|502|503|504)\b|\b(500|502|503|504) (Internal Server Error|Bad Gateway|Service Unavailable|Gateway Time-?out)/i,
      why: 'The request was forwarded to the backend but the backend/ICM/Web Dispatcher returned a server error.',
      fix: ['Check SMICM (ICM trace), ST22, SM21, and /IWFND/ERROR_LOG or /IWBEP/ERROR_LOG for OData.']
    },

    /* ---------- JVM / OS resources ---------- */
    {
      id: 'oom', sev: 'critical', cat: 'JVM / OS',
      title: 'Java out of memory (OutOfMemoryError)',
      re: /OutOfMemoryError|Java heap space|GC overhead limit exceeded|Metaspace|unable to create (new )?native thread/i,
      why: 'The SCC JVM heap is too small for the current load; SCC may hang or restart.',
      fix: ['Increase the heap under Configuration > Advanced > JVM (initial/maximum heap) and restart SCC.', 'Check whether payload/traffic trace is permanently enabled or connections spiked.']
    },
    {
      id: 'resources', sev: 'high', cat: 'JVM / OS',
      title: 'OS resource limit reached',
      re: /Too many open files|No space left on device|disk (is )?full|RejectedExecutionException|pool exhausted|maximum number of (connections|threads)|too many connections/i,
      why: 'File descriptors, disk, thread pool or the SCC connection limit are exhausted.',
      fix: ['Linux: raise ulimit -n for the SCC user.', 'Free up disk space (the log/trace folder can grow large with high trace levels).', 'Review the number of concurrent connections to the backend.']
    },
    {
      id: 'java-version', sev: 'high', cat: 'JVM / OS',
      title: 'Unsupported Java version',
      re: /UnsupportedClassVersionError|unsupported (Java|JVM|JDK)|requires (a )?Java (version )?\d+/i,
      why: 'SCC runs on a JVM that does not match the SCC version.',
      fix: ['Check the SCC prerequisites / Product Availability Matrix and use a supported SAP JVM / SapMachine.']
    },

    /* ---------- Lifecycle & High Availability (informational) ---------- */
    {
      id: 'lifecycle', sev: 'info', cat: 'Lifecycle', minLevel: 'INFO',
      title: 'Cloud Connector start / stop',
      re: /(Cloud Connector|SCC|server)[^\n]{0,40}(start(ed|ing)|stop(ped|ping)|shut(ting)? ?down)|Server startup in|JVM (is )?shutting down/i,
      why: 'Marks restart times. Useful to correlate errors with restarts or configuration changes.',
      fix: ['Compare with maintenance / patch / server reboot schedules.']
    },
    {
      id: 'tunnel-up', sev: 'info', cat: 'Lifecycle', minLevel: 'INFO',
      title: 'Tunnel to BTP connected',
      re: /(tunnel|connection)[^\n]{0,60}(established|opened|connected|reconnected)|connected to (the )?(cloud|subaccount|account)/i,
      exclude: /not connected|disconnected|could not|unable|failed/i,
      why: 'Marks when the tunnel to the BTP subaccount became active (again). Compare with "Tunnel disconnected" to see the outage duration.',
      fix: []
    },
    {
      id: 'ha', sev: 'info', cat: 'High Availability', minLevel: 'INFO',
      title: 'High Availability event (master / shadow)',
      re: /\b(shadow|master) (instance|node)|high availability|switch ?over|fail ?over|takeover/i,
      why: 'Master/shadow role change or HA synchronization. Frequent switchovers may indicate an unstable connection between the instances.',
      fix: ['Check master <-> shadow connectivity and the High Availability settings.']
    },
    {
      id: 'config-change', sev: 'info', cat: 'Audit', minLevel: 'INFO',
      title: 'Configuration change',
      re: /(configuration|access control|mapping|resource|subaccount|certificate|trust store)[^\n]{0,60}(changed|created|deleted|removed|added|modified|updated|imported)/i,
      why: 'A configuration change was logged. Useful to answer "what changed before the problem started".',
      fix: ['Match with the SCC Audit Log to see which user made the change.']
    }
  ];

  /* ---------- Insights ---------- */
  const RE_VERSION = /(?:Cloud Connector|SCC)\b[^\n]{0,60}?\bversion\b\s*[:=]?\s*(\d+\.\d+\.\d+(?:\.\d+)?)/i;
  const RE_JAVA = /\b(?:Java|JVM|JDK)\b[^\n]{0,30}?\bversion\b\s*[:=]?\s*["']?(\d[\w.\-+_]*)/i;
  const RE_OS = /\b(?:os\.name|operating system)\b\s*[:=]?\s*([^\n,;#]{2,60})/i;
  const RE_REGION = /\b(?:connectivitytunnel|connectivitynotification|connectivitycertsigning)\.((?:[a-z0-9-]+\.)*(?:hana\.ondemand\.com|cloud\.sap|hanacloudservices\.cloud\.sap))/gi;
  const RE_SUBACC = /sub-?account[^\n]{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi;
  const RE_ENDPOINT = /\b((?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z][a-z0-9-]{1,62}|\d{1,3}(?:\.\d{1,3}){3}|[a-z][a-z0-9-]{2,62}):(\d{2,5})\b/gi;

  function bump(map, k) { map.set(k, (map.get(k) || 0) + 1); }

  /* Requests that carried an SSO token without principal propagation, correlated per connection ID
   * ("0x…#" prefix of the message): mapping (virtual host, authentication mode), subaccount / location, IdP redirect */
  const RE_CONN = /^(0x[0-9a-f]+)#/i;
  /* One record per tunnel connection ID (DEBUG level needed for most fields):
   * {id, t0, t1, sub, mode, vhost, scheme, path, target (internal host:port), backendIp, sccIp, pp, redirect,
   *  principal, x509 (SHA-256 of the short-lived certificate), certSubject, emptyCert} */
  function connFacts(entries) {
    const conn = new Map(), certByThread = new Map();
    let m;
    for (const e of entries) {
      // "Generated / Using cached X.509 certificate with subject …" is logged without connection ID, just before "Will use X.509 …" on the same thread
      if ((m = /(?:Generated|Using cached) X\.509 certificate with subject (.+)$/.exec(e.message || ''))) { certByThread.set(e.thread, m[1].trim()); continue; }
      const c = RE_CONN.exec(e.message || '');
      if (!c) continue;
      const msg = e.message;
      let r = conn.get(c[1]);
      if (!r) { r = { id: c[1], t0: e.t, t1: e.t }; conn.set(c[1], r); }
      if (e.t != null) { if (r.t0 == null || e.t < r.t0) r.t0 = e.t; if (r.t1 == null || e.t > r.t1) r.t1 = e.t; }
      if ((m = /authentication mode is set to '(\w+)' for: protocol (\w+), virtualHost ([^,]+), virtualPort (\d+)/.exec(msg))) Object.assign(r, { mode: m[1], vhost: `${m[3]}:${m[4]}` });
      else if ((m = /tunnelId account:\/\/\/([^/\s]+)\/(\S+)/.exec(msg))) r.sub = `${m[1]} / ${m[2]}`;
      else if (/not been configured for principal propagation/i.test(msg)) r.pp = true;
      else if ((m = /Location header represents unknown host: (\S+?)\.?\s+The value/.exec(msg))) r.redirect = m[1];
      else if ((m = /Start sending (https?):\/\/([^/\s]+)(\/\S*?)(?:\?\S*)? to backend/.exec(msg))) Object.assign(r, { scheme: m[1], vhost: r.vhost || m[2], path: m[3].replace(/^\/sap\([^)]*\)/, '/sap(…)') });
      else if ((m = /Host header changed\. Source: \S+; Target \(internal\): (\S+)/.exec(msg))) r.target = m[1];
      else if ((m = /opened backend connection \[id: \w+, L:\/([\d.]+):\d+ - R:([^/\s]*)\/([\d.]+):(\d+)\]/.exec(msg))) Object.assign(r, { sccIp: m[1], backendIp: m[3], target: r.target || `${m[2]}:${m[4]}` });
      else if ((m = /Will use X\.509 certificate for authentication to backend: (\w+)/.exec(msg))) Object.assign(r, { x509: m[1], certSubject: certByThread.get(e.thread) || r.certSubject });
      else if (/no principal available, injecting empty certificate/.test(msg)) r.emptyCert = true;
      else if ((m = /Assigned principal: '([^']*)'/.exec(msg))) r.principal = m[1];
      else if ((m = /Opening connection to backend system (\S+)/.exec(msg))) r.vhost = r.vhost || m[1];
    }
    return [...conn.values()];
  }

  /* Requests with principal propagation (short-lived X.509 certificate) per mapping and certificate subject, and how the backend answered */
  function ppX509Insight(entries) {
    const rows = new Map();
    for (const c of connFacts(entries)) {
      if (!c.x509) continue;
      const k = [c.vhost || '?', c.target || '?', c.certSubject || c.principal || '?'].join('|');
      const r = rows.get(k) || { n: 0, redir: new Map(), paths: new Map(), t0: null, t1: null, r1: null };
      r.n++; if (c.redirect) { bump(r.redir, c.redirect); if (c.t1 != null && (r.r1 == null || c.t1 > r.r1)) r.r1 = c.t1; }
      if (c.path) bump(r.paths, c.path.split('/').slice(0, 6).join('/'));
      if (c.t0 != null && (r.t0 == null || c.t0 < r.t0)) r.t0 = c.t0;
      if (c.t1 != null && (r.t1 == null || c.t1 > r.t1)) r.t1 = c.t1;
      rows.set(k, r);
    }
    if (!rows.size) return null;
    const ft = t => (t == null ? '-' : TS.fmtTime(t, 0) + ' UTC');
    return {
      title: 'Principal propagation requests (short-lived X.509 certificate, per system mapping)',
      cols: ['Virtual host', 'Internal host', 'Certificate subject / user', 'Requests', 'Redirected to IdP (not logged on)', 'First / last request', 'Last redirect', 'Paths'],
      rows: [...rows].sort((a, b) => b[1].n - a[1].n).map(([k, r]) => {
        const [vh, tg, subj] = k.split('|');
        return [vh, tg, subj, r.n,
          r.redir.size ? [...r.redir].map(([h, n]) => `${h} (${n}×)`).join(', ') : '-',
          `${ft(r.t0)} / ${ft(r.t1)}`, ft(r.r1),
          TS.topN(r.paths, 3).map(([p, n]) => `${p} (${n}×)`).join(', ')];
      }),
      filterCol: 0
    };
  }

  /* Client certificate requests of HTTPS backends (TLS trace / availability check), see x509.parseHandshakes */
  function handshakeInsight(entries) {
    if (!TS.x509 || !TS.x509.parseHandshakes) return null;
    const recs = [];
    for (const e of entries) {
      if (!/ssl_debug|issuer certificates trusted|Opening connection \{s\}/.test(e.message || '')) continue;
      recs.push({ ts: e.tsText, thread: e.thread, msg: e.message, line: e.line });
      (e.detail ? e.detail.split('\n') : []).forEach((d, i) => recs.push({ ts: e.tsText, thread: e.thread, msg: d, line: e.line + i + 1 }));
    }
    const groups = new Map();
    for (const h of TS.x509.parseHandshakes(recs, '')) {
      const k = h.peer + '|' + h.cas.join(' ; ');
      const g = groups.get(k) || { n: 0, none: 0, sent: 0, first: h.ts, last: h.ts };
      g.n++; g.last = h.ts; if (h.client === 'none') g.none++; else if (h.client === 'sent') g.sent++;
      groups.set(k, g);
    }
    if (!groups.size) return null;
    return {
      title: 'Client certificate requested by HTTPS backends (TLS handshake)',
      cols: ['Backend', 'Accepted issuers (CA list of the backend PSE)', 'Handshakes', 'Client certificate sent', 'First / last'],
      rows: [...groups].map(([k, g]) => {
        const [peer, cas] = k.split('|');
        return [peer || '?', cas || '(empty list)', g.n, g.none ? `NO (${g.none}× "No client certificate available")` : g.sent ? `yes (${g.sent}×)` : '?', `${g.first} / ${g.last}`];
      }),
      filterCol: 0
    };
  }
  function ppInsight(entries) {
    const rows = new Map();
    for (const c of connFacts(entries)) {
      if (!c.pp) continue;
      const k = [c.vhost || '?', c.scheme || '?', c.mode || '?', c.sub || '?'].join('|');
      const r = rows.get(k) || { n: 0, redir: new Map(), paths: new Map() };
      r.n++; if (c.redirect) bump(r.redir, c.redirect); if (c.path) bump(r.paths, c.path.split('/').slice(0, 6).join('/'));
      rows.set(k, r);
    }
    if (!rows.size) return null;
    return {
      title: 'Requests with SSO token but no principal propagation (per system mapping)',
      cols: ['Virtual host', 'Protocol', 'Authentication mode', 'Subaccount / location ID', 'Requests', 'Redirected to IdP', 'Paths'],
      rows: [...rows].sort((a, b) => b[1].n - a[1].n).map(([k, r]) => {
        const [vh, sch, mode, sub] = k.split('|');
        return [vh, sch.toUpperCase(), mode, sub, r.n,
          r.redir.size ? [...r.redir].map(([h, n]) => `${h} (${n}×)`).join(', ') : '-',
          TS.topN(r.paths, 3).map(([p, n]) => `${p} (${n}×)`).join(', ')];
      }),
      filterCol: 0
    };
  }

  function insights(entries) {
    const ver = new Map(), java = new Map(), os = new Map(), regions = new Map(), subs = new Map(), ep = new Map();
    for (const e of entries) {
      const msg = e.message;
      let m;
      if ((m = RE_VERSION.exec(msg))) bump(ver, m[1]);
      if ((m = RE_JAVA.exec(msg))) bump(java, m[1]);
      if ((m = RE_OS.exec(msg))) bump(os, m[1].trim());
      const text = e.level === 'INFO' || e.level === 'OTHER' || TS.LEVEL_RANK[e.level] <= 2 ? msg : null;
      if (text) {
        RE_REGION.lastIndex = 0; while ((m = RE_REGION.exec(text))) bump(regions, m[1].toLowerCase());
        RE_SUBACC.lastIndex = 0; while ((m = RE_SUBACC.exec(text))) bump(subs, m[1].toLowerCase());
      }
      if (TS.LEVEL_RANK[e.level] <= 2) {
        const t = TS.entryText(e).slice(0, 2000);
        RE_ENDPOINT.lastIndex = 0;
        const seen = new Set();
        while ((m = RE_ENDPOINT.exec(t))) {
          const host = m[1].toLowerCase();
          // skip Java source refs like "Foo.java:123" and words like "port:443"
          if (/\.(java|kt|scala|groovy|class)$/.test(host) || /^(http|https|ldap|ldaps|file|port|line|column|col|size|length|code|status|id|timeout|version)$/.test(host)) continue;
          const k = host + ':' + m[2];
          if (!seen.has(k)) { seen.add(k); bump(ep, k); }
        }
      }
    }
    const list = map => TS.topN(map, 5).map(([k, n]) => `${k} (${n}×)`).join(', ') || '-';
    return {
      kv: [
        ['Cloud Connector version', list(ver)],
        ['Java version', list(java)],
        ['Operating system', list(os)],
        ['BTP region', list(regions)],
        ['Subaccount ID', list(subs)]
      ],
      tables: [
        {
          title: 'Endpoints (host:port) appearing in WARN/ERROR entries',
          cols: ['Endpoint', 'Entries'],
          rows: TS.topN(ep, 25).map(([k, n]) => [k, n]),
          filterCol: 0
        }
      ].concat(ppInsight(entries) || [], ppX509Insight(entries) || [], handshakeInsight(entries) || [])
    };
  }

  // an SSO token on a mapping without principal propagation is only a failure when the backend then sent the user to the IdP
  function review(hits, entries) {
    const h = hits.find(x => x.rule.id === 'pp-not-configured');
    if (!h) return;
    const pp = connFacts(entries).filter(c => c.pp);
    if (pp.length && !pp.some(c => c.redirect)) {
      h.sev = 'medium';
      h.note = `None of these ${pp.length} request(s) was redirected to the IdP: the backend logged on in another way (technical user, basic / OAuth) — harmless when that is intended; configure principal propagation only when the backend must see the cloud user.`;
    }
  }

  TS.registerModule({
    connFacts,
    review,
    id: 'scc',
    name: 'SAP Cloud Connector',
    short: 'SCC',
    description: 'Analyze ljs_trace.log, scc_core.trc, tunnel traffic trace, audit log and HTTP access log of SAP Cloud Connector.',
    fileTypes: [
      { match: /^ljs_trace.*\.log/i, label: 'SCC main trace (ljs_trace)', parser: 'scc-hash' },
      { match: /^scc_core.*\.trc/i, label: 'SCC core / native trace' },
      { match: /tunnel_traffic.*\.trc/i, label: 'Tunnel traffic trace (payload)' },
      { match: /^(scc_)?audit/i, label: 'Audit log' },
      { match: /http_access|access_log|localhost_access/i, label: 'HTTP access log', parser: 'access' },
      { match: /^gc.*\.log|jvm.*\.log/i, label: 'JVM log' },
      { match: /scc_daemon|scc_service|daemon/i, label: 'Service / daemon log' }
    ],
    parsers: [sccHash],
    rules: R,
    insights,
    guide: [
      ['File location', 'The <code>log/</code> folder of the SCC installation — Windows default <code>C:\\SAP\\scc20\\log</code>, Linux <code>/opt/sap/scc/log</code>. Audit logs are in <code>log/audit/</code>.'],
      ['Quick way', 'In the SCC UI open <b>Log and Trace Files</b> and click <b>Download All</b> → drop the .zip here (ZIP files are read directly).'],
      ['Raise the trace level', 'While reproducing the problem, set <b>Cloud Connector Loggers</b> to <code>ALL</code> and enable <b>TLS Trace</b> for certificate/handshake issues. Reset to the normal level afterwards.'],
      ['Payload trace', 'Tunnel traffic / payload trace (<code>tunnel_traffic_*.trc</code>) contains business data; enabling it may require the four-eyes principle. Analyze its HTTP requests/responses in <a href="scc-traffic.html">Traffic Trace (SCC)</a>.'],
      ['Correlation', 'Note the time of the incident on the BTP application side, then use the time filter in the Log Viewer. For ABAP backends, correlate with SMICM, SM21, ST22 and SMGW.']
    ]
  });
})(window.TS);
