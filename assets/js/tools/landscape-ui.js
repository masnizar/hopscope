/* Landscape map UI: the SAP S/4HANA on-premise reference landscape (with SAP BTP) as an animated SVG.
 * The Cloud Connector requests of the logs are replayed along the selected path, each packet ending at the hop where that request
 * stopped: a red burst at a failing hop (nothing flows past it), a "302" bounce to IAS when the logon redirected it, green at the
 * application when it got through. Every hop shows the verdict of the loaded logs.
 * Click a hop, a component or a step for cause, evidence and fix. Geometry: viewBox 1200 × 800, laid out like SAP's reference network diagram. */
(function (TS) {
  'use strict';
  const C = TS.corr, L = TS.landscape, esc = TS.esc, $ = id => document.getElementById(id);
  const base = p => String(p).split(/[\\/]|!\//).pop();
  const NS = 'http://www.w3.org/2000/svg';
  const REDUCED = !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  const range = (a, b) => {
    if (a == null) return '';
    const x = TS.fmtTime(a), y = b != null && b !== a ? TS.fmtTime(b) : '';
    return y ? `${x} – ${y.slice(x.slice(0, 10) === y.slice(0, 10) ? 11 : 0)}` : x;
  };

  const S = { files: [], skipped: [], data: null, diag: null, path: 'pp', step: null, node: null, tier: 'auto', from: null, to: null, paused: REDUCED, flow: '', allTime: false };
  let slider = null;

  /* ================= Geometry ================= */
  const TX = { dev: 290, qas: 510, prd: 730 };   // S/4 boxes
  const WX = { dev: 510, qas: 510, prd: 730 };   // Web Dispatcher (Non-PRD / PRD) in front of them
  const S4Y = 570, CHIP = { icm: 624, logon: 652, abap: 680 }, COR = 540, TOP = 270, ELBY = 314;
  const TIER = { dev: 'DEV', qas: 'QAS', prd: 'PRD' };
  const ICON = {
    user: '<circle cx="12" cy="8" r="3.6"/><path d="M5 20c.8-3.8 3.6-5.6 7-5.6s6.2 1.8 7 5.6"/>',
    app: '<rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><path d="M3.5 9h17M8 13h8M8 16h5"/>',
    id: '<path d="M12 3 5 6v5c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V6z"/><circle cx="12" cy="10.5" r="2.2"/><path d="M8.6 16c.7-1.6 1.9-2.4 3.4-2.4s2.7.8 3.4 2.4"/>',
    link: '<path d="M9.5 14.5 14.5 9.5"/><path d="M8 11.5 6 13.5a3.5 3.5 0 0 0 5 5l2-2"/><path d="M16 12.5l2-2a3.5 3.5 0 0 0-5-5l-2 2"/>',
    lb: '<rect x="9.5" y="3" width="5" height="4" rx="1"/><rect x="3" y="16" width="5" height="4" rx="1"/><rect x="9.5" y="16" width="5" height="4" rx="1"/><rect x="16" y="16" width="5" height="4" rx="1"/><path d="M12 7v5M5.5 16v-4h13v4M12 12v4"/>',
    server: '<rect x="4" y="3.5" width="16" height="5" rx="1.2"/><rect x="4" y="9.5" width="16" height="5" rx="1.2"/><rect x="4" y="15.5" width="16" height="5" rx="1.2"/><path d="M7 6h.01M7 12h.01M7 18h.01M14 6h3M14 12h3M14 18h3"/>',
    shield: '<path d="M12 3 5 6v5c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V6z"/><rect x="9" y="11" width="6" height="5" rx="1"/><path d="M10.2 11V9.6a1.8 1.8 0 0 1 3.6 0V11"/>',
    globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.6 2.6 2.6 14.4 0 17M12 3.5c-2.6 2.6-2.6 14.4 0 17"/>'
  };
  const icon = (k, x, y, s) => `<g class="ls-ico" transform="translate(${x},${y}) scale(${(s || 24) / 24})"><g fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICON[k]}</g></g>`;
  const NODES = {
    user: { x: 110, y: 95, w: 124, h: 50, ic: 'user', t: 'Users', s: 'browser' },
    app: { x: 560, y: 95, w: 180, h: 54, ic: 'app', t: 'BTP application', s: 'destination' },
    ias: { x: 800, y: 95, w: 180, h: 54, ic: 'id', t: 'Cloud Identity', s: 'IAS · SAML / OIDC IdP' },
    remote: { x: 905, y: 180, w: 150, h: 46, ic: 'globe', t: 'Remote service', s: 'API / BTP service' },
    scc: { x: 290, y: 455, w: 160, h: 64, ic: 'link', t: 'Cloud Connectors', s: 'master / shadow' },
    'wd-np': { x: 510, y: 455, w: 160, h: 64, ic: 'lb', t: 'Web Dispatcher', s: 'Non-PRD' },
    'wd-p': { x: 730, y: 455, w: 160, h: 64, ic: 'lb', t: 'Web Dispatcher', s: 'PRD' },
    'dr-wd': { x: 940, y: 455, w: 104, h: 54, ic: 'lb', t: 'Web Disp.', s: 'standby', dr: true },
    'dr-scc': { x: 940, y: 600, w: 104, h: 50, ic: 'link', t: 'Cloud Conn.', s: 'standby', dr: true },
    'dr-s4': { x: 940, y: 680, w: 104, h: 54, ic: 'server', t: 'S/4', s: 'standby', dr: true }
  };
  // components that are not a hop of the selected path
  const INFO = {
    user: ['Users', 'People working in the BTP application or the Fiori launchpad. Their browser is not covered by SAP logs — the hops behind it show whether their requests arrived.'],
    ias: ['SAP Cloud Identity Services', 'Identity provider of the BTP application and, via SAML, of S/4. When the S/4 ICF service cannot log on the forwarded user it redirects to this IdP (HTTP 302, sap-authenticated: pending); a BTP app calling OData then receives the IdP login page instead of data (405 / "remote OData service responded with status code …").'],
    ilb: ['Internal load balancing', '*.sap.<customerdomain> inside the customer network: internal names of Web Dispatchers and application servers, used by Cloud Connector mappings and on-premise clients. Operated by the network team.'],
    'dr-wd': ['Web Dispatcher (DR)', 'Standby Web Dispatcher in the DR site — only active after a DR failover.'],
    'dr-scc': ['Cloud Connector (DR)', 'Standby Cloud Connector in the DR site — only connected to the subaccount after a DR failover.'],
    'dr-s4': ['S/4 (DR)', 'Replicated standby system in the DR site (replication from the primary PRD database).'],
    remote: ['Remote service', 'Target of outbound calls from S/4 (SM59 destinations, ICM as HTTP client) — select the path "S/4 → outbound".'],
    app: ['BTP application', 'Application in the SAP BTP subaccount; reaches S/4 through a destination of proxy type OnPremise.'],
    conn: ['Connectivity service', 'Cloud side of the tunnel; select the path "Cloud → on-premise".'],
    tunnel: ['Secure tunnel', 'TLS tunnel opened by the Cloud Connector to the subaccount; select the path "Cloud → on-premise".'],
    scc: ['Cloud Connectors', 'Master / shadow pair in the customer network; select the path "Cloud → on-premise".'],
    elb: ['External load balancing / WAF / Proxy', '*.sap.<customerdomain>: internet entry to the Web Dispatchers and outbound proxy — operated by the network team.']
  };

  /* ================= Static SVG ================= */
  const badge = w => `<g class="ls-badge" transform="translate(${w - 2},2)"><circle r="9"/><text y="3.6" text-anchor="middle"></text></g>`;
  function card(id, n) {
    const sm = n.w < 120, is = sm ? 18 : 24, ix = sm ? 8 : 11, tx = sm ? 32 : 44;
    return `<g class="ls-node${n.dr ? ' dr' : ''}" data-node="${id}" transform="translate(${n.x - n.w / 2},${n.y - n.h / 2})" tabindex="0" role="button" aria-label="${esc(n.t)}">
      <rect class="ls-halo" x="-6" y="-6" width="${n.w + 12}" height="${n.h + 12}" rx="15"/>
      <rect class="ls-card" width="${n.w}" height="${n.h}" rx="11"/>
      ${icon(n.ic, ix, (n.h - is) / 2, is)}
      <text class="ls-t1" x="${tx}" y="${n.h / 2 - 2}">${esc(n.t)}</text>
      <text class="ls-t2" x="${tx}" y="${n.h / 2 + 13}" data-sub data-max="${Math.floor((n.w - tx - 8) / 5.6)}">${esc(n.s)}</text>
      ${n.dr ? '' : badge(n.w)}
    </g>`;
  }
  function s4box(tier) {
    const chip = (k, y, t) => `<g class="ls-layer" data-layer="${k}" transform="translate(8,${y})"><rect width="144" height="24" rx="7"/><text x="30" y="16">${t}</text></g>`;
    return `<g class="ls-node ls-s4" data-node="s4-${tier}" transform="translate(${TX[tier] - 80},${S4Y})" tabindex="0" role="button" aria-label="S/4 ${TIER[tier]}">
      <rect class="ls-halo" x="-6" y="-6" width="172" height="152" rx="16"/>
      <rect class="ls-card" width="160" height="140" rx="12"/>
      ${icon('server', 130, 9, 20)}
      <text class="ls-t1" x="12" y="22" data-title>S/4 ${TIER[tier]}</text>
      <text class="ls-t2" x="12" y="36" data-sub data-max="26"></text>
      ${chip('icm', 42, 'ICM · TLS / proxy')}${chip('logon', 70, 'Logon · CERTRULE')}${chip('abap', 98, 'ABAP · app / dumps')}
      ${badge(160)}
    </g>`;
  }
  function buildMap() {
    const cloud = 'M 285 250 C 215 250 205 160 270 150 C 250 85 330 45 410 70 C 450 10 620 -5 690 55 C 750 20 870 30 895 95 C 985 85 1060 160 1015 220 C 1000 245 985 250 960 250 Z';
    $('map').innerHTML = `<svg class="ls-svg" viewBox="0 0 1200 800" role="group" aria-labelledby="lsSvgTitle">
      <title id="lsSvgTitle">SAP S/4HANA on-premise reference landscape with the request path</title>
      <g class="ls-static" aria-hidden="true">
        <path class="ls-cloud" d="${cloud}"/>
        <text class="ls-cloud-t" x="640" y="205" text-anchor="middle">SAP Business Technology Platform</text>
        <g transform="translate(560,236)"><rect class="ls-pill" width="160" height="28" rx="14"/><text class="ls-pill-t" x="80" y="19" text-anchor="middle">Public Cloud</text></g>
        <rect class="ls-band" x="40" y="300" width="50" height="490" rx="25"/>
        <text class="ls-band-t" transform="translate(71,545) rotate(-90)" text-anchor="middle">SAP S/4HANA on-premise</text>
        <rect class="ls-vnet" x="110" y="300" width="1000" height="490" rx="22"/>
        <text class="ls-vnet-t" x="150" y="773">Customer dedicated virtual network</text>
        <rect class="ls-zone" x="150" y="378" width="710" height="364" rx="16"/>
        <text class="ls-zone-t" x="168" y="401">Primary</text>
        <rect class="ls-zone" x="880" y="378" width="120" height="364" rx="16"/>
        <text class="ls-zone-t" x="896" y="401">DR</text>
      </g>
      <g id="lsRoutes"></g>
      <g id="lsPk" aria-hidden="true"></g>
      <g id="lsNodes">
        <g class="ls-node ls-ilb" data-node="ilb" tabindex="0" role="button" aria-label="Internal load balancing">
          <rect class="ls-card" x="1020" y="378" width="72" height="364" rx="12"/>${icon('lb', 1044, 394, 24)}
          <text class="ls-t1" transform="translate(1060,600) rotate(-90)" text-anchor="middle">Internal load balancing</text>
          <text class="ls-elb-d" transform="translate(1078,600) rotate(-90)" text-anchor="middle">*.sap.&lt;customerdomain&gt;</text>
        </g>
        <g class="ls-node ls-elb" data-node="elb" tabindex="0" role="button" aria-label="External load balancing, WAF and proxy">
          <rect class="ls-halo" x="374" y="274" width="702" height="80" rx="40"/>
          <rect class="ls-card" x="380" y="280" width="690" height="68" rx="34"/>
          <text class="ls-elb-d" x="760" y="307">*.sap.&lt;customerdomain&gt;</text>
          <text class="ls-t1" x="760" y="329">External LB / WAF / Proxy</text>
          ${icon('shield', 962, 300, 28)}${icon('lb', 1010, 300, 28)}
          <g class="ls-badge" transform="translate(1060,286)"><circle r="9"/><text y="3.6" text-anchor="middle"></text></g>
        </g>
        <g class="ls-node ls-tunnel" data-node="tunnel" tabindex="0" role="button" aria-label="Secure tunnel">
          <rect class="ls-halo" x="270" y="194" width="40" height="232" rx="20"/>
          <rect class="ls-card" x="276" y="200" width="28" height="220" rx="14"/>
          <text class="ls-tunnel-t" transform="translate(295,262) rotate(-90)" text-anchor="middle">Secure tunnel</text>
        </g>
        <g class="ls-node ls-conn" data-node="conn" tabindex="0" role="button" aria-label="Connectivity service">
          <circle class="ls-halo" cx="290" cy="175" r="29"/>
          <circle class="ls-card" cx="290" cy="175" r="22"/>${icon('link', 278, 163, 24)}
          <text class="ls-t2" x="290" y="141" text-anchor="middle">Connectivity</text>
        </g>
        ${Object.keys(NODES).map(k => card(k, NODES[k])).join('')}
        ${['dev', 'qas', 'prd'].map(s4box).join('')}
      </g>
      <g id="lsMarks"></g>
      <g id="lsFx" aria-hidden="true"></g>
      <g id="lsHud" class="ls-hud" aria-hidden="true"></g>
    </svg>`;
  }

  /* ================= Routes =================
   * Packets travel through the component centers underneath the cards (they enter and leave a component); the numbered
   * hop markers sit where the route leaves a card, so they never cover its label. */
  function route(pathId, tier, viaWd) {
    const tx = TX[tier] - 58, wx = WX[tier], lane = TX[tier] - 110, P = [];
    const pt = (x, y, step) => P.push({ x, y, step });
    const s4 = () => { pt(tx, COR); pt(tx, CHIP.icm, 'icm'); pt(tx, CHIP.logon, 'logon'); pt(tx, CHIP.abap, 'abap'); };
    if (pathId === 'pp') {
      pt(110, 95); pt(172, 95, 'user'); pt(560, 95); pt(560, 122, 'app'); pt(560, 175); pt(290, 175); pt(290, 395, 'tunnel');
      pt(290, 455); pt(290, 487, 'scc'); pt(290, COR, 'scc-be');
      if (viaWd) { pt(wx, COR); pt(wx, 487, 'wd'); pt(wx, 455); pt(wx, COR - 22, 'wd-be'); }
      s4();
    } else if (pathId === 'web') {
      pt(110, 95); pt(110, 120, 'browser'); pt(110, TOP); pt(wx, TOP); pt(wx, ELBY, 'elb'); pt(wx, 455); pt(wx, 487, 'wd'); pt(wx, COR, 'wd-be');
      s4();
    } else {
      const ex = Math.max(lane, 420);
      pt(tx, CHIP.abap, 'abap-out'); pt(tx, CHIP.icm, 'icm-out'); pt(lane, CHIP.icm); pt(lane, ELBY);
      if (ex !== lane) pt(ex, ELBY);
      P[P.length - 1].step = 'egress';
      pt(ex, TOP); pt(905, TOP); pt(905, 212, 'remote'); pt(905, 180);
    }
    return poly(P);
  }
  // logon → IAS: the backend's SAML redirect travels back to the IdP
  const bounceRoute = tier => poly([{ x: TX[tier] - 58, y: CHIP.logon }, { x: TX[tier] - 110, y: CHIP.logon }, { x: TX[tier] - 110, y: TOP }, { x: 800, y: TOP }, { x: 800, y: 95 }]);
  function poly(P) {
    let d = 0;
    P.forEach((p, i) => { if (i) d += Math.hypot(p.x - P[i - 1].x, p.y - P[i - 1].y); p.d = d; });
    const at = dist => {
      if (dist <= 0) return P[0];
      for (let i = 1; i < P.length; i++) {
        if (P[i].d < dist) continue;
        const a = P[i - 1], b = P[i], k = b.d - a.d ? (dist - a.d) / (b.d - a.d) : 1;
        return { x: a.x + (b.x - a.x) * k, y: a.y + (b.y - a.y) * k };
      }
      return P[P.length - 1];
    };
    // the part of the line between two distances, as SVG path data
    const part = (a, b) => {
      const pts = [at(a)].concat(P.filter(p => p.d > a && p.d < b), [at(b)]);
      return 'M' + pts.map(p => `${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' L');
    };
    return { P, len: d, at, part, d: part(0, d) };
  }

  /* ================= Paths, steps, state ================= */
  const curTier = () => (S.diag ? S.diag.target.tier : S.tier !== 'auto' ? S.tier : 'prd');
  function introPath(id) {
    const p = L.PATHS.find(x => x.id === id) || L.PATHS[0];
    return Object.assign({}, p, { relevant: true, fail: null, warn: null, steps: p.steps.map((s, i) => ({ id: s, n: i + 1, def: L.STEPS[s], status: 'idle', items: [], oks: [], gaps: [] })) });
  }
  const curPath = () => (S.diag ? S.diag.paths.find(p => p.id === S.path) || S.diag.paths[0] : introPath(S.path));
  const defaultStep = p => (p.fail || p.warn || p.steps.find(s => s.items.length || s.gaps.length) || p.steps.find(s => s.status === 'unknown') || p.steps[0]).id;
  const RANK = { fail: 0, warn: 1, ok: 2, clear: 3, unknown: 4, blocked: 5, idle: 6 };
  const worse = (a, b) => (a == null || RANK[b] < RANK[a] ? b : a);
  const BADGE = { fail: '✕', warn: '!', ok: '✓', clear: '✓', unknown: '?', blocked: '–', idle: '' };
  const LABEL = Object.assign({ idle: 'Not analyzed yet' }, L.STATUS_LABEL);
  function setState(el, st) {
    [...el.classList].filter(c => c.startsWith('is-')).forEach(c => el.classList.remove(c));
    el.classList.add('is-' + st);
  }
  const resolveNode = n => (n === 'wd' ? (curTier() === 'prd' ? 'wd-p' : 'wd-np') : n === 's4' ? 's4-' + curTier() : n);

  /* ================= Map painting ================= */
  function setSub(g, text) {
    const t = g && g.querySelector('[data-sub]');
    if (!t) return;
    const max = +t.dataset.max || 30, s = String(text || '');
    t.textContent = s.length > max ? s.slice(0, max - 1) + '…' : s;
    let tt = g.querySelector(':scope > title');
    if (!tt) { tt = document.createElementNS(NS, 'title'); g.insertBefore(tt, g.firstChild); }
    tt.textContent = `${g.getAttribute('aria-label')}${s ? ' — ' + s : ''}`;
  }
  function paintMap() {
    const svg = $('map').querySelector('svg'), p = curPath(), tier = curTier();
    const s4Id = 's4-' + tier, wdId = resolveNode('wd');
    const nodeSt = new Map(), layerSt = new Map();
    p.steps.forEach(s => {
      s.def.nodes.forEach(n => nodeSt.set(resolveNode(n), worse(nodeSt.get(resolveNode(n)), s.status)));
      if (s.def.layer) layerSt.set(s.def.layer, worse(layerSt.get(s.def.layer), s.status));
    });
    // the backend sent the request to the IdP instead of logging the user on
    if (p.steps.some(s => s.id === 'logon' && s.items.some(i => i.id === 'scc:pp-idp-redirect'))) nodeSt.set('ias', 'warn');
    const selNodes = new Set();
    const sel = p.steps.find(s => s.id === S.step);
    if (sel) sel.def.nodes.forEach(n => selNodes.add(resolveNode(n)));
    if (S.node) selNodes.add(S.node);
    svg.querySelectorAll('#lsNodes [data-node]').forEach(g => {
      const id = g.dataset.node, st = nodeSt.get(id);
      setState(g, st || 'off');
      g.classList.toggle('target', id === s4Id || id === wdId);
      g.classList.toggle('sel', selNodes.has(id));
      const b = g.querySelector(':scope > .ls-badge text');
      if (b) b.textContent = st ? BADGE[st] : '';
    });
    svg.querySelectorAll('.ls-layer').forEach(l => {
      const mine = l.closest('[data-node]').dataset.node === s4Id && layerSt.has(l.dataset.layer);
      setState(l, mine ? layerSt.get(l.dataset.layer) : 'off');
      l.classList.toggle('sel', mine && !!sel && sel.def.layer === l.dataset.layer);
    });
    const lb = S.diag ? S.diag.labels : {}, t = S.diag ? S.diag.target : {};
    const node = id => svg.querySelector(`[data-node="${id}"]`);
    ['app', 'scc', 'ias', 'remote', 'user'].forEach(k => setSub(node(k), lb[k] || NODES[k].s));
    ['wd-np', 'wd-p'].forEach(k => setSub(node(k), k === wdId && lb.wd ? `${NODES[k].s} · ${lb.wd}` : NODES[k].s));
    ['dev', 'qas', 'prd'].forEach(k => {
      const g = node('s4-' + k);
      g.querySelector('[data-title]').textContent = `S/4 ${TIER[k]}${k === tier && t.sid ? ' · ' + t.sid : ''}`;
      setSub(g, k === tier ? (t.endpoint || t.host || (S.diag ? (t.assumed ? 'tier assumed' : '') : '')) : '');
    });
    setSub(node('tunnel'), lb.tunnel || '');
    drawRoute(p);
  }

  /* ================= Route, markers, animation ================= */
  /* With Cloud Connector requests in the logs the map replays them: one packet per request, in their real order and spacing
   * (compressed), each ending at the hop where that request stopped (diag.requests) — nothing flows past a failing hop.
   * Without request-level data (other paths, the intro) one request per interval shows the verdict. */
  const A = { raf: 0, pks: [], last: 0, next: 0, R: null, B: null, stop: 0, failD: null, redirD: null, marks: [], lastStep: '',
    plan: null, pi: 0, cycle: null, period: 0, k: 1, t0: null, span: 0, sent: 0, okN: 0, stopN: 0, live: {} };
  const SPEED = 330, EVERY = 1150, GAP = 220, PAUSE = 1400, MAX_PK = 120;
  const dOf = id => { const q = A.R.P.find(x => x.step === id); return q ? q.d : null; };
  function buildPlan(reqs) {
    if (!reqs.length) return null;
    const ts = reqs.map(r => r.t0).filter(t => t != null);
    const t0 = ts.length ? Math.min(...ts) : null, span = ts.length ? Math.max(...ts) - t0 : 0;
    const want = Math.min(16000, Math.max(4000, reqs.length * 600));   // length of one replay
    const k = span > want ? span / want : 1;
    const per = Math.ceil(reqs.length / MAX_PK);   // many requests: one packet stands for several with the same journey
    const plan = [];
    let last = -Infinity;
    for (const r of reqs) {
      const prev = plan[plan.length - 1];
      if (prev && prev.w < per && prev.stop === r.stop && prev.fate === r.fate) { prev.w++; continue; }
      const at = Math.max(t0 != null && r.t0 != null ? (r.t0 - t0) / k : 0, last + GAP);
      last = at;
      const d = r.stop ? dOf(r.stop) : null;
      plan.push({ at, w: 1, stop: r.stop, fate: r.fate, d: d == null ? A.R.len : d });
    }
    const far = Math.max(...plan.map(e => e.d)), back = A.B ? A.B.len : 0;
    Object.assign(A, { k, t0, span, period: Math.ceil((last + (far + back) / SPEED * 1000 + PAUSE) / 100) * 100 });
    return plan;
  }
  function drawRoute(p) {
    const R = A.R = route(p.id, curTier(), S.diag ? S.diag.viaWd : false);
    A.failD = p.fail ? dOf(p.fail.id) : null;
    const lg = p.steps.find(s => s.id === 'logon' && s.items.some(i => i.id === 'scc:pp-idp-redirect'));
    A.redirD = lg ? dOf('logon') : null;
    A.lastStep = p.steps[p.steps.length - 1].id;
    const reqs = S.diag && p.id === 'pp' ? S.diag.requests || [] : [];
    // the backend's redirect travels to the IdP only for requests that reached the logon
    A.B = (reqs.length ? reqs.some(r => r.fate === 'warn') : A.failD == null && A.redirD != null) ? bounceRoute(curTier()) : null;
    A.plan = buildPlan(reqs);
    // the line ends at the farthest hop a request reached
    A.stop = A.plan ? Math.max(...A.plan.map(e => e.d)) : A.failD != null ? A.failD : A.redirD != null ? A.redirD : R.len;
    A.marks = R.P.filter(q => q.step).map(q => ({ id: q.step, d: q.d, x: q.x, y: q.y }));
    const idle = S.diag ? '' : ' idle';
    let h = `<path class="ls-route-bg" d="${R.d}"/><path class="ls-route${idle}${A.failD != null && A.stop <= A.failD + .5 ? ' broken' : ''}" d="${R.part(0, A.stop)}"/>`;
    if (A.stop < R.len - 0.5) h += `<path class="ls-route-dead" d="${R.part(A.stop, R.len)}"/>`;
    if (A.B) h += `<path class="ls-route bounce" d="${A.B.d}"/>`;
    $('lsRoutes').innerHTML = h;
    // request counts sit outside the S/4 box for its layers (inside, they would cover the host name)
    const IN_S4 = new Set(['icm', 'logon', 'abap', 'icm-out', 'abap-out']);
    $('lsMarks').innerHTML = A.marks.map(m => {
      const s = p.steps.find(x => x.id === m.id);
      if (!s) return '';
      const cnt = IN_S4.has(s.id) ? 'x="-26" y="4" text-anchor="end"' : 'x="15" y="-12"';
      return `<g class="ls-mark is-${s.status}${s.id === S.step ? ' sel' : ''}" data-step="${s.id}" transform="translate(${m.x},${m.y})">
        <title>${s.n}. ${esc(s.def.title)} — ${esc(LABEL[s.status])}</title>
        <circle class="pulse" r="12"/><circle class="ring" r="12"/><circle class="core" r="9"/><text y="3.6" text-anchor="middle">${s.n}</text><text class="ls-cnt" ${cnt}></text></g>`;
    }).join('');
    showCounts(totals()); hud();
  }
  // requests per hop where they ended: ✕ stopped · 302 redirected to the IdP · ✓ reached the application
  const CNT = { fail: n => `✕ ${n}`, warn: n => `302 ×${n}`, ok: n => `✓ ${n}` };
  function totals() {
    const c = {};
    (A.plan || []).forEach(e => { const k = e.stop || A.lastStep; c[k] = c[k] || { n: 0, fate: e.fate }; c[k].n += e.w; });
    return c;
  }
  function showCounts(c) {
    $('lsMarks').querySelectorAll('.ls-mark').forEach(g => {
      const t = g.querySelector('.ls-cnt'), x = c[g.dataset.step];
      t.textContent = x && x.n ? CNT[x.fate](x.n) : '';
      t.setAttribute('class', 'ls-cnt' + (x ? ' is-' + x.fate : ''));
    });
  }
  // replay clock, requests sent / through / stopped, progress of the replay
  function hud(ct) {
    const g = $('lsHud');
    if (!g) return;
    let a = '', b = '', frac = null;
    if (A.plan) {
      const n = A.plan.reduce((s, e) => s + e.w, 0), live = ct != null;
      const tot = Object.values(totals()), ok = live ? A.okN : tot.filter(x => x.fate === 'ok').reduce((s, x) => s + x.n, 0);
      const stopped = live ? A.stopN : n - ok, hms = t => TS.fmtTime(t).slice(11, 19);
      a = `Replay of ${n} request${n === 1 ? '' : 's'} from the logs${A.k > 1.5 ? ` · ×${Math.round(A.k)}` : ''}`;
      const when = A.t0 == null ? '' : live ? hms(A.t0 + Math.min(ct * A.k, A.span)) : A.span ? `${hms(A.t0)}–${hms(A.t0 + A.span)}` : hms(A.t0);
      b = `${when ? when + ' · ' : ''}${live ? `${A.sent}/${n} sent · ` : ''}${ok} reached the app · ${stopped} stopped`;
      frac = live ? Math.min(1, ct / A.period) : null;
    } else if (S.diag) a = 'No request-level log for this path: the packets show the verdict';
    const key = `${a}|${b}|${frac == null ? '' : frac.toFixed(2)}`;
    if (g.dataset.k === key) return;
    g.dataset.k = key;
    g.innerHTML = !a ? '' : `<text class="ls-hud-a" x="20" y="26">${esc(a)}</text>${b ? `<text class="ls-hud-b" x="20" y="44">${esc(b)}</text>` : ''}` +
      (frac != null ? `<rect class="ls-hud-bar" x="20" y="52" width="240" height="4" rx="2"/><rect class="ls-hud-fill" x="20" y="52" width="${(240 * frac).toFixed(1)}" height="4" rx="2"/>` : '');
  }
  function placePk(p) {
    const q = (p.kind === 'bounce' ? A.B : A.R).at(p.d);
    p.el.setAttribute('cx', q.x.toFixed(1)); p.el.setAttribute('cy', q.y.toFixed(1));
    if (p.tag) p.tag.setAttribute('transform', `translate(${(q.x + 9).toFixed(1)},${(q.y - 8).toFixed(1)})`);
  }
  function spawn(kind, e) {
    const g = $('lsPk'), el = document.createElementNS(NS, 'circle');
    el.setAttribute('r', kind === 'bounce' ? 5 : 6);
    el.setAttribute('class', 'ls-pk' + (kind === 'bounce' ? ' bounce' : S.diag ? '' : ' idle'));
    g.appendChild(el);
    const p = { el, d: 0, kind: kind || 'req', e: e || null, stop: kind === 'bounce' ? A.B.len : e ? e.d : A.stop };
    if (kind === 'bounce') { p.tag = document.createElementNS(NS, 'text'); p.tag.setAttribute('class', 'ls-pk-tag'); p.tag.textContent = '302'; g.appendChild(p.tag); }
    if (e) A.sent += e.w;
    A.pks.push(p); placePk(p);
  }
  // a request packet at the end of its journey: burst in the colour of its fate; an IdP redirect bounces to the IdP
  function arrive(p, end) {
    const e = p.e, fate = e ? e.fate : A.failD != null ? 'fail' : A.redirD != null ? 'warn' : 'ok';
    burst(end, fate === 'fail' ? 'fail' : fate === 'warn' ? 'redirect' : S.diag ? 'ok' : 'idle');
    if (fate === 'warn' && A.B) spawn('bounce');
    if (!e) return;
    const k = e.stop || A.lastStep;
    A.live[k] = A.live[k] || { n: 0, fate };
    A.live[k].n += e.w;
    if (fate === 'ok') A.okN += e.w; else A.stopN += e.w;
    showCounts(A.live);
  }
  function newCycle(now) {
    Object.assign(A, { cycle: now, pi: 0, sent: 0, okN: 0, stopN: 0, live: {} });
    showCounts({});
  }
  function burst(q, cls) {
    const el = document.createElementNS(NS, 'circle');
    el.setAttribute('cx', q.x); el.setAttribute('cy', q.y); el.setAttribute('r', 10); el.setAttribute('class', 'ls-burst ' + cls);
    $('lsFx').appendChild(el);
    setTimeout(() => el.remove(), 900);
  }
  function flash(id) {
    const m = $('lsMarks').querySelector(`[data-step="${id}"]`);
    if (!m) return;
    m.classList.add('hit');
    setTimeout(() => m.classList.remove('hit'), 420);
  }
  function drop(p) { p.el.remove(); if (p.tag) p.tag.remove(); A.pks.splice(A.pks.indexOf(p), 1); }
  function tick(now) {
    A.raf = requestAnimationFrame(tick);
    const dt = Math.min(50, now - (A.last || now)) / 1000;
    A.last = now;
    if (A.plan) {
      if (A.cycle == null || now - A.cycle >= A.period) newCycle(now);
      const ct = now - A.cycle;
      while (A.pi < A.plan.length && A.plan[A.pi].at <= ct) spawn('req', A.plan[A.pi++]);
      hud(ct);
    } else if (now >= A.next && A.pks.length < 9) { spawn(); A.next = now + EVERY; }
    for (const p of A.pks.slice()) {
      const prev = p.d;
      p.d += dt * SPEED;
      if (p.kind === 'req') A.marks.forEach(m => { if (prev < m.d && p.d >= m.d && m.d < p.stop - 0.5) flash(m.id); });
      if (p.d >= p.stop) {
        const end = (p.kind === 'bounce' ? A.B : A.R).at(p.stop);
        drop(p);
        if (p.kind === 'bounce') burst(end, 'redirect');
        else { flash((A.marks.find(m => Math.abs(m.d - p.stop) < 0.5) || {}).id); arrive(p, end); }
        continue;
      }
      placePk(p);
    }
  }
  function stopAnim() {
    cancelAnimationFrame(A.raf); A.raf = 0;
    A.pks.slice().forEach(drop);
    ['lsPk', 'lsFx'].forEach(id => { const g = $(id); if (g) g.innerHTML = ''; });
  }
  function startAnim() {
    stopAnim();
    $('map').classList.toggle('still', S.paused);
    showCounts(totals()); hud();
    if (S.paused) return;
    A.last = 0; A.next = 0; A.cycle = null;
    A.raf = requestAnimationFrame(tick);
  }

  /* ================= Verdict, path switch, legend ================= */
  function whereLabel(s) {
    const t = curTier(), sid = S.diag && S.diag.target.sid;
    if (s.def.nodes.includes('s4')) return `S/4 ${TIER[t]}${sid ? ' (' + sid + ')' : ''} — ${s.def.title.replace(/^S\/4 · /, '')}`;
    if (s.def.nodes.includes('wd')) return `Web Dispatcher ${t === 'prd' ? 'PRD' : 'Non-PRD'} — ${s.def.title}`;
    return s.def.title;
  }
  const V_ICON = {
    fail: '<svg viewBox="0 0 24 24" width="30" height="30"><path d="M7 7l10 10M17 7 7 17" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg>',
    warn: '<svg viewBox="0 0 24 24" width="30" height="30"><path d="M12 7v6m0 4h.01" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg>',
    ok: '<svg viewBox="0 0 24 24" width="30" height="30"><path d="m6 12.5 4 4 8-9" stroke="currentColor" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    unknown: '<svg viewBox="0 0 24 24" width="30" height="30"><path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14m0 3h.01" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round"/></svg>'
  };
  function renderVerdict() {
    $('intro').hidden = !!S.diag;
    const v = $('verdict');
    v.hidden = !S.diag;
    if (!S.diag) { v.innerHTML = ''; return; }
    const p = curPath();
    let cls, kick, title, sub;
    if (p.fail) {
      const s = p.fail, it = s.items.find(x => x.kind === 'cause') || s.items[0];
      cls = 'fail'; kick = `Request breaks at hop ${s.n} of ${p.steps.length} · ${p.title}`; title = whereLabel(s);
      sub = `${it.title}${it.count ? ` · ${it.count}×` : ''}${it.t0 != null ? ` · ${range(it.t0, it.t1)}` : ''}`;
    } else if (p.warn) {
      cls = 'warn'; kick = `No hop fails · warning at hop ${p.warn.n} of ${p.steps.length} · ${p.title}`; title = whereLabel(p.warn); sub = p.warn.items[0].title;
    } else if (!p.relevant) {
      cls = 'unknown'; kick = p.title; title = 'No log of this path is loaded';
      sub = `Load ${p.id === 'web' ? 'dev_webdisp / the HTTP log of the Web Dispatcher' : p.id === 'out' ? 'SM59 connection tests or the dev_icm of the calling instance' : 'the Cloud Connector logs'} — or pick another path above.`;
    } else {
      const unk = p.steps.filter(s => s.status === 'unknown');
      cls = 'ok'; kick = p.title; title = 'No failing hop in the loaded logs';
      sub = unk.length ? `Not covered by any loaded log: ${unk.map(s => s.def.title).join(', ')}.` : 'Every hop is covered by a log and shows no error.';
    }
    const cnt = {};
    p.steps.forEach(s => (cnt[s.status] = (cnt[s.status] || 0) + 1));
    const CHIP_L = { fail: 'failing', warn: 'warning', ok: 'working', clear: 'clean in the logs', blocked: 'not reached', unknown: 'without log' };
    const chips = ['fail', 'warn', 'ok', 'clear', 'blocked', 'unknown'].filter(k => cnt[k]).map(k => `<span class="ls-chip is-${k}"><i>${BADGE[k]}</i>${cnt[k]} ${CHIP_L[k]}</span>`).join('');
    const t = S.diag.target;
    v.innerHTML = `<div class="ls-verdict is-${cls}">
      <div class="v-ic" aria-hidden="true">${V_ICON[cls]}</div>
      <div class="v-body"><div class="v-kick">${esc(kick)}</div><h1>${esc(title)}</h1><p>${esc(sub)}</p>
        <div class="v-counts">${chips}<span class="ls-chip plain">Target: S/4 ${TIER[t.tier]}${t.sid ? ' · ' + esc(t.sid) : ''} <span class="muted">(${esc(t.how)})</span></span></div></div>
      ${p.fail || p.warn ? '<div class="v-act"><button class="btn primary" id="btnFix">Show cause &amp; fix →</button></div>' : ''}
    </div>`;
    const b = $('btnFix');
    if (b) b.onclick = () => { select((p.fail || p.warn).id); $('inspector').scrollIntoView({ behavior: REDUCED ? 'auto' : 'smooth', block: 'nearest' }); };
  }
  function renderSeg() {
    const paths = S.diag ? S.diag.paths : L.PATHS.map(p => introPath(p.id));
    $('pathSeg').innerHTML = paths.map(p => {
      const st = !S.diag ? '' : p.fail ? 'fail' : p.warn ? 'warn' : p.relevant ? 'ok' : 'unknown';
      return `<button role="tab" aria-selected="${p.id === S.path}" class="${p.id === S.path ? 'active' : ''}" data-path="${p.id}" title="${esc(p.title)}">${st ? `<span class="ls-seg-dot is-${st}">${BADGE[st]}</span>` : ''}${esc(p.short)}${S.diag && !p.relevant ? '<span class="n">no logs</span>' : ''}</button>`;
    }).join('');
  }
  function renderLegend() {
    const k = ['fail', 'warn', 'ok', 'clear', 'blocked', 'unknown'];
    $('legend').innerHTML = k.map(s => `<span><b class="ls-lg is-${s}">${BADGE[s]}</b>${esc(LABEL[s])}</span>`).join('') +
      '<span><b class="ls-lg pk"></b>Request (replayed from the logs)</span><span><b class="ls-lg pk bounce"></b>Redirect to the IdP</span>' +
      '<span><b class="ls-cnt-lg">✕ n</b>Requests that stopped at this hop</span>';
  }

  /* ================= Journey + inspector ================= */
  const summaryOf = s => (s.items[0] ? (s.items[0].kind === 'symptom' ? 'Symptom: ' : '') + s.items[0].title + (s.items.length > 1 ? ` (+${s.items.length - 1})` : '')
    : s.gaps[0] ? s.gaps[0].title : s.oks[0] ? s.oks[0] : s.status === 'idle' ? s.def.what : LABEL[s.status]);
  function renderJourney() {
    const p = curPath();
    $('journeyTitle').textContent = p.title;
    $('journeyNote').textContent = S.diag ? `${p.steps.length} hops` : 'drop logs to check each hop';
    $('journey').innerHTML = p.steps.map(s => `<li class="ls-step is-${s.status}${s.id === S.step ? ' sel' : ''}" data-step="${s.id}" tabindex="0" role="button" aria-current="${s.id === S.step}">
      <span class="ls-dot" aria-hidden="true">${BADGE[s.status] || s.n}</span>
      <div class="ls-step-b"><div class="ls-step-t"><span class="n">${s.n}</span>${esc(s.def.title)}</div><div class="ls-step-s">${esc(summaryOf(s))}</div></div>
    </li>`).join('');
  }
  const SEV_C = { critical: 'var(--critical)', high: 'var(--serious)', medium: 'var(--warning)', low: 'var(--muted)', info: 'var(--lvl-info)' };
  function itemCard(it) {
    const sym = it.kind === 'symptom';
    return `<article class="finding ls-item${sym ? ' sym' : ''}" style="--fc:${sym ? 'var(--warning)' : SEV_C[it.sev] || 'var(--border-strong)'}">
      <div class="finding-head">${TS.sevPill(it.sev)}<span class="ls-kind">${sym ? 'Symptom — caused at an earlier hop' : 'Located at this hop'}</span></div>
      <h3>${esc(it.title)}</h3>
      <div class="finding-meta">${it.count ? `<span><b>${it.count}×</b></span>` : ''}${it.t0 != null ? `<span>${esc(range(it.t0, it.t1))}</span>` : ''}${it.src ? `<span>${esc(C.label(it.src))}</span>` : ''}</div>
      ${it.note ? `<p class="ls-note">${esc(it.note)}</p>` : ''}
      ${it.why ? `<p>${esc(it.why)}</p>` : ''}
      ${(it.params || []).map(x => `<div class="ls-param"><code>${esc(x)}</code><button class="btn ghost" data-copy="${esc(x)}">Copy</button></div>`).join('')}
      ${it.evidence && it.evidence.length ? `<details${it.evidence.length <= 3 ? ' open' : ''}><summary>Evidence (${it.evidence.length})</summary><ul class="ls-ev">${it.evidence.slice(0, 12).map(e => `<li>${esc(e)}</li>`).join('')}</ul></details>` : ''}
      ${it.fix && it.fix.length && !sym ? `<h4 class="ins-h">Fix</h4><ol class="ls-fix">${it.fix.map(f => `<li>${esc(f)}</li>`).join('')}</ol>` : ''}
    </article>`;
  }
  function coverage(s) {
    const files = S.files.filter(f => s.def.covers.includes(f.src));
    return `<div class="ls-cover"><h4 class="ins-h">Logs for this hop</h4>
      ${files.length ? `<p class="ls-files">${files.map(f => `<span class="badge" title="${esc(f.name)}">${esc(base(f.name))}</span>`).join(' ')}</p>`
        : `<p class="muted small">${s.def.covers.length ? `Not loaded — this hop is shown by: ${s.def.covers.map(c => C.label(c)).join(', ')}.` : 'No SAP log shows this hop.'}</p>`}
      <p class="small"><b>How to collect:</b> ${esc(s.def.collect)}</p></div>`;
  }
  function renderInspector() {
    const box = $('inspector'), p = curPath();
    if (S.node && !S.step) {
      const i = INFO[S.node] || [S.node, ''];
      box.innerHTML = `<div class="ins-top"><span class="ls-st is-off">Component</span><span class="muted small">not a hop of “${esc(p.title)}”</span></div><h2 class="ins-title">${esc(i[0])}</h2><p class="ins-what">${esc(i[1])}</p>`;
      return;
    }
    const s = p.steps.find(x => x.id === S.step);
    if (!s) { box.innerHTML = ''; return; }
    let h = `<div class="ins-top"><span class="ls-st is-${s.status}"><i>${BADGE[s.status] || s.n}</i>${esc(LABEL[s.status])}</span><span class="muted small">Hop ${s.n} of ${p.steps.length} · ${esc(p.title)}</span></div>
      <h2 class="ins-title">${esc(S.diag ? whereLabel(s) : s.def.title)}</h2><p class="ins-what">${esc(s.def.what)}</p>`;
    if (!S.diag) {
      h += `<div class="ls-how"><h4 class="ins-h">How it works</h4><ol class="ls-fix">
        <li>${TS.embed.on ? 'Add the logs of one incident in <b>Evidence</b> (the one place for files) — every workspace uses them.'
          : 'Drop the logs of one incident (files, a folder or a .zip) — or <button class="btn link" data-example>try the example</button>.'}</li>
        <li>Each hop of the request path is checked with the logs that cover it; the request animation stops where it breaks.</li>
        <li>Click a hop for the cause, the evidence from the logs and the fix. Hops without a log tell you which log to collect.</li></ol></div>`;
      box.innerHTML = h + coverage(s);
      return;
    }
    if (s.status === 'blocked') h += `<p class="ls-note">Not reached: the request already fails at hop ${p.fail.n} (${esc(p.fail.def.title)}). Fix that hop first, then check again with new logs.</p>`;
    if (s.status === 'clear') h += '<p class="ls-note ok">The loaded logs cover this hop and show no error for it.</p>';
    // the requests of the replay that ended here
    const reqs = p.id === 'pp' ? S.diag.requests || [] : [];
    const here = reqs.filter(r => (r.stop || p.steps[p.steps.length - 1].id) === s.id);
    if (here.length) {
      const when = here.map(r => r.t0).filter(t => t != null);
      const thru = !here[0].stop;
      h += `<p class="ls-note${thru ? ' ok' : ''}">${here.length} of ${reqs.length} request(s) ${thru ? 'got through to the application' : `stopped here — ${esc(here[0].why)}`}` +
        `${when.length ? ` (${esc(range(Math.min(...when), Math.max(...when)))})` : ''}.</p>`;
    }
    h += s.items.map(itemCard).join('');
    h += s.gaps.map(g => `<article class="finding ls-item" style="--fc:var(--muted)"><div class="finding-head"><span class="ls-kind">The loaded log does not cover this hop</span></div><h3>${esc(g.title)}</h3><p>${esc(g.why)}</p>
      ${g.evidence && g.evidence.length ? `<ul class="ls-ev">${g.evidence.map(e => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}${g.fix && g.fix.length ? `<h4 class="ins-h">Collect</h4><ol class="ls-fix">${g.fix.map(f => `<li>${esc(f)}</li>`).join('')}</ol>` : ''}</article>`).join('');
    if (s.oks.length) h += `<h4 class="ins-h">Evidence that it works</h4><ul class="ls-oks">${s.oks.map(o => `<li>${esc(o)}</li>`).join('')}</ul>`;
    box.innerHTML = h + coverage(s);
  }

  /* ================= Sources ================= */
  function renderSources() {
    $('srcCard').hidden = !S.diag;
    if (!S.diag) return;
    if (TS.embed.on) {   // the cockpit lists and manages the files in Evidence; the time range stays here
      $('srcTable').closest('.table-wrap').hidden = true;
      $('srcCard').querySelector('h2').textContent = 'Analysis time range';
    }
    const opts = sel => C.SOURCES.map(s => `<option value="${s.id}"${s.id === sel ? ' selected' : ''}>${esc(s.label)}</option>`).join('');
    $('srcTable').innerHTML = `<thead><tr><th>File</th><th>Read as</th><th>Result</th><th class="num">Errors</th><th></th></tr></thead><tbody>${S.files.map((f, i) => `
      <tr><td class="mono" title="${esc(f.name)}">${esc(base(f.name))}</td>
      <td><select data-src="${i}" aria-label="Source of ${esc(base(f.name))}">${opts(f.src)}</select></td>
      <td class="small muted">${esc(f.note || '')}</td><td class="num">${(f.errCount || 0).toLocaleString('en-US')}</td>
      <td><button class="btn ghost icon" data-del="${i}" aria-label="Remove file" title="Remove">✕</button></td></tr>`).join('')}
      ${S.skipped.length ? `<tr><td colspan="5" class="small muted">Skipped: ${S.skipped.map(s => esc(base(s.name) + ' — ' + s.reason)).join('; ')}</td></tr>` : ''}</tbody>`;
    $('srcTable').querySelectorAll('[data-src]').forEach(s => (s.onchange = () => { S.files[+s.dataset.src].src = s.value; rebuild(); }));
    $('srcTable').querySelectorAll('[data-del]').forEach(b => (b.onclick = () => { S.files.splice(+b.dataset.del, 1); if (S.files.length) rebuild(); else reset(); }));
    const tz = S.diag.tz;
    $('tzNote').textContent = tz && tz.off != null ? `Times in SAP server time ${TS.fmtOffset(tz.off)} (${tz.how})` : '';
    const rest = S.diag.notes.concat(S.diag.other);
    $('otherFindings').innerHTML = rest.length ? `<h4 class="ins-h">Not on the request path</h4><ul class="ls-ev">${rest.map(x => `<li>${TS.sevPill(x.sev)} ${esc(x.title)}${x.count ? ` · ${x.count}×` : ''}</li>`).join('')}</ul>` : '';
  }

  /* ================= Rendering & selection ================= */
  function renderAll(keepAnim) {
    renderVerdict(); renderSeg(); paintMap(); renderJourney(); renderInspector(); renderSources();
    if (!keepAnim) startAnim();
  }
  function select(stepId) {
    S.step = stepId; S.node = null;
    renderJourney(); renderInspector(); paintMap();
  }
  function selectNode(id) {
    const p = curPath();
    const hits = p.steps.filter(s => s.def.nodes.some(n => resolveNode(n) === id));
    if (hits.length) { select(hits.slice().sort((a, b) => RANK[a.status] - RANK[b.status])[0].id); return; }
    S.step = null; S.node = id;
    renderJourney(); renderInspector(); paintMap();
  }
  function setPath(id) {
    S.path = id; S.node = null;
    S.step = defaultStep(curPath());
    renderAll();
  }
  function highlight(stepId, on) {
    const m = $('lsMarks').querySelector(`[data-step="${stepId}"]`);
    if (m) m.classList.toggle('hl', on);
    const s = curPath().steps.find(x => x.id === stepId);
    if (s) s.def.nodes.forEach(n => { const g = $('map').querySelector(`#lsNodes [data-node="${resolveNode(n)}"]`); if (g) g.classList.toggle('hl', on); });
  }

  /* ================= Loading ================= */
  function setStatus(msg, isErr) { const s = $('status'); s.textContent = msg || ''; s.classList.toggle('error', !!isErr); }
  async function addFiles(list, fromCockpit) {
    if (!list || !list.length) return;
    if (!fromCockpit && TS.embed.forward(list)) return;
    try {
      const { out, skipped } = await TS.readInputs(list, msg => setStatus(msg));
      S.skipped.push(...skipped);
      for (const f of out) {
        if (S.files.some(x => x.name === f.name && x.size === f.size)) continue;
        S.files.push({ name: f.name, text: f.text, size: f.size, mtime: f.mtime, src: TS.embed.srcOf.get(f.name) || C.classify(f.name, f.text), shiftH: 0 });
      }
      if (!S.files.length) { setStatus('No readable files. ' + skipped.map(s => `${base(s.name)}: ${s.reason}`).join('; '), true); TS.embed.report({ status: 'empty', badge: '–', line: 'No readable files' }); return; }
      setStatus('Checking every hop…');
      await new Promise(r => setTimeout(r, 0));
      rebuild();
      setStatus('');
    } catch (err) {
      console.error(err);
      setStatus('Failed to process files: ' + err.message, true);
    }
  }
  function rebuild() {
    S.data = C.build(S.files, { datefmt: 'auto', tz: 'auto' });
    S.from = S.to = null;
    S.flow = '';
    slider.setData({
      tMin: S.data.tMin, tMax: S.data.tMax, items: S.data.events,
      series: [{ label: 'ERROR', color: 'var(--lvl-error)' }, { label: 'WARN', color: 'var(--lvl-warn)' }],
      seriesOf: e => (e.level === 'ERROR' || e.level === 'FATAL' ? 0 : e.level === 'WARN' ? 1 : -1)
    });
    diagnose(true);
  }
  const opts = extra => Object.assign({ tier: S.tier, from: S.from, to: S.to, flow: S.flow, window: S.allTime ? 'all' : 'auto' }, extra);
  // request flows (applications) of the Cloud Connector, each with its own verdict — a shared SCC carries several applications
  function renderFlows() {
    const flows = L.flows(S.data.conns);
    $('flowWrap').hidden = flows.length < 2;
    if (flows.length < 2) { S.flow = ''; return; }
    const mark = f => { const p = L.diagnose(S.data, S.files, opts({ flow: f.key })).paths.find(x => x.id === 'pp'); return p.fail ? `✕ hop ${p.fail.n}` : p.warn ? '! warning' : '✓ OK'; };
    $('optFlow').innerHTML = `<option value="">All request flows (${flows.length})</option>` +
      flows.map(f => `<option value="${esc(f.key)}"${f.key === S.flow ? ' selected' : ''}>${esc(mark(f))} · ${esc(L.flowLabel(f))}</option>`).join('');
  }
  function renderScope() {
    const el = $('scope'), w = S.diag && S.diag.window, d = S.data;
    if (!w || !d || !d.conns.length) { el.hidden = true; return; }
    el.hidden = false;
    const all = d.tMin != null ? range(d.tMin, d.tMax) : '';
    el.innerHTML = S.allTime
      ? `All log entries are used${all ? ` (${esc(all)})` : ''}. <button class="btn link" type="button" data-scope="auto">Focus on the minutes of the requests</button>`
      : w.auto ? `Focused on the minutes around the Cloud Connector requests: <b>${esc(range(w.from, w.to))}</b>${all && (d.tMin < w.from || d.tMax > w.to) ? ` — the logs cover ${esc(all)}; older and later entries (other days, other clients) are not used` : ''}. <button class="btn link" type="button" data-scope="all">Use all entries</button>`
        : `Analysis time range: <b>${esc(range(w.from, w.to))}</b> (set in “Analysis time range”).`;
  }
  function diagnose(newData) {
    if (newData) renderFlows();
    S.diag = L.diagnose(S.data, S.files, opts());
    renderScope();
    if (newData || !S.diag.paths.some(p => p.id === S.path)) S.path = L.pickPath(S.diag);
    S.node = null;
    S.step = defaultStep(curPath());
    ['btnAdd', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = false));
    renderAll();
    const p = curPath(), s = p.fail || p.warn, t = S.diag.target;
    const w = S.diag.window;
    TS.embed.report({
      status: p.fail ? 'fail' : p.warn ? 'warn' : p.relevant ? 'ok' : 'empty', badge: s ? `hop ${s.n}` : p.relevant ? 'OK' : '–',
      line: s ? whereLabel(s) : p.relevant ? 'No failing hop in the loaded logs' : 'No log of a request path',
      cause: s ? (s.items[0] || {}).title || '' : '', path: S.diag.flow ? L.flowLabel(S.diag.flow) : p.title,
      target: `S/4 ${TIER[t.tier]}${t.sid ? ' · ' + t.sid : ''}`, range: w.from != null ? range(w.from, w.to) : S.data.tMin != null ? range(S.data.tMin, S.data.tMax) : '',
      win: [w.from, w.to]   // the cockpit focuses the timeline on the same minutes
    });
  }
  function reset() {
    Object.assign(S, { files: [], skipped: [], data: null, diag: null, path: 'pp', node: null, from: null, to: null });
    S.step = defaultStep(curPath());
    ['btnAdd', 'btnReport', 'btnReset'].forEach(id => ($(id).hidden = true));
    setStatus('');
    renderAll();
  }

  /* Synthetic example (no customer data): principal propagation from a BTP app, the S/4 ICM does not trust the
   * certificate the Cloud Connector presents (self-signed CN=SCC-PRD vs. the CA-signed one in icm/trusted_reverse_proxy_0) */
  function exampleFiles() {
    const sl = (t, lvl, lg, thr, id, msg) => `2026-11-03 ${t} +0000#${lvl}#${lg}#${thr}#${id}#${msg}`;
    const P = 'com.sap.core.connectivity.';
    const scc = [sl('01:05:12,004', 'INFO', P + 'tunnel.client.TunnelClient', 'tunnel-client-1-1', '          ', 'Tunnel connection established to connectivitytunnel.cf.eu10.hana.ondemand.com')];
    const ssl = (t, msg) => sl(t, 'DEBUG', 'com.sap.scc.rt', 'notification-client-8-1', '          ', 'ssl_debug(51): ' + msg);
    scc.push(ssl('01:09:40,101', 'Sending v3 client_hello message to s4prd.example.test:44300, requesting version 3.3...'),
      ssl('01:09:40,102', 'Received certificate_request handshake message.'), ssl('01:09:40,102', '  Accepted certificate authorities:'),
      ssl('01:09:40,102', '    CN=Example Issuing CA,DC=example,DC=test'), ssl('01:09:40,102', '    CN=SCC-PRD'), ssl('01:09:40,103', 'Sending certificate_verify handshake message.'));
    const icm = ['---------------------------------------------------', 'trc file: "dev_icm", trc level: 2, release: "793"', '---------------------------------------------------',
      'sid        PR1', 'sysno      00', ''];
    [['01:10:58', '09:10:58', '0xa101', '1'], ['01:11:20', '09:11:20', '0xa102', '2'], ['01:12:05', '09:12:05', '0xa103', '3']].forEach(([u, w, id, n], i) => {
      const thr = 'tunnel-client-9-' + n;
      scc.push(sl(u + ',101', 'DEBUG', P + 'tunnel.core.Tunnel', thr, id, `Subscribed connectionId ${id} to tunnel channel [id: 0x1] with tunnelId account:///3f2a9c1e-0000-4000-8000-0000000000a1/LOC_EXAMPLE`),
        sl(u + ',120', 'DEBUG', 'com.sap.scc.security', thr, '          ', `${i ? 'Using cached' : 'Generated'} X.509 certificate with subject CN=jane.doe@example.test`),
        sl(u + ',140', 'DEBUG', P + 'spi.processing.AbstractProtocolProcessor', thr, id, `Successfully opened backend connection [id: 0xd${n}, L:/10.0.0.8:5034${n} - R:s4prd.example.test/10.0.0.27:44300]`),
        sl(u + ',141', 'DEBUG', P + 'protocol.http.handlers.HttpRequestStateHandler', thr, id, 'Start sending https://s4-prd.virtual:443/sap/opu/odata/sap/API_GRMASTERDATA_SRV/$metadata to backend'),
        sl(u + ',142', 'DEBUG', P + 'protocol.http.handlers.HttpAuthenticationHandler', thr, id, 'Will use X.509 certificate for authentication to backend: 8b0b6590(SHA-256)'),
        sl(u + ',190', 'DEBUG', P + 'protocol.http.handlers.HttpLocationHeaderHandler', thr, id, 'Location header represents unknown host: tenant.accounts.ondemand.com. The value of the header remains unchanged: https://tenant.accounts.ondemand.com/saml2/idp/sso/tenant.accounts.ondemand.com?SAMLRequest=x'));
      const T = `[Thr 1402${n}1]`;
      icm.push(`${T} Tue Nov  3 ${w}:763 2026`,
        `${T} HttpHandleCertificate: Client certificate received: with len=1187, subj="CN=SCC-PRD", issuer="CN=SCC-PRD", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`,
        `${T} HttpCertIsReverseProxyTrustworthy: intermediate cert issuer "CN=SCC-PRD" does not match trusted issuer "CN=Example Issuing CA, DC=example, DC=test"`,
        `${T} HttpCertIsReverseProxyTrustworthy: intermediate cert subject "CN=SCC-PRD" does not match trusted subject "CN=SCC-PRD, O=Example, C=MY"`,
        `${T} HttpIsReverseProxyTrustworthy: intermediary is NOT trusted`,
        `${T} HTTP request (raw) [298/63083${n}/1]:`, `${T}   GET /sap/opu/odata/sap/API_GRMASTERDATA_SRV/$metadata HTTP/1.1`,
        `${T} Connection Info: role=Server, local=s4prd.example.test:44300, peer=10.0.0.8, protocol=HTTPS, SNI=s4prd.example.test`,
        `${T} Reject untrusted forwarded certificate: subject="CN=jane.doe@example.test", issuer="CN=SCC-PRD"`,
        `${T} HttpSrvHdlRequest: method: 1; path: /sap/opu/odata/sap/API_GRMASTERDATA_SRV/$metadata`,
        `${T} HTTP response (raw):`, `${T}   HTTP/1.1 302 Found`, `${T}   date: Tue, 03 Nov 2026 ${u} GMT`, `${T}   sap-authenticated: pending`);
    });
    const mk = (name, text) => ({ name, text, size: text.length, mtime: Date.UTC(2026, 10, 3, 1, 15), src: C.classify(name, text), shiftH: 0 });
    return [mk('example/scc_core.trc', scc.join('\n')), mk('example/PR1_dev_icm.trc', icm.join('\n'))];
  }
  function loadExample() {
    if (TS.embed.on) { TS.embed.ask('example'); return; }   // the cockpit loads it into every tool
    S.files = exampleFiles(); S.skipped = [];
    setStatus('');
    rebuild();
  }

  /* ================= Init ================= */
  function init() {
    if (!$('map')) return;   // loaded without the page (self-test)
    TS.initThemeButton($('btnTheme'));
    buildMap();
    const dz = $('dropzone');
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
    dz.addEventListener('drop', async e => addFiles(await TS.filesFromDrop(e.dataTransfer)));
    document.addEventListener('dragover', e => e.preventDefault());
    document.addEventListener('drop', async e => { if (!dz.contains(e.target)) { e.preventDefault(); addFiles(await TS.filesFromDrop(e.dataTransfer)); } });
    $('btnPickFiles').onclick = () => $('inputFiles').click();
    $('btnPickFolder').onclick = () => $('inputFolder').click();
    $('btnAdd').onclick = () => $('inputFiles').click();
    $('inputFiles').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('inputFolder').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('btnExample').onclick = loadExample;
    $('btnReset').onclick = reset;
    $('btnReport').onclick = () => S.diag && TS.download('sap-landscape-report.md', L.report(S.diag, S.files), 'text/markdown;charset=utf-8');
    $('btnReplay').onclick = () => { if (S.paused) togglePause(); startAnim(); };
    $('btnPause').onclick = togglePause;
    $('btnPause').textContent = S.paused ? 'Play' : 'Pause';
    $('btnPause').setAttribute('aria-pressed', String(S.paused));
    $('optTier').onchange = () => { S.tier = $('optTier').value; if (S.diag) diagnose(false); else renderAll(); };
    $('optFlow').onchange = () => { S.flow = $('optFlow').value; diagnose(false); };
    $('scope').addEventListener('click', e => { const b = e.target.closest('[data-scope]'); if (b) { S.allTime = b.dataset.scope === 'all'; diagnose(false); } });
    $('pathSeg').addEventListener('click', e => { const b = e.target.closest('[data-path]'); if (b) setPath(b.dataset.path); });

    const map = $('map');
    map.addEventListener('click', e => {
      const m = e.target.closest('[data-step]');
      if (m) return select(m.dataset.step);
      const n = e.target.closest('[data-node]'), ly = e.target.closest('[data-layer]');
      if (ly && n && n.dataset.node === 's4-' + curTier()) {
        const s = curPath().steps.find(x => x.def.layer === ly.dataset.layer);
        if (s) return select(s.id);
      }
      if (n) selectNode(n.dataset.node);
    });
    map.addEventListener('keydown', e => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const n = e.target.closest('[data-node]');
      if (n) { e.preventDefault(); selectNode(n.dataset.node); }
    });
    const j = $('journey');
    j.addEventListener('click', e => { const li = e.target.closest('[data-step]'); if (li) select(li.dataset.step); });
    j.addEventListener('keydown', e => {
      const li = e.target.closest('[data-step]');
      if (!li) return;
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(li.dataset.step); $('journey').querySelector(`[data-step="${li.dataset.step}"]`).focus(); }
      else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const sib = e.key === 'ArrowDown' ? li.nextElementSibling : li.previousElementSibling; if (sib) sib.focus(); }
    });
    j.addEventListener('mouseover', e => { const li = e.target.closest('[data-step]'); if (li) highlight(li.dataset.step, true); });
    j.addEventListener('mouseout', e => { const li = e.target.closest('[data-step]'); if (li) highlight(li.dataset.step, false); });
    $('inspector').addEventListener('click', async e => {
      const c = e.target.closest('[data-copy]');
      if (c) { try { await navigator.clipboard.writeText(c.dataset.copy); c.textContent = 'Copied'; } catch (err) { c.textContent = 'Copy failed'; } setTimeout(() => (c.textContent = 'Copy'), 1500); }
      if (e.target.closest('[data-example]')) loadExample();
    });
    slider = TS.createTimeSlider($('timeFilter'), { unit: 1000, fmt: t => TS.fmtTime(t), title: 'Analysis time range (e.g. only after a fix)', onChange(from, to) { S.from = from; S.to = to; diagnose(false); } });
    document.addEventListener('visibilitychange', () => { if (document.hidden) stopAnim(); else if (!S.paused) startAnim(); });
    renderLegend();
    reset();
    if (location.hash === '#example') loadExample();   // shareable demo link: landscape.html#example
    TS.embed.listen({
      files: d => addFiles(TS.embed.toFiles(d.files), true), reset,
      visible: d => { if (!d.on) stopAnim(); else if (!S.paused) startAnim(); }   // no animation while another workspace is shown
    });
  }
  function togglePause() {
    S.paused = !S.paused;
    $('btnPause').textContent = S.paused ? 'Play' : 'Pause';
    $('btnPause').setAttribute('aria-pressed', String(S.paused));
    startAnim();
  }

  TS.landscapeUi = { exampleFiles, replay: () => (A.plan ? { period: A.period, packets: A.plan.length, speed: A.k } : null) };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(window.TS);
