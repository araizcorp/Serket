"use strict";

/* Serket — interfaz simple estilo BloodHound: grafo legible + clic derecho + rutas.
   · Explorar: foco + vecinos directos (1 salto), aristas AGREGADAS con etiqueta.
   · Ruta: al elegir un resultado, el grafo muestra solo esa ruta, izquierda→derecha.
   Bilingüe ES/EN. */

const I18N = {
  es: {
    tagline: "rutas de ataque", search_ph: "Buscar usuario, grupo, equipo…  ( / )",
    classic: "vista clásica", my_accounts: "Mis cuentas", clear: "Limpiar marcas",
    search: "Búsqueda", origin: "Origen", target: "Objetivo", find_paths: "Buscar rutas",
    paths: "Rutas", hops: "saltos", hop1: "salto", activity: "actividad",
    noise_low: "baja", noise_med: "media", noise_high: "alta", cost: "coste",
    all_mine: "todas las mías", tier0: "Tier 0",
    empty_owned: "Ninguna. Clic derecho en un nodo → «Es mía».",
    empty_results: "Marca tus cuentas y pulsa «Buscar rutas».",
    empty_results2: "Sin resultados todavía.",
    menu_owned_add: "✋  Es mía", menu_owned_del: "✖  Quitar «mía»",
    menu_origin: "🎯  Origen desde aquí", menu_target: "🏁  Objetivo: este nodo",
    menu_go: "⚡  Rutas a Tier 0 desde aquí",
    toast_origin: "Origen", toast_target: "Objetivo", toast_focus: "Foco",
    toast_mark_first: "Marca cuentas con clic derecho → «Es mía».",
    toast_found: "rutas encontradas.", toast_none: "Sin rutas hacia el objetivo desde ahí.",
    toast_err: "Error", toast_loading: "Error cargando datos",
    searching: "Buscando…", objects: "objetos", relations: "relaciones",
    no_hits: "sin coincidencias", no_detail: "sin detalle",
    relation: "Relación", owned_badge: "Mía",
    legal_title: "Uso profesional autorizado",
    legal_text: "Serket analiza rutas de ataque de Active Directory. Solo puedes ejecutarlo contra sistemas propios o con autorización escrita y alcance definido.",
    legal_check: "Confirmo que dispongo de autorización escrita y asumo la responsabilidad de su uso.",
    legal_go: "Entrar",
    legend_user: "Usuario", legend_group: "Grupo", legend_computer: "Equipo",
    legend_dc: "DC/Dominio", legend_owned: "Mía",
    legend_controls: "controla", legend_controlled: "le controlan",
    sec_controls: "Controla", sec_controlled: "Lo controlan",
    sec_default_acl: "ACEs por defecto",
    no_relations: "sin relaciones",
    lang_button: "EN",
    explore: "Explorar", route: "Ruta", one_more_hop: "+1 salto", one_less_hop: "−1 salto",
    rel_count: "relaciones",
    node_info: "Información del nodo",
    prop_dn: "DN", prop_guid: "GUID",
    prop_enabled: "Habilitada", prop_disabled: "Deshabilitada",
    prop_pwd: "Pwd cambiada", prop_lastlogon: "Último logon",
    prop_krb: "Kerberoastable", prop_asrep: "AS-REP roastable",
    prop_deleg: "Delegación", prop_spns: "SPNs",
    prop_admincount: "AdminCount", prop_laps: "LAPS legible",
    prop_os: "SO", prop_sens: "Sensibilidad",
    prop_hv: "Alto valor", prop_dc: "DC",
    prop_stale: "Stale", prop_locked: "Bloqueada",
    prop_neverexp: "Nunca expira", prop_notreq: "Pwd no requerida",
    prop_reversible: "Cifrado reversible", prop_protected: "Protected Users",
    prop_missing_pu: "Fuera de Protected Users",
    prop_hv1hop: "HV a 1 salto", prop_out: "Controla", prop_in: "Lo controlan",
    prop_gmsa: "gMSA legible", prop_days: "días",
    prop_hint: "Clic en un nodo para enfocarlo · clic derecho para marcarlo",
    yes: "sí", no: "no",
    prop_findings: "Hallazgos",
    theme_to_dark: "Tema oscuro", theme_to_light: "Tema claro"
  },
  en: {
    tagline: "attack paths", search_ph: "Search user, group, computer…  ( / )",
    classic: "classic view", my_accounts: "My accounts", clear: "Clear marks",
    search: "Search", origin: "Start", target: "Target", find_paths: "Find paths",
    paths: "Paths", hops: "hops", hop1: "hop", activity: "activity",
    noise_low: "low", noise_med: "medium", noise_high: "high", cost: "cost",
    all_mine: "all owned", tier0: "Tier 0",
    empty_owned: "None yet. Right-click a node → \"Owned\".",
    empty_results: "Mark your accounts and hit \"Find paths\".",
    empty_results2: "No results yet.",
    menu_owned_add: "✋  Mark as owned", menu_owned_del: "✖  Unmark owned",
    menu_origin: "🎯  Set as start", menu_target: "🏁  Set as target",
    menu_go: "⚡  Paths to Tier 0 from here",
    toast_origin: "Start", toast_target: "Target", toast_focus: "Focus",
    toast_mark_first: "Mark accounts first (right-click → \"Owned\").",
    toast_found: "paths found.", toast_none: "No paths to the target from there.",
    toast_err: "Error", toast_loading: "Failed to load data",
    searching: "Searching…", objects: "objects", relations: "relationships",
    no_hits: "no matches", no_detail: "no details",
    relation: "Relationship", owned_badge: "Owned",
    legal_title: "Authorized professional use",
    legal_text: "Serket analyzes Active Directory attack paths. Only run it against your own systems or with written authorization and a defined scope.",
    legal_check: "I confirm I have written authorization and accept responsibility for its use.",
    legal_go: "Enter",
    legend_user: "User", legend_group: "Group", legend_computer: "Computer",
    legend_dc: "DC/Domain", legend_owned: "Owned",
    legend_controls: "controls", legend_controlled: "controlled by",
    sec_controls: "Controls", sec_controlled: "Controlled by",
    sec_default_acl: "default ACEs",
    no_relations: "no relations",
    lang_button: "ES",
    explore: "Explore", route: "Path", one_more_hop: "+1 hop", one_less_hop: "−1 hop",
    rel_count: "relationships",
    node_info: "Node info",
    prop_dn: "DN", prop_guid: "GUID",
    prop_enabled: "Enabled", prop_disabled: "Disabled",
    prop_pwd: "Pwd changed", prop_lastlogon: "Last logon",
    prop_krb: "Kerberoastable", prop_asrep: "AS-REP roastable",
    prop_deleg: "Delegation", prop_spns: "SPNs",
    prop_admincount: "AdminCount", prop_laps: "LAPS readable",
    prop_os: "OS", prop_sens: "Sensitivity",
    prop_hv: "High value", prop_dc: "DC",
    prop_stale: "Stale", prop_locked: "Locked out",
    prop_neverexp: "Never expires", prop_notreq: "Pwd not required",
    prop_reversible: "Reversible encryption", prop_protected: "Protected Users",
    prop_missing_pu: "Not in Protected Users",
    prop_hv1hop: "HV 1 hop", prop_out: "Controls", prop_in: "Controlled by",
    prop_gmsa: "gMSA readable", prop_days: "days",
    prop_hint: "Click a node to focus · right-click to mark it",
    yes: "yes", no: "no",
    prop_findings: "Findings",
    theme_to_dark: "Dark theme", theme_to_light: "Light theme"
  }
};

let LANG = localStorage.getItem("serket.lang");
if (!LANG) LANG = (navigator.language || "en").toLowerCase().startsWith("es") ? "es" : "en";
const T = I18N[LANG];
const t = k => T[k] || k;
const otherLang = () => (LANG === "es" ? "en" : "es");

const S = {
  nodes: [], edges: [], nodeMap: new Map(), high: new Set(),
  owned: new Set(JSON.parse(localStorage.getItem("serket.owned.v1") || "[]")),
  origin: null, target: "tier0",
  focus: null,
  results: [], active: -1,
  mode: "neighbors", depth: 1,
  transform: {x: 0, y: 0, k: 1}
};

const $ = id => document.getElementById(id);
const esc = v => String(v == null ? "" : v).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const cssvar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const TYPE_COLOR = {User:"var(--user)", Group:"var(--group)", Computer:"var(--computer)", Workstation:"var(--computer)", Server:"var(--computer)", DomainController:"var(--dc)", Domain:"var(--dc)", CertTemplate:"#5eead4", CA:"#5eead4", GPO:"#94a3b8", OU:"#94a3b8"};
const TYPE_CLASS = {User:"t-user", Group:"t-group", Computer:"t-computer", Workstation:"t-computer", Server:"t-computer", DomainController:"t-dc", Domain:"t-dc", CertTemplate:"t-cert", CA:"t-cert", GPO:"t-obj", OU:"t-obj", Container:"t-obj", Configuration:"t-obj", BuiltinDomain:"t-obj"};
const color = n => TYPE_COLOR[n.type] || "#8a94ab";
const typeClass = n => TYPE_CLASS[n.type] || "t-other";

/* Iconos SVG — glyphs geométricos, trazo afilado 1.5, sin formas infantiles. */
const ICONS = {
  User: '<circle cx="12" cy="7.2" r="3.1"/><path d="M4.8 20c0-4 3.2-6.2 7.2-6.2s7.2 2.2 7.2 6.2"/>',
  Group: '<circle cx="8.2" cy="8" r="2.6"/><circle cx="16" cy="8.6" r="2.2"/><path d="M3.2 19.4c0-3.4 2.2-5.2 5-5.2s5 1.8 5 5.2"/><path d="M14.2 14.7c2.7.2 4.6 1.7 5.1 4.7"/>',
  Computer: '<rect x="3" y="4.5" width="18" height="11.5"/><path d="M9 20h6M12 16v4"/>',
  Server: '<rect x="4" y="3.5" width="16" height="7"/><rect x="4" y="13.5" width="16" height="7"/><rect x="6.4" y="6.1" width="1.6" height="1.6"/><rect x="6.4" y="16.1" width="1.6" height="1.6"/>',
  Dc: '<path d="M3 9.5L12 4l9 5.5"/><path d="M5 9.5V18M9.3 9.5V18M14.7 9.5V18M19 9.5V18"/><path d="M3 20.5h18"/>',
  Cert: '<path d="M12 2.8l7.2 2.6v5.2c0 4.8-3.1 7.9-7.2 9.4-4.1-1.5-7.2-4.6-7.2-9.4V5.4z"/><path d="M8.6 11.6l2.4 2.4 4.4-4.6"/>',
  Folder: '<path d="M3 5.5h6.2l2 2.5H21v11H3z"/>',
  Dot: '<path d="M12 7l5 5-5 5-5-5z"/>'
};
const ICON_FOR = {User:"User", Group:"Group", Computer:"Computer", Workstation:"Computer", Server:"Server", DomainController:"Dc", Domain:"Dc", CertTemplate:"Cert", CA:"Cert", GPO:"Folder", OU:"Folder", Container:"Folder", Configuration:"Folder", BuiltinDomain:"Folder"};
function iconSvg(n, px) {
  const body = ICONS[ICON_FOR[n.type] || "Dot"];
  const half = px / 2;
  return '<svg class="sym-svg" x="-' + half + '" y="-' + half + '" width="' + px + '" height="' + px +
    '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="square" stroke-linejoin="miter">' + body + "</svg>";
}
const noiseClass = s => (Number(s) <= 2 ? "low" : Number(s) === 3 ? "med" : "high");
const noiseName = s => t("noise_" + noiseClass(s));
const isHigh = n => Boolean(n.high_value || n.is_dc || n.type === "Domain");
const eid = v => (v && typeof v === "object" ? String(v.id || "") : String(v || ""));
const persistOwned = () => localStorage.setItem("serket.owned.v1", JSON.stringify(Array.from(S.owned)));
const nodeName = id => { const n = S.nodeMap.get(String(id)); return n ? String(n.name || n.id) : String(id); };

/* Relaciones "de privilegio": se muestran primero al explorar. */
const PRIO = new Set(["MemberOf","GenericAll","GenericWrite","WriteDACL","WriteOwner","AllExtendedRights","Owns","AdminTo","CanRDP","CanPSRemote","ForceChangePassword","AddMember","AddSelf","AddKeyCredentialLink","AddAllowedToAct","Contains","GPLink","TrustedBy","DumpSMSAPassword","ReadLAPSPassword","ReadGMSAPassword","DCSync"]);

let toastTimer = null;
function toast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.style.display = "none"; }, 4200);
}

/* ── i18n chrome ──────────────────────────────────────────────────────── */

function applyLang() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-ph]").forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  $("lang").textContent = t("lang_button");
  renderLegend(); renderChips(); renderResults(); updateScopeButtons();
  if (S.results[S.active]) renderStrip(S.results[S.active]);
  updateMarks();
  renderNodeInfo();
}

$("lang").addEventListener("click", () => {
  LANG = otherLang();
  localStorage.setItem("serket.lang", LANG);
  location.reload();
});

/* ── tema claro / oscuro ─────────────────────────────────────────────── */
function applyTheme() {
  const dark = document.documentElement.dataset.theme === "dark";
  localStorage.setItem("serket.theme", dark ? "dark" : "light");
  const btn = $("theme");
  btn.textContent = dark ? "☀️" : "🌙";
  btn.title = dark ? t("theme_to_light") : t("theme_to_dark");
  const mark = (mid, v) => { const p = document.querySelector("#" + mid + " path"); if (p) p.setAttribute("fill", v); };
  mark("arr", cssvar("--edge")); mark("arr-on", cssvar("--accent")); mark("arr-in", cssvar("--edge-in"));
  renderLegend(); renderGraph();
  if (S.results[S.active]) renderStrip(S.results[S.active]);
}
$("theme").addEventListener("click", () => {
  document.documentElement.dataset.theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme();
});

/* ── panel de información del nodo (clic) ───────────────────────────── */
const TYPE_NAME = {User:"User", Group:"Group", Computer:"Computer", Workstation:"Computer", Server:"Server", DomainController:"Domain Controller", Domain:"Domain", CertTemplate:"Cert Template", CA:"CA", GPO:"GPO", OU:"OU", Container:"Container", Configuration:"Configuration", BuiltinDomain:"Builtin Domain"};
const shortDate = iso => {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? String(iso).slice(0, 10) : d.toISOString().slice(0, 10);
};

function renderNodeInfo() {
  const box = $("ninfo");
  if (!box) return;
  const id = S.focus;
  const n = (id && S.nodeMap.get(id)) || null;
  if (!n) { box.innerHTML = '<span class="empty">' + esc(t("empty_results2")) + "</span>"; return; }
  const col = color(n);
  const isDC = Boolean(n.is_dc || n.type === "Domain" || n.type === "DomainController");
  const flags = [];
  const F = (cls, label) => flags.push('<span class="' + cls + '">' + esc(label) + "</span>");
  if (isHigh(n)) F("", t("prop_hv"));
  if (isDC) F("", t("prop_dc"));
  if (S.owned.has(id)) F("", t("owned_badge"));
  if (n.enabled === false) F("bad", t("prop_disabled"));
  if (n.locked_out) F("warn", t("prop_locked"));
  if (n.stale) F("warn", t("prop_stale"));
  if (n.kerberoastable) F("warn", t("prop_krb"));
  if (n.asreproastable) F("bad", t("prop_asrep"));
  if (n.delegation_mode && n.delegation_mode !== "none") F("warn", t("prop_deleg") + ": " + n.delegation_mode);
  if (n.pwd_never_expires) F("warn", t("prop_neverexp"));
  if (n.pwd_not_required) F("bad", t("prop_notreq"));
  if (n.reversible_encryption) F("bad", t("prop_reversible"));
  if (n.gmsa_password_readable) F("bad", t("prop_gmsa"));
  if (n.missing_protected_users) F("warn", t("prop_missing_pu"));
  if (n.protected_user) F("", t("prop_protected"));

  const out = edgesOut(id), inn = edgesIn(id);
  const hv1 = out.filter(x => S.high.has(x.other)).length + inn.filter(x => S.high.has(x.other)).length;

  const row = (k, v) => '<div class="ni-row"><span>' + esc(k) + '</span><b>' + esc(v) + "</b></div>";
  let rows = "";
  rows += row(t("prop_dn"), n.dn || "—");
  rows += row(t("prop_guid"), n.guid || String(id));
  rows += row(t("prop_enabled"), n.enabled === false ? t("no") : t("yes"));
  if (n.pwd_last_set) rows += row(t("prop_pwd"), shortDate(n.pwd_last_set) + "  ·  " + (n.pwd_age_days != null ? n.pwd_age_days + " " + t("prop_days") : "—"));
  if (n.last_logon) rows += row(t("prop_lastlogon"), shortDate(n.last_logon) + (n.last_logon_age_days != null ? "  ·  " + n.last_logon_age_days + " " + t("prop_days") : ""));
  if (n.delegation_mode && n.delegation_mode !== "none") rows += row(t("prop_deleg"), n.delegation_mode);
  if (Array.isArray(n.spns) && n.spns.length) rows += row(t("prop_spns"), n.spns.length + "  ·  " + n.spns.slice(0, 2).join(", ") + (n.spns.length > 2 ? "…" : ""));
  if (n.admin_count) rows += row(t("prop_admincount"), String(n.admin_count));
  if (n.laps_readable) rows += row(t("prop_laps"), t("yes"));
  if (n.os_display) rows += row(t("prop_os"), n.os_display);
  if (n.sensitivity && n.sensitivity !== "none") rows += row(t("prop_sens"), n.sensitivity);
  (n.findings || []).forEach(f => {
    const label = typeof f === "string" ? f
      : [f.badge || f.title || f.id || f.name, f.severity].filter(Boolean).join(" · ");
    if (label) rows += row(t("prop_findings"), label);
  });

  box.innerHTML =
    '<div class="ni-head"><span class="ni-ico" style="--nc:' + col + '">' + iconSvg(n, 19) + "</span>" +
      "<div><b>" + esc(n.name || id) + "</b><small>" + esc(TYPE_NAME[n.type] || n.type || "Object") + "</small></div></div>" +
    (flags.length ? '<div class="ni-flags">' + flags.join("") + "</div>" : "") +
    '<div class="ni-stats">' +
      "<div><b>" + out.length + "</b><span>" + esc(t("prop_out")) + "</span></div>" +
      "<div><b>" + inn.length + "</b><span>" + esc(t("prop_in")) + "</span></div>" +
      "<div><b>" + hv1 + "</b><span>" + esc(t("prop_hv1hop")) + "</span></div></div>" +
    rows +
    '<div class="ni-hint">' + esc(t("prop_hint")) + "</div>";
}

function renderLegend() {
  $("legend").innerHTML =
    '<span><i style="background:var(--user)"></i>' + esc(t("legend_user")) + "</span>" +
    '<span><i style="background:var(--group)"></i>' + esc(t("legend_group")) + "</span>" +
    '<span><i style="background:var(--computer)"></i>' + esc(t("legend_computer")) + "</span>" +
    '<span><i style="background:var(--dc)"></i>' + esc(t("legend_dc")) + "</span>" +
    '<span><i style="background:var(--accent)"></i>' + esc(t("legend_owned")) + "</span>" +
    '<span><i class="li-line"></i>' + esc(t("legend_controls")) + "</span>" +
    '<span><i class="li-line dash"></i>' + esc(t("legend_controlled")) + "</span>";
}

/* ── data ─────────────────────────────────────────────────────────────── */

async function init() {
  const [domain, graph] = await Promise.all([
    fetch("/api/domain").then(r => r.json()),
    fetch("/api/graph").then(r => r.json())
  ]);
  S.nodes = graph.nodes || [];
  S.edges = (graph.edges || []).filter(e => e.traversable !== false);
  S.nodeMap = new Map(S.nodes.map(n => [String(n.id), n]));
  S.nodes.forEach(n => { if (isHigh(n)) S.high.add(String(n.id)); });
  $("domain").innerHTML = "<b>" + esc(domain.name || domain.dns_root || "domain") + "</b> · " +
    S.nodes.length + " " + t("objects") + " · " + S.edges.length + " " + t("relations");
  const start = S.nodes.find(n => n.type === "Domain") || S.nodes[0];
  focusNode(start ? String(start.id) : null, false);
}

/* ── graph: dos modos legibles ────────────────────────────────────────── */

/* Aristas en ambas direcciones: salientes (foco → controla) y entrantes
   (lo controlan). Se distinguen visualmente: sólida vs punteada. */
function edgesOut(id) {
  const out = [];
  for (const e of S.edges) {
    if (eid(e.source) === id) out.push({other: eid(e.target), edge: e});
  }
  return out;
}
function edgesIn(id) {
  const out = [];
  for (const e of S.edges) {
    if (eid(e.target) === id) out.push({other: eid(e.source), edge: e});
  }
  return out;
}

function focusNode(id, announce = true) {
  if (!id || !S.nodeMap.has(String(id))) return;
  S.focus = String(id);
  S.mode = "neighbors";
  updateScopeButtons();
  renderGraph();
  renderNodeInfo();
  if (announce) {
    const rel = edgesOut(S.focus).length + edgesIn(S.focus).length;
    toast(t("toast_focus") + ": " + nodeName(id) + (rel ? "" : " · " + t("no_relations")));
  }
}

/* Grupos protegidos por defecto: tienen ACL sobre TODOS los objetos del
   dominio. Mostrarlos en cada nodo es ruido (Domain Admins controla todo),
   así que en «Lo controlan» se ocultan salvo que no quede otra cosa. */
const DEFAULT_CTRL = new Set([
  "administrators", "domain admins", "enterprise admins", "system", "account operators",
  "cert publishers", "terminal server license servers", "creator owner", "self",
  "backup operators", "print operators", "everyone", "authenticated users",
  "anonymous logon", "pre-windows 2000 compatible access", "windows authorization access group",
  "domain controllers", "schema admins", "group policy creators owners"
]);
const isDefaultCtrl = id => {
  const n = S.nodeMap.get(String(id));
  const nm = String(n && n.name || "").trim().toLowerCase();
  return DEFAULT_CTRL.has(nm) || /^s-1-5-32-54[49]$/.test(nm) || nm === "s-1-5-18" || nm === "s-1-5-32-544";
};

/* Explorar: foco a la izquierda; a la derecha lo que CONTROLAS (aristas
   sólidas) y, más a la derecha en columna punteada, QUIÉN TE CONTROLA
   (filtrando los ACEs por defecto, que están en todos los objetos). */
function stageSize() {
  const r = $("graph").getBoundingClientRect();
  return {w: Math.max(320, r.width || 1280), h: Math.max(360, r.height || 800)};
}

const OUT_CAP = 16, IN_CAP = 8;

function neighborScope(w, h) {
  const mk = (list, dir) => {
    const seen = new Map();
    for (const {other, edge} of list) {
      const prio = PRIO.has(edge.type) ? 0 : 1;
      const opsec = Number(edge.opsec_score || 5);
      const cur = seen.get(other);
      if (!cur || prio < cur.prio || (prio === cur.prio && opsec < cur.opsec))
        seen.set(other, {id: other, dir, prio, opsec});
    }
    return Array.from(seen.values())
      .sort((a, b) => a.prio - b.prio || a.opsec - b.opsec || nodeName(a.id).localeCompare(nodeName(b.id)));
  };
  const outs = mk(edgesOut(S.focus), "out").slice(0, OUT_CAP);
  const allIns = mk(edgesIn(S.focus), "in");
  let ins = allIns.filter(x => !isDefaultCtrl(x.id)).slice(0, IN_CAP);
  let nInHidden = allIns.length - ins.length;
  if (!ins.length) { ins = allIns.slice(0, IN_CAP); nInHidden = 0; } // todo era por defecto: mejor mostrarlo

  const pos = new Map();
  pos.set(S.focus, {x: Math.round(w * 0.13), y: Math.round(h / 2)});

  const ROWS = Math.max(3, Math.min(8, Math.floor((h - 160) / 105)));
  const outCols = Math.max(1, Math.ceil(outs.length / ROWS));
  const outEnd = ins.length ? w * 0.76 : w * 0.9;
  const outW = outs.length ? Math.max(200, Math.min(300, (outEnd - w * 0.36) / outCols)) : 0;
  outs.forEach((it, i) => {
    const c = Math.floor(i / ROWS), r = i % ROWS;
    const colCount = Math.min(ROWS, outs.length - c * ROWS);
    const gap = Math.min(108, (h - 160) / Math.max(1, colCount));
    pos.set(it.id, {x: Math.round(w * 0.36) + c * outW, y: Math.round(h / 2 - ((colCount - 1) * gap) / 2 + r * gap)});
  });

  const iGap = Math.min(104, (h - 160) / Math.max(1, ins.length));
  ins.forEach((it, i) => {
    pos.set(it.id, {x: Math.round(w * 0.86), y: Math.round(h / 2 - ((ins.length - 1) * iGap) / 2 + i * iGap)});
  });

  const ids = new Set([S.focus, ...outs.map(o => o.id), ...ins.map(x => x.id)]);
  return {ids, pos, star: true, nOut: outs.length, nIn: ins.length, nInHidden};
}

const _nbCache = new Map();

/* Ruta: solo los nodos de la ruta activa, en orden. */
function pathScope(w, h) {
  const p = S.results[S.active];
  if (!p) return null;
  const steps = p.steps || [];
  const ids = [String(p.src)];
  steps.forEach(st => ids.push(String(st.tgt)));
  const pos = new Map();
  const span = Math.min(260, (w * 0.8) / Math.max(1, ids.length - 1));
  const x0 = Math.max(90, (w - span * (ids.length - 1)) / 2);
  ids.forEach((id, i) => pos.set(id, {x: Math.round(x0 + i * span), y: Math.round(h / 2)}));
  return {ids: new Set(ids), pos};
}

/* Agrega aristas paralelas entre el mismo par: una curva + etiqueta.
   En modo estrella solo se dibujan las aristas que tocan el foco. */
function aggregateEdges(ids, star) {
  const map = new Map();
  for (const e of S.edges) {
    const s = eid(e.source), tg = eid(e.target);
    if (!ids.has(s) || !ids.has(tg) || s === tg) continue;
    if (star && s !== S.focus && tg !== S.focus) continue;
    const key = s < tg ? s + "|" + tg : tg + "|" + s;
    if (!map.has(key)) map.set(key, {a: s < tg ? s : tg, b: s < tg ? tg : s, types: [], best: e, count: 0, hasOut: false, hasIn: false});
    const agg = map.get(key);
    if (star) { if (s === S.focus) agg.hasOut = true; else agg.hasIn = true; }
    agg.count += 1;
    agg.types.push(e.type || t("relation"));
    if (Number(e.opsec_score || 5) < Number(agg.best.opsec_score || 5)) agg.best = e;
  }
  return Array.from(map.values());
}

function renderGraph() {
  const vp = $("vp");
  const {w, h} = stageSize();
  $("graph").setAttribute("viewBox", "0 0 " + w + " " + h);
  const scope = S.mode === "path" ? pathScope(w, h) : neighborScope(w, h);
  if (!scope) { vp.innerHTML = ""; return; }
  const {ids, pos} = scope;
  const activePairs = S.mode === "path"
    ? new Set((S.results[S.active].steps || []).map(st => String(st.src) + "|" + String(st.tgt)))
    : new Set();

  let html = '<g class="edges">';
  for (const agg of aggregateEdges(ids, Boolean(scope.star))) {
    const a = pos.get(agg.a), b = pos.get(agg.b);
    if (!a || !b) continue;
    const on = activePairs.has(agg.a + "|" + agg.b) || activePairs.has(agg.b + "|" + agg.a);
    const horizontal = Math.abs(b.y - a.y) < 8;
    const bend = horizontal ? 0 : Math.max(46, Math.abs(b.x - a.x) * 0.42);
    const midX = (a.x + b.x) / 2;
    const midY = (a.y + b.y) / 2 - (horizontal ? 0 : 14);
    const d = horizontal
      ? "M" + (a.x + 22) + "," + a.y + " L" + (b.x - 22) + "," + b.y
      : "M" + a.x + "," + a.y + " C" + (a.x + bend) + "," + a.y + " " + (b.x - bend) + "," + b.y + " " + b.x + "," + b.y;
    const label = agg.types[0] + (agg.count > 1 ? " ×" + agg.count : "");
    const inOnly = Boolean(scope.star) && agg.hasIn && !agg.hasOut;
    const stroke = inOnly ? "var(--edge-in)" : (on ? "var(--accent)" : "var(--edge)");
    const dash = inOnly ? ' stroke-dasharray="6 5"' : "";
    const marker = on ? "#arr-on" : (inOnly ? "#arr-in" : "#arr");
    html += '<path d="' + d + '" fill="none"' + dash + ' style="stroke:' + stroke + '" stroke-width="' + (on ? 2.6 : (inOnly ? 1.3 : 1.7)) +
      '" marker-end="url(' + marker + ')" opacity="' + (on ? 1 : (inOnly ? 0.6 : 0.85)) + '"><title>' + esc(agg.types.join(", ")) + '</title></path>';
    /* etiqueta con pastilla de fondo para que se lea siempre */
    const tw = label.length * 5.9 + 10;
    html += '<rect x="' + (midX - tw / 2) + '" y="' + (midY - 8.5) + '" width="' + tw + '" height="13" rx="6.5" style="fill:var(--pill);stroke:var(--pill-border)" stroke-width="0.7"></rect>' +
      '<text x="' + midX + '" y="' + (midY + 2.5) + '" text-anchor="middle" font-size="10" style="fill:' + (inOnly ? "var(--faint)" : "var(--dim)") + '" class="edge-lbl">' + esc(label) + "</text>";
  }
  if (scope.star) {
    const cap = (s, x, anchor) => '<text x="' + x + '" y="30"' + (anchor ? ' text-anchor="' + anchor + '"' : "") + ' font-size="9.5" font-weight="700" letter-spacing="2.5" style="fill:var(--faint)" class="edge-lbl">' + esc(s.toUpperCase()) + "</text>";
    if (scope.nOut) html += cap(t("sec_controls"), Math.round(w * 0.36), "");
    if (scope.nIn) html += cap(t("sec_controlled") + " · " + scope.nIn + (scope.nInHidden ? "  (+" + scope.nInHidden + " " + t("sec_default_acl") + ")" : ""), Math.round(w * 0.86), "middle");
  }
  html += '</g><g class="nodes">';
  ids.forEach(id => {
    const n = S.nodeMap.get(id);
    const p = pos.get(id);
    if (!n || !p) return;
    const cls = ["gnode", typeClass(n),
      S.owned.has(id) ? "owned" : "",
      S.origin === id ? "origin" : "",
      S.target === id ? "target" : "",
      isHigh(n) ? "high" : ""].join(" ");
    const col = color(n);
    const lbl = String(n.name || id);
    html += '<g class="' + cls + '" data-id="' + esc(id) + '" transform="translate(' + p.x + ' ' + p.y + ')">' +
      '<circle r="25" class="halo"></circle><circle r="21" class="glow" style="stroke:' + col + '"></circle>' +
      '<circle r="17" class="body" style="stroke:' + col + '"></circle>' +
      '<g class="sym" style="color:' + col + '">' + iconSvg(n, 17) + "</g>" +
      '<text class="lbl" y="41">' + esc(lbl.length > 26 ? lbl.slice(0, 24) + "…" : lbl) + "</text>" +
      (S.owned.has(id) ? '<circle class="own" cx="14" cy="-14" r="7"><title>' + esc(t("owned_badge")) + '</title></circle>' : "") +
      "</g>";
  });
  html += "</g>";
  vp.innerHTML = html;
  applyTransform();
}

function applyTransform() {
  const tr = S.transform;
  $("vp").setAttribute("transform", "translate(" + tr.x + " " + tr.y + ") scale(" + tr.k + ")");
}

/* pan & zoom */
(function () {
  const svg = $("graph");
  let pan = null;
  svg.addEventListener("pointerdown", ev => {
    if (ev.target.closest(".gnode")) return;
    pan = {x: ev.clientX, y: ev.clientY, tx: S.transform.x, ty: S.transform.y};
    svg.classList.add("panning");
    svg.setPointerCapture(ev.pointerId);
  });
  svg.addEventListener("pointermove", ev => {
    if (!pan) return;
    S.transform.x = pan.tx + (ev.clientX - pan.x);
    S.transform.y = pan.ty + (ev.clientY - pan.y);
    applyTransform();
  });
  const end = () => { pan = null; svg.classList.remove("panning"); };
  svg.addEventListener("pointerup", end);
  svg.addEventListener("pointercancel", end);
  svg.addEventListener("wheel", ev => {
    ev.preventDefault();
    S.transform.k = Math.min(2.6, Math.max(0.25, S.transform.k * Math.exp(-ev.deltaY * 0.0012)));
    applyTransform();
  }, {passive: false});
})();

/* scope buttons */
function updateScopeButtons() {
  $("m-neigh").classList.toggle("on", S.mode === "neighbors");
  $("m-path").classList.toggle("on", S.mode === "path");
  $("m-path").style.display = S.results.length ? "" : "none";
  $("d-toggle").style.display = "none";
}
$("m-neigh").addEventListener("click", () => { S.mode = "neighbors"; updateScopeButtons(); renderGraph(); });
$("m-path").addEventListener("click", () => { if (S.results.length) { S.mode = "path"; updateScopeButtons(); renderGraph(); } });

/* ── context menu ─────────────────────────────────────────────────────── */

const menu = $("menu");
let menuId = null;

function openMenu(id, x, y) {
  menuId = String(id);
  const n = S.nodeMap.get(menuId) || {};
  menu.innerHTML =
    '<div class="mh"><span>' + esc(n.type || "Object") + '</span><b>' + esc(n.name || menuId) + "</b></div>" +
    '<button data-act="owned">' + esc(S.owned.has(menuId) ? t("menu_owned_del") : t("menu_owned_add")) + "</button>" +
    '<button data-act="origin">' + esc(t("menu_origin")) + "</button>" +
    '<button data-act="target">' + esc(t("menu_target")) + "</button>" +
    '<button data-act="go">' + esc(t("menu_go")) + "</button>";
  menu.classList.add("open");
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, innerWidth - r.width - 8) + "px";
  menu.style.top = Math.min(y, innerHeight - r.height - 8) + "px";
}
function closeMenu() { menu.classList.remove("open"); menuId = null; }

menu.addEventListener("click", ev => {
  const b = ev.target.closest("button[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  const id = menuId;
  closeMenu();
  if (act === "owned") toggleOwned(id);
  if (act === "origin") { S.origin = id; updateMarks(); toast(t("toast_origin") + ": " + nodeName(id)); }
  if (act === "target") { S.target = id; updateMarks(); toast(t("toast_target") + ": " + nodeName(id)); }
  if (act === "go") { S.origin = id; S.target = "tier0"; updateMarks(); runSearch([id], "tier0"); }
});

document.addEventListener("contextmenu", ev => {
  const g = ev.target.closest && ev.target.closest(".gnode");
  if (!g) { closeMenu(); return; }
  ev.preventDefault();
  openMenu(g.dataset.id, ev.clientX, ev.clientY);
}, true);
document.addEventListener("click", ev => {
  if (menu.classList.contains("open") && !menu.contains(ev.target)) closeMenu();
}, true);
document.addEventListener("keydown", ev => { if (ev.key === "Escape") closeMenu(); });

$("graph").addEventListener("click", ev => {
  const g = ev.target.closest && ev.target.closest(".gnode");
  if (g) focusNode(g.dataset.id);
});
$("graph").addEventListener("dblclick", ev => {
  const g = ev.target.closest && ev.target.closest(".gnode");
  if (!g) return;
  ev.preventDefault();
  const id = g.dataset.id;
  S.origin = id; S.target = "tier0"; updateMarks();
  runSearch([id], "tier0");
});

/* ── owned / marks ────────────────────────────────────────────────────── */

function toggleOwned(id) {
  id = String(id);
  if (S.owned.has(id)) S.owned.delete(id);
  else S.owned.add(id);
  persistOwned();
  renderChips();
  renderGraph();
}

function renderChips() {
  const box = $("chips");
  $("owned-count").textContent = S.owned.size || "";
  box.innerHTML = S.owned.size
    ? Array.from(S.owned).map(id =>
        '<span class="chip" data-id="' + esc(id) + '"><i>' + esc(nodeName(id)) + '</i><b>×</b></span>').join("")
    : '<span class="empty">' + esc(t("empty_owned")) + "</span>";
  box.querySelectorAll(".chip i").forEach(el => el.addEventListener("click", () => focusNode(el.parentElement.dataset.id)));
  box.querySelectorAll(".chip b").forEach(el => el.addEventListener("click", () => toggleOwned(el.parentElement.dataset.id)));
  updateMarks();
}

function updateMarks() {
  $("m-origin").textContent = S.origin ? nodeName(S.origin) : t("all_mine");
  $("m-target").textContent = S.target === "tier0" ? t("tier0") : nodeName(S.target);
  renderGraph();
}

$("clear-owned").addEventListener("click", () => {
  S.owned.clear(); S.origin = null; S.target = "tier0";
  persistOwned(); renderChips(); updateMarks();
});

/* ── search ───────────────────────────────────────────────────────────── */

async function runSearch(sources, target) {
  sources = (sources || []).map(String).filter(Boolean);
  if (!sources.length) { toast(t("toast_mark_first")); return; }
  const btn = $("search");
  btn.disabled = true; btn.textContent = t("searching");
  try {
    const r = await fetch("/api/query-paths", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({sources, target: target || "tier0", max_hops: "all", include_edge: "all", limit: 50})
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.detail || ("HTTP " + r.status));
    S.results = body.paths || [];
    S.active = S.results.length ? 0 : -1;
    renderResults();
    if (S.results.length) {
      S.mode = "path";
      updateScopeButtons();
      selectResult(0);
      toast(S.results.length + " " + t("toast_found"));
    } else {
      closeStrip(); toast(t("toast_none"));
    }
  } catch (err) {
    toast(t("toast_err") + ": " + err.message);
  } finally {
    btn.disabled = false; btn.textContent = t("find_paths");
  }
}

$("search").addEventListener("click", () => {
  const sources = S.origin ? [S.origin] : Array.from(S.owned);
  runSearch(sources, S.target);
});

function renderResults() {
  const box = $("results");
  $("res-count").textContent = S.results.length || "";
  if (!S.results.length) {
    box.innerHTML = '<span class="empty">' + esc(S.owned.size ? t("empty_results2") : t("empty_results")) + "</span>";
    return;
  }
  box.innerHTML = S.results.map((p, i) =>
    '<button class="result' + (i === S.active ? " active" : "") + '" data-i="' + i + '">' +
    '<span class="r1"><span>' + esc(p.src_name) + " → " + esc(p.target_name) + '</span><span>' + p.hops + " " + (p.hops === 1 ? t("hop1") : t("hops")) + "</span></span>" +
    '<span class="r2"><span class="n ' + noiseClass(p.noise) + '"></span>' + esc(t("activity")) + " " + noiseName(p.noise) + " · " + esc(t("cost")) + " " + esc(p.cost) + "</span></button>"
  ).join("");
  box.querySelectorAll(".result").forEach(b => b.addEventListener("click", () => selectResult(Number(b.dataset.i))));
}

function selectResult(i) {
  S.active = i;
  renderResults();
  renderStrip(S.results[i]);
  S.mode = "path";
  updateScopeButtons();
  renderGraph();
}

/* ── path strip ───────────────────────────────────────────────────────── */

function renderStrip(p) {
  if (!p) return closeStrip();
  const steps = p.steps || [];
  const nodes = [{id: p.src, name: p.src_name, type: p.src_type}];
  steps.forEach(st => nodes.push({id: st.tgt, name: st.tgt_name, type: st.tgt_type}));
  const W = Math.max(720, 140 * 2 + (nodes.length - 1) * 225);
  $("spath").setAttribute("viewBox", "0 0 " + W + " 175");
  let html = "";
  const y = 82;
  nodes.forEach((n, i) => {
    const x = 140 + i * 225;
    const full = S.nodeMap.get(String(n.id)) || {id: n.id, name: n.name, type: n.type};
    const col = color(full);
    if (i < steps.length) {
      const st = steps[i];
      html += '<g class="sstep" data-i="' + i + '" style="cursor:pointer">' +
        '<line x1="' + (x + 44) + '" y1="' + y + '" x2="' + (x + 181) + '" y2="' + y + '" style="stroke:var(--edge)" stroke-width="2" marker-end="url(#arr)"></line>' +
        '<text x="' + (x + 112) + '" y="' + (y - 14) + '" text-anchor="middle" style="fill:var(--faint)" font-size="10.5">' + esc(st.edge_type || t("relation")) + "</text></g>";
    }
    html += '<g class="snode ' + typeClass(full) + '" data-id="' + esc(n.id) + '" style="cursor:pointer">' +
      (S.owned.has(String(n.id)) ? '<circle cx="' + x + '" cy="' + y + '" r="41" fill="none" style="stroke:var(--accent)" stroke-width="2"></circle>' : "") +
      '<g transform="translate(' + x + ' ' + y + ')" style="color:' + col + '">' +
      '<circle class="body2" r="31" style="stroke:' + col + '" stroke-width="2.5"></circle>' +
      iconSvg(full, 30) + "</g>" +
      '<text class="nm" x="' + x + '" y="' + (y + 56) + '" text-anchor="middle" font-size="11.5" font-weight="600">' + esc(String(n.name || n.id).length > 20 ? String(n.name || n.id).slice(0, 18) + "…" : String(n.name || n.id)) + "</text></g>";
  });
  $("spath").innerHTML = html;
  $("stitle").textContent = (p.src_name || p.src) + " → " + (p.target_name || p.target);
  $("smeta").textContent = p.hops + " " + (p.hops === 1 ? t("hop1") : t("hops")) + " · " + t("activity") + " " + noiseName(p.noise);
  $("sdetail").textContent = "";
  $("spath").querySelectorAll(".sstep").forEach(g => g.addEventListener("click", () => {
    const st = steps[Number(g.dataset.i)];
    $("sdetail").innerHTML = "<b>" + esc(st.edge_type) + "</b> · " + esc(st.detail || t("no_detail")) +
      (st.mitre && st.mitre.id ? " · MITRE " + esc(st.mitre.id) : "");
  }));
  $("spath").querySelectorAll(".snode").forEach(g => g.addEventListener("click", () => focusNode(g.dataset.id)));
  $("strip").classList.add("open");
  $("sprev").disabled = S.active <= 0;
  $("snext").disabled = S.active >= S.results.length - 1;
}

function closeStrip() { $("strip").classList.remove("open"); }
$("sclose").addEventListener("click", closeStrip);
$("sprev").addEventListener("click", () => { if (S.active > 0) selectResult(S.active - 1); });
$("snext").addEventListener("click", () => { if (S.active < S.results.length - 1) selectResult(S.active + 1); });

/* ── search box ───────────────────────────────────────────────────────── */

const q = $("q"), qdrop = $("qdrop");
q.addEventListener("input", () => {
  const v = q.value.trim().toLowerCase();
  if (v.length < 2) { qdrop.style.display = "none"; return; }
  const hits = S.nodes
    .filter(n => String(n.name || "").toLowerCase().includes(v) || String(n.id).toLowerCase().includes(v))
    .slice(0, 12);
  qdrop.innerHTML = hits.length
    ? hits.map(n => '<div data-id="' + esc(n.id) + '"><span>' + esc(n.name || n.id) + '</span><span class="t">' + esc(n.type || "") + "</span></div>").join("")
    : '<div><span class="t">' + esc(t("no_hits")) + "</span></div>";
  qdrop.style.display = "block";
  qdrop.querySelectorAll("div[data-id]").forEach(el => el.addEventListener("click", () => {
    focusNode(el.dataset.id);
    qdrop.style.display = "none";
    q.value = nodeName(el.dataset.id);
  }));
});
document.addEventListener("click", ev => { if (!ev.target.closest(".search")) qdrop.style.display = "none"; });
document.addEventListener("keydown", ev => {
  if (ev.key === "/" && document.activeElement !== q) { ev.preventDefault(); q.focus(); }
});
window.addEventListener("resize", () => { if (S.focus) renderGraph(); });

/* ── legal gate & boot ────────────────────────────────────────────────── */

$("legal-ok").addEventListener("change", ev => { $("legal-go").disabled = !ev.target.checked; });
$("legal-go").addEventListener("click", () => { $("legal").hidden = true; });

applyLang();
applyTheme();
init().catch(err => toast(t("toast_loading") + ": " + err.message));
