"use strict";

const state = {
  domain: {},
  stats: {},
  paths: [],
  surface: {},
  graph: {nodes: [], edges: [], available: false},
  meta: {},
  adcs: {},
  trusts: [],
  findings: [],
  riskSummary: {},
  findingsByObject: new Map(),
  nodeMap: new Map(),
  searchNodes: [],
  incoming: new Map(),
  outgoing: new Map(),
  highValue: new Set(),
  filteredPaths: [],
  activePathIndex: -1,
  activeView: "overview",
  selectedNodeId: null,
  explorerFocusId: null,
  explorerHistory: [],
  selectedEdge: null,
  inspectorKind: null,
  inspectorTab: "evidence",
  query: {source: "all", target: "tier0", maxHops: "all", edge: "all"},
  graphOptions: {scope: "relevant", type: "all", edge: "all", limit: 120},
  graphDrawn: false,
  visibleNodes: new Map(),
  visibleEdges: [],
  transform: {x: 0, y: 0, k: 1},
  drag: null,
  searchCursor: -1,
  lastCommand: ""
};

let EDGE_CATALOG = {
  MemberOf: {
    impact: "La identidad hereda las capacidades concedidas al grupo. La relevancia depende de los permisos que el grupo tenga después en la ruta.",
    telemetry: "Cambios de membresía pueden producir eventos de administración de grupos; el uso posterior de los privilegios genera señales diferentes.",
    prerequisites: "La cobertura depende de la auditoría de administración de cuentas y de la conservación de eventos en los controladores adecuados.",
    remediation: "Retirar membresías innecesarias, utilizar grupos por función y revisar periódicamente grupos anidados y privilegiados."
  },
  GenericAll: {
    impact: "Control amplio sobre el objeto de destino. Las acciones posibles dependen de si el destino es una cuenta, grupo, equipo u objeto del dominio.",
    telemetry: "Una validación puede modificar atributos, credenciales o membresías. Las señales exactas dependen de la operación y de las SACL configuradas.",
    prerequisites: "Auditoría de cambios del servicio de directorio, SACL sobre el objeto relevante y correlación de identidad, origen y controlador.",
    remediation: "Eliminar la ACE amplia, sustituirla por derechos mínimos y revisar si fue heredada desde una unidad organizativa."
  },
  GenericWrite: {
    impact: "Permite modificar un subconjunto amplio de atributos del objeto y puede habilitar relaciones adicionales según su tipo.",
    telemetry: "Se esperan cambios de atributos del directorio cuando la validación escribe sobre el objeto; la visibilidad requiere auditoría y SACL apropiadas.",
    prerequisites: "Auditoría de cambios de directorio y recogida de los eventos del controlador que procesó la modificación.",
    remediation: "Restringir escritura a atributos concretos y separar funciones administrativas mediante grupos dedicados."
  },
  WriteDACL: {
    impact: "Permite cambiar la lista de control de acceso y conceder nuevas capacidades sobre el objeto.",
    telemetry: "Una validación implica modificar el descriptor de seguridad. Debe correlacionarse el objeto, la identidad y la ACE añadida o retirada.",
    prerequisites: "Auditoría del servicio de directorio, SACL relevante y conservación del detalle del cambio.",
    remediation: "Retirar delegaciones de modificación de DACL no justificadas y proteger objetos de alta criticidad frente a herencia accidental."
  },
  WriteOwner: {
    impact: "El control de propietario puede permitir posteriormente alterar permisos sobre el objeto.",
    telemetry: "La toma de propiedad y un cambio posterior de DACL son operaciones distintas y deben correlacionarse.",
    prerequisites: "Auditoría de cambios del descriptor de seguridad y una ventana de correlación suficiente.",
    remediation: "Limitar el derecho de cambiar propietario y revisar propietarios anómalos en objetos privilegiados."
  },
  ForceChangePassword: {
    impact: "Permite restablecer la credencial de la cuenta de destino sin conocer la contraseña anterior.",
    telemetry: "El restablecimiento puede generar eventos de administración de cuentas. La autenticación posterior debe analizarse como una actividad separada.",
    prerequisites: "Auditoría de gestión de cuentas, identidad de origen y eventos de autenticación posteriores.",
    remediation: "Retirar el derecho extendido cuando no sea necesario y delegar restablecimientos únicamente a grupos operativos controlados."
  },
  AddMember: {
    impact: "Permite añadir identidades al grupo de destino y heredar sus capacidades.",
    telemetry: "Los cambios de membresía deberían registrarse si la auditoría de administración de grupos está habilitada.",
    prerequisites: "Recogida de eventos de gestión de grupos y resolución correcta de los SID implicados.",
    remediation: "Restringir quién puede modificar el grupo, utilizar flujos de aprobación y alertar especialmente sobre grupos Tier 0."
  },
  AddSelf: {
    impact: "La identidad puede añadirse a sí misma al grupo y obtener las capacidades que este conceda.",
    telemetry: "El cambio de membresía es el punto principal de observación; el uso posterior de privilegios debe correlacionarse.",
    prerequisites: "Auditoría de gestión de grupos y conservación del miembro añadido y el actor.",
    remediation: "Eliminar la escritura validada AddSelf salvo en flujos expresamente diseñados y revisados."
  },
  AllExtendedRights: {
    impact: "Agrupa derechos extendidos cuyo efecto depende del objeto, incluyendo operaciones sensibles sobre cuentas o el dominio.",
    telemetry: "La señal depende del derecho concreto utilizado. Serket no presupone una acción específica solo por observar esta ACE.",
    prerequisites: "Catálogo de GUID de derechos extendidos, SACL aplicable y telemetría de la operación realizada.",
    remediation: "Sustituir AllExtendedRights por derechos concretos y documentar la finalidad de cada delegación."
  },
  DCSync: {
    impact: "Capacidad para solicitar replicación de secretos del directorio cuando los derechos necesarios son realmente utilizables.",
    telemetry: "La validación utiliza operaciones de replicación y debe distinguirse de controladores y servicios autorizados.",
    prerequisites: "Auditoría de acceso al directorio, inventario de replicadores legítimos y correlación con la identidad y el origen de red.",
    remediation: "Limitar los derechos de replicación a controladores y servicios estrictamente necesarios; rotar credenciales si hubo uso no autorizado."
  },
  Kerberoastable: {
    impact: "Una cuenta con SPN puede exponer material para comprobación offline de la fortaleza de su contraseña.",
    telemetry: "Las solicitudes de tickets pueden observarse en la telemetría Kerberos, pero el análisis offline no ocurre en el dominio.",
    prerequisites: "Registro de solicitudes de servicio, inventario de SPN y contexto de cifrado, volumen y cuenta solicitante.",
    remediation: "Usar gMSA cuando sea posible, contraseñas largas y aleatorias, AES y privilegios mínimos para las cuentas de servicio."
  },
  ASREPRoastable: {
    impact: "La ausencia de preautenticación permite solicitar una respuesta utilizable para comprobar offline la fortaleza de la credencial.",
    telemetry: "La solicitud AS-REQ puede observarse en los controladores; el análisis posterior es externo.",
    prerequisites: "Telemetría Kerberos conservada y contexto sobre cuentas legítimamente configuradas sin preautenticación.",
    remediation: "Habilitar preautenticación Kerberos y rotar la contraseña de la cuenta después de corregir la configuración."
  },
  UnconstrainedDelegation: {
    impact: "El sistema puede recibir credenciales delegadas y representa una superficie de alto impacto fuera de controladores de dominio.",
    telemetry: "Las señales dependen de la autenticación que llegue al equipo y del uso posterior de tickets.",
    prerequisites: "Inventario de delegación, telemetría Kerberos y visibilidad del sistema de destino.",
    remediation: "Eliminar delegación no restringida, migrar a alternativas restringidas y proteger cuentas que no deban delegarse."
  },
  ConstrainedDelegation: {
    impact: "Permite delegación hacia servicios declarados. El impacto depende de los SPN y de la capacidad de la identidad controladora.",
    telemetry: "La validación utiliza flujos Kerberos S4U y requiere correlación de tickets, cuenta y servicio de destino.",
    prerequisites: "Telemetría Kerberos suficiente y resolución de SPN a equipos y servicios reales.",
    remediation: "Reducir los servicios delegables, revisar cuentas controladoras y preferir configuraciones con límites explícitos."
  },
  RBCD: {
    impact: "La delegación restringida basada en recursos puede permitir actuar frente al equipo de destino desde una identidad controlada.",
    telemetry: "Los cambios del atributo de delegación y el uso posterior de S4U son señales separadas.",
    prerequisites: "Auditoría de cambios del directorio, telemetría Kerberos y análisis del descriptor almacenado en el atributo.",
    remediation: "Eliminar entradas no autorizadas, limitar quién puede escribir el atributo y revisar cuentas de equipo creadas por usuarios."
  },
  ADCS_ESC1: {
    impact: "Una plantilla y CA compatibles pueden permitir solicitar certificados con una identidad alternativa cuando se cumplen todas las condiciones.",
    telemetry: "La solicitud y emisión de certificados debe correlacionarse con la plantilla, solicitante, identidad indicada y autenticaciones posteriores.",
    prerequisites: "Auditoría de AD CS, registros de la CA y confirmación de que la plantilla está publicada y utilizable.",
    remediation: "Eliminar SAN aportado por solicitante cuando no sea necesario, restringir inscripción y exigir aprobaciones o firmas autorizadas."
  },
  HasPasswordInDescription: {
    impact: "El atributo contiene texto que coincide con una heurística de posible credencial. Es un indicio, no una contraseña confirmada.",
    telemetry: "La lectura LDAP puede quedar registrada según la configuración; Serket no conserva el valor sensible en el resultado.",
    prerequisites: "Revisión manual autorizada y tratamiento confidencial de cualquier valor encontrado.",
    remediation: "Eliminar secretos de atributos descriptivos, rotar cualquier credencial confirmada y aplicar un gestor de secretos."
  },
  HasSIDHistory: {
    impact: "El SID histórico puede ampliar el token de acceso. Su efecto depende del SID, el ámbito y los filtros aplicables.",
    telemetry: "El uso efectivo aparece en accesos realizados con el token; la presencia del atributo por sí sola no confirma abuso.",
    prerequisites: "Resolución del SID histórico, análisis de trusts y correlación con accesos reales.",
    remediation: "Retirar SIDHistory que ya no sea necesario y revisar migraciones, trusts y filtrado de SID."
  }
};

const SURFACE_DEFINITIONS = [
  ["acl_abuse", "Control mediante ACL", "Relaciones de escritura o control observadas"],
  ["dcsync", "Replicación del directorio", "Identidades con relaciones DCSync"],
  ["kerberoastable", "Cuentas con SPN", "Superficie Kerberos para comprobación offline"],
  ["asreproastable", "Sin preautenticación", "Cuentas con preautenticación deshabilitada"],
  ["unconstrained", "Delegación no restringida", "Equipos o cuentas observados"],
  ["constrained", "Delegación restringida", "Relaciones de delegación configuradas"],
  ["rbcd", "RBCD", "Delegación basada en recursos"],
  ["adcs_esc1", "AD CS ESC1", "Plantillas que requieren validación"],
  ["laps_readable", "Lectura LAPS", "Equipos marcados como legibles"],
  ["gmsa_accounts", "Cuentas gMSA", "Cuentas de servicio administradas"],
  ["sid_history", "SID History", "Identidades con SID histórico"],
  ["password_in_desc", "Texto sensible", "Coincidencias heurísticas en descripciones"],
  ["shadow_credentials", "Shadow Credentials", "Cuentas con KeyCredentialLink poblado"],
  ["adminsdholder_drift", "Drift de AdminSDHolder", "DACL protegida distinta de la plantilla"],
  ["protected_users_gaps", "Admins sin Protected Users", "Gap de hardening en cuentas sensibles"],
  ["rodc_exposure", "Credenciales en RODC", "Secretos observados en controladores de solo lectura"],
  ["special_group_exposure", "Grupos especiales expuestos", "Membresías amplias o heredadas"],
  ["uac_risks", "Riesgos UAC", "Flags de cuenta débiles o heredados"],
  ["trust_risks", "Trusts a revisar", "Filtrado SID relajado o delegación TGT"]
];

const $ = (selector, root) => (root || document).querySelector(selector);
const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

function esc(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function fmt(value) {
  return new Intl.NumberFormat("es-ES").format(Number(value || 0));
}

function fmtDuration(ms) {
  const value = Number(ms || 0);
  if (!value) return "—";
  if (value < 1000) return Math.round(value) + " ms";
  if (value < 60000) return (value / 1000).toFixed(1) + " s";
  return (value / 60000).toFixed(1) + " min";
}

function endpointId(value) {
  if (value && typeof value === "object") return String(value.id == null ? "" : value.id);
  return String(value == null ? "" : value);
}

function activityLevel(score) {
  const value = Number(score || 0);
  return value <= 2 ? "low" : value <= 3 ? "medium" : "high";
}

function activityLabel(score) {
  return {low: "Baja", medium: "Media", high: "Alta"}[activityLevel(score)];
}

function typeColor(type, highValue) {
  if (highValue) return "#d6ae55";
  return {
    User: "#65a9e8",
    Group: "#a68af6",
    Computer: "#74b5bc",
    Workstation: "#74b5bc",
    Server: "#e4a64e",
    DomainController: "#d6ae55",
    Domain: "#d6ae55",
    CertTemplate: "#62c78a",
    GPO: "#e4a64e",
    OU: "#9aabb8",
    CA: "#62c78a"
  }[type] || "#8f9ba5";
}

function typeGlyph(type) {
  return {
    User: "USR", Group: "GRP", Computer: "PC", Workstation: "WS",
    Server: "SRV", DomainController: "DC", Domain: "DOM",
    CertTemplate: "CT", GPO: "GPO", OU: "OU", CA: "CA"
  }[type] || "OBJ";
}

function typeIcon(type) {
  const base = ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"';
  const icons = {
    User: '<svg' + base + '><circle cx="12" cy="7.5" r="3.5"></circle><path d="M4.5 20c0-4 3.2-7 7.5-7s7.5 3 7.5 7"></path></svg>',
    Group: '<svg' + base + '><circle cx="9" cy="8" r="3"></circle><path d="M2.5 20c0-3.5 2.8-6 6.5-6s6.5 2.5 6.5 6"></path><circle cx="17" cy="9" r="2.5" opacity=".55"></circle><path d="M15 15c3.5-.6 6.5 1.3 6.5 5" opacity=".55"></path></svg>',
    Computer: '<svg' + base + '><rect x="2.5" y="3" width="19" height="13" rx="2"></rect><path d="M8 21h8M12 16v5"></path></svg>',
    Workstation: '<svg' + base + '><rect x="2.5" y="3" width="19" height="13" rx="2"></rect><path d="M8 21h8M12 16v5"></path></svg>',
    Server: '<svg' + base + '><rect x="3" y="3" width="18" height="7" rx="1.5"></rect><rect x="3" y="14" width="18" height="7" rx="1.5"></rect><circle cx="17.5" cy="6.5" r="1"></circle><circle cx="17.5" cy="17.5" r="1"></circle></svg>',
    DomainController: '<svg' + base + '><rect x="3" y="2.5" width="18" height="8" rx="1.5"></rect><rect x="3" y="13.5" width="18" height="8" rx="1.5"></rect><path d="M7 6.5h6M7 17.5h6"></path><circle cx="17.5" cy="6.5" r="1" fill="currentColor" stroke="none"></circle><circle cx="17.5" cy="17.5" r="1" fill="currentColor" stroke="none"></circle></svg>',
    Domain: '<svg' + base + '><rect x="3" y="2.5" width="18" height="8" rx="1.5"></rect><rect x="3" y="13.5" width="18" height="8" rx="1.5"></rect><circle cx="17.5" cy="6.5" r="1" fill="currentColor" stroke="none"></circle><circle cx="17.5" cy="17.5" r="1" fill="currentColor" stroke="none"></circle></svg>',
    CertTemplate: '<svg' + base + '><path d="M12 2.5 4.5 6v5.5c0 5 3.2 9 7.5 10.5 4.3-1.5 7.5-5.5 7.5-10.5V6Z"></path><path d="m9 12 2 2 4-4"></path></svg>'
  };
  return icons[type] || '<svg' + base + '><rect x="4" y="4" width="16" height="16" rx="2"></rect><path d="M8 12h8M12 8v8"></path></svg>';
}

async function api(path, fallback) {
  try {
    const response = await fetch(path, {cache: "no-store"});
    if (!response.ok) throw new Error("HTTP " + response.status);
    return await response.json();
  } catch (error) {
    console.error("Serket API", path, error);
    return fallback;
  }
}

async function apiAllFindings() {
  const findings = [];
  let offset = 0;
  let riskSummary = {};
  let snapshotId = "";
  while (true) {
    const page = await api("/api/findings?offset=" + offset + "&limit=2000", null);
    if (!page || !Array.isArray(page.findings)) break;
    findings.push(...page.findings);
    riskSummary = page.risk_summary || riskSummary;
    snapshotId = page.snapshot_id || snapshotId;
    offset += page.findings.length;
    if (!page.findings.length || offset >= Number(page.total || 0)) break;
  }
  return {findings, risk_summary: riskSummary, snapshot_id: snapshotId};
}

async function init() {
  const result = await Promise.all([
    api("/api/domain", {}),
    api("/api/stats", {}),
    api("/api/paths", []),
    api("/api/surface", {}),
    api("/api/graph", {nodes: [], edges: [], available: false}),
    api("/api/meta", {}),
    api("/api/adcs", {}),
    api("/api/trusts", []),
    api("/api/detection-catalog", {entries: {}}),
    apiAllFindings()
  ]);

  state.domain = result[0] || {};
  state.stats = result[1] || {};
  state.paths = Array.isArray(result[2]) ? result[2] : [];
  state.surface = result[3] || {};
  state.graph = result[4] || {nodes: [], edges: [], available: false};
  state.meta = result[5] || {};
  state.adcs = result[6] || {};
  state.trusts = Array.isArray(result[7]) ? result[7] : [];
  const detectionEntries = (result[8] && result[8].entries) || {};
  state.findings = Array.isArray(result[9] && result[9].findings) ? result[9].findings : [];
  state.riskSummary = (result[9] && result[9].risk_summary) || {};
  Object.keys(detectionEntries).forEach(type => {
    const item = detectionEntries[type] || {};
    EDGE_CATALOG[type] = {
      impact: (EDGE_CATALOG[type] || {}).impact || "Documented relationship with context-dependent impact.",
      telemetry: item.source + (item.event_ids && item.event_ids.length ? " · Event IDs " + item.event_ids.join(", ") : ""),
      prerequisites: item.prerequisites,
      remediation: item.remediation,
      event_ids: item.event_ids || []
    };
  });

  buildIndexes();
  bindStaticEvents();
  renderTopbar();
  renderOverview();
  renderExposure();
  renderDetection();
  applyPathFilters(false);
  renderContext();
  renderGraph();
}

function buildIndexes() {
  const nodes = Array.isArray(state.graph.nodes) ? state.graph.nodes.slice() : [];
  const known = new Set(nodes.map(node => String(node.id)));

  state.findingsByObject = new Map();
  state.findings.forEach(finding => {
    const objectId = String(finding.object_id || "");
    if (!objectId) return;
    if (!state.findingsByObject.has(objectId)) state.findingsByObject.set(objectId, []);
    state.findingsByObject.get(objectId).push(finding);
  });

  state.paths.forEach(path => {
    (path.steps || []).forEach(step => {
      [
        {id: step.src, name: step.src_name, type: step.src_type},
        {id: step.tgt, name: step.tgt_name, type: step.tgt_type}
      ].forEach(node => {
        if (node.id != null && !known.has(String(node.id))) {
          known.add(String(node.id));
          nodes.push(node);
        }
      });
    });
  });

  nodes.forEach(node => {
    const inferred = state.findingsByObject.get(String(node.id));
    if (inferred && inferred.length) node.findings = inferred;
  });
  state.nodeMap = new Map(nodes.map(node => [String(node.id), node]));
  state.searchNodes = nodes.slice().sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id)));
  state.incoming = new Map();
  state.outgoing = new Map();
  state.highValue = new Set();

  nodes.forEach(node => {
    if (node.high_value || node.is_dc || node.type === "Domain") state.highValue.add(String(node.id));
  });
  state.paths.forEach(path => {
    if (path.target != null) state.highValue.add(String(path.target));
  });

  (state.graph.edges || []).forEach((edge, index) => {
    const source = endpointId(edge.source);
    const target = endpointId(edge.target);
    if (!state.outgoing.has(source)) state.outgoing.set(source, []);
    if (!state.incoming.has(target)) state.incoming.set(target, []);
    state.outgoing.get(source).push({edge, index});
    state.incoming.get(target).push({edge, index});
  });
}

function renderTopbar() {
  const domainName = state.domain.name || state.domain.dns_name || "Dominio sin nombre";
  $("#domain-name").textContent = domainName;
  document.title = "Serket — " + domainName;
  const collection = (state.meta && state.meta.collection) || {};
  const stamp = collection.started_at || state.meta.generated_at || state.meta.timestamp;
  $("#collection-stamp").textContent = stamp ? "Colección " + String(stamp).replace("T", " ").slice(0, 19) : "Colección local";
}

function renderOverview() {
  const uniqueSources = new Set(state.paths.map(path => String(path.src || path.src_name || ""))).size;
  const hvCount = state.highValue.size;
  const metrics = [
    ["Objetos", state.stats.nodes || state.nodeMap.size, "incluidos en el grafo", "gold"],
    ["Relaciones", state.stats.edges || (state.graph.edges || []).length, "aristas serializadas", ""],
    ["Orígenes con ruta", uniqueSources, "identidades precalculadas", "critical"],
    ["Objetivos Tier 0", hvCount, "marcados en la colección", "gold"]
  ];
  $("#overview-metrics").innerHTML = metrics.map(metric =>
    '<article class="metric-card ' + metric[3] + '"><span>' + esc(metric[0]) + '</span><strong>' + fmt(metric[1]) + '</strong><small>' + esc(metric[2]) + '</small></article>'
  ).join("");

  const topPaths = state.paths.slice().sort((a, b) => Number(a.hops || 0) - Number(b.hops || 0) || Number(a.cost || 0) - Number(b.cost || 0)).slice(0, 6);
  $("#overview-paths").innerHTML = topPaths.length ? topPaths.map((path, index) => {
    const actual = state.paths.indexOf(path);
    return '<button class="priority-row" type="button" data-path-index="' + actual + '">' +
      '<span class="priority-rank">' + String(index + 1).padStart(2, "0") + '</span>' +
      '<span class="priority-main"><strong>' + esc(path.src_name) + ' → ' + esc(path.target_name) + '</strong><span>' + esc(path.src_type || "Objeto") + ' hacia objetivo de alto valor</span></span>' +
      '<span class="priority-meta"><span class="small-chip">' + fmt(path.hops) + ' saltos</span><span class="small-chip red">' + activityLabel(path.noise) + '</span></span>' +
    '</button>';
  }).join("") : '<div class="list-empty">No hay rutas precalculadas en este resultado.</div>';

  $$(".priority-row", $("#overview-paths")).forEach(button => {
    button.addEventListener("click", () => {
      selectPath(Number(button.dataset.pathIndex), true);
      switchView("paths");
    });
  });

  const summaryKeys = ["acl_abuse", "kerberoastable", "dcsync", "adcs_esc1", "unconstrained"];
  const labels = Object.fromEntries(SURFACE_DEFINITIONS.map(item => [item[0], item[1]]));
  $("#surface-summary").innerHTML = summaryKeys.map(key =>
    '<div class="summary-row"><span>' + esc(labels[key]) + '</span><strong>' + fmt(arrayValue(state.surface[key]).length) + '</strong></div>'
  ).join("");

  renderDomainPolicy();

  const collection = (state.meta && state.meta.collection) || {};
  const systems = state.stats.systems || {};
  const quality = state.stats.quality || {};
  $("#collection-summary").innerHTML = [
    ["Estaciones", fmt(systems.workstation)],
    ["Servidores", fmt(systems.server)],
    ["Controladores de dominio", fmt(systems.domain_controller)],
    ["Relaciones ACL", fmt(quality.acl_relationships)],
    ["Calidad", quality.status || "No registrada"],
    ["Perfil", collection.profile || "No registrado"],
    ["Búsquedas LDAP", fmt(collection.searches)],
    ["Entradas procesadas", fmt(collection.entries)],
    ["Duración", fmtDuration(collection.duration_ms)],
    ["Transporte", collection.transport || "No registrado"]
  ].map(item => '<div class="summary-row"><span>' + esc(item[0]) + '</span><strong>' + esc(item[1]) + '</strong></div>').join("");
}

function renderDomainPolicy() {
  const password = state.domain.password_policy || {};
  const lockout = state.domain.lockout_policy || {};
  const hasPolicy = Object.keys(password).length || Object.keys(lockout).length || state.domain.maq != null || state.trusts.length;
  const target = $("#domain-policy-summary");
  if (!hasPolicy) {
    target.innerHTML = '<div class="list-empty">Esta colección no incluye la política de contraseñas.</div>';
    return;
  }
  const rows = [
    ["Longitud mínima", fmt(password.min_length), Number(password.min_length) < 12],
    ["Edad mínima", fmt(password.min_age_days) + " días", false],
    ["Edad máxima", Number(password.max_age_days) ? fmt(password.max_age_days) + " días" : "Sin caducidad", !Number(password.max_age_days)],
    ["Historial", fmt(password.history_length), false],
    ["Complejidad", password.complexity_required ? "Activada" : "Desactivada", !password.complexity_required],
    ["Bloqueo", Number(lockout.threshold) ? fmt(lockout.threshold) + " intentos" : "Desactivado", !Number(lockout.threshold)],
    ["Duración de bloqueo", fmt(lockout.duration_minutes) + " min", false],
    ["Ventana de observación", fmt(lockout.observation_window_minutes) + " min", false],
    ["MachineAccountQuota", fmt(state.domain.maq || 0), Number(state.domain.maq || 0) > 0],
    ["RODC", fmt(state.domain.rodc_count || 0), Number(state.domain.rodc_tier0_exposure_count || 0) > 0],
    ["Drift de AdminSDHolder", fmt(state.domain.adminsdholder_drift_count || 0), Number(state.domain.adminsdholder_drift_count || 0) > 0],
    ["Trusts", fmt(state.trusts.length), state.trusts.some(trust => trust.sid_filtering_risk)],
    ["Sistemas operativos", fmt(Object.keys(state.domain.operating_system_inventory || {}).length), false]
  ];
  const alerts = [];
  if (password.store_cleartext) alerts.push("REVERSIBLE ENCRYPTION ACTIVADO");
  if (state.trusts.some(trust => trust.sid_filtering_risk)) alerts.push("FOREST TRUST CON FILTRADO SID RELAJADO");
  if (Number(state.domain.rodc_tier0_exposure_count || 0) > 0) alerts.push("RODC CON CREDENCIALES TIER 0 REPLICADAS");
  if (state.domain.prewin2000_exposure) alerts.push("PRE-WINDOWS 2000 ACCESS EXPUESTO");
  const unconstrainedNonDc = state.searchNodes.filter(node => node.unconstrained && !node.is_dc).length;
  if (unconstrainedNonDc) alerts.push(unconstrainedNonDc + " EQUIPOS/CUENTAS NO-DC CON DELEGACIÓN NO RESTRINGIDA");
  const alert = alerts.map(message => '<div class="policy-alert">' + esc(message) + '</div>').join("");
  const maq = Number(state.domain.maq || 0);
  const maqAlert = maq > 0
    ? '<button class="policy-alert maq" id="maq-alert" type="button">MAQ: ' + fmt(maq) + ' - RIESGO DE ALTA DE EQUIPOS</button>'
    : '';
  target.innerHTML = alert + maqAlert + rows.map(item =>
    '<div class="summary-row' + (item[2] ? ' critical' : '') + '"><span>' + esc(item[0]) + '</span><strong>' + esc(item[1]) + '</strong></div>'
  ).join("");
  const maqButton = $("#maq-alert");
  if (maqButton) maqButton.addEventListener("click", () => showToast("MachineAccountQuota permite a identidades autenticadas crear cuentas de equipo. Valida necesidad, delegaciones y RBCD."));
}

function renderContext() {
  const config = {
    overview: ["WORKSPACE", "Resumen del dominio", "Lectura local del resultado cargado."],
    paths: ["QUERY BUILDER", "Construir una ruta", "Filtra las rutas calculadas durante la colección."],
    explorer: ["GRAPH SCOPE", "Controlar el subgrafo", "Limita los objetos visibles para mantener contexto y rendimiento."],
    exposure: ["SURFACE INDEX", "Categorías observadas", "Accede a cada familia sin mezclar indicios con explotación confirmada."],
    detection: ["EVIDENCE STATUS", "Cobertura declarada", "Serket conserva el estado desconocido hasta importar o registrar una validación."]
  }[state.activeView];
  $("#context-eyebrow").textContent = config[0];
  $("#context-title").textContent = config[1];
  $("#context-description").textContent = config[2];

  if (state.activeView === "paths") renderPathContext();
  else if (state.activeView === "explorer") renderGraphContext();
  else if (state.activeView === "exposure") renderExposureContext();
  else if (state.activeView === "detection") renderDetectionContext();
  else renderOverviewContext();
}

function renderOverviewContext() {
  const collection = (state.meta && state.meta.collection) || {};
  $("#context-body").innerHTML =
    '<section class="context-block"><div class="context-block-title">Resumen</div><div class="context-stat-grid">' +
      contextStat(state.paths.length, "Rutas") +
      contextStat(state.highValue.size, "Tier 0") +
      contextStat((state.graph.edges || []).length, "Relaciones") +
      contextStat(collection.searches || 0, "Consultas LDAP") +
    '</div></section>' +
    '<section class="context-block"><div class="context-block-title">Consultas rápidas</div><div class="quick-query-list">' +
      quickQuery("tier0", "Todas las rutas a Tier 0", "Ordenadas por saltos") +
      quickQuery("short", "Rutas de hasta 3 saltos", "Prioridad para revisión manual") +
      quickQuery("adcs", "Relaciones de AD CS", "Plantillas y rutas presentes") +
      quickQuery("acl", "Control mediante ACL", "Escritura, propietario y DACL") +
    '</div></section>' +
    '<div class="context-note">Las consultas de esta versión operan sobre rutas ya incluidas en la colección. No vuelven a consultar Active Directory.</div>';

  $$("[data-quick-query]", $("#context-body")).forEach(button => {
    button.addEventListener("click", () => {
      applyQuickQuery(button.dataset.quickQuery);
      switchView("paths");
    });
  });
}

function contextStat(value, label) {
  return '<div class="context-stat"><strong>' + fmt(value) + '</strong><span>' + esc(label) + '</span></div>';
}

function quickQuery(id, title, subtitle) {
  return '<button class="quick-query" type="button" data-quick-query="' + esc(id) + '"><strong>' + esc(title) + '</strong><span>' + esc(subtitle) + '</span></button>';
}

function renderPathContext() {
  const sources = uniquePathOptions("src", "src_name");
  const targets = uniquePathOptions("target", "target_name");
  const edges = uniqueEdgeTypes();
  $("#context-body").innerHTML =
    '<section class="context-block">' +
      selectField("Origen", "path-source", [['all', 'Cualquier identidad']].concat(sources), state.query.source) +
      selectField("Objetivo", "path-target", [['tier0', 'Cualquier objetivo Tier 0']].concat(targets), state.query.target) +
      selectField("Máximo de saltos", "path-hops", [['all', 'Sin límite adicional'], ['1', '1 salto'], ['2', '2 saltos'], ['3', '3 saltos'], ['4', '4 saltos'], ['6', '6 saltos']], state.query.maxHops) +
      selectField("Relación incluida", "path-edge", [['all', 'Cualquier relación']].concat(edges.map(type => [type, type])), state.query.edge) +
      '<button class="primary-button full" id="run-path-query" type="button">Aplicar consulta</button>' +
    '</section>' +
    '<section class="context-block"><div class="context-block-title"><span>Resultados</span><span id="path-result-count">' + fmt(state.filteredPaths.length) + '</span></div><div class="result-list" id="path-result-list"></div></section>' +
    '<div class="context-note">El ranking principal utiliza número de saltos. La actividad esperada se muestra como contexto, no como criterio de evasión.</div>';

  $("#run-path-query").addEventListener("click", () => {
    state.query.source = $("#path-source").value;
    state.query.target = $("#path-target").value;
    state.query.maxHops = $("#path-hops").value;
    state.query.edge = $("#path-edge").value;
    applyPathFilters(true);
  });
  renderPathResults();
}

function selectField(label, id, options, selected) {
  return '<label class="form-field"><span>' + esc(label) + '</span><select id="' + esc(id) + '">' + options.map(option =>
    '<option value="' + esc(option[0]) + '"' + (String(option[0]) === String(selected) ? ' selected' : '') + '>' + esc(option[1]) + '</option>'
  ).join("") + '</select></label>';
}

function uniquePathOptions(idKey, nameKey) {
  const map = new Map();
  state.paths.forEach(path => {
    const id = path[idKey];
    if (id != null) map.set(String(id), path[nameKey] || String(id));
  });
  return Array.from(map.entries()).sort((a, b) => String(a[1]).localeCompare(String(b[1])));
}

function uniqueEdgeTypes() {
  const types = new Set();
  state.paths.forEach(path => (path.steps || []).forEach(step => {
    if (step.edge_type) types.add(step.edge_type);
  }));
  return Array.from(types).sort();
}

function applyQuickQuery(id) {
  state.query = {source: "all", target: "tier0", maxHops: "all", edge: "all"};
  if (id === "short") state.query.maxHops = "3";
  if (id === "adcs") {
    const edge = uniqueEdgeTypes().find(type => type.startsWith("ADCS_") || type.startsWith("ESC"));
    state.query.edge = edge || "ADCS_ESC1";
  }
  if (id === "acl") {
    const edge = uniqueEdgeTypes().find(type => ["GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"].includes(type));
    state.query.edge = edge || "GenericAll";
  }
  applyPathFilters(false);
}

function applyPathFilters(showMessage) {
  state.filteredPaths = state.paths.filter(path => {
    if (state.query.source !== "all" && String(path.src) !== String(state.query.source)) return false;
    if (state.query.target !== "tier0" && String(path.target) !== String(state.query.target)) return false;
    if (state.query.maxHops !== "all" && Number(path.hops || 0) > Number(state.query.maxHops)) return false;
    if (state.query.edge !== "all" && !(path.steps || []).some(step => step.edge_type === state.query.edge)) return false;
    return true;
  }).sort((a, b) => Number(a.hops || 0) - Number(b.hops || 0) || Number(a.cost || 0) - Number(b.cost || 0));

  if (!state.filteredPaths.length) {
    state.activePathIndex = -1;
    clearPathView();
  } else {
    const current = state.paths[state.activePathIndex];
    if (!current || !state.filteredPaths.includes(current)) {
      state.activePathIndex = state.paths.indexOf(state.filteredPaths[0]);
    }
    renderPath(state.paths[state.activePathIndex]);
  }
  if (state.activeView === "paths") renderPathContext();
  renderOverview();
  state.graphDrawn = false;
  if (showMessage) showToast(state.filteredPaths.length + " rutas coinciden con la consulta.");
}

function renderPathResults() {
  const list = $("#path-result-list");
  const count = $("#path-result-count");
  if (!list || !count) return;
  count.textContent = fmt(state.filteredPaths.length);
  if (!state.filteredPaths.length) {
    list.innerHTML = '<div class="list-empty">No hay rutas precalculadas que cumplan estos filtros.</div>';
    return;
  }
  list.innerHTML = state.filteredPaths.map((path, index) => {
    const actual = state.paths.indexOf(path);
    const active = actual === state.activePathIndex ? " active" : "";
    return '<button class="path-result' + active + '" type="button" data-path-index="' + actual + '"><span class="path-result-row"><strong>' + esc(path.src_name) + ' → ' + esc(path.target_name) + '</strong><span class="path-result-index">' + String(index + 1).padStart(2, "0") + '</span></span><span>' + fmt(path.hops) + ' saltos · actividad ' + activityLabel(path.noise).toLowerCase() + '</span></button>';
  }).join("");
  $$(".path-result", list).forEach(button => button.addEventListener("click", () => selectPath(Number(button.dataset.pathIndex), true)));
}

function selectPath(index, renderList) {
  if (!state.paths[index]) return;
  state.activePathIndex = index;
  renderPath(state.paths[index]);
  state.graphDrawn = false;
  if (renderList && state.activeView === "paths") renderPathResults();
}

function clearPathView() {
  $("#path-title").textContent = "Sin rutas visibles";
  $("#path-subtitle").textContent = "Ajusta el origen, objetivo o filtros de la consulta.";
  $("#path-metrics").innerHTML = "";
  $("#path-flow").innerHTML = '<div class="empty-state"><span class="empty-mark">S</span><strong>Sin coincidencias</strong><p>La colección no contiene una ruta precalculada que cumpla la consulta actual.</p></div>';
  $("#mitre-timeline").innerHTML = '<span class="muted">Sin técnicas asociadas</span>';
}

function renderPath(path) {
  if (!path) return clearPathView();
  $("#path-title").textContent = (path.src_name || path.src) + " → " + (path.target_name || path.target);
  $("#path-subtitle").textContent = "Ruta precalculada desde " + (path.src_type || "objeto") + " hasta un objetivo marcado como Tier 0.";
  $("#path-metrics").innerHTML =
    pathMetric("SALTOS", path.hops) +
    pathMetric("RELACIONES", (path.steps || []).length) +
    pathMetric("ACTIVIDAD", activityLabel(path.noise), activityLevel(path.noise));

  const steps = path.steps || [];
  const nodes = [];
  if (steps.length) {
    nodes.push({id: steps[0].src, name: steps[0].src_name, type: steps[0].src_type});
    steps.forEach(step => nodes.push({id: step.tgt, name: step.tgt_name, type: step.tgt_type}));
  } else {
    nodes.push({id: path.src, name: path.src_name, type: path.src_type});
  }

  let html = '<div class="flow-track">';
  nodes.forEach((node, index) => {
    const full = state.nodeMap.get(String(node.id)) || node;
    const color = typeColor(full.type, full.high_value || full.is_dc || full.type === "Domain");
    html += '<button class="flow-node" type="button" data-node-id="' + esc(node.id) + '" style="--node-color:' + color + '">' +
      '<span class="node-icon">' + typeIcon(full.type) + '</span>' +
      '<span class="node-kind">' + esc(full.type || "Objeto") + '</span>' +
      '<span class="node-label">' + esc(full.name || full.id || "Objeto") + '</span>' +
      '<span class="node-flags">' + nodeFlags(full).map(flag => '<span class="node-flag' + (/^(OLD|NO-PWD|STALE|REV|SHADOW|SD-DRIFT|NO-PROTECTED|DES|LOCKED|RODC-T0|PREWIN-OPEN|POLICY FAIL|ACL_ABUSE|TIER0_PATH|WRITE_DACL_TIER0|KERBEROASTABLE|ASREP_ROAST|UNCONSTRAINED_DELEGATION|CONSTRAINED_DELEGATION|PROTOCOL_TRANSITION|MAQ_ABUSE_OBSERVED|GPO_ABUSE|ESC[1-4]_CANDIDATE)/.test(flag) ? ' critical' : '') + '">' + esc(flag) + '</span>').join("") + '</span>' +
    '</button>';
    if (index < steps.length) {
      const step = steps[index];
      html += '<button class="flow-edge" type="button" data-step-index="' + index + '"><span class="edge-label">' + esc(step.edge_type || "Relación") + '</span><span class="edge-line"></span><span class="edge-activity">Actividad ' + activityLabel(step.opsec).toLowerCase() + '</span></button>';
    }
  });
  html += '</div>';
  $("#path-flow").innerHTML = html;

  $$(".flow-node", $("#path-flow")).forEach(button => button.addEventListener("click", () => inspectNode(state.nodeMap.get(String(button.dataset.nodeId)) || {id: button.dataset.nodeId})));
  $$(".flow-edge", $("#path-flow")).forEach(button => button.addEventListener("click", () => inspectEdge(steps[Number(button.dataset.stepIndex)])));

  const techniques = [];
  steps.forEach(step => {
    if (step.mitre && step.mitre.id && !techniques.some(item => item.id === step.mitre.id)) techniques.push(step.mitre);
  });
  $("#mitre-timeline").innerHTML = techniques.length ? techniques.map(item => '<span class="trace-chip"><b>' + esc(item.id) + '</b><span>' + esc(item.name || "Técnica asociada") + '</span></span>').join("") : '<span class="muted">Sin técnicas asociadas</span>';
}

function pathMetric(label, value, cls) {
  return '<div class="path-metric"><span>' + esc(label) + '</span><strong class="' + esc(cls || "") + '">' + esc(value) + '</strong></div>';
}

function nodeFlags(node) {
  const flags = [];
  if (node.high_value) flags.push("TIER 0");
  if (node.is_dc) flags.push("DC");
  if (node.admin_count) flags.push("ADMIN");
  if (node.laps_readable) flags.push("LAPS");
  if (node.laps_encrypted) flags.push("LAPS ENC");
  if (node.is_gmsa) flags.push("gMSA");
  if (node.gmsa_password_readable) flags.push("LECTURA gMSA");
  if (Number(node.pwd_age_days) > 730) flags.push("OLD " + node.pwd_age_days + "d");
  if (node.pwd_never_expires) flags.push("NO-EXP");
  if (node.pwd_not_required) flags.push("NO-PWD");
  if (node.stale) flags.push("STALE");
  if (node.store_cleartext) flags.push("REV");
  if (node.reversible_encryption) flags.push("REV-USER");
  if (node.has_key_credential_link) flags.push("SHADOW");
  if (node.adminsdholder_drift) flags.push("SD-DRIFT");
  if (node.missing_protected_users) flags.push("NO-PROTECTED");
  if (node.credential_reuse) flags.push("REUSE (" + Number(node.reuse_count || 0) + ")");
  if (node.cloud_linked) flags.push("CLOUD");
  if (node.laps_reuse) flags.push("LAPS REUSE");
  if (node.matches_domain_policy === false) flags.push("POLICY FAIL");
  if (node.unconstrained) flags.push("UD");
  if (node.protocol_transition) flags.push("PT");
  else if (node.constrained_kerberos_only || (node.delegation_targets || []).length) flags.push("KCD");
  if ((node.rbcd_trustees || []).length) flags.push("RBCD");
  if (node.smartcard_required) flags.push("SMARTCARD");
  if (node.not_delegated) flags.push("NO-DELEG");
  if (node.use_des_key_only) flags.push("DES");
  if (node.locked_out) flags.push("LOCKED");
  if (node.logon_hours_restricted || (node.user_workstations || []).length) flags.push("LOGON-RESTRICT");
  if (node.authn_policy_assigned) flags.push("AUTH-POLICY");
  if (node.is_rodc) flags.push("RODC");
  if (node.rodc_tier0_exposure) flags.push("RODC-T0");
  if (node.is_dns_admins) flags.push("DNS-ADM");
  if (node.is_exchange_privileged) flags.push("EXCHANGE");
  if (node.is_key_admin) flags.push("KEY-ADMIN");
  if (node.prewin2000_exposure) flags.push("PREWIN-OPEN");
  const aliases = {
    SHADOW: "SHADOW", SD_DRIFT: "SD-DRIFT", NO_PROTECTED: "NO-PROTECTED",
    RODC_TIER0: "RODC-T0", PREWIN_OPEN: "PREWIN-OPEN",
    REVERSIBLE_ENCRYPTION: "REV", DES_ONLY: "DES",
    UNCONSTRAINED_DELEGATION: "UD", ASREP_ROAST: "ASREP_ROAST",
    KERBEROASTABLE: "KERBEROASTABLE",
    CONSTRAINED_DELEGATION: "KCD", PROTOCOL_TRANSITION: "PT",
    MAQ_ABUSE_OBSERVED: "MAQ-OBS"
  };
  const findings = Array.isArray(node.findings)
    ? node.findings
    : (state.findingsByObject.get(String(node.id)) || []);
  findings.forEach(finding => {
    const badge = String(finding.badge || "FINDING");
    const base = aliases[badge] || badge;
    const decorated = badge + " · " + String(finding.certainty || "informational").toUpperCase() +
      (finding.tier0_reachable ? " · TIER0" : "");
    const index = flags.indexOf(base);
    if (index >= 0) flags[index] = decorated;
    else flags.push(decorated);
  });
  return Array.from(new Set(flags));
}

function renderGraphContext() {
  const types = Array.from(new Set(state.searchNodes.map(node => node.type).filter(Boolean))).sort();
  const edges = Array.from(new Set((state.graph.edges || []).map(edge => edge.type || edge.edge_type).filter(Boolean))).sort();
  const focus = state.nodeMap.get(String(state.explorerFocusId || ""));
  $("#context-body").innerHTML =
    (focus ? '<section class="context-block graph-focus-controls"><div class="context-block-title">Foco actual</div><div class="focus-card"><strong>' + esc(focus.name || focus.id) + '</strong><span>' + esc(focus.type || "Objeto") + '</span></div><button class="secondary-button full" id="clear-graph-focus" type="button">Quitar foco</button></section>' : '') +
    '<section class="context-block graph-filter-controls">' +
      selectField("Ámbito", "graph-scope", [["outgoing", "Puede alcanzar"], ["incoming", "Puede alcanzarlo"], ["both", "Entrantes y salientes"], ["relevant", "Rutas y Tier 0"], ["active", "Solo ruta activa"], ["tier0", "Vecindario Tier 0"]], state.graphOptions.scope) +
      selectField("Tipo de objeto", "graph-type", [["all", "Todos los tipos"]].concat(types.map(type => [type, type])), state.graphOptions.type) +
      selectField("Tipo de relación", "graph-edge", [["all", "Todas las relaciones"]].concat(edges.map(type => [type, type])), state.graphOptions.edge) +
      selectField("Límite visual", "graph-limit", [["60", "60 objetos"], ["120", "120 objetos"], ["200", "200 objetos"]], String(state.graphOptions.limit)) +
      '<button class="primary-button full" id="apply-graph-filter" type="button">Actualizar subgrafo</button>' +
    '</section>' +
    '<div class="context-note graph-context-note">El límite afecta solo a la visualización. Los datos no se eliminan del paquete ni del análisis.</div>';

  $("#apply-graph-filter").addEventListener("click", () => {
    state.graphOptions.scope = $("#graph-scope").value;
    state.graphOptions.type = $("#graph-type").value;
    state.graphOptions.edge = $("#graph-edge").value;
    state.graphOptions.limit = Number($("#graph-limit").value);
    state.graphDrawn = false;
    renderGraph();
  });
  const clearFocus = $("#clear-graph-focus");
  if (clearFocus) clearFocus.addEventListener("click", () => clearExplorerFocus());
}

function renderGraph() {
  const viewport = $("#graph-viewport");
  const nodes = Array.isArray(state.graph.nodes) ? state.graph.nodes : [];
  const edges = Array.isArray(state.graph.edges) ? state.graph.edges : [];
  if (!state.graph.available || !nodes.length) {
    $("#graph-empty").style.display = "grid";
    viewport.innerHTML = "";
    $("#graph-count").textContent = "0 objetos";
    return;
  }
  $("#graph-empty").style.display = "none";
  const focusNode = state.nodeMap.get(String(state.explorerFocusId || ""));
  $("#explorer-title").textContent = focusNode ? String(focusNode.name || focusNode.id) : "Relaciones relevantes";
  $("#explorer-subtitle").textContent = focusNode
    ? "Sólo se muestran el foco y sus relaciones directas. Selecciona otro nodo para continuar."
    : "Se carga un subgrafo limitado y verificable; no todo el dominio a la vez.";

  const visibleIds = graphScopeIds(nodes, edges);
  let visibleNodes = nodes.filter(node => visibleIds.has(String(node.id)));
  if (state.graphOptions.type !== "all") visibleNodes = visibleNodes.filter(node => node.type === state.graphOptions.type || state.highValue.has(String(node.id)) || String(node.id) === String(state.explorerFocusId));
  visibleNodes = visibleNodes.slice(0, state.graphOptions.limit);
  const finalIds = new Set(visibleNodes.map(node => String(node.id)));
  let visibleEdges = edges.filter(edge => finalIds.has(endpointId(edge.source)) && finalIds.has(endpointId(edge.target)) && endpointId(edge.source) !== endpointId(edge.target));
  if (state.explorerFocusId && ["outgoing", "incoming", "both"].includes(state.graphOptions.scope)) {
    const focus = String(state.explorerFocusId);
    visibleEdges = visibleEdges.filter(edge => {
      const source = endpointId(edge.source);
      const target = endpointId(edge.target);
      if (state.graphOptions.scope === "outgoing") return source === focus;
      if (state.graphOptions.scope === "incoming") return target === focus;
      return source === focus || target === focus;
    });
  }
  if (state.graphOptions.edge !== "all") visibleEdges = visibleEdges.filter(edge => (edge.type || edge.edge_type) === state.graphOptions.edge);

  const focusedNavigation = Boolean(state.explorerFocusId && ["outgoing", "incoming", "both"].includes(state.graphOptions.scope));
  const activePath = state.paths[state.activePathIndex];
  const activeEdges = new Set();
  const depth = new Map();
  if (activePath && !focusedNavigation) {
    (activePath.steps || []).forEach((step, index) => {
      activeEdges.add(String(step.src) + "|" + String(step.tgt));
      if (!depth.has(String(step.src))) depth.set(String(step.src), index);
      depth.set(String(step.tgt), index + 1);
    });
  }
  if (focusedNavigation) {
    graphDepthsFromFocus(visibleEdges, String(state.explorerFocusId), state.graphOptions.scope).forEach((value, id) => depth.set(id, value));
  }

  const positions = layeredPositions(visibleNodes, depth);
  const parallelEdges = new Map();
  visibleEdges.forEach((edge, index) => {
    const key = endpointId(edge.source) + "|" + endpointId(edge.target);
    if (!parallelEdges.has(key)) parallelEdges.set(key, []);
    parallelEdges.get(key).push(index);
  });
  let html = '<g class="graph-edges">';
  visibleEdges.forEach((edge, index) => {
    const source = endpointId(edge.source);
    const target = endpointId(edge.target);
    const a = positions.get(source);
    const b = positions.get(target);
    if (!a || !b) return;
    const bend = Math.max(34, Math.abs(b.x - a.x) * .42);
    const siblings = parallelEdges.get(source + "|" + target) || [index];
    const slot = siblings.indexOf(index) - (siblings.length - 1) / 2;
    const offset = slot * 18;
    const d = "M" + a.x + "," + a.y + " C" + (a.x + bend) + "," + (a.y + offset) + " " + (b.x - bend) + "," + (b.y + offset) + " " + b.x + "," + b.y;
    const active = activeEdges.has(source + "|" + target) ? " active" : "";
    const relation = String(edge.type || edge.edge_type || "Relación");
    html += '<path class="graph-edge' + active + '" data-edge-index="' + index + '" d="' + d + '"><title>' + esc(relation) + '</title></path>' +
      (focusedNavigation ? '<text class="graph-edge-label" x="' + ((a.x + b.x) / 2) + '" y="' + (((a.y + b.y) / 2) + offset - 5) + '">' + esc(relation) + '</text>' : '');
  });
  html += '</g><g class="graph-nodes">';
  visibleNodes.forEach(node => {
    const pos = positions.get(String(node.id));
    if (!pos) return;
    const high = state.highValue.has(String(node.id));
    const active = String(node.id) === String(state.selectedNodeId) ? " active" : "";
    const label = String(node.name || node.id);
    html += '<g class="graph-node' + active + (high ? ' high-value' : '') + '" data-node-id="' + esc(node.id) + '" transform="translate(' + pos.x + ' ' + pos.y + ')" style="--node-color:' + typeColor(node.type, high) + '">' +
      '<circle class="node-halo" r="22"></circle><circle class="node-ring" r="16"></circle>' +
      '<text class="node-symbol" y="3">' + esc(typeGlyph(node.type)) + '</text>' +
      '<text class="node-text" y="35">' + esc(label.length > 25 ? label.slice(0, 23) + '…' : label) + '</text>' +
    '</g>';
  });
  html += '</g>';
  viewport.innerHTML = html;
  state.visibleNodes = new Map(visibleNodes.map(node => [String(node.id), node]));
  state.visibleEdges = visibleEdges;
  state.graphDrawn = true;
  $("#graph-count").textContent = fmt(visibleNodes.length) + (visibleNodes.length === 1 ? " objeto · " : " objetos · ") + fmt(visibleEdges.length) + (visibleEdges.length === 1 ? " relación" : " relaciones");
  $("#graph-back").disabled = state.explorerHistory.length === 0;
  $("#graph-details").hidden = !state.inspectorKind;

  $$(".graph-node", viewport).forEach(group => group.addEventListener("click", event => {
    event.stopPropagation();
    focusExplorerNode(group.dataset.nodeId);
  }));
  $$(".graph-edge", viewport).forEach(path => path.addEventListener("click", event => {
    event.stopPropagation();
    const edge = state.visibleEdges[Number(path.dataset.edgeIndex)];
    if (edge) {
      inspectEdge(rawEdgeToStep(edge));
      $("#graph-details").hidden = false;
      collapseExplorerInspector();
    }
  }));
  updateGraphTransform();
}

function graphScopeIds(nodes, edges) {
  const ids = new Set();
  const addNeighbors = seeds => {
    edges.forEach(edge => {
      const source = endpointId(edge.source);
      const target = endpointId(edge.target);
      if (seeds.has(source) || seeds.has(target)) {
        ids.add(source);
        ids.add(target);
      }
    });
  };

  if (["outgoing", "incoming", "both"].includes(state.graphOptions.scope) && state.explorerFocusId) {
    const focus = String(state.explorerFocusId);
    ids.add(focus);
    edges.forEach(edge => {
      const source = endpointId(edge.source);
      const target = endpointId(edge.target);
      if ((state.graphOptions.scope === "outgoing" || state.graphOptions.scope === "both") && source === focus) ids.add(target);
      if ((state.graphOptions.scope === "incoming" || state.graphOptions.scope === "both") && target === focus) ids.add(source);
    });
  } else if (state.graphOptions.scope === "active") {
    const path = state.paths[state.activePathIndex];
    (path && path.steps || []).forEach(step => { ids.add(String(step.src)); ids.add(String(step.tgt)); });
  } else if (state.graphOptions.scope === "tier0") {
    state.highValue.forEach(id => ids.add(id));
    addNeighbors(state.highValue);
  } else {
    state.paths.forEach(path => (path.steps || []).forEach(step => { ids.add(String(step.src)); ids.add(String(step.tgt)); }));
    state.highValue.forEach(id => ids.add(id));
    if (!ids.size) nodes.slice(0, state.graphOptions.limit).forEach(node => ids.add(String(node.id)));
  }
  return ids;
}

function graphDepthsFromFocus(edges, focus, scope) {
  const depth = new Map([[focus, scope === "outgoing" ? 0 : 1]]);
  edges.forEach(edge => {
    const source = endpointId(edge.source);
    const target = endpointId(edge.target);
    if (source === focus && scope !== "incoming") depth.set(target, scope === "both" ? 2 : 1);
    if (target === focus && scope !== "outgoing") depth.set(source, 0);
  });
  return depth;
}

function focusExplorerNode(id, remember = true) {
  const next = String(id || "");
  if (!next || !state.nodeMap.has(next)) return;
  if (remember && state.explorerFocusId && String(state.explorerFocusId) !== next) {
    state.explorerHistory.push(String(state.explorerFocusId));
  }
  state.explorerFocusId = next;
  state.selectedNodeId = next;
  state.graphOptions.scope = "outgoing";
  state.transform = {x: 0, y: 0, k: 1};
  inspectNode(state.nodeMap.get(next));
  collapseExplorerInspector();
  renderContext();
  renderGraph();
}

function explorerBack() {
  const previous = state.explorerHistory.pop();
  if (previous) focusExplorerNode(previous, false);
}

function clearExplorerFocus() {
  state.explorerFocusId = null;
  state.explorerHistory = [];
  state.graphOptions.scope = "relevant";
  state.graphDrawn = false;
  renderContext();
  renderGraph();
}

function collapseExplorerInspector() {
  if (state.activeView !== "explorer") return;
  const shell = $("#app-shell");
  const inspector = $("#inspector");
  shell.classList.add("inspector-collapsed");
  inspector.setAttribute("aria-hidden", "true");
}

function openExplorerInspector() {
  $("#app-shell").classList.remove("inspector-collapsed");
  $("#inspector").removeAttribute("aria-hidden");
}

function layeredPositions(nodes, depth) {
  const layers = new Map();
  const typeLayer = {User: 0, Computer: 1, Workstation: 1, Server: 1, DomainController: 4, OU: 1, Container: 1, Group: 2, GPO: 2, CertTemplate: 2, CA: 3, Domain: 4};
  const focusedNavigation = Boolean(state.explorerFocusId && ["outgoing", "incoming", "both"].includes(state.graphOptions.scope));
  let maxDepth = focusedNavigation ? Math.max(1, ...Array.from(depth.values())) : Math.max(4, ...Array.from(depth.values()));
  nodes.forEach((node, index) => {
    let layer = depth.get(String(node.id));
    if (layer == null) layer = state.highValue.has(String(node.id)) ? maxDepth : (typeLayer[node.type] == null ? index % maxDepth : typeLayer[node.type]);
    layer = Math.max(0, Math.min(maxDepth, layer));
    if (!layers.has(layer)) layers.set(layer, []);
    layers.get(layer).push(node);
  });
  const positions = new Map();
  Array.from(layers.keys()).sort((a, b) => a - b).forEach(layer => {
    const bucket = layers.get(layer).sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id)));
    const x = (focusedNavigation ? 120 : 90) + (layer / Math.max(1, maxDepth)) * (focusedNavigation ? 1000 : 1100);
    const spacing = Math.min(72, 650 / Math.max(1, bucket.length));
    bucket.forEach((node, index) => positions.set(String(node.id), {x, y: 380 + (index - (bucket.length - 1) / 2) * spacing}));
  });
  return positions;
}

function rawEdgeToStep(edge) {
  const source = endpointId(edge.source);
  const target = endpointId(edge.target);
  const src = state.nodeMap.get(source) || {};
  const tgt = state.nodeMap.get(target) || {};
  return {
    src: source, src_name: src.name || source, src_type: src.type || "?",
    tgt: target, tgt_name: tgt.name || target, tgt_type: tgt.type || "?",
    edge_type: edge.type || edge.edge_type || "Relación",
    detail: edge.detail || "", mitre: edge.mitre,
    opsec: edge.opsec_score || edge.opsec || 0,
    commands: edge.commands || []
  };
}

function renderExposure() {
  const cards = SURFACE_DEFINITIONS.map(definition => {
    const entries = arrayValue(state.surface[definition[0]]);
    return '<article class="exposure-card" id="surface-' + esc(definition[0]) + '"><div class="exposure-card-head"><div><span class="overline">' + esc(definition[2]) + '</span><h2>' + esc(definition[1]) + '</h2></div><strong class="exposure-count">' + fmt(entries.length) + '</strong></div><div class="exposure-items">' +
      (entries.length ? entries.slice(0, 5).map(entry => '<div class="exposure-item"><span>' + esc(surfaceItemName(entry)) + '</span><small>' + esc(surfaceItemMeta(entry)) + '</small></div>').join("") : '<div class="list-empty">Sin elementos observados</div>') +
    '</div></article>';
  });
  if (state.trusts.length) {
    cards.push('<article class="exposure-card" id="surface-trusts"><div class="exposure-card-head"><div><span class="overline">RELACIONES ENTRE DOMINIOS</span><h2>Trusts</h2></div><strong class="exposure-count">' + fmt(state.trusts.length) + '</strong></div><div class="exposure-items">' + state.trusts.slice(0, 5).map(entry => '<div class="exposure-item"><span>' + esc(surfaceItemName(entry)) + '</span><small>TRUST</small></div>').join("") + '</div></article>');
  }
  $("#exposure-grid").innerHTML = cards.join("");
}

function renderExposureContext() {
  const definitions = SURFACE_DEFINITIONS.map(item => {
    const count = arrayValue(state.surface[item[0]]).length;
    return '<button class="quick-query" type="button" data-surface-target="surface-' + esc(item[0]) + '"><strong>' + esc(item[1]) + '</strong><span>' + fmt(count) + ' elementos observados</span></button>';
  }).join("");
  $("#context-body").innerHTML = '<section class="context-block"><div class="context-block-title">Índice</div><div class="quick-query-list">' + definitions + '</div></section><div class="context-note">Las categorías son resultados del modelo actual. Los elementos no compatibles con esta versión permanecen fuera del catálogo hasta validarse.</div>';
  $$("[data-surface-target]", $("#context-body")).forEach(button => button.addEventListener("click", () => {
    const target = document.getElementById(button.dataset.surfaceTarget);
    if (target) target.scrollIntoView({behavior: "smooth", block: "start"});
  }));
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function surfaceItemName(entry) {
  if (entry == null) return "Elemento";
  if (typeof entry !== "object") return String(entry);
  return entry.name || entry.account || entry.partner || entry.target_name || entry.target || entry.enroller || entry.template || entry.dns || entry.sid || "Elemento";
}

function surfaceItemMeta(entry) {
  if (!entry || typeof entry !== "object") return "OBSERVADO";
  return entry.edge || entry.finding || entry.type || (entry.risks || []).join(", ") || (entry.password_readable ? "LECTURA" : "OBSERVADO");
}

function renderDetection() {
  const telemetry = (state.meta && state.meta.collection) || {};
  $("#collection-profile").textContent = telemetry.profile ? String(telemetry.profile).toUpperCase() : "PERFIL NO REGISTRADO";
  const cards = [
    ["Búsquedas LDAP", fmt(telemetry.searches), "operaciones lógicas"],
    ["Páginas", fmt(telemetry.pages), "respuestas paginadas"],
    ["Entradas", fmt(telemetry.entries), "objetos procesados"],
    ["Duración", fmtDuration(telemetry.duration_ms), "tiempo total"],
    ["Ritmo", telemetry.rate_per_second ? Number(telemetry.rate_per_second).toFixed(2) : "—", "entradas por segundo"],
    ["Riesgo", fmt(state.riskSummary.global_score), state.riskSummary.risk_model || "sin modelo"]
  ];
  $("#telemetry-grid").innerHTML = cards.map(card => '<article class="telemetry-card"><span>' + esc(card[0]) + '</span><strong>' + esc(card[1]) + '</strong><small>' + esc(card[2]) + '</small></article>').join("");

  const stages = telemetry.stages || {};
  const names = Object.keys(stages);
  $("#stage-table").innerHTML = '<div class="stage-row header"><span>ETAPA</span><span>BUSQ.</span><span>PÁG.</span><span>OBJ.</span></div>' +
    (names.length ? names.map(name => {
      const row = stages[name] || {};
      return '<div class="stage-row"><span class="stage-name">' + esc(name) + '</span><span>' + fmt(row.searches) + '</span><span>' + fmt(row.pages) + '</span><span>' + fmt(row.entries) + '</span></div>';
    }).join("") : '<div class="list-empty">La colección no contiene telemetría por etapas.</div>');

  const findingGroups = new Map();
  state.findings.forEach(finding => {
    const badge = String(finding.badge || "FINDING");
    const group = findingGroups.get(badge) || {count: 0, max: 0, certainties: new Set()};
    group.count += 1;
    group.max = Math.max(group.max, Number(finding.risk_score || 0));
    group.certainties.add(String(finding.certainty || "informational"));
    findingGroups.set(badge, group);
  });
  const findingRows = Array.from(findingGroups.entries()).sort((a, b) => b[1].max - a[1].max || a[0].localeCompare(b[0]));
  const types = uniqueEdgeTypes();
  $("#coverage-list").innerHTML = findingRows.length ? findingRows.map(([badge, group]) =>
    '<div class="coverage-row"><div><strong>' + esc(badge) + '</strong><span>' + esc(Array.from(group.certainties).join(", ").toUpperCase()) + ' · score máximo ' + fmt(group.max) + '</span></div><span class="coverage-state documented">' + fmt(group.count) + ' FINDINGS</span></div>'
  ).join("") : types.length ? types.map(type => {
    const documented = Boolean(EDGE_CATALOG[type]);
    return '<div class="coverage-row"><div><strong>' + esc(type) + '</strong><span>' + (documented ? 'Expectativas y corrección documentadas' : 'Pendiente de investigación y validación') + '</span></div><span class="coverage-state ' + (documented ? 'documented' : '') + '">' + (documented ? 'DOCUMENTADO' : 'DESCONOCIDO') + '</span></div>';
  }).join("") : '<div class="list-empty">No hay relaciones incluidas en rutas.</div>';
}

function renderDetectionContext() {
  const types = uniqueEdgeTypes();
  const documented = types.filter(type => EDGE_CATALOG[type]).length;
  $("#context-body").innerHTML =
    '<section class="context-block"><div class="context-stat-grid">' + contextStat(types.length, "Relaciones presentes") + contextStat(documented, "Documentadas") + contextStat(types.length - documented, "Desconocidas") + contextStat(0, "Validadas por SIEM") + '</div></section>' +
    '<section class="context-block"><div class="context-block-title">Estados</div><div class="quick-query-list">' +
      '<div class="context-note">ESPERADO: existe una señal documentada, condicionada a la auditoría.</div>' +
      '<div class="context-note">OBSERVADO: requiere evidencia importada de una validación real.</div>' +
      '<div class="context-note">DESCONOCIDO: no existe información suficiente; es el estado seguro por defecto.</div>' +
    '</div></section>';
}

function inspectEdge(step) {
  if (!step) return;
  state.selectedEdge = step;
  state.inspectorKind = "edge";
  state.inspectorTab = "evidence";
  state.lastCommand = formatCommands(step);
  renderInspector();
}

function inspectNode(node) {
  if (!node) return;
  state.selectedNodeId = String(node.id == null ? "" : node.id);
  state.inspectorKind = "node";
  state.inspectorTab = "evidence";
  renderInspector();
}

function renderInspector() {
  const inspector = $("#inspector");
  inspector.classList.add("has-content");
  $$("[data-inspector-tab]").forEach(button => button.classList.toggle("active", button.dataset.inspectorTab === state.inspectorTab));
  if (state.inspectorKind === "edge") renderEdgeInspector();
  else if (state.inspectorKind === "node") renderNodeInspector();
}

function renderEdgeInspector() {
  const step = state.selectedEdge || {};
  const catalog = EDGE_CATALOG[step.edge_type] || {};
  $("#inspector-title").textContent = step.edge_type || "Relación";
  $("#inspector-code").textContent = step.mitre && step.mitre.id ? step.mitre.id : "EDGE";
  let html = "";

  if (state.inspectorTab === "evidence") {
    html = inspectorRelationHeader(step) +
      '<section class="inspector-section"><h3>Evidencia disponible</h3><div class="status-box gold"><strong>RELACIÓN DERIVADA</strong><span>Serket ha construido esta arista a partir de los atributos y permisos incluidos en la colección. No equivale por sí sola a una acción ejecutada.</span></div></section>' +
      '<section class="inspector-section"><div class="detail-grid">' +
        detailCell("Origen", step.src_type || "?") + detailCell("Destino", step.tgt_type || "?") +
        detailCell("Actividad esperada", activityLabel(step.opsec)) + detailCell("Confianza", step.confidence || "Derivada") +
      '</div></section>' +
      (step.detail ? '<section class="inspector-section"><h3>Detalle técnico</h3><div class="detail-copy">' + esc(step.detail) + '</div></section>' : '');
  } else if (state.inspectorTab === "impact") {
    html = inspectorRelationHeader(step) + '<section class="inspector-section"><h3>Qué permite esta relación</h3><div class="detail-copy">' + esc(catalog.impact || "El impacto específico todavía no está documentado en el catálogo de esta versión.") + '</div></section>' +
      '<section class="inspector-section"><div class="status-box red"><strong>CONTEXTO DE RUTA</strong><span>El impacto final depende de las relaciones posteriores y del objetivo alcanzado; no debe evaluarse esta arista de forma aislada.</span></div></section>';
  } else if (state.inspectorTab === "validation") {
    html = inspectorRelationHeader(step) + '<section class="inspector-section"><h3>Validación autorizada</h3><div class="status-box gold"><strong>NO SE EJECUTA DESDE SERKET</strong><span>Los procedimientos son referencias para un entorno autorizado. Revisa alcance, objetivo y posibles cambios antes de utilizarlos.</span></div></section>' +
      '<section class="inspector-section">' + (state.lastCommand ? '<div class="command-block"><button class="copy-button" type="button">COPIAR</button><pre>' + esc(state.lastCommand) + '</pre></div>' : '<div class="detail-copy">No existe un procedimiento asociado a esta relación.</div>') + '</section>';
  } else if (state.inspectorTab === "telemetry") {
    html = inspectorRelationHeader(step) + '<section class="inspector-section"><h3>Estado de detección</h3><div class="status-box"><strong>DESCONOCIDO</strong><span>No se ha importado evidencia de SIEM o EDR para esta validación.</span></div></section>' +
      '<section class="inspector-section"><h3>Señal esperada</h3><div class="detail-copy">' + esc(catalog.telemetry || "La telemetría específica de esta relación está pendiente de investigación.") + '</div></section>' +
      '<section class="inspector-section"><h3>Requisitos</h3><div class="detail-copy">' + esc(catalog.prerequisites || "Auditoría, fuente y condiciones todavía no documentadas.") + '</div></section>' +
      (step.mitre && step.mitre.id ? '<section class="inspector-section"><h3>MITRE ATT&CK</h3><div class="detail-copy"><strong>' + esc(step.mitre.id) + '</strong><br>' + esc(step.mitre.name || "Técnica asociada") + '</div></section>' : '');
  } else {
    html = inspectorRelationHeader(step) + '<section class="inspector-section"><h3>Corrección propuesta</h3><div class="detail-copy">' + esc(catalog.remediation || "La corrección específica de esta relación todavía no está documentada en el catálogo de esta versión.") + '</div></section>' +
      '<section class="inspector-section"><div class="status-box gold"><strong>VALIDAR DESPUÉS DEL CAMBIO</strong><span>Repite la colección y confirma que la arista desaparece sin interrumpir el servicio legítimo.</span></div></section>';
  }
  $("#inspector-body").innerHTML = html;
  const copy = $(".copy-button", $("#inspector-body"));
  if (copy) copy.addEventListener("click", copyCommand);
}

function inspectorRelationHeader(step) {
  return '<section class="inspector-section"><h3>Relación seleccionada</h3><div class="inspector-object"><span class="inspector-object-icon" style="color:#e0444e">→</span><div><h2>' + esc(step.edge_type || "Relación") + '</h2><p>' + esc(step.src_name || step.src) + ' → ' + esc(step.tgt_name || step.tgt) + '</p></div></div></section>';
}

function renderNodeInspector() {
  const node = state.nodeMap.get(String(state.selectedNodeId)) || state.visibleNodes.get(String(state.selectedNodeId)) || {id: state.selectedNodeId, name: state.selectedNodeId, type: "Objeto"};
  const outgoing = state.outgoing.get(String(node.id)) || [];
  const incoming = state.incoming.get(String(node.id)) || [];
  const high = state.highValue.has(String(node.id));
  $("#inspector-title").textContent = node.name || node.id || "Objeto";
  $("#inspector-code").textContent = node.type || "NODE";
  const header = '<section class="inspector-section"><h3>Objeto seleccionado</h3><div class="inspector-object"><span class="inspector-object-icon" style="color:' + typeColor(node.type, high) + '">' + typeIcon(node.type) + '</span><div><h2>' + esc(node.name || node.id || "Objeto") + '</h2><p>' + esc(node.type || "Unknown") + '</p></div></div></section>';
  let html = header;
  if (state.inspectorTab === "evidence") {
    html += '<section class="inspector-section"><h3>Propiedades</h3><div class="detail-grid">' +
      detailCell("Tipo", node.type || "?") + detailCell("Tier 0", high ? "Sí" : "No") +
      detailCell("Entrantes", incoming.length) + detailCell("Salientes", outgoing.length) +
    '</div></section><section class="inspector-section"><h3>Identificador</h3><div class="detail-copy">' + esc(node.id || "No disponible") + '</div></section>' + nodePropertyDetails(node);
  } else if (state.inspectorTab === "impact") {
    html += '<section class="inspector-section"><h3>Contexto</h3><div class="detail-copy">' + (high ? 'Este objeto está marcado como objetivo de alta criticidad en la colección.' : 'El impacto depende de las relaciones entrantes, salientes y de las rutas que conectan este objeto con Tier 0.') + '</div></section><section class="inspector-section"><div class="detail-grid">' + detailCell("Controlado por", incoming.length) + detailCell("Puede afectar a", outgoing.length) + '</div></section>';
  } else if (state.inspectorTab === "validation") {
    html += '<section class="inspector-section"><div class="status-box gold"><strong>SELECCIONA UNA RELACIÓN</strong><span>Los procedimientos de validación se asocian a aristas concretas, no al objeto aislado.</span></div></section>';
  } else if (state.inspectorTab === "telemetry") {
    html += '<section class="inspector-section"><div class="status-box"><strong>DESCONOCIDO</strong><span>No existe evidencia de detección asociada al objeto en este paquete.</span></div></section>';
  } else {
    html += '<section class="inspector-section"><h3>Revisión recomendada</h3><div class="detail-copy">Revisa las relaciones entrantes, elimina delegaciones innecesarias y valida el cambio mediante una nueva colección controlada.</div></section>';
  }
  $("#inspector-body").innerHTML = html;
}

function nodePropertyDetails(node) {
  const properties = [
    ["DNS", node.dns], ["UPN", node.upn], ["sAMAccountName", node.sam_account_name || node.sam],
    ["Rol", node.computer_role], ["Sistema operativo", node.os_display || node.os],
    ["Versión de SO", node.os_version], ["Service Pack", node.os_service_pack],
    ["AdminCount", node.admin_count], ["LAPS", node.laps_readable ? "Lectura marcada" : "—"],
    ["gMSA", node.is_gmsa ? "Sí" : "—"],
    ["Último cambio de contraseña", node.pwd_last_set],
    ["Edad de contraseña", node.pwd_age_days != null ? node.pwd_age_days + " días" : null],
    ["Último inicio de sesión", node.last_logon_timestamp || node.last_logon],
    ["Inactividad", node.last_logon_age_days != null ? node.last_logon_age_days + " días" : null],
    ["La contraseña no caduca", node.pwd_never_expires ? "Sí" : null],
    ["Contraseña no requerida", node.pwd_not_required ? "Sí" : null],
    ["Cifrado reversible", (node.store_cleartext || node.reversible_encryption) ? "ACTIVADO" : null],
    ["Delegación restringida", (node.delegation_targets || []).join(", ")],
    ["Principales RBCD", (node.rbcd_trustees || []).join(", ")],
    ["Política de autenticación", node.assigned_authn_policy],
    ["Estaciones permitidas", (node.user_workstations || []).join(", ")],
    ["Cuenta bloqueada", node.locked_out ? "Sí" : null],
    ["RODC secretos replicados", node.is_rodc ? (node.rodc_revealed_users || []).length : null],
    ["RODC secretos Tier 0", node.is_rodc ? (node.rodc_tier0_revealed_users || []).length : null]
  ].filter(item => item[1] != null && item[1] !== "");
  if (!properties.length) return "";
  return '<section class="inspector-section"><h3>Atributos relevantes</h3><div class="detail-grid">' + properties.map(item => detailCell(item[0], item[1])).join("") + '</div></section>';
}

function detailCell(label, value) {
  return '<div class="detail-cell"><span>' + esc(label) + '</span><strong title="' + esc(value) + '">' + esc(value) + '</strong></div>';
}

function formatCommands(step) {
  const commands = Array.isArray(step.commands) ? step.commands : [];
  return commands.join("\n")
    .replace(/\{domain\}/g, state.domain.name || "{domain}")
    .replace(/\{dc_ip\}/g, "<DC_IP>")
    .replace(/\{user\}/g, "<USUARIO_AUTORIZADO>")
    .replace(/\{password\}/g, "<CREDENCIAL>")
    .replace(/\{target\}/g, step.tgt_name || "<OBJETIVO>")
    .replace(/\{target_spn\}/g, "<TARGET_SPN>")
    .replace(/\{ca_name\}/g, "<CA_NAME>")
    .replace(/\{template\}/g, step.tgt_name || "<TEMPLATE>");
}

async function copyCommand() {
  if (!state.lastCommand) return;
  try {
    await navigator.clipboard.writeText(state.lastCommand);
    showToast("Procedimiento copiado. Revisa el alcance antes de utilizarlo.");
  } catch (error) {
    showToast("No se pudo copiar automáticamente.");
  }
}

function handleSearch() {
  const input = $("#global-search");
  const popover = $("#search-results");
  const query = input.value.trim().toLowerCase();
  state.searchCursor = -1;
  if (!query) {
    popover.hidden = true;
    popover.innerHTML = "";
    return;
  }
  const scored = state.searchNodes.map(node => {
    const id = String(node.id || "").toLowerCase();
    const name = String(node.name || "").toLowerCase();
    const upn = String(node.upn || "").toLowerCase();
    let score = 99;
    if (id === query || name === query || upn === query) score = 0;
    else if (name.startsWith(query) || upn.startsWith(query)) score = 1;
    else if (id.startsWith(query)) score = 2;
    else if (name.includes(query) || upn.includes(query)) score = 3;
    else if (id.includes(query)) score = 4;
    return {node, score};
  }).filter(item => item.score < 99).sort((a, b) => a.score - b.score || String(a.node.name || a.node.id).localeCompare(String(b.node.name || b.node.id))).slice(0, 9);
  popover.hidden = false;
  popover.innerHTML = scored.length ? scored.map((item, index) => {
    const node = item.node;
    return '<button class="search-result" type="button" data-search-index="' + index + '" data-node-id="' + esc(node.id) + '"><span class="search-result-icon" style="color:' + typeColor(node.type, state.highValue.has(String(node.id))) + '">' + esc(typeGlyph(node.type)) + '</span><span class="search-result-copy"><strong>' + esc(node.name || node.id) + '</strong><span>' + esc(node.id || "Sin identificador") + '</span></span><span class="search-result-type">' + esc(node.type || "OBJ") + '</span></button>';
  }).join("") : '<div class="search-empty">No se encontraron objetos en el grafo cargado.</div>';
  $$(".search-result", popover).forEach(button => button.addEventListener("click", () => chooseSearchResult(button.dataset.nodeId)));
}

function chooseSearchResult(id) {
  const node = state.nodeMap.get(String(id));
  if (!node) return;
  $("#global-search").value = node.name || node.id;
  $("#search-results").hidden = true;
  switchView("explorer");
  state.explorerHistory = [];
  focusExplorerNode(id, false);
}

function switchView(view) {
  if (!document.querySelector('[data-view-panel="' + view + '"]')) return;
  state.activeView = view;
  $("#app-shell").classList.toggle("explorer-mode", view === "explorer");
  $$(".nav-item[data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === view));
  $$("[data-view-panel]").forEach(panel => panel.classList.toggle("active", panel.dataset.viewPanel === view));
  renderContext();
  if (view === "paths" && state.activePathIndex >= 0) renderPath(state.paths[state.activePathIndex]);
  if (view === "explorer") {
    collapseExplorerInspector();
    renderGraph();
  } else if (state.inspectorKind) {
    openExplorerInspector();
  }
}

function resetGraph() {
  state.transform = {x: 0, y: 0, k: 1};
  updateGraphTransform();
}

function zoomGraph(delta) {
  state.transform.k = Math.max(.45, Math.min(2.8, state.transform.k + delta));
  updateGraphTransform();
}

function updateGraphTransform() {
  $("#graph-viewport").setAttribute("transform", "translate(" + state.transform.x + " " + state.transform.y + ") scale(" + state.transform.k + ")");
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("show"), 2800);
}

function bindStaticEvents() {
  $$(".nav-item[data-view]").forEach(button => button.addEventListener("click", () => switchView(button.dataset.view)));
  $$("[data-open-view]").forEach(button => button.addEventListener("click", () => switchView(button.dataset.openView)));
  $$("[data-inspector-tab]").forEach(button => button.addEventListener("click", () => {
    state.inspectorTab = button.dataset.inspectorTab;
    renderInspector();
  }));

  $("#global-search").addEventListener("input", handleSearch);
  $("#global-search").addEventListener("keydown", event => {
    const results = $$(".search-result", $("#search-results"));
    if (event.key === "ArrowDown" && results.length) {
      event.preventDefault();
      state.searchCursor = Math.min(results.length - 1, state.searchCursor + 1);
    } else if (event.key === "ArrowUp" && results.length) {
      event.preventDefault();
      state.searchCursor = Math.max(0, state.searchCursor - 1);
    } else if (event.key === "Enter" && state.searchCursor >= 0 && results[state.searchCursor]) {
      event.preventDefault();
      chooseSearchResult(results[state.searchCursor].dataset.nodeId);
      return;
    } else if (event.key === "Escape") {
      $("#search-results").hidden = true;
      return;
    }
    results.forEach((item, index) => item.classList.toggle("active", index === state.searchCursor));
  });

  $("#zoom-in").addEventListener("click", () => zoomGraph(.18));
  $("#zoom-out").addEventListener("click", () => zoomGraph(-.18));
  $("#zoom-reset").addEventListener("click", resetGraph);
  $("#graph-back").addEventListener("click", explorerBack);
  $("#graph-details").addEventListener("click", openExplorerInspector);
  const svg = $("#graph-canvas");
  svg.addEventListener("wheel", event => {
    event.preventDefault();
    zoomGraph(event.deltaY < 0 ? .12 : -.12);
  }, {passive: false});
  svg.addEventListener("pointerdown", event => {
    state.drag = {x: event.clientX, y: event.clientY, tx: state.transform.x, ty: state.transform.y};
    svg.setPointerCapture(event.pointerId);
    svg.classList.add("dragging");
  });
  svg.addEventListener("pointermove", event => {
    if (!state.drag) return;
    state.transform.x = state.drag.tx + event.clientX - state.drag.x;
    state.transform.y = state.drag.ty + event.clientY - state.drag.y;
    updateGraphTransform();
  });
  const endDrag = event => {
    if (!state.drag) return;
    state.drag = null;
    svg.classList.remove("dragging");
    try { svg.releasePointerCapture(event.pointerId); } catch (_) {}
  };
  svg.addEventListener("pointerup", endDrag);
  svg.addEventListener("pointercancel", endDrag);

  const legalModal = $("#legal-modal");
  const legalAccept = $("#legal-accept");
  const legalContinue = $("#legal-continue");
  legalAccept.addEventListener("change", () => { legalContinue.disabled = !legalAccept.checked; });
  legalContinue.addEventListener("click", () => {
    legalModal.classList.remove("open");
    showToast("Sesión autorizada. Los datos permanecen en localhost.");
  });
  $("#legal-button").addEventListener("click", () => {
    legalAccept.checked = false;
    legalContinue.disabled = true;
    legalModal.classList.add("open");
  });
  $("#legal-full").addEventListener("click", () => showToast("El texto completo está disponible en LEGAL.md dentro del proyecto."));

  const helpModal = $("#help-modal");
  $("#help-button").addEventListener("click", () => helpModal.classList.add("open"));
  $("#help-close").addEventListener("click", () => helpModal.classList.remove("open"));
  helpModal.addEventListener("click", event => { if (event.target === helpModal) helpModal.classList.remove("open"); });

  document.addEventListener("click", event => {
    if (!event.target.closest("#universal-search")) $("#search-results").hidden = true;
  });
  document.addEventListener("keydown", event => {
    if (event.key === "/" && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) {
      event.preventDefault();
      $("#global-search").focus();
    }
    if (/^[1-5]$/.test(event.key) && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) {
      switchView(["overview", "paths", "explorer", "exposure", "detection"][Number(event.key) - 1]);
    }
    if ((event.key === "j" || event.key === "k") && state.filteredPaths.length && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) {
      const current = state.filteredPaths.indexOf(state.paths[state.activePathIndex]);
      const delta = event.key === "j" ? 1 : -1;
      const next = (Math.max(0, current) + delta + state.filteredPaths.length) % state.filteredPaths.length;
      selectPath(state.paths.indexOf(state.filteredPaths[next]), true);
    }
    if (event.key === "0" && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) resetGraph();
    if (event.key === "Escape") {
      $("#search-results").hidden = true;
      helpModal.classList.remove("open");
    }
  });
}

window.addEventListener("DOMContentLoaded", () => {
  init().catch(error => {
    console.error(error);
    showToast("No se pudo inicializar Serket Workbench.");
  });
});
