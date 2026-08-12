"use strict";

(() => {
  const STORAGE_KEY = "serket.language";
  const language = localStorage.getItem(STORAGE_KEY) === "es" ? "es" : "en";

  const exact = {
    "Saltar al contenido": "Skip to content",
    "ENTORNO ACTIVO": "ACTIVE ENVIRONMENT",
    "Cargando dominio…": "Loading domain…",
    "Colección local": "Local collection",
    "Resumen": "Overview",
    "Rutas": "Paths",
    "Explorador": "Explorer",
    "Explorar": "Explore",
    "Exposición": "Exposure",
    "Superficie": "Exposure",
    "Detección": "Detection",
    "Aviso legal": "Legal notice",
    "Controles de la vista": "View controls",
    "Resumen del dominio": "Domain overview",
    "Lectura local del resultado cargado.": "Local analysis of the loaded result.",
    "Datos procesados en localhost": "Data processed on localhost",
    "Lo importante, antes que el grafo": "What matters before the graph",
    "Identidades expuestas, rutas priorizadas y señales disponibles en esta colección.": "Exposed identities, prioritized paths and signals available in this collection.",
    "Consultar rutas": "Query paths",
    "Métricas principales": "Key metrics",
    "RUTAS PRIORITARIAS": "PRIORITY PATHS",
    "Acceso hacia Tier 0": "Reachability to Tier 0",
    "Ver todas": "View all",
    "SUPERFICIE": "EXPOSURE",
    "Hallazgos por categoría": "Findings by category",
    "COLECCIÓN": "COLLECTION",
    "Huella registrada": "Recorded footprint",
    "RUTA SELECCIONADA": "SELECTED PATH",
    "Selecciona una consulta": "Select a query",
    "Serket muestra rutas precalculadas contenidas en esta colección.": "Serket shows precomputed paths contained in this collection.",
    "No hay una ruta seleccionada": "No path selected",
    "Utiliza el constructor situado a la izquierda para elegir un origen y un objetivo.": "Use the query builder on the left to choose a source and target.",
    "TRAZA MITRE": "MITRE TRACE",
    "Sin técnicas asociadas": "No mapped techniques",
    "Relaciones relevantes": "Relevant relationships",
    "Se carga un subgrafo limitado y verificable; no todo el dominio a la vez.": "A bounded, verifiable subgraph is loaded instead of the entire domain.",
    "Sólo se muestran el foco y sus relaciones directas. Selecciona otro nodo para continuar.": "Only the focused object and its direct relationships are shown. Select another node to continue.",
    "← Volver": "← Back",
    "Detalles": "Details",
    "Centrar": "Center",
    "Mapa de relaciones de Active Directory": "Active Directory relationship map",
    "Esta colección no contiene un grafo serializado.": "This collection does not contain a serialized graph.",
    "Usuario": "User",
    "Grupo": "Group",
    "Equipo": "Computer",
    "Alto valor": "High value",
    "Catálogo de exposición": "Exposure catalog",
    "Resumen de configuraciones y relaciones presentes en el resultado, sin afirmar explotación.": "Summary of configurations and relationships in the result without claiming exploitation.",
    "Telemetría y cobertura": "Telemetry and coverage",
    "Señales esperadas y actividad registrada. “Desconocido” se mantiene hasta aportar evidencia.": "Expected signals and recorded activity. Status remains unknown until evidence is provided.",
    "ACTIVIDAD": "ACTIVITY",
    "Etapas de colección": "Collection stages",
    "CATÁLOGO": "CATALOG",
    "Relaciones presentes": "Relationships present",
    "Evidencia": "Evidence",
    "Impacto": "Impact",
    "Validación": "Validation",
    "Telemetría": "Telemetry",
    "Corrección": "Remediation",
    "Inspector": "Inspector",
    "Ningún elemento seleccionado": "Nothing selected",
    "Selecciona una identidad, un nodo o una relación para revisar la evidencia disponible.": "Select an identity, node or relationship to review the available evidence.",
    "Sin ejecución remota desde la interfaz": "No remote execution from the interface",
    "Uso profesional autorizado": "Authorized professional use",
    "Serket analiza relaciones de Active Directory y puede utilizarse en auditorías, validaciones defensivas y ejercicios autorizados. Su capacidad es de doble uso y exige alcance y autorización escritos.": "Serket analyzes Active Directory relationships and can be used in audits, defensive validation and authorized exercises. It is dual-use software and requires written scope and authorization.",
    "Responsabilidad": "Responsibility",
    "La persona operadora verifica objetivo, horario, credenciales y reglas de enfrentamiento.": "The operator verifies the objective, schedule, credentials and rules of engagement.",
    "Datos sensibles": "Sensitive data",
    "Los resultados contienen información confidencial del directorio y deben protegerse como evidencia.": "Results contain confidential directory information and must be protected as evidence.",
    "Sin autorización implícita": "No implied authorization",
    "AraizCorp LLC no autoriza usos ilegales, no consentidos o fuera de alcance.": "AraizCorp LLC does not authorize illegal, non-consensual or out-of-scope use.",
    "Propiedad": "Ownership",
    "Serket, su nombre e identidad visual son propiedad de AraizCorp LLC.": "Serket, its name and visual identity are property of AraizCorp LLC.",
    "Confirmo que dispongo de autorización escrita y asumo la responsabilidad sobre el uso de la herramienta y los datos obtenidos.": "I confirm that I have written authorization and accept responsibility for using the tool and handling the resulting data.",
    "Entrar en Serket": "Enter Serket",
    "Consultar aviso legal completo": "Read the complete legal notice",
    "AYUDA RÁPIDA": "QUICK HELP",
    "Navegación": "Navigation",
    "Buscar cualquier objeto cargado": "Search any loaded object",
    "Cambiar de vista": "Change view",
    "Cambiar entre rutas visibles": "Move between visible paths",
    "Recentrar el explorador": "Recenter the explorer",
    "Cerrar resultados o diálogo": "Close results or dialog",
    "Dominio sin nombre": "Unnamed domain",
    "Objetos": "Objects",
    "Relaciones": "Relationships",
    "Orígenes con ruta": "Sources with paths",
    "Objetivos Tier 0": "Tier 0 targets",
    "incluidos en el grafo": "included in the graph",
    "aristas serializadas": "serialized edges",
    "identidades precalculadas": "precomputed identities",
    "marcados en la colección": "marked in the collection",
    "Objeto": "Object",
    "Perfil": "Profile",
    "Búsquedas LDAP": "LDAP searches",
    "Entradas procesadas": "Entries processed",
    "Duración": "Duration",
    "Transporte": "Transport",
    "No registrado": "Not recorded",
    "Construir una ruta": "Build a path",
    "Filtra las rutas calculadas durante la colección.": "Filter the paths calculated for this collection.",
    "Controlar el subgrafo": "Control the subgraph",
    "Limita los objetos visibles para mantener contexto y rendimiento.": "Limit visible objects to preserve context and performance.",
    "Foco actual": "Current focus",
    "Quitar foco": "Clear focus",
    "Puede alcanzar": "Can reach",
    "Puede alcanzarlo": "Can reach it",
    "Entrantes y salientes": "Incoming and outgoing",
    "Categorías observadas": "Observed categories",
    "Accede a cada familia sin mezclar indicios con explotación confirmada.": "Review each family without confusing indicators with confirmed exploitation.",
    "Cobertura declarada": "Declared coverage",
    "Serket conserva el estado desconocido hasta importar o registrar una validación.": "Serket keeps status unknown until validation evidence is imported or recorded.",
    "Consultas LDAP": "LDAP queries",
    "Consultas rápidas": "Quick queries",
    "Todas las rutas a Tier 0": "All paths to Tier 0",
    "Ordenadas por saltos": "Sorted by hops",
    "Rutas de hasta 3 saltos": "Paths up to 3 hops",
    "Prioridad para revisión manual": "Prioritized for manual review",
    "Relaciones de AD CS": "AD CS relationships",
    "Plantillas y rutas presentes": "Templates and paths present",
    "Control mediante ACL": "ACL-based control",
    "Escritura, propietario y DACL": "Write, ownership and DACL relationships",
    "Las consultas de esta versión operan sobre rutas ya incluidas en la colección. No vuelven a consultar Active Directory.": "Queries in this version operate on paths already included in the collection. They do not query Active Directory again.",
    "Origen": "Source",
    "Cualquier identidad": "Any identity",
    "Objetivo": "Target",
    "Cualquier objetivo Tier 0": "Any Tier 0 target",
    "Máximo de saltos": "Maximum hops",
    "Sin límite adicional": "No additional limit",
    "Relación incluida": "Included relationship",
    "Cualquier relación": "Any relationship",
    "Aplicar consulta": "Run query",
    "Resultados": "Results",
    "El ranking principal utiliza número de saltos. La actividad esperada se muestra como contexto, no como criterio de evasión.": "Primary ranking uses hop count. Expected activity is shown as context, never as an evasion criterion.",
    "No hay rutas precalculadas que cumplan estos filtros.": "No precomputed paths match these filters.",
    "Sin rutas visibles": "No visible paths",
    "Ajusta el origen, objetivo o filtros de la consulta.": "Adjust the source, target or query filters.",
    "Sin coincidencias": "No matches",
    "La colección no contiene una ruta precalculada que cumpla la consulta actual.": "The collection does not contain a precomputed path matching the current query.",
    "SALTOS": "HOPS",
    "RELACIONES": "RELATIONSHIPS",
    "ACTIVIDAD": "ACTIVITY",
    "Relación": "Relationship",
    "Técnica asociada": "Mapped technique",
    "Baja": "Low",
    "Media": "Medium",
    "Alta": "High",
    "Ámbito": "Scope",
    "Tipo de objeto": "Object type",
    "Todos los tipos": "All object types",
    "Actualizar subgrafo": "Update subgraph",
    "Ruta activa": "Active path",
    "Rutas y Tier 0": "Paths and Tier 0",
    "Solo ruta activa": "Active path only",
    "Vecindario seleccionado": "Selected neighborhood",
    "Vecindario Tier 0": "Tier 0 neighborhood",
    "Tipo de relación": "Relationship type",
    "Todas las relaciones": "All relationships",
    "Límite visual": "Visual limit",
    "El límite afecta solo a la visualización. Los datos no se eliminan del paquete ni del análisis.": "The limit affects only visualization. No data is removed from the package or analysis.",
    "Sin elementos observados": "No observed items",
    "Índice": "Index",
    "Las categorías son resultados del modelo actual. Los elementos no compatibles con esta versión permanecen fuera del catálogo hasta validarse.": "Categories reflect the current model. Unsupported items remain outside the catalog until validated.",
    "operaciones lógicas": "logical operations",
    "Páginas": "Pages",
    "respuestas paginadas": "paged responses",
    "tiempo total": "total time",
    "ETAPA": "STAGE",
    "BUSQ.": "SEARCH",
    "PÁG.": "PAGES",
    "OBJ.": "OBJECTS",
    "La colección no contiene telemetría por etapas.": "The collection contains no per-stage telemetry.",
    "Expectativas y corrección documentadas": "Expected signals and remediation documented",
    "Pendiente de investigación y validación": "Pending research and validation",
    "DOCUMENTADO": "DOCUMENTED",
    "DESCONOCIDO": "UNKNOWN",
    "No hay relaciones incluidas en rutas.": "No relationships are included in paths.",
    "ESPERADO: existe una señal documentada, condicionada a la auditoría.": "EXPECTED: a documented signal exists, subject to audit configuration.",
    "OBSERVADO: requiere evidencia importada de una validación real.": "OBSERVED: requires imported evidence from a real validation.",
    "DESCONOCIDO: no existe información suficiente; es el estado seguro por defecto.": "UNKNOWN: insufficient information; this is the safe default state.",
    "Evidencia disponible": "Available evidence",
    "RELACIÓN DERIVADA": "DERIVED RELATIONSHIP",
    "Serket ha construido esta arista a partir de los atributos y permisos incluidos en la colección. No equivale por sí sola a una acción ejecutada.": "Serket derived this edge from attributes and permissions in the collection. It does not by itself prove that an action was executed.",
    "Destino": "Target",
    "Detalle técnico": "Technical detail",
    "Qué permite esta relación": "What this relationship enables",
    "CONTEXTO DE RUTA": "PATH CONTEXT",
    "El impacto final depende de las relaciones posteriores y del objetivo alcanzado; no debe evaluarse esta arista de forma aislada.": "Final impact depends on downstream relationships and the reached target; this edge should not be assessed in isolation.",
    "Validación autorizada": "Authorized validation",
    "NO SE EJECUTA DESDE SERKET": "NOT EXECUTED BY SERKET",
    "Los procedimientos son referencias para un entorno autorizado. Revisa alcance, objetivo y posibles cambios antes de utilizarlos.": "Procedures are references for an authorized environment. Review scope, target and potential changes before use.",
    "COPIAR": "COPY",
    "No existe un procedimiento asociado a esta relación.": "No procedure is associated with this relationship.",
    "Estado de detección": "Detection status",
    "No se ha importado evidencia de SIEM o EDR para esta validación.": "No SIEM or EDR evidence has been imported for this validation.",
    "Señal esperada": "Expected signal",
    "Requisitos": "Prerequisites",
    "Corrección propuesta": "Proposed remediation",
    "VALIDAR DESPUÉS DEL CAMBIO": "VALIDATE AFTER THE CHANGE",
    "Repite la colección y confirma que la arista desaparece sin interrumpir el servicio legítimo.": "Repeat collection and confirm the edge disappears without disrupting legitimate service.",
    "Relación seleccionada": "Selected relationship",
    "Tipo": "Type",
    "Sí": "Yes",
    "No": "No",
    "Contexto": "Context",
    "Controlado por": "Controlled by",
    "Puede afectar a": "Can affect",
    "SELECCIONA UNA RELACIÓN": "SELECT A RELATIONSHIP",
    "Los procedimientos de validación se asocian a aristas concretas, no al objeto aislado.": "Validation procedures are associated with specific edges, not isolated objects.",
    "No existe evidencia de detección asociada al objeto en este paquete.": "No detection evidence is associated with this object in the package.",
    "Revisión recomendada": "Recommended review",
    "Revisa las relaciones entrantes, elimina delegaciones innecesarias y valida el cambio mediante una nueva colección controlada.": "Review incoming relationships, remove unnecessary delegation and validate the change with a new controlled collection.",
    "No se pudo copiar automáticamente.": "Could not copy automatically.",
    "Sin identificador": "No identifier",
    "Sesión autorizada. Los datos permanecen en localhost.": "Authorized session. Data remains on localhost.",
    "El texto completo está disponible en LEGAL.md dentro del proyecto.": "The full text is available in LEGAL.md in the project."
  };

  const attributes = {
    "Buscar identidad, SID, equipo o grupo": "Search identity, SID, computer or group",
    "Buscar objetos del directorio": "Search directory objects",
    "Ver ayuda y atajos": "View help and shortcuts",
    "Navegación principal": "Primary navigation",
    "Cerrar": "Close",
    "Alejar": "Zoom out",
    "Acercar": "Zoom in"
  };

  const englishCatalog = {
    MemberOf: {
      impact: "The identity inherits capabilities granted to the group. Relevance depends on permissions held by the group later in the path.",
      telemetry: "Membership changes may produce group-management events; later use of inherited privileges generates separate signals.",
      prerequisites: "Coverage depends on account-management auditing and event retention on the relevant domain controllers.",
      remediation: "Remove unnecessary membership, use role-based groups and periodically review nested and privileged groups."
    },
    GenericAll: {
      impact: "Broad control over the target object. Available actions depend on whether the target is an account, group, computer or domain object.",
      telemetry: "Validation may modify attributes, credentials or membership. Exact signals depend on the operation and configured SACLs.",
      prerequisites: "Directory-service change auditing, a SACL on the relevant object and correlation of identity, source and controller.",
      remediation: "Remove the broad ACE, replace it with least privilege and determine whether it was inherited from an organizational unit."
    },
    GenericWrite: {
      impact: "Allows modification of a broad subset of object attributes and may enable additional relationships depending on object type.",
      telemetry: "Directory attribute changes are expected when validation writes to the object; visibility requires appropriate auditing and SACLs.",
      prerequisites: "Directory change auditing and collection of events from the controller that processed the modification.",
      remediation: "Restrict writes to specific attributes and separate administrative duties through dedicated groups."
    },
    WriteDACL: {
      impact: "Allows modification of the access-control list and the grant of new capabilities over the object.",
      telemetry: "Validation modifies the security descriptor. Correlate the object, identity and the ACE added or removed.",
      prerequisites: "Directory-service auditing, a relevant SACL and retention of change details.",
      remediation: "Remove unjustified DACL modification delegation and protect high-value objects from accidental inheritance."
    },
    WriteOwner: {
      impact: "Ownership control may subsequently allow permissions on the object to be changed.",
      telemetry: "Taking ownership and a later DACL change are separate operations and should be correlated.",
      prerequisites: "Security-descriptor change auditing and a sufficient correlation window.",
      remediation: "Limit the right to change owners and review anomalous owners on privileged objects."
    },
    ForceChangePassword: {
      impact: "Allows the target account credential to be reset without knowing the previous password.",
      telemetry: "The reset may generate account-management events. Subsequent authentication should be analyzed separately.",
      prerequisites: "Account-management auditing, source identity and subsequent authentication events.",
      remediation: "Remove the extended right where unnecessary and delegate resets only to controlled operational groups."
    },
    AddMember: {
      impact: "Allows identities to be added to the target group and inherit its capabilities.",
      telemetry: "Membership changes should be recorded when group-management auditing is enabled.",
      prerequisites: "Collection of group-management events and correct resolution of the involved SIDs.",
      remediation: "Restrict who can modify the group, use approval workflows and alert specifically on Tier 0 groups."
    },
    AddSelf: {
      impact: "The identity can add itself to the group and gain the capabilities it grants.",
      telemetry: "The membership change is the primary observation point; subsequent privileged activity should be correlated.",
      prerequisites: "Group-management auditing with retention of both the added member and the actor.",
      remediation: "Remove the AddSelf validated write except in explicitly designed and reviewed workflows."
    },
    AllExtendedRights: {
      impact: "Groups extended rights whose effects depend on the target, including sensitive account or domain operations.",
      telemetry: "Signals depend on the right actually used. Serket does not assume a specific action from the ACE alone.",
      prerequisites: "An extended-right GUID catalog, applicable SACLs and telemetry for the operation performed.",
      remediation: "Replace AllExtendedRights with specific rights and document the purpose of each delegation."
    },
    DCSync: {
      impact: "Capability to request replication of directory secrets when the required rights are effectively usable.",
      telemetry: "Validation uses replication operations and must be distinguished from authorized controllers and services.",
      prerequisites: "Directory-access auditing, an inventory of legitimate replicators and correlation with identity and network source.",
      remediation: "Limit replication rights to required controllers and services; rotate credentials if unauthorized use occurred."
    },
    Kerberoastable: {
      impact: "An account with an SPN can expose material for offline password-strength assessment.",
      telemetry: "Ticket requests may be visible in Kerberos telemetry, while offline analysis does not occur in the domain.",
      prerequisites: "Service-ticket logging, SPN inventory and context for encryption, volume and requesting account.",
      remediation: "Use gMSA where possible, long random passwords, AES and least privilege for service accounts."
    },
    ASREPRoastable: {
      impact: "Disabled preauthentication permits a response that can be used for offline credential-strength assessment.",
      telemetry: "The AS-REQ may be observed on domain controllers; subsequent analysis is external.",
      prerequisites: "Retained Kerberos telemetry and context for accounts legitimately configured without preauthentication.",
      remediation: "Enable Kerberos preauthentication and rotate the account password after correcting the configuration."
    },
    UnconstrainedDelegation: {
      impact: "The system may receive delegated credentials and represents high-impact exposure outside domain controllers.",
      telemetry: "Signals depend on authentication reaching the computer and subsequent ticket use.",
      prerequisites: "Delegation inventory, Kerberos telemetry and visibility on the target system.",
      remediation: "Remove unconstrained delegation, migrate to constrained alternatives and protect accounts that must not be delegated."
    },
    ConstrainedDelegation: {
      impact: "Permits delegation to declared services. Impact depends on SPNs and control of the delegating identity.",
      telemetry: "Validation uses Kerberos S4U flows and requires correlation of tickets, account and target service.",
      prerequisites: "Sufficient Kerberos telemetry and resolution of SPNs to actual computers and services.",
      remediation: "Reduce delegable services, review controlling accounts and prefer configurations with explicit boundaries."
    },
    RBCD: {
      impact: "Resource-based constrained delegation may allow a controlled identity to act against the target computer.",
      telemetry: "Delegation-attribute changes and later S4U use are separate signals.",
      prerequisites: "Directory change auditing, Kerberos telemetry and analysis of the descriptor stored in the attribute.",
      remediation: "Remove unauthorized entries, limit who can write the attribute and review computer accounts created by users."
    },
    ADCS_ESC1: {
      impact: "A compatible template and CA may permit certificate enrollment with an alternative identity when all conditions are met.",
      telemetry: "Certificate requests and issuance should be correlated with template, requester, claimed identity and subsequent authentication.",
      prerequisites: "AD CS auditing, CA logs and confirmation that the template is published and usable.",
      remediation: "Remove requester-supplied SAN where unnecessary, restrict enrollment and require approval or authorized signatures."
    },
    HasPasswordInDescription: {
      impact: "The attribute contains text matching a possible-credential heuristic. It is an indicator, not a confirmed password.",
      telemetry: "LDAP reads may be recorded depending on configuration; Serket does not retain the sensitive value in results.",
      prerequisites: "Authorized manual review and confidential handling of any discovered value.",
      remediation: "Remove secrets from descriptive attributes, rotate confirmed credentials and use a secrets manager."
    },
    HasSIDHistory: {
      impact: "Historical SIDs may expand the access token. Effect depends on the SID, scope and applicable filters.",
      telemetry: "Effective use appears in access performed with the token; the attribute alone does not confirm abuse.",
      prerequisites: "Historical SID resolution, trust analysis and correlation with actual access.",
      remediation: "Remove SIDHistory when no longer needed and review migrations, trusts and SID filtering."
    }
  };

  const englishSurface = [
    ["acl_abuse", "ACL-based control", "Observed write or control relationships"],
    ["dcsync", "Directory replication", "Identities with DCSync relationships"],
    ["kerberoastable", "Accounts with SPNs", "Kerberos exposure for offline assessment"],
    ["asreproastable", "No preauthentication", "Accounts with preauthentication disabled"],
    ["unconstrained", "Unconstrained delegation", "Observed computers or accounts"],
    ["constrained", "Constrained delegation", "Configured delegation relationships"],
    ["rbcd", "RBCD", "Resource-based delegation"],
    ["adcs_esc1", "AD CS ESC1", "Templates requiring validation"],
    ["laps_readable", "LAPS readability", "Computers marked as readable"],
    ["gmsa_accounts", "gMSA accounts", "Managed service accounts"],
    ["sid_history", "SID History", "Identities with historical SIDs"],
    ["password_in_desc", "Sensitive text", "Heuristic matches in descriptions"]
  ];

  function translateValue(value) {
    if (language !== "en" || !value) return value;
    const leading = value.match(/^\s*/)[0];
    const trailing = value.match(/\s*$/)[0];
    const core = value.trim();
    if (!core) return value;
    if (exact[core]) return leading + exact[core] + trailing;

    const patterns = [
      [/^Colección (.+)$/, (_, stamp) => "Collection " + stamp],
      [/^(\d+) salto$/, (_, count) => count + " hop"],
      [/^(\d+) saltos$/, (_, count) => count + " hops"],
      [/^(\d+) rutas coinciden con la consulta\.$/, (_, count) => count + " paths match the query."],
      [/^(\d+) objeto · (\d+) relación$/, (_, nodes, edges) => nodes + " object · " + edges + " relationship"],
      [/^(\d+) objeto · (\d+) relaciones$/, (_, nodes, edges) => nodes + " object · " + edges + " relationships"],
      [/^(\d+) objetos · (\d+) relación$/, (_, nodes, edges) => nodes + " objects · " + edges + " relationship"],
      [/^(\d+) objetos · (\d+) relaciones$/, (_, nodes, edges) => nodes + " objects · " + edges + " relationships"],
      [/^(\d+) objetos$/, (_, count) => count + " objects"],
      [/^(\d+) elementos observados$/, (_, count) => count + " observed items"],
      [/^(\d+) saltos · actividad (baja|media|alta)$/i, (_, count, level) => count + " hops · " + ({baja: "low", media: "medium", alta: "high"}[level.toLowerCase()]) + " activity"],
      [/^Actividad (baja|media|alta)$/i, (_, level) => ({baja: "Low", media: "Medium", alta: "High"}[level.toLowerCase()]) + " activity"],
      [/^Ruta precalculada desde (.+) hasta un objetivo marcado como Tier 0\.$/, (_, source) => "Precomputed path from " + source + " to a target marked as Tier 0."],
      [/^Cualquier (.+)$/, (_, item) => "Any " + item.toLowerCase()]
    ];
    for (const [pattern, replacement] of patterns) {
      if (pattern.test(core)) return leading + core.replace(pattern, replacement) + trailing;
    }
    return value;
  }

  function translateTree(root) {
    if (language !== "en") return;
    if (root.nodeType === Node.TEXT_NODE) {
      const translated = translateValue(root.nodeValue);
      if (translated !== root.nodeValue) root.nodeValue = translated;
      return;
    }
    if (!(root instanceof Element) && root !== document) return;

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(node => {
      const parent = node.parentElement;
      if (!parent || ["SCRIPT", "STYLE", "PRE", "CODE"].includes(parent.tagName)) return;
      const translated = translateValue(node.nodeValue);
      if (translated !== node.nodeValue) node.nodeValue = translated;
    });

    const elements = root === document ? document.querySelectorAll("[placeholder],[aria-label],[title]") : root.querySelectorAll("[placeholder],[aria-label],[title]");
    elements.forEach(element => ["placeholder", "aria-label", "title"].forEach(name => {
      const value = element.getAttribute(name);
      if (attributes[value]) element.setAttribute(name, attributes[value]);
    }));
  }

  function installCatalog() {
    if (language !== "en") return;
    if (typeof EDGE_CATALOG !== "undefined") {
      Object.keys(englishCatalog).forEach(key => {
        EDGE_CATALOG[key] = englishCatalog[key];
      });
    }
    if (typeof SURFACE_DEFINITIONS !== "undefined") {
      SURFACE_DEFINITIONS.splice(0, SURFACE_DEFINITIONS.length, ...englishSurface);
    }
  }

  function installLanguageSwitch() {
    const actions = document.querySelector(".topbar-actions");
    if (!actions || document.getElementById("language-select")) return;
    const label = document.createElement("label");
    label.className = "language-switch";
    label.setAttribute("aria-label", language === "en" ? "Interface language" : "Idioma de la interfaz");
    label.innerHTML = '<span aria-hidden="true">LANG</span><select id="language-select"><option value="en">EN</option><option value="es">ES</option></select>';
    label.querySelector("select").value = language;
    label.querySelector("select").addEventListener("change", event => {
      localStorage.setItem(STORAGE_KEY, event.target.value);
      location.reload();
    });
    actions.insertBefore(label, actions.lastElementChild);
  }

  function installPathSelection() {
    document.addEventListener("click", event => {
      const edge = event.target.closest(".flow-edge");
      const node = event.target.closest(".flow-node");
      if (edge) {
        document.querySelectorAll(".flow-edge.selected,.flow-node.selected").forEach(item => item.classList.remove("selected"));
        edge.classList.add("selected");
      } else if (node) {
        document.querySelectorAll(".flow-edge.selected,.flow-node.selected").forEach(item => item.classList.remove("selected"));
        node.classList.add("selected");
      }
    });
  }

  document.documentElement.lang = language;
  installCatalog();
  installLanguageSwitch();
  installPathSelection();
  translateTree(document);

  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => mutation.addedNodes.forEach(node => translateTree(node)));
  });
  observer.observe(document.body, {childList: true, subtree: true});
  document.documentElement.classList.add("i18n-ready");
})();
