"use strict";

(() => {
  const edgeTabLabels = {
    en: ["Evidence", "Impact", "Validation", "Telemetry", "Remediation"],
    es: ["Evidencia", "Impacto", "Validación", "Telemetría", "Corrección"]
  };
  const nodeTabLabels = {
    en: ["Properties", "Controls", "Controlled by", "Memberships", "Paths from here"],
    es: ["Propiedades", "Controla", "Controlado por", "Membresías", "Rutas desde aquí"]
  };

  const spanish = () => localStorage.getItem("serket.language") === "es";

  function setTabLabels(kind) {
    const labels = (kind === "node" ? nodeTabLabels : edgeTabLabels)[spanish() ? "es" : "en"];
    document.querySelectorAll("[data-inspector-tab]").forEach((button, index) => {
      button.textContent = labels[index];
      button.title = labels[index];
    });
  }

  function relationList(items, direction) {
    if (!items.length) {
      return '<div class="node-relation-empty">' + (spanish() ? "No hay relaciones observadas en esta dirección." : "No relationships were observed in this direction.") + '</div>';
    }
    return '<div class="node-relation-list">' + items.slice(0, 100).map((item, index) => {
      const step = rawEdgeToStep(item.edge);
      const peer = direction === "out" ? step.tgt_name : step.src_name;
      const peerType = direction === "out" ? step.tgt_type : step.src_type;
      return '<button class="node-relation-row" type="button" data-node-relation="' + direction + ':' + index + '">' +
        '<span class="node-relation-type">' + esc(step.edge_type) + '</span>' +
        '<span><strong>' + esc(peer) + '</strong><small>' + esc(peerType || "Object") + '</small></span>' +
        '<span class="node-relation-arrow">' + (direction === "out" ? "→" : "←") + '</span>' +
      '</button>';
    }).join("") + '</div>';
  }

  const originalInspectNode = inspectNode;
  const originalInspectEdge = inspectEdge;

  inspectNode = function inspectNodeWithNavigation(node) {
    setTabLabels("node");
    originalInspectNode(node);
  };

  inspectEdge = function inspectEdgeWithNavigation(step) {
    setTabLabels("edge");
    originalInspectEdge(step);
  };

  renderNodeInspector = function renderExpandedNodeInspector() {
    setTabLabels("node");
    const node = state.nodeMap.get(String(state.selectedNodeId)) || state.visibleNodes.get(String(state.selectedNodeId)) || {id: state.selectedNodeId, name: state.selectedNodeId, type: "Object"};
    const outgoing = state.outgoing.get(String(node.id)) || [];
    const incoming = state.incoming.get(String(node.id)) || [];
    const memberships = outgoing.filter(item => (item.edge.type || item.edge.edge_type) === "MemberOf");
    const high = state.highValue.has(String(node.id));
    const paths = state.paths.filter(path => String(path.src) === String(node.id));
    const s = spanish();

    document.getElementById("inspector-title").textContent = node.name || node.id || "Object";
    document.getElementById("inspector-code").textContent = node.type || "NODE";
    const header = '<section class="inspector-section"><h3>' + (s ? "Objeto seleccionado" : "Selected object") + '</h3><div class="inspector-object"><span class="inspector-object-icon" style="color:' + typeColor(node.type, high) + '">' + typeIcon(node.type) + '</span><div><h2>' + esc(node.name || node.id || "Object") + '</h2><p>' + esc(node.type || "Unknown") + '</p></div></div></section>';
    let html = header;

    if (state.inspectorTab === "evidence") {
      html += '<section class="inspector-section"><h3>' + (s ? "Propiedades" : "Properties") + '</h3><div class="detail-grid">' +
        detailCell(s ? "Tipo" : "Type", node.type || "?") +
        detailCell("Tier 0", high ? (s ? "Sí" : "Yes") : "No") +
        detailCell(s ? "Entrantes" : "Incoming", incoming.length) +
        detailCell(s ? "Salientes" : "Outgoing", outgoing.length) +
      '</div></section><section class="inspector-section"><h3>' + (s ? "Identificador" : "Identifier") + '</h3><div class="detail-copy">' + esc(node.id || "Unavailable") + '</div></section>' + nodePropertyDetails(node);
    } else if (state.inspectorTab === "impact") {
      html += '<section class="inspector-section"><h3>' + (s ? "Controla" : "Controls") + '</h3>' + relationList(outgoing, "out") + '</section>';
    } else if (state.inspectorTab === "validation") {
      html += '<section class="inspector-section"><h3>' + (s ? "Controlado por" : "Controlled by") + '</h3>' + relationList(incoming, "in") + '</section>';
    } else if (state.inspectorTab === "telemetry") {
      html += '<section class="inspector-section"><h3>' + (s ? "Membresías" : "Memberships") + '</h3>' + relationList(memberships, "out") + '</section>';
    } else {
      html += '<section class="inspector-section"><h3>' + (s ? "Rutas desde aquí" : "Paths from here") + '</h3>' +
        '<button class="primary-button full" id="node-query-paths" type="button">' + (s ? "Calcular rutas a Tier 0" : "Calculate paths to Tier 0") + '</button>' +
        '<div class="node-path-summary">' + (s ? "Rutas ya incluidas: " : "Paths already included: ") + '<strong>' + paths.length + '</strong></div>' +
        (paths.length ? '<div class="node-relation-list">' + paths.slice(0, 20).map(path => '<button class="node-path-row" type="button" data-node-path-index="' + state.paths.indexOf(path) + '"><strong>' + esc(path.target_name || path.target) + '</strong><small>' + path.hops + (s ? " saltos" : " hops") + '</small></button>').join("") + '</div>' : '') +
      '</section>';
    }

    document.getElementById("inspector-body").innerHTML = html;
    document.querySelectorAll("[data-node-relation]").forEach(button => button.addEventListener("click", () => {
      const [direction, rawIndex] = button.dataset.nodeRelation.split(":");
      const collection = direction === "out" ? outgoing : incoming;
      const item = collection[Number(rawIndex)];
      if (item) inspectEdge(rawEdgeToStep(item.edge));
    }));
    document.querySelectorAll("[data-node-path-index]").forEach(button => button.addEventListener("click", () => {
      selectPath(Number(button.dataset.nodePathIndex), true);
      switchView("paths");
    }));
    const queryButton = document.getElementById("node-query-paths");
    if (queryButton) queryButton.addEventListener("click", () => {
      state.query = {source: String(node.id), target: "tier0", maxHops: "all", edge: "all"};
      switchView("paths");
      applyPathFilters(true);
    });
  };

  setTabLabels("edge");
})();
