"use strict";

(() => {
  function isSpanish() {
    return localStorage.getItem("serket.language") === "es";
  }

  function hexPoints(x, y, radius) {
    return Array.from({length: 6}, (_, index) => {
      const angle = Math.PI / 3 * index - Math.PI / 2;
      return (x + Math.cos(angle) * radius).toFixed(1) + "," + (y + Math.sin(angle) * radius).toFixed(1);
    }).join(" ");
  }

  function edgePath(x1, y1, x2, y2) {
    const lift = Math.min(58, Math.max(34, (x2 - x1) * .2));
    return "M " + (x1 + 48) + " " + y1 + " C " + (x1 + 92) + " " + (y1 - lift) + ", " + (x2 - 92) + " " + (y2 - lift) + ", " + (x2 - 48) + " " + y2;
  }

  function routeNode(node, index, x, y, isTarget) {
    const full = state.nodeMap.get(String(node.id)) || node;
    const high = Boolean(full.high_value || full.is_dc || full.type === "Domain" || isTarget);
    const color = high ? "#d6ae55" : typeColor(full.type, false);
    const type = full.type || (isSpanish() ? "Objeto" : "Object");
    const name = full.name || full.id || type;
    const flags = nodeFlags(full).filter(flag => !(isTarget && flag === "TIER 0"));
    const badge = isTarget ? '<g class="route-tier-badge" transform="translate(' + x + ' ' + (y - 79) + ')"><rect x="-26" y="-10" width="52" height="20" rx="10"></rect><text y="3">TIER 0</text></g>' : '';
    const flagMarkup = flags.length
      ? '<text class="route-node-flags" x="' + x + '" y="' + (y + 90) + '">' + esc(flags.join(" · ")) + '</text>'
      : '';
    return '<g class="route-node' + (high ? ' high-value' : '') + '" role="button" tabindex="0" data-route-node="' + esc(node.id) + '" style="--route-node-color:' + color + '">' +
      '<polygon class="route-node-halo" points="' + hexPoints(x, y, 55) + '"></polygon>' +
      '<polygon class="route-node-body" points="' + hexPoints(x, y, 45) + '"></polygon>' +
      '<text class="route-node-glyph" x="' + x + '" y="' + (y + 4) + '">' + esc(typeGlyph(full.type)) + '</text>' +
      '<text class="route-node-sequence" x="' + (x + 50) + '" y="' + (y - 50) + '">' + String(index + 1).padStart(2, "0") + '</text>' +
      '<text class="route-node-type" x="' + x + '" y="' + (y + 68) + '">' + esc(type.toUpperCase()) + '</text>' +
      '<text class="route-node-name" x="' + x + '" y="' + (y + 84) + '">' + esc(name) + '</text>' +
      flagMarkup + badge +
    '</g>';
  }

  function routeEdge(step, index, x1, y1, x2, y2) {
    const path = edgePath(x1, y1, x2, y2);
    const middleX = (x1 + x2) / 2;
    const middleY = (y1 + y2) / 2 - 35;
    const label = step.edge_type || (isSpanish() ? "Relación" : "Relationship");
    const labelWidth = Math.max(86, Math.min(154, label.length * 7 + 26));
    const activity = (isSpanish() ? "Actividad " : "Activity ") + activityLabel(step.opsec).toLowerCase();
    return '<g class="route-edge" role="button" tabindex="0" data-route-step="' + index + '">' +
      '<path class="route-edge-hit" d="' + path + '"></path>' +
      '<path class="route-edge-line" d="' + path + '" marker-end="url(#route-arrow)"></path>' +
      '<g class="route-edge-label" transform="translate(' + middleX + ' ' + middleY + ')">' +
        '<rect x="' + (-labelWidth / 2) + '" y="-14" width="' + labelWidth + '" height="28" rx="14"></rect>' +
        '<text y="4">' + esc(label) + '</text>' +
      '</g>' +
      '<g class="route-activity" transform="translate(' + middleX + ' ' + (middleY + 57) + ')"><circle cx="-4" cy="-3" r="3"></circle><text x="5">' + esc(activity) + '</text></g>' +
    '</g>';
  }

  renderPath = function renderPathGraph(path) {
    if (!path) return clearPathView();
    const spanish = isSpanish();
    document.getElementById("path-title").textContent = (path.src_name || path.src) + " → " + (path.target_name || path.target);
    document.getElementById("path-subtitle").textContent = spanish
      ? "Ruta calculada sobre el grafo cargado; selecciona cualquier nodo o relación para investigarla."
      : "Path calculated over the loaded graph; select any node or relationship to investigate it.";
    document.getElementById("path-metrics").innerHTML =
      pathMetric(spanish ? "SALTOS" : "HOPS", path.hops) +
      pathMetric(spanish ? "RELACIONES" : "RELATIONSHIPS", (path.steps || []).length) +
      pathMetric(spanish ? "ACTIVIDAD" : "ACTIVITY", activityLabel(path.noise), activityLevel(path.noise));

    const steps = path.steps || [];
    const nodes = [];
    if (steps.length) {
      nodes.push({id: steps[0].src, name: steps[0].src_name, type: steps[0].src_type});
      steps.forEach(step => nodes.push({id: step.tgt, name: step.tgt_name, type: step.tgt_type}));
    } else {
      nodes.push({id: path.src, name: path.src_name, type: path.src_type});
    }

    const spacing = 250;
    const margin = 110;
    const width = Math.max(720, margin * 2 + Math.max(0, nodes.length - 1) * spacing);
    const height = 500;
    const y = 245;
    let edgesMarkup = "";
    let nodesMarkup = "";
    nodes.forEach((node, index) => {
      const x = margin + index * spacing;
      nodesMarkup += routeNode(node, index, x, y, index === nodes.length - 1);
      if (index < steps.length) {
        edgesMarkup += routeEdge(steps[index], index, x, y, x + spacing, y);
      }
    });

    document.getElementById("path-flow").innerHTML =
      '<div class="route-graph-shell" style="width:' + width + 'px">' +
        '<svg class="route-graph" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="' + (spanish ? 'Ruta de control seleccionada' : 'Selected control path') + '">' +
          '<defs>' +
            '<marker id="route-arrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto"><path d="M0 0 10 5 0 10Z"></path></marker>' +
            '<filter id="route-glow" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="5" result="blur"></feGaussianBlur><feMerge><feMergeNode in="blur"></feMergeNode><feMergeNode in="SourceGraphic"></feMergeNode></feMerge></filter>' +
          '</defs>' +
          '<g class="route-edges">' + edgesMarkup + '</g>' +
          '<g class="route-nodes">' + nodesMarkup + '</g>' +
        '</svg>' +
      '</div>';

    document.querySelectorAll("[data-route-node]").forEach(element => {
      const open = () => {
        document.querySelectorAll(".route-node.selected,.route-edge.selected").forEach(item => item.classList.remove("selected"));
        element.classList.add("selected");
        inspectNode(state.nodeMap.get(String(element.dataset.routeNode)) || {id: element.dataset.routeNode});
      };
      element.addEventListener("click", open);
      element.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
      });
    });
    document.querySelectorAll("[data-route-step]").forEach(element => {
      const open = () => {
        document.querySelectorAll(".route-node.selected,.route-edge.selected").forEach(item => item.classList.remove("selected"));
        element.classList.add("selected");
        inspectEdge(steps[Number(element.dataset.routeStep)]);
      };
      element.addEventListener("click", open);
      element.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
      });
    });

    const techniques = [];
    steps.forEach(step => {
      if (step.mitre && step.mitre.id && !techniques.some(item => item.id === step.mitre.id)) techniques.push(step.mitre);
    });
    document.getElementById("mitre-timeline").innerHTML = techniques.length
      ? techniques.map(item => '<span class="trace-chip"><b>' + esc(item.id) + '</b><span>' + esc(item.name || (spanish ? "Técnica asociada" : "Mapped technique")) + '</span></span>').join("")
      : '<span class="muted">' + (spanish ? "Sin técnicas asociadas" : "No mapped techniques") + '</span>';
  };
})();
