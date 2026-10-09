"use strict";

/* BloodHound-style layer: right-click node menu, owned accounts, path search.
   Loaded last; reuses workbench globals ($, $$, esc, state, switchView,
   applyPathFilters, renderPathContext, renderPath, renderGraph, inspectNode,
   showToast, focusExplorerNode) and monkey-patches like query-runtime.js. */

(() => {
  const OWNED_KEY = "serket.owned.v1";
  const SPANISH = () => localStorage.getItem("serket.language") === "es";
  const t = (es, en) => (SPANISH() ? es : en);

  if (!state.owned) {
    try {
      state.owned = new Set(JSON.parse(localStorage.getItem(OWNED_KEY) || "[]"));
    } catch (_) {
      state.owned = new Set();
    }
  }
  if (!("startNode" in state)) state.startNode = null;
  if (!("targetNode" in state)) state.targetNode = "tier0";

  let basePaths = null;
  function rememberBase() {
    if (basePaths === null) {
      basePaths = state.paths.filter(path => !path.computed);
    }
  }

  function persistOwned() {
    localStorage.setItem(OWNED_KEY, JSON.stringify(Array.from(state.owned)));
  }

  function nodeName(id) {
    const node = state.nodeMap.get(String(id));
    return node ? String(node.name || node.id) : String(id);
  }

  function nodeType(id) {
    const node = state.nodeMap.get(String(id));
    return node && node.type ? String(node.type) : t("Objeto", "Object");
  }

  function isOwned(id) { return state.owned.has(String(id)); }

  function toggleOwned(id) {
    id = String(id);
    if (state.owned.has(id)) state.owned.delete(id);
    else state.owned.add(id);
    persistOwned();
    refreshMarks();
    if (state.activeView === "paths") renderPathContext();
  }

  function setStart(id) {
    state.startNode = String(id);
    showToast(t("Origen establecido: ", "Start set: ") + nodeName(id));
    refreshMarks();
  }

  function setTarget(id) {
    state.targetNode = String(id);
    showToast(t("Objetivo establecido: ", "Target set: ") + nodeName(id));
    refreshMarks();
  }

  /* -- context menu ----------------------------------------------------- */

  const menu = document.createElement("div");
  menu.className = "bh-menu";
  menu.setAttribute("role", "menu");
  document.body.appendChild(menu);
  let menuNodeId = null;

  function menuItem(icon, label, action, opts) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "bh-menu-item" + (opts && opts.danger ? " danger" : "");
    button.innerHTML = '<span class="bh-icon">' + icon + "</span><span>" + esc(label) + "</span>";
    if (opts && opts.disabled) button.disabled = true;
    else button.addEventListener("click", () => { closeMenu(); action(); });
    menu.appendChild(button);
    return button;
  }

  function openMenu(id, x, y) {
    menuNodeId = String(id);
    menu.innerHTML = "";
    const header = document.createElement("div");
    header.className = "bh-menu-header";
    header.innerHTML = "<span>" + esc(nodeType(id)) + "</span><strong>" + esc(nodeName(id)) + "</strong>";
    menu.appendChild(header);

    menuItem("🔍", t("Inspeccionar", "Inspect"), () => {
      const node = state.nodeMap.get(menuNodeId);
      if (node) inspectNode(node);
    });
    menuItem("🎯", t("Establecer como origen", "Set as start"), () => setStart(menuNodeId));
    menuItem("🏁", t("Establecer como objetivo", "Set as target"), () => setTarget(menuNodeId));
    if (isOwned(menuNodeId)) {
      menuItem("✖", t("Quitar marca de comprometida", "Unmark as owned"), () => toggleOwned(menuNodeId), {danger: true});
    } else {
      menuItem("✅", t("Marcar como comprometida", "Mark as owned"), () => toggleOwned(menuNodeId));
    }
    const sep = document.createElement("div");
    sep.className = "bh-menu-sep";
    menu.appendChild(sep);
    menuItem("⚡", t("Calcular rutas a Tier 0 desde aquí", "Find paths to Tier 0 from here"), () => {
      state.query = {source: menuNodeId, target: "tier0", maxHops: "all", edge: "all"};
      switchView("paths");
      applyPathFilters(true);
    });
    menuItem("🧨", t("Calcular ruta origen → objetivo", "Find path start → target"), () => {
      runMultiSourceSearch([state.startNode || menuNodeId], state.targetNode || "tier0");
    }, {disabled: !state.startNode && !state.owned.size});

    menu.classList.add("open");
    const rect = menu.getBoundingClientRect();
    menu.style.left = Math.min(x, window.innerWidth - rect.width - 8) + "px";
    menu.style.top = Math.min(y, window.innerHeight - rect.height - 8) + "px";
  }

  function closeMenu() {
    menu.classList.remove("open");
    menuNodeId = null;
  }

  document.addEventListener("contextmenu", event => {
    const routeNode = event.target.closest && event.target.closest("[data-route-node]");
    const graphNode = event.target.closest && event.target.closest("[data-node-id]");
    const hit = routeNode || graphNode;
    if (!hit) { closeMenu(); return; }
    const id = routeNode ? routeNode.dataset.routeNode : graphNode.dataset.nodeId;
    event.preventDefault();
    event.stopPropagation();
    openMenu(id, event.clientX, event.clientY);
  }, true);

  document.addEventListener("click", event => {
    if (menu.classList.contains("open") && !menu.contains(event.target)) closeMenu();
  }, true);

  document.addEventListener("keydown", event => {
    if (event.key === "Escape") closeMenu();
  });

  /* Double-click sets start, like BloodHound's drag-to-start but simpler. */
  document.addEventListener("dblclick", event => {
    const hit = (event.target.closest && (event.target.closest("[data-route-node]") || event.target.closest("[data-node-id]")));
    if (!hit) return;
    event.preventDefault();
    setStart(hit.dataset.routeNode || hit.dataset.nodeId);
  });

  /* -- visual marks ------------------------------------------------------ */

  function markElements() {
    $$("[data-route-node]").forEach(el => {
      const id = String(el.dataset.routeNode);
      el.classList.toggle("owned", isOwned(id));
      el.classList.toggle("start-node", state.startNode === id);
      el.classList.toggle("target-node", state.targetNode !== "tier0" && state.targetNode === id);
    });
    $$("[data-node-id]").forEach(el => {
      const id = String(el.dataset.nodeId);
      el.classList.toggle("owned", isOwned(id));
      el.classList.toggle("start-node", state.startNode === id);
      el.classList.toggle("target-node", state.targetNode !== "tier0" && state.targetNode === id);
    });
  }

  function refreshMarks() {
    markElements();
    renderStartTargetBadges();
  }

  const originalRenderPath = renderPath;
  renderPath = function bloodhoundRenderPath(path) {
    originalRenderPath(path);
    markElements();
    renderOwnedBadges();
  };

  const originalRenderGraph = renderGraph;
  renderGraph = function bloodhoundRenderGraph() {
    originalRenderGraph();
    markElements();
  };

  function renderOwnedBadges() {
    $$(".route-node[data-route-node]").forEach(el => {
      if (!isOwned(el.dataset.routeNode)) return;
      if (el.querySelector(".route-owned-badge")) return;
      const svgNS = "http://www.w3.org/2000/svg";
      const badge = document.createElementNS(svgNS, "circle");
      badge.setAttribute("class", "route-owned-badge");
      badge.setAttribute("cx", "38");
      badge.setAttribute("cy", "-38");
      badge.setAttribute("r", "11");
      const glyph = document.createElementNS(svgNS, "text");
      glyph.setAttribute("class", "route-owned-glyph");
      glyph.setAttribute("x", "38");
      glyph.setAttribute("y", "-33.5");
      glyph.setAttribute("text-anchor", "middle");
      glyph.textContent = "✓";
      el.appendChild(badge);
      el.appendChild(glyph);
    });
  }

  /* -- owned panel inside the paths context ------------------------------ */

  const originalRenderPathContext = renderPathContext;
  renderPathContext = function bloodhoundRenderPathContext() {
    originalRenderPathContext();
    const body = $("#context-body");
    if (!body || body.querySelector(".bh-owned-panel")) return;
    const panel = document.createElement("div");
    panel.className = "bh-owned-panel";
    body.insertBefore(panel, body.firstChild);
    renderOwnedPanel();
  };

  function renderOwnedPanel() {
    const panel = $(".bh-owned-panel");
    if (!panel) return;
    const chips = Array.from(state.owned).map(id =>
      '<span class="bh-chip" data-owned-id="' + esc(id) + '"><span>' + esc(nodeName(id)) + '</span><button type="button" title="' + esc(t("Quitar", "Remove")) + '">×</button></span>'
    ).join("");
    panel.innerHTML =
      "<h3>" + esc(t("Cuentas comprometidas", "Owned accounts")) + "</h3>" +
      '<p class="bh-hint">' + esc(t("Clic derecho sobre cualquier nodo → «Marcar como comprometida». Doble clic fija el origen.", "Right-click any node → \"Mark as owned\". Double-click sets the start.")) + "</p>" +
      '<div class="bh-owned-chips">' + (chips || '<span class="bh-owned-empty">' + esc(t("Ninguna marcada todavía.", "None marked yet.")) + "</span>") + "</div>" +
      '<div class="bh-mark-row">' +
        '<span class="bh-mark start">🎯 ' + esc(t("Origen", "Start")) + ": " + esc(state.startNode ? nodeName(state.startNode) : t("sin fijar", "not set")) + "</span>" +
        '<span class="bh-mark target">🏁 ' + esc(t("Objetivo", "Target")) + ": " + esc(state.targetNode === "tier0" ? t("Cualquier Tier 0", "Any Tier 0") : nodeName(state.targetNode)) + "</span>" +
      "</div>" +
      '<div class="bh-actions">' +
        '<button class="primary-button" id="bh-search-owned" type="button"' + (state.owned.size ? "" : " disabled") + ">" +
          esc(t("Buscar rutas desde marcadas", "Find paths from owned")) +
        "</button>" +
        (state.startNode ? '<button class="quiet-button" id="bh-search-start" type="button">' + esc(t("Desde origen", "From start")) + "</button>" : "") +
      "</div>";

    $$(".bh-chip button", panel).forEach(button => button.addEventListener("click", () => {
      const chip = button.closest(".bh-chip");
      if (chip) toggleOwned(chip.dataset.ownedId);
      renderOwnedPanel();
    }));
    const searchOwned = $("#bh-search-owned");
    if (searchOwned) searchOwned.addEventListener("click", () => {
      runMultiSourceSearch(Array.from(state.owned), state.targetNode || "tier0");
    });
    const searchStart = $("#bh-search-start");
    if (searchStart) searchStart.addEventListener("click", () => {
      runMultiSourceSearch([state.startNode], state.targetNode || "tier0");
    });
  }

  function renderStartTargetBadges() {
    if (state.activeView === "paths") {
      const panel = $(".bh-owned-panel");
      if (panel) renderOwnedPanel();
    }
  }

  /* -- multi-source path search ------------------------------------------ */

  async function fetchPaths(sources, target) {
    const response = await fetch("/api/query-paths", {
      method: "POST",
      cache: "no-store",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({sources: sources, target: target, max_hops: "all", include_edge: "all", limit: 50})
    });
    if (!response.ok) {
      let detail = "HTTP " + response.status;
      try { detail = (await response.json()).detail || detail; } catch (_) {}
      throw new Error(detail);
    }
    const result = await response.json();
    return {
      paths: Array.isArray(result.paths) ? result.paths : [],
      missing: Array.isArray(result.sources_missing) ? result.sources_missing : []
    };
  }

  function pathKey(path) {
    return String(path.src) + "|" + String(path.target) + "|" +
      (path.steps || []).map(step => String(step.tgt)).join(">");
  }

  async function runMultiSourceSearch(sources, target) {
    sources = (sources || []).map(String).filter(Boolean);
    if (!sources.length) {
      showToast(t("Marca al menos una cuenta comprometida (clic derecho).", "Mark at least one owned account (right-click)."));
      return;
    }
    rememberBase();
    const runButton = $("#bh-search-owned");
    if (runButton) { runButton.disabled = true; runButton.textContent = t("Calculando…", "Computing…"); }

    let dynamic = [];
    let missing = [];
    try {
      const result = await fetchPaths(sources, target || "tier0");
      dynamic = result.paths;
      missing = result.missing;
    } catch (error) {
      showToast(t("No se pudo calcular la ruta: ", "Path query failed: ") + error.message);
      if (runButton) { runButton.disabled = false; runButton.textContent = t("Buscar rutas desde marcadas", "Find paths from owned"); }
      return;
    }

    dynamic.sort((a, b) => Number(a.hops || 0) - Number(b.hops || 0) || Number(a.cost || 0) - Number(b.cost || 0));

    state.paths = basePaths.slice();
    const firstDynamicIndex = state.paths.length;
    state.paths.push(...dynamic);
    state.filteredPaths = dynamic;
    state.query = {source: "all", target: target, maxHops: "all", edge: "all"};
    state.graphDrawn = false;

    if (dynamic.length) {
      state.activePathIndex = firstDynamicIndex;
      renderPath(state.paths[firstDynamicIndex]);
    } else {
      state.activePathIndex = -1;
      clearPathView();
    }
    if (state.activeView !== "paths") switchView("paths");
    else renderPathContext();

    const spanish = SPANISH();
    let message = dynamic.length
      ? (spanish ? dynamic.length + " rutas desde " + sources.length + " cuenta(s)." : dynamic.length + " paths from " + sources.length + " account(s).")
      : (spanish ? "Sin rutas hacia el objetivo desde las cuentas marcadas." : "No paths to the target from the marked accounts.");
    if (missing.length) {
      message += spanish
        ? " (" + missing.length + " nodo(s) fuera del grafo cargado)"
        : " (" + missing.length + " node(s) not in the loaded graph)";
    }
    showToast(message);
  }

  /* -- explorer legend ---------------------------------------------------- */

  function extendLegend() {
    const legend = $(".graph-legend");
    if (!legend || legend.querySelector(".legend-dot.owned-dot")) return;
    const owned = document.createElement("span");
    owned.innerHTML = '<i class="legend-dot owned-dot"></i>' + esc(t("Comprometida", "Owned"));
    const start = document.createElement("span");
    start.innerHTML = '<i class="legend-dot start-dot"></i>' + esc(t("Origen", "Start"));
    legend.appendChild(owned);
    legend.appendChild(start);
  }

  const originalSwitchView = switchView;
  switchView = function bloodhoundSwitchView(view) {
    originalSwitchView(view);
    if (view === "explorer") {
      extendLegend();
      markElements();
    }
    if (view === "paths") refreshMarks();
  };

  /* initial paint for late loads */
  window.addEventListener("load", () => {
    markElements();
    extendLegend();
  });
})();
