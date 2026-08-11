"use strict";

(() => {
  let basePaths = null;
  let requestSequence = 0;
  const originalApplyPathFilters = applyPathFilters;
  const originalUniquePathOptions = uniquePathOptions;

  function rememberBasePaths() {
    if (basePaths === null && Array.isArray(state.paths) && state.paths.length) {
      basePaths = state.paths.slice();
    }
  }

  uniquePathOptions = function dynamicPathOptions(idKey, nameKey) {
    if (!state.searchNodes || !state.searchNodes.length) {
      return originalUniquePathOptions(idKey, nameKey);
    }
    if (idKey === "src") {
      return state.searchNodes
        .filter(node => ["User", "Group", "Computer"].includes(node.type) && !state.highValue.has(String(node.id)))
        .map(node => [String(node.id), node.name || String(node.id)])
        .sort((a, b) => String(a[1]).localeCompare(String(b[1])));
    }
    if (idKey === "target") {
      return state.searchNodes
        .filter(node => state.highValue.has(String(node.id)))
        .map(node => [String(node.id), node.name || String(node.id)])
        .sort((a, b) => String(a[1]).localeCompare(String(b[1])));
    }
    return originalUniquePathOptions(idKey, nameKey);
  };

  applyPathFilters = async function dynamicApplyPathFilters(showMessage) {
    rememberBasePaths();
    if (state.query.source === "all" || basePaths === null) {
      if (basePaths !== null) state.paths = basePaths.slice();
      return originalApplyPathFilters(showMessage);
    }

    const sequence = ++requestSequence;
    const runButton = document.getElementById("run-path-query");
    if (runButton) {
      runButton.disabled = true;
      runButton.textContent = localStorage.getItem("serket.language") === "es" ? "Calculando…" : "Computing…";
    }

    try {
      const response = await fetch("/api/query-paths", {
        method: "POST",
        cache: "no-store",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          source: state.query.source,
          target: state.query.target,
          max_hops: state.query.maxHops,
          include_edge: state.query.edge,
          limit: 25
        })
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const result = await response.json();
      if (sequence !== requestSequence) return;

      const dynamicPaths = Array.isArray(result.paths) ? result.paths : [];
      state.paths = basePaths.slice();
      const firstDynamicIndex = state.paths.length;
      state.paths.push(...dynamicPaths);
      state.filteredPaths = dynamicPaths;

      if (!dynamicPaths.length) {
        state.activePathIndex = -1;
        clearPathView();
      } else {
        state.activePathIndex = firstDynamicIndex;
        renderPath(state.paths[firstDynamicIndex]);
      }
      if (state.activeView === "paths") renderPathContext();
      state.graphDrawn = false;

      if (showMessage) {
        const spanish = localStorage.getItem("serket.language") === "es";
        showToast(spanish
          ? dynamicPaths.length + " rutas calculadas sobre el grafo cargado."
          : dynamicPaths.length + " paths computed over the loaded graph.");
      }
    } catch (error) {
      console.error("Serket path query", error);
      state.paths = basePaths.slice();
      state.filteredPaths = [];
      state.activePathIndex = -1;
      clearPathView();
      showToast(localStorage.getItem("serket.language") === "es"
        ? "No se pudo calcular la ruta sobre el grafo cargado."
        : "The path could not be computed over the loaded graph.");
    } finally {
      const currentButton = document.getElementById("run-path-query");
      if (currentButton) {
        currentButton.disabled = false;
        currentButton.textContent = localStorage.getItem("serket.language") === "es" ? "Aplicar consulta" : "Run query";
      }
    }
  };
})();
