"use strict";

(() => {
  const originalHandleSearch = handleSearch;
  let searchSequence = 0;

  handleSearch = async function apiBackedSearch() {
    const input = document.getElementById("global-search");
    const popover = document.getElementById("search-results");
    const query = input.value.trim();
    const sequence = ++searchSequence;
    state.searchCursor = -1;

    if (!query) {
      popover.hidden = true;
      popover.innerHTML = "";
      return;
    }

    popover.hidden = false;
    popover.innerHTML = '<div class="search-empty">' + (localStorage.getItem("serket.language") === "es" ? "Buscando en el grafo cargado…" : "Searching the loaded graph…") + '</div>';
    try {
      const response = await fetch("/api/search?q=" + encodeURIComponent(query) + "&limit=12", {cache: "no-store"});
      if (!response.ok) throw new Error("HTTP " + response.status);
      const body = await response.json();
      if (sequence !== searchSequence) return;
      const results = Array.isArray(body.results) ? body.results : [];
      results.forEach(node => state.nodeMap.set(String(node.id), node));
      popover.innerHTML = results.length ? results.map((node, index) =>
        '<button class="search-result" type="button" data-search-index="' + index + '" data-node-id="' + esc(node.id) + '">' +
          '<span class="search-result-icon" style="color:' + typeColor(node.type, state.highValue.has(String(node.id))) + '">' + esc(typeGlyph(node.type)) + '</span>' +
          '<span class="search-result-copy"><strong>' + esc(node.name || node.id) + '</strong><span>' + esc(node.id || "No identifier") + '</span></span>' +
          '<span class="search-result-type">' + esc(node.type || "OBJ") + '</span>' +
        '</button>'
      ).join("") : '<div class="search-empty">' + (localStorage.getItem("serket.language") === "es" ? "No se encontraron objetos en el grafo cargado." : "No objects were found in the loaded graph.") + '</div>';
      popover.querySelectorAll(".search-result").forEach(button => button.addEventListener("click", () => chooseSearchResult(button.dataset.nodeId)));
    } catch (error) {
      console.warn("Serket search API fallback", error);
      if (sequence === searchSequence) originalHandleSearch();
    }
  };
})();
