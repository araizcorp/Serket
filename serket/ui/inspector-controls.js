"use strict";

(() => {
  const shell = document.getElementById("app-shell");
  const inspector = document.getElementById("inspector");
  const header = inspector && inspector.querySelector(".inspector-header");
  if (!shell || !inspector || !header) return;

  const closeButton = document.createElement("button");
  closeButton.id = "inspector-close";
  closeButton.className = "inspector-close";
  closeButton.type = "button";
  closeButton.setAttribute("aria-label", localStorage.getItem("serket.language") === "es" ? "Cerrar inspector" : "Close inspector");
  closeButton.innerHTML = '<span aria-hidden="true">×</span>';
  header.appendChild(closeButton);

  function closeInspector() {
    shell.classList.add("inspector-collapsed");
    inspector.setAttribute("aria-hidden", "true");
    closeButton.setAttribute("aria-expanded", "false");
  }

  function openInspector() {
    shell.classList.remove("inspector-collapsed");
    inspector.removeAttribute("aria-hidden");
    closeButton.setAttribute("aria-expanded", "true");
  }

  closeButton.addEventListener("click", closeInspector);
  document.addEventListener("click", event => {
    const graphSelection = event.target.closest(".graph-node,.graph-edge");
    const explorerActive = document.getElementById("explorer-view")?.classList.contains("active");
    const explorerSelection = graphSelection || event.target.closest(".search-result");
    if (explorerSelection && explorerActive) {
      closeInspector();
    } else if (event.target.closest(".flow-edge,.flow-node,.route-edge,.route-node,.search-result,.priority-row")) {
      openInspector();
    }
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !document.querySelector(".modal-backdrop.open")) closeInspector();
  });
})();
