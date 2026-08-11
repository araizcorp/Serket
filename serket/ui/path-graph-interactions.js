"use strict";

(() => {
  const layouts = new Map();
  const SVG_NS = "http://www.w3.org/2000/svg";
  const originalRenderPathGraph = renderPath;

  function layoutKey(path) {
    return [path.src, path.target].concat((path.steps || []).map(step => step.edge_type)).join("|");
  }

  function iconMarkup(type) {
    const icons = {
      User: '<circle cx="0" cy="-11" r="8"></circle><path d="M-17 20c0-11 7-18 17-18s17 7 17 18"></path>',
      Group: '<circle cx="-11" cy="-8" r="6"></circle><circle cx="11" cy="-8" r="6"></circle><circle cx="0" cy="-15" r="7"></circle><path d="M-22 19c0-8 5-13 12-13M22 19c0-8-5-13-12-13M-15 20c0-10 6-16 15-16s15 6 15 16"></path>',
      Computer: '<rect x="-21" y="-17" width="42" height="29" rx="4"></rect><path d="M-8 21h16M0 12v9"></path>',
      Domain: '<rect x="-21" y="-20" width="42" height="16" rx="3"></rect><rect x="-21" y="4" width="42" height="16" rx="3"></rect><circle cx="14" cy="-12" r="2"></circle><circle cx="14" cy="12" r="2"></circle><path d="M-14-12h14M-14 12h14"></path>',
      CertTemplate: '<path d="M0-23 19-14v14c0 13-8 22-19 27C-11 22-19 13-19 0v-14Z"></path><path d="m-9 1 6 6L10-7"></path>',
      CA: '<path d="M0-22 18-13v13c0 12-7 21-18 26C-11 21-18 12-18 0v-13Z"></path><circle cx="0" cy="-3" r="7"></circle><path d="M-4 4-8 15 0 11 8 15 4 4"></path>',
      GPO: '<path d="M-20-16h40v32h-40z"></path><path d="M-12-7h24M-12 0h24M-12 7h15"></path>',
      OU: '<path d="M-22-14h17l5 6h22v26h-44z"></path>'
    };
    return icons[type] || '<path d="M0-22 21-10v22L0 22-21 12v-22Z"></path><path d="M-9 0h18M0-9v18"></path>';
  }

  function curve(x1, y1, x2, y2) {
    const direction = x2 >= x1 ? 1 : -1;
    const startX = x1 + 48 * direction;
    const endX = x2 - 48 * direction;
    const distance = Math.abs(x2 - x1);
    const lift = Math.min(76, Math.max(34, distance * .2));
    const control = Math.max(54, distance * .36);
    return "M " + startX + " " + y1 + " C " + (startX + control * direction) + " " + (y1 - lift) + ", " + (endX - control * direction) + " " + (y2 - lift) + ", " + endX + " " + y2;
  }

  function enhance(path) {
    const svg = document.querySelector(".route-graph");
    if (!svg) return;
    const nodes = Array.from(svg.querySelectorAll(".route-node"));
    const edges = Array.from(svg.querySelectorAll(".route-edge"));
    const key = layoutKey(path);
    const saved = layouts.get(key) || new Map();
    const positions = [];

    nodes.forEach((node, index) => {
      const glyph = node.querySelector(".route-node-glyph");
      const baseX = Number(glyph && glyph.getAttribute("x")) || 110 + index * 250;
      const baseY = Number(glyph && glyph.getAttribute("y")) - 4 || 245;
      const stored = saved.get(String(node.dataset.routeNode));
      const position = stored || {x: baseX, y: baseY};
      positions[index] = {baseX, baseY, x: position.x, y: position.y};
      node.dataset.routeIndex = String(index);
      node.setAttribute("transform", "translate(" + (position.x - baseX) + " " + (position.y - baseY) + ")");

      if (glyph) {
        const icon = document.createElementNS(SVG_NS, "g");
        icon.setAttribute("class", "route-node-icon");
        icon.setAttribute("transform", "translate(" + baseX + " " + baseY + ")");
        const full = state.nodeMap.get(String(node.dataset.routeNode)) || {};
        icon.innerHTML = iconMarkup(full.type);
        glyph.replaceWith(icon);
      }
    });

    function updateEdges() {
      edges.forEach((edge, index) => {
        const source = positions[index];
        const target = positions[index + 1];
        if (!source || !target) return;
        const d = curve(source.x, source.y, target.x, target.y);
        edge.querySelectorAll(".route-edge-line,.route-edge-hit").forEach(item => item.setAttribute("d", d));
        const middleX = (source.x + target.x) / 2;
        const middleY = (source.y + target.y) / 2 - 35;
        const label = edge.querySelector(".route-edge-label");
        const activity = edge.querySelector(".route-activity");
        if (label) label.setAttribute("transform", "translate(" + middleX + " " + middleY + ")");
        if (activity) activity.setAttribute("transform", "translate(" + middleX + " " + (middleY + 57) + ")");
      });
    }

    updateEdges();
    let drag = null;

    function point(event) {
      const matrix = svg.getScreenCTM();
      if (!matrix) return {x: event.clientX, y: event.clientY};
      return new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
    }

    nodes.forEach(node => {
      node.addEventListener("pointerdown", event => {
        if (event.button !== 0) return;
        const index = Number(node.dataset.routeIndex);
        const start = point(event);
        drag = {node, index, start, x: positions[index].x, y: positions[index].y, moved: false, pointerId: event.pointerId};
        svg.setPointerCapture(event.pointerId);
        node.classList.add("dragging");
        event.preventDefault();
      });
      node.addEventListener("click", event => {
        if (node.dataset.dragged === "true") {
          event.preventDefault();
          event.stopImmediatePropagation();
          node.dataset.dragged = "false";
        }
      }, true);
    });

    svg.addEventListener("pointermove", event => {
      if (!drag || event.pointerId !== drag.pointerId) return;
      const current = point(event);
      const dx = current.x - drag.start.x;
      const dy = current.y - drag.start.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      const width = svg.viewBox.baseVal.width;
      const height = svg.viewBox.baseVal.height;
      const nextX = Math.max(55, Math.min(width - 55, drag.x + dx));
      const nextY = Math.max(90, Math.min(height - 105, drag.y + dy));
      positions[drag.index].x = nextX;
      positions[drag.index].y = nextY;
      drag.node.setAttribute("transform", "translate(" + (nextX - positions[drag.index].baseX) + " " + (nextY - positions[drag.index].baseY) + ")");
      updateEdges();
    });

    function endDrag(event) {
      if (!drag || event.pointerId !== drag.pointerId) return;
      drag.node.classList.remove("dragging");
      drag.node.dataset.dragged = drag.moved ? "true" : "false";
      if (drag.moved) {
        if (!layouts.has(key)) layouts.set(key, new Map());
        layouts.get(key).set(String(drag.node.dataset.routeNode), {x: positions[drag.index].x, y: positions[drag.index].y});
      }
      try { svg.releasePointerCapture(event.pointerId); } catch (_) {}
      drag = null;
    }

    svg.addEventListener("pointerup", endDrag);
    svg.addEventListener("pointercancel", endDrag);
  }

  renderPath = function renderInteractivePath(path) {
    originalRenderPathGraph(path);
    enhance(path);
  };
})();
