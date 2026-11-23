/* Serket Query Console — SKQL: Serket Query Language.
   Client-side graph queries over the loaded bundle. No traffic to AD. */
(function () {
  "use strict";

  /* ── Tokenizer ─────────────────────────────────────────────────────────── */

  const KEYWORDS = new Set([
    "MATCH", "WHERE", "RETURN", "ORDER", "BY", "LIMIT", "AS",
    "AND", "OR", "NOT", "CONTAINS", "STARTS", "ENDS", "WITH",
    "IS", "TRUE", "FALSE", "ASC", "DESC", "COUNT",
  ]);

  function tokenize(src) {
    const tokens = [];
    let i = 0;
    const push = (type, value) => tokens.push({ type, value });
    while (i < src.length) {
      const c = src[i];
      if (/\s/.test(c)) { i++; continue; }
      if (c === '"') {
        let j = i + 1, out = "";
        while (j < src.length && src[j] !== '"') {
          if (src[j] === "\\" && j + 1 < src.length) { out += src[j + 1]; j += 2; }
          else { out += src[j]; j++; }
        }
        if (j >= src.length) throw new Error("Unterminated string literal");
        push("string", out); i = j + 1; continue;
      }
      if (/[0-9]/.test(c)) {
        let j = i;
        while (j < src.length && /[0-9.]/.test(src[j])) j++;
        push("number", parseFloat(src.slice(i, j))); i = j; continue;
      }
      if (/[A-Za-z_]/.test(c)) {
        let j = i;
        while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
        const word = src.slice(i, j);
        push(KEYWORDS.has(word.toUpperCase()) ? "keyword" : "ident", word);
        i = j; continue;
      }
      const two = src.slice(i, i + 2);
      if (["==", "!=", ">=", "<=", "->", "<-"].includes(two)) { push("op", two); i += 2; continue; }
      if ("()[]:,.*".includes(c)) { push("punct", c); i++; continue; }
      if ("=<>!".includes(c)) { push("op", c); i++; continue; }
      if ("-+/%".includes(c)) { push("op", c); i++; continue; }
      throw new Error(`Unexpected character "${c}" at position ${i}`);
    }
    return tokens;
  }

  /* ── Parser ────────────────────────────────────────────────────────────── */

  function parse(tokens) {
    let pos = 0;
    const peek = () => tokens[pos];
    const next = () => tokens[pos++];
    const expect = (type, value) => {
      const t = next();
      if (!t || t.type !== type || (value !== undefined && t.value !== value))
        throw new Error(`Expected ${value || type} but found ${t ? JSON.stringify(t.value) : "end of query"}`);
      return t;
    };
    const isKw = (v) => { const t = peek(); return t && t.type === "keyword" && t.value.toUpperCase() === v; };

    if (!isKw("MATCH")) throw new Error("Query must start with MATCH");
    next();

    /* pattern: (a:Type)-[r:Rel]->(b:Type)-... */
    const pattern = [];
    const node = () => {
      expect("punct", "(");
      let variable = null, type = null;
      const t = peek();
      if (t && t.type === "ident") { variable = next().value; if (peek() && peek().value === ":") { next(); type = expect("ident").value; } }
      else if (t && t.value === ":") { next(); type = expect("ident").value; }
      expect("punct", ")");
      return { kind: "node", variable, type };
    };
    const edge = () => {
      if (peek() && peek().type === "op" && peek().value === "-") next();
      expect("punct", "[");
      let variable = null, type = null, any = false;
      const t = peek();
      if (t && t.type === "ident") { variable = next().value; if (peek() && peek().value === ":") { next(); type = expect("ident").value; } }
      else if (t && t.value === "*") { next(); any = true; }
      else if (t && t.value === ":") { next(); type = expect("ident").value; }
      expect("punct", "]");
      if (peek() && peek().type === "op" && peek().value === "-") next();
      const dir = peek() && peek().value === "->" ? next().value : (peek() && peek().value === "<-" ? next().value : "--");
      return { kind: "edge", variable, type, any, dir };
    };
    pattern.push(node());
    while (peek() && (peek().value === "[" || (peek().type === "op" && peek().value === "-"))) { pattern.push(edge()); pattern.push(node()); }

    let where = null;
    if (isKw("WHERE")) { next(); where = parseExpr(); }

    expect("keyword", "RETURN");
    const returns = [];
    let countStar = false;
    do {
      if (isKw("COUNT")) {
        next(); expect("punct", "("); expect("punct", "*"); expect("punct", ")");
        countStar = true;
        let alias = null;
        if (isKw("AS")) { next(); alias = expect("ident").value; }
        returns.push({ kind: "count", alias });
        continue;
      }
      const target = expect("ident").value;
      let prop = null;
      if (peek() && peek().value === ".") { next(); prop = expect("ident").value; }
      let alias = null;
      if (isKw("AS")) { next(); alias = expect("ident").value; }
      returns.push({ kind: "field", target, prop, alias, text: prop ? `${target}.${prop}` : target });
    } while (peek() && peek().value === "," && next());

    let orderBy = null, limit = 100;
    if (isKw("ORDER")) { next(); expect("keyword", "BY"); const t = expect("ident").value; let prop = null; if (peek() && peek().value === ".") { next(); prop = expect("ident").value; } let dir = "ASC"; const d = peek(); if (d && /^(ASC|DESC)$/i.test(d.value)) dir = next().value.toUpperCase(); orderBy = { target: t, prop, dir }; }
    if (isKw("LIMIT")) { next(); limit = expect("number").value; }

    function parseExpr() {
      return parseOr();
    }
    function parseOr() {
      let left = parseAnd();
      while (isKw("OR")) { next(); left = { kind: "or", left, right: parseAnd() }; }
      return left;
    }
    function parseAnd() {
      let left = parseNot();
      while (isKw("AND")) { next(); left = { kind: "and", left, right: parseNot() }; }
      return left;
    }
    function parseNot() {
      if (isKw("NOT")) { next(); return { kind: "not", expr: parseNot() }; }
      return parseAtom();
    }
    function parseAtom() {
      if (peek() && peek().value === "(") { next(); const e = parseExpr(); expect("punct", ")"); return e; }
      const operand = parseOperand();
      if (isKw("IS")) {
        next();
        let negate = false;
        if (isKw("NOT")) { next(); negate = true; }
        const truth = isKw("TRUE") ? (next(), true) : (expect("keyword", "FALSE"), false);
        return { kind: "is", operand, value: negate ? !truth : truth };
      }
      if (isKw("CONTAINS")) { next(); return { kind: "cmp", op: "contains", left: operand, right: parseOperand() }; }
      if (isKw("STARTS")) { next(); expect("keyword", "WITH"); return { kind: "cmp", op: "starts", left: operand, right: parseOperand() }; }
      if (isKw("ENDS")) { next(); expect("keyword", "WITH"); return { kind: "cmp", op: "ends", left: operand, right: parseOperand() }; }
      const t = next();
      if (!t || t.type !== "op" || ["->", "<-", "-", "+", "/", "%"].includes(t.value))
        throw new Error("Expected a comparison operator in WHERE clause");
      const op = t.value === "==" ? "=" : t.value;
      return { kind: "cmp", op, left: operand, right: parseOperand() };
    }
    function parseOperand() {
      const t = next();
      if (!t) throw new Error("Unexpected end of WHERE clause");
      if (t.type === "number") return { kind: "literal", value: t.value };
      if (t.type === "string") return { kind: "literal", value: t.value };
      if (t.type === "keyword" && (t.value.toUpperCase() === "TRUE" || t.value.toUpperCase() === "FALSE"))
        return { kind: "literal", value: t.value.toUpperCase() === "TRUE" };
      if (t.type === "ident") {
        let prop = null;
        if (peek() && peek().value === ".") { next(); prop = expect("ident").value; }
        return prop ? { kind: "ref", target: t.value, prop } : { kind: "ref", target: t.value, prop: null };
      }
      throw new Error(`Unexpected token "${t.value}" in WHERE clause`);
    }

    return { pattern, where, returns, countStar, orderBy, limit: Math.min(limit, 1000) };
  }

  /* ── Evaluator ─────────────────────────────────────────────────────────── */

  let graphCache = null;

  async function loadGraph() {
    if (graphCache) return graphCache;
    const res = await fetch("/api/graph");
    if (!res.ok) throw new Error("Could not load the graph from the local API");
    const data = await res.json();
    const nodes = data.nodes || [];
    const edges = data.edges || [];
    graphCache = {
      nodes,
      edges,
      byId: new Map(nodes.map(n => [n.id, n])),
    };
    return graphCache;
  }

  function resolveRef(bindings, ref) {
    const obj = bindings.get(ref.target);
    if (obj == null) throw new Error(`Unknown variable "${ref.target}"`);
    if (ref.prop === null) return obj;
    return obj[ref.prop];
  }

  function evalWhere(expr, bindings) {
    switch (expr.kind) {
      case "and": return evalWhere(expr.left, bindings) && evalWhere(expr.right, bindings);
      case "or": return evalWhere(expr.left, bindings) || evalWhere(expr.right, bindings);
      case "not": return !evalWhere(expr.expr, bindings);
      case "is": return Boolean(resolveRef(bindings, expr.operand)) === expr.value;
      case "cmp": {
        const l = resolveRef(bindings, expr.left);
        let r = expr.right.kind === "literal" ? expr.right.value
              : expr.right.kind === "ref" ? resolveRef(bindings, expr.right)
              : undefined;
        const ls = l == null ? "" : String(l);
        const rs = r == null ? "" : String(r);
        switch (expr.op) {
          case "=": return ls.toLowerCase() === rs.toLowerCase();
          case "!=": return ls.toLowerCase() !== rs.toLowerCase();
          case ">": return Number(l) > Number(r);
          case "<": return Number(l) < Number(r);
          case ">=": return Number(l) >= Number(r);
          case "<=": return Number(l) <= Number(r);
          case "contains": return ls.toLowerCase().includes(rs.toLowerCase());
          case "starts": return ls.toLowerCase().startsWith(rs.toLowerCase());
          case "ends": return ls.toLowerCase().endsWith(rs.toLowerCase());
          default: return false;
        }
      }
    }
    return true;
  }

  function nodeMatches(node, pat) {
    if (pat.type && String(node.type).toLowerCase() !== pat.type.toLowerCase()) return false;
    return true;
  }

  function execute(query, graph) {
    const { pattern, where, returns, countStar, orderBy, limit } = parse(tokenize(query));
    const bindingsList = [];

    function extend(idx, bindings) {
      const pat = pattern[idx];
      if (pat.kind === "node") {
        for (const node of graph.nodes) {
          if (!nodeMatches(node, pat)) continue;
          if (pat.variable && bindings.has(pat.variable) && bindings.get(pat.variable) !== node) continue;
          const b = new Map(bindings);
          if (pat.variable) b.set(pat.variable, node);
          if (idx === pattern.length - 1) {
            if (!where || evalWhere(where, b)) bindingsList.push(b);
          } else {
            extend(idx + 1, b);
          }
        }
      } else {
        const fromPat = pattern[idx - 1];
        const toPat = pattern[idx + 1];
        const fromNode = bindings.get(fromPat.variable);
        if (!fromNode) { extend(idx + 1, bindings); return; }
        for (const edge of graph.edges) {
          const isOut = edge.source === fromNode.id;
          const isIn = edge.target === fromNode.id;
          const dir = pat.dir === "<-" ? isIn : pat.dir === "--" ? (isOut || isIn) : isOut;
          if (!dir) continue;
          if (pat.type && String(edge.type).toLowerCase() !== pat.type.toLowerCase()) continue;
          const otherId = isOut ? edge.target : edge.source;
          const otherNode = graph.byId.get(otherId);
          if (!otherNode || !nodeMatches(otherNode, toPat)) continue;
          if (toPat.variable && bindings.has(toPat.variable) && bindings.get(toPat.variable) !== otherNode) continue;
          const b = new Map(bindings);
          if (pat.variable) b.set(pat.variable, edge);
          b.set("__to__", otherNode);
          /* stash to-node under its variable for the next step */
          const b2 = new Map(b);
          if (toPat.variable) b2.set(toPat.variable, otherNode);
          /* continue from the next pattern element */
          if (idx + 1 === pattern.length - 1) {
            if (!where || evalWhere(where, b2)) bindingsList.push(b2);
          } else {
            extend(idx + 2, b2);
          }
        }
      }
    }
    extend(0, new Map());

    if (countStar) {
      const alias = (returns.find(r => r.kind === "count") || {}).alias || "count";
      return { columns: [alias], rows: [[bindingsList.length]], truncated: false };
    }

    const columns = returns.map(r => r.alias || (r.kind === "count" ? "count" : r.text));
    const rows = bindingsList.slice(0, limit).map(b => returns.map(r => {
      if (r.kind === "count") return bindingsList.length;
      const obj = b.get(r.target);
      if (obj == null) throw new Error(`Unknown variable "${r.target}" in RETURN`);
      if (r.prop === null) return obj.name || obj.id || JSON.stringify(obj);
      const v = obj[r.prop];
      return v == null ? "" : v;
    }));

    if (orderBy) {
      const colIdx = returns.findIndex(r => (r.alias || r.text) === (orderBy.prop ? `${orderBy.target}.${orderBy.prop}` : orderBy.target));
      if (colIdx >= 0) {
        rows.sort((a, b2) => {
          const x = a[colIdx], y = b2[colIdx];
          const nx = Number(x), ny = Number(y);
          const cmp = !isNaN(nx) && !isNaN(ny) ? nx - ny : String(x).localeCompare(String(y));
          return orderBy.dir === "DESC" ? -cmp : cmp;
        });
      }
    }
    return { columns, rows, truncated: bindingsList.length > limit };
  }

  /* ── Console UI ────────────────────────────────────────────────────────── */

  const EXAMPLES = [
    { label: "All identities", query: 'MATCH (n) RETURN n.type, n.name LIMIT 50' },
    { label: "Users matching a name", query: 'MATCH (u:User) WHERE n.name CONTAINS "svc" RETURN u.name LIMIT 25'.replace("n.name", "u.name") },
    { label: "Paths into high-value groups", query: 'MATCH (a)-[e]->(g:Group) WHERE g.high_value = true RETURN a.name, e.type, g.name, e.opsec_score ORDER BY e.opsec_score DESC LIMIT 25' },
    { label: "DCSync-capable principals", query: 'MATCH (a)-[e:DCSync]->(b) RETURN a.name, b.name, e.detail LIMIT 25' },
    { label: "Kerberoastable accounts", query: 'MATCH (u:User)-[e:Kerberoastable]->(b) RETURN u.name, e.detail LIMIT 25' },
    { label: "Loudest edges (OPSEC)", query: 'MATCH (a)-[e]->(b) WHERE e.opsec_score > 1 RETURN a.name, e.type, b.name, e.opsec_score ORDER BY e.opsec_score DESC LIMIT 25' },
  ];

  function init() {
    const root = document.getElementById("query-console");
    if (!root) return;
    const input = root.querySelector("#qc-input");
    const runBtn = root.querySelector("#qc-run");
    const closeBtn = root.querySelector("#qc-close");
    const examples = root.querySelector("#qc-examples");
    const status = root.querySelector("#qc-status");
    const results = root.querySelector("#qc-results");

    examples.innerHTML = EXAMPLES.map((e, i) => `<option value="${i}">${e.label}</option>`).join("");
    examples.addEventListener("change", () => { input.value = EXAMPLES[Number(examples.value)].query; input.focus(); });

    async function run() {
      const query = input.value.trim();
      if (!query) return;
      runBtn.disabled = true;
      status.textContent = "Running…";
      results.innerHTML = "";
      const started = performance.now();
      try {
        const graph = await loadGraph();
        const { columns, rows, truncated } = execute(query, graph);
        const ms = Math.round(performance.now() - started);
        status.textContent = `${rows.length} row${rows.length === 1 ? "" : "s"} · ${ms} ms · local graph (${graph.nodes.length} nodes)` + (truncated ? " · truncated at LIMIT" : "");
        if (!rows.length) { results.innerHTML = '<div class="qc-empty">No results.</div>'; return; }
        const head = columns.map(c => `<th>${escapeHtml(c)}</th>`).join("");
        const body = rows.map(r => "<tr>" + r.map(v => `<td>${escapeHtml(String(v))}</td>`).join("") + "</tr>").join("");
        results.innerHTML = `<table class="qc-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
        saveHistory(query);
      } catch (err) {
        status.textContent = "Query error";
        results.innerHTML = `<div class="qc-error">${escapeHtml(err.message)}</div>`;
      } finally {
        runBtn.disabled = false;
      }
    }

    runBtn.addEventListener("click", run);
    input.addEventListener("keydown", e => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });
    closeBtn.addEventListener("click", () => root.classList.remove("open"));

    /* trigger button in topbar */
    const trigger = document.getElementById("console-button");
    if (trigger) trigger.addEventListener("click", () => {
      root.classList.add("open");
      loadGraph().catch(() => {});
      input.focus();
    });

    renderHistory();
    function saveHistory(q) {
      try {
        const h = JSON.parse(localStorage.getItem("serket.skql.history") || "[]").filter(x => x !== q);
        h.unshift(q);
        localStorage.setItem("serket.skql.history", JSON.stringify(h.slice(0, 12)));
        renderHistory();
      } catch (_) {}
    }
    function renderHistory() {
      let h = [];
      try { h = JSON.parse(localStorage.getItem("serket.skql.history") || "[]"); } catch (_) {}
      const sel = root.querySelector("#qc-history");
      sel.innerHTML = '<option value="">History…</option>' + h.map((q, i) => `<option value="${i}">${q.length > 60 ? q.slice(0, 60) + "…" : q}</option>`).join("");
      sel.onchange = () => { if (sel.value !== "") { input.value = h[Number(sel.value)]; input.focus(); } };
    }
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
