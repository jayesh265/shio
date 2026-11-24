/* Shio Guard Monitor: a read-only dashboard over the console's JSON API.
 *
 * Every value from the API is put on the page with textContent (through h()), never innerHTML, so nothing in a
 * record, a card or a pack can run here; the content security policy allows scripts from this console only.
 * Views poll their API sections every REFRESH_MS while the tab is visible, and the pause is honoured when the user
 * turns auto-refresh off. No libraries, no build step. */
"use strict";

const REFRESH_MS = 10000;
const SVG = "http://www.w3.org/2000/svg";

/* ---------------- DOM helpers ---------------- */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") el.style.cssText = v;            // CSSOM, which the CSP allows (a style attribute it would not)
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, kids);
  return el;
}
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, String(v));
  for (const k of kids.flat()) if (k) el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}
const $ = (sel) => document.querySelector(sel);

/* ---------------- formatting ---------------- */
const fmt = {
  n: (x) => (x === null || x === undefined ? "–" : Number(x).toLocaleString()),
  pct: (x, d = 0) => (x === null || x === undefined ? "–" : `${(x * 100).toFixed(d)}%`),
  num: (x, d = 3) => (x === null || x === undefined ? "–" : Number(x).toFixed(d)),
  time: (t) => (t ? new Date(t * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "–"),
  day: (d) => (d ? new Date(d + "T12:00:00").toLocaleDateString([], { month: "short", day: "numeric" }) : "–"),
  ago: (ms) => {
    const sec = Math.round(ms / 1000);
    return sec < 5 ? "just now" : sec < 60 ? `${sec}s ago` : `${Math.round(sec / 60)}m ago`;
  },
};
const STATUS = {
  ok: "ok", warn: "warn", fail: "fail", none: "none",
  APPROVED: "ok", EVIDENCED: "ok", PROVEN: "ok", VERIFIED: "ok", CLOSED: "ok", MITIGATED: "ok", reviewed: "ok",
  compliant: "ok", allowed: "ok", approved: "ok",
  PENDING: "warn", OPEN: "fail", INVESTIGATING: "warn", GAP: "fail", MISSING: "fail", FAILED: "fail",
  REJECTED: "fail", draft: "warn", research: "none", denied: "fail", "held for approval": "warn",
  NOT_APPLICABLE: "none", low: "none", moderate: "warn", high: "fail", critical: "fail",
};
const LABEL = { ok: "OK", warn: "Attention", fail: "Failing", none: "No data" };
function pill(text, kind) {
  return h("span", { class: `pill ${kind || STATUS[text] || "info"}` }, text);
}
function statusPill(st) { return pill(LABEL[st] || st, st); }
function meter(rate) {
  if (rate === null || rate === undefined) return h("span", { class: "faint" }, "–");
  const cls = rate >= 0.95 ? "" : rate >= 0.8 ? "warn" : "fail";
  return h("div", { class: "meter" },
    h("div", { class: "track" }, h("div", { class: `fill ${cls}`, style: `width:${Math.max(2, rate * 100)}%` })),
    h("span", {}, fmt.pct(rate)));
}
function chips(list, max = 6) {
  const items = (list || []).slice(0, max).map((x) => h("span", { class: "chip" }, x));
  if ((list || []).length > max) items.push(h("span", { class: "faint" }, `+${list.length - max}`));
  return h("div", { class: "chips" }, items);
}
function card(title, extra, ...body) {
  return h("section", { class: "card" },
    h("header", {}, h("h2", {}, title), extra || null),
    h("div", { class: "body" }, body));
}
function flushCard(title, extra, ...body) {
  return h("section", { class: "card" },
    h("header", {}, h("h2", {}, title), extra || null),
    h("div", { class: "body flush" }, body));
}
function kpi(label, value, note, cls, href) {
  return h(href ? "a" : "div", { class: `card kpi ${cls || ""}`, href },
    h("div", { class: "label" }, label), h("div", { class: "value" }, value), note ? h("div", { class: "note" }, note) : null);
}
function empty(text) { return h("div", { class: "empty" }, text); }

/* A table from column specs: {label, value(row) -> Node|string, num, sort(row)}. Sortable by clicking a header. */
function table(cols, rows, opts = {}) {
  const state = { key: opts.sortKey ?? null, dir: opts.sortDir ?? -1 };
  const wrap = h("div", { class: "table-wrap" });
  function draw() {
    let data = rows.slice();
    if (state.key !== null) {
      const c = cols[state.key];
      const get = c.sort || ((r) => { const v = c.value(r); return typeof v === "string" || typeof v === "number" ? v : ""; });
      data.sort((a, b) => { const x = get(a), y = get(b); return (x > y ? 1 : x < y ? -1 : 0) * state.dir; });
    }
    const head = h("tr", {}, cols.map((c, i) => h("th", {
      class: c.num ? "num" : null, scope: "col", "aria-sort": state.key === i ? (state.dir > 0 ? "ascending" : "descending") : null,
      style: c.sort !== false ? "cursor:pointer" : null,
      onclick: c.sort === false ? null : () => { state.dir = state.key === i ? -state.dir : -1; state.key = i; draw(); },
    }, c.label, state.key === i ? (state.dir > 0 ? " ▲" : " ▼") : "")));
    const body = h("tbody", {}, data.length ? data.map((r) => h("tr", {
      class: opts.onRow ? "clickable" : null, onclick: opts.onRow ? () => opts.onRow(r) : null,
    }, cols.map((c) => h("td", { class: c.num ? "num" : null }, c.value(r))))) :
      h("tr", {}, h("td", { colspan: cols.length }, empty(opts.empty || "Nothing here yet."))));
    wrap.replaceChildren(h("table", {}, h("thead", {}, head), body));
  }
  draw();
  return wrap;
}

/* ---------------- charts (SVG) ---------------- */
const tip = { el: null };
function showTip(evt, text) {
  if (!tip.el) { tip.el = h("div", { class: "tip", role: "tooltip" }); document.body.appendChild(tip.el); }
  tip.el.textContent = text;
  tip.el.style.left = `${evt.clientX}px`;
  tip.el.style.top = `${evt.clientY - 6}px`;
  tip.el.hidden = false;
}
function hideTip() { if (tip.el) tip.el.hidden = true; }

/* Stacked bars over days. series: [{key, label, color}], points: [{day, <key>: n}]. */
function stackedBars(points, series, { height = 180 } = {}) {
  const W = 760, H = height, padL = 34, padB = 22, padT = 8;
  const totals = points.map((p) => series.reduce((a, sr) => a + (p[sr.key] || 0), 0));
  const max = Math.max(1, ...totals);
  const step = niceStep(max);
  const top = Math.ceil(max / step) * step;
  const bw = (W - padL) / Math.max(points.length, 1);
  const y = (v) => H - padB - ((H - padB - padT) * v) / top;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img",
    "aria-label": `${series.map((x) => x.label).join(", ")} per day` });
  for (let v = 0; v <= top; v += step) {
    svg.appendChild(s("line", { x1: padL, x2: W, y1: y(v), y2: y(v), class: "grid-line" }));
    svg.appendChild(s("text", { x: padL - 6, y: y(v) + 3, "text-anchor": "end" }, String(v)));
  }
  points.forEach((p, i) => {
    let acc = 0;
    const x = padL + i * bw;
    for (const sr of series) {
      const v = p[sr.key] || 0;
      if (v) {
        svg.appendChild(s("rect", { x: x + bw * 0.15, width: bw * 0.7, y: y(acc + v), height: y(acc) - y(acc + v),
          fill: sr.color, rx: 1.5 }));
      }
      acc += v;
    }
    const every = Math.ceil(points.length / 8);
    if (i % every === 0 || (i === points.length - 1 && i % every >= every / 2)) {
      svg.appendChild(s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" }, fmt.day(p.day)));
    }
    const hit = s("rect", { x, y: padT, width: bw, height: H - padB - padT, class: "hit" });
    const text = `${fmt.day(p.day)}\n` + series.map((sr) => `${sr.label}: ${p[sr.key] || 0}`).join("\n");
    hit.addEventListener("mousemove", (e) => showTip(e, text));
    hit.addEventListener("mouseleave", hideTip);
    svg.appendChild(hit);
  });
  const legend = h("div", { class: "legend" }, series.map((sr) => h("span", {}, h("i", { style: `background:${sr.color}` }), sr.label)));
  return h("div", { class: "stack", style: "gap:8px" }, svg, legend);
}
function niceStep(max) {
  const raw = max / 4, mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  return [1, 2, 5, 10].map((m) => m * mag).find((m) => m >= raw) || mag;
}
/* A small bar sparkline of failures per day. */
function sparkline(series, key = "failed") {
  const W = 120, H = 26, max = Math.max(1, ...series.map((p) => p[key] || 0)), bw = W / Math.max(series.length, 1);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, class: "spark", "aria-hidden": "true" });
  series.forEach((p, i) => {
    const v = p[key] || 0, run = (p.passed || 0) + (p.failed || 0);
    const hgt = v ? Math.max(2, (H - 2) * (v / max)) : run ? 1 : 0;
    if (hgt) svg.appendChild(s("rect", { x: i * bw + 0.5, width: Math.max(1, bw - 1), y: H - hgt, height: hgt,
      fill: v ? "var(--fail-bar)" : "var(--line-2)" }));
  });
  return svg;
}
function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
const COLORS = () => ({ pass: css("--pass-bar"), fail: css("--fail-bar"), held: css("--held-bar"), appr: css("--approved-bar") });

/* ---------------- data ---------------- */
const api = {
  cache: new Map(),
  async get(section, params) {
    const qs = params ? "?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null)) : "";
    const res = await fetch(`/api/${section}${qs}`, { headers: { Accept: "application/json" }, cache: "no-store" });
    const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    this.cache.set(section + qs, body);
    return body;
  },
};

/* ---------------- views ---------------- */
const VIEWS = {};
function view(id, title, sections, render, subtitle) { VIEWS[id] = { id, title, sections, render, subtitle }; }

view("overview", "Overview", ["summary"], ({ summary: d }) => {
  const k = d.kpis, c = COLORS();
  const passRate = k.check_runs ? (k.check_runs - k.check_failures) / k.check_runs : null;
  const counts = d.counts || {};
  const byArea = {};
  d.checkpoints.forEach((cp) => (byArea[cp.area] = byArea[cp.area] || []).push(cp));
  const order = { fail: 0, warn: 1, ok: 2, none: 3 };
  const sorted = d.checkpoints.slice().sort((a, b) => order[a.status] - order[b.status]);
  return [
    h("div", { class: "grid kpis" },
      kpi("Decisions", fmt.n(k.decisions), "in the ledger", "", "#/decisions"),
      kpi("Check pass rate", fmt.pct(passRate, 1), `${fmt.n(k.check_failures)} failures of ${fmt.n(k.check_runs)}`,
        passRate === null ? "" : passRate >= 0.95 ? "ok" : passRate >= 0.8 ? "warn" : "fail", "#/checks"),
      kpi("Waiting for sign-off", fmt.n(k.pending_signoffs), k.overdue_signoffs ? `${k.overdue_signoffs} overdue` : "none overdue",
        k.overdue_signoffs ? "fail" : k.pending_signoffs ? "warn" : "ok", "#/decisions"),
      kpi("Open incidents", fmt.n(k.open_incidents), `${fmt.n(k.alerts)} monitor alert(s)`,
        k.open_incidents ? "fail" : k.alerts ? "warn" : "ok", "#/monitoring"),
      kpi("Tool calls stopped or held", fmt.n(k.gate_stopped), `of ${fmt.n(k.gate_decisions)} gated`, "", "#/gates"),
      kpi("Controls", fmt.n(k.controls), `in ${k.packs} packs`, "", "#/packs")),
    card("Checkpoints", h("div", { class: "summary-bar" },
      ["fail", "warn", "ok", "none"].filter((x) => counts[x]).map((x) => h("span", {}, statusPill(x), " ", counts[x]))),
      h("div", { class: "checkpoints" }, sorted.map((cp) => h("a", { class: `cp ${cp.status}`, href: `#/${cp.tab}` },
        statusPill(cp.status), h("span", { class: "area" }, cp.area), h("span", { class: "t" }, cp.title),
        h("span", { class: "d" }, cp.detail))))),
    h("div", { class: "grid cols-2" },
      card("Check runs, last 30 days", null, stackedBars(d.daily, [
        { key: "passed", label: "Passed", color: c.pass }, { key: "failed", label: "Failed", color: c.fail }])),
      flushCard("Waiting for a person", h("a", { href: "#/decisions?signoff=PENDING" }, "All decisions"),
        table([
          { label: "Record", value: (r) => h("span", { class: "mono" }, r.file) },
          { label: "Agent", value: (r) => r.agent || "–" },
          { label: "Roles", value: (r) => r.roles.join(", ") },
          { label: "Days", value: (r) => String(r.age_days), num: true, sort: (r) => r.age_days },
        ], d.pending, { empty: "No decision is waiting for sign-off." }))),
  ];
});

view("checks", "Checks", ["checks"], ({ checks: d }, ui) => {
  const q = (ui.q || "").toLowerCase();
  const rows = d.checks.filter((c) => !q || c.key.toLowerCase().includes(q) || c.controls.join(" ").toLowerCase().includes(q));
  const c = COLORS();
  const search = h("input", { type: "search", placeholder: "Filter checks or controls", value: ui.q || "",
    oninput: (e) => { ui.q = e.target.value; rerender(); }, "aria-label": "Filter checks" });
  return [
    card("Every check, every run, last 30 days", null, stackedBars(d.daily, [
      { key: "passed", label: "Passed", color: c.pass }, { key: "failed", label: "Failed", color: c.fail }], { height: 150 })),
    flushCard(`Checks (${rows.length})`, h("div", { class: "filters" }, search),
      table([
        { label: "Check", value: (r) => h("div", {}, h("strong", {}, r.check), h("span", { class: "sub" }, r.agent)), sort: (r) => r.key },
        { label: "Runs", value: (r) => fmt.n(r.runs), num: true, sort: (r) => r.runs },
        { label: "Pass rate", value: (r) => meter(r.pass_rate), sort: (r) => r.pass_rate ?? 2 },
        { label: "Failed", value: (r) => fmt.n(r.failed), num: true, sort: (r) => r.failed },
        { label: "Failures, 30 days", value: (r) => sparkline(r.series), sort: false },
        { label: "Top reasons", value: (r) => r.codes.length ? chips(r.codes.map(([k, n]) => `${k} ×${n}`), 3) : h("span", { class: "faint" }, "–"), sort: false },
        { label: "Controls", value: (r) => r.controls.length ? chips(r.controls, 3) : h("span", { class: "faint" }, "none cited"), sort: false },
        { label: "Last failure", value: (r) => r.last_failure ? h("div", {}, fmt.day(r.last_failure.day),
          h("span", { class: "sub mono" }, r.last_failure.record)) : h("span", { class: "faint" }, "never"), sort: (r) => r.last_failure?.day || "" },
      ], rows, { sortKey: 2, sortDir: 1, empty: "No checks have run." })),
  ];
});

view("decisions", "Decisions", [], async (_, ui) => {
  const params = { limit: 50, offset: ui.offset || 0, agent: ui.agent || "", status: ui.status || "", failed: ui.failed ? 1 : "", q: ui.q || "" };
  const d = await api.get("decisions", params);
  const agent = h("select", { "aria-label": "Agent", onchange: (e) => { ui.agent = e.target.value; ui.offset = 0; rerender(); } },
    h("option", { value: "" }, "All agents"), d.agents.map((a) => h("option", { value: a, selected: ui.agent === a }, a)));
  const status = h("select", { "aria-label": "Status", onchange: (e) => { ui.status = e.target.value; ui.offset = 0; rerender(); } },
    ["", "PENDING", "APPROVED", "REJECTED"].map((x) => h("option", { value: x, selected: (ui.status || "") === x }, x ? `Sign-off ${x.toLowerCase()}` : "Any sign-off")));
  const failed = h("label", { class: "toggle" }, h("input", { type: "checkbox", checked: !!ui.failed,
    onchange: (e) => { ui.failed = e.target.checked; ui.offset = 0; rerender(); } }), "Failed checks only");
  const search = h("input", { type: "search", placeholder: "Record, check or outcome", value: ui.q || "", "aria-label": "Search decisions",
    onchange: (e) => { ui.q = e.target.value; ui.offset = 0; rerender(); } });
  const page = Math.floor(params.offset / params.limit) + 1, pages = Math.max(1, Math.ceil(d.total / params.limit));
  return [flushCard(`Decisions (${fmt.n(d.total)})`, h("div", { class: "filters" }, search, agent, status, failed),
    table([
      { label: "When", value: (r) => fmt.time(r.time), sort: (r) => r.time },
      { label: "Record", value: (r) => h("a", { href: `/record/${encodeURIComponent(r.file)}`, class: "mono" }, r.file), sort: (r) => r.file },
      { label: "Agent", value: (r) => r.agent || "–" },
      { label: "Type", value: (r) => r.type },
      { label: "Outcome", value: (r) => h("div", {}, r.decided, r.outcome !== r.decided ? h("span", { class: "sub" }, r.outcome) : null) },
      { label: "Checks", value: (r) => r.failed.length ? h("div", {}, pill(`${r.failed.length} of ${r.checks} failed`, "fail"),
        h("span", { class: "sub" }, r.failed.join(", "))) : r.checks ? pill(`${r.checks} passed`, "ok") : h("span", { class: "faint" }, "–"),
        sort: (r) => r.failed.length },
      { label: "Sign-off", value: (r) => r.signoff ? h("div", {}, pill(r.signoff), h("span", { class: "sub" }, r.roles.join(", "))) : h("span", { class: "faint" }, "not needed"), sort: (r) => r.signoff || "" },
      { label: "Label", value: (r) => r.label ? pill(r.label, r.label === "wrong" ? "fail" : "ok") : h("span", { class: "faint" }, "–") },
      { label: "Signed", value: (r) => r.signed ? pill("signed", "ok") : pill("unsigned", "warn"), sort: (r) => r.signed },
    ], d.rows, { empty: "No decisions match." }),
    h("div", { class: "pager" }, `Page ${page} of ${pages}`,
      h("button", { class: "btn", disabled: page <= 1, onclick: () => { ui.offset = Math.max(0, params.offset - params.limit); rerender(); } }, "Previous"),
      h("button", { class: "btn", disabled: page >= pages, onclick: () => { ui.offset = params.offset + params.limit; rerender(); } }, "Next")))];
});

function gateOutcome(r) {
  if (r.allowed) return r.approval && r.approval.approved ? "approved" : "allowed";
  return r.effect === "require_approval" ? "held for approval" : "denied";
}
view("gates", "Tool-call gates", ["gates", "policies"], ({ gates: g, policies: p }, ui) => {
  const c = COLORS();
  const by = g.by_effect || {};
  const filter = ui.outcome || "";
  const rows = g.entries.filter((r) => !filter || gateOutcome(r) === filter);
  const parts = [];
  if (!p.installed) parts.push(h("div", { class: "banner info" },
    "Microsoft Agent Governance Toolkit is not installed in this Python. Gate ledgers still show; install shio-lang[agt] to load and check policies."));
  parts.push(h("div", { class: "grid kpis" },
    kpi("Gated calls", fmt.n(g.total), `${g.chains.length} ledger(s)`),
    kpi("Allowed", fmt.n(by.allowed || 0), "by policy", "ok"),
    kpi("Approved by a person", fmt.n(by.approved || 0), "require_approval, then yes", ""),
    kpi("Held for approval", fmt.n(by["held for approval"] || 0), "no approval given", by["held for approval"] ? "warn" : ""),
    kpi("Denied", fmt.n(by.denied || 0), "by policy, Guard or fail-safe", by.denied ? "fail" : "")));
  parts.push(h("div", { class: "grid cols-2" },
    card("Decisions per day, last 30 days", null, stackedBars(g.daily, [
      { key: "allowed", label: "Allowed", color: c.pass }, { key: "approved", label: "Approved", color: c.appr },
      { key: "held for approval", label: "Held", color: c.held }, { key: "denied", label: "Denied", color: c.fail }])),
    flushCard("Rules that decided", null, table([
      { label: "Rule", value: (r) => h("span", { class: "mono" }, r.rule) },
      { label: "Outcome", value: (r) => pill(r.outcome) },
      { label: "Calls", value: (r) => fmt.n(r.n), num: true, sort: (r) => r.n },
    ], g.by_rule, { sortKey: 2, empty: "No rule has matched yet." }))));
  parts.push(h("div", { class: "grid cols-2" },
    flushCard("Ledgers", null, table([
      { label: "Ledger", value: (r) => h("span", { class: "mono" }, r.name) },
      { label: "Engine", value: (r) => r.engines.join(", ") },
      { label: "Entries", value: (r) => fmt.n(r.entries), num: true },
      { label: "Chain", value: (r) => r.verified ? pill("verified", "ok") : h("div", {}, pill("broken", "fail"), h("ul", { class: "lines" }, r.problems.map((x) => h("li", {}, x)))) },
    ], g.chains, { empty: "No gate ledgers in this workspace." })),
    flushCard("Which layer decided", null, table([
      { label: "Layer", value: (r) => ({ agt: "Microsoft AGT policy", guard: "Shio Guard provenance", "shio-strict": "Shio fail-safe (missing input)" }[r[0]] || r[0]) },
      { label: "Calls", value: (r) => fmt.n(r[1]), num: true, sort: (r) => r[1] },
    ], Object.entries(g.by_layer || {}), { sortKey: 1 }))));
  const outcomeSel = h("select", { "aria-label": "Outcome", onchange: (e) => { ui.outcome = e.target.value; rerender(); } },
    ["", "allowed", "approved", "held for approval", "denied"].map((x) => h("option", { value: x, selected: filter === x }, x || "Any outcome")));
  parts.push(flushCard(`Recent gate decisions (${rows.length} of ${fmt.n(g.total)})`, h("div", { class: "filters" }, outcomeSel), table([
    { label: "When", value: (r) => fmt.time(r.time), sort: (r) => r.time },
    { label: "Agent", value: (r) => r.agent || "–" },
    { label: "Tool", value: (r) => h("div", {}, h("strong", {}, r.action), r.args.length ? h("span", { class: "sub mono" }, r.args.join(", ")) : null) },
    { label: "Outcome", value: (r) => pill(gateOutcome(r)), sort: gateOutcome },
    { label: "Rule", value: (r) => r.rule ? h("span", { class: "mono" }, r.rule) : h("span", { class: "faint" }, "default") },
    { label: "Why", value: (r) => h("div", {}, r.reason || "–", r.approval && r.approval.by ? h("span", { class: "sub" }, `${r.approval.approved ? "approved" : "refused"} by ${r.approval.by}`) : r.approval ? h("span", { class: "sub" }, r.approval.note) : null), sort: false },
    { label: "Engine", value: (r) => h("span", { class: "sub" }, `${r.engine || "?"} ${r.engine_version || ""}`), sort: false },
  ], rows.slice(0, 150), { empty: "No gate decisions." })));
  parts.push(policiesCard(p));
  return parts;
});
function policiesCard(p) {
  if (!p.policies.length) return card("AGT policies", null, empty("No policy files in this workspace's policies folder."));
  return h("div", { class: "stack" }, p.policies.map((f) => flushCard(`Policy file ${f.file}`,
    f.ok ? h("span", {}, pill("loads, strict", "ok"), " ", h("span", { class: "faint mono" }, f.sha256)) :
      f.ok === null ? pill("AGT not installed", "none") : pill("refused", "fail"),
    f.ok ? f.policies.map((pol) => h("div", {},
      h("div", { style: "padding:4px 16px 8px" }, h("strong", {}, pol.name), h("span", { class: "faint" }, ` v${pol.version}, default ${pol.default}`)),
      table([
        { label: "Rule", value: (r) => h("span", { class: "mono" }, r.name) },
        { label: "Effect", value: (r) => pill(r.effect, { deny: "fail", require_approval: "warn", allow: "ok" }[r.effect] || "info") },
        { label: "Condition", value: (r) => h("code", {}, r.condition), sort: false },
        { label: "Approvers", value: (r) => r.approvers.join(", ") || "–" },
        { label: "Stage", value: (r) => r.stage },
      ], pol.rules))) : h("div", { class: "body" }, h("div", { class: "banner fail" }, f.problem || "")))));
}

view("preflight", "Pre-model gate", ["preflight"], ({ preflight: p }) => {
  const c = COLORS(), by = p.by_outcome || {}, cov = p.coverage || {};
  const parts = [h("div", { class: "grid kpis" },
    kpi("Model calls decided", fmt.n(p.total), p.verified === false ? "ledger BROKEN" : "every one recorded before sending",
      p.verified === false ? "fail" : ""),
    kpi("Allowed", fmt.n(by.allow || 0), "sent as asked", "ok"),
    kpi("Redacted or routed", fmt.n((by.redact || 0) + (by.route || 0)), `${by.redact || 0} redacted, ${by.route || 0} routed`),
    kpi("Held for a person", fmt.n(by.hold || 0), "waiting for a named role", by.hold ? "warn" : ""),
    kpi("Denied", fmt.n(by.deny || 0), "nothing left for the model", by.deny ? "fail" : ""))];
  if (p.total) parts.push(h("div", { class: "grid cols-2" },
    card("Gate decisions per day, last 30 days", null, stackedBars(p.daily, [
      { key: "allow", label: "Allowed", color: c.pass }, { key: "redact", label: "Redacted", color: c.appr },
      { key: "route", label: "Routed", color: css("--accent") }, { key: "hold", label: "Held", color: c.held },
      { key: "deny", label: "Denied", color: c.fail }])),
    flushCard("Controls that stopped or changed a call", null, table([
      { label: "Control", value: (r) => h("span", { class: "mono" }, r.control) },
      { label: "Outcome", value: (r) => pill(r.outcome, { deny: "fail", hold: "warn", redact: "info", route: "info" }[r.outcome]) },
      { label: "Calls", value: (r) => fmt.n(r.n), num: true, sort: (r) => r.n },
    ], p.by_control, { sortKey: 2 }))));
  parts.push(h("div", { class: "grid cols-2" },
    flushCard("Attestations", p.attestations_verified === false ? pill("ledger broken", "fail") : null, table([
      { label: "Duty", value: (a) => h("span", { class: "mono" }, a.kind) },
      { label: "State", value: (a) => pill(a.state, { current: "ok", expiring: "warn", expired: "fail", missing: "fail" }[a.state]),
        sort: (a) => ({ missing: 0, expired: 1, expiring: 2, current: 3 }[a.state]) },
      { label: "Signed by", value: (a) => a.signed_by || "–" },
      { label: "Expires", value: (a) => a.expires || "–", sort: (a) => a.expires || "" },
    ], p.attestations, { sortKey: 1, sortDir: 1, empty: "No attestations folder in this workspace." })),
    card("Coverage of the policy pack specification", null,
      h("div", { class: "grid kpis" }, kpi("Enforced", fmt.n(cov.enforced), "gate, runtime or lint", "ok"),
        kpi("Measured", fmt.n(cov.measured), "evals in CI"), kpi("Attested", fmt.n(cov.attested), "signed attestations"),
        kpi("Planned", fmt.n(cov.planned), "listed, NOT covered", cov.planned ? "warn" : "")),
      h("p", { class: "faint" }, "Never \"compliant\": the claim is that enforced controls passed and attestations are current. shio preflight coverage prints every row."))));
  parts.push(flushCard(`Recent gate decisions (${Math.min(p.decisions.length, 200)} of ${fmt.n(p.total)})`, null, table([
    { label: "When", value: (r) => fmt.time(r.time), sort: (r) => r.time },
    { label: "Caller", value: (r) => h("div", {}, r.caller, h("span", { class: "sub" }, r.role)) },
    { label: "Purpose", value: (r) => r.purpose },
    { label: "Source", value: (r) => r.source },
    { label: "Destination", value: (r) => r.destination === r.asked_for ? r.destination : h("div", {}, r.destination, h("span", { class: "sub" }, `asked for ${r.asked_for}`)) },
    { label: "Classes", value: (r) => chips(r.classes, 4), sort: false },
    { label: "Outcome", value: (r) => pill(r.outcome, { allow: "ok", deny: "fail", hold: "warn", redact: "info", route: "info" }[r.outcome]) },
    { label: "Why", value: (r) => r.reasons.length ? h("ul", { class: "lines" }, r.reasons.map((x) => h("li", {}, x))) : h("span", { class: "faint" }, "every control passed"), sort: false },
  ], p.decisions, { empty: "No pre-model gate decisions in this workspace (gates/preflight.jsonl)." })));
  return parts;
});

view("monitoring", "Monitoring", ["monitoring"], ({ monitoring: m }) => {
  if (!m.metrics) return [card("Monitors", null, empty("No decision ledger to monitor."), m.alerts.map((a) => h("div", { class: "banner fail" }, a.message)))];
  const x = m.metrics, t = m.thresholds || {};
  const allPsi = Object.entries(x.check_psi || {}).map(([k, v]) => ({ check: k, psi: v })).sort((a, b) => b.psi - a.psi);
  const psiRows = allPsi.filter((r) => r.psi > 0).slice(0, 10);
  const still = allPsi.length - psiRows.length;
  return [
    h("div", { class: "grid kpis" },
      kpi("Decisions in window", fmt.n(x.decisions), `${fmt.day(m.window[0])} to ${fmt.day(m.window[1])}`),
      kpi("Model failure rate", fmt.pct(x.failure_rate, 1), `threshold ${fmt.pct(t.failure_rate)}`, x.failure_rate > t.failure_rate ? "fail" : "ok"),
      kpi("Check failure rate", fmt.pct(x.check_failure_rate, 1), `baseline ${fmt.pct(x.baseline_check_failure_rate, 1)}`,
        x.check_failure_rate > (x.baseline_check_failure_rate || 0) * 1.5 ? "warn" : ""),
      kpi("Override rate", fmt.pct(x.override_rate, 1), `threshold ${fmt.pct(t.override_rate)}`, x.override_rate > t.override_rate ? "fail" : "ok"),
      kpi("Outcome drift (PSI)", fmt.num(x.outcome_psi), "0.1 watch · 0.2 alert", x.outcome_psi > 0.2 ? "fail" : x.outcome_psi > 0.1 ? "warn" : "ok")),
    h("div", { class: "grid cols-2" },
      card("Alerts", pill(`${m.alerts.length}`, m.alerts.length ? "fail" : "ok"),
        m.alerts.length ? h("div", { class: "stack", style: "gap:8px" }, m.alerts.map((a) =>
          h("div", { class: `banner ${a.severity === "high" || a.severity === "critical" ? "fail" : ""}` }, h("strong", {}, `${a.kind}: `), a.message))) :
          empty("No alerts: rates and drift are inside their thresholds."),
        h("p", { class: "faint", style: "margin:12px 0 0" }, `Window ${m.window.join(" to ")} against baseline ${m.baseline.join(" to ")}.`)),
      card("Drift per check (PSI, window against baseline)", null, psiRows.length ? h("div", { class: "stack", style: "gap:10px" },
        still ? h("p", { class: "faint", style: "margin:0" }, `${still} other check(s): no shift.`) : null,
        psiRows.map((r) => h("div", { class: "gauge" }, h("div", { style: "display:flex;justify-content:space-between" },
          h("span", { class: "mono" }, r.check), h("strong", {}, fmt.num(r.psi))),
          h("div", { class: "scale" }, h("div", { class: "needle", style: `left:calc(${Math.min(100, (r.psi / 0.5) * 100)}% - 1px)` })),
          h("div", { class: "ticks" }, h("span", {}, "0"), h("span", {}, "0.1"), h("span", {}, "0.2"), h("span", {}, "0.3"), h("span", {}, "0.4"), h("span", {}, "0.5+"))))) :
        empty(allPsi.length ? "No check's pass/fail mix has shifted." : "Not enough decisions to compare."))),
    flushCard("Incidents", null, table([
      { label: "Incident", value: (r) => h("span", { class: "mono" }, r.incident) },
      { label: "Title", value: (r) => r.title },
      { label: "Severity", value: (r) => pill(r.severity) },
      { label: "Status", value: (r) => pill(r.status) },
      { label: "Opened", value: (r) => h("div", {}, r.opened.replace("T", " "), h("span", { class: "sub" }, `by ${r.opened_by}`)), sort: (r) => r.opened },
      { label: "History", value: (r) => `${r.history.length} signed record(s)`, sort: (r) => r.history.length },
    ], m.incidents, { empty: "No incidents recorded." })),
  ];
});

view("evals", "Evals", ["evals"], ({ evals: e }) => [
  e.results.length ? h("div", { class: "grid cols-2" }, e.results.map((r) => card(`${r.suite} · ${r.file.replace(/\.json$/, "")}`,
    h("span", {}, r.gate_failures.length ? pill("gate missed", "fail") : pill("gates met", "ok"), " ",
      r.sealed ? pill(r.signed ? "sealed, signed" : "sealed", "ok") : pill("edited", "fail")),
    h("dl", { class: "kv" },
      h("dt", {}, "Cases"), h("dd", {}, `${r.passed} of ${r.cases} passed`),
      h("dt", {}, "Target"), h("dd", { class: "mono" }, r.target || "–"),
      h("dt", {}, "Run"), h("dd", {}, r.generated || "–"),
      Object.entries(r.metrics).map(([k, v]) => [h("dt", {}, k), h("dd", {}, typeof v === "number" && v <= 1 ? fmt.pct(v, 1) : String(v))])),
    Object.keys(r.gates).length ? h("div", { style: "margin-top:12px" }, h("h3", {}, "Gates"), table([
      { label: "Metric", value: (g) => g[0] },
      { label: "Needs", value: (g) => `${g[1].op} ${g[1].threshold}` },
      { label: "Value", value: (g) => fmt.num(g[1].value, 4), num: true },
      { label: "", value: (g) => g[1].ok ? pill("met", "ok") : pill("missed", "fail"), sort: false },
    ], Object.entries(r.gates))) : null,
    r.failed_cases.length ? h("details", { class: "row-detail", style: "margin-top:12px" }, h("summary", {}, `${r.failed_cases.length} failed case(s)`),
      h("ul", { class: "lines" }, r.failed_cases.map((c) => h("li", {}, h("span", { class: "mono" }, c.id), `: ${c.detail}`)))) : null,
    sliceTable(r.slices)))) : card("Eval results", null, empty("No sealed eval results in this workspace's evals folder.")),
  flushCard("Other sealed documents", null, table([
    { label: "File", value: (d) => h("span", { class: "mono" }, d.file) },
    { label: "Kind", value: (d) => d.format },
    { label: "Summary", value: (d) => d.summary || "–" },
    { label: "Seal", value: (d) => d.sealed ? pill(d.signed ? "sealed, signed" : "sealed", "ok") : pill("edited", "fail") },
  ], e.documents, { empty: "None." })),
]);
function sliceTable(slices) {
  const rows = [];
  for (const [attr, groups] of Object.entries(slices || {})) for (const [g, v] of Object.entries(groups)) rows.push({ attr, g, ...v });
  if (!rows.length) return null;
  return h("details", { class: "row-detail", style: "margin-top:12px" }, h("summary", {}, `Results by subgroup (${rows.length})`), table([
    { label: "Slice", value: (r) => `${r.attr} = ${r.g}` },
    { label: "Cases", value: (r) => fmt.n(r.n), num: true, sort: (r) => r.n },
    { label: "Pass rate", value: (r) => meter(r.pass_rate), sort: (r) => r.pass_rate },
  ], rows));
}

view("packs", "Packs and controls", ["packs"], ({ packs: d }, ui) => {
  const q = (ui.q || "").toLowerCase();
  const search = h("input", { type: "search", placeholder: "Find a control (e.g. PHI-1, MEASURE 2.5)", value: ui.q || "", "aria-label": "Find a control",
    oninput: (e) => { ui.q = e.target.value; rerender(); } });
  const controls = [];
  d.packs.forEach((p) => (p.controls || []).forEach((c) => controls.push({ pack: p, ...c })));
  const hits = q ? controls.filter((c) => [c.pack.id, c.id, c.title, ...c.refs, ...c.proofs].join(" ").toLowerCase().includes(q)) : [];
  return [
    flushCard(`Packs (${d.packs.length})`, h("div", { class: "filters" }, search), q ? table([
      { label: "Control", value: (c) => h("a", { href: `/control/${encodeURIComponent(c.pack.id)}/${encodeURIComponent(c.id)}` }, c.id) },
      { label: "Pack", value: (c) => `${c.pack.id}@${c.pack.version}` },
      { label: "Title", value: (c) => c.title },
      { label: "Framework refs", value: (c) => chips(c.refs, 4), sort: false },
      { label: "Proofs", value: (c) => chips(c.proofs, 4), sort: false },
    ], hits, { empty: "No control matches." }) : table([
      { label: "Pack", value: (p) => h("div", {}, h("strong", {}, p.id), h("span", { class: "sub" }, p.name || "")) , sort: (p) => p.id },
      { label: "Version", value: (p) => h("span", { class: "mono" }, p.version || "–") },
      { label: "Status", value: (p) => pill(p.status || "?"), sort: (p) => p.status },
      { label: "Licence", value: (p) => p.licence || "–" },
      { label: "Controls", value: (p) => fmt.n((p.controls || []).length), num: true, sort: (p) => (p.controls || []).length },
      { label: "Validator", value: (p) => p.ok ? pill("valid, fixtures pass", "ok") : h("div", {}, pill("invalid", "fail"), h("ul", { class: "lines" }, p.problems.map((x) => h("li", {}, x)))) },
      { label: "Reviewed by", value: (p) => p.reviewed_by && p.reviewed_by.length ? p.reviewed_by.join(", ") : h("span", { class: "faint" }, "not yet") , sort: false },
    ], d.packs)),
    h("p", { class: "faint" }, "A pack may claim \"compliant\" only when counsel (and for med.* packs, the clinical lead) are named in its review. Draft and research packs make no compliance claim."),
  ];
});

view("cards", "Agents", ["cards"], ({ cards: d }) => [
  d.cards.length ? h("div", { class: "grid cols-2" }, d.cards.map((c) => card(c.name,
    h("span", {}, c.intact ? pill("card intact", "ok") : pill("card edited", "fail"), " ", c.reviewed ? pill("reviewed", "ok") : pill("needs review", "warn")),
    h("p", { class: "muted", style: "margin:0 0 12px" }, c.purpose),
    h("dl", { class: "kv" },
      h("dt", {}, "Owner"), h("dd", {}, c.owner || "–"),
      h("dt", {}, "Card hash"), h("dd", { class: "mono" }, c.sha256),
      h("dt", {}, "Risk tiers"), h("dd", {}, c.risk_tiers.map((t) => pill(t, t === "high" ? "warn" : "info"))),
      h("dt", {}, "Models"), h("dd", {}, c.models.map((m) => pill(`${m.name}${m.pinned ? " pinned" : " UNPINNED"}`, m.pinned ? "ok" : "fail"))),
      h("dt", {}, "Checks"), h("dd", {}, String(c.checks)),
      h("dt", {}, "Tools"), h("dd", {}, c.tools.length ? chips(c.tools) : "none"),
      h("dt", {}, "Packs"), h("dd", {}, chips(c.packs)),
      h("dt", {}, "Sign-off by"), h("dd", {}, c.signoff_roles.join(", ") || "–"),
      h("dt", {}, "Review roles"), h("dd", {}, c.review_roles.join(", ") || "–")),
    h("ul", { class: "lines", style: "margin-top:10px" }, c.review.map((x) => h("li", {}, x))),
    c.problems.length ? h("div", { class: "banner fail", style: "margin-top:10px" }, c.problems.join("; ")) : null))) :
    card("Agent cards", null, empty("No agent cards in this workspace's cards folder.")),
]);

view("evidence", "Evidence", ["bundles", "evals"], ({ bundles: b, evals: e }) => [
  flushCard("Framework evidence bundles", null, table([
    { label: "Bundle", value: (x) => h("a", { href: `/bundle/${encodeURIComponent(x.name)}` }, x.name) },
    { label: "Framework", value: (x) => x.framework || "–" },
    { label: "Period", value: (x) => (x.period || []).join(" to ") },
    { label: "Controls", value: (x) => h("div", { class: "chips" }, Object.entries(x.summary).filter(([, n]) => n).map(([k, n]) => pill(`${n} ${k.toLowerCase()}`, STATUS[k]))), sort: false },
    { label: "Ledger", value: (x) => x.ledger_verified ? pill("verified", "ok") : pill("not verified", "fail") },
    { label: "Gaps", value: (x) => x.gaps.length ? h("ul", { class: "lines" }, x.gaps.map((g) => h("li", {}, `${g.id}: ${g.title}`))) : h("span", { class: "faint" }, "none"), sort: (x) => x.gaps.length },
  ], b.bundles, { empty: "No evidence bundles in this workspace." })),
  flushCard("Assessments and other sealed documents", null, table([
    { label: "File", value: (d) => h("span", { class: "mono" }, d.file) },
    { label: "Kind", value: (d) => d.format },
    { label: "Summary", value: (d) => d.summary || "–" },
    { label: "Seal", value: (d) => d.sealed ? pill(d.signed ? "sealed, signed" : "sealed", "ok") : pill("edited", "fail") },
  ], e.documents, { empty: "None." })),
  h("p", { class: "faint" }, "Verify any of these offline with the public key: shio verify <path> --pubkey <key>."),
]);

/* ---------------- shell: routing, polling, theme ---------------- */
const ORDER = ["overview", "checks", "decisions", "preflight", "gates", "monitoring", "evals", "packs", "cards", "evidence"];
const NAV_STATUS = { preflight: ["Pre-model gate"], checks: ["Checks"], decisions: ["Ledger", "People"], gates: ["Gates"], monitoring: ["Monitoring"],
  evals: ["Evals"], packs: ["Packs"], cards: ["Agents"], evidence: ["Evidence"] };
const state = { route: "overview", ui: {}, last: 0, failed: false, timer: null, inflight: null, summary: null };

function parseHash() {
  const [path, query] = (location.hash.replace(/^#\/?/, "") || "overview").split("?");
  const route = VIEWS[path] ? path : "overview";
  const ui = state.ui[route] || (state.ui[route] = {});
  if (query) for (const [k, v] of new URLSearchParams(query)) ui[k === "signoff" ? "status" : k] = v;
  return route;
}
function buildNav() {
  const nav = $("#nav");
  nav.replaceChildren(...ORDER.map((id) => {
    const worst = navStatus(id);
    return h("a", { href: `#/${id}`, "aria-current": state.route === id ? "page" : null },
      h("span", {}, VIEWS[id].title), worst ? h("span", { class: `dot ${worst}`, title: LABEL[worst] }) : null);
  }));
}
function navStatus(id) {
  if (!state.summary || !NAV_STATUS[id]) return null;
  const sts = state.summary.checkpoints.filter((c) => NAV_STATUS[id].includes(c.area)).map((c) => c.status);
  return sts.includes("fail") ? "fail" : sts.includes("warn") ? "warn" : sts.includes("ok") ? "ok" : null;
}

let renderSeq = 0;
async function rerender(quiet) {
  const seq = ++renderSeq;
  const v = VIEWS[state.route];
  $("#title").textContent = v.title;
  document.title = `${v.title} · Shio Guard Monitor`;
  const target = $("#view");
  if (!quiet) target.replaceChildren(h("div", { class: "grid kpis" }, [1, 2, 3, 4].map(() => h("div", { class: "skeleton" }))));
  try {
    const sections = Array.from(new Set(["summary", ...v.sections]));
    const results = await Promise.all(sections.map((sec) => api.get(sec)));
    const data = Object.fromEntries(sections.map((sec, i) => [sec, results[i]]));
    state.summary = data.summary;
    const nodes = await v.render(data, state.ui[state.route]);
    if (seq !== renderSeq) return;                       // a newer render started: drop this one
    const scroll = window.scrollY;
    target.replaceChildren(...[].concat(nodes).filter(Boolean));
    if (quiet) window.scrollTo(0, scroll);
    const ws = data.summary.workspace || {};
    $("#subtitle").textContent = ws.records ? `Workspace: ${commonRoot(Object.values(ws).filter(Boolean))}` : "No workspace folders given";
    state.last = Date.now(); state.failed = false;
    buildNav();
  } catch (err) {
    if (seq !== renderSeq) return;
    state.failed = true;
    target.replaceChildren(h("div", { class: "banner fail" }, `Could not load this view: ${err.message}. Is the console still running?`));
  }
  tick();
}
function commonRoot(paths) {
  if (!paths.length) return "";
  const parts = paths.map((p) => p.split("/"));
  const out = [];
  for (let i = 0; i < parts[0].length; i++) { const seg = parts[0][i]; if (parts.every((p) => p[i] === seg)) out.push(seg); else break; }
  return out.join("/") || "/";
}
function tick() {
  const live = $("#live");
  live.classList.toggle("down", state.failed);
  live.classList.toggle("stale", !state.failed && !$("#auto").checked);
  $("#updated").textContent = state.failed ? "offline" : state.last ? `updated ${fmt.ago(Date.now() - state.last)}` : "loading";
}
function schedule() {
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    tick();
    if ($("#auto").checked && !document.hidden && Date.now() - state.last >= REFRESH_MS) rerender(true);
  }, 1000);
}
function applyTheme(t) {
  if (t) document.documentElement.setAttribute("data-theme", t); else document.documentElement.removeAttribute("data-theme");
  try { if (t) localStorage.setItem("shio-theme", t); else localStorage.removeItem("shio-theme"); } catch (e) { /* storage may be blocked */ }
  if (state.summary) rerender(true);                    // charts read colours from the theme
}

document.addEventListener("DOMContentLoaded", () => {
  try { const t = localStorage.getItem("shio-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch (e) { /* ignore */ }
  try { const a = localStorage.getItem("shio-auto"); if (a === "0") $("#auto").checked = false; } catch (e) { /* ignore */ }
  $("#refresh").addEventListener("click", () => rerender(true));
  $("#auto").addEventListener("change", (e) => { try { localStorage.setItem("shio-auto", e.target.checked ? "1" : "0"); } catch (x) { /* ignore */ } tick(); });
  $("#theme").addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    const dark = cur ? cur === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(dark ? "light" : "dark");
  });
  $("#menu").addEventListener("click", () => {
    const open = $("#side").classList.toggle("open");
    $("#menu").setAttribute("aria-expanded", String(open));
  });
  $("#nav").addEventListener("click", () => { $("#side").classList.remove("open"); $("#menu").setAttribute("aria-expanded", "false"); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && $("#auto").checked) rerender(true); });
  window.addEventListener("hashchange", () => { state.route = parseHash(); buildNav(); rerender(); $("#view").focus({ preventScroll: true }); });
  state.route = parseHash();
  buildNav();
  rerender();
  schedule();
});
