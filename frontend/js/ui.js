/* UI helpers: escaping, icons, charts (pure SVG), C syntax highlighting, markdown-lite, toasts. */
const UI = (() => {
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const pct = (v) => `${Math.round((v || 0) * 100)}%`;
  const fmtDate = (iso) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";

  const ICON_PATHS = {
    shield: '<path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/>',
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    repo: '<path d="M4 4h11a3 3 0 013 3v13H7a3 3 0 01-3-3z"/><path d="M4 17a3 3 0 013-3h11"/>',
    bug: '<rect x="7" y="8" width="10" height="12" rx="5"/><path d="M12 8V5M9 5l1.5 1.5M15 5l-1.5 1.5M3 13h4M17 13h4M4 19l3-2M20 19l-3-2M4 7l3 2M20 7l-3 2"/>',
    code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>',
    log: '<path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h8M8 16h5"/>',
    chat: '<path d="M4 5h16v11H9l-5 4z"/><path d="M8 9h8M8 12h5"/>',
    model: '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/>',
    report: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
    audit: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5M9 11l1.5 1.5L13 10"/>',
    play: '<path d="M7 4l13 8-13 8z"/>',
    upload: '<path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v4h16v-4"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z"/>',
    logout: '<path d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    lock: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    spark: '<path d="M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z"/>',
    send: '<path d="M4 12l16-8-6 16-2-6z"/>',
    download: '<path d="M12 4v12M7 11l5 5 5-5M4 20h16"/>',
    refresh: '<path d="M20 11a8 8 0 10-2.3 5.7M20 5v6h-6"/>',
    check: '<path d="M5 12l5 5 9-10"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    folder: '<path d="M3 6h7l2 2h9v11H3z"/>',
    inbox: '<path d="M3 13l3-8h12l3 8v6H3z"/><path d="M3 13h5l1 3h6l1-3h5"/>',
  };
  const icon = (name) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] || ""}</svg>`;

  const SEV_COLORS = { critical: "#F43F5E", high: "#F97316", medium: "#F59E0B", low: "#38BDF8" };
  const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;
  const status = (s) => `<span class="status status-${esc(s)}">${esc(s)}</span>`;
  const conf = (v) => `<div class="conf"><div class="bar"><i style="width:${Math.round((v || 0) * 100)}%"></i></div><span>${pct(v)}</span></div>`;
  const SRC = { rules: ["R", "src-rules", "Rule engine"], defect_model: ["ML", "src-ml", "Defect classifier"], compiler_log: ["L", "src-log", "Compiler / static-analysis log"],
    injection_model: ["AI", "src-ai", "Injection detector"], anomaly_model: ["A", "src-ml", "Complexity anomaly model"], triage_model: ["T", "src-ai", "Triage model"] };
  const sources = (list) => `<span class="src-icons">${(list || []).map((s) => { const m = SRC[s] || [s[0], "src-rules", s]; return `<span class="src ${m[1]}" title="${esc(m[2])}">${m[0]}</span>`; }).join("")}</span>`;

  /* ---------------- charts (SVG) */
  function donut(data, { size = 150, thickness = 22, center = "" } = {}) {
    const total = data.reduce((a, d) => a + d.value, 0);
    const r = (size - thickness) / 2, c = 2 * Math.PI * r;
    let offset = 0;
    const arcs = total === 0
      ? `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="${thickness}"/>`
      : data.filter((d) => d.value > 0).map((d) => {
        const len = (d.value / total) * c;
        const s = `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${d.color}" stroke-width="${thickness}" stroke-dasharray="${Math.max(len - 2, 0.5)} ${c - len + 2}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${size / 2} ${size / 2})"><title>${esc(d.label)}: ${d.value}</title></circle>`;
        offset += len; return s;
      }).join("");
    return `<svg viewBox="0 0 ${size} ${size}" role="img" aria-label="donut chart">${arcs}
      <text x="50%" y="47%" text-anchor="middle" style="font-size:26px;font-weight:750;fill:var(--text)">${total}</text>
      <text x="50%" y="62%" text-anchor="middle">${esc(center)}</text></svg>`;
  }

  function hbars(data) {
    const max = Math.max(1, ...data.map((d) => d.value));
    return `<div class="hbar">${data.map((d) => `<div class="hbar-row"><span class="name" title="${esc(d.label)}">${esc(d.label)}</span>
      <div class="track"><i style="width:${(d.value / max) * 100}%;${d.color ? `background:${d.color}` : ""}"></i></div><b>${d.value}</b></div>`).join("")}</div>`;
  }

  function line(points, { w = 420, h = 150 } = {}) {
    if (!points.length) return `<div class="empty" style="padding:24px">No runs yet</div>`;
    const pad = 24, max = Math.max(1, ...points.map((p) => p.total));
    const x = (i) => pad + (points.length === 1 ? (w - 2 * pad) / 2 : (i * (w - 2 * pad)) / (points.length - 1));
    const y = (v) => h - pad - (v / max) * (h - 2 * pad);
    const path = (key) => points.map((p, i) => `${i ? "L" : "M"}${x(i)},${y(p[key])}`).join(" ");
    const area = `${path("total")} L${x(points.length - 1)},${h - pad} L${x(0)},${h - pad} Z`;
    return `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="trend chart">
      <defs><linearGradient id="lg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#3D7BFF" stop-opacity=".35"/><stop offset="1" stop-color="#3D7BFF" stop-opacity="0"/></linearGradient></defs>
      ${[0, 0.5, 1].map((t) => `<line x1="${pad}" x2="${w - pad}" y1="${y(max * t)}" y2="${y(max * t)}" stroke="var(--border)" stroke-dasharray="3 4"/><text x="2" y="${y(max * t) + 4}">${Math.round(max * t)}</text>`).join("")}
      <path d="${area}" fill="url(#lg)"/>
      <path d="${path("total")}" fill="none" stroke="#3D7BFF" stroke-width="2.5" stroke-linejoin="round"/>
      <path d="${path("high")}" fill="none" stroke="#F97316" stroke-width="2" stroke-dasharray="5 4"/>
      ${points.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.total)}" r="3.5" fill="#3D7BFF"><title>Run #${p.run}: ${p.total} findings, ${p.high} critical/high</title></circle><text x="${x(i)}" y="${h - 6}" text-anchor="middle">#${p.run}</text>`).join("")}
    </svg>`;
  }

  /* Returns "rgba(r,g,b," so callers can append their own alpha + ")". */
  function heatColor(score, max) {
    const t = max ? Math.min(1, score / max) : 0;
    const stops = [[56, 189, 248], [245, 158, 11], [249, 115, 22], [244, 63, 94]];
    const seg = Math.min(stops.length - 2, Math.floor(t * (stops.length - 1)));
    const lt = t * (stops.length - 1) - seg;
    const c = stops[seg].map((v, i) => Math.round(v + (stops[seg + 1][i] - v) * lt));
    return `rgba(${c.join(",")},`;
  }

  /* ---------------- C syntax highlighting (stateful across lines for block comments) */
  const KW = new Set("if else for while do switch case default break continue return goto sizeof typedef struct enum union static const volatile extern inline register".split(" "));
  const TY = new Set("void char short int long float double signed unsigned bool _Bool size_t Std_ReturnType FILE".split(" "));
  function highlight(src) {
    const out = [];
    let inBlock = false;
    for (const raw of src.split("\n")) {
      let i = 0, html = "";
      const n = raw.length;
      if (!inBlock && /^\s*#/.test(raw)) { out.push(`<span class="tk-pp">${esc(raw)}</span>`); continue; }
      while (i < n) {
        if (inBlock) {
          const end = raw.indexOf("*/", i);
          const stop = end === -1 ? n : end + 2;
          html += `<span class="tk-com">${esc(raw.slice(i, stop))}</span>`;
          i = stop; if (end !== -1) inBlock = false; continue;
        }
        const ch = raw[i], rest = raw.slice(i);
        if (rest.startsWith("//")) { html += `<span class="tk-com">${esc(rest)}</span>`; break; }
        if (rest.startsWith("/*")) { inBlock = true; continue; }
        if (ch === '"' || ch === "'") {
          let j = i + 1; while (j < n && raw[j] !== ch) { if (raw[j] === "\\") j++; j++; }
          html += `<span class="tk-str">${esc(raw.slice(i, j + 1))}</span>`; i = j + 1; continue;
        }
        const num = rest.match(/^(0x[0-9a-fA-F]+|\d+(\.\d+)?)[uUlLfF]*/);
        if (num && !/\w/.test(raw[i - 1] || "")) { html += `<span class="tk-num">${esc(num[0])}</span>`; i += num[0].length; continue; }
        const id = rest.match(/^[A-Za-z_]\w*/);
        if (id) {
          const w = id[0];
          const isCall = /^\s*\(/.test(raw.slice(i + w.length));
          const cls = KW.has(w) ? "tk-kw" : (TY.has(w) || /_t$/.test(w)) ? "tk-ty" : isCall ? "tk-fn" : "";
          html += cls ? `<span class="${cls}">${esc(w)}</span>` : esc(w);
          i += w.length; continue;
        }
        html += esc(ch); i++;
      }
      out.push(html);
    }
    return out;
  }

  /* ---------------- markdown-lite (safe: escape first, then format) */
  function md(text, citeButtons = true) {
    const inline = (s) => esc(s)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
      .replace(/(^|\s)_([^_]+)_(?=\s|$|[.,])/g, "$1<i>$2</i>")
      .replace(/\[(\d{1,2})\]/g, citeButtons ? '<button class="cite" data-cite="$1">$1</button>' : "[$1]");
    return String(text || "").split(/\n{2,}/).map((b) => {
      const out = []; let para = []; let list = [];
      const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(" "))}</p>`); para = []; } };
      const flushList = () => { if (list.length) { out.push(`<ul>${list.map((l) => `<li>${inline(l)}</li>`).join("")}</ul>`); list = []; } };
      for (const l of b.split("\n")) {
        if (/^\s*[-*] /.test(l)) { flushPara(); list.push(l.replace(/^\s*[-*] /, "")); }
        else if (l.trim()) { flushList(); para.push(l); }
      }
      flushPara(); flushList();
      return out.join("");
    }).join("");
  }

  function toast(message, kind = "info") {
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.innerHTML = `<i></i><div>${esc(message)}</div>`;
    $("#toasts").appendChild(el);
    setTimeout(() => { el.style.opacity = "0"; el.style.transition = "opacity .3s"; setTimeout(() => el.remove(), 300); }, 3800);
  }

  const empty = (ico, title, text, action = "") => `<div class="empty"><div class="ico">${icon(ico)}</div><h3>${esc(title)}</h3><div>${esc(text)}</div>${action}</div>`;
  const skeleton = (cls, n = 1) => Array.from({ length: n }, () => `<div class="skeleton ${cls}"></div>`).join("");

  return { esc, $, $$, pct, fmtDate, icon, sev, status, conf, sources, donut, hbars, line, heatColor, highlight, md, toast, empty, skeleton, SEV_COLORS };
})();
