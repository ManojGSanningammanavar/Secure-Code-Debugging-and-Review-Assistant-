/* ECU Sentinel single-page app: routing, views, review workflow. Vanilla JS, no build step. */
(() => {
  const { esc, $, $$, icon, sev, status, conf, sources, donut, hbars, line, heatColor, highlight, md, toast, empty, skeleton, fmtDate, pct, SEV_COLORS } = UI;

  const state = {
    user: Api.session.user,
    repos: [],
    repoId: Number(localStorage.getItem("ecu_repo")) || null,
    view: "dashboard",
    filters: { severity: [], status: ["open", "accepted"], q: "" },
    chat: [],
    explorer: { path: null, line: null },
    lastLog: null,
  };
  const app = $("#app");
  const canReview = () => ["reviewer", "admin"].includes(state.user?.role);

  /* --------------------------------------------------------------- theme */
  const setTheme = (t) => { document.documentElement.dataset.theme = t; localStorage.setItem("ecu_theme", t); };
  setTheme(localStorage.getItem("ecu_theme") || "dark");

  /* --------------------------------------------------------------- login */
  function renderLogin() {
    app.innerHTML = `
    <div class="login">
      <section class="login-brand">
        <div class="brand-row"><div class="logo">${icon("shield")}</div>ECU Sentinel</div>
        <div class="login-hero">
          <h1>Secure code review that <span>never leaves your network.</span></h1>
          <p>Evidence-fused debugging and MISRA-oriented review for automotive embedded C — rules, five local ML models and grounded RAG, with humans in control.</p>
          <div class="feature-list">
            <div class="feature"><div class="ico">${icon("bug")}</div><div><b>Evidence fusion</b><span>Rule engine + ML defect model + compiler logs agree → higher confidence.</span></div></div>
            <div class="feature"><div class="ico">${icon("chat")}</div><div><b>Grounded Q&amp;A with citations</b><span>Answers only from authorised code and approved guidelines.</span></div></div>
            <div class="feature"><div class="ico">${icon("lock")}</div><div><b>Injection-aware &amp; access controlled</b><span>Repo text is treated as data; path-level permissions and full audit trail.</span></div></div>
          </div>
        </div>
        <div class="trust"><span class="pill">${icon("cpu")} Local inference</span><span class="pill">${icon("lock")} Path-level RBAC</span><span class="pill">${icon("audit")} Audit logged</span></div>
      </section>
      <section class="login-panel">
        <form class="login-card" id="loginForm" autocomplete="on">
          <h2>Sign in</h2>
          <div class="sub">Use your engineering account to continue.</div>
          <div class="field"><label for="u">Username</label><input class="input" id="u" name="username" required autocomplete="username"></div>
          <div class="field"><label for="p">Password</label><input class="input" id="p" name="password" type="password" required autocomplete="current-password"></div>
          <div class="error-text" id="loginErr"></div>
          <button class="btn btn-primary btn-block" id="loginBtn" type="submit">Sign in</button>
          <div class="demo-accounts">
            <div class="label">Demo accounts</div>
            <div class="demo-grid">
              ${[["reviewer", "review123", "Reviewer", "Approve / reject"], ["admin", "admin123", "Admin", "All repos + users"], ["dev", "dev123", "Developer", "Brake ECU only"], ["intern", "intern123", "Intern", "src/com + include"]]
                .map(([u, p, r, d]) => `<button type="button" class="demo-chip" data-u="${u}" data-p="${p}"><b>${r}</b><span>${d}</span></button>`).join("")}
            </div>
          </div>
        </form>
      </section>
    </div>`;
    $$(".demo-chip").forEach((b) => b.onclick = () => { $("#u").value = b.dataset.u; $("#p").value = b.dataset.p; $("#loginForm").requestSubmit(); });
    $("#loginForm").onsubmit = async (e) => {
      e.preventDefault();
      const btn = $("#loginBtn"); btn.disabled = true; btn.textContent = "Signing in…"; $("#loginErr").textContent = "";
      try {
        const res = await Api.post("/api/auth/login", { username: $("#u").value.trim(), password: $("#p").value });
        Api.session.set(res.token, res.user); state.user = res.user;
        await boot();
      } catch (err) { $("#loginErr").textContent = err.message; btn.disabled = false; btn.textContent = "Sign in"; }
    };
  }

  /* --------------------------------------------------------------- shell */
  const NAV = [
    ["Overview", [["dashboard", "Dashboard", "dashboard"], ["repos", "Repositories", "repo"]]],
    ["Review", [["findings", "Findings", "bug"], ["explorer", "Code explorer", "code"], ["logs", "Build logs", "log"], ["assistant", "Ask the codebase", "chat"]]],
    ["Governance", [["models", "ML models", "model"], ["reports", "Reports", "report"], ["audit", "Audit trail", "audit", true]]],
  ];

  function renderShell() {
    const u = state.user;
    const repo = state.repos.find((r) => r.id === state.repoId);
    app.innerHTML = `
    <div class="shell">
      <aside class="sidebar" id="sidebar">
        <div class="brand-row"><div class="logo">${icon("shield")}</div><div>ECU Sentinel<small>Secure Review Assistant</small></div></div>
        ${NAV.map(([sec, items]) => `<div class="nav-section">${sec}</div>` + items.filter((i) => !i[3] || canReview()).map(([id, label, ic]) =>
          `<div class="nav-item ${state.view === id ? "active" : ""}" data-view="${id}" title="${label}" tabindex="0">${icon(ic)}<span>${label}</span>${id === "findings" && repo ? `<span class="count">${repo.open_findings}</span>` : ""}</div>`).join("")).join("")}
        <div class="sidebar-foot">
          <span class="pill ok">${icon("cpu")} On-prem · offline</span>
          <div class="user-card"><div class="avatar">${esc(u.full_name.split(" ").map((s) => s[0]).join("").slice(0, 2))}</div>
            <div class="who"><b>${esc(u.full_name)}</b><span class="pill pri" style="padding:1px 8px">${esc(u.role)}</span></div>
            <button class="icon-btn" id="logout" title="Sign out" style="margin-left:auto">${icon("logout")}</button></div>
        </div>
      </aside>
      <div class="main">
        <header class="topbar">
          <button class="icon-btn menu-btn" id="menuBtn" aria-label="Menu">${icon("menu")}</button>
          <div class="title"><div class="crumb">${esc(repo ? repo.name : "No repository")}</div><h2 id="viewTitle"></h2></div>
          <div class="spacer"></div>
          <select class="input repo-select" id="repoSelect" aria-label="Repository">
            ${state.repos.map((r) => `<option value="${r.id}" ${r.id === state.repoId ? "selected" : ""}>${esc(r.name)}${r.scope !== "full" ? " (partial)" : ""}</option>`).join("")}
          </select>
          <button class="btn btn-primary" id="runBtn" ${repo && repo.scope === "full" ? "" : "disabled title='Requires full repository access'"}>${icon("play")}<span>Run analysis</span></button>
          <button class="icon-btn" id="themeBtn" title="Toggle theme">${icon(document.documentElement.dataset.theme === "dark" ? "sun" : "moon")}</button>
        </header>
        <main class="content" id="view"></main>
      </div>
    </div>`;
    $$(".nav-item").forEach((n) => { n.onclick = () => go(n.dataset.view); n.onkeydown = (e) => e.key === "Enter" && go(n.dataset.view); });
    $("#logout").onclick = () => { Api.session.clear(); state.user = null; renderLogin(); };
    $("#themeBtn").onclick = () => { setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"); renderShell(); };
    $("#menuBtn").onclick = () => $("#sidebar").classList.toggle("open");
    $("#repoSelect").onchange = (e) => selectRepo(Number(e.target.value));
    $("#runBtn").onclick = runAnalysis;
    renderView();
  }

  function go(view) { state.view = view; if (location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`); renderShell(); }
  function selectRepo(id) { state.repoId = id; localStorage.setItem("ecu_repo", id); state.explorer = { path: null, line: null }; state.chat = []; renderShell(); }
  async function refreshRepos() { state.repos = await Api.get("/api/repos"); if (!state.repos.find((r) => r.id === state.repoId)) state.repoId = state.repos[0]?.id || null; }

  const TITLES = { dashboard: "Review dashboard", repos: "Repositories", findings: "Findings", explorer: "Code explorer", logs: "Build log triage",
    assistant: "Ask the codebase", models: "ML models", reports: "Reports & workflow", audit: "Audit trail" };
  const VIEWS = {};
  function renderView() {
    $("#viewTitle").textContent = TITLES[state.view] || "";
    const v = $("#view");
    if (!state.repoId && !["repos", "audit"].includes(state.view)) { v.innerHTML = `<div class="card">${empty("repo", "No repository access", "Ask an administrator to grant you access to a repository.")}</div>`; return; }
    (VIEWS[state.view] || VIEWS.dashboard)(v).catch((err) => { v.innerHTML = `<div class="card">${empty("x", "Something went wrong", err.message)}</div>`; });
  }

  /* --------------------------------------------------------------- run analysis modal */
  async function runAnalysis() {
    const steps = ["Parsing C sources & building call graph", "Running MISRA / secure-coding rules", "Defect classifier + complexity anomaly model",
      "Prompt-injection scan of repository text", "Fusing compiler-log evidence & triage scoring", "Refreshing hybrid RAG index"];
    const host = document.createElement("div");
    host.innerHTML = `<div class="overlay"></div><div class="modal" role="dialog" aria-modal="true"><h2>Analysing repository</h2>
      <p style="color:var(--text-2);margin:0 0 14px">Everything runs locally. No source code leaves this machine.</p>
      <div class="steps">${steps.map((s, i) => `<div class="step" data-i="${i}"><i></i>${s}</div>`).join("")}</div><div class="actions" id="runActions"></div></div>`;
    document.body.appendChild(host);
    let i = 0;
    const tick = setInterval(() => { $$(".step", host).forEach((el, k) => el.className = `step ${k < i ? "done" : k === i ? "run" : ""}`); i = Math.min(i + 1, steps.length - 1); }, 350);
    try {
      const res = await Api.post(`/api/repos/${state.repoId}/analyze`);
      clearInterval(tick);
      $$(".step", host).forEach((el) => el.className = "step done");
      $("#runActions", host).innerHTML = `<span style="margin-right:auto;color:var(--text-2)">${res.total} findings · ${res.functions} functions · ${res.duration_ms} ms</span><button class="btn btn-primary" id="closeRun">View results</button>`;
      $("#closeRun", host).onclick = async () => { host.remove(); await refreshRepos(); go("dashboard"); };
    } catch (err) { clearInterval(tick); host.remove(); toast(err.message, "err"); }
  }

  /* --------------------------------------------------------------- dashboard */
  VIEWS.dashboard = async (v) => {
    v.innerHTML = `<div class="grid g-6">${skeleton("sk-kpi", 6)}</div><div class="grid g-2-1">${skeleton("sk-card", 2)}</div>`;
    const d = await Api.get(`/api/dashboard?repo_id=${state.repoId}`);
    const k = d.kpis;
    const kpi = (label, value, foot, color) => `<div class="card kpi" style="--kpi-glow:${color}22"><div class="label"><span class="dot" style="background:${color}"></span>${label}</div><div class="value">${value}</div><div class="foot">${foot}</div></div>`;
    const maxRisk = Math.max(...d.file_risk.map((f) => f.score), 1);
    v.innerHTML = `
      <div class="page-head"><div><h1>Code health at a glance</h1><p>Latest analysis of <b>${esc(state.repos.find((r) => r.id === state.repoId)?.name)}</b>. Findings are hypotheses until a reviewer approves them.</p></div>
        <div class="toolbar"><button class="btn btn-ghost" data-go="assistant">${icon("chat")} Ask a question</button><button class="btn btn-secondary" data-go="findings">${icon("bug")} Start review</button></div></div>
      <div class="grid g-6">
        ${kpi("Open findings", k.open, `${k.functions} functions in ${k.files} files`, "#3D7BFF")}
        ${kpi("Critical / high", k.critical_high, "open or accepted", "#F43F5E")}
        ${kpi("Reviewed precision", k.precision == null ? "—" : pct(k.precision), `${k.accepted} accepted · ${k.rejected} rejected`, "#22C55E")}
        ${kpi("Avg. confidence", pct(k.avg_confidence), "fused evidence score", "#A78BFA")}
        ${kpi("ML-corroborated", k.ml_corroborated, "defect model agrees", "#14B8A6")}
        ${kpi("Log-corroborated", k.log_corroborated, "compiler / cppcheck agree", "#F59E0B")}
      </div>
      <div class="grid g-2-1">
        <div class="card"><div class="card-head"><h3>Priority queue</h3><span class="hint">Highest severity × confidence</span></div>
          ${d.top.length ? `<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Confidence</th></tr></thead><tbody>
          ${d.top.map((f) => `<tr class="clickable" data-f="${f.id}"><td>${sev(f.severity)}</td><td><div class="t-title">${esc(f.title)}</div><div class="loc">${esc(f.file_path)}:${f.line} · ${esc(f.function || "file scope")}</div></td><td>${sources(f.sources)}</td><td>${conf(f.confidence)}</td></tr>`).join("")}
          </tbody></table></div>` : empty("check", "Queue is clear", "No open findings — nice work.")}
        </div>
        <div class="card"><div class="card-head"><h3>Severity mix</h3><span class="hint">excl. rejected</span></div>
          <div class="donut-wrap"><div class="chart">${donut(Object.entries(d.by_severity).map(([s, n]) => ({ label: s, value: n, color: SEV_COLORS[s] })), { center: "findings" })}</div>
          <div class="legend">${Object.entries(d.by_severity).map(([s, n]) => `<div class="legend-row"><i style="background:${SEV_COLORS[s]}"></i><span style="text-transform:capitalize">${s}</span><b>${n}</b></div>`).join("")}</div></div>
          <div style="margin-top:18px" class="card-head"><h3>Review status</h3></div>
          ${hbars(Object.entries(d.by_status).map(([s, n]) => ({ label: s, value: n })))}
        </div>
      </div>
      <div class="grid g-3">
        <div class="card"><div class="card-head"><h3>Defect categories</h3></div>${hbars(Object.entries(d.by_category).sort((a, b) => b[1] - a[1]).map(([c, n]) => ({ label: c.replace(/_/g, " "), value: n })))}</div>
        <div class="card"><div class="card-head"><h3>Findings trend</h3><span class="hint"><span style="color:#3D7BFF">━</span> total &nbsp;<span style="color:#F97316">╌</span> crit/high</span></div><div class="chart">${line(d.trend)}</div></div>
        <div class="card"><div class="card-head"><h3>Complexity hotspots</h3><span class="hint">Isolation Forest</span></div>
          <div class="breakdown">${d.hotspots.map((h) => `<div class="row"><span class="loc" title="${esc(h.file)}">${esc(h.function)}()</span><div class="bar"><i style="width:${h.anomaly * 100}%;background:linear-gradient(90deg,#F59E0B,#F43F5E)"></i></div><b>${pct(h.anomaly)}</b></div>`).join("") || empty("cpu", "No functions", "Run an analysis first.")}</div>
        </div>
      </div>
      <div class="card"><div class="card-head"><h3>File risk heatmap</h3><span class="hint">Σ severity weight × confidence — click a tile to open the file</span></div>
        ${d.file_risk.length ? `<div class="heat">${d.file_risk.map((f) => { const c = heatColor(f.score, maxRisk); return `<div class="heat-tile" data-path="${esc(f.path)}" style="background:${c}.14);border-color:${c}.45)"><div class="p">${esc(f.path)}</div><div><div class="s" style="color:${c}1)">${f.score}</div><div class="n">${f.findings} findings</div></div></div>`; }).join("")}</div>` : empty("check", "No risky files", "")}
      </div>`;
    $$("[data-go]", v).forEach((b) => b.onclick = () => go(b.dataset.go));
    $$("[data-f]", v).forEach((r) => r.onclick = () => openFinding(Number(r.dataset.f)));
    $$(".heat-tile", v).forEach((t) => t.onclick = () => { state.explorer = { path: t.dataset.path, line: null }; go("explorer"); });
  };

  /* --------------------------------------------------------------- repositories */
  VIEWS.repos = async (v) => {
    await refreshRepos();
    v.innerHTML = `
      <div class="page-head"><div><h1>Repositories</h1><p>Only repositories and paths you are authorised for are visible.</p></div></div>
      <div class="grid g-3">${state.repos.map((r) => `
        <div class="card repo-card ${r.id === state.repoId ? "on" : ""}" data-id="${r.id}">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center"><h3>${esc(r.name)}</h3>
          <span class="pill ${r.scope === "full" ? "ok" : "warn"}">${r.scope === "full" ? "Full access" : "Paths: " + esc(r.scope)}</span></div>
          <div style="color:var(--text-2);font-size:13px">${esc(r.description)}</div>
          <div class="stats"><div><b>${r.files}</b><span>files</span></div><div><b>${r.open_findings}</b><span>open</span></div><div><b style="color:var(--sev-high)">${r.critical_high}</b><span>crit/high</span></div></div>
          <div style="font-size:12px;color:var(--muted)">Last run: ${r.last_run ? `${fmtDate(r.last_run.at)} by ${esc(r.last_run.by)}` : "never"}</div>
        </div>`).join("") || `<div class="card">${empty("repo", "No repositories", "You have not been granted access to any repository.")}</div>`}</div>
      ${state.repoId ? `<div class="card"><div class="card-head"><h3>Add source files or build logs</h3><span class="hint">.c .h → repository · .log .txt → build logs · max 2 MB each</span></div>
        <div class="grid g-2-1">
          <label class="dropzone" id="drop">${icon("upload")}<div style="margin-top:8px"><b>Drop files here</b> or click to browse</div><div style="font-size:12px;color:var(--muted)">Files are stored locally and never transmitted externally.</div>
            <input type="file" id="fileInput" multiple accept=".c,.h,.log,.txt" hidden></label>
          <div><div class="field"><label>Target folder for .c files</label><input class="input" id="folder" value="src"></div>
          <div class="note">After uploading, press <b>Run analysis</b> to rescan. Reviewer decisions carry over to unchanged findings via fingerprints.</div></div>
        </div></div>` : ""}
      ${state.user.role === "admin" ? `<div class="card"><div class="card-head"><h3>Create repository</h3><span class="hint">Admin only</span></div>
        <form id="newRepo" class="toolbar"><input class="input" name="name" placeholder="repo-name" required pattern="[a-zA-Z0-9._\\-]+"><input class="input" name="description" placeholder="Description" style="flex:1"><button class="btn btn-primary">Create</button></form></div>` : ""}`;
    $$(".repo-card", v).forEach((c) => c.onclick = () => selectRepo(Number(c.dataset.id)));
    const drop = $("#drop", v);
    if (drop) {
      const send = async (files) => {
        if (!files.length) return;
        const form = new FormData(); [...files].forEach((f) => form.append("files", f)); form.append("folder", $("#folder").value || "src");
        try {
          const r = await Api.upload(`/api/repos/${state.repoId}/upload`, form);
          toast(`Saved ${r.saved.length} source file(s), ${r.logs.length} log(s)${r.skipped.length ? `, skipped ${r.skipped.length}` : ""}`, "ok");
          VIEWS.repos(v);
        } catch (err) { toast(err.message, "err"); }
      };
      $("#fileInput").onchange = (e) => send(e.target.files);
      ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("drag"); }));
      ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("drag"); }));
      drop.addEventListener("drop", (e) => send(e.dataTransfer.files));
    }
    const nr = $("#newRepo", v);
    if (nr) nr.onsubmit = async (e) => {
      e.preventDefault();
      try { const r = await Api.post("/api/repos", Object.fromEntries(new FormData(nr))); toast(`Repository ${r.name} created`, "ok"); await refreshRepos(); selectRepo(r.id); }
      catch (err) { toast(err.message, "err"); }
    };
  };

  /* --------------------------------------------------------------- findings */
  VIEWS.findings = async (v) => {
    const f = state.filters;
    v.innerHTML = `
      <div class="card">
        <div class="toolbar" style="margin-bottom:14px">
          <div class="search">${icon("search")}<input class="input" id="q" placeholder="Search title, file, function, MISRA rule, CWE…" value="${esc(f.q)}"></div>
          ${["critical", "high", "medium", "low"].map((s) => `<button class="chip ${f.severity.includes(s) ? "on" : ""}" data-sev="${s}">${s}</button>`).join("")}
          <select class="input" id="st">${[["open,accepted", "Active"], ["open", "Open"], ["accepted", "Accepted"], ["rejected", "Rejected"], ["fixed", "Fixed"], ["", "All statuses"]]
            .map(([val, l]) => `<option value="${val}" ${f.status.join(",") === val ? "selected" : ""}>${l}</option>`).join("")}</select>
        </div>
        <div id="ftable">${skeleton("sk-row", 6)}</div>
      </div>
      <div class="note" style="display:flex;gap:16px;flex-wrap:wrap;align-items:center"><b>Evidence:</b> ${sources(["rules"])} rule engine ${sources(["defect_model"])} ML defect model ${sources(["compiler_log"])} compiler/static-analysis log ${sources(["injection_model"])} injection detector ${sources(["triage_model"])} triage model</div>`;
    const load = async () => {
      const params = new URLSearchParams({ repo_id: state.repoId, severity: f.severity.join(","), status: f.status.join(","), q: f.q });
      const items = await Api.get(`/api/findings?${params}`);
      $("#ftable").innerHTML = items.length ? `<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Rule</th><th>Evidence</th><th>Confidence</th><th>Status</th></tr></thead><tbody>
        ${items.map((x) => `<tr class="clickable" data-f="${x.id}"><td>${sev(x.severity)}</td>
          <td><div class="t-title">${esc(x.title)}</div><div class="loc">${esc(x.file_path)}:${x.line} · ${esc(x.function || "file scope")}</div></td>
          <td><div class="mono" style="font-size:12px">${esc(x.rule_id)}</div><div class="t-sub">${esc([x.misra_ref && "MISRA " + x.misra_ref, x.cwe].filter(Boolean).join(" · "))}</div></td>
          <td>${sources(x.sources)}</td><td>${conf(x.confidence)}</td><td>${status(x.status)}</td></tr>`).join("")}</tbody></table></div>
          <div style="margin-top:10px;font-size:12px;color:var(--muted)">${items.length} finding(s)</div>`
        : empty("search", "No findings match", "Try clearing filters, or run a new analysis.");
      $$("[data-f]", v).forEach((r) => r.onclick = () => openFinding(Number(r.dataset.f), load));
    };
    let timer;
    $("#q", v).oninput = (e) => { clearTimeout(timer); timer = setTimeout(() => { f.q = e.target.value; load(); }, 250); };
    $$("[data-sev]", v).forEach((c) => c.onclick = () => { const s = c.dataset.sev; f.severity = f.severity.includes(s) ? f.severity.filter((x) => x !== s) : [...f.severity, s]; c.classList.toggle("on"); load(); });
    $("#st", v).onchange = (e) => { f.status = e.target.value ? e.target.value.split(",") : []; load(); };
    await load();
  };

  /* --------------------------------------------------------------- finding drawer */
  async function openFinding(id, onChange) {
    const host = document.createElement("div");
    host.innerHTML = `<div class="overlay"></div><aside class="drawer" role="dialog" aria-modal="true"><div class="drawer-body">${skeleton("sk-card", 2)}</div></aside>`;
    document.body.appendChild(host);
    const onKey = (e) => e.key === "Escape" && close();
    const close = () => { host.remove(); document.removeEventListener("keydown", onKey); };
    document.addEventListener("keydown", onKey);
    $(".overlay", host).onclick = close;
    let f;
    try { f = await Api.get(`/api/findings/${id}`); } catch (err) { close(); toast(err.message, "err"); return; }
    const hl = highlight(f.context.map((c) => c.text).join("\n"));
    const comps = [["Rule engine", f.rule_conf, "#3D7BFF"], ["Defect model", f.ml_conf, "#14B8A6"], ["Triage model", f.triage_score, "#A78BFA"]];
    const fixHtml = `<div class="note"><b>Recommended remediation.</b> ${esc(f.suggested_fix)}</div>
      <p style="font-size:12px;color:var(--muted);margin:8px 0 0">Fixes are suggestions. They must compile, pass tests and be approved before merge — ECU Sentinel never changes code automatically.</p>`;
    $(".drawer", host).innerHTML = `
      <div class="drawer-head">
        <div class="row">${sev(f.severity)} ${status(f.status)} <span class="pill">${esc(f.rule_id)}</span>${f.misra_ref ? `<span class="pill pri">MISRA ${esc(f.misra_ref)}</span>` : ""}${f.cwe ? `<span class="pill err">${esc(f.cwe)}</span>` : ""}<span class="pill">${esc(f.guideline)}</span>
          <button class="icon-btn" id="dClose" style="margin-left:auto" aria-label="Close">${icon("close")}</button></div>
        <h2>${esc(f.title)}</h2>
        <div class="loc">${esc(f.file_path)}:${f.line} · ${esc(f.function || "file scope")}</div>
      </div>
      <div class="drawer-body">
        <div>${md(f.message, false)}</div>
        <div class="code">${f.context.map((c, i) => `<div class="ln ${c.n === f.line ? "hl" : ""}"><span class="g"></span><span class="n">${c.n}</span><span class="c">${hl[i] || " "}</span></div>`).join("")}</div>
        <div class="card" style="padding:14px"><div class="card-head" style="margin-bottom:10px"><h3>Why this confidence? (${pct(f.confidence)})</h3>${sources(f.sources)}</div>
          <div class="breakdown">${comps.map(([l, val, c]) => `<div class="row"><span>${l}</span><div class="bar"><i style="width:${val * 100}%;background:${c}"></i></div><b>${pct(val)}</b></div>`).join("")}
          ${f.sources.includes("compiler_log") ? `<div class="row"><span>Compiler / log</span><div><span class="pill warn">Corroborated (+8%)</span></div><b></b></div>` : ""}</div></div>
        <div class="tabs"><button class="tab on" data-t="fix">Suggested fix</button><button class="tab" data-t="explain">✦ Explain with guidelines</button></div>
        <div id="tabBody">${fixHtml}</div>
        ${f.reviewer ? `<div class="card" style="padding:14px"><dl class="kv"><dt>Reviewed by</dt><dd>${esc(f.reviewer)}</dd><dt>When</dt><dd>${fmtDate(f.reviewed_at)}</dd><dt>Comment</dt><dd>${esc(f.review_comment || "—")}</dd></dl></div>` : ""}
      </div>
      <div class="drawer-foot">
        <textarea class="input" id="rc" rows="2" placeholder="${canReview() ? "Reviewer comment (required when rejecting)" : "Comment (developers can mark fixed or dispute)"}"></textarea>
        <div class="actions">
          ${canReview() ? `<button class="btn btn-success" data-s="accepted">${icon("check")} Accept</button><button class="btn btn-danger" data-s="rejected">${icon("x")} Reject (false positive)</button>` : ""}
          <button class="btn btn-ghost" data-s="fixed">Mark fixed</button>
          ${canReview() ? `<button class="btn btn-ghost" data-s="open">Reopen</button>` : `<button class="btn btn-ghost" data-s="disputed">Dispute</button>`}
          <button class="btn btn-ghost" id="toCode" style="margin-left:auto">${icon("code")} Open in explorer</button>
        </div>
      </div>`;
    $("#dClose", host).onclick = close;
    $("#toCode", host).onclick = () => { close(); state.explorer = { path: f.file_path, line: f.line }; go("explorer"); };
    $$(".tab", host).forEach((t) => t.onclick = async () => {
      $$(".tab", host).forEach((x) => x.classList.toggle("on", x === t));
      const body = $("#tabBody", host);
      if (t.dataset.t === "fix") { body.innerHTML = fixHtml; return; }
      body.innerHTML = skeleton("sk-row", 3);
      try {
        const e = await Api.get(`/api/findings/${id}/explain`);
        body.innerHTML = `<div class="md">${md(e.explanation, false)}</div><span class="pill ${e.used_llm ? "ai" : "ml"}">${e.used_llm ? "Local LLM" : "Grounded engine"}</span>
          <div class="sources">${e.guidelines.map((g) => `<details class="source"><summary><span class="cite">${g.n}</span>${esc(g.title)}</summary><pre>${esc(g.snippet)}</pre></details>`).join("")}</div>`;
      } catch (err) { body.innerHTML = `<div class="note warn">${esc(err.message)}</div>`; }
    });
    $$("[data-s]", host).forEach((b) => b.onclick = async () => {
      try {
        await Api.post(`/api/findings/${id}/review`, { status: b.dataset.s, comment: $("#rc", host).value });
        toast(`Finding marked ${b.dataset.s}`, "ok"); close();
        await refreshRepos();
        if (onChange) onChange(); else renderView();
      } catch (err) { toast(err.message, "err"); }
    });
  }

  /* --------------------------------------------------------------- explorer */
  VIEWS.explorer = async (v) => {
    const files = await Api.get(`/api/repos/${state.repoId}/files`);
    if (!files.length) { v.innerHTML = `<div class="card">${empty("folder", "No files", "Upload C sources on the Repositories page.")}</div>`; return; }
    if (!state.explorer.path || !files.find((f) => f.path === state.explorer.path)) state.explorer.path = (files.find((f) => f.path.endsWith(".c")) || files[0]).path;
    const maxRisk = Math.max(...files.map((f) => f.risk), 1);
    const groups = {};
    files.forEach((f) => { const d = f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : "."; (groups[d] = groups[d] || []).push(f); });
    v.innerHTML = `<div class="explorer">
      <div class="card" style="padding:10px"><div class="tree">${Object.entries(groups).map(([d, fs]) => `<div class="dir">${esc(d)}</div>` + fs.map((f) =>
        `<div class="file ${f.path === state.explorer.path ? "on" : ""}" data-p="${esc(f.path)}"><span class="risk-dot" style="background:${f.findings ? heatColor(f.risk, maxRisk) + "1)" : "var(--success)"}"></span>${esc(f.path.split("/").pop())}${f.findings ? `<span class="cnt" style="color:${heatColor(f.risk, maxRisk)}1)">${f.findings}</span>` : ""}</div>`).join("")).join("")}</div></div>
      <div class="card code-panel" style="padding:0;overflow:hidden;display:flex;flex-direction:column"><div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:center"><span class="loc" id="cpath"></span><span style="flex:1"></span><span class="pill" id="cmeta"></span></div><div class="code" id="code" style="border:0;border-radius:0;flex:1">${skeleton("sk-card")}</div></div>
      <div class="fn-col"><div class="fn-list" id="fns"></div></div></div>`;
    $$(".file", v).forEach((el) => el.onclick = () => { state.explorer = { path: el.dataset.p, line: null }; VIEWS.explorer(v); });
    const data = await Api.get(`/api/repos/${state.repoId}/file?path=${encodeURIComponent(state.explorer.path)}`);
    $("#cpath").textContent = data.path;
    $("#cmeta").textContent = `${data.loc} LOC · ${data.functions.length} functions · ${data.findings.length} findings`;
    const byLine = {};
    data.findings.forEach((f) => (byLine[f.line] = byLine[f.line] || []).push(f));
    const starts = new Set(data.functions.map((fn) => fn.start_line));
    const order = ["low", "medium", "high", "critical"];
    $("#code").innerHTML = highlight(data.content).map((h, i) => {
      const n = i + 1, fs = byLine[n];
      const worst = fs ? fs.reduce((a, b) => (order.indexOf(b.severity) > order.indexOf(a.severity) ? b : a)) : null;
      return `<div class="ln ${fs ? "hl" : ""} ${starts.has(n) ? "fn-start" : ""}" id="L${n}"><span class="g">${worst ? `<i style="background:${SEV_COLORS[worst.severity]}" data-f="${worst.id}" title="${esc(fs.map((x) => x.title).join("\n"))}"></i>` : ""}</span><span class="n">${n}</span><span class="c">${h || " "}</span></div>`;
    }).join("");
    $$("#code [data-f]").forEach((d) => d.onclick = () => openFinding(Number(d.dataset.f), () => VIEWS.explorer(v)));
    $("#fns").innerHTML = data.functions.map((fn) => `<div class="fn-card" data-l="${fn.start_line}">
      <div style="display:flex;justify-content:space-between;gap:8px"><span class="name">${esc(fn.name)}()</span>${fn.ml_label !== "clean" ? `<span class="pill ml" title="Defect classifier prediction">ML: ${esc(fn.ml_label.replace(/_/g, " "))}</span>` : `<span class="pill ok" title="Defect classifier prediction">ML: clean</span>`}</div>
      <div class="metrics"><div class="metric"><b>${fn.metrics.cyclomatic}</b><span>cyclomatic</span></div><div class="metric"><b>${fn.metrics.nesting}</b><span>nesting</span></div><div class="metric"><b style="color:${fn.anomaly > 0.6 ? "var(--sev-high)" : "inherit"}">${pct(fn.anomaly)}</b><span>anomaly</span></div></div>
      <p>${md(fn.summary, false).replace(/<\/?p>/g, "")}</p></div>`).join("") || empty("code", "No functions", "Header or declaration-only file.");
    $$(".fn-card", v).forEach((c) => c.onclick = () => $(`#L${c.dataset.l}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
    if (state.explorer.line) setTimeout(() => $(`#L${state.explorer.line}`)?.scrollIntoView({ block: "center" }), 50);
  };

  /* --------------------------------------------------------------- build logs */
  VIEWS.logs = async (v) => {
    const logs = await Api.get(`/api/repos/${state.repoId}/logs`);
    v.innerHTML = `<div class="grid g-1-2">
      <div class="card"><div class="card-head"><h3>Paste or load a build log</h3></div>
        <div class="field"><label>Log name</label><input class="input" id="lname" value="${esc(logs[0]?.name || "build.log")}"></div>
        <div class="field"><label>GCC / Clang / cppcheck / linker output</label><textarea class="input mono" id="ltext" rows="14" placeholder="src/foo.c:12:5: warning: ...">${esc(logs[0]?.content || "")}</textarea></div>
        <button class="btn btn-primary btn-block" id="lgo">${icon("spark")} Classify &amp; cluster warnings</button>
        <p style="font-size:12px;color:var(--muted)">A TF-IDF + logistic-regression model labels each warning; agglomerative clustering groups them by root cause; warnings are linked to findings within ±2 lines.</p></div>
      <div id="lres">${state.lastLog ? "" : `<div class="card">${empty("log", "No log analysed yet", "The latest stored build log is pre-filled — press Classify.")}</div>`}</div></div>`;
    const show = (r) => {
      $("#lres").innerHTML = `<div class="grid g-4" style="margin-bottom:16px">
        ${[["Messages", r.stats.total], ["Errors", r.stats.errors], ["Root-cause groups", r.stats.clusters], ["Linked to findings", r.stats.linked]].map(([l, n]) => `<div class="card kpi"><div class="label">${l}</div><div class="value">${n}</div></div>`).join("")}</div>
        <div class="card" style="margin-bottom:16px"><div class="card-head"><h3>Fix order (root-cause groups)</h3><span class="hint">errors & undefined behaviour first</span></div>
        <div class="grid g-2">${r.clusters.map((c, i) => `<div class="card cluster" style="padding:14px;border-left-color:${["#F43F5E", "#F97316", "#F59E0B", "#38BDF8"][c.priority]}">
          <div style="display:flex;justify-content:space-between;gap:8px"><b>#${i + 1} ${esc(c.category_label)}</b><span class="pill">${c.size}×</span></div>
          <div class="loc" style="margin:6px 0">${esc(c.representative)}</div><div style="font-size:12px;color:var(--muted)">${c.files.map(esc).join(", ") || "linker"}${c.linked_findings ? ` · <span style="color:var(--secondary)">${c.linked_findings} linked finding(s)</span>` : ""}</div></div>`).join("")}</div></div>
        <div class="card"><div class="table-wrap"><table><thead><tr><th>Level</th><th>Location</th><th>Message</th><th>ML category</th><th>Linked</th></tr></thead><tbody>
        ${r.warnings.map((w) => `<tr><td><span class="pill ${w.level === "error" ? "err" : "warn"}">${esc(w.level)}</span></td><td class="loc">${esc(w.file || "—")}${w.line ? ":" + w.line : ""}</td><td>${esc(w.message)}${w.flag ? ` <span class="t-sub">${esc(w.flag)}</span>` : ""}</td>
          <td><span class="pill ml">${esc(w.category_label)}</span> <span class="t-sub">${pct(w.confidence)}</span></td><td>${w.linked_findings.map((f) => `<button class="cite" data-f="${f.id}" title="${esc(f.title)}">F${f.id}</button>`).join("") || "—"}</td></tr>`).join("")}</tbody></table></div></div>`;
      $$("[data-f]", $("#lres")).forEach((b) => b.onclick = () => openFinding(Number(b.dataset.f)));
    };
    if (state.lastLog?.repo === state.repoId) show(state.lastLog.data);
    $("#lgo").onclick = async () => {
      const content = $("#ltext").value.trim();
      if (!content) { toast("Paste a build log first", "err"); return; }
      $("#lres").innerHTML = `<div class="card">${skeleton("sk-row", 6)}</div>`;
      try { const r = await Api.post("/api/logs/analyze", { repo_id: state.repoId, name: $("#lname").value, content }); state.lastLog = { repo: state.repoId, data: r }; show(r); }
      catch (err) { toast(err.message, "err"); $("#lres").innerHTML = ""; }
    };
  };

  /* --------------------------------------------------------------- assistant */
  VIEWS.assistant = async (v) => {
    const suggestions = ["What does Brake_ComputePressure do and is it safe?", "Why is strcpy not allowed in our coding standard?", "How should interrupts share data with tasks?", "Where is UDS security access handled?"];
    v.innerHTML = `<div class="card chat"><div class="chat-scroll" id="cs"></div>
      <form class="composer" id="cf"><div class="suggestions">${suggestions.map((s) => `<button type="button" class="chip" data-s="${esc(s)}">${esc(s)}</button>`).join("")}</div>
      <div class="row"><textarea class="input" id="ci" placeholder="Ask about functions, control flow, warnings or coding rules…" rows="1"></textarea><button class="btn btn-primary" id="cb" aria-label="Send">${icon("send")}</button></div></form></div>`;
    const draw = () => {
      $("#cs").innerHTML = state.chat.length ? state.chat.map((m, idx) => m.role === "user"
        ? `<div class="msg user"><div class="bubble">${esc(m.text)}</div></div>`
        : `<div class="msg"><div class="bot-ico">${icon("spark")}</div><div class="bubble" data-m="${idx}">${m.loading ? `<div class="skeleton sk-row" style="width:320px"></div>` : `<div class="md">${md(m.answer)}</div>
          <div class="meta-row">${m.blocked ? `<span class="pill err">Blocked: injection ${pct(m.injection_score)}</span>` : `<span class="pill ${m.used_llm ? "ai" : "ml"}">${m.used_llm ? "Local LLM" : "Grounded engine"}</span>`}
          ${m.quarantined ? `<span class="pill warn">${m.quarantined} source(s) quarantined</span>` : ""}<span class="pill">${(m.citations || []).length} citations</span></div>
          <div class="sources">${(m.citations || []).map((c) => `<details class="source" id="c${idx}-${c.n}"><summary><span class="cite">${c.n}</span>${esc(c.title)}${c.kind === "code" ? `<span class="loc" style="margin-left:auto">${esc(c.path)}:${c.start_line}-${c.end_line}</span>` : `<span class="pill" style="margin-left:auto">guideline</span>`}</summary><pre>${esc(c.snippet)}</pre></details>`).join("")}</div>`}</div></div>`).join("")
        : empty("chat", "Ask the codebase", "Answers are built only from code you are authorised to see and from approved internal guidelines — every claim is cited.");
      $$(".cite[data-cite]", v).forEach((b) => b.onclick = () => { const idx = b.closest("[data-m]").dataset.m; const d = $(`#c${idx}-${b.dataset.cite}`); if (d) { d.open = true; d.scrollIntoView({ behavior: "smooth", block: "nearest" }); } });
      $("#cs").scrollTop = $("#cs").scrollHeight;
    };
    const ask = async (q) => {
      if (!q.trim()) return;
      state.chat.push({ role: "user", text: q }, { role: "bot", loading: true });
      draw(); $("#ci").value = "";
      try { const r = await Api.post("/api/qa", { repo_id: state.repoId, question: q }); state.chat[state.chat.length - 1] = { role: "bot", ...r }; }
      catch (err) { state.chat[state.chat.length - 1] = { role: "bot", answer: `Error: ${err.message}`, citations: [] }; }
      draw();
    };
    $$("[data-s]", v).forEach((b) => b.onclick = () => ask(b.dataset.s));
    $("#cf").onsubmit = (e) => { e.preventDefault(); ask($("#ci").value); };
    $("#ci").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask($("#ci").value); } };
    draw();
  };

  /* --------------------------------------------------------------- models */
  VIEWS.models = async (v) => {
    v.innerHTML = `<div class="grid g-3">${skeleton("sk-card", 6)}</div>`;
    const m = await Api.get("/api/models");
    const M = m.metrics;
    const card = (title, purpose, algo, metrics, tag) => `<div class="card model-card"><div style="display:flex;justify-content:space-between;gap:8px"><h3>${title}</h3><span class="pill ml">${tag}</span></div>
      <div style="color:var(--text-2);font-size:13px;margin-top:6px">${purpose}</div><div class="metric-grid">${metrics.map(([l, val]) => `<div class="m"><b>${val}</b><span>${l}</span></div>`).join("")}</div><div class="algo">${esc(algo || "")}</div></div>`;
    const d = M.defect_classifier, t = M.triage_model, l = M.log_classifier, i = M.injection_detector, a = M.complexity_anomaly;
    v.innerHTML = `
      <div class="page-head"><div><h1>Five local models, one decision</h1><p>All models train on-prem in ~10 s and never call external services.</p></div>
        <div class="toolbar"><span class="pill ${m.llm.available ? "ai" : "ml"}">${m.llm.available ? `LLM: ${esc(m.llm.model)}` : "LLM: grounded engine (offline)"}</span><span class="pill">Embeddings: ${esc(m.embeddings)}</span>
        ${canReview() ? `<button class="btn btn-primary" id="rt">${icon("refresh")} Retrain triage from reviews</button>` : ""}</div></div>
      <div class="grid g-3">
        ${card("Defect classifier", "Predicts the defect class of each function; corroborates rule findings and surfaces defects rules miss.", d.algorithm, [["accuracy", pct(d.accuracy)], ["macro F1", pct(d.macro_f1)], ["train", d.train_samples]], "Logistic Reg.")}
        ${card("Triage model", "Learns from reviewer accept/reject decisions to rank findings and cut false positives.", t.algorithm, [["ROC-AUC", t.roc_auc], ["precision", pct(t.precision)], ["reviewer labels", t.reviewer_labels]], "Gradient Boost")}
        ${card("Log classifier + clustering", "Categorises compiler / cppcheck messages and groups them into root causes.", l.algorithm, [["accuracy", pct(l.accuracy)], ["macro F1", pct(l.macro_f1)], ["train", l.train_samples]], "LR + Agglom.")}
        ${card("Prompt-injection detector", "Scores repository comments and user questions; quarantines instruction-like text from AI context.", i.algorithm, [["ROC-AUC", i.roc_auc], ["accuracy", pct(i.accuracy)], ["train", i.train_samples]], "Logistic Reg.")}
        ${card("Complexity anomaly", "Finds outlier functions from 12 code metrics, relative to a reference corpus and to the repo itself.", a.algorithm, [["reference fns", a.reference_functions], ["flagged ref.", a.flagged_in_reference], ["features", 12]], "Isolation Forest")}
        <div class="card"><h3>How confidence is fused</h3><div class="md" style="margin-top:10px;font-size:13px">${md("For rule findings: **0.5 × rule** + **0.2 × defect model** + **0.3 × triage** + **0.08** if a compiler/static-analysis message agrees within ±2 lines.\n\nML-only findings are capped lower and are always labelled as hypotheses.\n\nReviewer rejections are remembered by fingerprint and fed back into the triage model.", false)}</div>
          <div class="note" style="margin-top:12px">Reviewer labels available: <b>${m.reviewer_labels_available}</b></div></div>
      </div>`;
    const rt = $("#rt", v);
    if (rt) rt.onclick = async () => {
      rt.disabled = true; rt.textContent = "Retraining…";
      try { const r = await Api.post("/api/models/retrain"); toast(`Triage retrained on ${r.reviewer_labels} reviewer labels; ${r.rescored} findings re-scored`, "ok"); VIEWS.models(v); }
      catch (err) { toast(err.message, "err"); rt.disabled = false; }
    };
  };

  /* --------------------------------------------------------------- reports */
  VIEWS.reports = async (v) => {
    let scope = "approved", fmt = "md";
    v.innerHTML = `<div class="grid g-1-2">
      <div class="card"><div class="card-head"><h3>Structured review report</h3></div>
        <div class="field"><label>Scope</label><div class="segmented" id="scope"><button class="on" data-v="approved">Approved only</button><button data-v="all">All findings</button></div></div>
        <div class="field"><label>Format</label><div class="segmented" id="fmt"><button class="on" data-v="md">Markdown</button><button data-v="json">JSON</button><button data-v="sarif">SARIF 2.1</button></div></div>
        <div class="toolbar"><button class="btn btn-ghost" id="prev">Preview</button><button class="btn btn-primary" id="dl">${icon("download")} Download</button></div>
        <hr style="border:0;border-top:1px solid var(--border);margin:18px 0">
        <h3>Write to workflow system</h3><p style="color:var(--text-2);font-size:13px">Exports only reviewer-approved findings to the workflow outbox (integration point for Jira / Polarion / internal tracker).</p>
        ${canReview() ? `<button class="btn btn-secondary" id="push">${icon("inbox")} Push approved findings</button>` : `<span class="pill warn">Reviewer role required</span>`}
        <div class="note warn" style="margin-top:16px">Governance: AI output must be traceable to approved sources and reviewed by authorised specialists before use in compliance, release or vehicle validation.</div></div>
      <div class="card"><div class="card-head"><h3>Preview</h3><span class="hint">SARIF opens in VS Code, GitHub code scanning, Azure DevOps</span></div><pre class="preview" id="pv">Choose options and press Preview.</pre></div></div>`;
    const seg = (id, set) => $$(`#${id} button`, v).forEach((b) => b.onclick = () => { $$(`#${id} button`, v).forEach((x) => x.classList.toggle("on", x === b)); set(b.dataset.v); });
    seg("scope", (x) => { scope = x; }); seg("fmt", (x) => { fmt = x; });
    const url = () => `/api/reports/${state.repoId}?fmt=${fmt}&scope=${scope}`;
    $("#prev").onclick = async () => {
      try { const res = await Api.get(url()); $("#pv").textContent = (typeof res === "string" ? res : JSON.stringify(res, null, 2)).slice(0, 20000); }
      catch (err) { toast(err.message, "err"); }
    };
    $("#dl").onclick = async () => { try { const r = await Api.download(url(), `report.${fmt}`); toast(`Downloaded ${r.name}`, "ok"); } catch (err) { toast(err.message, "err"); } };
    const push = $("#push", v);
    if (push) push.onclick = async () => { try { const r = await Api.post(`/api/reports/${state.repoId}/push`); toast(`${r.count} approved finding(s) written to ${r.file}`, "ok"); } catch (err) { toast(err.message, "err"); } };
  };

  /* --------------------------------------------------------------- audit */
  VIEWS.audit = async (v) => {
    if (!canReview()) { v.innerHTML = `<div class="card">${empty("lock", "Restricted", "The audit trail is visible to reviewers and administrators.")}</div>`; return; }
    v.innerHTML = `<div class="card">${skeleton("sk-row", 8)}</div>`;
    const [items, users] = await Promise.all([Api.get("/api/audit?limit=300"), state.user.role === "admin" ? Api.get("/api/users") : Promise.resolve(null)]);
    const tone = (a) => a.includes("denied") || a.includes("failed") || a.includes("blocked") ? "err" : a.startsWith("finding") ? "pri" : a.startsWith("model") ? "ml" : "";
    v.innerHTML = `${users ? `<div class="card"><div class="card-head"><h3>Users &amp; access grants</h3></div><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Repository / path grants</th></tr></thead><tbody>
      ${users.map((u) => `<tr><td><b>${esc(u.full_name)}</b><div class="t-sub">${esc(u.username)}</div></td><td><span class="pill pri">${esc(u.role)}</span></td><td>${u.role === "admin" ? "<span class='pill ok'>All repositories</span>" : u.grants.map((g) => `<span class="pill">${esc(g.repo)}${g.path_prefix ? " / " + esc(g.path_prefix) : ""}</span>`).join(" ")}</td></tr>`).join("")}</tbody></table></div></div>` : ""}
      <div class="card"><div class="card-head"><h3>Audit events</h3><span class="hint">${items.length} most recent</span></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>
      ${items.map((a) => `<tr><td class="t-sub" style="white-space:nowrap">${fmtDate(a.ts)}</td><td>${esc(a.username)}</td><td><span class="pill ${tone(a.action)}">${esc(a.action)}</span></td><td class="loc">${esc(a.target)}</td><td class="t-sub">${esc(a.detail)}</td></tr>`).join("")}</tbody></table></div></div>`;
  };

  /* --------------------------------------------------------------- boot */
  async function boot() {
    if (!Api.session.token) { renderLogin(); return; }
    try { state.user = await Api.get("/api/auth/me"); await refreshRepos(); }
    catch { Api.session.clear(); renderLogin(); return; }
    const h = location.hash.slice(1);
    if (TITLES[h]) state.view = h;
    renderShell();
  }
  window.addEventListener("auth:expired", () => { toast("Session expired, please sign in again", "err"); renderLogin(); });
  boot();
})();
