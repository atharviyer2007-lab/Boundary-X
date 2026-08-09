const state = {
  changes: [],
  analysis: null,
  source: "sample",     // "sample" | "diff"
  diffMeta: null,       // { files_touched, parsed_changes, parse_warnings } for diff-sourced analyses
};

// Read once from the <meta> tag the server injects into index.html. Every
// call to a protected /api/* route needs this in the X-API-Key header.
const API_KEY = document.querySelector('meta[name="api-key"]')?.content || "";

let navToken = 0;

const NODE_COLOR = { identity: "#8B96A8", iam: "#FBBF24", data: "#F87171", service: "#22D3EE" };

const ANALYSIS_STEPS = [
  "Parsing infrastructure diff",
  "Building dependency graph",
  "Comparing before / after state",
  "Analyzing IAM trust boundaries",
  "Analyzing network exposure",
  "Tracing attack paths",
  "Searching for minimum causal change",
];

const STEP_LABELS = ["Upload", "Compare", "Analyze", "Boundary", "Min. Change", "Remediate"];

const views = ["landing", "input", "analyzing", "result", "dashboard"];

function goto(name) {
  navToken++;
  views.forEach(v => document.getElementById(`view-${v}`).classList.remove("visible"));
  document.getElementById(`view-${name}`).classList.add("visible");
  window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });

  if (name === "input") renderInput();
  if (name === "analyzing") runAnalyzing();
  if (name === "result") startResult();
  if (name === "dashboard") renderDashboard();
}

document.addEventListener("click", e => {
  const t = e.target.closest("[data-goto]");
  if (!t) return;
  const target = t.dataset.goto;
  if (target === "result-stage-2") { showResultStage(2); return; }
  if (target === "result-stage-3") { showResultStage(3); return; }
  if (target === "result-stage-4") { showResultStage(4); return; }
  goto(target);
});

async function fetchJSON(url, opts) {
  const res = await fetchWithRetry(url, opts);
  if (!res.ok) throw new Error(`${url} → ${res.status}`);
  return res.json();
}

// Wraps fetch with one automatic retry and a clearer error message when the
// request never reaches the server at all (network drop, backend restarted
// mid-request, etc.) vs. when the server responded with an error status.
// Also attaches the X-API-Key header required by every protected /api/* route.
async function fetchWithRetry(url, opts = {}, retries = 1) {
  const headers = { ...(opts.headers || {}), "X-API-Key": API_KEY };
  try {
    const res = await fetch(url, { ...opts, headers });
    if (res.status === 401) {
      throw Object.assign(new Error("Unauthorized — the page's API key doesn't match the server. Reload the page."), { isAuthError: true });
    }
    return res;
  } catch (err) {
    if (err.isAuthError) throw err;
    if (retries > 0) {
      await new Promise(r => setTimeout(r, 400));
      return fetchWithRetry(url, opts, retries - 1);
    }
    throw new Error(
      "Could not reach the server. Make sure `python app.py` is still running, " +
      "and that this page was opened as http://127.0.0.1:5000 (not a local file)."
    );
  }
}

async function loadChanges() {
  if (state.changes.length) return state.changes;
  state.changes = await fetchJSON("/api/changes");
  return state.changes;
}

function renderStepper(container, active) {
  if (!container) return;
  container.innerHTML = "";
  STEP_LABELS.forEach((label, i) => {
    const status = i < active ? "done" : i === active ? "active" : "pending";
    const wrap = document.createElement("div");
    wrap.className = "step-item";
    wrap.innerHTML = `
      <div class="step-dot ${status === "active" ? "active" : status === "done" ? "done" : ""}">${status === "done" ? "&#10003;" : i + 1}</div>
      <span class="step-label ${status !== "pending" ? "on" : ""}">${label}</span>
    `;
    container.appendChild(wrap);
    if (i < STEP_LABELS.length - 1) {
      const line = document.createElement("div");
      line.className = "step-line" + (i < active ? " on" : "");
      wrap.appendChild(line);
    }
  });
}

function mountHeader(targetId, activeStep, prTagText) {
  const tpl = document.getElementById("tpl-shell-header").content.cloneNode(true);
  const target = document.getElementById(targetId);
  target.innerHTML = "";
  target.appendChild(tpl);
  if (prTagText) {
    target.querySelector(".pr-tag").innerHTML = prTagText;
  }
  // Template uses class="stepper" (not id) so headers can be mounted into
  // multiple views without duplicate IDs.
  renderStepper(target.querySelector(".stepper"), activeStep);
}

function currentPrTag() {
  if (state.source === "diff" && state.diffMeta) {
    const n = state.diffMeta.files_touched.length;
    return `&#9670; Pasted diff · ${n} file${n === 1 ? "" : "s"}`;
  }
  return `&#9670; PR #1843 · payments-api`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function buildDiffLines(minus, plus) {
  return [
    { t: 'resource "aws_iam_role" "prod_deploy_role" {', c: "ctx" },
    { t: '  name = "prod-deploy-role"', c: "ctx" },
    { t: "", c: "ctx" },
    { t: "  assume_role_policy = jsonencode({", c: "ctx" },
    { t: "    Statement = [{", c: "ctx" },
    { t: '      Effect = "Allow"', c: "ctx" },
    { t: '      Principal = { Federated = "token.actions.githubusercontent.com" }', c: "ctx" },
    { t: '      Action = "sts:AssumeRoleWithWebIdentity"', c: "ctx" },
    { t: "      Condition = {", c: "ctx" },
    { t: "        StringLike = {", c: "ctx" },
    { t: `-         ${minus}`, c: "minus" },
    { t: `+         ${plus}`, c: "plus" },
    { t: "        }", c: "ctx" },
    { t: "      }", c: "ctx" },
    { t: "    }]", c: "ctx" },
    { t: "  })", c: "ctx" },
    { t: "}", c: "ctx" },
  ];
}

function renderChangeRows(container, changes) {
  container.innerHTML = changes.map((c, i) => `
    <div class="change-row${c.security_pattern_detected ? " flagged" : ""}" style="animation-delay:${Math.min(i * 25, 400)}ms">
      <span class="idx">#${c.id}</span>
      <span class="txt">${escapeHtml(c.description)}</span>
      ${c.security_pattern_detected ? '<span class="flag-badge" title="Widens a trust or access condition">&#9888;</span>' : ""}
    </div>
  `).join("");
}

async function renderInput() {
  mountHeader("input-header", 0, currentPrTag());

  // Attach the tab handlers FIRST so "Sample PR" / "Paste a diff" always
  // work, even if the backend is unreachable. (Previously the handler was
  // attached after an await that could throw, leaving the tabs dead.)
  initSourceTabs();

  let changes = [];
  try {
    changes = await loadChanges();
    renderChangeRows(document.getElementById("changes-grid"), changes);

    // Optional-chain through remediation.diff — it can be null when the
    // causal change has no diff block.
    const remDiff = state.analysis?.remediation?.diff;
    const minus = remDiff ? remDiff.add : '"token.actions.githubusercontent.com:sub" = "repo:trusted-org/*"';
    const plus = remDiff ? remDiff.remove : '"token.actions.githubusercontent.com:sub" = "repo:*"';

    document.getElementById("diff-block").innerHTML =
      buildDiffLines(minus, plus).map(l => {
        const cls = l.c === "minus" ? "l-minus" : l.c === "plus" ? "l-plus" : "l-ctx";
        return `<span class="${cls}">${escapeHtml(l.t) || "&nbsp;"}</span>`;
      }).join("");
  } catch (err) {
    console.error(err);
    document.getElementById("changes-grid").innerHTML =
      `<div class="change-row"><span class="txt" style="color:var(--red)">&#9888; Could not load changes — is the backend running? (${escapeHtml(err.message)})</span></div>`;
    document.getElementById("diff-block").textContent =
      "// Backend unreachable — start it with:  python app.py   then reload.";
  }
}

function initSourceTabs() {
  const tabs = document.getElementById("source-tabs");
  const samplePanel = document.getElementById("sample-panel");
  const diffPanel = document.getElementById("diff-paste-panel");

  function setSource(src) {
    tabs.querySelectorAll(".source-tab").forEach(b => b.classList.toggle("active", b.dataset.source === src));
    samplePanel.classList.toggle("hidden", src !== "sample");
    diffPanel.classList.toggle("hidden", src !== "diff");
    if (src === "sample") {
      state.source = "sample";
      state.diffMeta = null;
      state.analysis = null;
    }
  }

  tabs.onclick = e => {
    const btn = e.target.closest(".source-tab");
    if (!btn) return;
    setSource(btn.dataset.source);
  };

  const errBox = document.getElementById("diff-error");
  const parseBtn = document.getElementById("parse-diff-btn");
  const preview = document.getElementById("diff-preview");

  parseBtn.onclick = async () => {
    const text = document.getElementById("diff-textarea").value.trim();
    errBox.classList.add("hidden");
    if (!text) {
      errBox.textContent = "Paste a unified diff first.";
      errBox.classList.remove("hidden");
      return;
    }
    parseBtn.disabled = true;
    const originalLabel = parseBtn.innerHTML;
    parseBtn.innerHTML = "Parsing&hellip;";
    try {
      const res = await fetchWithRetry("/api/ingest-diff", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ diff: text }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `Request failed (${res.status})`);
      }
      state.analysis = data;
      state.source = "diff";
      state.diffMeta = {
        files_touched: data.files_touched,
        parsed_changes: data.parsed_changes,
        parse_warnings: data.parse_warnings,
      };
      renderChangeRows(document.getElementById("diff-changes-grid"), data.parsed_changes);
      document.getElementById("diff-preview-eyebrow").innerHTML =
        `&#9776; ${data.parsed_changes.length} change(s) across ${data.files_touched.length} file(s)`;
      preview.classList.remove("hidden");
      mountHeader("input-header", 0, currentPrTag());
    } catch (err) {
      console.error(err);
      errBox.textContent = err.message || "Could not parse this diff.";
      errBox.classList.remove("hidden");
      preview.classList.add("hidden");
    } finally {
      parseBtn.disabled = false;
      parseBtn.innerHTML = originalLabel;
    }
  };

  setSource(state.source === "diff" && state.diffMeta ? "diff" : "sample");
  if (state.source === "diff" && state.diffMeta) {
    renderChangeRows(document.getElementById("diff-changes-grid"), state.diffMeta.parsed_changes);
    document.getElementById("diff-preview-eyebrow").innerHTML =
      `&#9776; ${state.diffMeta.parsed_changes.length} change(s) across ${state.diffMeta.files_touched.length} file(s)`;
    document.getElementById("diff-preview").classList.remove("hidden");
  }

  initDiffUpload();
}

// Lets a person upload a .diff/.patch/.tf file (button click or drag-and-drop)
// instead of pasting. Reads it client-side and drops the text straight into
// the existing textarea, reusing the same parse/analyze flow.
function initDiffUpload() {
  const dropzone = document.getElementById("diff-dropzone");
  const overlay = document.getElementById("dropzone-overlay");
  const fileInput = document.getElementById("diff-file-input");
  const uploadBtn = document.getElementById("upload-diff-btn");
  const textarea = document.getElementById("diff-textarea");
  const filenameEl = document.getElementById("upload-filename");
  const errBox = document.getElementById("diff-error");
  if (!dropzone || dropzone.dataset.uploadBound) return;
  dropzone.dataset.uploadBound = "1";

  function loadFile(file) {
    if (!file) return;
    errBox.classList.add("hidden");
    const reader = new FileReader();
    reader.onload = () => {
      textarea.value = String(reader.result || "");
      filenameEl.innerHTML = `&#128196; ${escapeHtml(file.name)} <span class="clear-upload" id="clear-upload-btn" title="Clear">&#10005;</span>`;
      filenameEl.classList.remove("hidden");
      const clearBtn = document.getElementById("clear-upload-btn");
      if (clearBtn) {
        clearBtn.onclick = () => {
          textarea.value = "";
          filenameEl.classList.add("hidden");
          fileInput.value = "";
        };
      }
      textarea.focus();
    };
    reader.onerror = () => {
      errBox.textContent = "Could not read that file.";
      errBox.classList.remove("hidden");
    };
    reader.readAsText(file);
  }

  uploadBtn.onclick = () => fileInput.click();
  fileInput.onchange = () => loadFile(fileInput.files[0]);

  let dragDepth = 0;
  dropzone.addEventListener("dragenter", e => {
    e.preventDefault();
    dragDepth++;
    overlay.classList.add("active");
  });
  dropzone.addEventListener("dragover", e => e.preventDefault());
  dropzone.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) overlay.classList.remove("active");
  });
  dropzone.addEventListener("drop", e => {
    e.preventDefault();
    dragDepth = 0;
    overlay.classList.remove("active");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
  });
}

function runAnalyzing() {
  mountHeader("analyzing-header", 1, currentPrTag());
  const box = document.getElementById("analysis-steps");
  box.innerHTML = ANALYSIS_STEPS.map((label, i) => `
    <div class="analysis-step" data-i="${i}">
      <div class="step-icon"><span class="idle-dot"></span></div>
      <span class="analysis-step-label">${label}</span>
    </div>
  `).join("");

  const myToken = navToken;
  // In "diff" mode the analysis already ran during ingestion (state.analysis
  // is populated) — the step animation below just narrates it. In "sample"
  // mode we call the demo endpoint fresh.
  const analysisPromise = state.source === "diff" && state.analysis
    ? Promise.resolve()
    : fetchJSON("/api/analyze", { method: "POST" })
        .then(data => { state.analysis = data; })
        .catch(err => {
          console.error(err);
          state.analysis = null;
        });

  let step = 0;
  function tick() {
    if (myToken !== navToken) return;
    const rows = box.querySelectorAll(".analysis-step");
    if (step > 0) {
      const prev = rows[step - 1];
      prev.classList.add("on");
      prev.querySelector(".step-icon").innerHTML = `<span class="check">&#10003;</span>`;
    }
    if (step >= ANALYSIS_STEPS.length) {
      analysisPromise.finally(() => {
        if (myToken !== navToken) return;
        setTimeout(() => { if (myToken === navToken) goto("result"); }, 300);
      });
      return;
    }
    const cur = rows[step];
    cur.classList.add("on", "active");
    cur.querySelector(".step-icon").innerHTML = `<span class="spinner"></span>`;
    const delay = step === ANALYSIS_STEPS.length - 1 ? 1400 : 550;
    step++;
    setTimeout(tick, delay);
  }
  tick();
}

function startResult() {
  mountHeader("result-header", 3, currentPrTag());
  ["stage-funnel", "stage-reveal", "stage-graph", "stage-blast", "stage-fix"].forEach(id =>
    document.getElementById(id).classList.add("hidden")
  );
  document.getElementById("fix-pre").classList.remove("hidden");
  document.getElementById("fix-post").classList.add("hidden");
  document.getElementById("stage-funnel").classList.remove("hidden");
  renderReveal();
  renderFix();
  runFunnel();
}

function runFunnel() {
  const a = state.analysis;
  const causal = a?.minimum_causal_changes?.length ?? 0;
  const funnel = a
    ? [a.changes_submitted, a.security_relevant_changes, causal]
    : [0, 0, 0];
  const captions = ["changes detected", "touch IAM or networking", "minimum causal change"];
  const numberEl = document.getElementById("funnel-number");
  const captionEl = document.getElementById("funnel-caption");
  const dotsEl = document.getElementById("funnel-dots");
  dotsEl.innerHTML = funnel.map(() => `<div class="fdot"></div>`).join("");
  const dots = dotsEl.querySelectorAll(".fdot");

  const myToken = navToken;
  let idx = 0;
  function show() {
    if (myToken !== navToken) return;
    numberEl.textContent = funnel[idx];
    numberEl.classList.toggle("danger", idx === funnel.length - 1);
    numberEl.style.animation = "none";
    void numberEl.offsetWidth;
    numberEl.style.animation = "fadeScale .4s ease both";
    captionEl.textContent = captions[idx];
    dots.forEach((d, i) => d.classList.toggle("on", i <= idx));

    if (idx < funnel.length - 1) {
      idx++;
      setTimeout(show, 750);
    } else {
      setTimeout(() => { if (myToken === navToken) showResultStage(1); }, 900);
    }
  }
  show();
}

function renderReveal() {
  const a = state.analysis;
  const reveal = document.getElementById("stage-reveal");
  const tagEl = reveal.querySelector(".reveal-tag");
  const headline = reveal.querySelector("h2");
  const sub = reveal.querySelector(".sub");
  const panelHead = reveal.querySelector(".panel-head .mono");
  const linesWrap = reveal.querySelector(".diff-lines");

  if (!a || (!a.minimum_causal_changes.length && !a.search_truncated)) {
    tagEl.textContent = "No boundary crossing found";
    headline.textContent = "This batch does not introduce a new access path.";
    sub.textContent = "Every proposed change was tested and none opened a path from an untrusted identity to a sensitive resource.";
    reveal.querySelector(".diff-panel").classList.add("hidden");
    return;
  }

  if (a.search_truncated) {
    tagEl.textContent = "Search limited";
    headline.textContent = "A boundary crossing was found, but the minimum-change search ran out of time.";
    sub.textContent = `Analyzed ${a.changes_submitted} changes — the causal search couldn't isolate a single minimum change within its budget. Try a smaller batch, or narrow the diff.`;
    reveal.querySelector(".diff-panel").classList.add("hidden");
    return;
  }
  reveal.querySelector(".diff-panel").classList.remove("hidden");

  const causal = a.minimum_causal_changes[0];
  const rem = a.remediation;
  tagEl.textContent = `${a.minimum_causal_changes.length} minimum causal change`;
  headline.textContent = `Change #${causal.id} created the new production access path.`;
  sub.textContent = `${causal.description} — reverting only this change restores the boundary.`;

  // rem.diff can be null (causal change without a diff block) — guard it.
  if (rem && rem.diff) {
    reveal.querySelector(".diff-panel").classList.remove("hidden");
    panelHead.textContent = `${rem.diff.file} · ${rem.diff.line}`;
    linesWrap.innerHTML = `
      <div class="diff-line diff-minus">- ${escapeHtml(rem.diff.add)}</div>
      <div class="diff-line diff-plus">+ ${escapeHtml(rem.diff.remove)}</div>
    `;
  } else {
    reveal.querySelector(".diff-panel").classList.add("hidden");
  }
}

function showResultStage(n) {
  const mapId = { 1: "stage-reveal", 2: "stage-graph", 3: "stage-blast", 4: "stage-fix" };
  document.getElementById("stage-funnel").classList.add("hidden");
  Object.values(mapId).forEach(id => document.getElementById(id).classList.add("hidden"));
  document.getElementById(mapId[n]).classList.remove("hidden");
  document.getElementById(mapId[n]).classList.add("fade-up");

  const stepperActive = n === 4 ? 5 : 3;
  // Scoped to the result view — the header template is mounted in three views,
  // so an unscoped getElementById would hit the hidden input view's stepper.
  renderStepper(document.querySelector("#view-result .stepper"), stepperActive);

  if (n === 2) initGraphStage();
  if (n === 3) runBlastRadius();
}

function layoutGraph(graph) {
  const outgoing = {};
  const inDeg = {};
  graph.nodes.forEach(n => { outgoing[n.id] = []; inDeg[n.id] = 0; });
  graph.edges.forEach(e => { outgoing[e.src].push(e.dst); inDeg[e.dst] = (inDeg[e.dst] || 0) + 1; });

  const layer = {};
  graph.nodes.forEach(n => { layer[n.id] = 0; });
  const degCopy = { ...inDeg };
  const queue = graph.nodes.filter(n => inDeg[n.id] === 0).map(n => n.id);
  while (queue.length) {
    const cur = queue.shift();
    outgoing[cur].forEach(dst => {
      layer[dst] = Math.max(layer[dst], layer[cur] + 1);
      degCopy[dst]--;
      if (degCopy[dst] === 0) queue.push(dst);
    });
  }

  const byLayer = {};
  graph.nodes.forEach(n => {
    (byLayer[layer[n.id]] = byLayer[layer[n.id]] || []).push(n);
  });

  const maxLayer = Math.max(...Object.keys(byLayer).map(Number));
  const xGap = maxLayer > 0 ? (900 - 130) / maxLayer : 0;
  const positions = {};
  Object.entries(byLayer).forEach(([layerIdx, nodes]) => {
    const x = 20 + Number(layerIdx) * xGap;
    const count = nodes.length;
    nodes.forEach((n, i) => {
      const y = 210 - ((count - 1) * 65) / 2 + i * 65 - 22;
      positions[n.id] = { x, y: Math.max(10, y) };
    });
  });
  return positions;
}

function buildGraphSVG(graph, highlightSet, danger) {
  const positions = layoutGraph(graph);
  const markerId = danger ? "arrow-d" : "arrow-s";
  let defs = `<defs><marker id="${markerId}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
    <path d="M0,0 L8,4 L0,8 z" fill="${danger ? "#F87171" : "#2A3648"}" /></marker></defs>`;

  const edgesSvg = graph.edges.map((e, i) => {
    const A = positions[e.src], B = positions[e.dst];
    const onPath = highlightSet.has(e.src) && highlightSet.has(e.dst);
    const x1 = A.x + 108, y1 = A.y + 22, x2 = B.x, y2 = B.y + 22;
    const stroke = onPath && danger ? "#F87171" : "#2A3648";
    const width = onPath && danger ? 1.75 : 1.25;
    const glow = onPath && danger ? `style="filter:drop-shadow(0 0 3px rgba(248,113,113,0.5))"` : "";
    const particle = onPath && danger
      ? `<circle r="3" fill="#F87171"><animateMotion dur="1.8s" repeatCount="indefinite" begin="${i * 0.2}s" path="M${x1},${y1} L${x2},${y2}" /></circle>`
      : "";
    // Render the trust condition on each edge so the before/after toggle
    // actually shows the change (e.g. "trusted-org/*" -> "*").
    const condLabel = e.condition != null
      ? `<text x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 - 7}" font-size="7.5" font-family="ui-monospace, monospace"
           fill="${onPath && danger ? "#FBBF24" : "#546074"}" text-anchor="middle">${escapeHtml(e.condition)}</text>`
      : "";
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-width="${width}" marker-end="url(#${markerId})" ${glow}/>${particle}${condLabel}`;
  }).join("");

  const nodesSvg = graph.nodes.map((n, i) => {
    const p = positions[n.id];
    const onPath = danger && highlightSet.has(n.id) && n.kind !== "identity";
    const strokeColor = onPath ? "#F87171" : "#1E2634";
    const strokeW = onPath ? 1.5 : 1;
    const glow = onPath ? `style="filter:drop-shadow(0 0 6px rgba(248,113,113,0.25))"` : "";
    const dotColor = NODE_COLOR[n.kind] || "#8B96A8";
    const sub = n.kind === "identity" ? (n.untrusted ? "untrusted identity" : "trusted identity")
      : n.sensitive ? "sensitive"
      : n.critical ? "critical"
      : n.kind;
    return `
      <g class="svg-node" style="animation-delay:${i * 70}ms" transform="translate(${p.x},${p.y})">
        <rect width="108" height="44" rx="9" fill="#10151F" stroke="${strokeColor}" stroke-width="${strokeW}" ${glow}/>
        <circle cx="14" cy="22" r="4" fill="${dotColor}" />
        <text x="24" y="19" font-size="9.5" font-family="ui-monospace, monospace" fill="#E6EAF0">${escapeHtml(n.label)}</text>
        <text x="24" y="32" font-size="7.5" font-family="ui-monospace, monospace" fill="#546074">${sub}</text>
      </g>`;
  }).join("");

  return defs + edgesSvg + nodesSvg;
}

function initGraphStage() {
  const a = state.analysis;
  const toggle = document.getElementById("compare-toggle");
  const svg = document.getElementById("attack-graph");
  const panel = document.getElementById("graph-panel");
  const status = document.getElementById("graph-status");

  if (!a) return;

  function render(mode) {
    const danger = mode === "after" ? a.boundary_crossed : false;
    const highlightIds = new Set(mode === "after" ? a.after_reachable : a.before_reachable);
    // Use the actual before/after graphs from the backend (with a fallback to
    // the legacy "graph" field) so the toggle shows the real condition change.
    const graphData = mode === "after" ? (a.graph_after || a.graph) : (a.graph_before || a.graph);
    svg.innerHTML = buildGraphSVG(graphData, highlightIds, danger);
    panel.classList.toggle("danger-border", danger);
    if (danger) {
      const lastLabel = a.attack_path.labels[a.attack_path.labels.length - 1];
      status.innerHTML = `<span class="gdot" style="background:#F87171"></span><span style="color:#F87171">Boundary crossed — external identity now reaches ${escapeHtml(lastLabel)}</span>`;
    } else {
      status.innerHTML = `<span class="gdot" style="background:#34D399"></span><span style="color:#34D399">Safe — no path from an untrusted identity to a sensitive resource</span>`;
    }
    toggle.querySelectorAll(".toggle-btn").forEach(b => b.classList.toggle("active", b.dataset.mode === mode));
  }

  toggle.onclick = e => {
    const btn = e.target.closest(".toggle-btn");
    if (!btn) return;
    render(btn.dataset.mode);
  };
  render("after");
}

function runBlastRadius() {
  const a = state.analysis;
  const targets = a
    ? {
        res: a.blast_radius.resources,
        crit: a.blast_radius.critical_services,
        data: a.blast_radius.sensitive_datastores,
        flows: a.blast_radius.user_workflows,
      }
    : { res: 0, crit: 0, data: 0, flows: 0 };
  const ids = { res: "blast-res", crit: "blast-crit", data: "blast-data", flows: "blast-flows" };
  const steps = 20, dur = 700;
  const myToken = navToken;
  let i = 0;
  Object.values(ids).forEach(id => (document.getElementById(id).textContent = "0"));
  const iv = setInterval(() => {
    if (myToken !== navToken) { clearInterval(iv); return; }
    i++;
    Object.keys(targets).forEach(k => {
      document.getElementById(ids[k]).textContent = Math.round((targets[k] * i) / steps);
    });
    if (i >= steps) clearInterval(iv);
  }, dur / steps);
}

function renderFix() {
  const a = state.analysis;
  const pre = document.getElementById("fix-pre");
  const headline = pre.querySelector("h2");
  const panelHead = pre.querySelector(".panel-head .mono");
  const linesWrap = pre.querySelector(".diff-lines");
  const applyBtn = document.getElementById("apply-fix-btn");

  if (!a || !a.remediation) {
    headline.textContent = a && a.search_truncated
      ? "Search limited — no minimum fix isolated."
      : "No fix required.";
    pre.querySelector(".diff-panel").classList.add("hidden");
    applyBtn.classList.add("hidden");
    return;
  }
  pre.querySelector(".diff-panel").classList.remove("hidden");
  applyBtn.classList.remove("hidden");

  const rem = a.remediation;
  headline.textContent = rem.action + ".";
  // Same rem.diff null guard as renderReveal.
  if (rem.diff) {
    pre.querySelector(".diff-panel").classList.remove("hidden");
    panelHead.textContent = `${rem.diff.file} · ${rem.diff.line}`;
    linesWrap.innerHTML = `
      <div class="diff-line diff-minus">- ${escapeHtml(rem.diff.remove)}</div>
      <div class="diff-line diff-plus">+ ${escapeHtml(rem.diff.add)}</div>
    `;
  } else {
    pre.querySelector(".diff-panel").classList.add("hidden");
  }
}

document.getElementById("apply-fix-btn").addEventListener("click", () => {
  document.getElementById("fix-pre").classList.add("hidden");
  const post = document.getElementById("fix-post");
  post.classList.remove("hidden");
  post.classList.add("fade-up");
  const a = state.analysis;
  if (a) {
    // Render the restored (before) graph — not the broken after-state.
    document.getElementById("attack-graph-final").innerHTML =
      buildGraphSVG(a.graph_before || a.graph, new Set(a.before_reachable), false);
  }
});

function buildReportMarkdown(a, prLabel) {
  const now = new Date().toLocaleString();

  if (!a) {
    return `# BOUNDARY-X Report\n\nGenerated: ${now}\n\nNo analysis data available.\n`;
  }

  const lines = [];
  lines.push(`# BOUNDARY-X — Minimum-Change Security Report`);
  lines.push(``);
  lines.push(`**Source:** ${prLabel}`);
  lines.push(`**Generated:** ${now}`);
  lines.push(``);
  lines.push(`## Summary`);
  lines.push(``);
  lines.push(`- Changes submitted: ${a.changes_submitted}`);
  lines.push(`- Security-relevant changes (IAM/networking): ${a.security_relevant_changes}`);
  lines.push(`- Before-state safe: ${a.before_state_safe ? "Yes" : "No"}`);
  lines.push(`- After-state safe: ${a.after_state_safe ? "Yes" : "No"}`);
  lines.push(`- **Boundary crossed: ${a.boundary_crossed ? "YES" : "No"}**`);
  if (a.search_truncated) {
    lines.push(`- **Minimum-change search: limited** — ran out of its time/combination budget before isolating a single minimum change.`);
  }
  lines.push(``);

  if (a.minimum_causal_changes && a.minimum_causal_changes.length) {
    lines.push(`## Minimum Causal Change`);
    lines.push(``);
    a.minimum_causal_changes.forEach(c => {
      lines.push(`- **#${c.id}** (${c.domain}): ${c.description}`);
    });
    lines.push(``);
  }

  if (a.attack_path && a.attack_path.labels && a.attack_path.labels.length) {
    lines.push(`## Attack Path`);
    lines.push(``);
    lines.push(a.attack_path.labels.join(" → "));
    lines.push(``);
  }

  if (a.blast_radius) {
    lines.push(`## Blast Radius`);
    lines.push(``);
    lines.push(`- Resources affected: ${a.blast_radius.resources}`);
    lines.push(`- Critical services: ${a.blast_radius.critical_services}`);
    lines.push(`- Sensitive datastores: ${a.blast_radius.sensitive_datastores}`);
    lines.push(`- User workflows: ${a.blast_radius.user_workflows}`);
    lines.push(``);
  }

  if (a.remediation) {
    lines.push(`## Remediation`);
    lines.push(``);
    lines.push(a.remediation.action + ".");
    if (a.remediation.diff) {
      lines.push(``);
      lines.push("```diff");
      lines.push(`# ${a.remediation.diff.file} · ${a.remediation.diff.line}`);
      lines.push(`- ${a.remediation.diff.remove}`);
      lines.push(`+ ${a.remediation.diff.add}`);
      lines.push("```");
    }
    lines.push(``);
    lines.push(`Status: Boundary restored — attack path removed, production access restricted.`);
    lines.push(``);
  } else {
    lines.push(`## Remediation`);
    lines.push(``);
    lines.push(
      a.search_truncated
        ? `No minimum fix isolated — the causal search was limited before it could finish. Revisit with a smaller batch of changes.`
        : `No boundary crossing found — no fix required.`
    );
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(`_Generated by BOUNDARY-X._`);
  return lines.join("\n");
}

function triggerMarkdownDownload(md, stampSource) {
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const stamp = (stampSource || new Date()).toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const a = document.createElement("a");
  a.href = url;
  a.download = `boundary-x-report-${stamp}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadReport() {
  const prLabel = state.source === "diff" && state.diffMeta
    ? `Pasted diff · ${state.diffMeta.files_touched.length} file(s)`
    : "PR #1843 · payments-api";
  triggerMarkdownDownload(buildReportMarkdown(state.analysis, prLabel));
}

async function downloadPastReport(analysisId, prLabel) {
  try {
    const a = await fetchJSON(`/api/report/${analysisId}`);
    triggerMarkdownDownload(buildReportMarkdown(a, prLabel));
  } catch (err) {
    console.error(err);
  }
}

const downloadReportBtn = document.getElementById("download-report-btn");
if (downloadReportBtn) downloadReportBtn.addEventListener("click", downloadReport);

const STATUS_COLOR = { critical: "#F87171", high: "#FBBF24", safe: "#34D399" };

async function renderDashboard() {
  const list = document.getElementById("recent-list");
  list.innerHTML = `<div class="snapshot-loading">Loading recent analyses&hellip;</div>`;

  try {
    const recent = await fetchJSON("/api/recent?limit=10");
    if (!recent.length) {
      list.innerHTML = `<div class="snapshot-loading">No analyses yet — run one from "Analyze Changes".</div>`;
    } else {
      list.innerHTML = recent.map(r => {
        const prLabel = r.repo ? `${r.pr_tag} · ${r.repo}` : r.pr_tag;
        const when = new Date(r.created_at).toLocaleString();
        return `
        <div class="recent-row">
          <span class="mono" style="color:#546074">&#9670;</span>
          <div class="recent-pr" data-goto="input">${escapeHtml(r.pr_tag)}${r.repo ? ` <span class="repo">· ${escapeHtml(r.repo)}</span>` : ""}</div>
          <div class="recent-meta">${r.changes_submitted} changes</div>
          <div class="recent-meta">${escapeHtml(when)}</div>
          <div class="status-pill" style="background:${STATUS_COLOR[r.status]}15;color:${STATUS_COLOR[r.status]}">
            <span class="sdot" style="background:${STATUS_COLOR[r.status]}"></span>${r.status}
          </div>
          <button class="btn btn-ghost btn-small recent-download-btn" data-analysis-id="${r.id}" data-pr-label="${escapeHtml(prLabel)}" title="Download report">
            <span class="download-icon">&#8595;</span>
          </button>
        </div>`;
      }).join("");

      list.querySelectorAll(".recent-download-btn").forEach(btn => {
        btn.addEventListener("click", e => {
          e.stopPropagation();
          downloadPastReport(btn.dataset.analysisId, btn.dataset.prLabel);
        });
      });
    }
  } catch (err) {
    console.error(err);
    list.innerHTML = `<div class="snapshot-loading" style="color:#F87171">Could not load recent analyses.</div>`;
  }

  animatePostureNumbers();
  loadSnapshot();
  document.getElementById("snapshot-refresh-btn").onclick = loadSnapshot;
}

function animatePostureNumbers() {
  document.querySelectorAll(".posture-val").forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (Number.isNaN(target)) return;
    const steps = 22, dur = 600;
    let i = 0;
    el.textContent = "0";
    const iv = setInterval(() => {
      i++;
      el.textContent = i >= steps ? target : Math.round((target * i) / steps);
      if (i >= steps) clearInterval(iv);
    }, dur / steps);
  });
}

async function loadSnapshot() {
  const body = document.getElementById("snapshot-body");
  const panel = document.getElementById("snapshot-panel");
  const refreshBtn = document.getElementById("snapshot-refresh-btn");
  const myToken = navToken;
  if (refreshBtn) refreshBtn.classList.add("spinning");
  body.innerHTML = `<div class="snapshot-loading">Fetching live state&hellip;</div>`;
  try {
    const snap = await fetchJSON("/api/snapshot");
    if (myToken !== navToken) return;
    panel.classList.toggle("danger-border", snap.boundary_crossed);

    const statusColor = snap.boundary_crossed ? "#F87171" : "#34D399";
    const statusText = snap.boundary_crossed
      ? "Boundary crossed in live environment"
      : "Live environment is within its safe boundary";
    const fetchedAt = new Date(snap.fetched_at).toLocaleString();

    const driftRows = snap.drift.edges_changed.map(d => `
      <div class="drift-row">
        <span class="drift-edge">${escapeHtml(d.src_label)} &#8594; ${escapeHtml(d.dst_label)}</span>
        <span class="drift-cond"><span class="l-minus mono">${escapeHtml(d.before_condition ?? "(none)")}</span> &#8594; <span class="l-plus mono">${escapeHtml(d.after_condition ?? "(none)")}</span></span>
      </div>
    `).join("");

    body.innerHTML = `
      <div class="snapshot-status-row">
        <span class="sdot" style="background:${statusColor}"></span>
        <span style="color:${statusColor}">${statusText}</span>
        <span class="snapshot-fetched">fetched ${escapeHtml(fetchedAt)}</span>
      </div>
      <div class="snapshot-summary mono">${escapeHtml(snap.drift.summary)}</div>
      ${driftRows ? `<div class="drift-list">${driftRows}</div>` : ""}
    `;
  } catch (err) {
    if (myToken !== navToken) return;
    console.error(err);
    body.innerHTML = `<div class="snapshot-loading" style="color:#F87171">Could not fetch live snapshot.</div>`;
  } finally {
    if (refreshBtn) refreshBtn.classList.remove("spinning");
  }
}

loadChanges().catch(err => console.error(err));
goto("landing");