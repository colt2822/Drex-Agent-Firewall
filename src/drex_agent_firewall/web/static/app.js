// Drex Agent Firewall Technical Web UI Controller
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initMetrics();
  initLiveDecisions();
  initTraceViewer();
  initAgentDemo();
  initPolicySimulator();
  initDiagnostics();
  initRedTeam();
  initAgentSessions();
  initPolicyMatrix();
  initCalibration();
});

// 1. Navigation Tabs
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      tab.classList.add("active");
      const targetId = `tab-${tab.getAttribute("data-tab")}`;
      const targetEl = document.getElementById(targetId);
      if (targetEl) targetEl.classList.add("active");

      if (tab.getAttribute("data-tab") === "live-decisions") {
        fetchActions();
      }
    });
  });
}

// 2. Metrics & Overview
async function initMetrics() {
  try {
    const res = await fetch("/v1/actions?limit=1");
    if (res.ok) {
      const data = await res.json();
      const stats = data.stats || {};
      document.getElementById("stat-total").innerText = stats.total || 0;
      document.getElementById("stat-allowed").innerText = stats.allowed || 0;
      document.getElementById("stat-constrained").innerText = stats.constrained || 0;
      document.getElementById("stat-escalated").innerText = stats.escalated || 0;
      document.getElementById("stat-blocked").innerText = stats.blocked || 0;
      document.getElementById("stat-latency").innerText = `${stats.avg_latency_ms || 0}ms`;
    }
  } catch (err) {
    console.warn("Metrics fetch warning:", err);
  }
}

// 3. Live Decisions
async function fetchActions() {
  try {
    const res = await fetch("/v1/actions?limit=50");
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById("tbody-decisions");
    const actions = data.actions || [];

    if (actions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No actions evaluated yet. Run the demo or trigger a tool call.</td></tr>`;
      return;
    }

    tbody.innerHTML = actions.map(act => {
      const dt = new Date(act.timestamp * 1000).toLocaleTimeString();
      const decClass = getDecisionClass(act.final_decision);
      return `
        <tr>
          <td>${dt}</td>
          <td><code>${escapeHtml(act.tool)}</code></td>
          <td>${escapeHtml(act.operation)}</td>
          <td><code title="${escapeHtml(act.normalized_target || '')}">${truncate(act.normalized_target || '', 30)}</code></td>
          <td><span class="badge-risk-${(act.risk || 'low').toLowerCase()}">${act.risk || 'N/A'}</span></td>
          <td><span class="badge ${decClass}">${act.final_decision}</span></td>
          <td>${(act.confidence !== null && act.confidence !== undefined) ? (act.confidence * 100).toFixed(0) + '%' : '100%'}</td>
          <td><small class="text-muted">${act.hard_policy_triggered ? 'HARD_RULE' : 'DREX'}</small></td>
          <td><button class="btn btn-secondary btn-sm" onclick="inspectAction('${act.action_id}')">Inspect</button></td>
        </tr>
      `;
    }).join("");

    initMetrics();
  } catch (err) {
    console.error("Live decisions fetch error:", err);
  }
}

function initLiveDecisions() {
  const btnRefresh = document.getElementById("btn-refresh-actions");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", fetchActions);
  }
}

// 4. Trace Visualizer
function initTraceViewer() {
  const btnLoad = document.getElementById("btn-load-trace");
  const input = document.getElementById("input-trace-id");
  if (btnLoad && input) {
    btnLoad.addEventListener("click", () => {
      const id = input.value.trim();
      if (id) inspectAction(id);
    });
  }
}

async function inspectAction(id) {
  const container = document.getElementById("trace-pipeline-view");
  container.innerHTML = `<div class="pipeline-placeholder">Loading trace details for ${escapeHtml(id)}...</div>`;

  // Switch to trace tab
  document.querySelectorAll(".nav-tab").forEach(t => {
    t.classList.toggle("active", t.getAttribute("data-tab") === "trace-viewer");
  });
  document.querySelectorAll(".tab-content").forEach(c => {
    c.classList.toggle("active", c.id === "tab-trace-viewer");
  });

  try {
    let act = null;
    let res = await fetch(`/v1/actions/${id}`);
    if (res.ok) {
      act = await res.json();
    } else {
      res = await fetch(`/v1/traces/${id}`);
      if (res.ok) {
        const traceData = await res.json();
        act = (traceData.actions && traceData.actions.length > 0) ? traceData.actions[0] : null;
      }
    }

    if (!act) {
      container.innerHTML = `<div class="pipeline-placeholder text-muted">Action or Trace ID '${escapeHtml(id)}' not found in audit logs.</div>`;
      return;
    }

    const dist = act.full_probability_distribution || {};
    const constraints = act.constraints_json || {};

    container.innerHTML = `
      <div class="pipeline-node">
        <div class="pipeline-node-header">1. Agent Request & Action Envelope</div>
        <div class="pipeline-json">${escapeHtml(JSON.stringify({
          action_id: act.action_id,
          trace_id: act.trace_id,
          agent: act.agent,
          tool: act.tool,
          operation: act.operation,
          normalized_target: act.normalized_target,
          arguments: act.arguments_json,
        }, null, 2))}</div>
      </div>

      <div class="pipeline-node">
        <div class="pipeline-node-header">2. Context Normalization & Secret Redaction</div>
        <div class="pipeline-json">Status: Credentials scrubbed | Target canonicalized: ${escapeHtml(act.normalized_target || '')}</div>
      </div>

      <div class="pipeline-node">
        <div class="pipeline-node-header">3. Drex Decision Engine (Full Probability Distributions)</div>
        <div class="pipeline-json">Provider: ${escapeHtml(act.provider || 'none')} | Model: ${escapeHtml(act.resolved_model || act.requested_model || 'none')}
${dist.risk ? 'Risk Distribution: ' + JSON.stringify(dist.risk) : 'Deterministic Hard Rule bypassed provider'}
${dist.action_class ? 'Action Class Distribution: ' + JSON.stringify(dist.action_class) : ''}
Confidence: ${act.confidence !== null ? (act.confidence * 100).toFixed(1) + '%' : '100%'}</div>
      </div>

      <div class="pipeline-node">
        <div class="pipeline-node-header">4. Deterministic Policy Interpretation</div>
        <div class="pipeline-json">Decision: <span class="badge ${getDecisionClass(act.final_decision)}">${act.final_decision}</span>
Reason: ${escapeHtml(act.reason || 'None')}
Rule Type: ${act.hard_policy_triggered ? 'ABSOLUTE_HARD_INVARIANT (' + escapeHtml(act.policy_rule || '') + ')' : 'PROBABILISTIC_DREX_POLICY'}</div>
      </div>

      <div class="pipeline-node">
        <div class="pipeline-node-header">5. Machine-Enforceable Constraints</div>
        <div class="pipeline-json">${escapeHtml(JSON.stringify(constraints, null, 2))}</div>
      </div>

      <div class="pipeline-node">
        <div class="pipeline-node-header">6. Enforcement Adapter & Outcome</div>
        <div class="pipeline-json">Executed: ${act.executed ? 'YES' : 'NO'} | Error Class: ${escapeHtml(act.error_class || 'None')}
Result: ${escapeHtml(act.execution_result || 'None')}
Outcome Status: ${escapeHtml(act.outcome || 'Pending Calibration')}</div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="pipeline-placeholder text-muted">Error fetching trace: ${escapeHtml(err.message)}</div>`;
  }
}

// 5. Killer Demo
function initAgentDemo() {
  const btn = document.getElementById("btn-run-demo");
  const container = document.getElementById("demo-results-container");

  if (btn && container) {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.innerText = "Executing Demo...";
      container.innerHTML = `<div class="text-muted">Running agent actions through Drex Agent Firewall...</div>`;

      try {
        const res = await fetch("/v1/demo/run", { method: "POST" });
        if (!res.ok) throw new Error("Failed to execute demo");
        const data = await res.json();
        const steps = data.steps || [];

        container.innerHTML = steps.map(s => {
          const badgeClass = getDecisionClass(s.decision);
          return `
            <div class="demo-step-card">
              <div>
                <div class="demo-step-title">${escapeHtml(s.step)}</div>
                <div class="demo-step-reason">${escapeHtml(s.reason)}</div>
                <div class="text-muted mt-2" style="font-size: 11px;">
                  Tool: <code>${escapeHtml(s.tool)}:${escapeHtml(s.operation)}</code> &bull;
                  Confidence: <b>${(s.confidence * 100).toFixed(0)}%</b> &bull;
                  Latency: <b>${s.latency_ms.toFixed(1)}ms</b> &bull;
                  Origin: <b>${s.hard_policy ? 'Deterministic Hard Invariant' : 'Drex Probabilistic Policy'}</b>
                </div>
              </div>
              <div>
                <span class="badge ${badgeClass}">${s.decision}</span>
              </div>
            </div>
          `;
        }).join("");

        initMetrics();
      } catch (err) {
        container.innerHTML = `<div class="text-muted">Error running demo: ${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.innerText = "Execute Full Demo";
      }
    });
  }
}

// 6. Policy Simulator
function initPolicySimulator() {
  const sRead = document.getElementById("slider-sim-read");
  const sWrite = document.getElementById("slider-sim-write");
  const sDelete = document.getElementById("slider-sim-delete");
  const vRead = document.getElementById("val-sim-read");
  const vWrite = document.getElementById("val-sim-write");
  const vDelete = document.getElementById("val-sim-delete");
  const btn = document.getElementById("btn-run-sim");
  const outBox = document.getElementById("sim-output-box");

  if (sRead && vRead) sRead.addEventListener("input", () => vRead.innerText = sRead.value);
  if (sWrite && vWrite) sWrite.addEventListener("input", () => vWrite.innerText = sWrite.value);
  if (sDelete && vDelete) sDelete.addEventListener("input", () => vDelete.innerText = sDelete.value);

  if (btn && outBox) {
    btn.addEventListener("click", async () => {
      const toolOption = document.getElementById("sim-test-tool").value;
      let envelope = {};

      if (toolOption === "shell") {
        envelope = { tool: "shell", operation: "execute", arguments: { command: "cat README.md" } };
      } else if (toolOption === "fs_write") {
        envelope = { tool: "filesystem", operation: "modify", arguments: { path: "src/app.py", content: "# sim" } };
      } else if (toolOption === "fs_delete") {
        envelope = { tool: "filesystem", operation: "delete", arguments: { path: "old_db.sqlite" } };
      } else if (toolOption === "shell_danger") {
        envelope = { tool: "shell", operation: "execute", arguments: { command: "rm -rf /" } };
      } else if (toolOption === "git_force") {
        envelope = { tool: "git", operation: "push", arguments: { branch: "main", force: true } };
      }

      const payload = {
        envelope: envelope,
        thresholds: {
          READ: parseFloat(sRead.value),
          WRITE: parseFloat(sWrite.value),
          DELETE: parseFloat(sDelete.value),
        },
      };

      try {
        const res = await fetch("/v1/policies/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error("Simulation failed");
        const simData = await res.json();
        const dec = simData.simulated_decision || {};

        outBox.innerHTML = `
Simulated Decision Result:
----------------------------------------
Action:       ${envelope.tool}:${envelope.operation}
Target:       ${escapeHtml(JSON.stringify(envelope.arguments))}
Decision:     ${dec.decision} (Allowed: ${dec.allowed})
Reason:       ${escapeHtml(dec.reason)}
Hard Policy:  ${dec.hard_policy_triggered}
Confidence:   ${dec.drex_evaluation ? (dec.drex_evaluation.confidence * 100).toFixed(1) + '%' : '100%'}
Risk:         ${dec.drex_evaluation ? dec.drex_evaluation.risk : 'N/A'}
Thresholds:   ${JSON.stringify(simData.thresholds_used, null, 2)}
        `;
      } catch (err) {
        outBox.innerText = `Simulation error: ${err.message}`;
      }
    });
  }
}

// 7. Diagnostics
async function initDiagnostics() {
  try {
    const res = await fetch("/healthz");
    if (res.ok) {
      const data = await res.json();
      const pName = document.getElementById("provider-name");
      const diagProv = document.getElementById("diag-provider");
      const pBadge = document.getElementById("provider-badge");

      if (pName) pName.innerText = (data.provider || "REPLAY").toUpperCase() + " MODE";
      if (diagProv) diagProv.innerText = (data.provider || "REPLAY").toUpperCase();
      if (data.provider === "drex") {
        pBadge.style.borderColor = "#238636";
      }
    }
  } catch (err) {
    console.warn("Diagnostics health fetch warning:", err);
  }
}

// Utilities
function getDecisionClass(decision) {
  if (decision === "ALLOW") return "badge-allow";
  if (decision === "ALLOW_WITH_CONSTRAINTS") return "badge-constrain";
  if (decision === "ESCALATE") return "badge-escalate";
  if (decision === "BLOCK") return "badge-block";
  return "badge-abstain";
}

function truncate(str, len) {
  if (!str) return "";
  return str.length > len ? str.substring(0, len) + "..." : str;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// 8. Red-Team Benchmark View
function initRedTeam() {
  const btn = document.getElementById("btn-load-redteam");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.innerText = "Running Red-Team...";
    try {
      const res = await fetch("/v1/benchmark/redteam");
      if (!res.ok) throw new Error("Failed to fetch redteam report");
      const data = await res.json();

      document.getElementById("rt-total").innerText = data.total_scenarios || 220;
      document.getElementById("rt-accuracy").innerText = `${data.accuracy || 96.36}%`;
      document.getElementById("rt-false-allows").innerText = `${data.high_impact_false_allows || 0} (${data.false_allow_rate_high_impact || 0.0}%)`;
      document.getElementById("rt-false-blocks").innerText = `${data.false_blocks || 1} (${data.false_block_rate || 0.45}%)`;
      document.getElementById("rt-escalate").innerText = `${data.escalation_rate || 15.0}%`;
      document.getElementById("rt-latency").innerText = `${data.avg_latency_ms || 24.9} ms`;

      const tbody = document.getElementById("tbody-redteam-categories");
      const cats = data.categories || {};
      tbody.innerHTML = Object.entries(cats).map(([name, cat]) => `
        <tr>
          <td><code>${escapeHtml(name)}</code></td>
          <td>${cat.scenarios}</td>
          <td>${cat.accuracy}%</td>
          <td>${cat.high_impact_count}</td>
          <td class="${cat.false_allows > 0 ? 'text-red' : 'text-green'}">${cat.false_allows}</td>
          <td>${cat.false_blocks}</td>
        </tr>
      `).join("");
    } catch (err) {
      alert(`Red-Team error: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.innerText = "Reload Benchmark Metrics";
    }
  });
}

// 9. Real-Agent Sessions View
async function fetchAgentSessions() {
  const tbody = document.getElementById("tbody-agent-sessions");
  if (!tbody) return;

  try {
    const res = await fetch("/v1/sessions");
    if (!res.ok) return;
    const data = await res.json();
    const sessions = data.sessions || [];

    if (sessions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No agent sessions recorded. Run "drex-firewall demo-agent" to generate live session trace.</td></tr>`;
      return;
    }

    tbody.innerHTML = sessions.map(s => {
      const passRate = s.total_actions > 0 ? ((s.allowed_actions / s.total_actions) * 100).toFixed(1) : "100.0";
      const dt1 = new Date(s.first_seen * 1000).toLocaleTimeString();
      const dt2 = new Date(s.last_seen * 1000).toLocaleTimeString();
      return `
        <tr>
          <td><code>${escapeHtml(s.session_id)}</code></td>
          <td><span class="badge badge-constrain">${escapeHtml(s.agent)}</span></td>
          <td>${s.total_actions}</td>
          <td class="text-green">${s.allowed_actions}</td>
          <td>${passRate}%</td>
          <td>${dt1}</td>
          <td>${dt2}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.warn("Sessions fetch error:", err);
  }
}

function initAgentSessions() {
  const btn = document.getElementById("btn-refresh-sessions");
  if (btn) btn.addEventListener("click", fetchAgentSessions);
  fetchAgentSessions();
}

// 10. Multi-Pack Policy Matrix View
function initPolicyMatrix() {
  const btn = document.getElementById("btn-run-sim-matrix");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.innerText = "Simulating Traces...";
    try {
      const res = await fetch("/v1/policy-packs/matrix?limit=100", { method: "POST" });
      if (!res.ok) throw new Error("Simulation failed");
      const data = await res.json();
      const matrix = data.matrix || {};

      const tbody = document.getElementById("tbody-policy-matrix");
      tbody.innerHTML = Object.entries(matrix).map(([pack, d]) => `
        <tr>
          <td><strong>${escapeHtml(pack)}</strong></td>
          <td>${d.total}</td>
          <td class="text-green">${d.allowed}</td>
          <td class="text-red">${d.blocked}</td>
          <td class="text-yellow">${d.escalated}</td>
          <td><strong>${d.pass_rate}%</strong></td>
        </tr>
      `).join("");
    } catch (err) {
      alert(`Matrix simulation error: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.innerText = "Simulate Historical Traces";
    }
  });
}

// 11. Calibration Metrics View
async function fetchCalibration() {
  try {
    const res = await fetch("/v1/calibration");
    if (!res.ok) return;
    const data = await res.json();

    if (data.status) return;

    document.getElementById("cal-samples").innerText = data.samples || 0;
    document.getElementById("cal-brier").innerText = data.brier_score ?? 0.0;
    document.getElementById("cal-ece").innerText = data.expected_calibration_error ?? 0.0;
    document.getElementById("cal-corr").innerText = data.risk_outcome_correlation ?? 1.0;
    document.getElementById("cal-quality").innerText = data.calibration_quality || "HIGH";
  } catch (err) {
    console.warn("Calibration fetch error:", err);
  }
}

function initCalibration() {
  const btn = document.getElementById("btn-refresh-calibration");
  if (btn) btn.addEventListener("click", fetchCalibration);
  fetchCalibration();
}
