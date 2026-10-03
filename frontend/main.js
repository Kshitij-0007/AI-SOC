/**
 * AI-SOC Frontend Dashboard Client
 * Connects to FastAPI backend at http://localhost:8000
 */

const API_BASE = "http://localhost:8000";

const MITRE_NAMES = {
  "T1046": "Network Service Discovery",
  "T1498": "Network Denial of Service (DDoS)",
  "T1499": "Endpoint Denial of Service (DoS)",
  "T1071": "Application Layer Protocol (C2)",
  "T1105": "Ingress Tool Transfer (Botnet)",
  "T1110": "Brute Force Authentication",
  "T1190": "Exploit Public-Facing Application",
  "T1041": "Exfiltration Over C2 Channel"
};

let currentFilter = "all";
let selectedIncidentId = null;
let isFeedRunning = false;
let knownEventIds = new Set();
let incidentsCache = [];

// DOM References
const feedStatusIndicator = document.getElementById("feed-status-indicator");
const statusPulseDot = document.getElementById("status-pulse-dot");
const feedStatusText = document.getElementById("feed-status-text");
const btnToggleFeed = document.getElementById("btn-toggle-feed");
const feedToggleIcon = document.getElementById("feed-toggle-icon");
const feedToggleLabel = document.getElementById("feed-toggle-label");
const btnFeedTick = document.getElementById("btn-feed-tick");

const statTotalEvents = document.getElementById("stat-total-events");
const statTotalIncidents = document.getElementById("stat-total-incidents");
const statOpenIncidents = document.getElementById("stat-open-incidents");
const statCriticalCount = document.getElementById("stat-critical-count");
const statHighCount = document.getElementById("stat-high-count");
const statMediumCount = document.getElementById("stat-medium-count");
const topActiveSources = document.getElementById("top-active-sources");

const telemetryTbody = document.getElementById("telemetry-tbody");
const streamRowCount = document.getElementById("stream-row-count");
const btnClearFeed = document.getElementById("btn-clear-feed");

const incidentsContainer = document.getElementById("incidents-container");
const incidentFilterCount = document.getElementById("incident-filter-count");
const detailEmptyState = document.getElementById("detail-empty-state");
const detailActiveState = document.getElementById("detail-active-state");
const detailTierBadge = document.getElementById("detail-tier-badge");
const detailIncidentId = document.getElementById("detail-incident-id");
const detailRiskNum = document.getElementById("detail-risk-num");
const detailNarrativeSummary = document.getElementById("detail-narrative-summary");
const detailNarrativeRationale = document.getElementById("detail-narrative-rationale");
const detailRecommendedActions = document.getElementById("detail-recommended-actions");
const detailMitreTags = document.getElementById("detail-mitre-tags");
const detailSrcIp = document.getElementById("detail-src-ip");
const detailDstIp = document.getElementById("detail-dst-ip");
const detailFirstSeen = document.getElementById("detail-first-seen");
const detailStatus = document.getElementById("detail-status");

const btnSubmitFeedback = document.getElementById("btn-submit-feedback");
const feedbackVerdict = document.getElementById("feedback-verdict");
const feedbackNotes = document.getElementById("feedback-notes");
const feedbackStatusMsg = document.getElementById("feedback-status-msg");

const kbRowCount = document.getElementById("kb-row-count");
const kbEntriesContainer = document.getElementById("kb-entries-container");
const btnRefreshKb = document.getElementById("btn-refresh-kb");
const uploadInput = document.getElementById("upload-input");
const uploadDropzone = document.getElementById("upload-dropzone");
const btnUploadBrowse = document.getElementById("btn-upload-browse");
const btnUploadSubmit = document.getElementById("btn-upload-submit");
const uploadPreview = document.getElementById("upload-preview");
const previewFilename = document.getElementById("preview-filename");
const previewFilesize = document.getElementById("preview-filesize");
const uploadResultBox = document.getElementById("upload-result-box");
const uploadResultTitle = document.getElementById("upload-result-title");
const uploadResultDesc = document.getElementById("upload-result-desc");
const uploadHistoryList = document.getElementById("upload-history-list");
const scanUrlInput = document.getElementById("scan-url-input");
const btnScanUrl = document.getElementById("btn-scan-url");
const scanResultCard = document.getElementById("scan-result-card");
const scanHistoryList = document.getElementById("scan-history-list");
const urlSourceInput = document.getElementById("url-source-input");
const urlSourceName = document.getElementById("url-source-name");
const urlSourceInterval = document.getElementById("url-source-interval");
const btnUrlImport = document.getElementById("btn-url-import");
const btnUrlLive = document.getElementById("btn-url-live");
const urlSourceStatus = document.getElementById("url-source-status");
const urlSourceList = document.getElementById("url-source-list");
let selectedUploadFile = null;

// Initialize Tabs
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    const tabId = `pane-${btn.dataset.tab}`;
    const targetPane = document.getElementById(tabId);
    if (targetPane) targetPane.classList.add("active");
  });
});

// Filter Pills
document.querySelectorAll(".filter-pill").forEach(pill => {
  pill.addEventListener("click", () => {
    document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
    pill.classList.add("active");
    currentFilter = pill.dataset.filter;
    renderIncidents();
  });
});

// Clear Feed View
btnClearFeed.addEventListener("click", () => {
  telemetryTbody.innerHTML = `<tr class="empty-row"><td colspan="7">Telemetry table cleared. New incoming records will appear below.</td></tr>`;
  knownEventIds.clear();
  streamRowCount.textContent = "0 records";
});

// Toggle Feed Stream
btnToggleFeed.addEventListener("click", async () => {
  try {
    const endpoint = isFeedRunning ? "/live-feed/stop" : "/live-feed/start";
    const res = await fetch(`${API_BASE}${endpoint}`, { method: "POST" });
    const data = await res.json();
    isFeedRunning = data.is_running;
    updateFeedControlUI(isFeedRunning);
  } catch (err) {
    console.error("Failed to toggle live feed:", err);
  }
});

// Single Tick Batch
btnFeedTick.addEventListener("click", async () => {
  try {
    btnFeedTick.disabled = true;
    btnFeedTick.textContent = "⚡ Ingesting...";
    const res = await fetch(`${API_BASE}/live-feed/tick`, { method: "POST" });
    const data = await res.json();
    console.log("Tick result:", data);
    await refreshAll();
  } catch (err) {
    console.error("Tick failed:", err);
  } finally {
    btnFeedTick.disabled = false;
    btnFeedTick.textContent = "⚡ Ingest Batch";
  }
});

// Submit Analyst Feedback
btnSubmitFeedback.addEventListener("click", async () => {
  if (!selectedIncidentId) return;
  try {
    btnSubmitFeedback.disabled = true;
    feedbackStatusMsg.textContent = "Recording feedback...";
    feedbackStatusMsg.className = "feedback-status-msg";

    const payload = {
      analyst_verdict: feedbackVerdict.value,
      notes: feedbackNotes.value || null,
      corrected_label: null
    };

    const res = await fetch(`${API_BASE}/incidents/${selectedIncidentId}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Feedback submission error");
    const data = await res.json();

    feedbackStatusMsg.textContent = `✓ Feedback recorded! Incident updated to: ${data.incident_status}. KB synced.`;
    feedbackStatusMsg.className = "feedback-status-msg success";
    feedbackNotes.value = "";

    await refreshAll();
    if (selectedIncidentId) selectIncident(selectedIncidentId);
  } catch (err) {
    feedbackStatusMsg.textContent = `✗ Failed: ${err.message}`;
    feedbackStatusMsg.className = "feedback-status-msg error";
  } finally {
    btnSubmitFeedback.disabled = false;
  }
});

btnRefreshKb.addEventListener("click", fetchKnowledgeBase);

function showUploadFile(file) {
  if (!file) return;
  selectedUploadFile = file;
  previewFilename.textContent = file.name;
  previewFilesize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
  uploadPreview.classList.remove("hidden");
  uploadResultBox.classList.add("hidden");
}

btnUploadBrowse.addEventListener("click", () => uploadInput.click());
uploadDropzone.addEventListener("click", event => { if (event.target !== btnUploadBrowse) uploadInput.click(); });
uploadInput.addEventListener("change", () => showUploadFile(uploadInput.files[0]));
uploadDropzone.addEventListener("dragover", event => { event.preventDefault(); uploadDropzone.classList.add("dragging"); });
uploadDropzone.addEventListener("dragleave", () => uploadDropzone.classList.remove("dragging"));
uploadDropzone.addEventListener("drop", event => { event.preventDefault(); uploadDropzone.classList.remove("dragging"); showUploadFile(event.dataTransfer.files[0]); });
btnUploadSubmit.addEventListener("click", async () => {
  if (!selectedUploadFile) return;
  btnUploadSubmit.disabled = true;
  try {
    const body = new FormData(); body.append("file", selectedUploadFile);
    const response = await fetch(`${API_BASE}/upload`, { method: "POST", body });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Upload failed");
    uploadResultTitle.textContent = "Ingestion complete";
    uploadResultDesc.textContent = data.message;
    uploadResultBox.classList.remove("hidden");
    await refreshAll(); await fetchUploadHistory();
  } catch (error) { uploadResultTitle.textContent = "Ingestion failed"; uploadResultDesc.textContent = error.message; uploadResultBox.classList.remove("hidden"); }
  finally { btnUploadSubmit.disabled = false; }
});

btnScanUrl.addEventListener("click", async () => {
  const target = scanUrlInput.value.trim(); if (!target) return;
  btnScanUrl.disabled = true;
  try {
    const response = await fetch(`${API_BASE}/scan/url`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target }) });
    const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Scan failed");
    renderScanResult(data); await fetchScanHistory(); await refreshAll();
  } catch (error) { console.error("Scan error:", error); }
  finally { btnScanUrl.disabled = false; }
});

function renderScanResult(data) {
  scanResultCard.classList.remove("hidden");
  document.getElementById("scan-res-target").textContent = data.target;
  document.getElementById("scan-res-source").textContent = data.source;
  document.getElementById("scan-res-score").textContent = data.risk_score;
  document.getElementById("scan-res-ip").textContent = data.resolved_ip || "Unresolved";
  document.getElementById("scan-res-label").textContent = data.label;
  document.getElementById("scan-res-conf").textContent = `${Math.round(data.confidence * 100)}%`;
  document.getElementById("scan-res-src").textContent = data.source;
  document.getElementById("scan-flags-container").textContent = (data.flags || []).join(" · ") || "No threat indicators returned";
  document.getElementById("scan-incident-notice").classList.toggle("hidden", data.risk_score < 20);
}

function urlSourcePayload() { return { url: urlSourceInput.value.trim(), name: urlSourceName.value.trim() || null, poll_interval_seconds: Number(urlSourceInterval.value) || 10 }; }
function setUrlSourceStatus(message, error = false) { urlSourceStatus.textContent = message; urlSourceStatus.className = `source-status-msg ${error ? "error" : "success"}`; }
btnUrlImport.addEventListener("click", () => submitUrlSource("/ingest/url", "Imported"));
btnUrlLive.addEventListener("click", () => submitUrlSource("/live-feed/sources", "Live feed added"));
async function submitUrlSource(endpoint, successLabel) {
  const payload = urlSourcePayload(); if (!payload.url) return setUrlSourceStatus("Enter a public HTTP(S) URL.", true);
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Source request failed");
    const suffix = endpoint === "/live-feed/sources" ? " Start Live Feed to begin polling." : "";
    setUrlSourceStatus(`${successLabel}: ${data.records_ingested ?? data.name}.${suffix}`); await fetchUrlSources(); await refreshAll();
  } catch (error) { setUrlSourceStatus(error.message, true); }
}
async function fetchUrlSources() {
  try { const response = await fetch(`${API_BASE}/live-feed/sources`); const sources = await response.json();
    urlSourceList.innerHTML = sources.length ? "" : '<div class="loading-state">No URL feeds configured.</div>';
    sources.forEach(source => { const row = document.createElement("div"); row.className = "url-source-row"; row.innerHTML = `<div><strong></strong><small></small></div><button class="btn btn-outline btn-sm">Remove</button>`; row.querySelector("strong").textContent = source.name; row.querySelector("small").textContent = `${source.url} · ${source.last_record_count || 0} last records`; row.querySelector("button").addEventListener("click", async () => { await fetch(`${API_BASE}/live-feed/sources/${source.source_id}`, { method: "DELETE" }); await fetchUrlSources(); }); urlSourceList.appendChild(row); });
  } catch (error) { console.error("URL source fetch error:", error); }
}
async function fetchUploadHistory() { try { const response = await fetch(`${API_BASE}/upload/history`); const items = await response.json(); uploadHistoryList.innerHTML = items.length ? "" : '<div class="loading-state">No uploads yet.</div>'; items.forEach(item => { const row = document.createElement("div"); row.className = "history-row"; row.textContent = `${item.filename} · ${(item.size_bytes / 1024).toFixed(1)} KB`; uploadHistoryList.appendChild(row); }); } catch (error) { console.error(error); } }
async function fetchScanHistory() { try { const response = await fetch(`${API_BASE}/scan/history`); const items = await response.json(); scanHistoryList.innerHTML = items.length ? "" : '<div class="loading-state">No scans performed yet…</div>'; items.forEach(item => { const row = document.createElement("div"); row.className = "history-row"; row.textContent = `${item.target} · ${item.label} (${item.risk_score})`; scanHistoryList.appendChild(row); }); } catch (error) { console.error(error); } }

function updateFeedControlUI(running) {
  if (running) {
    statusPulseDot.className = "status-pulse active";
    feedStatusText.textContent = "Feed: Streaming Live (2s)";
    btnToggleFeed.classList.add("running");
    feedToggleIcon.textContent = "⏸";
    feedToggleLabel.textContent = "Stop Live Feed";
  } else {
    statusPulseDot.className = "status-pulse idle";
    feedStatusText.textContent = "Feed: Standby";
    btnToggleFeed.classList.remove("running");
    feedToggleIcon.textContent = "▶";
    feedToggleLabel.textContent = "Start Live Feed";
  }
}

// Fetch System Stats
async function fetchStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    if (!res.ok) return;
    const stats = await res.json();
    statTotalEvents.textContent = stats.total_events.toLocaleString();
    statTotalIncidents.textContent = stats.total_incidents.toLocaleString();
    statOpenIncidents.textContent = `${stats.open_incidents} open alerts`;
    statCriticalCount.textContent = stats.critical_incidents;
    statHighCount.textContent = stats.high_incidents;
    statMediumCount.textContent = `${stats.medium_incidents} medium alerts`;
  } catch (err) {
    console.error("Stats fetch error:", err);
  }
}

// Fetch Live Status
async function fetchLiveStatus() {
  try {
    const res = await fetch(`${API_BASE}/live-feed/status`);
    if (!res.ok) return;
    const status = await res.json();
    isFeedRunning = status.is_running;
    updateFeedControlUI(isFeedRunning);
    if (status.active_connectors && status.active_connectors.length > 0) {
      topActiveSources.textContent = status.active_connectors.join(", ");
    }
  } catch (err) {
    console.error("Live status fetch error:", err);
  }
}

// Fetch Live Telemetry Events
async function fetchLiveEvents() {
  try {
    const res = await fetch(`${API_BASE}/events/live?limit=35`);
    if (!res.ok) return;
    const events = await res.json();
    if (!events || events.length === 0) return;

    const emptyRow = telemetryTbody.querySelector(".empty-row");
    if (emptyRow) emptyRow.remove();

    // Check for newly arrived events
    const newItems = events.filter(e => !knownEventIds.has(e.event_id));
    if (newItems.length > 0) {
      newItems.reverse().forEach(ev => {
        knownEventIds.add(ev.event_id);
        const tr = document.createElement("tr");
        tr.className = "new-record";
        
        const timeFormatted = new Date(ev.ingested_at).toLocaleTimeString();
        const srcDisplay = ev.src_ip ? `${ev.src_ip}${ev.src_port ? ':' + ev.src_port : ''}` : '---';
        const dstDisplay = ev.dst_ip ? `${ev.dst_ip}${ev.dst_port ? ':' + ev.dst_port : ''}` : '---';
        const protoDisplay = ev.protocol || 'TCP';
        const label = ev.label || 'BENIGN';
        const labelClass = label === 'BENIGN' ? 'text-emerald' : 'text-rose font-mono';

        tr.innerHTML = `
          <td>${timeFormatted}</td>
          <td><span class="connector-badge">${ev.source_type}</span></td>
          <td class="font-mono">${srcDisplay}</td>
          <td class="font-mono">${dstDisplay}</td>
          <td><span class="badge-version">${protoDisplay}</span></td>
          <td class="${labelClass}"><strong>${label}</strong></td>
          <td class="font-mono text-faint">${ev.event_id.substring(0, 13)}...</td>
        `;

        telemetryTbody.insertBefore(tr, telemetryTbody.firstChild);
      });

      // Limit table rows to prevent memory build-up
      while (telemetryTbody.children.length > 80) {
        telemetryTbody.removeChild(telemetryTbody.lastChild);
      }

      streamRowCount.textContent = `${telemetryTbody.children.length} records`;
    }
  } catch (err) {
    console.error("Live events fetch error:", err);
  }
}

// Fetch Incidents
async function fetchIncidents() {
  try {
    const res = await fetch(`${API_BASE}/incidents?limit=100`);
    if (!res.ok) return;
    incidentsCache = await res.json();
    renderIncidents();
  } catch (err) {
    console.error("Incidents fetch error:", err);
  }
}

function renderIncidents() {
  let filtered = incidentsCache;
  if (currentFilter !== "all") {
    filtered = incidentsCache.filter(inc => (inc.risk_tier || "low").toLowerCase() === currentFilter.toLowerCase());
  }

  incidentFilterCount.textContent = `Showing ${filtered.length} of ${incidentsCache.length}`;

  if (filtered.length === 0) {
    incidentsContainer.innerHTML = `<div class="empty-row">No incidents found matching tier "${currentFilter}".</div>`;
    return;
  }

  incidentsContainer.innerHTML = "";
  filtered.forEach(inc => {
    const card = document.createElement("div");
    const tier = inc.risk_tier || "medium";
    card.className = `incident-card ${selectedIncidentId === inc.incident_id ? 'selected' : ''}`;
    card.dataset.id = inc.incident_id;

    // Parse narrative if available
    let summaryText = "Automated threat correlation alert";
    let dominantThreat = "Suspicious Traffic";
    if (inc.llm_narrative) {
      try {
        const parsed = JSON.parse(inc.llm_narrative);
        if (parsed.summary) summaryText = parsed.summary;
      } catch (e) {
        summaryText = inc.llm_narrative;
      }
    }

    const mitreTags = (inc.mitre_techniques || []).map(t => `<span class="mini-mitre-tag">${t}</span>`).join(" ");

    card.innerHTML = `
      <div class="inc-card-top">
        <span class="inc-id-tag">INC-${inc.incident_id.substring(0, 8)}</span>
        <div class="inc-risk-meter ${tier}">
          <span>SCORE: ${inc.risk_score.toFixed(1)}</span>
        </div>
      </div>
      <div class="inc-flow-desc">${summaryText}</div>
      <div class="inc-card-foot">
        <div class="inc-mitre-mini">${mitreTags || '<span class="text-faint text-xs">No MITRE tag</span>'}</div>
        <span class="inc-time">${new Date(inc.created_at).toLocaleTimeString()}</span>
      </div>
    `;

    card.addEventListener("click", () => {
      document.querySelectorAll(".incident-card").forEach(c => c.classList.remove("selected"));
      card.classList.add("selected");
      selectIncident(inc.incident_id);
    });

    incidentsContainer.appendChild(card);
  });
}

function selectIncident(incidentId) {
  selectedIncidentId = incidentId;
  const inc = incidentsCache.find(i => i.incident_id === incidentId);
  if (!inc) return;

  detailEmptyState.classList.add("hidden");
  detailActiveState.classList.remove("hidden");

  const tier = inc.risk_tier || "medium";
  detailTierBadge.className = `tier-tag ${tier}`;
  detailTierBadge.textContent = tier.toUpperCase();
  detailIncidentId.textContent = `INCIDENT #${inc.incident_id.substring(0, 12)}...`;
  detailRiskNum.textContent = inc.risk_score.toFixed(1);
  detailRiskNum.className = `risk-score-num text-${tier === 'critical' ? 'rose' : tier === 'high' ? 'amber' : 'cyan'}`;

  // Parse Tier-2 AI Narrative
  let summary = "Threat activity detected across network telemetry.";
  let rationale = "Calculated risk score combines threat confidence and asset importance.";
  let actions = ["Monitor target asset traffic.", "Inspect source firewall logs."];

  if (inc.llm_narrative) {
    try {
      const parsed = JSON.parse(inc.llm_narrative);
      if (parsed.summary) summary = parsed.summary;
      if (parsed.severity_rationale) rationale = parsed.severity_rationale;
      if (parsed.recommended_actions) actions = parsed.recommended_actions;
    } catch (e) {
      summary = inc.llm_narrative;
    }
  }

  detailNarrativeSummary.textContent = summary;
  detailNarrativeRationale.textContent = rationale;
  detailRecommendedActions.innerHTML = actions.map(a => `<li>${a}</li>`).join("");

  // MITRE Techniques with lookup names
  if (inc.mitre_techniques && inc.mitre_techniques.length > 0) {
    detailMitreTags.innerHTML = inc.mitre_techniques.map(t => {
      const name = MITRE_NAMES[t] || "Tactical Technique";
      return `<div class="mitre-pill"><strong>${t}</strong> <span>${name}</span></div>`;
    }).join("");
  } else {
    detailMitreTags.innerHTML = `<span class="text-faint">Standard Anomaly (No direct MITRE mapping)</span>`;
  }

  // Meta items
  detailSrcIp.textContent = "185.220.101.5 / Remote";
  detailDstIp.textContent = "10.0.0.5 (Critical Asset)";
  detailFirstSeen.textContent = new Date(inc.created_at).toLocaleString();
  detailStatus.textContent = inc.status || "open";

  feedbackStatusMsg.textContent = "";
}

// Fetch Knowledge Base Entries
async function fetchKnowledgeBase() {
  try {
    const res = await fetch(`${API_BASE}/kb`);
    if (!res.ok) return;
    const entries = await res.json();
    kbRowCount.textContent = `${entries.length} items`;

    if (entries.length === 0) {
      kbEntriesContainer.innerHTML = `<div class="empty-row">No feedback entries recorded yet. Submit a verdict on any incident to enrich the continuous learning knowledge base!</div>`;
      return;
    }

    kbEntriesContainer.innerHTML = entries.map(e => `
      <div class="kb-card">
        <div class="kb-card-head">
          <span class="kb-source">Origin: ${e.source}</span>
          <span class="kb-time">${new Date(e.created_at).toLocaleString()}</span>
        </div>
        <div class="kb-text">${e.text_chunk}</div>
      </div>
    `).join("");
  } catch (err) {
    console.error("KB fetch error:", err);
  }
}

// Global Refresh
async function refreshAll() {
  await Promise.all([
    fetchStats(),
    fetchLiveStatus(),
    fetchLiveEvents(),
    fetchIncidents(),
    fetchKnowledgeBase(),
    fetchUploadHistory(),
    fetchScanHistory(),
    fetchUrlSources()
  ]);
}

// Initial Boot & Continuous Polling
refreshAll();
setInterval(refreshAll, 2500);
