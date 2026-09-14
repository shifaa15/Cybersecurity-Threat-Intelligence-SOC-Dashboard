// Backend base URL. Set in config.js — empty string means "same origin"
// (fine for local dev where the backend also serves this frontend).
const API = (window.SOC_API_BASE || "").replace(/\/$/, "");
const SEV_COLORS = { Low: "#4FAE83", Medium: "#4FA3E0", High: "#E8A33D", Critical: "#E5555C" };

let severityFilter = "all";
let searchTerm = "";
let allEventsCache = [];
let incidentsCache = {};

// ---------- utils ----------

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", { hour12: false });
}

function timeAgo(iso) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function escapeHtml(str) {
  return (str || "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

// ---------- clock ----------

setInterval(() => {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}, 1000);

// ---------- charts ----------

const timelineCtx = document.getElementById("timeline-chart").getContext("2d");
const timelineChart = new Chart(timelineCtx, {
  type: "bar",
  data: {
    labels: [],
    datasets: ["Low", "Medium", "High", "Critical"].map((sev) => ({
      label: sev,
      data: [],
      backgroundColor: SEV_COLORS[sev],
      stack: "s",
      borderRadius: 1,
      maxBarThickness: 18,
    })),
  },
  options: {
    responsive: true,
    animation: { duration: 250 },
    plugins: {
      legend: { position: "bottom", labels: { color: "#A9B4C2", boxWidth: 10, font: { size: 11 } } },
    },
    scales: {
      x: { stacked: true, ticks: { color: "#6B7789", font: { size: 10 } }, grid: { color: "#1B2431" } },
      y: { stacked: true, ticks: { color: "#6B7789", font: { size: 10 } }, grid: { color: "#1B2431" } },
    },
  },
});

const severityCtx = document.getElementById("severity-chart").getContext("2d");
const severityChart = new Chart(severityCtx, {
  type: "doughnut",
  data: {
    labels: ["Low", "Medium", "High", "Critical"],
    datasets: [{
      data: [0, 0, 0, 0],
      backgroundColor: ["#4FAE83", "#4FA3E0", "#E8A33D", "#E5555C"],
      borderColor: "#121821",
      borderWidth: 2,
    }],
  },
  options: {
    responsive: true,
    cutout: "68%",
    plugins: {
      legend: { position: "bottom", labels: { color: "#A9B4C2", boxWidth: 10, font: { size: 11 } } },
    },
  },
});

// ---------- data fetch ----------

async function loadStats() {
  const s = await fetch(`${API}/api/stats`).then((r) => r.json());
  document.getElementById("stat-total").textContent = s.total_events;
  document.getElementById("stat-incidents").textContent = s.open_incidents;
  document.getElementById("stat-avg").textContent = s.avg_severity_score;
  document.getElementById("stat-critical").textContent = s.by_severity.Critical || 0;

  severityChart.data.datasets[0].data = [
    s.by_severity.Low || 0, s.by_severity.Medium || 0, s.by_severity.High || 0, s.by_severity.Critical || 0,
  ];
  severityChart.update();
}

async function loadTimeline() {
  const rows = await fetch(`${API}/api/timeline?minutes=30`).then((r) => r.json());
  timelineChart.data.labels = rows.map((r) => fmtTime(r.timestamp));
  ["Low", "Medium", "High", "Critical"].forEach((sev, i) => {
    timelineChart.data.datasets[i].data = rows.map((r) => r[sev]);
  });
  timelineChart.update();
}

async function loadMitreMatrix() {
  const tactics = await fetch(`${API}/api/mitre-matrix`).then((r) => r.json());
  const container = document.getElementById("mitre-matrix");
  container.innerHTML = "";
  tactics.forEach((bucket) => {
    const col = document.createElement("div");
    const head = document.createElement("div");
    head.className = "mitre-col-head";
    head.textContent = bucket.tactic;
    col.appendChild(head);
    bucket.techniques.forEach((t) => {
      const cell = document.createElement("div");
      cell.className = "mitre-cell";
      const intensity = Math.min(t.count / 6, 1);
      if (t.count > 0) {
        cell.style.background = `rgba(140, 123, 246, ${0.12 + intensity * 0.55})`;
        cell.style.borderColor = "rgba(140, 123, 246, 0.35)";
        cell.style.color = "#E3E8EE";
      }
      cell.innerHTML = `<span class="t-id">${t.id}</span><span class="t-count">${t.count || ""}</span><div>${escapeHtml(t.name)}</div>`;
      col.appendChild(cell);
    });
    container.appendChild(col);
  });
}

async function loadIncidents() {
  const incidents = await fetch(`${API}/api/incidents`).then((r) => r.json());
  const list = document.getElementById("incident-list");
  list.innerHTML = "";
  incidents.forEach((inc) => {
    incidentsCache[inc.id] = inc;
    list.appendChild(renderIncidentCard(inc));
  });
}

function renderIncidentCard(inc) {
  const card = document.createElement("div");
  card.className = "incident-card";
  card.dataset.id = inc.id;
  card.innerHTML = `
    <div class="incident-top">
      <div>
        <p class="incident-title">${escapeHtml(inc.title)}</p>
        <div class="incident-meta">${inc.src_ip} · ${inc.event_ids.length} event${inc.event_ids.length === 1 ? "" : "s"} · ${timeAgo(inc.last_seen_at)}</div>
      </div>
      <span class="sev-badge ${inc.max_severity_label}">${inc.max_severity_label}</span>
    </div>
    <div class="incident-tactics">
      ${inc.tactics_observed.map((t) => `<span class="tactic-chip">${escapeHtml(t)}</span>`).join("")}
    </div>
  `;
  card.addEventListener("click", () => openIncidentDrawer(inc.id));
  return card;
}

async function loadEvents() {
  const params = new URLSearchParams({ limit: "150" });
  if (severityFilter !== "all") params.set("severity", severityFilter);
  if (searchTerm) params.set("search", searchTerm);
  const events = await fetch(`${API}/api/events?${params}`).then((r) => r.json());
  allEventsCache = events;
  renderFeed(events);
}

function renderFeed(events) {
  const feed = document.getElementById("event-feed");
  feed.innerHTML = "";
  events.forEach((e) => feed.appendChild(renderEventRow(e)));
}

function renderEventRow(e) {
  const row = document.createElement("div");
  row.className = "event-row";
  const techniques = e.mitre_techniques.map((t) => t.id).join(", ");
  row.innerHTML = `
    <span class="sev-badge ${e.severity_label}">${e.severity_label}</span>
    <div>
      <div class="event-desc">${escapeHtml(e.description)}</div>
      <div class="event-meta">${e.asset} · ${e.src_ip}${techniques ? " · " + techniques : ""}</div>
    </div>
    <div class="event-time">${fmtTime(e.timestamp)}</div>
  `;
  return row;
}

function prependEvent(e) {
  if (severityFilter !== "all" && e.severity_label !== severityFilter) return;
  if (searchTerm) {
    const hay = `${e.description} ${e.asset} ${e.src_ip} ${e.event_type}`.toLowerCase();
    if (!hay.includes(searchTerm.toLowerCase())) return;
  }
  const feed = document.getElementById("event-feed");
  feed.prepend(renderEventRow(e));
  while (feed.children.length > 150) feed.removeChild(feed.lastChild);
}

// ---------- incident drawer ----------

async function openIncidentDrawer(id) {
  const inc = incidentsCache[id];
  const events = await fetch(`${API}/api/incidents/${id}/events`).then((r) => r.json());
  document.getElementById("drawer-title").textContent = inc ? inc.title : "Incident chain";
  const body = document.getElementById("drawer-body");
  body.innerHTML = `
    <div class="incident-meta" style="margin-bottom:14px;">
      Source ${inc.src_ip} → ${inc.asset} · ${events.length} correlated event${events.length === 1 ? "" : "s"}
    </div>
    ${events.map((e) => `
      <div class="chain-step">
        <span class="chain-dot" style="background:${SEV_COLORS[e.severity_label]}"></span>
        <div>
          <div class="event-desc">${escapeHtml(e.description)}</div>
          <div class="event-meta">${fmtTime(e.timestamp)} · ${e.mitre_techniques.map((t) => t.id).join(", ") || "—"}</div>
        </div>
      </div>
    `).join("")}
  `;
  document.getElementById("drawer").classList.add("open");
  document.getElementById("drawer-overlay").classList.add("open");
}

function closeDrawer() {
  document.getElementById("drawer").classList.remove("open");
  document.getElementById("drawer-overlay").classList.remove("open");
}
document.getElementById("drawer-close").addEventListener("click", closeDrawer);
document.getElementById("drawer-overlay").addEventListener("click", closeDrawer);

// ---------- filters ----------

document.getElementById("severity-filter").addEventListener("change", (e) => {
  severityFilter = e.target.value;
  loadEvents();
});
let searchDebounce;
document.getElementById("search-input").addEventListener("input", (e) => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    searchTerm = e.target.value.trim();
    loadEvents();
  }, 250);
});

// ---------- websocket ----------

function wsUrl() {
  if (API) {
    // Derive ws(s):// from whatever http(s):// was set in config.js
    return API.replace(/^http/, "ws") + "/ws/stream";
  }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/ws/stream`;
}

function connect() {
  const ws = new WebSocket(wsUrl());

  ws.onopen = () => {
    document.getElementById("conn-dot").classList.add("on");
    document.getElementById("conn-label").textContent = "live";
  };
  ws.onclose = () => {
    document.getElementById("conn-dot").classList.remove("on");
    document.getElementById("conn-label").textContent = "reconnecting…";
    setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();

  ws.onmessage = (msg) => {
    const { type, payload } = JSON.parse(msg.data);
    if (type === "event") {
      prependEvent(payload);
      bumpStatFromEvent(payload);
    } else if (type === "incident") {
      incidentsCache[payload.id] = payload;
      refreshIncidentCard(payload);
    }
  };
}

function bumpStatFromEvent(e) {
  const totalEl = document.getElementById("stat-total");
  totalEl.textContent = (parseInt(totalEl.textContent, 10) || 0) + 1;
  if (e.severity_label === "Critical") {
    const critEl = document.getElementById("stat-critical");
    critEl.textContent = (parseInt(critEl.textContent, 10) || 0) + 1;
  }
}

function refreshIncidentCard(inc) {
  const list = document.getElementById("incident-list");
  const existing = list.querySelector(`[data-id="${inc.id}"]`);
  const fresh = renderIncidentCard(inc);
  if (existing) {
    list.replaceChild(fresh, existing);
  } else {
    list.prepend(fresh);
    document.getElementById("stat-incidents").textContent =
      (parseInt(document.getElementById("stat-incidents").textContent, 10) || 0) + 1;
    while (list.children.length > 40) list.removeChild(list.lastChild);
  }
}

// ---------- periodic refresh (charts + stats reconcile from server truth) ----------

async function refreshAll() {
  await Promise.all([loadStats(), loadTimeline(), loadMitreMatrix(), loadIncidents(), loadEvents()]);
}

refreshAll();
connect();
setInterval(loadStats, 5000);
setInterval(loadTimeline, 8000);
setInterval(loadMitreMatrix, 10000);
