
"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  events: [],
  filteredEvents: [],
  refreshing: false,
  trendDrawn: false,
  autoRefresh: true,
  refreshTimer: null
};

const COLORS = {
  critical: "#ff5277",
  high: "#ff5277",
  medium: "#ffb454",
  low: "#42f5a7",
  info: "#35e6ff",
  other: "#9b72ff"
};

// -------------------- UI SOUND --------------------

function playUiSound(type = "click") {
  try {
    const AudioContextClass =
      window.AudioContext || window.webkitAudioContext;

    if (!AudioContextClass) return;

    const ctx = new AudioContextClass();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    const now = ctx.currentTime;

    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === "refresh") {
      osc.type = "sine";
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.15);
      gain.gain.setValueAtTime(0.05, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
      osc.start(now);
      osc.stop(now + 0.15);
    } else if (type === "alert") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(300, now);
      osc.frequency.setValueAtTime(600, now + 0.08);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      osc.start(now);
      osc.stop(now + 0.2);
    } else {
      osc.type = "triangle";
      osc.frequency.setValueAtTime(520, now);
      gain.gain.setValueAtTime(0.03, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
      osc.start(now);
      osc.stop(now + 0.08);
    }

    osc.onended = () => ctx.close().catch(() => {});
  } catch {
    // Audio may be unavailable.
  }
}

// -------------------- MESSAGES & CONNECTION --------------------

function setMessage(text, type = "info") {
  const el = $("message");
  if (!el) return;

  el.textContent = text || "";
  el.className = text ? `message show ${type}` : "message";
}

function setConnection(connected, text) {
  const status = $("connectionStatus");
  const sidebarStatus = $("sidebarApiStatus");

  if (status) {
    status.textContent = text;
    status.style.color = connected ? "var(--green)" : "var(--red)";
  }

  if (sidebarStatus) {
    sidebarStatus.textContent = connected ? "Connected" : "Unavailable";
    sidebarStatus.style.color = connected ? "var(--green)" : "var(--red)";
  }
}

// -------------------- API --------------------

async function fetchJSON(url, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...options.headers
  };

  const response = await fetch(url, {
    method: options.method || "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok) {
    const error = new Error(
      data.error || data.message || `Request failed (${response.status})`
    );

    error.status = response.status;
    throw error;
  }

  return data;
}

function getEventType(event) {
  return String(
    event.event_type ??
    event.type ??
    event.action ??
    event.event ??
    "UNKNOWN"
  );
}

function getTimestamp(event) {
  return event.created_at ?? event.timestamp ?? event.time ?? null;
}

function getDateObject(value) {
  if (value === null || value === undefined || value === "") return null;

  const date = typeof value === "number"
    ? new Date(value < 1e12 ? value * 1000 : value)
    : new Date(value);

  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDate(value) {
  const date = getDateObject(value);
  if (!date) return String(value ?? "—");

  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function getIP(event) {
  return event.ip_address ??
    event.ip ??
    event.source_ip ??
    event.client_ip ??
    "—";
}

function getPathAndUser(event) {
  const path = event.path ?? event.endpoint ?? "—";
  return event.username ? `${path} · ${event.username}` : path;
}

function getEventId(event, index) {
  return event.id ??
    event.event_id ??
    `EVT-${String(index + 1).padStart(4, "0")}`;
}

function getEventText(event) {
  return [
    getEventType(event),
    event.username,
    event.ip_address,
    event.ip,
    event.source_ip,
    event.client_ip,
    event.path,
    event.endpoint,
    event.details,
    event.message,
    event.severity,
    event.level,
    event.user_agent,
    event.method,
    event.status_code
  ].filter(value => value !== null && value !== undefined)
   .join(" ")
   .toLowerCase();
}

function getSeverity(event) {
  const supplied = String(
    event.severity ?? event.level ?? ""
  ).toLowerCase();

  if (supplied.includes("critical")) return "critical";
  if (supplied.includes("high")) return "high";

  if (
    supplied.includes("medium") ||
    supplied.includes("warning")
  ) {
    return "medium";
  }

  if (supplied.includes("low")) return "low";
  if (supplied.includes("info")) return "info";

  const type = getEventType(event).toUpperCase();

  if (
    type.includes("BLOCK") ||
    type.includes("SQLI") ||
    type.includes("SQL_INJECTION") ||
    type.includes("XSS")
  ) {
    return "high";
  }

  if (
    type.includes("FAIL") ||
    type.includes("DETECTION") ||
    type.includes("DETECT") ||
    type.includes("SUSPICIOUS") ||
    type.includes("ANOMALY")
  ) {
    return "medium";
  }

  return "info";
}

function severityLabel(severity) {
  const labels = {
    critical: "CRITICAL",
    high: "HIGH",
    medium: "MEDIUM",
    low: "LOW",
    info: "INFO"
  };

  return labels[severity] || "INFO";
}

function severityStyle(severity) {
  const color = COLORS[severity] || COLORS.other;
  return `--pill-color:${color};--pill-bg:${color}19`;
}

function getEventCategory(event) {
  const type = getEventType(event).toUpperCase();

  if (
    type.includes("LOGIN") ||
    type.includes("AUTH") ||
    type.includes("PASSWORD")
  ) {
    return "login";
  }

  if (
    type.includes("WAF") ||
    type.includes("SQLI") ||
    type.includes("SQL_INJECTION") ||
    type.includes("XSS") ||
    type.includes("DETECTION") ||
    type.includes("DETECT") ||
    type.includes("BLOCK")
  ) {
    return "waf";
  }

  return "other";
}

// -------------------- SUMMARY --------------------

async function loadSummary() {
  const summary = await fetchJSON("/api/siem/summary");

  return {
    ...summary,
    failedLogins: Number(summary.failedLogins) || 0,
    wafEvents: Number(summary.wafEvents) || 0,
    recentEvents: Number(
      summary.events24h ?? summary.recentEvents
    ) || 0
  };
}

function normalizeEvents(response) {
  if (Array.isArray(response)) return response;
  if (Array.isArray(response?.events)) return response.events;
  if (Array.isArray(response?.data)) return response.data;
  if (Array.isArray(response?.logs)) return response.logs;
  return [];
}

async function loadEvents() {
  return normalizeEvents(await fetchJSON("/api/security/events"));
}

async function loadCurrentUser() {
  try {
    const result = await fetchJSON("/api/auth/me");
    const user = result.user ?? result;

    if (user.username && $("adminName")) {
      $("adminName").textContent = user.username;
    }
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      setMessage(
        "Your session may have expired. Sign in again if the API denies access.",
        "error"
      );
    }
  }
}

// -------------------- STATS & RINGS --------------------

function setStat(id, value) {
  const el = $(id);
  if (!el) return;

  const n = Number(value) || 0;
  const text = n.toLocaleString();

  el.dataset.value = String(n);

  if (el.textContent !== text) {
    el.textContent = text;
    el.classList.remove("flash");
    void el.offsetWidth;
    el.classList.add("flash");
  }
}

function updateRings() {
  const pairs = [
    ["failedLogins", "ringA"],
    ["wafEvents", "ringB"],
    ["recentEvents", "ringC"]
  ];

  const values = pairs.map(([id]) => Number($(id)?.dataset.value) || 0);
  const max = Math.max(...values, 1);

  pairs.forEach(([, ringId], index) => {
    const ring = $(ringId);
    if (!ring) return;

    const percentage = values[index] > 0
      ? Math.max(8, (values[index] / max) * 100)
      : 0;

    ring.style.strokeDashoffset = String(100 - percentage);
  });

  const core = $("coreNum");
  if (core) core.textContent = values[2].toLocaleString();
}

function updateMetrics(summary = {}) {
  setStat(
    "failedLogins",
    summary.failedLogins ?? summary.failed_logins ?? 0
  );

  setStat(
    "wafEvents",
    summary.wafEvents ?? summary.waf_events ?? 0
  );

  setStat(
    "recentEvents",
    summary.recentEvents ?? summary.recent_events ?? state.events.length
  );

  updateRings();
}

// -------------------- EVENT MODAL --------------------

function showEventModal(event, index) {
  playUiSound("click");

  let modal = $("eventModal");

  if (!modal) {
    modal = document.createElement("div");
    modal.id = "eventModal";

    modal.style.cssText = `
      position:fixed;
      inset:0;
      z-index:1000;
      background:rgba(4,4,12,.85);
      backdrop-filter:blur(8px);
      display:grid;
      place-items:center;
      padding:20px;
    `;

    document.body.appendChild(modal);
  }

  const id = getEventId(event, index);
  const type = getEventType(event);
  const severity = getSeverity(event);
  const ip = getIP(event);
  const timestamp = formatDate(getTimestamp(event));

  modal.innerHTML = `
    <div style="width:100%;max-width:600px;max-height:90vh;overflow:auto;background:#121225;border:1px solid rgba(155,114,255,.3);border-radius:20px;padding:24px;color:#fff;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;gap:12px;">
        <div>
          <div style="font-size:11px;color:#35e6ff;">EVENT INVESTIGATION</div>
          <h3>${escapeHTML(type)}</h3>
        </div>
        <button id="closeModalBtn" type="button" aria-label="Close dialog">✕</button>
      </div>

      <p><strong>Event ID:</strong> ${escapeHTML(id)}</p>
      <p><strong>Severity:</strong>
        <span class="pill" style="${severityStyle(severity)}">${severityLabel(severity)}</span>
      </p>
      <p><strong>Source IP:</strong> ${escapeHTML(ip)}</p>
      <p><strong>Timestamp:</strong> ${escapeHTML(timestamp)}</p>

      <h4>Raw Event Data</h4>
      <pre style="white-space:pre-wrap;overflow:auto;max-height:240px;background:#080812;padding:12px;border-radius:10px;">${escapeHTML(JSON.stringify(event, null, 2))}</pre>

      <div style="display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;">
        <button id="blockIpBtn" type="button">Block Source IP</button>
        <button id="closeModalActionBtn" type="button">Close</button>
      </div>
    </div>
  `;

  modal.style.display = "grid";

  const closeModal = () => {
    modal.style.display = "none";
  };

  modal.querySelector("#closeModalBtn").onclick = closeModal;
  modal.querySelector("#closeModalActionBtn").onclick = closeModal;

  modal.onclick = (eventClick) => {
    if (eventClick.target === modal) closeModal();
  };

  modal.querySelector("#blockIpBtn").onclick = () => {
    playUiSound("alert");

    setMessage(
      `No firewall rule was created for ${ip}. Configure a real firewall integration to block an IP.`,
      "error"
    );

    closeModal();
  };

  modal.onkeydown = (eventKey) => {
    if (eventKey.key === "Escape") closeModal();
  };
}

// -------------------- EVENT TABLE --------------------

function renderEventTable(events) {
  const table = $("eventsTable");
  if (!table) return;

  if (!events.length) {
    table.innerHTML = `
      <tr>
        <td colspan="6" class="empty">No events match your filters.</td>
      </tr>
    `;
    return;
  }

  table.innerHTML = events.map((event, idx) => {
    const index = state.events.indexOf(event);
    const safeIndex = index >= 0 ? index : idx;
    const type = getEventType(event);
    const severity = getSeverity(event);
    const pathUser = getPathAndUser(event);
    const id = getEventId(event, safeIndex);
    const color = COLORS[severity] || COLORS.other;

    return `
      <tr class="event-row" data-index="${safeIndex}" tabindex="0" role="button" style="cursor:pointer;">
        <td class="mono event-id">${escapeHTML(id)}</td>
        <td>
          <div class="event-name" style="--event-color:${color}">
            <span class="event-indicator"></span>
            ${escapeHTML(type)}
          </div>
        </td>
        <td>
          <span class="pill" style="${severityStyle(severity)}">
            ${severityLabel(severity)}
          </span>
        </td>
        <td class="mono">${escapeHTML(getIP(event))}</td>
        <td title="${escapeHTML(pathUser)}">${escapeHTML(pathUser)}</td>
        <td class="mono">${escapeHTML(formatDate(getTimestamp(event)))}</td>
      </tr>
    `;
  }).join("");

  table.querySelectorAll(".event-row").forEach(row => {
    const openEvent = () => {
      const index = Number(row.dataset.index);
      const event = state.events[index];
      if (event) showEventModal(event, index);
    };

    row.addEventListener("click", openEvent);

    row.addEventListener("keydown", eventKey => {
      if (eventKey.key === "Enter" || eventKey.key === " ") {
        eventKey.preventDefault();
        openEvent();
      }
    });
  });
}

// -------------------- FILTERS --------------------

function matchesType(event, filter) {
  if (filter === "all") return true;

  const type = getEventType(event).toUpperCase();
  const category = getEventCategory(event);

  if (filter === "login") return category === "login";
  if (filter === "waf") return category === "waf";

  if (filter === "block") {
    return type.includes("BLOCK") || type.includes("DENY");
  }

  if (filter === "detect") {
    return (
      type.includes("DETECT") ||
      type.includes("DETECTION") ||
      type.includes("SUSPICIOUS") ||
      type.includes("ALERT") ||
      type.includes("ANOMAL") ||
      type.includes("SQLI") ||
      type.includes("SQL_INJECTION") ||
      type.includes("XSS")
    );
  }

  return true;
}

function matchesSeverity(event, filter) {
  if (filter === "all") return true;

  const severity = getSeverity(event);

  if (filter === "high") {
    return severity === "high" || severity === "critical";
  }

  if (filter === "medium") return severity === "medium";

  if (filter === "low") {
    return severity === "low" || severity === "info";
  }

  return true;
}

function applyFilters() {
  const search = ($("eventSearch")?.value ?? "").trim().toLowerCase();
  const typeFilter = $("eventFilter")?.value ?? "all";
  const severityFilter = $("severityFilter")?.value ?? "all";

  state.filteredEvents = state.events.filter(event =>
    (!search || getEventText(event).includes(search)) &&
    matchesType(event, typeFilter) &&
    matchesSeverity(event, severityFilter)
  );

  renderEventTable(state.filteredEvents);

  if ($("resultsCount")) {
    $("resultsCount").textContent =
      state.filteredEvents.length.toLocaleString();
  }

  if ($("eventTotalBadge")) {
    $("eventTotalBadge").textContent =
      state.events.length.toLocaleString();
  }

  if ($("tableStatus")) {
    $("tableStatus").textContent =
      `Showing ${state.filteredEvents.length} of ${state.events.length} loaded events`;
  }
}

// -------------------- EVENT DISTRIBUTION --------------------

function renderDistribution(events) {
  const container = $("distributionList");
  if (!container) return;

  if (!events.length) {
    container.innerHTML = `<div class="empty">No event data available yet.</div>`;
    return;
  }

  const counts = new Map();

  for (const event of events) {
    const type = getEventType(event);
    counts.set(type, (counts.get(type) || 0) + 1);
  }

  const entries = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  const max = Math.max(...entries.map(entry => entry[1]), 1);

  const palette = [
    "#9b72ff",
    "#35e6ff",
    "#ff5277",
    "#42f5a7",
    "#ffb454",
    "#6d83ff"
  ];

  container.innerHTML = entries.map(([name, count], index) => {
    const color = palette[index % palette.length];
    const width = Math.max(3, (count / max) * 100);

    return `
      <div>
        <div class="dist-top">
          <span class="dist-name">
            <span class="dist-dot" style="--dot:${color}"></span>
            ${escapeHTML(name)}
          </span>
          <span class="dist-number">${count}</span>
        </div>
        <div class="progress">
          <div class="progress-fill" style="--dot:${color};width:${width}%"></div>
        </div>
      </div>
    `;
  }).join("");
}

// -------------------- EVENT TIMELINE --------------------

function renderTrend(events) {
  const box = $("zigzagChart");
  if (!box) return;

  if (!events.length) {
    box.innerHTML = `<div class="empty">No timeline data available.</div>`;
    return;
  }

  const dates = events
    .map(event => getDateObject(getTimestamp(event)))
    .filter(Boolean);

  if (!dates.length) {
    box.innerHTML = `<div class="empty">Events have no usable timestamps.</div>`;
    return;
  }

  const pad = n => String(n).padStart(2, "0");
  const day = date =>
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;

  const modes = [
    {
      label: "BY DATE",
      max: 7,
      key: date => day(date),
      text: key => key.slice(5)
    },
    {
      label: "BY HOUR",
      max: 24,
      key: date => `${day(date)} ${pad(date.getHours())}`,
      text: key => `${key.slice(-2)}:00`
    },
    {
      label: "BY MINUTE",
      max: 30,
      key: date => `${day(date)} ${pad(date.getHours())}:${pad(date.getMinutes())}`,
      text: key => key.slice(-5)
    }
  ];

  let chosen = modes[0];
  let entries = [];

  for (const mode of modes) {
    const bucket = new Map();

    dates.forEach(date => {
      const key = mode.key(date);
      bucket.set(key, (bucket.get(key) || 0) + 1);
    });

    entries = [...bucket.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(-mode.max);

    chosen = mode;
    if (entries.length >= 2) break;
  }

  const points = entries.map(([key, value]) => ({
    label: chosen.text(key),
    value,
    full: key
  }));

  const W = 640;
  const H = 235;
  const L = 40;
  const R = 40;
  const T = 36;
  const B = 40;
  const n = points.length;

  const maxValue = Math.max(...points.map(point => point.value), 1) * 1.15;

  points.forEach((point, index) => {
    point.x = n === 1
      ? W / 2
      : L + (index * (W - L - R)) / (n - 1);

    point.y = H - B -
      (point.value / maxValue) * (H - T - B);
  });

  const line = points.map((point, index) =>
    `${index ? "L" : "M"}${point.x.toFixed(1)} ${point.y.toFixed(1)}`
  ).join(" ");

  const step = Math.max(1, Math.ceil(n / 10));

  let svg = `
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Security events timeline">
      <defs>
        <linearGradient id="zgL" x1="0" y1="0" x2="${W}" y2="0">
          <stop offset="0" stop-color="#35e6ff"/>
          <stop offset="1" stop-color="#9b72ff"/>
        </linearGradient>
        <linearGradient id="zgA" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="#35e6ff" stop-opacity=".32"/>
          <stop offset="1" stop-color="#9b72ff" stop-opacity="0"/>
        </linearGradient>
        <filter id="zgG" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur"/>
          <feMerge>
            <feMergeNode in="blur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
  `;

  for (let grid = 0; grid < 5; grid++) {
    const y = T + (grid * (H - T - B)) / 4;
    svg += `<line class="zz-grid" x1="${L}" x2="${W - R}" y1="${y}" y2="${y}"/>`;
  }

  if (n > 1) {
    svg += `
      <path class="zz-area"
        d="${line} L${points[n - 1].x} ${H - B} L${points[0].x} ${H - B} Z"/>
      <path class="zz-line" pathLength="1" d="${line}" style="filter:url(#zgG)"/>
    `;
  } else {
    svg += `
      <line class="zz-grid"
        style="stroke:rgba(53,230,255,.35);stroke-dasharray:4 5"
        x1="${L}" x2="${W - R}" y1="${points[0].y}" y2="${points[0].y}"/>
      <circle class="zz-ping" cx="${points[0].x}" cy="${points[0].y}" r="6"/>
    `;
  }

  points.forEach((point, index) => {
    const delay = (0.3 + index * (1.4 / Math.max(n, 1))).toFixed(2);

    svg += `
      <circle class="zz-dot"
        style="animation-delay:${delay}s"
        cx="${point.x.toFixed(1)}"
        cy="${point.y.toFixed(1)}"
        r="6">
        <title>${escapeHTML(point.full)}: ${point.value} events</title>
      </circle>
    `;

    if (n <= 14) {
      svg += `
        <text class="zz-val"
          x="${point.x.toFixed(1)}"
          y="${(point.y - 14).toFixed(1)}">${point.value}</text>
      `;
    }

    if (index % step === 0) {
      svg += `
        <text class="zz-day"
          x="${point.x.toFixed(1)}"
          y="${H - 14}">${escapeHTML(point.label)}</text>
      `;
    }
  });

  if (n > 1) {
    svg += `
      <circle class="zz-runner" r="4">
        <animateMotion dur="5s" repeatCount="indefinite" path="${line}"/>
      </circle>
    `;
  }

  svg += `
      <text class="zz-day"
        style="text-anchor:end;fill:var(--cyan);opacity:.7"
        x="${W - R}" y="14">${chosen.label}</text>
    </svg>
  `;

  box.innerHTML = svg;
}

// -------------------- DASHBOARD --------------------

function renderDashboard() {
  applyFilters();
  renderDistribution(state.events);
  renderTrend(state.events);

  if (window.lucide) {
    window.lucide.createIcons();
  }
}

async function refreshDashboard(manual = false) {
  if (state.refreshing) return;

  state.refreshing = true;

  if (manual) playUiSound("refresh");

  const buttons = [
    $("refreshBtn"),
    $("mobileRefreshBtn")
  ].filter(Boolean);

  buttons.forEach(button => {
    button.disabled = true;
    button.style.opacity = ".65";
  });

  setMessage("");

  try {
    const [summaryResult, eventsResult] = await Promise.allSettled([
      loadSummary(),
      loadEvents()
    ]);

    if (summaryResult.status === "rejected") {
      throw summaryResult.reason;
    }

    if (eventsResult.status === "rejected") {
      throw eventsResult.reason;
    }

    state.events = eventsResult.value;

    updateMetrics(summaryResult.value);
    renderDashboard();
    setConnection(true, "API CONNECTED");

    if ($("lastUpdated")) {
      $("lastUpdated").textContent = new Date().toLocaleTimeString();
    }

    if ($("tableStatus")) {
      $("tableStatus").textContent =
        `Showing ${state.filteredEvents.length} of ${state.events.length} loaded events`;
    }
  } catch (error) {
    console.error("SecureWeb dashboard refresh failed:", error);

    if (error.status === 401 || error.status === 403) {
      setConnection(false, "AUTHENTICATION REQUIRED");

      setMessage(
        "The API denied access. Sign in first and check your account permissions.",
        "error"
      );
    } else {
      setConnection(false, "API CONNECTION ERROR");

      setMessage(
        `Could not load dashboard data: ${error.message}. Check the backend API endpoints.`,
        "error"
      );
    }

    if ($("tableStatus")) {
      $("tableStatus").textContent = "Unable to refresh data";
    }
  } finally {
    state.refreshing = false;

    buttons.forEach(button => {
      button.disabled = false;
      button.style.opacity = "1";
    });

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }
}

// -------------------- INITIALIZATION --------------------

function initializeDashboard() {
  $("refreshBtn")?.addEventListener("click", () => refreshDashboard(true));
  $("mobileRefreshBtn")?.addEventListener("click", () => refreshDashboard(true));

  $("eventSearch")?.addEventListener("input", applyFilters);
  $("eventFilter")?.addEventListener("change", applyFilters);
  $("severityFilter")?.addEventListener("change", applyFilters);

  loadCurrentUser();
  refreshDashboard(false);

  if (state.autoRefresh) {
    if (state.refreshTimer) clearInterval(state.refreshTimer);

    state.refreshTimer = setInterval(() => {
      if (!state.refreshing) refreshDashboard(false);
    }, 20000);
  }
}

document.addEventListener("DOMContentLoaded", initializeDashboard);
