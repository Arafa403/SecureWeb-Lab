
"use strict";

const byId = (id) => document.getElementById(id);

// SIEM state
let knownIncidentStates = null;
let audioContext = null;
let audioUnlocked = false;
let isLoading = false;

// API request helper
async function request(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body
        ? { "Content-Type": "application/json" }
        : {}),
      ...options.headers
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error || `Request failed (${response.status})`
    );
  }

  return data;
}

// Escape HTML
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

// Dashboard message
function showMessage(text, error = false) {
  const element = byId("message");
  if (!element) return;

  element.className = error ? "error" : "label";
  element.textContent = text;
}

// Format date
function formatDate(value) {
  if (!value) return "—";

  const normalized = String(value).replace(" ", "T");
  const date = new Date(
    normalized.endsWith("Z") ? normalized : `${normalized}Z`
  );

  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString();
}

// Initialize audio after a user gesture
async function unlockAudio() {
  try {
    const AudioContextClass =
      window.AudioContext || window.webkitAudioContext;

    if (!AudioContextClass) {
      console.warn("Audio alerts are not supported by this browser.");
      return false;
    }

    if (!audioContext || audioContext.state === "closed") {
      audioContext = new AudioContextClass();
    }

    if (audioContext.state === "suspended") {
      await audioContext.resume();
    }

    audioUnlocked = audioContext.state === "running";

    if (audioUnlocked) {
      console.info("Audio alert is ready.");
    } else {
      console.warn("Audio is not running. Check browser permissions.");
    }

    return audioUnlocked;
  } catch (error) {
    console.error("Audio initialization error:", error);
    return false;
  }
}

// Play three short security beeps
async function playSecurityAlarm() {
  try {
    const AudioContextClass =
      window.AudioContext || window.webkitAudioContext;

    if (!AudioContextClass) {
      console.warn("Web Audio API is not supported.");
      return;
    }

    if (!audioContext || audioContext.state === "closed") {
      audioContext = new AudioContextClass();
    }

    if (audioContext.state === "suspended") {
      await audioContext.resume();
    }

    if (audioContext.state !== "running") {
      console.warn(
        "Audio is not running. Click the dashboard to enable sound."
      );
      return;
    }

    audioUnlocked = true;

    for (let i = 0; i < 3; i++) {
      const oscillator = audioContext.createOscillator();
      const gain = audioContext.createGain();
      const start = audioContext.currentTime + i * 0.28;

      oscillator.type = "sine";
      oscillator.frequency.setValueAtTime(880, start);

      gain.gain.setValueAtTime(0.001, start);
      gain.gain.exponentialRampToValueAtTime(0.2, start + 0.03);
      gain.gain.setValueAtTime(0.2, start + 0.12);
      gain.gain.exponentialRampToValueAtTime(0.001, start + 0.2);

      oscillator.connect(gain);
      gain.connect(audioContext.destination);

      oscillator.start(start);
      oscillator.stop(start + 0.22);
    }
  } catch (error) {
    console.error("Security alarm error:", error);
  }
}

// Update incident status
async function updateStatus(id, status) {
  try {
    await request(
      `/api/siem/incidents/${encodeURIComponent(id)}/status`,
      {
        method: "PATCH",
        body: JSON.stringify({ status })
      }
    );

    // Update known status immediately to avoid false alerts.
    if (knownIncidentStates?.has(String(id))) {
      const previous = knownIncidentStates.get(String(id));

      knownIncidentStates.set(String(id), {
        ...previous,
        status
      });
    }

    await load();
    showMessage("Incident status updated.");
  } catch (error) {
    showMessage(error.message, true);
    console.error("Update incident error:", error);
  }
}

// Render event types
function renderEventTypes(eventTypes) {
  const element = byId("types");
  if (!element) return;

  element.innerHTML = eventTypes.length
    ? eventTypes.map((event) => {
        const name = esc(event.event_type || "UNKNOWN");
        const total = Number(event.total ?? event.count) || 0;

        return `
          <div style="
            display:flex;
            justify-content:space-between;
            gap:12px;
            padding:8px 0;
            border-bottom:1px solid var(--line);
          ">
            <span>${name}</span>
            <strong>${total}</strong>
          </div>
        `;
      }).join("")
    : '<div class="empty">No events in the last 24 hours.</div>';
}

// Render incidents
function renderIncidents(incidents) {
  const element = byId("incidents");
  if (!element) return;

  element.innerHTML = incidents.length
    ? incidents.map((incident) => {
        const id = Number(incident.id);
        const severity = String(incident.severity || "unknown")
          .toLowerCase();
        const status = String(incident.status || "open")
          .toLowerCase();

        return `
          <tr>
            <td>
              <span class="pill ${esc(severity)}">
                ${esc(severity.toUpperCase())}
              </span>
            </td>
            <td>
              <strong>${esc(incident.title || "Untitled incident")}</strong><br>
              <span class="label">
                ${esc(incident.description || "")}
              </span>
            </td>
            <td>${esc(incident.source_ip || "—")}</td>
            <td>${Number(incident.event_count) || 0}</td>
            <td class="${esc(status)}">${esc(status)}</td>
            <td>${esc(formatDate(incident.last_seen))}</td>
            <td>
              <select
                aria-label="Update incident ${id}"
                data-action="status"
                data-id="${id}"
              >
                <option value="">Change…</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>
            </td>
          </tr>
        `;
      }).join("")
    : `
      <tr>
        <td colspan="7" class="empty">
          No incidents match this filter.
        </td>
      </tr>
    `;

  element
    .querySelectorAll('[data-action="status"]')
    .forEach((control) => {
      control.addEventListener("change", () => {
        if (control.value) {
          updateStatus(control.dataset.id, control.value);
        }
      });
    });
}

// Compare current incidents against previously known incidents.
// Preserve states across filters so hidden incidents are not forgotten.
function detectIncidentAlerts(incidents) {
  const currentStates = new Map(
    incidents.map((incident) => [
      String(incident.id),
      {
        eventCount: Number(incident.event_count) || 0,
        status: String(incident.status || "open").toLowerCase()
      }
    ])
  );

  const alerts = [];

  // First successful load establishes the baseline.
  if (knownIncidentStates !== null) {
    for (const incident of incidents) {
      const id = String(incident.id);
      const previous = knownIncidentStates.get(id);
      const current = currentStates.get(id);

      if (current.status !== "open") continue;

      const isNewIncident = !previous;
      const eventCountIncreased =
        previous && current.eventCount > previous.eventCount;

      if (isNewIncident || eventCountIncreased) {
        alerts.push(incident);
      }
    }

    // Merge instead of replacing; retain incidents hidden by filters.
    for (const [id, state] of currentStates) {
      knownIncidentStates.set(id, state);
    }
  } else {
    knownIncidentStates = new Map(currentStates);
  }

  return alerts;
}

// Refresh dashboard
async function load() {
  if (isLoading) return;

  isLoading = true;

  try {
    const statusElement = byId("status");
    const selectedStatus = statusElement?.value || "";

    const incidentsUrl = selectedStatus
      ? `/api/siem/incidents?status=${encodeURIComponent(selectedStatus)}`
      : "/api/siem/incidents";

    const [summary, result] = await Promise.all([
      request("/api/siem/summary"),
      request(incidentsUrl)
    ]);

    // Summary cards
    const openElement = byId("openIncidents");
    const highElement = byId("highSeverity");
    const eventsElement = byId("events24h");

    if (openElement) {
      openElement.textContent = Number(summary.openIncidents) || 0;
    }

    if (highElement) {
      highElement.textContent = Number(summary.highSeverity) || 0;
    }

    if (eventsElement) {
      eventsElement.textContent = Number(summary.events24h) || 0;
    }

    // Event volume
    const eventTypes = Array.isArray(summary.eventTypes)
      ? summary.eventTypes
      : [];

    renderEventTypes(eventTypes);

    // Incident list
    const incidents = Array.isArray(result.incidents)
      ? result.incidents
      : [];

    const alerts = detectIncidentAlerts(incidents);

    renderIncidents(incidents);

    if (alerts.length > 0) {
      const message =
        `SECURITY ALERT: ${alerts.length} new or updated open incident(s)!`;

      showMessage(message, true);
      await playSecurityAlarm();
    } else {
      showMessage(`Updated ${new Date().toLocaleTimeString()}.`);
    }
  } catch (error) {
    showMessage(
      `${error.message}. Sign in as an administrator if access is denied.`,
      true
    );

    console.error("SIEM dashboard error:", error);
  } finally {
    isLoading = false;
  }
}

// Initialize dashboard
document.addEventListener("DOMContentLoaded", () => {
  byId("refresh")?.addEventListener("click", load);
  byId("status")?.addEventListener("change", load);

  // Enable audio after the first user interaction.
  document.addEventListener("click", async () => {
    if (!audioUnlocked) {
      await unlockAudio();
    }
  }, { once: true });

  // Initial baseline load
  load();

  // Poll every 10 seconds
  setInterval(load, 10000);
});
