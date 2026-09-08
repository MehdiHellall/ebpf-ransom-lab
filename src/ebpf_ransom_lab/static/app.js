"use strict";

const byId = (id) => document.getElementById(id);
const setText = (id, value) => { byId(id).textContent = String(value); };

function renderRows(target, rows, fields, emptyText) {
  const body = byId(target);
  body.replaceChildren();
  if (rows.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = fields.length;
    cell.textContent = emptyText;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  rows.forEach((item) => {
    const row = document.createElement("tr");
    fields.forEach((field) => {
      const cell = document.createElement("td");
      const value = typeof field === "function" ? field(item) : item[field];
      cell.textContent = value === null || value === undefined ? "—" : String(value);
      row.appendChild(cell);
    });
    body.appendChild(row);
  });
}

async function get(path) {
  const response = await fetch(path, {headers: {"Accept": "application/json"}});
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

async function refresh() {
  try {
    const [health, metrics, alerts, processes] = await Promise.all([
      get("/api/v1/health"), get("/api/v1/metrics"),
      get("/api/v1/alerts?limit=20"), get("/api/v1/processes?limit=20"),
    ]);
    const connection = byId("connection");
    connection.textContent = health.collector_connected ? "Connected" : "Disconnected";
    connection.className = health.collector_connected ? "status connected" : "status disconnected";
    setText("event-rate", `${Number(health.event_rate).toFixed(1)}/s`);
    setText("lost-events", health.lost_events);
    setText("recording", health.recording ? "On" : "Off");
    setText("active-alerts", metrics.active_alerts);
    renderRows("alerts", alerts.items, ["run_id", "tgid", (x) => Number(x.score).toFixed(3),
      (x) => JSON.stringify(x.supporting_features)], "No alerts recorded.");
    renderRows("processes", processes.items, ["run_id", "tgid", "window_count", "latest_window_ns"],
      "No process windows yet.");
  } catch (error) {
    const connection = byId("connection");
    connection.textContent = "Service unavailable";
    connection.className = "status disconnected";
  }
}

refresh();
window.setInterval(refresh, 1000);
