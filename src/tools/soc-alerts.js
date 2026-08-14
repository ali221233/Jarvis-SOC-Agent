// ============================================================
// Jarvis SOC — Alert Triage Queue
// create_alert, triage_alert, escalate_alert, close_alert,
// get_alert_queue
// Persisted to data/alerts.json
// ============================================================

const fs = require('fs');
const path = require('path');

const ALERTS_DIR = path.join(__dirname, '..', '..', 'data');
const ALERTS_FILE = path.join(ALERTS_DIR, 'alerts.json');

let alerts = [];
let alertCounter = 0;
let wsBroadcast = null;

function setWsBroadcast(fn) { wsBroadcast = fn; }

function init() {
  if (!fs.existsSync(ALERTS_DIR)) fs.mkdirSync(ALERTS_DIR, { recursive: true });
  if (fs.existsSync(ALERTS_FILE)) {
    try {
      alerts = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf-8'));
      // Find highest counter from existing IDs
      for (const a of alerts) {
        const match = a.id.match(/-(\d+)$/);
        if (match) alertCounter = Math.max(alertCounter, parseInt(match[1]));
      }
    } catch { alerts = []; }
  }
}

function persist() {
  try {
    if (!fs.existsSync(ALERTS_DIR)) fs.mkdirSync(ALERTS_DIR, { recursive: true });
    fs.writeFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2));
  } catch (err) {
    console.error('[Alerts] Persist failed:', err.message);
  }
}

function generateIncidentId() {
  const now = new Date();
  const date = now.toISOString().slice(0, 10);
  alertCounter++;
  return `INC-${date}-${String(alertCounter).padStart(3, '0')}`;
}

// ---- TOOL: create_alert (Tier 1) ----
async function createAlert({ title, severity = 'MEDIUM', source = 'manual', details = '' }) {
  if (!title) return { error: 'Alert title is required.' };

  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  severity = severity.toUpperCase();
  if (!validSeverities.includes(severity)) severity = 'MEDIUM';

  const alert = {
    id: generateIncidentId(),
    title,
    severity,
    source,
    details: typeof details === 'object' ? JSON.stringify(details) : details,
    status: 'OPEN',
    triageDecision: null,
    triageNotes: null,
    priority: severity === 'CRITICAL' ? 'P1' : severity === 'HIGH' ? 'P2' : 'P3',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    closedAt: null,
    resolution: null,
    mitreMapping: [],
    timelineEvents: [
      { time: new Date().toISOString(), event: 'Alert created', actor: 'Jarvis' }
    ],
  };

  alerts.push(alert);
  persist();

  // Broadcast via WebSocket
  if (wsBroadcast) {
    wsBroadcast({ type: 'alert_created', alert });
  }

  // CRITICAL alerts: fire n8n webhook + Ntfy push notification
  if (severity === 'CRITICAL') {
    // n8n trigger (non-blocking)
    setImmediate(async () => {
      try {
        const n8nClient = require('../n8n-client');
        await n8nClient.triggerCriticalAlert(alert);
      } catch {}
      try {
        const ntfy = require('../ntfy-notifier');
        await ntfy.sendNtfy(alert);
      } catch {}
    });
  }

  return {
    tool: 'create_alert',
    alert,
    summary: `Alert ${alert.id} created — ${severity}: ${title}`,
  };
}

// ---- TOOL: triage_alert (Tier 2) ----
async function triageAlert({ incidentId, decision, notes = '' }) {
  if (!incidentId) return { error: 'Incident ID required.' };

  const validDecisions = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'NEEDS_INVESTIGATION'];
  decision = (decision || '').toUpperCase().replace(/\s+/g, '_');
  if (!validDecisions.includes(decision)) {
    return { error: `Invalid decision. Must be one of: ${validDecisions.join(', ')}` };
  }

  const alert = alerts.find(a => a.id === incidentId);
  if (!alert) return { error: `Alert ${incidentId} not found.` };

  alert.triageDecision = decision;
  alert.triageNotes = notes;
  alert.status = decision === 'FALSE_POSITIVE' ? 'CLOSED' : 'TRIAGED';
  alert.updatedAt = new Date().toISOString();
  if (decision === 'FALSE_POSITIVE') alert.closedAt = new Date().toISOString();

  alert.timelineEvents.push({
    time: new Date().toISOString(),
    event: `Triaged as ${decision}${notes ? ': ' + notes : ''}`,
    actor: 'Boss',
  });

  persist();

  if (wsBroadcast) {
    wsBroadcast({ type: 'alert_updated', alert });
  }

  return {
    tool: 'triage_alert',
    incidentId,
    decision,
    notes,
    summary: `${incidentId} triaged as ${decision}.${decision === 'FALSE_POSITIVE' ? ' Alert closed.' : ''}`,
  };
}

// ---- TOOL: escalate_alert (Tier 2) ----
async function escalateAlert({ incidentId, reason = '' }) {
  if (!incidentId) return { error: 'Incident ID required.' };

  const alert = alerts.find(a => a.id === incidentId);
  if (!alert) return { error: `Alert ${incidentId} not found.` };

  alert.priority = 'P1';
  alert.status = 'ESCALATED';
  alert.updatedAt = new Date().toISOString();
  alert.timelineEvents.push({
    time: new Date().toISOString(),
    event: `Escalated to P1${reason ? ': ' + reason : ''}`,
    actor: 'Boss',
  });

  persist();

  if (wsBroadcast) {
    wsBroadcast({ type: 'alert_escalated', alert });
  }

  return {
    tool: 'escalate_alert',
    incidentId,
    priority: 'P1',
    summary: `Escalated ${incidentId} to P1, Boss. Timeline clock starts now.`,
  };
}

// ---- TOOL: close_alert (Tier 2) ----
async function closeAlert({ incidentId, resolution = '' }) {
  if (!incidentId) return { error: 'Incident ID required.' };

  const alert = alerts.find(a => a.id === incidentId);
  if (!alert) return { error: `Alert ${incidentId} not found.` };

  alert.status = 'CLOSED';
  alert.resolution = resolution;
  alert.closedAt = new Date().toISOString();
  alert.updatedAt = new Date().toISOString();
  alert.timelineEvents.push({
    time: new Date().toISOString(),
    event: `Closed: ${resolution || 'No resolution provided'}`,
    actor: 'Boss',
  });

  persist();

  if (wsBroadcast) {
    wsBroadcast({ type: 'alert_closed', alert });
  }

  return {
    tool: 'close_alert',
    incidentId,
    resolution,
    summary: `${incidentId} closed. ${resolution}`,
  };
}

// ---- TOOL: get_alert_queue (Tier 1) ----
async function getAlertQueue() {
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const open = alerts
    .filter(a => a.status !== 'CLOSED')
    .sort((a, b) => {
      const sevDiff = (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
      if (sevDiff !== 0) return sevDiff;
      return new Date(a.createdAt) - new Date(b.createdAt);
    });

  return {
    tool: 'get_alert_queue',
    alerts: open,
    total: open.length,
    bySeverity: {
      critical: open.filter(a => a.severity === 'CRITICAL').length,
      high: open.filter(a => a.severity === 'HIGH').length,
      medium: open.filter(a => a.severity === 'MEDIUM').length,
      low: open.filter(a => a.severity === 'LOW').length,
      info: open.filter(a => a.severity === 'INFO').length,
    },
    summary: `${open.length} open alert(s). ${open.filter(a => a.severity === 'CRITICAL').length} critical, ${open.filter(a => a.severity === 'HIGH').length} high.`,
  };
}

// ---- Helpers for other modules ----
function getAllAlerts() { return alerts; }
function getOpenAlerts() { return alerts.filter(a => a.status !== 'CLOSED'); }
function getClosedAlerts() { return alerts.filter(a => a.status === 'CLOSED'); }
function getAlertById(id) { return alerts.find(a => a.id === id); }

function getFindings() {
  // Return alerts as findings for CVSS risk scoring
  return alerts.map(a => ({
    severity: a.severity,
    cvssScore: a.cvssScore || null,
    status: a.status,
  }));
}

function getMetrics() {
  const open = alerts.filter(a => a.status !== 'CLOSED');
  const today = new Date().toDateString();
  return {
    open: open.length,
    critical: open.filter(a => a.severity === 'CRITICAL').length,
    high: open.filter(a => a.severity === 'HIGH').length,
    medium: open.filter(a => a.severity === 'MEDIUM').length,
    low: open.filter(a => a.severity === 'LOW').length,
    resolvedToday: alerts.filter(a => a.status === 'CLOSED' && a.closedAt && new Date(a.closedAt).toDateString() === today).length,
  };
}

function addMitreMapping(incidentId, techniqueId, techniqueName) {
  const alert = alerts.find(a => a.id === incidentId);
  if (alert) {
    if (!alert.mitreMapping.some(m => m.id === techniqueId)) {
      alert.mitreMapping.push({ id: techniqueId, name: techniqueName });
      persist();
    }
  }
}

init();

module.exports = {
  createAlert, triageAlert, escalateAlert, closeAlert, getAlertQueue,
  getAllAlerts, getOpenAlerts, getClosedAlerts, getAlertById,
  addMitreMapping, setWsBroadcast, getFindings, getMetrics,
};
