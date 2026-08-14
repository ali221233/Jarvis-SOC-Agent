// ============================================================
// Jarvis SOC — SQLite Database Layer
// Persistent storage using better-sqlite3.
// Auto-migrates from JSON files on first run.
// ============================================================

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, '..', 'data', 'jarvis.db');
const DATA_DIR = path.join(__dirname, '..', 'data');

let db = null;
let currentSessionId = null;

/**
 * Initialize database, create tables, migrate existing JSON data.
 */
function init() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  createTables();
  migrateFromJson();
  startSession();

  console.log(`  [DB] SQLite initialized: ${DB_PATH}`);
  console.log(`  [DB] Session: ${currentSessionId}`);
}

function createTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      source TEXT,
      details TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      mitre_techniques TEXT,
      status TEXT DEFAULT 'OPEN',
      triage_decision TEXT,
      triage_notes TEXT,
      priority TEXT DEFAULT 'P3',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      resolved_at TEXT,
      resolution TEXT,
      session_id TEXT
    );

    CREATE TABLE IF NOT EXISTS actions (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      summary TEXT,
      tool TEXT,
      tier INTEGER NOT NULL,
      params TEXT,
      result TEXT,
      status TEXT DEFAULT 'completed',
      source TEXT DEFAULT 'user',
      severity TEXT,
      cvss_score REAL
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
      id TEXT PRIMARY KEY,
      indicator_type TEXT NOT NULL,
      indicator_value TEXT NOT NULL,
      source TEXT NOT NULL,
      score REAL,
      details TEXT,
      checked_at TEXT NOT NULL,
      session_id TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      risk_score REAL,
      findings_count INTEGER DEFAULT 0,
      report_path TEXT,
      report_hash TEXT
    );

    CREATE TABLE IF NOT EXISTS baseline (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      metric_name TEXT NOT NULL,
      metric_value REAL NOT NULL,
      recorded_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id);
    CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id);
    CREATE INDEX IF NOT EXISTS idx_actions_tool ON actions(tool);
    CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intel(indicator_value);
  `);
}

/**
 * Migrate existing JSON data into SQLite on first run.
 */
function migrateFromJson() {
  const alertsFile = path.join(DATA_DIR, 'alerts.json');
  const actionLogFile = path.join(DATA_DIR, 'action-log.json');

  // Check if migration already happened (incidents table has data)
  const count = db.prepare('SELECT COUNT(*) as cnt FROM incidents').get();
  if (count.cnt > 0) return; // Already migrated

  // Migrate alerts
  if (fs.existsSync(alertsFile)) {
    try {
      const alerts = JSON.parse(fs.readFileSync(alertsFile, 'utf-8'));
      const stmt = db.prepare(`
        INSERT OR IGNORE INTO incidents (id, title, severity, source, details, status,
          triage_decision, triage_notes, priority, created_at, updated_at, resolved_at,
          resolution, session_id, mitre_techniques)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const insertMany = db.transaction((alerts) => {
        for (const a of alerts) {
          stmt.run(
            a.id, a.title, a.severity, a.source, a.details,
            a.status || 'OPEN', a.triageDecision, a.triageNotes,
            a.priority || 'P3', a.createdAt, a.updatedAt,
            a.closedAt, a.resolution, 'migrated',
            a.mitreMapping ? JSON.stringify(a.mitreMapping) : null
          );
        }
      });
      insertMany(alerts);
      console.log(`  [DB] Migrated ${alerts.length} alerts from JSON`);
    } catch (err) {
      console.error(`  [DB] Alert migration error: ${err.message}`);
    }
  }

  // Migrate action log
  if (fs.existsSync(actionLogFile)) {
    try {
      const actions = JSON.parse(fs.readFileSync(actionLogFile, 'utf-8'));
      const stmt = db.prepare(`
        INSERT OR IGNORE INTO actions (id, session_id, timestamp, summary, tool,
          tier, params, result, status, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const insertMany = db.transaction((actions) => {
        for (const a of actions) {
          stmt.run(
            a.id, 'migrated', a.timestamp, a.summary, a.tool,
            a.tier || 1,
            typeof a.params === 'object' ? JSON.stringify(a.params) : a.params,
            typeof a.result === 'object' ? JSON.stringify(a.result) : a.result,
            a.status || 'completed', a.severity
          );
        }
      });
      insertMany(actions);
      console.log(`  [DB] Migrated ${actions.length} actions from JSON`);
    } catch (err) {
      console.error(`  [DB] Action migration error: ${err.message}`);
    }
  }
}

// ---- Session Management ----

function startSession() {
  currentSessionId = uuidv4();
  db.prepare(`
    INSERT INTO sessions (id, started_at) VALUES (?, ?)
  `).run(currentSessionId, new Date().toISOString());
}

function endSession(riskScore, findingsCount) {
  if (!currentSessionId) return;
  db.prepare(`
    UPDATE sessions SET ended_at = ?, risk_score = ?, findings_count = ?
    WHERE id = ?
  `).run(new Date().toISOString(), riskScore || 0, findingsCount || 0, currentSessionId);
}

function getSessionId() {
  return currentSessionId;
}

function getSessionHistory(limit = 10) {
  return db.prepare(`
    SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?
  `).all(limit);
}

function getLastSession() {
  return db.prepare(`
    SELECT * FROM sessions WHERE id != ? ORDER BY started_at DESC LIMIT 1
  `).get(currentSessionId);
}

// ---- Incident CRUD ----

function insertIncident(incident) {
  const id = incident.id || `INC-${new Date().toISOString().slice(0, 10)}-${String(Date.now()).slice(-3)}`;
  db.prepare(`
    INSERT OR REPLACE INTO incidents (id, title, severity, source, details, cvss_score,
      cvss_vector, mitre_techniques, status, triage_decision, triage_notes, priority,
      created_at, updated_at, resolved_at, resolution, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, incident.title, incident.severity, incident.source, incident.details,
    incident.cvss_score || null, incident.cvss_vector || null,
    incident.mitre_techniques ? JSON.stringify(incident.mitre_techniques) : null,
    incident.status || 'OPEN', incident.triage_decision || null,
    incident.triage_notes || null, incident.priority || 'P3',
    incident.created_at || new Date().toISOString(),
    incident.updated_at || new Date().toISOString(),
    incident.resolved_at || null, incident.resolution || null,
    currentSessionId
  );
  return id;
}

function getOpenIncidents() {
  return db.prepare(`
    SELECT * FROM incidents WHERE status = 'OPEN' ORDER BY
      CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        WHEN 'INFO' THEN 5
        ELSE 6
      END, created_at DESC
  `).all();
}

function getClosedIncidents() {
  return db.prepare(`
    SELECT * FROM incidents WHERE status = 'CLOSED' ORDER BY resolved_at DESC
  `).all();
}

function getAllIncidents() {
  return db.prepare('SELECT * FROM incidents ORDER BY created_at DESC').all();
}

function getIncidentById(id) {
  return db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
}

function updateIncident(id, updates) {
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(updates)) {
    // Convert camelCase to snake_case for DB
    const col = key.replace(/([A-Z])/g, '_$1').toLowerCase();
    fields.push(`${col} = ?`);
    values.push(typeof val === 'object' ? JSON.stringify(val) : val);
  }
  fields.push('updated_at = ?');
  values.push(new Date().toISOString());
  values.push(id);
  db.prepare(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ?`).run(...values);
}

// ---- Action CRUD ----

function insertAction(action) {
  const id = action.id || uuidv4();
  db.prepare(`
    INSERT INTO actions (id, session_id, timestamp, summary, tool, tier,
      params, result, status, source, severity, cvss_score)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, currentSessionId, action.timestamp || new Date().toISOString(),
    action.summary, action.tool, action.tier || 1,
    typeof action.params === 'object' ? JSON.stringify(action.params) : action.params,
    typeof action.result === 'object' ? JSON.stringify(action.result) : action.result,
    action.status || 'completed', action.source || 'user',
    action.severity || null, action.cvss_score || null
  );
  return id;
}

function getActionHistory(filter = {}) {
  let sql = 'SELECT * FROM actions WHERE 1=1';
  const params = [];

  if (filter.tier) { sql += ' AND tier = ?'; params.push(filter.tier); }
  if (filter.tool) { sql += ' AND tool = ?'; params.push(filter.tool); }
  if (filter.status) { sql += ' AND status = ?'; params.push(filter.status); }
  if (filter.session) { sql += ' AND session_id = ?'; params.push(filter.session); }
  if (filter.source) { sql += ' AND source = ?'; params.push(filter.source); }
  if (filter.since) { sql += ' AND timestamp >= ?'; params.push(filter.since); }

  sql += ' ORDER BY timestamp DESC';
  if (filter.limit) { sql += ' LIMIT ?'; params.push(filter.limit); }

  return db.prepare(sql).all(...params);
}

// ---- Threat Intel ----

function insertThreatIntel(entry) {
  const id = uuidv4();
  db.prepare(`
    INSERT INTO threat_intel (id, indicator_type, indicator_value, source,
      score, details, checked_at, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, entry.type, entry.value, entry.source,
    entry.score || null,
    typeof entry.details === 'object' ? JSON.stringify(entry.details) : entry.details,
    new Date().toISOString(), currentSessionId
  );
  return id;
}

function getThreatIntelHistory(limit = 50) {
  return db.prepare(`
    SELECT * FROM threat_intel ORDER BY checked_at DESC LIMIT ?
  `).all(limit);
}

// ---- Baseline ----

function insertBaselineMetric(name, value) {
  db.prepare(`
    INSERT INTO baseline (metric_name, metric_value, recorded_at) VALUES (?, ?, ?)
  `).run(name, value, new Date().toISOString());
}

function getBaselineMetrics(name) {
  return db.prepare(`
    SELECT * FROM baseline WHERE metric_name = ? ORDER BY recorded_at DESC
  `).all(name);
}

function clearBaseline() {
  db.prepare('DELETE FROM baseline').run();
}

// ---- Aggregate Queries ----

function getIncidentCountByPeriod(days = 7) {
  const since = new Date(Date.now() - days * 86400000).toISOString();
  return db.prepare(`
    SELECT severity, COUNT(*) as count FROM incidents
    WHERE created_at >= ? GROUP BY severity
  `).all(since);
}

function getActionCountByTool(sessionId) {
  const sid = sessionId || currentSessionId;
  return db.prepare(`
    SELECT tool, COUNT(*) as count FROM actions
    WHERE session_id = ? AND tool IS NOT NULL GROUP BY tool ORDER BY count DESC
  `).all(sid);
}

function searchIncidents(query) {
  return db.prepare(`
    SELECT * FROM incidents
    WHERE title LIKE ? OR details LIKE ? OR source LIKE ?
    ORDER BY created_at DESC LIMIT 50
  `).all(`%${query}%`, `%${query}%`, `%${query}%`);
}

// ---- Cleanup ----

function close() {
  if (db) {
    try { db.close(); } catch {}
  }
}

// Initialize on load
try {
  init();
} catch (err) {
  console.error(`  [DB] Init failed: ${err.message}. Falling back to JSON.`);
}

module.exports = {
  getDb: () => db,
  getSessionId,
  startSession,
  endSession,
  getSessionHistory,
  getLastSession,
  insertIncident,
  getOpenIncidents,
  getClosedIncidents,
  getAllIncidents,
  getIncidentById,
  updateIncident,
  insertAction,
  getActionHistory,
  insertThreatIntel,
  getThreatIntelHistory,
  insertBaselineMetric,
  getBaselineMetrics,
  clearBaseline,
  getIncidentCountByPeriod,
  getActionCountByTool,
  searchIncidents,
  close,
};
