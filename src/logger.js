// ============================================================
// Jarvis — Action Logger
// Every tool execution is logged. No exceptions.
// ============================================================

const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(LOG_DIR, 'action-log.json');

// In-memory log + file persistence
let actionLog = [];

function init() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
  if (fs.existsSync(LOG_FILE)) {
    try {
      actionLog = JSON.parse(fs.readFileSync(LOG_FILE, 'utf-8'));
    } catch {
      actionLog = [];
    }
  }
}

function logAction(summary, tier, details = {}) {
  const entry = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    summary,
    tier,
    tool: details.tool || null,
    params: sanitizeForLog(details.params),
    result: sanitizeForLog(details.result),
    status: details.status || 'completed',
    severity: details.severity || null,
  };
  actionLog.push(entry);
  persist();
  return entry;
}

/**
 * Defense-in-depth: scrub known secret patterns from any data
 * before it hits the log file. Even if a tool accidentally
 * includes raw secrets, they won't be persisted in plaintext.
 */
const SECRET_SCRUB_PATTERNS = [
  { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS_KEY' },
  { regex: /gh[ps]_[A-Za-z0-9_]{36,}/g, label: 'GH_TOKEN' },
  { regex: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g, label: 'STRIPE_KEY' },
  { regex: /xox[bpors]-[A-Za-z0-9-]{10,}/g, label: 'SLACK_TOKEN' },
  { regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, label: 'JWT' },
  { regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi, label: 'DB_URI' },
  { regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, label: 'PRIVATE_KEY' },
];

function sanitizeForLog(data) {
  if (!data) return data;

  let str;
  if (typeof data === 'string') {
    str = data;
  } else {
    try { str = JSON.stringify(data); } catch { return data; }
  }

  for (const { regex, label } of SECRET_SCRUB_PATTERNS) {
    const pat = new RegExp(regex.source, regex.flags);
    str = str.replace(pat, (match) => `[REDACTED:${label}:****${match.slice(-4)}]`);
  }

  if (typeof data === 'string') return str;
  try { return JSON.parse(str); } catch { return str; }
}

function getHistory(filter = {}) {
  let results = [...actionLog];

  if (filter.tier) {
    results = results.filter(e => e.tier === filter.tier);
  }
  if (filter.tool) {
    results = results.filter(e => e.tool === filter.tool);
  }
  if (filter.status) {
    results = results.filter(e => e.status === filter.status);
  }
  if (filter.since) {
    const since = new Date(filter.since);
    results = results.filter(e => new Date(e.timestamp) >= since);
  }
  if (filter.limit) {
    results = results.slice(-filter.limit);
  }

  return results;
}

function getSessionActions(sessionStart) {
  const start = sessionStart || actionLog[0]?.timestamp || new Date().toISOString();
  return actionLog.filter(e => new Date(e.timestamp) >= new Date(start));
}

function clearLog() {
  actionLog = [];
  persist();
}

function persist() {
  try {
    fs.writeFileSync(LOG_FILE, JSON.stringify(actionLog, null, 2));
  } catch (err) {
    console.error('[Logger] Failed to persist log:', err.message);
  }
}

init();

module.exports = { logAction, getHistory, getSessionActions, clearLog };
