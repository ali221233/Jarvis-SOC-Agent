// ============================================================
// Jarvis SOC — Seed Demo Data (LOW RISK scenario)
// Risk target: 35-45 (1 LOW + 1 INFO = 5 + 3 = 8 from alerts)
// Additional findings from log parsing should bring it to ~38
// Run: node scripts/seed-demo-low.js
// ============================================================

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DEMO_DIR = path.join(DATA_DIR, 'demo-logs');
const ROOT = path.join(__dirname, '..');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---- Windows Event Log (low severity) ----
function seedWindowsEventsLow() {
  const events = [
    'TimeCreated: 2024-01-15T09:05:00Z | EventID: 4625 | Source: Security | Failed logon attempt for user jsmith from 10.0.0.15',
    'TimeCreated: 2024-01-15T09:22:00Z | EventID: 4625 | Source: Security | Failed logon attempt for user agarcia from 10.0.0.22',
    'TimeCreated: 2024-01-15T09:45:00Z | EventID: 4625 | Source: Security | Failed logon attempt for user jsmith from 10.0.0.15',
    'TimeCreated: 2024-01-15T10:00:00Z | EventID: 4624 | Source: Security | Successful logon for jsmith from 10.0.0.15',
    'TimeCreated: 2024-01-15T10:05:00Z | EventID: 4624 | Source: Security | Successful logon for agarcia from 10.0.0.22',
  ];
  fs.writeFileSync(path.join(DEMO_DIR, 'windows_events.txt'), events.join('\n') + '\n');
  console.log('[Seed-Low] windows_events.txt — 3 failed logins (normal user errors), 2 successful');
}

// ---- Linux auth.log (low severity) ----
function seedAuthLogLow() {
  const lines = [
    'Jan 15 09:10:01 devbox sshd[4001]: Failed password for devuser from 192.168.1.50 port 22 ssh2',
    'Jan 15 09:10:15 devbox sshd[4002]: Failed password for devuser from 192.168.1.50 port 22 ssh2',
    'Jan 15 09:13:00 devbox sshd[4003]: Accepted password for devuser from 192.168.1.50 port 22 ssh2',
    'Jan 15 09:15:00 devbox CRON[4004]: (root) CMD (/usr/bin/apt-get update > /dev/null 2>&1)',
  ];
  fs.writeFileSync(path.join(DEMO_DIR, 'auth.log'), lines.join('\n') + '\n');
  console.log('[Seed-Low] auth.log — 2 failed SSH + 1 success (forgot password), routine cron');
}

// ---- Web access log (no attacks) ----
function seedAccessLogLow() {
  const lines = [
    '192.168.1.50 - - [15/Jan/2024:09:00:01 +0000] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0"',
    '192.168.1.50 - - [15/Jan/2024:09:00:02 +0000] "GET /css/style.css HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.50 - - [15/Jan/2024:09:01:00 +0000] "GET /dashboard HTTP/1.1" 200 8901 "-" "Mozilla/5.0"',
    '192.168.1.50 - - [15/Jan/2024:09:05:00 +0000] "GET /api/status HTTP/1.1" 200 234 "-" "Mozilla/5.0"',
    '192.168.1.51 - - [15/Jan/2024:09:10:00 +0000] "GET /nonexistent-page HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
    '192.168.1.50 - - [15/Jan/2024:09:15:00 +0000] "POST /api/login HTTP/1.1" 200 567 "-" "Mozilla/5.0"',
  ];
  fs.writeFileSync(path.join(DEMO_DIR, 'access.log'), lines.join('\n') + '\n');
  console.log('[Seed-Low] access.log — 6 normal requests, 1 x 404, no attack signatures');
}

// ---- Clean test_secrets (no secrets) ----
function seedCleanSecrets() {
  const content = `# Configuration file - no secrets
APP_NAME=JarvisSOC
LOG_LEVEL=info
PORT=3000
DATABASE_HOST=localhost
`;
  fs.writeFileSync(path.join(ROOT, 'test_secrets.txt'), content);
  console.log('[Seed-Low] test_secrets.txt — clean config, no secrets');
}

// ---- Alerts (2 MEDIUM + 2 LOW + 2 INFO) → risk = 20+10+6 = 36 from alerts ----
function seedAlertsLow() {
  const now = new Date();
  const alerts = [
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-001',
      title: 'SSL certificate expires in 14 days',
      severity: 'MEDIUM',
      source: 'Certificate Monitor',
      details: 'TLS certificate for api.internal.local expires on 2024-02-01. Renewal recommended.',
      status: 'OPEN', triageDecision: null, triageNotes: null, priority: 'P3',
      createdAt: new Date(now - 259200000).toISOString(),
      updatedAt: new Date(now - 259200000).toISOString(),
      closedAt: null, resolution: null, mitreMapping: [],
      timelineEvents: [{ time: new Date(now - 259200000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-002',
      title: 'Firewall rule allows broad inbound on port 8080',
      severity: 'MEDIUM',
      source: 'Firewall Audit',
      details: 'Inbound rule permits 0.0.0.0/0 on port 8080. Consider restricting to known subnets.',
      status: 'OPEN', triageDecision: null, triageNotes: null, priority: 'P3',
      createdAt: new Date(now - 172800000).toISOString(),
      updatedAt: new Date(now - 172800000).toISOString(),
      closedAt: null, resolution: null, mitreMapping: [],
      timelineEvents: [{ time: new Date(now - 172800000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-003',
      title: 'Routine patch check: 3 updates available',
      severity: 'LOW',
      source: 'System Monitor',
      details: 'Windows Update reports 3 non-critical patches pending installation.',
      status: 'OPEN', triageDecision: null, triageNotes: null, priority: 'P4',
      createdAt: new Date(now - 172800000).toISOString(),
      updatedAt: new Date(now - 172800000).toISOString(),
      closedAt: null, resolution: null, mitreMapping: [],
      timelineEvents: [{ time: new Date(now - 172800000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-004',
      title: 'Antivirus definitions 5 days old',
      severity: 'LOW',
      source: 'Endpoint Protection',
      details: 'Malware definitions last updated 5 days ago. Auto-update may be disabled.',
      status: 'OPEN', triageDecision: null, triageNotes: null, priority: 'P4',
      createdAt: new Date(now - 86400000).toISOString(),
      updatedAt: new Date(now - 86400000).toISOString(),
      closedAt: null, resolution: null, mitreMapping: [],
      timelineEvents: [{ time: new Date(now - 86400000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-005',
      title: 'Scheduled backup completed successfully',
      severity: 'INFO',
      source: 'Backup Service',
      details: 'Daily backup completed. 4.2 GB written to NAS.',
      status: 'OPEN', triageDecision: null, triageNotes: null, priority: 'P4',
      createdAt: new Date(now - 86400000).toISOString(),
      updatedAt: new Date(now - 86400000).toISOString(),
      closedAt: null, resolution: null, mitreMapping: [],
      timelineEvents: [{ time: new Date(now - 86400000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-006',
      title: 'Disk usage at 72% on /var',
      severity: 'INFO',
      source: 'System Monitor',
      details: '/var partition at 72% capacity. No immediate action needed.',
      status: 'OPEN', triageDecision: null, triageNotes: null, priority: 'P4',
      createdAt: new Date(now - 43200000).toISOString(),
      updatedAt: new Date(now - 43200000).toISOString(),
      closedAt: null, resolution: null, mitreMapping: [],
      timelineEvents: [{ time: new Date(now - 43200000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
  ];
  fs.writeFileSync(path.join(DATA_DIR, 'alerts.json'), JSON.stringify(alerts, null, 2));
  console.log('[Seed-Low] alerts.json — 2 MEDIUM, 2 LOW, 2 INFO (risk: 36)');
}

// ---- Run ----
console.log('\n  ╔═══════════════════════════════════════╗');
console.log('  ║  Seed: LOW RISK scenario (35-45)      ║');
console.log('  ╚═══════════════════════════════════════╝\n');

ensureDir(DATA_DIR);
ensureDir(DEMO_DIR);
seedWindowsEventsLow();
seedAuthLogLow();
seedAccessLogLow();
seedCleanSecrets();
seedAlertsLow();

// Clear action log for fresh session
const logFile = path.join(DATA_DIR, 'action-log.json');
fs.writeFileSync(logFile, '[]');
console.log('[Seed-Low] action-log.json cleared');

console.log('\n[Seed-Low] Done. Expected risk score: ~8 (from 1 LOW + 1 INFO alert)');
console.log('           After parsing logs: should reach ~35-45\n');
