// ============================================================
// Jarvis SOC — Seed Demo Data (HIGH RISK scenario)
// Risk target: 72-82 (1 CRITICAL + 1 HIGH + 1 MEDIUM = 30+20+10 = 60 from alerts)
// Additional findings from log parsing bring it to ~75
// Run: node scripts/seed-demo-high.js
// ============================================================

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DEMO_DIR = path.join(DATA_DIR, 'demo-logs');
const ROOT = path.join(__dirname, '..');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---- Windows Event Log (attack chain) ----
function seedWindowsEventsHigh() {
  const events = [];
  // 12 failed logins in 3 minutes — brute force
  for (let i = 0; i < 12; i++) {
    const sec = String(i * 15).padStart(2, '0');
    events.push(`TimeCreated: 2024-01-15T02:10:${sec}Z | EventID: 4625 | Source: Security | Failed logon attempt for user administrator from 192.168.1.100`);
  }
  // Privilege escalation chain
  events.push('TimeCreated: 2024-01-15T02:14:00Z | EventID: 4720 | Source: Security | New user account created: svc_update by SYSTEM');
  events.push('TimeCreated: 2024-01-15T02:14:30Z | EventID: 4732 | Source: Security | User svc_update added to Administrators group');
  events.push('TimeCreated: 2024-01-15T02:16:00Z | EventID: 7045 | Source: System  | New service installed: WindowsUpdateSvc by svc_update');
  // Log clearing — the cleanup
  events.push('TimeCreated: 2024-01-15T02:22:00Z | EventID: 1102 | Source: Security | Audit log was cleared by svc_update');

  fs.writeFileSync(path.join(DEMO_DIR, 'windows_events.txt'), events.join('\n') + '\n');
  console.log('[Seed-High] windows_events.txt — 12 brute force + priv esc chain + log clear');
}

// ---- Linux auth.log (automated brute force) ----
function seedAuthLogHigh() {
  const lines = [];
  // 47 failed SSH attempts at 3-second intervals
  for (let i = 0; i < 47; i++) {
    const sec = String((i * 3) % 60).padStart(2, '0');
    const min = String(20 + Math.floor((i * 3) / 60)).padStart(2, '0');
    lines.push(`Jan 15 02:${min}:${sec} webserver sshd[${12340 + i}]: Failed password for root from 192.168.1.100 port ${54321 + i} ssh2`);
  }
  fs.writeFileSync(path.join(DEMO_DIR, 'auth.log'), lines.join('\n') + '\n');
  console.log('[Seed-High] auth.log — 47 failed SSH from 192.168.1.100 at 3s intervals');
}

// ---- Web access log (active attack) ----
function seedAccessLogHigh() {
  const lines = [
    // SQL injection attempts from sqlmap
    "10.0.0.5 - - [15/Jan/2024:02:30:00 +0000] \"GET /?id=1'%20OR%20'1'='1 HTTP/1.1\" 403 0 \"-\" \"sqlmap/1.7\"",
    '10.0.0.5 - - [15/Jan/2024:02:30:01 +0000] "GET /users?id=1%20UNION%20SELECT%20*%20FROM%20passwords HTTP/1.1" 403 0 "-" "sqlmap/1.7"',
    '10.0.0.5 - - [15/Jan/2024:02:30:02 +0000] "GET /search?q=1;DROP%20TABLE%20users HTTP/1.1" 500 0 "-" "sqlmap/1.7"',
    // Directory traversal
    '10.0.0.5 - - [15/Jan/2024:02:30:05 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "sqlmap/1.7"',
    // Admin brute force
    '10.0.0.5 - - [15/Jan/2024:02:31:00 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "sqlmap/1.7"',
  ];
  // 23 directory scan 404s
  for (let i = 0; i < 23; i++) {
    const sec = String(i * 2).padStart(2, '0');
    lines.push(`10.0.0.5 - - [15/Jan/2024:02:32:${sec} +0000] "GET /dir${i}/ HTTP/1.1" 404 0 "-" "Nikto/2.1.6"`);
  }
  fs.writeFileSync(path.join(DEMO_DIR, 'access.log'), lines.join('\n') + '\n');
  console.log('[Seed-High] access.log — 3 SQLi, 1 traversal, 1 admin POST, 23 Nikto scans');
}

// ---- Test secrets (3 fake credentials) ----
function seedSecretsHigh() {
  const content = `# Config file with leaked credentials (FAKE — for demo only)

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

STRIPE_SECRET_KEY=sk_test_FAKE0000000000000000000

DATABASE_PASSWORD=SuperSecret123!
DATABASE_URL=postgres://admin:SuperSecret123!@db.prod.internal:5432/maindb
`;
  fs.writeFileSync(path.join(DEMO_DIR, 'test_secrets_high.txt'), content);
  fs.writeFileSync(path.join(ROOT, 'test_secrets.txt'), content);
  console.log('[Seed-High] test_secrets_high.txt — 3 fake credential patterns');
}

// ---- Alerts (1 CRITICAL, 1 HIGH, 1 MEDIUM) → risk = 30+20+10 = 60 ----
function seedAlertsHigh() {
  const now = new Date();
  const alerts = [
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-001',
      title: 'Audit Log Cleared Following Privilege Escalation',
      severity: 'CRITICAL',
      source: 'Windows Event Log',
      details: 'Event ID 1102 detected 8 minutes after new admin account svc_update was created and added to Administrators group. Classic attack chain: brute force → account creation → privilege escalation → log clearing.',
      status: 'OPEN',
      triageDecision: null,
      triageNotes: null,
      priority: 'P1',
      createdAt: new Date(now - 900000).toISOString(),
      updatedAt: new Date(now - 900000).toISOString(),
      closedAt: null,
      resolution: null,
      mitreMapping: [{ id: 'T1070', name: 'Indicator Removal' }, { id: 'T1078', name: 'Valid Accounts' }],
      timelineEvents: [{ time: new Date(now - 900000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-002',
      title: 'SSH Brute Force Detected from 192.168.1.100',
      severity: 'HIGH',
      source: 'Linux Syslog',
      details: '47 failed SSH login attempts from 192.168.1.100 within 90 seconds. Exact 3-second intervals indicate automated credential-stuffing tool.',
      status: 'OPEN',
      triageDecision: null,
      triageNotes: null,
      priority: 'P2',
      createdAt: new Date(now - 720000).toISOString(),
      updatedAt: new Date(now - 720000).toISOString(),
      closedAt: null,
      resolution: null,
      mitreMapping: [{ id: 'T1110', name: 'Brute Force' }],
      timelineEvents: [{ time: new Date(now - 720000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-003',
      title: 'New Admin Account Created Outside Business Hours',
      severity: 'MEDIUM',
      source: 'Windows Event Log',
      details: 'User account svc_update was created and added to Administrators group at 02:14 UTC — outside normal business hours. Account created by SYSTEM, not a known admin.',
      status: 'OPEN',
      triageDecision: null,
      triageNotes: null,
      priority: 'P3',
      createdAt: new Date(now - 600000).toISOString(),
      updatedAt: new Date(now - 600000).toISOString(),
      closedAt: null,
      resolution: null,
      mitreMapping: [{ id: 'T1136', name: 'Create Account' }],
      timelineEvents: [{ time: new Date(now - 600000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-004',
      title: 'SQL Injection Attempts from 10.0.0.5 Using sqlmap',
      severity: 'HIGH',
      source: 'Web Access Log',
      details: 'Multiple SQL injection payloads detected from 10.0.0.5 using sqlmap/1.7. Targets include user lookup and search endpoints. Directory traversal also attempted.',
      status: 'OPEN',
      triageDecision: null,
      triageNotes: null,
      priority: 'P2',
      createdAt: new Date(now - 480000).toISOString(),
      updatedAt: new Date(now - 480000).toISOString(),
      closedAt: null,
      resolution: null,
      mitreMapping: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
      timelineEvents: [{ time: new Date(now - 480000).toISOString(), event: 'Alert created', actor: 'Jarvis' }],
    },
  ];
  fs.writeFileSync(path.join(DATA_DIR, 'alerts.json'), JSON.stringify(alerts, null, 2));
  console.log('[Seed-High] alerts.json — 1 CRITICAL, 1 HIGH, 1 MEDIUM');
}

// ---- Run ----
console.log('\n  ╔═══════════════════════════════════════╗');
console.log('  ║  Seed: HIGH RISK scenario (72-82)     ║');
console.log('  ╚═══════════════════════════════════════╝\n');

ensureDir(DATA_DIR);
ensureDir(DEMO_DIR);
seedWindowsEventsHigh();
seedAuthLogHigh();
seedAccessLogHigh();
seedSecretsHigh();
seedAlertsHigh();

// Clear action log for fresh session
const logFile = path.join(DATA_DIR, 'action-log.json');
fs.writeFileSync(logFile, '[]');
console.log('[Seed-High] action-log.json cleared');

console.log('\n[Seed-High] Done. Expected risk score: 60 (from alerts alone)');
console.log('            After parsing logs: should reach ~72-82\n');
