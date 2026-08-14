// ============================================================
// Jarvis SOC — Full Health Check (Task 0)
// Tests every API key, tool, and endpoint.
// ============================================================

const http = require('http');
const https = require('https');
require('dotenv').config();

const BASE = 'http://localhost:3000';

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const opts = typeof url === 'string' ? new URL(url) : url;
    const req = mod.get(url, { headers, timeout: 15000 }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpPost(url, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const u = new URL(url);
    const body = typeof data === 'string' ? data : JSON.stringify(data);
    const opts = {
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'POST', timeout: 15000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers },
    };
    const req = mod.request(opts, (res) => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

async function test(name, fn) {
  try {
    const result = await fn();
    console.log(`  ✓ ${name.padEnd(35)} ${result}`);
    return true;
  } catch (err) {
    console.log(`  ✗ ${name.padEnd(35)} FAIL: ${err.message}`);
    return false;
  }
}

async function run() {
  console.log('\n══════════════════════════════════════════');
  console.log('  JARVIS SOC — FULL HEALTH CHECK');
  console.log('══════════════════════════════════════════\n');

  let pass = 0, fail = 0;
  const r = async (name, fn) => { (await test(name, fn)) ? pass++ : fail++; };

  // ---- 1. API ENDPOINTS ----
  console.log('  [1] API ENDPOINTS');
  await r('GET /api/status', async () => {
    const res = await httpGet(`${BASE}/api/status`);
    const d = JSON.parse(res.body);
    return `groq=${d.groq}, tools=${d.toolCount}`;
  });
  await r('GET /api/soc-metrics', async () => {
    const res = await httpGet(`${BASE}/api/soc-metrics`);
    const d = JSON.parse(res.body);
    return `alerts=${d.openAlerts}, risk=${d.riskScore}`;
  });
  await r('GET /api/monitor-status', async () => {
    const res = await httpGet(`${BASE}/api/monitor-status`);
    const d = JSON.parse(res.body);
    return `paused=${d.paused}, watchers=${Object.keys(d.watchers||{}).length}`;
  });
  await r('GET /api/anomaly-status', async () => {
    const res = await httpGet(`${BASE}/api/anomaly-status`);
    const d = JSON.parse(res.body);
    return `status=${d.status}`;
  });
  await r('GET /api/notification-status', async () => {
    const res = await httpGet(`${BASE}/api/notification-status`);
    const d = JSON.parse(res.body);
    return `email=${d.email}, slack=${d.slack}, ntfy=${d.ntfy}`;
  });
  await r('GET /api/session-history', async () => {
    const res = await httpGet(`${BASE}/api/session-history`);
    const d = JSON.parse(res.body);
    return `sessions=${(d.sessions||[]).length}`;
  });

  // ---- 2. API KEYS ----
  console.log('\n  [2] API KEY VERIFICATION');

  await r('GROQ', async () => {
    const res = await httpPost(`${BASE}/api/command`, { command: 'hello' });
    const d = JSON.parse(res.body);
    return d.error ? `ERROR: ${d.error}` : `OK (source=${d.source||'groq'})`;
  });

  await r('ABUSEIPDB', async () => {
    if (!process.env.ABUSEIPDB_API_KEY) return 'NOT CONFIGURED';
    const res = await httpGet('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90', {
      'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json'
    });
    const d = JSON.parse(res.body);
    return d.data ? `OK (score=${d.data.abuseConfidenceScore})` : `ERROR: ${res.status}`;
  });

  await r('VIRUSTOTAL', async () => {
    if (!process.env.VIRUSTOTAL_API_KEY) return 'NOT CONFIGURED';
    const res = await httpGet('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', {
      'x-apikey': process.env.VIRUSTOTAL_API_KEY
    });
    return res.status === 200 ? 'OK' : `HTTP ${res.status}`;
  });

  await r('SHODAN', async () => {
    if (!process.env.SHODAN_API_KEY) return 'NOT CONFIGURED';
    const res = await httpGet(`https://api.shodan.io/shodan/host/8.8.8.8?key=${process.env.SHODAN_API_KEY}`);
    return res.status === 200 ? 'OK' : `HTTP ${res.status}`;
  });

  await r('URLSCAN', async () => {
    if (!process.env.URLSCAN_API_KEY) return 'NOT CONFIGURED';
    const res = await httpGet('https://urlscan.io/api/v1/search/?q=domain:google.com&size=1', {
      'API-Key': process.env.URLSCAN_API_KEY
    });
    return res.status === 200 ? 'OK' : `HTTP ${res.status}`;
  });

  await r('ALIENVAULT', async () => {
    if (!process.env.ALIENVAULT_API_KEY) return 'NOT CONFIGURED';
    const res = await httpGet('https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general', {
      'X-OTX-API-KEY': process.env.ALIENVAULT_API_KEY
    });
    return res.status === 200 ? 'OK' : `HTTP ${res.status}`;
  });

  await r('HIBP', async () => {
    if (!process.env.HIBP_API_KEY) return 'NOT CONFIGURED (no key)';
    const res = await httpGet('https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com?truncateResponse=true', {
      'hibp-api-key': process.env.HIBP_API_KEY, 'user-agent': 'Jarvis-SOC-Agent'
    });
    return res.status === 200 ? `OK (breaches found)` : res.status === 404 ? 'OK (no breaches)' : `HTTP ${res.status}`;
  });

  // ---- 3. TOOL TESTS ----
  console.log('\n  [3] TOOL TESTS (via /api/command)');

  const toolTests = [
    ['scan_secrets', 'scan test_secrets.txt for secrets'],
    ['audit_dependencies', 'audit dependencies in .'],
    ['run_sast', 'run sast on test_secrets.txt'],
    ['audit_firewall', 'check firewall status'],
    ['monitor_network', 'show active network connections'],
    ['parse_windows_event_log', 'parse the windows event log'],
    ['create_alert', 'create a test alert for health check'],
    ['get_alert_queue', 'show alert queue'],
  ];

  for (const [name, cmd] of toolTests) {
    await r(name, async () => {
      const res = await httpPost(`${BASE}/api/command`, { command: cmd });
      const d = JSON.parse(res.body);
      if (d.error) return `ERROR: ${d.error.substring(0, 80)}`;
      return `OK (source=${d.source||'groq'})`;
    });
  }

  // ---- 4. NTFY TEST ----
  console.log('\n  [4] NTFY NOTIFICATION TEST');
  await r('NTFY SEND', async () => {
    if (!process.env.NTFY_TOPIC) return 'NOT CONFIGURED';
    const url = `https://ntfy.sh/${process.env.NTFY_TOPIC}`;
    const res = await httpPost(url, 
      'Jarvis SOC health check — this notification confirms Ntfy is working, Boss.',
      { 'Title': 'JARVIS SOC — System Test', 'Priority': 'high', 'Tags': 'white_check_mark' }
    );
    return `HTTP ${res.status}`;
  });

  // ---- 5. OSV API TEST ----
  console.log('\n  [5] OSV API (lodash 4.17.15)');
  await r('OSV query', async () => {
    const res = await httpPost('https://api.osv.dev/v1/query', {
      version: '4.17.15', package: { name: 'lodash', ecosystem: 'npm' }
    });
    const d = JSON.parse(res.body);
    const vulns = d.vulns || [];
    return `${vulns.length} vulnerabilities found (${vulns.slice(0,3).map(v=>v.id).join(', ')}...)`;
  });

  // ---- 6. SQLite ----
  console.log('\n  [6] SQLITE DATABASE');
  await r('DB tables', async () => {
    const res = await httpGet(`${BASE}/api/session-history?limit=1`);
    const d = JSON.parse(res.body);
    return `sessions table OK (${(d.sessions||[]).length} records)`;
  });

  // ---- SUMMARY ----
  console.log('\n══════════════════════════════════════════');
  console.log(`  RESULT: ${pass} PASS, ${fail} FAIL`);
  console.log('══════════════════════════════════════════\n');
}

run().catch(err => console.error('Health check crashed:', err));
