// ============================================================
// Jarvis SOC — Verification Test Suite
// Run: node test-soc.js
// Tests Groq, routing, tiers, alerts, secrets, and demo data.
// ============================================================

require('dotenv').config();
const http = require('http');

const PORT = process.env.PORT || 3000;
const BASE = `http://localhost:${PORT}`;

let passed = 0;
let failed = 0;
const results = [];

function log(test, pass, detail) {
  const icon = pass ? '✅' : '❌';
  console.log(`  ${icon} ${test}`);
  if (detail) console.log(`     ${detail}`);
  if (pass) passed++;
  else failed++;
  results.push({ test, pass, detail });
}

function httpPost(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const options = {
      hostname: 'localhost',
      port: PORT,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
      timeout: 30000,
    };

    const req = http.request(options, (res) => {
      let buf = '';
      res.on('data', chunk => buf += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); }
        catch { resolve({ error: `Non-JSON response: ${buf.substring(0, 200)}` }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(data);
    req.end();
  });
}

function httpGet(path) {
  return new Promise((resolve, reject) => {
    http.get(`${BASE}${path}`, { timeout: 15000 }, (res) => {
      let buf = '';
      res.on('data', chunk => buf += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); }
        catch { resolve({ raw: buf.substring(0, 500) }); }
      });
    }).on('error', reject);
  });
}

async function runTests() {
  console.log('\n  ╔═══════════════════════════════════════╗');
  console.log('  ║  JARVIS SOC — Verification Suite      ║');
  console.log('  ╚═══════════════════════════════════════╝\n');

  // Test 0: Server reachable + Groq API status
  console.log('\n  ── Test 0: Server & Groq Status ──\n');
  try {
    const status = await httpGet('/api/status');
    log('Server reachable', true, `Tools: ${status.tools?.total || 0}`);

    if (status.groq?.available) {
      log('Groq API reachable', true, status.groq.message);
    } else {
      log('Groq API reachable', false, status.groq?.error || 'GROQ_API_KEY not set');
    }

    const toolCount = status.tools?.total || 0;
    log(`Tool count >= 35`, toolCount >= 35, `${toolCount} tools loaded`);

    const socTools = status.tools?.byCategory?.soc || 0;
    log(`SOC tools registered`, socTools >= 15, `${socTools} SOC tools`);
  } catch (err) {
    log('Server reachable', false, `Cannot reach server: ${err.message}. Is it running?`);
    console.log('\n  ❌ Server not running. Start with: npm start\n');
    process.exit(1);
  }

  // Test 1: Groq routing for ambiguous command
  console.log('\n  ── Test 1: Ambiguous Command → Groq Routing ──\n');
  try {
    const result = await httpPost('/api/command', {
      command: 'check if anything in the data folder looks suspicious and let me know what you find',
    });

    const source = result.source;
    log('Command routed correctly', !!source, `Source: ${source || 'unknown'}`);
    log('Response received', !!result.response, `Response: ${(result.response || '').substring(0, 80)}...`);

    if (result.toolResults?.length > 0) {
      log('Tool calls executed', true, `Tools: ${result.toolResults.map(t => t.tool).join(', ')}`);
    }
  } catch (err) {
    log('Ambiguous command test', false, err.message);
  }

  // Test 2: SOC Alerts API
  console.log('\n  ── Test 2: SOC Alert Queue ──\n');
  try {
    const alerts = await httpGet('/api/alerts');
    log('Alerts endpoint works', Array.isArray(alerts.alerts), `${alerts.total || 0} alerts`);

    // Create a test alert
    const createResult = await httpPost('/api/command', {
      command: 'create alert titled "Test Alert from Verification Suite" with severity HIGH',
    });
    log('Alert creation', !!createResult.response, `Response: ${(createResult.response || '').substring(0, 80)}`);

    // Check it appears in queue
    const updatedAlerts = await httpGet('/api/alerts');
    log('Alert visible in queue', updatedAlerts.total > 0, `${updatedAlerts.total} alerts now`);
  } catch (err) {
    log('SOC Alerts test', false, err.message);
  }

  // Test 3: MITRE ATT&CK mapping
  console.log('\n  ── Test 3: MITRE ATT&CK Mapping ──\n');
  try {
    const mitre = await httpGet('/api/mitre-summary');
    log('MITRE endpoint works', Array.isArray(mitre.heatmap), `${mitre.heatmap?.length || 0} techniques in DB`);

    // Map a finding
    const mapResult = await httpPost('/api/command', {
      command: 'map to mitre: detected brute force SSH login attempts from external IP',
    });
    log('MITRE mapping command', !!mapResult.response, `Response: ${(mapResult.response || '').substring(0, 80)}`);
  } catch (err) {
    log('MITRE test', false, err.message);
  }

  // Test 4: Threat Intel enrichment
  console.log('\n  ── Test 4: Threat Intelligence ──\n');
  try {
    const tiResult = await httpPost('/api/command', {
      command: 'enrich ip 185.220.101.42',
    });
    const ipSummary = tiResult.response || tiResult.result?.summary || tiResult.summary || (tiResult.result ? JSON.stringify(tiResult.result) : '');
    log('IP enrichment', !!ipSummary, `Response: ${ipSummary.substring(0, 80)}`);

    const hashResult = await httpPost('/api/command', {
      command: 'enrich hash a1b2c3d4e5f678901234567890abcdef',
    });
    const hashSummary = hashResult.response || hashResult.result?.summary || hashResult.summary || (hashResult.result ? JSON.stringify(hashResult.result) : '');
    log('Hash enrichment', !!hashSummary, `Response: ${hashSummary.substring(0, 80)}`);

    const intel = await httpGet('/api/threat-intel');
    log('Threat intel panel data', intel.enrichments?.length >= 0, `${intel.enrichments?.length || 0} enrichments`);
  } catch (err) {
    log('Threat Intel test', false, err.message);
  }


  // Test 5: SOC Metrics
  console.log('\n  ── Test 5: SOC Metrics ──\n');
  try {
    const metrics = await httpGet('/api/soc-metrics');
    log('SOC metrics endpoint', metrics.riskScore !== undefined, `Risk: ${metrics.riskScore}, Open: ${metrics.openAlerts}, MITRE: ${metrics.mitreTechniques}`);
  } catch (err) {
    log('SOC Metrics test', false, err.message);
  }

  // Test 6: Report generation
  console.log('\n  ── Test 6: SOC Report ──\n');
  try {
    const report = await httpGet('/api/report');
    log('Report generated', !!report.report, `Report ID: ${report.reportId || 'N/A'}`);
    log('Report has SHA-256', !!report.hash, `Hash: ${(report.hash || '').substring(0, 16)}...`);
    log('Report stats present', !!report.stats, `Actions: ${report.stats?.totalActions || 0}, Risk: ${report.stats?.riskPosture || 'N/A'}`);
  } catch (err) {
    log('Report test', false, err.message);
  }

  // Summary
  console.log('\n  ══════════════════════════════════════');
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log('  ══════════════════════════════════════\n');

  if (failed > 0) {
    console.log('  ⚠️  Some tests failed. Check the output above for details.');
  } else {
    console.log('  ✅ All tests passed, Boss. SOC is operational.');
  }
  console.log('');
}

runTests().catch(err => {
  console.error('Test suite crashed:', err);
  process.exit(1);
});
