// Test 5: Secret leakage check
const http = require('http');
const fs = require('fs');
const path = require('path');

function post(p, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: 'localhost', port: 3000, path: p, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => resolve(JSON.parse(buf)));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}
function get(p) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${p}`, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => resolve(JSON.parse(buf)));
    }).on('error', reject);
  });
}

(async () => {
  console.log('═══════════════════════════════════════════════════');
  console.log('TEST 5: Secret leakage in action log and report');
  console.log('═══════════════════════════════════════════════════\n');

  // Create file with fake secrets
  const mockStripe = ['sk', 'live', '1234567890abcdefghij1234'].join('_');
  const mockGh = ['ghp', '1234567890abcdefghijklmnopqrstuvwxyz'].join('_');
  const secretFile = path.join(__dirname, 'test-secrets.js');
  fs.writeFileSync(secretFile, `
    const API_KEY = "AKIAIOSFODNN7EXAMPLE";
    const secret = "${mockStripe}";
    const password = "SuperSecret123!@#";
    const db = "mongodb://admin:password123@10.0.0.1:27017/mydb";
    const ghToken = "${mockGh}";
  `);

  console.log('Step 1: Scan file containing fake secrets');
  const scanResult = await post('/api/tools/scan_secrets/execute', { path: secretFile });
  console.log('  Findings count:', scanResult.result?.findings?.length || 0);
  for (const f of (scanResult.result?.findings || [])) {
    console.log(`  - [${f.severity}] ${f.pattern} at line ${f.line}`);
    console.log(`    Preview: "${f.preview}"`);
  }
  console.log('');

  // Check action log
  console.log('Step 2: Check action log for plaintext secrets');
  const logFile = path.join(__dirname, 'data', 'action-log.json');
  if (fs.existsSync(logFile)) {
    const logContent = fs.readFileSync(logFile, 'utf-8');

    const secrets = [
      { name: 'AWS Access Key', pattern: 'AKIAIOSFODNN7EXAMPLE' },
      { name: 'Stripe Key', pattern: '1234567890abcdefghij1234' },
      { name: 'GitHub Token', pattern: '1234567890abcdefghij' },
      { name: 'Password value', pattern: 'SuperSecret123' },
      { name: 'MongoDB password', pattern: 'password123@' },
    ];

    let anyLeak = false;
    for (const s of secrets) {
      if (logContent.includes(s.pattern)) {
        console.log(`  ✗ LEAK DETECTED: ${s.name} found unmasked in action-log.json!`);
        anyLeak = true;
      } else {
        console.log(`  ✓ ${s.name}: Properly masked (not found in log)`);
      }
    }

    if (!anyLeak) {
      console.log('\n  PASS: No secrets leaked to action-log.json');
    } else {
      console.log('\n  FAIL: One or more secrets leaked to action-log.json!');
    }
  } else {
    console.log('  Log file not found');
  }
  console.log('');

  // Check report
  console.log('Step 3: Check report for plaintext secrets');
  const report = await get('/api/report');
  const reportContent = report.report || '';
  const reportHasAWS = reportContent.includes('AKIAIOSFODNN7EXAMPLE');
  const reportHasStripe = reportContent.includes('1234567890abcdefghij1234');
  console.log('  Report contains AWS key:', reportHasAWS);
  console.log('  Report contains Stripe key:', reportHasStripe);
  console.log('');

  // Cleanup
  try { fs.unlinkSync(secretFile); } catch {}


  console.log('═══════════════════════════════════════════════════');
  console.log('TEST 5 COMPLETE');
  console.log('═══════════════════════════════════════════════════');
})();
