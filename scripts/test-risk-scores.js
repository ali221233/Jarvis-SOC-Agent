require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const http = require('http');
const { spawn, execSync } = require('child_process');
const path = require('path');

async function testRisk(seedScript, label) {
  // Run seed
  execSync(`node ${seedScript}`, { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  // Start server
  const srv = spawn('node', ['server.js'], { cwd: path.join(__dirname, '..'), env: process.env, stdio: 'pipe' });

  await new Promise(r => setTimeout(r, 3000));

  return new Promise((resolve) => {
    http.get('http://localhost:3000/api/soc-metrics', (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        const data = JSON.parse(body);
        console.log(`\n${label}: riskScore = ${data.riskScore}, openAlerts = ${data.openAlerts}`);
        srv.kill();
        resolve(data.riskScore);
      });
    }).on('error', (e) => {
      console.error('Error:', e.message);
      srv.kill();
      resolve(-1);
    });
  });
}

(async () => {
  const low = await testRisk('scripts/seed-demo-low.js', 'LOW RISK');
  await new Promise(r => setTimeout(r, 2000));
  const high = await testRisk('scripts/seed-demo-high.js', 'HIGH RISK');

  console.log('\n=== RESULTS ===');
  console.log(`LOW:  ${low} (target: 35-45)`);
  console.log(`HIGH: ${high} (target: 72-82)`);
  console.log(`LOW in range:  ${low >= 35 && low <= 45 ? 'YES ✓' : 'NO ✗'}`);
  console.log(`HIGH in range: ${high >= 72 && high <= 82 ? 'YES ✓' : 'NO ✗'}`);
  process.exit(0);
})();
