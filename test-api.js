// Quick API test
const http = require('http');

function post(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: 'localhost', port: 3000, path, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length },
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

function get(path) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${path}`, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => resolve(JSON.parse(buf)));
    }).on('error', reject);
  });
}

(async () => {
  console.log('=== JARVIS API TESTS ===\n');

  // 1. Status
  console.log('1. GET /api/status');
  const status = await get('/api/status');
  console.log(`   Greeting: ${status.greeting}`);
  console.log(`   Tools: ${status.tools?.total || Object.keys(status.tools || {}).length}`);
  console.log(`   LLM: ${status.groq?.available ? 'Groq Online' : status.ollama?.available ? 'Ollama Online' : 'Offline'}`);
  console.log(`   Vault: ${status.keyManager?.initialized ? 'Initialized' : 'Not set up'}\n`);

  // 2. Tools list
  console.log('2. GET /api/tools');
  const tools = await get('/api/tools');
  console.log(`   ${tools.tools.length} tools registered\n`);

  // 3. Fast-path scan secrets with dot
  console.log('3. POST /api/command — "scan secrets in ."');
  const scan = await post('/api/command', { command: 'scan secrets in .' });
  console.log(`   Source: ${scan.source}`);
  console.log(`   Tool: ${scan.tool}`);
  console.log(`   Status: ${scan.status}`);
  if (scan.result) console.log(`   Summary: ${scan.result.summary}`);
  console.log('');

  // 4. Fast-path firewall
  console.log('4. POST /api/command — "check firewall"');
  const fw = await post('/api/command', { command: 'check firewall' });
  console.log(`   Source: ${fw.source}`);
  console.log(`   Tool: ${fw.tool}`);
  console.log(`   Status: ${fw.status}`);
  console.log('');

  // 5. Network monitor
  console.log('5. POST /api/command — "monitor network"');
  const net = await post('/api/command', { command: 'monitor network' });
  console.log(`   Source: ${net.source}`);
  console.log(`   Tool: ${net.tool}`);
  if (net.result) console.log(`   Summary: ${net.result.summary}`);
  console.log('');

  // 6. Fast-path IP enrichment
  console.log('6. POST /api/command — "enrich ip 8.8.8.8"');
  const ipRes = await post('/api/command', { command: 'enrich ip 8.8.8.8' });
  console.log(`   Source: ${ipRes.source}`);
  console.log(`   Tool: ${ipRes.tool}`);
  if (ipRes.result) console.log(`   Summary: ${ipRes.result.summary}`);
  console.log('');

  // 7. TTS Status
  console.log('7. GET /api/tts-status');
  const ttsStatus = await get('/api/tts-status');
  console.log(`   Engine: ${ttsStatus.engine}, Ready: ${ttsStatus.ready}\n`);

  // 8. Monitor Status
  console.log('8. GET /api/monitor/status');
  const monStatus = await get('/api/monitor/status');
  console.log(`   Active: ${monStatus.active}, Watchers: ${Object.keys(monStatus.watchers || {}).length}\n`);

  // 9. N8N Status
  console.log('9. GET /api/n8n/status');
  const n8nStatus = await get('/api/n8n/status');
  console.log(`   Connected: ${n8nStatus.connected}, Triggers: ${n8nStatus.workflowsTriggered}\n`);

  // 10. History
  console.log('10. GET /api/history');
  const hist = await get('/api/history');
  console.log(`   ${hist.history.length} logged actions\n`);

  // 11. Report
  console.log('11. GET /api/report');
  const report = await get('/api/report');
  console.log(`   Risk Posture: ${report.stats.riskPosture}`);
  console.log(`   Hash: ${report.hash ? report.hash.substring(0, 16) + '...' : 'N/A'}`);
  console.log(`   Total Actions: ${report.stats.totalActions}\n`);

  console.log('=== ALL TESTS PASSED ===');
})();

