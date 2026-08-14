// Tests 0 and 1: Ollama verification + ambiguous command routing
const http = require('http');

function post(p, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: 'localhost', port: 3000, path: p, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: 120000, // 2 min for CPU inference
    }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve({ raw: buf }); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout — Ollama may be overloaded')); });
    req.write(data);
    req.end();
  });
}

function get(p) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3000${p}`, { timeout: 10000 }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve({ raw: buf }); } });
    }).on('error', reject);
  });
}

function ollamaGet(p) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:11434${p}`, { timeout: 5000 }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch { resolve({ raw: buf }); } });
    }).on('error', reject);
  });
}

(async () => {
  console.log('═══════════════════════════════════════════════════');
  console.log('TEST 0: Ollama installation and model availability');
  console.log('═══════════════════════════════════════════════════\n');

  // Direct query to Ollama
  console.log('Step 1: Direct query to Ollama at localhost:11434/api/tags');
  try {
    const tags = await ollamaGet('/api/tags');
    console.log('  Ollama reachable: true');
    console.log('  Models:', JSON.stringify(tags.models?.map(m => m.name || m.model), null, 2));

    const hasModel = (tags.models || []).some(m => (m.name || m.model || '').includes('llama3.2'));
    console.log('  llama3.2 available:', hasModel);
    if (!hasModel) {
      console.log('  >> Need to pull model first: ollama pull llama3.2:3b');
      console.log('  >> Skipping Test 1 — model not available.');
      return;
    }
  } catch (err) {
    console.log('  Ollama reachable: false');
    console.log('  Error:', err.message);
    console.log('  >> Ollama is not running. Start it with: ollama serve');
    console.log('  >> Skipping Test 1.');
    return;
  }

  // Via Jarvis /api/status
  console.log('\nStep 2: Jarvis /api/status → Ollama health');
  const status = await get('/api/status');
  console.log('  Ollama available:', status.ollama?.available);
  console.log('  Model available:', status.ollama?.modelAvailable);
  console.log('  Model:', status.ollama?.model);
  console.log('  Message:', status.ollama?.message);
  console.log('');

  console.log('═══════════════════════════════════════════════════');
  console.log('TEST 1: Ambiguous command → Ollama routing');
  console.log('═══════════════════════════════════════════════════\n');

  // First verify fast-path DOES NOT match this
  console.log('Step 1: Verify command-parser does NOT match ambiguous command');
  const parser = require('./src/command-parser');
  const parsed = parser.parse('check if anything in my downloads is sensitive and lock it down if so');
  console.log('  Parser result:', JSON.stringify(parsed, null, 2));
  console.log('  Tool matched:', parsed.tool || 'NONE');
  console.log('  Confidence:', parsed.confidence);
  console.log('  >> Should route to Ollama because confidence < 0.85 or no tool matched.');
  console.log('');

  // Send to Jarvis API
  console.log('Step 2: Send ambiguous command to /api/command');
  console.log('  Command: "check if anything in my downloads is sensitive and lock it down if so"');
  console.log('  (This is a multi-step, ambiguous command — should route to Ollama)');
  console.log('  Waiting for Ollama response (CPU inference, may take 30-120s)...\n');

  const startTime = Date.now();
  const result = await post('/api/command', {
    command: 'check if anything in my downloads is sensitive and lock it down if so'
  });
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log(`  Response received in ${elapsed}s`);
  console.log('  Source:', result.source);
  console.log('  Response:', result.response?.substring(0, 300));
  console.log('');

  if (result.toolResults) {
    console.log('  Tool calls Ollama selected:');
    for (const tr of result.toolResults) {
      console.log(`    - ${tr.tool} (Tier ${tr.tier}) — Status: ${tr.status}`);
      if (tr.result?.summary) console.log(`      Summary: ${tr.result.summary}`);
    }
  } else if (result.tool) {
    console.log('  Tool selected:', result.tool);
    console.log('  Tier:', result.tier);
  }

  if (result.ollamaError) {
    console.log('  Ollama error:', result.ollamaError);
  }

  console.log('\n  Full response object:');
  console.log(JSON.stringify(result, null, 2).substring(0, 1000));

  console.log('\n═══════════════════════════════════════════════════');
  console.log('TESTS 0+1 COMPLETE');
  console.log('═══════════════════════════════════════════════════');
})();
