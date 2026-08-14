// ============================================================
// Jarvis SOC — Main Server v4.0
// Express + WebSocket. Groq LPU inference. SOC Dashboard.
// TTS Engine. n8n Workflow Automation. Background Monitoring.
// ============================================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const http = require('http');

const { router: apiRouter, setWsBroadcast } = require('./src/routes/api');
const ransomware = require('./src/tools/ransomware');

const PORT = process.env.PORT || 3000;
const app = express();
const server = http.createServer(app);

// ---- Middleware ----
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---- API Routes ----
app.use('/api', apiRouter);

// ---- SPA fallback ----
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---- WebSocket Server ----
const wss = new WebSocketServer({ server });
const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
  ws.on('error', () => clients.delete(ws));
});

function broadcast(data) {
  const message = JSON.stringify(data);
  for (const client of clients) {
    if (client.readyState === 1) { // WebSocket.OPEN
      client.send(message);
    }
  }
}

// Wire up WebSocket broadcast to API routes and ransomware alerts
setWsBroadcast(broadcast);
ransomware.setAlertCallback((alert) => {
  broadcast({ type: 'alert', ...alert });
});

// Wire up v3.0+ systems
let monitor, anomalyDetector, database, ttsEngine, n8nClient;
try { monitor = require('./src/monitor'); } catch {}
try { anomalyDetector = require('./src/anomaly-detector'); } catch {}
try { database = require('./src/database'); } catch {}
try { ttsEngine = require('./src/tts-engine'); } catch {}
try { n8nClient = require('./src/n8n-client'); } catch {}

// Make broadcast and ttsEngine available for SOC tools
module.exports.broadcast = broadcast;
module.exports.ttsEngine = ttsEngine;

// Ensure data directories exist
const dirs = ['data/watch-drop', 'data/bin', 'data/n8n/workflows'];
for (const dir of dirs) {
  const fullPath = path.join(__dirname, dir);
  if (!fs.existsSync(fullPath)) {
    fs.mkdirSync(fullPath, { recursive: true });
  }
}

// ---- Start ----
server.listen(PORT, async () => {
  const model = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
  const hasKey = !!process.env.GROQ_API_KEY;
  const toolCount = require('./src/tool-registry').getAllTools().length;

  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║         JARVIS SOC AGENT v4.0            ║');
  console.log('  ║    Security Operations Center for Ali     ║');
  console.log('  ╠══════════════════════════════════════════╣');
  console.log(`  ║  Dashboard: http://localhost:${PORT}          ║`);
  console.log(`  ║  API:       http://localhost:${PORT}/api      ║`);
  console.log(`  ║  LLM:       ${model.padEnd(28)}║`);
  console.log(`  ║  Groq:      ${(hasKey ? 'Configured ✓' : 'NO KEY — set GROQ_API_KEY').padEnd(28)}║`);
  console.log(`  ║  Tools:     ${String(toolCount).padEnd(28)}║`);
  console.log('  ╚══════════════════════════════════════════╝');

  // Start TTS engine
  if (ttsEngine) {
    try { await ttsEngine.init(broadcast); } catch (e) {
      console.error(`  [TTS] Init failed: ${e.message}`);
    }
  }

  // Start background systems
  if (anomalyDetector) {
    try { anomalyDetector.init(broadcast); } catch (e) {
      console.error(`  [Anomaly] Init failed: ${e.message}`);
    }
  }

  if (monitor) {
    try { monitor.start(broadcast); } catch (e) {
      console.error(`  [Monitor] Start failed: ${e.message}`);
    }
  }

  // Initialize n8n client
  if (n8nClient) {
    try {
      if (database) n8nClient.setSessionId(database.getSessionId());
      const connected = await n8nClient.checkConnection();
      console.log(`  [n8n] ${connected ? 'Connected ✓' : 'Offline (will retry on trigger)'}`);
    } catch (e) {
      console.log(`  [n8n] Init: ${e.message}`);
    }
  }

  // Start scheduled jobs (weekly briefing, patch check)
  try {
    const cron = require('node-cron');
    // Weekly briefing — Monday 8:00 AM
    cron.schedule('0 8 * * 1', () => {
      if (n8nClient) {
        console.log('  [Cron] Triggering weekly briefing...');
        n8nClient.triggerWorkflow('weekly_briefing', { 
          weekSummary: { timestamp: new Date().toISOString() } 
        });
      }
    });
    // Patch check — Sunday 9:00 AM
    cron.schedule('0 9 * * 0', () => {
      if (n8nClient) {
        console.log('  [Cron] Triggering patch check...');
        n8nClient.triggerWorkflow('patch_check', { 
          timestamp: new Date().toISOString() 
        });
      }
    });
    console.log('  [Cron] Scheduled: weekly briefing (Mon 8AM), patch check (Sun 9AM)');
  } catch {}

  console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n  [Jarvis] Shutting down...');
  if (monitor) try { monitor.stop(); } catch {}
  if (database) try { database.close(); } catch {}
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (monitor) try { monitor.stop(); } catch {}
  if (database) try { database.close(); } catch {}
  process.exit(0);
});

module.exports.app = app;
module.exports.server = server;
