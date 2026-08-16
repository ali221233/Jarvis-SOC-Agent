// ============================================================
// Jarvis SOC — API Routes
// /api/command routes through fast-path → Groq fallback → tier engine
// ============================================================

const express = require('express');
const router = express.Router();
const commandParser = require('../command-parser');
const groqClient = require('../groq-client');
const toolRegistry = require('../tool-registry');
const tierEngine = require('../tier-engine');
const keyManager = require('../key-manager');
const persona = require('../persona');
const { logAction, getHistory } = require('../logger');
const { generateReport } = require('../report-generator');
const socAlerts = require('../tools/soc-alerts');
const socMitre = require('../tools/soc-mitre');
const socThreatIntel = require('../tools/soc-threat-intel');
const cvssScorer = require('../cvss-scorer');
const n8nClient = require('../n8n-client');
const monitor = require('../monitor');


// WebSocket broadcast function — set by server.js
let wsBroadcast = () => {};
function setWsBroadcast(fn) {
  wsBroadcast = fn;
  socAlerts.setWsBroadcast(fn);
  // Wire playbooks too
  try {
    const socPlaybooks = require('../tools/soc-playbooks');
    socPlaybooks.setWsBroadcast(fn);
  } catch {}
}

// Conversation history for Groq context
let conversationHistory = [];

// ---- POST /api/command ----
// Main entry point: natural language → tool execution → response
router.post('/command', async (req, res) => {
  const { command } = req.body;
  if (!command) {
    return res.json({ error: 'No command provided.' });
  }

  // Step 1: Try fast-path pattern matching
  const parsed = commandParser.parse(command);

  if (parsed.tool && parsed.confidence >= 0.85) {
    // Fast-path: unambiguous, single-tool command — skip LLM
    const tool = toolRegistry.getTool(parsed.tool);
    if (!tool) {
      return res.json({ response: `Tool "${parsed.tool}" not found in registry.`, tier: 0 });
    }

    const result = await tierEngine.enforce(
      tool.name,
      tool.tier,
      parsed.params,
      tool.description,
      tool.execute
    );

    const formattedResponse = persona.formatToolResult(tool.name, result.result || result) || result.message;

    return res.json({
      source: 'fast-path',
      tool: tool.name,
      tier: tool.tier,
      ...result,
      response: formattedResponse || result.message,
    });
  }

  // Step 2: Route to Groq for reasoning
  wsBroadcast({ type: 'thinking', message: persona.templates.thinking() });

  const groqResult = await groqClient.chat(command, conversationHistory);

  if (groqResult.error) {
    // Groq not available — fall back to fast-path with lower confidence
    if (parsed.tool && parsed.confidence > 0.5) {
      const tool = toolRegistry.getTool(parsed.tool);
      if (tool) {
        const result = await tierEngine.enforce(tool.name, tool.tier, parsed.params, tool.description, tool.execute);
        return res.json({
          source: 'fast-path-fallback',
          tool: tool.name,
          tier: tool.tier,
          ...result,
          groqError: groqResult.error,
          response: `Groq offline — used pattern matching. ${persona.formatToolResult(tool.name, result.result || result) || ''}`,
        });
      }
    }
    return res.json({
      response: persona.templates.error(`Can't reach Groq (${groqResult.error}). Check GROQ_API_KEY in .env.`),
      error: groqResult.error,
    });
  }

  // Step 3: Handle tool calls from Groq
  if (groqResult.toolCalls && groqResult.toolCalls.length > 0) {
    const results = [];
    const messages = [
      { role: 'system', content: persona.getSystemPrompt() },
      ...conversationHistory,
      { role: 'user', content: command },
      {
        role: 'assistant',
        content: groqResult.response || null,
        tool_calls: groqResult.toolCalls.map(tc => ({
          id: tc.id,
          type: 'function',
          function: {
            name: tc.function.name,
            arguments: JSON.stringify(tc.function.arguments),
          },
        })),
      },
    ];

    for (const toolCall of groqResult.toolCalls) {
      const fn = toolCall.function;
      const tool = toolRegistry.getTool(fn.name);

      if (!tool) {
        results.push({ tool: fn.name, error: 'Tool not found in registry.' });
        messages.push({ role: 'tool', tool_call_id: toolCall.id, content: JSON.stringify({ error: 'Tool not found' }) });
        continue;
      }

      // Enforce tier regardless of who picked the tool
      const tierResult = await tierEngine.enforce(
        tool.name,
        tool.tier,
        fn.arguments || {},
        tool.description,
        tool.execute
      );

      results.push({ tool: fn.name, tier: tool.tier, ...tierResult });
      messages.push({ role: 'tool', tool_call_id: toolCall.id, content: JSON.stringify(tierResult.result || tierResult) });
    }

    // Get final response from Groq with tool results
    const finalResult = await groqClient.continueWithToolResults(messages);

    // Update conversation history
    conversationHistory.push({ role: 'user', content: command });
    conversationHistory.push({ role: 'assistant', content: finalResult.response || groqResult.response || '' });

    // Keep history manageable (last 20 messages)
    if (conversationHistory.length > 20) {
      conversationHistory = conversationHistory.slice(-20);
    }

    return res.json({
      source: 'groq',
      response: finalResult.response || groqResult.response || 'Command processed.',
      toolResults: results,
    });
  }

  // No tool calls — just a conversational response
  conversationHistory.push({ role: 'user', content: command });
  conversationHistory.push({ role: 'assistant', content: groqResult.response });

  if (conversationHistory.length > 20) {
    conversationHistory = conversationHistory.slice(-20);
  }

  return res.json({
    source: 'groq',
    response: groqResult.response,
  });
});

// ---- GET /api/tools ----
router.get('/tools', (req, res) => {
  const tools = toolRegistry.getAllTools().map(t => ({
    name: t.name,
    description: t.description,
    tier: t.tier,
    category: t.category,
  }));
  res.json({ tools });
});

// ---- POST /api/tools/:name/execute ----
router.post('/tools/:name/execute', async (req, res) => {
  const tool = toolRegistry.getTool(req.params.name);
  if (!tool) {
    return res.status(404).json({ error: `Tool "${req.params.name}" not found.` });
  }

  const result = await tierEngine.enforce(
    tool.name,
    tool.tier,
    req.body,
    tool.description,
    tool.execute
  );

  res.json({ tool: tool.name, tier: tool.tier, ...result });
});

// ---- POST /api/confirm/:actionId ----
router.post('/confirm/:actionId', async (req, res) => {
  const { passphrase } = req.body;
  let passphraseVerified = false;

  if (passphrase) {
    const verification = await keyManager.verifyPassphrase(passphrase);
    passphraseVerified = verification.verified;
    if (!passphraseVerified) {
      return res.json({ error: 'Incorrect passphrase.', status: 'passphrase_failed' });
    }
  }

  const result = await tierEngine.confirm(req.params.actionId, passphraseVerified);
  res.json(result);
});

// ---- GET /api/pending ----
router.get('/pending', (req, res) => {
  res.json({ pending: tierEngine.getPendingActions() });
});

// ---- DELETE /api/pending/:actionId ----
router.delete('/pending/:actionId', (req, res) => {
  const result = tierEngine.cancelAction(req.params.actionId);
  res.json(result);
});

// ---- GET /api/history ----
router.get('/history', (req, res) => {
  const { tier, tool, status, since, limit } = req.query;
  const filter = {};
  if (tier) filter.tier = parseInt(tier);
  if (tool) filter.tool = tool;
  if (status) filter.status = status;
  if (since) filter.since = since;
  if (limit) filter.limit = parseInt(limit);

  res.json({ history: getHistory(filter) });
});

// ---- GET /api/report ----
router.get('/report', (req, res) => {
  const result = generateReport(req.query.sessionId);
  res.json(result);
});

// ---- GET /api/status ----
router.get('/status', async (req, res) => {
  const groqHealth = await groqClient.checkHealth();
  const tools = toolRegistry.getAllTools();
  let ntfyStatus = { configured: false };
  let notifierStatus = { email: 'not configured', slack: 'not configured' };
  let monitorStatus = { active: false, watchers: {} };
  let n8nStatus = { connected: false };

  try {
    const ntfy = require('../ntfy-notifier');
    ntfyStatus = { configured: ntfy.ntfyConfigured, ...ntfy.getStatus() };
  } catch {}

  try {
    const notif = require('../notifier');
    notifierStatus = notif.getStatus();
  } catch {}

  try {
    const mon = require('../monitor');
    monitorStatus = mon.getStatus();
  } catch {}

  try {
    const n8n = require('../n8n-client');
    n8nStatus = n8n.getStatus();
  } catch {}

  res.json({
    greeting: persona.getGreeting(),
    user: persona.USER_NAME,
    time: new Date().toISOString(),
    groq: groqHealth,
    keyManager: {
      initialized: keyManager.isInitialized(),
      sessionActive: keyManager.hasSessionKey(),
    },
    tools: {
      total: tools.length,
      byCategory: tools.reduce((acc, t) => {
        acc[t.category] = (acc[t.category] || 0) + 1;
        return acc;
      }, {}),
    },
    pending: tierEngine.getPendingActions().length,
    ntfy: ntfyStatus,
    email: { configured: notifierStatus.email === 'configured', status: notifierStatus.email },
    slack: { configured: notifierStatus.slack === 'configured', status: notifierStatus.slack },
    monitoring: monitorStatus,
    n8n: n8nStatus,
  });
});


// ============================================================
// SOC-SPECIFIC ENDPOINTS
// ============================================================

// ---- GET /api/alerts ----
router.get('/alerts', (req, res) => {
  const open = req.query.status === 'all' ? socAlerts.getAllAlerts() : socAlerts.getOpenAlerts();
  res.json({
    alerts: open,
    total: open.length,
  });
});

// ---- GET /api/alerts/:id ----
router.get('/alerts/:id', (req, res) => {
  const alert = socAlerts.getAlertById(req.params.id);
  if (!alert) return res.status(404).json({ error: 'Alert not found.' });
  res.json(alert);
});

// ---- GET /api/mitre-summary ----
router.get('/mitre-summary', (req, res) => {
  res.json({
    heatmap: socMitre.getHeatmapData(),
    sessionHits: socMitre.getSessionHits(),
  });
});

// ---- GET /api/threat-intel ----
router.get('/threat-intel', (req, res) => {
  res.json({
    enrichments: socThreatIntel.getEnrichmentHistory(),
  });
});

// ---- GET /api/soc-metrics ----
router.get('/soc-metrics', async (req, res) => {
  const openAlerts = socAlerts.getOpenAlerts();
  const closedToday = socAlerts.getClosedAlerts().filter(a => {
    const closed = new Date(a.closedAt);
    const today = new Date();
    return closed.toDateString() === today.toDateString();
  });
  const mitreSummary = await socMitre.getAttackSummary();

  // Calculate risk score — CVSS v3.1 based scoring
  const { riskScore } = cvssScorer.calculateRiskFromAlerts(openAlerts);

  res.json({
    openAlerts: openAlerts.length,
    resolvedToday: closedToday.length,
    mitreTechniques: mitreSummary.totalTechniques,
    riskScore,
  });
});

// ---- POST /api/passphrase/init ----
router.post('/passphrase/init', async (req, res) => {
  const { passphrase } = req.body;
  if (!passphrase || passphrase.length < 8) {
    return res.json({ error: 'Passphrase must be at least 8 characters.' });
  }

  if (keyManager.isInitialized()) {
    return res.json({ error: 'Key manager already initialized. Use /api/passphrase/verify to unlock.' });
  }

  const result = await keyManager.initialize(passphrase);
  logAction('Master passphrase initialized', 2, { tool: 'key_manager', status: 'completed' });
  res.json({ ...result, message: `Vault initialized with ${result.method}. Session key active.` });
});

// ---- POST /api/passphrase/verify ----
router.post('/passphrase/verify', async (req, res) => {
  const { passphrase } = req.body;
  if (!passphrase) {
    return res.json({ error: 'Passphrase required.' });
  }

  const result = await keyManager.verifyPassphrase(passphrase);
  if (result.verified) {
    logAction('Passphrase verified — session unlocked', 2, { tool: 'key_manager', status: 'completed' });
  }
  res.json(result);
});

// ============================================================
// v3.0 API ENDPOINTS
// ============================================================

// ---- GET /api/monitor-status ----
router.get('/monitor-status', (req, res) => {
  try {
    const monitor = require('../monitor');
    res.json(monitor.getStatus());
  } catch {
    res.json({ error: 'Background monitor not available' });
  }
});

// ---- GET /api/anomaly-status ----
router.get('/anomaly-status', (req, res) => {
  try {
    const anomalyDetector = require('../anomaly-detector');
    const status = anomalyDetector.getStatus();
    const anomalies = anomalyDetector.runAnomalyCheck();
    res.json({ ...status, recentAnomalies: anomalies });
  } catch {
    res.json({ error: 'Anomaly detector not available' });
  }
});

// ---- GET /api/notification-status ----
router.get('/notification-status', (req, res) => {
  const status = {};
  try { Object.assign(status, require('../notifier').getStatus()); } catch {}
  try { Object.assign(status, require('../ntfy-notifier').getStatus()); } catch {}
  res.json(status);
});

// ---- GET /api/session-history ----
router.get('/session-history', (req, res) => {
  try {
    const db = require('../database');
    const limit = parseInt(req.query.limit) || 10;
    res.json({ sessions: db.getSessionHistory(limit) });
  } catch {
    res.json({ sessions: [] });
  }
});

// ---- POST /api/pdf-report ----
router.post('/pdf-report', async (req, res) => {
  try {
    const pdfGen = require('../pdf-report-generator');
    const result = await pdfGen.generatePdfReport(req.body.sessionId);
    res.json(result);
  } catch (err) {
    res.json({ error: `PDF generation failed: ${err.message}` });
  }
});

// ============================================================
// v4.0 API ENDPOINTS — n8n + TTS
// ============================================================

// ---- GET /api/n8n/status ----
router.get('/n8n/status', async (req, res) => {
  try {
    const n8nClient = require('../n8n-client');
    const status = await n8nClient.getStatus();
    res.json(status);
  } catch {
    res.json({ enabled: false, connected: false, error: 'n8n client not available' });
  }
});

// ---- GET /api/n8n/summary ----
router.get('/n8n/summary', async (req, res) => {
  try {
    const n8nClient = require('../n8n-client');
    const db = require('../database');
    const monitor = require('../monitor');
    const riskScore = cvssScorer.calculateRiskScore(socAlerts.getFindings());
    const mitreTechs = socMitre.getSessionTechniques();
    const alertMetrics = socAlerts.getMetrics();
    
    res.json({
      session: {
        id: db.getSessionId(),
        startedAt: db.getSessionStart(),
        duration: db.getSessionDuration(),
      },
      risk: { score: riskScore, cvssMethodology: true },
      alerts: {
        open: alertMetrics.open,
        critical: alertMetrics.critical || 0,
        high: alertMetrics.high || 0,
        medium: alertMetrics.medium || 0,
        low: alertMetrics.low || 0,
        resolvedToday: alertMetrics.resolvedToday || 0,
      },
      mitre: { techniques: mitreTechs },
      background: {
        watchersActive: Object.keys(monitor.getStatus().watchers || {}).length,
        findingsThisSession: monitor.getStatus().totalFindings || 0,
      },
      ...n8nClient.getSummary(),
    });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// ---- GET /api/tts-status ----
router.get('/tts-status', (req, res) => {
  try {
    const ttsEngine = require('../tts-engine');
    res.json(ttsEngine.getStatus());
  } catch {
    res.json({ engine: 'none', ready: false });
  }
});

// ---- GET /api/n8n/status ----
router.get('/n8n/status', async (req, res) => {
  try {
    const status = await n8nClient.getStatus();
    res.json(status);
  } catch (err) {
    res.json({ enabled: false, connected: false, error: err.message });
  }
});

// ---- POST /api/n8n/trigger/:name ----
router.post('/n8n/trigger/:name', async (req, res) => {
  const workflowName = req.params.name;
  let payload = req.body && Object.keys(req.body).length > 0 ? req.body : {};

  // Sensible default payload for test trigger
  if (Object.keys(payload).length === 0) {
    if (workflowName === 'critical_alert') {
      payload = { incidentId: 'INC-' + Date.now().toString(36), title: 'Test Ransomware Activity Detected', severity: 'CRITICAL', cvssScore: 9.2, source: 'Jarvis SOC Sensor' };
    } else if (workflowName === 'incident_response') {
      payload = { playbookName: 'brute_force', stepsCompleted: 5, riskScoreBefore: 88, riskScoreAfter: 15, status: 'CONTAINED' };
    } else if (workflowName === 'file_drop') {
      payload = { filePath: 'data/watch-drop/invoice_payload.exe', fileName: 'invoice_payload.exe', fileSize: 24576, fileExtension: '.exe' };
    } else if (workflowName === 'weekly_briefing') {
      payload = { title: 'Executive SOC Weekly Briefing', totalAlerts: 18, resolvedToday: 6, riskPosture: 'GOOD' };
    } else if (workflowName === 'threat_intel_hit') {
      payload = { indicator: '185.220.101.42', indicatorType: 'IP', compositeScore: 95, sources: ['AbuseIPDB', 'AlienVault OTX'] };
    } else if (workflowName === 'canary_triggered') {
      payload = { triggeredPath: 'canary_trap.docx', pid: 4892, fileChangeCount: 8 };
    } else if (workflowName === 'report_generated') {
      payload = { reportPath: 'data/reports/soc-report.md', riskScore: 12, openIncidents: 0, resolvedIncidents: 6 };
    } else if (workflowName === 'daily_patch_audit') {
      payload = { missingPatches: 2, totalScanned: 68, riskLevel: 'LOW' };
    }
  }

  const result = await n8nClient.triggerWorkflow(workflowName, payload);

  if (typeof wsBroadcast === 'function') {
    wsBroadcast({
      type: 'n8n_event',
      workflowName,
      status: result.status || (result.triggered ? 200 : 'ERROR'),
      payload,
      timestamp: new Date().toISOString(),
    });
  }

  res.json({
    workflowName,
    url: `${process.env.N8N_WEBHOOK_BASE || 'http://localhost:5678/webhook'}/${workflowName}`,
    payload,
    ...result,
  });
});

// ---- GET /api/monitor/status ----
router.get('/monitor/status', (req, res) => {

  try {
    res.json(monitor.getStatus());
  } catch (err) {
    res.json({ active: false, watchers: {}, error: err.message });
  }
});

module.exports = { router, setWsBroadcast };


