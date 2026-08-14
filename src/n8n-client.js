// ============================================================
// Jarvis SOC — n8n Workflow Automation Client
// Outbound webhook calls from Jarvis → n8n.
// ============================================================

const fetch = require('node-fetch');

const N8N_WEBHOOK_BASE = process.env.N8N_WEBHOOK_BASE || 'http://localhost:5678/webhook';
const N8N_ENABLED = (process.env.N8N_ENABLED || 'true').toLowerCase() === 'true';

let workflowsTriggered = 0;
let lastTrigger = null;
const recentTriggers = [];
let sessionId = null;

function setSessionId(id) {
  sessionId = id;
}

/**
 * Trigger an n8n workflow via webhook.
 * Never crashes Jarvis — all errors are caught silently.
 */
async function triggerWorkflow(workflowName, payload = {}) {
  if (!N8N_ENABLED) return { skipped: true, reason: 'n8n disabled' };
  
  const url = `${N8N_WEBHOOK_BASE}/${workflowName}`;
  const body = {
    source: 'jarvis',
    timestamp: new Date().toISOString(),
    sessionId: sessionId,
    ...payload,
  };
  
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      timeout: 5000,
    });
    
    const status = res.status;
    workflowsTriggered++;
    
    const triggerRecord = {
      workflowName,
      timestamp: new Date().toISOString(),
      status: status >= 200 && status < 300 ? 'SUCCESS' : `HTTP ${status}`,
    };
    lastTrigger = triggerRecord;
    recentTriggers.unshift(triggerRecord);
    if (recentTriggers.length > 10) recentTriggers.pop();
    
    console.log(`  [n8n] Triggered: ${workflowName} → HTTP ${status}`);
    return { triggered: true, status, workflowName };
  } catch (err) {
    const triggerRecord = {
      workflowName,
      timestamp: new Date().toISOString(),
      status: `FAILED: ${err.message}`,
    };
    lastTrigger = triggerRecord;
    recentTriggers.unshift(triggerRecord);
    if (recentTriggers.length > 10) recentTriggers.pop();
    
    // Silent failure — never crash Jarvis
    console.log(`  [n8n] Trigger failed (${workflowName}): ${err.message}`);
    return { triggered: false, error: err.message };
  }
}

/**
 * Check if n8n is reachable.
 */
async function checkConnection() {
  try {
    const res = await fetch(`${N8N_WEBHOOK_BASE.replace('/webhook', '')}/healthz`, {
      timeout: 3000,
    });
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * Get n8n status for the dashboard.
 */
async function getStatus() {
  const connected = await checkConnection();
  return {
    enabled: N8N_ENABLED,
    baseUrl: N8N_WEBHOOK_BASE.replace('/webhook', ''),
    connected,
    workflowsTriggered,
    lastTrigger,
    recentTriggers: recentTriggers.slice(0, 5),
  };
}

/**
 * Get comprehensive summary for n8n workflows.
 */
function getSummary() {
  return {
    n8n: {
      workflowsTriggered,
      lastTrigger: lastTrigger ? lastTrigger.workflowName : null,
      enabled: N8N_ENABLED,
    },
  };
}

// ---- Pre-built trigger helpers ----

async function triggerCriticalAlert(alert) {
  return triggerWorkflow('critical_alert', {
    incidentId: alert.id,
    title: alert.title,
    severity: alert.severity,
    cvssScore: alert.cvssScore || null,
    mitreTech: alert.mitreTechnique || null,
    details: alert.details,
    source: alert.source || 'jarvis',
  });
}

async function triggerIncidentResponse(playbookResult) {
  return triggerWorkflow('incident_response', {
    playbookName: playbookResult.playbookName,
    incidentId: playbookResult.incidentId,
    stepsCompleted: playbookResult.stepsCompleted,
    findings: playbookResult.findings,
    riskScoreBefore: playbookResult.riskScoreBefore,
    riskScoreAfter: playbookResult.riskScoreAfter,
  });
}

async function triggerFileDrop(fileInfo) {
  return triggerWorkflow('file_drop', {
    filePath: fileInfo.filePath,
    fileName: fileInfo.fileName,
    fileSize: fileInfo.fileSize,
    fileExtension: fileInfo.fileExtension,
  });
}

async function triggerThreatIntelHit(enrichment) {
  return triggerWorkflow('threat_intel_hit', {
    indicator: enrichment.indicator,
    indicatorType: enrichment.indicatorType,
    compositeScore: enrichment.compositeScore,
    sources: enrichment.sources,
    details: enrichment.details,
    autoCreatedAlert: enrichment.autoCreatedAlert || false,
  });
}

async function triggerCanary(canaryInfo) {
  return triggerWorkflow('canary_triggered', {
    triggeredPath: canaryInfo.triggeredPath,
    pid: canaryInfo.pid,
    fileChangeCount: canaryInfo.fileChangeCount,
  });
}

async function triggerReportGenerated(reportInfo) {
  return triggerWorkflow('report_generated', {
    reportPath: reportInfo.reportPath,
    pdfPath: reportInfo.pdfPath,
    reportHash: reportInfo.reportHash,
    riskScore: reportInfo.riskScore,
    openIncidents: reportInfo.openIncidents,
    resolvedIncidents: reportInfo.resolvedIncidents,
    mitreTechniques: reportInfo.mitreTechniques,
    sessionDuration: reportInfo.sessionDuration,
  });
}

module.exports = {
  triggerWorkflow,
  checkConnection,
  getStatus,
  getSummary,
  setSessionId,
  triggerCriticalAlert,
  triggerIncidentResponse,
  triggerFileDrop,
  triggerThreatIntelHit,
  triggerCanary,
  triggerReportGenerated,
};
