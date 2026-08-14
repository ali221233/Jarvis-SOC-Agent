// ============================================================
// Jarvis SOC — Incident Response Playbooks
// run_playbook, list_playbooks
// Orchestrates existing tools in predefined sequences.
// ============================================================

const { logAction } = require('../logger');

let wsBroadcast = null;
function setWsBroadcast(fn) { wsBroadcast = fn; }

function narrate(message) {
  if (wsBroadcast) {
    wsBroadcast({ type: 'playbook_narration', message, timestamp: new Date().toISOString() });
  }
}

// ---- Playbook Definitions ----

const PLAYBOOKS = {
  ransomware: {
    name: 'Ransomware Response',
    description: 'Detect and assess ransomware activity: mass file changes, startup audit, network C2, disk encryption, backup status.',
    tier: 2,
    steps: [
      { tool: 'detect_mass_file_change', params: { path: '.', threshold: 5 }, narration: 'checking for mass file modifications' },
      { tool: 'audit_startup_processes', params: {}, narration: 'auditing startup processes for persistence' },
      { tool: 'monitor_network', params: {}, narration: 'monitoring network for C2 traffic' },
      { tool: 'check_disk_encryption', params: {}, narration: 'checking disk encryption status' },
      { tool: 'verify_backups', params: {}, narration: 'verifying backup status and integrity' },
    ],
  },

  brute_force: {
    name: 'Brute Force Response',
    description: 'Investigate brute force attack: parse auth logs, enrich source IP, check firewall, create alert, propose block rule.',
    tier: 2,
    steps: [
      { tool: 'parse_windows_event_log', params: { logPath: 'data/demo-event-log.xml' }, narration: 'parsing authentication logs for the attack pattern' },
      { tool: 'enrich_ip', params: { ipAddress: '192.168.1.100' }, narration: 'enriching the source IP' },
      { tool: 'audit_firewall', params: {}, narration: 'checking if the IP is already blocked' },
      { tool: 'create_alert', params: { title: 'Brute Force Attack Detected', severity: 'HIGH', source: 'Playbook: brute_force', details: 'Multi-step brute force investigation completed.' }, narration: 'creating consolidated alert with all findings' },
      { tool: 'monitor_network', params: {}, narration: 'scanning network for any active connections from the source' },
    ],
  },

  insider_threat: {
    name: 'Insider Threat Investigation',
    description: 'Investigate insider activity: startup audit, privileged actions, sensitive file access, scheduled tasks, generate report.',
    tier: 2,
    steps: [
      { tool: 'audit_startup_processes', params: {}, narration: 'auditing startup processes for anomalies' },
      { tool: 'parse_windows_event_log', params: { logPath: 'data/demo-event-log.xml' }, narration: 'filtering for privileged account actions' },
      { tool: 'scan_sensitive_files', params: { path: '.' }, narration: 'scanning for sensitive file access patterns' },
      { tool: 'monitor_network', params: {}, narration: 'checking for data exfiltration indicators' },
      { tool: 'generate_report', params: {}, narration: 'generating investigation report' },
    ],
  },

  phishing: {
    name: 'Phishing Investigation',
    description: 'Analyze phishing attempt: triage email, enrich URLs/domains, check breach status, create alert, recommend actions.',
    tier: 2,
    steps: [
      { tool: 'triage_phishing_email', params: { content: 'Suspicious email under investigation' }, narration: 'triaging the phishing email content' },
      { tool: 'check_domain', params: { domain: 'suspicious-login.com' }, narration: 'enriching domains found in the email' },
      { tool: 'check_breach_status', params: { account: 'ali@example.com' }, narration: 'checking breach status for referenced accounts' },
      { tool: 'create_alert', params: { title: 'Phishing Attempt Detected', severity: 'MEDIUM', source: 'Playbook: phishing', details: 'Phishing investigation completed.' }, narration: 'creating alert with findings' },
    ],
  },

  malware_detected: {
    name: 'Malware Detection Response',
    description: 'Respond to malware detection: hash enrichment, directory permissions, malware scan, startup audit, network monitoring, report.',
    tier: 2,
    steps: [
      { tool: 'enrich_hash', params: { fileHash: 'a1b2c3d4e5f678901234567890abcdef' }, narration: 'enriching the detected file hash' },
      { tool: 'check_permissions', params: { path: '.' }, narration: 'checking permissions on affected directories' },
      { tool: 'scan_malware', params: { path: '.' }, narration: 'scanning the parent directory for additional malware' },
      { tool: 'audit_startup_processes', params: {}, narration: 'auditing startup processes for persistence mechanisms' },
      { tool: 'monitor_network', params: {}, narration: 'monitoring network for C2 traffic' },
    ],
  },
};

// ---- TOOL: run_playbook (Tier 2) ----
async function runPlaybook({ playbookName }) {
  if (!playbookName) return { error: 'Playbook name required. Use list_playbooks to see available options.' };

  const key = playbookName.toLowerCase().replace(/\s+/g, '_');
  const playbook = PLAYBOOKS[key];
  if (!playbook) {
    return {
      error: `Playbook "${playbookName}" not found. Available: ${Object.keys(PLAYBOOKS).join(', ')}`,
    };
  }

  const results = [];
  const errors = [];
  let completedSteps = 0;

  narrate(`Starting playbook: ${playbook.name}. ${playbook.steps.length} steps.`);

  const toolRegistry = require('../tool-registry');
  for (let i = 0; i < playbook.steps.length; i++) {
    const step = playbook.steps[i];
    const stepNum = i + 1;
    const totalSteps = playbook.steps.length;

    narrate(`Running step ${stepNum} of ${totalSteps}, Boss — ${step.narration}.`);

    const tool = toolRegistry.getTool(step.tool);
    if (!tool) {
      const err = { step: stepNum, tool: step.tool, error: `Tool ${step.tool} not found in registry` };
      errors.push(err);
      results.push(err);
      continue;
    }

    try {
      const result = await tool.execute(step.params);

      completedSteps++;
      results.push({
        step: stepNum,
        tool: step.tool,
        tier: tool.tier,
        status: 'completed',
        summary: result.summary || 'Completed',
        result,
      });

      // Log each step
      logAction({
        summary: `Playbook ${key} step ${stepNum}: ${step.tool}`,
        tier: tool.tier,
        tool: step.tool,
        params: step.params,
        result,
      });

    } catch (err) {
      errors.push({ step: stepNum, tool: step.tool, error: err.message });
      results.push({ step: stepNum, tool: step.tool, status: 'error', error: err.message });
    }
  }

  narrate(`Playbook complete: ${playbook.name}. ${completedSteps}/${playbook.steps.length} steps succeeded.`);

  const playbookResult = {
    tool: 'run_playbook',
    playbook: key,
    name: playbook.name,
    totalSteps: playbook.steps.length,
    completedSteps,
    errors: errors.length,
    results,
    summary: `${playbook.name} — ${completedSteps}/${playbook.steps.length} steps complete.${errors.length > 0 ? ` ${errors.length} error(s).` : ''}`
  };

  // Trigger n8n incident_response workflow (non-blocking)
  setImmediate(async () => {
    try {
      const n8nClient = require('../n8n-client');
      await n8nClient.triggerIncidentResponse({
        playbookName: playbook.name,
        incidentId: `PB-${Date.now()}`,
        stepsCompleted: completedSteps,
        findings: results.map(r => r.summary).filter(Boolean),
        riskScoreBefore: null,
        riskScoreAfter: null,
      });
    } catch {}
  });

  return playbookResult;
}

// ---- TOOL: list_playbooks (Tier 1) ----
async function listPlaybooks() {
  const list = Object.entries(PLAYBOOKS).map(([key, pb]) => ({
    name: key,
    displayName: pb.name,
    description: pb.description,
    tier: pb.tier,
    steps: pb.steps.length,
  }));

  return {
    tool: 'list_playbooks',
    playbooks: list,
    summary: `${list.length} playbooks available: ${list.map(p => p.name).join(', ')}`,
  };
}

module.exports = { runPlaybook, listPlaybooks, setWsBroadcast, PLAYBOOKS };
