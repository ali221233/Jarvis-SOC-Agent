// ============================================================
// Jarvis SOC — Tool Registry
// Central registry with Groq-compatible tool definitions.
// Every tool: { name, description, tier, category, parameters, execute }
// ============================================================

const codeSecurity = require('./tools/code-security');
const fileSecurity = require('./tools/file-security');
const networkSecurity = require('./tools/network-security');
const privacy = require('./tools/privacy');
const ransomware = require('./tools/ransomware');
const productivity = require('./tools/productivity');
const socAlerts = require('./tools/soc-alerts');
const socLogs = require('./tools/soc-logs');
const socThreatIntel = require('./tools/soc-threat-intel');
const socMitre = require('./tools/soc-mitre');
const socPlaybooks = require('./tools/soc-playbooks');

const tools = new Map();

// ---- Register all tools ----

function register(name, description, tier, category, parameters, execute) {
  tools.set(name, { name, description, tier, category, parameters, execute });
}

// -- Code Security (Tier 1 unless noted) --
register('scan_secrets', 'Scan files or directories for hardcoded secrets, API keys, tokens, and passwords', 1, 'code',
  { type: 'object', properties: { path: { type: 'string', description: 'File or directory path to scan' } }, required: ['path'] },
  codeSecurity.scanSecrets
);

register('audit_dependencies', 'Audit project dependencies for known vulnerabilities', 1, 'code',
  { type: 'object', properties: { path: { type: 'string', description: 'Project root directory path' } }, required: ['path'] },
  codeSecurity.auditDependencies
);

register('run_sast', 'Run static application security testing (SAST) to find code vulnerabilities', 1, 'code',
  { type: 'object', properties: { path: { type: 'string', description: 'File or directory path to analyze' } }, required: ['path'] },
  codeSecurity.runSast
);

register('generate_sbom', 'Generate a Software Bill of Materials (SBOM) for a project', 1, 'code',
  { type: 'object', properties: { path: { type: 'string', description: 'Project root directory path' } }, required: ['path'] },
  codeSecurity.generateSbom
);

register('git_precommit_check', 'Run combined secrets + SAST scan suitable for pre-commit hooks', 1, 'code',
  { type: 'object', properties: { path: { type: 'string', description: 'Repository root path' } }, required: ['path'] },
  codeSecurity.gitPrecommitCheck
);

register('propose_fix', 'Propose fixes for security findings without applying them', 1, 'code',
  { type: 'object', properties: { finding_id: { type: 'string', description: 'Finding ID to propose a fix for' }, findings: { type: 'array', description: 'Array of findings to generate fix proposals for' } }, required: [] },
  codeSecurity.proposeFix
);

register('apply_fix', 'Apply a previously proposed security fix', 2, 'code',
  { type: 'object', properties: { finding_id: { type: 'string', description: 'Fix ID to apply (from propose_fix)' } }, required: ['finding_id'] },
  codeSecurity.applyFix
);

register('sign_commit', 'Sign a git commit with GPG', 2, 'code',
  { type: 'object', properties: { path: { type: 'string', description: 'Repository path' } }, required: ['path'] },
  codeSecurity.signCommit
);

// -- File Security --
register('check_permissions', 'Check file or directory permissions and metadata', 1, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'File or directory path' } }, required: ['path'] },
  fileSecurity.checkPermissions
);

register('scan_malware', 'Scan files against known malware signatures', 1, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'File or directory path to scan' } }, required: ['path'] },
  fileSecurity.scanMalware
);

register('encrypt_file', 'Encrypt a file using AES-256-GCM with the master passphrase-derived key', 2, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'File path to encrypt' } }, required: ['path'] },
  fileSecurity.encryptFile
);

register('decrypt_file', 'Decrypt an encrypted file. Requires passphrase re-entry', 3, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'Encrypted file path (.enc)' } }, required: ['path'] },
  fileSecurity.decryptFile
);

register('scrub_metadata', 'Remove metadata from files', 2, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'File path to scrub' } }, required: ['path'] },
  fileSecurity.scrubMetadata
);

register('secure_delete', 'Securely delete a file with multi-pass overwrite. IRREVERSIBLE', 3, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'File path to securely delete' } }, required: ['path'] },
  fileSecurity.secureDelete
);

register('scan_sensitive_files', 'Scan directory for files containing sensitive data (SSN, credit cards, passwords, etc.)', 1, 'files',
  { type: 'object', properties: { path: { type: 'string', description: 'Root directory to scan' } }, required: ['path'] },
  fileSecurity.scanSensitiveFiles
);

register('search_files', 'Search files by name or content', 1, 'files',
  { type: 'object', properties: { query: { type: 'string', description: 'Search query' }, path: { type: 'string', description: 'Directory to search in' } }, required: ['query', 'path'] },
  fileSecurity.searchFiles
);

register('organize_files', 'Organize files according to a plan', 2, 'files',
  { type: 'object', properties: { plan: { type: 'string', description: 'Organization plan description' }, path: { type: 'string', description: 'Target directory' } }, required: ['plan', 'path'] },
  fileSecurity.organizeFiles
);

// -- Network Security --
register('check_patches', 'Check installed system patches and updates', 1, 'network',
  { type: 'object', properties: { target: { type: 'string', description: 'Target system (local by default)' } }, required: [] },
  networkSecurity.checkPatches
);

register('audit_firewall', 'Audit system firewall configuration and status', 1, 'network',
  { type: 'object', properties: {}, required: [] },
  networkSecurity.auditFirewall
);

register('monitor_network', 'Monitor active network connections and flag suspicious ports', 1, 'network',
  { type: 'object', properties: {}, required: [] },
  networkSecurity.monitorNetwork
);

register('audit_startup_processes', 'List and audit startup/autorun processes', 1, 'network',
  { type: 'object', properties: {}, required: [] },
  networkSecurity.auditStartupProcesses
);

register('check_disk_encryption', 'Check disk encryption status (BitLocker/FileVault)', 1, 'network',
  { type: 'object', properties: { target: { type: 'string', description: 'Target drive or system' } }, required: [] },
  networkSecurity.checkDiskEncryption
);

register('verify_backups', 'Verify backup status and integrity', 1, 'network',
  { type: 'object', properties: { target: { type: 'string', description: 'Backup target to verify' } }, required: [] },
  networkSecurity.verifyBackups
);

register('audit_router_config', 'Audit router/gateway configuration', 1, 'network',
  { type: 'object', properties: {}, required: [] },
  networkSecurity.auditRouterConfig
);

register('scan_iot_devices', 'Scan network for IoT devices', 1, 'network',
  { type: 'object', properties: {}, required: [] },
  networkSecurity.scanIotDevices
);

// -- Privacy & Identity --
register('check_breach_status', 'Check if an account/email has appeared in known data breaches', 1, 'privacy',
  { type: 'object', properties: { account: { type: 'string', description: 'Email address or account name to check' } }, required: ['account'] },
  privacy.checkBreachStatus
);

register('audit_browser_extensions', 'Audit installed browser extensions and flag risky permissions', 1, 'privacy',
  { type: 'object', properties: {}, required: [] },
  privacy.auditBrowserExtensions
);

register('triage_phishing_email', 'Analyze email content for phishing indicators', 1, 'privacy',
  { type: 'object', properties: { content: { type: 'string', description: 'Full email content to analyze' } }, required: ['content'] },
  privacy.triagePhishingEmail
);

register('vault_store', 'Store a sensitive item in the encrypted vault', 2, 'privacy',
  { type: 'object', properties: { name: { type: 'string', description: 'Name/label for the vault item' }, item: { type: 'string', description: 'Content to store' } }, required: ['name', 'item'] },
  privacy.vaultStore
);

register('vault_retrieve', 'Retrieve an item from the encrypted vault. Requires passphrase re-entry', 3, 'privacy',
  { type: 'object', properties: { name: { type: 'string', description: 'Name of the vault item to retrieve' } }, required: ['name'] },
  privacy.vaultRetrieve
);

register('verify_speaker', 'Verify speaker identity via voice biometrics', 3, 'privacy',
  { type: 'object', properties: { audio_sample: { type: 'string', description: 'Audio sample for voice verification' } }, required: [] },
  privacy.verifySpeaker
);

// -- Ransomware Defense --
register('deploy_canary_files', 'Deploy canary (honeypot) files to detect ransomware or unauthorized file modification', 2, 'defense',
  { type: 'object', properties: { paths: { type: 'array', items: { type: 'string' }, description: 'Array of directory paths to deploy canary files in' } }, required: ['paths'] },
  ransomware.deployCanaryFiles
);

register('detect_mass_file_change', 'Detect rapid mass file modifications that may indicate ransomware', 1, 'defense',
  { type: 'object', properties: { path: { type: 'string', description: 'Directory to monitor' }, threshold: { type: 'number', description: 'Number of changes to trigger alert (default: 10)' } }, required: ['path'] },
  ransomware.detectMassFileChange
);

// -- Productivity (TODO stubs) --
register('dictate_notes', 'Dictate and save voice notes (not yet implemented)', 1, 'productivity',
  { type: 'object', properties: { content: { type: 'string', description: 'Note content' } }, required: ['content'] },
  productivity.dictateNotes
);

register('generate_weekly_briefing', 'Generate a weekly security briefing (not yet implemented)', 1, 'productivity',
  { type: 'object', properties: {}, required: [] },
  productivity.generateWeeklyBriefing
);

register('search_calendar', 'Search calendar events (not yet implemented)', 1, 'productivity',
  { type: 'object', properties: { query: { type: 'string', description: 'Calendar search query' } }, required: ['query'] },
  productivity.searchCalendar
);

// ============================================================
// SOC TOOLS
// ============================================================

// -- SOC Log Analysis --
register('parse_windows_event_log', 'Parse Windows event log (.evtx export, .xml, .txt) and flag critical Event IDs (4625, 4720, 4732, 7045, 4698, 1102)', 1, 'soc',
  { type: 'object', properties: { logPath: { type: 'string', description: 'Path to Windows event log file' } }, required: ['logPath'] },
  socLogs.parseWindowsEventLog
);

register('parse_linux_syslog', 'Parse Linux syslog/auth.log for SSH brute force, sudo failures, su to root, cron changes', 1, 'soc',
  { type: 'object', properties: { logPath: { type: 'string', description: 'Path to syslog file' } }, required: ['logPath'] },
  socLogs.parseLinuxSyslog
);

register('parse_web_server_log', 'Parse Apache/Nginx access logs for SQL injection, directory traversal, scanner signatures, error spikes', 1, 'soc',
  { type: 'object', properties: { logPath: { type: 'string', description: 'Path to web server access log' } }, required: ['logPath'] },
  socLogs.parseWebServerLog
);

register('correlate_events', 'Cross-reference parsed logs from multiple sources within a time window to surface attack chains', 1, 'soc',
  { type: 'object', properties: { timeWindowMinutes: { type: 'number', description: 'Time window in minutes (default: 30)' } }, required: [] },
  socLogs.correlateEvents
);

// -- SOC Alert Triage --
register('create_alert', 'Create a new alert in the SOC triage queue', 1, 'soc',
  { type: 'object', properties: { title: { type: 'string', description: 'Alert title' }, severity: { type: 'string', description: 'CRITICAL/HIGH/MEDIUM/LOW/INFO' }, source: { type: 'string', description: 'Alert source' }, details: { type: 'string', description: 'Alert details' } }, required: ['title'] },
  socAlerts.createAlert
);

register('triage_alert', 'Triage a SOC alert: TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_INVESTIGATION', 2, 'soc',
  { type: 'object', properties: { incidentId: { type: 'string', description: 'Incident ID (INC-YYYY-MM-DD-NNN)' }, decision: { type: 'string', description: 'TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_INVESTIGATION' }, notes: { type: 'string', description: 'Triage notes' } }, required: ['incidentId', 'decision'] },
  socAlerts.triageAlert
);

register('escalate_alert', 'Escalate an alert to P1 priority', 2, 'soc',
  { type: 'object', properties: { incidentId: { type: 'string', description: 'Incident ID' }, reason: { type: 'string', description: 'Escalation reason' } }, required: ['incidentId'] },
  socAlerts.escalateAlert
);

register('close_alert', 'Close an alert with resolution summary', 2, 'soc',
  { type: 'object', properties: { incidentId: { type: 'string', description: 'Incident ID' }, resolution: { type: 'string', description: 'Resolution summary' } }, required: ['incidentId'] },
  socAlerts.closeAlert
);

register('get_alert_queue', 'Get all open alerts in the SOC triage queue, sorted by severity', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  socAlerts.getAlertQueue
);

// -- SOC Threat Intelligence --
register('enrich_ip', 'Enrich an IP address with threat intelligence (AbuseIPDB + local blocklist)', 1, 'soc',
  { type: 'object', properties: { ipAddress: { type: 'string', description: 'IP address to check' } }, required: ['ipAddress'] },
  socThreatIntel.enrichIp
);

register('enrich_hash', 'Check a file hash (MD5/SHA256) against known malware database', 1, 'soc',
  { type: 'object', properties: { fileHash: { type: 'string', description: 'File hash (MD5 or SHA-256)' } }, required: ['fileHash'] },
  socThreatIntel.enrichHash
);

register('check_domain', 'Check domain reputation: DGA detection, blocklist, age heuristic', 1, 'soc',
  { type: 'object', properties: { domain: { type: 'string', description: 'Domain name to check' } }, required: ['domain'] },
  socThreatIntel.checkDomain
);

register('lookup_cve', 'Look up CVE details from NVD: CVSS score, description, affected software', 1, 'soc',
  { type: 'object', properties: { cveId: { type: 'string', description: 'CVE ID (e.g., CVE-2021-44228)' } }, required: ['cveId'] },
  socThreatIntel.lookupCve
);

// -- SOC MITRE ATT&CK --
register('map_to_attack', 'Map a finding description to MITRE ATT&CK technique(s)', 1, 'soc',
  { type: 'object', properties: { findingDescription: { type: 'string', description: 'Finding or alert description to map' } }, required: ['findingDescription'] },
  socMitre.mapToAttack
);

register('get_attack_summary', 'Get MITRE ATT&CK technique summary for this session, grouped by tactic', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  socMitre.getAttackSummary
);

// -- SOC Playbooks --
register('run_playbook', 'Execute an incident response playbook (ransomware, brute_force, insider_threat, phishing, malware_detected)', 2, 'soc',
  { type: 'object', properties: { playbookName: { type: 'string', description: 'Playbook name: ransomware, brute_force, insider_threat, phishing, malware_detected' } }, required: ['playbookName'] },
  socPlaybooks.runPlaybook
);

register('list_playbooks', 'List available incident response playbooks', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  socPlaybooks.listPlaybooks
);

// -- n8n Automation --
const n8nClient = require('./n8n-client');
register('trigger_n8n_webhook', 'Dispatch an automated outbound webhook to n8n workflow engine', 1, 'soc',
  { type: 'object', properties: { workflowName: { type: 'string', description: 'Workflow trigger name: critical_alert, file_drop, incident_response, weekly_briefing, threat_intel_hit, canary_triggered, report_generated, daily_patch_audit' }, payload: { type: 'object', description: 'Optional JSON payload' } }, required: ['workflowName'] },
  async (params) => {
    const workflowName = params.workflowName || 'critical_alert';
    let payload = params.payload || {};
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
    const res = await n8nClient.triggerWorkflow(workflowName, payload);
    return {
      tool: 'trigger_n8n_webhook',
      workflowName,
      url: `${process.env.N8N_WEBHOOK_BASE || 'http://localhost:5678/webhook'}/${workflowName}`,
      status: res.status || (res.triggered ? 'SUCCESS' : 'FAILED'),
      payload,
      summary: `Dispatched n8n webhook for "${workflowName}" → ${res.status ? 'HTTP ' + res.status : (res.error || 'Triggered')}.`,
      ...res,
    };
  }
);




// ============================================================
// v3.0 Tool Registrations
// ============================================================

// -- Baseline / Anomaly Detection --
const anomalyDetector = require('./anomaly-detector');

register('baseline_learning_start', 'Start baseline learning mode — observe the system for 24 hours to learn normal behavior', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => anomalyDetector.startLearning()
);

register('baseline_learning_stop', 'Stop baseline learning and save the established baseline', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => anomalyDetector.stopLearning()
);

register('update_baseline', 'Update the existing baseline with current system readings', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => anomalyDetector.updateBaseline()
);

register('check_anomalies', 'Run an anomaly check against the established baseline', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => {
    const anomalies = anomalyDetector.runAnomalyCheck();
    return {
      anomalies,
      count: anomalies.length,
      message: anomalies.length > 0
        ? `Found ${anomalies.length} anomaly(s): ${anomalies.map(a => `${a.metricName} (${a.severity}, ${a.deviations}σ)`).join(', ')}`
        : 'All metrics within normal baseline range.',
    };
  }
);

// -- Background Monitor --
const monitor = require('./monitor');

register('get_monitor_status', 'Get the current status of all background monitoring watchers', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => monitor.getStatus()
);

register('pause_background_monitor', 'Pause all background monitoring watchers', 2, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => { monitor.pause(); return { status: 'paused', message: 'Background monitoring paused, Boss.' }; }
);

register('resume_background_monitor', 'Resume all background monitoring watchers', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => { monitor.resume(); return { status: 'active', message: 'Background monitoring resumed, Boss.' }; }
);

// -- Session History (requires database) --
let database = null;
try { database = require('./database'); } catch {}

register('get_session_history', 'List recent session history with risk scores and finding counts', 1, 'soc',
  { type: 'object', properties: { limit: { type: 'integer', description: 'Max sessions to return' } }, required: [] },
  async (params) => {
    if (!database) return { error: 'SQLite database not available' };
    const sessions = database.getSessionHistory(params.limit || 10);
    return { sessions, count: sessions.length };
  }
);

register('compare_sessions', 'Compare current session with the last session', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => {
    if (!database) return { error: 'SQLite database not available' };
    const last = database.getLastSession();
    if (!last) return { message: 'No previous session to compare.' };
    return {
      lastSession: last,
      currentSessionId: database.getSessionId(),
      comparison: {
        previousRisk: last.risk_score,
        previousFindings: last.findings_count,
        previousDate: last.started_at,
      },
    };
  }
);

// -- Notifications --
let notifier = null;
let ntfyNotifier = null;
try { notifier = require('./notifier'); } catch {}
try { ntfyNotifier = require('./ntfy-notifier'); } catch {}

register('send_test_notification', 'Send a test notification to all configured channels (email, Slack, phone)', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => {
    const results = {};
    if (notifier) { Object.assign(results, await notifier.sendTestNotification()); }
    if (ntfyNotifier) { Object.assign(results, await ntfyNotifier.sendTestNtfy()); }
    results.message = 'Test notifications sent to all configured channels.';
    return results;
  }
);

register('get_notification_status', 'Check the status of all notification channels', 1, 'soc',
  { type: 'object', properties: {}, required: [] },
  async () => {
    const status = {};
    if (notifier) { Object.assign(status, notifier.getStatus()); }
    if (ntfyNotifier) { Object.assign(status, ntfyNotifier.getStatus()); }
    return status;
  }
);

// -- PDF Report --
const pdfReportGenerator = require('./pdf-report-generator');

register('generate_pdf_report', 'Generate a professional PDF incident report with CVSS scoring and SHA-256 hash', 1, 'soc',
  { type: 'object', properties: { sessionId: { type: 'string', description: 'Optional session ID' } }, required: [] },
  async (params) => pdfReportGenerator.generatePdfReport(params.sessionId)
);

// ---- Registry API ----


function getTool(name) {
  return tools.get(name);
}

function getAllTools() {
  return Array.from(tools.values());
}

function getToolsByCategory(category) {
  return Array.from(tools.values()).filter(t => t.category === category);
}

/**
 * Export tool definitions in OpenAI/Groq tool-calling JSON Schema format.
 */
function getToolDefinitions() {
  return Array.from(tools.values()).map(tool => ({
    type: 'function',
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    },
  }));
}

module.exports = {
  getTool,
  getAllTools,
  getToolsByCategory,
  getToolDefinitions,
  register,
};
