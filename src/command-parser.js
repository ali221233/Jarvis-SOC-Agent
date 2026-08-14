// ============================================================
// Jarvis SOC — Command Parser (Fast-Path)
// Keyword/pattern matcher for unambiguous single-tool commands.
// High confidence (>0.85) skips LLM call.
// Low confidence → routes to Groq.
// ============================================================

const PATTERNS = [
  // Code security
  { regex: /\b(?:scan|check|find)\b.*\b(?:secrets?|keys?|tokens?|passwords?|credentials?)\b/i, tool: 'scan_secrets', paramExtractor: extractPath },
  { regex: /\b(?:audit|check|scan)\b.*\b(?:dependenc|packages?|npm|pip|vulnerabilit)\b/i, tool: 'audit_dependencies', paramExtractor: extractPath },
  { regex: /\b(?:run|do|perform)\b.*\bsast\b/i, tool: 'run_sast', paramExtractor: extractPath },
  { regex: /\bstatic\s+analysis\b/i, tool: 'run_sast', paramExtractor: extractPath },
  { regex: /\b(?:generate|create)\b.*\bsbom\b/i, tool: 'generate_sbom', paramExtractor: extractPath },
  { regex: /\bpre\s*-?\s*commit\b.*\b(?:check|scan|hook)\b/i, tool: 'git_precommit_check', paramExtractor: extractPath },
  { regex: /\b(?:propose|suggest)\b.*\bfix/i, tool: 'propose_fix', confidence: 0.7 },
  { regex: /\b(?:apply|implement)\b.*\bfix/i, tool: 'apply_fix', confidence: 0.7 },

  // File security
  { regex: /\b(?:check|show|get)\b.*\bpermissions?\b/i, tool: 'check_permissions', paramExtractor: extractPath },
  { regex: /\b(?:scan|check)\b.*\b(?:malware|virus|infected)\b/i, tool: 'scan_malware', paramExtractor: extractPath },
  { regex: /\bencrypt\b.*\bfile\b/i, tool: 'encrypt_file', paramExtractor: extractPath },
  { regex: /\bdecrypt\b.*\bfile\b/i, tool: 'decrypt_file', paramExtractor: extractPath },
  { regex: /\b(?:scrub|strip|remove)\b.*\bmetadata\b/i, tool: 'scrub_metadata', paramExtractor: extractPath },
  { regex: /\b(?:secure|permanent)\b.*\bdelete\b/i, tool: 'secure_delete', paramExtractor: extractPath },
  { regex: /\b(?:scan|find|search)\b.*\b(?:sensitive|pii|personal)\b/i, tool: 'scan_sensitive_files', paramExtractor: extractPath },
  { regex: /\b(?:search|find|look\s+for)\b.*\bfiles?\b/i, tool: 'search_files', paramExtractor: extractSearchQuery },

  // Network security
  { regex: /\b(?:check|list|show)\b.*\bpatches?\b/i, tool: 'check_patches' },
  { regex: /\b(?:audit|check|show)\b.*\bfirewall\b/i, tool: 'audit_firewall' },
  { regex: /\b(?:monitor|check|show|scan)\b.*\bnetwork\b/i, tool: 'monitor_network' },
  { regex: /\b(?:audit|check|list|show)\b.*\b(?:startup|autorun|boot)\b/i, tool: 'audit_startup_processes' },
  { regex: /\b(?:check|verify)\b.*\b(?:disk\s*encrypt|bitlocker|filevault)\b/i, tool: 'check_disk_encryption' },
  { regex: /\b(?:verify|check)\b.*\bbackups?\b/i, tool: 'verify_backups' },
  { regex: /\b(?:audit|check)\b.*\brouter\b/i, tool: 'audit_router_config' },
  { regex: /\b(?:scan|find|discover|audit)\b.*\b(?:iot|router|smart\s*(?:home|devices?)|network\s*devices?)\b/i, tool: 'scan_iot_devices' },

  // Privacy
  { regex: /\b(?:check|search)\b.*\b(?:breach|pwned|leaked|compromised)\b/i, tool: 'check_breach_status', paramExtractor: extractAccount },
  { regex: /\b(?:audit|check|list)\b.*\b(?:browser\s*ext|extensions?|addons?|plugins?)\b/i, tool: 'audit_browser_extensions' },
  { regex: /\b(?:triage|analyze|check)\b.*\b(?:phishing|spam|suspicious)\b/i, tool: 'triage_phishing_email', paramExtractor: extractPath },
  { regex: /\b(?:store|save|put)\b.*\bvault\b/i, tool: 'vault_store', confidence: 0.7 },
  { regex: /\b(?:get|retrieve|fetch)\b.*\bvault\b/i, tool: 'vault_retrieve', confidence: 0.7 },

  // Ransomware defense
  { regex: /\b(?:deploy|create|set\s*up)\b.*\bcanar(?:y|ies)\b/i, tool: 'deploy_canary_files', confidence: 0.8 },
  { regex: /\b(?:detect|check)\b.*\b(?:mass\s*(?:file)?|ransomware)\b.*\b(?:change|modification)\b/i, tool: 'detect_mass_file_change', paramExtractor: extractPath },

  // Productivity
  { regex: /\b(?:dictate|take)\b.*\bnotes?\b/i, tool: 'dictate_notes' },
  { regex: /\b(?:weekly|week)\b.*\b(?:briefing|summary|report)\b/i, tool: 'generate_weekly_briefing' },
  { regex: /\b(?:search|check|find)\b.*\bcalendar\b/i, tool: 'search_calendar' },

  // ---- SOC Tools ----
  // Log analysis
  { regex: /\b(?:parse|analyze|read)\b.*\b(?:windows|event|security\.evtx)\b/i, tool: 'parse_windows_event_log', paramExtractor: extractLogPath },
  { regex: /\b(?:parse|analyze|read)\b.*\b(?:syslog|auth\.?log|linux)\b/i, tool: 'parse_linux_syslog', paramExtractor: extractLogPath },
  { regex: /\b(?:parse|analyze|read)\b.*\b(?:web|access|apache|nginx)\b/i, tool: 'parse_web_server_log', paramExtractor: extractLogPath },

  { regex: /\bcorrelate\b.*\b(?:events?|logs?)\b/i, tool: 'correlate_events' },

  // Alerts
  { regex: /\b(?:show|list|get|view)\b.*\b(?:alert|incident|queue)\b/i, tool: 'get_alert_queue' },
  { regex: /\b(?:create|new|add)\b.*\balert\b/i, tool: 'create_alert', confidence: 0.7 },
  { regex: /\btriage\b.*\b(?:alert|incident)\b/i, tool: 'triage_alert', confidence: 0.7 },
  { regex: /\bescalate\b.*\b(?:alert|incident)\b/i, tool: 'escalate_alert', confidence: 0.7 },
  { regex: /\bclose\b.*\b(?:alert|incident)\b/i, tool: 'close_alert', confidence: 0.7 },

  // Threat intelligence
  { regex: /\b(?:enrich|lookup|check)\b.*\bip\b\s+\d/i, tool: 'enrich_ip', paramExtractor: extractIp },
  { regex: /\benrich\b.*\b(?:ip|address)\b/i, tool: 'enrich_ip', paramExtractor: extractIp },
  { regex: /\b(?:enrich|lookup|check)\b.*\b(?:hash|md5|sha)\b/i, tool: 'enrich_hash', paramExtractor: extractHash },
  { regex: /\b(?:check|lookup|analyze)\b.*\bdomain\b/i, tool: 'check_domain', paramExtractor: extractDomain },
  { regex: /\b(?:lookup|search|check)\b.*\bcve\b/i, tool: 'lookup_cve', paramExtractor: extractCve },

  // MITRE ATT&CK
  { regex: /\bmitre\b.*\b(?:summary|overview|heatmap)\b/i, tool: 'get_attack_summary' },
  { regex: /\bmap\b.*\b(?:mitre|attack|att&ck)\b/i, tool: 'map_to_attack', confidence: 0.7 },

  // Playbooks
  { regex: /\b(?:run|execute|start)\b.*\bplaybook\b/i, tool: 'run_playbook', paramExtractor: extractPlaybook },
  { regex: /\b(?:list|show)\b.*\bplaybooks?\b/i, tool: 'list_playbooks' },
  { regex: /\b(?:run|execute|start)\b.*\b(?:brute\s*force)\b.*\b(?:playbook|response)\b/i, tool: 'run_playbook', paramExtractor: () => ({ playbookName: 'brute_force' }) },
  { regex: /\b(?:run|execute|start)\b.*\b(?:ransomware)\b.*\b(?:playbook|response)\b/i, tool: 'run_playbook', paramExtractor: () => ({ playbookName: 'ransomware' }) },

  // Report
  { regex: /\b(?:generate|create|write)\b.*\b(?:incident\s*)?report\b/i, tool: 'generate_report', confidence: 0.9 },

  // n8n Webhook Triggers
  { regex: /\b(?:trigger|test|fire|dispatch)\b.*\b(?:n8n|webhook)\b/i, tool: 'trigger_n8n_webhook', paramExtractor: (cmd) => {
    const lower = cmd.toLowerCase();
    for (const name of ['critical_alert', 'file_drop', 'incident_response', 'weekly_briefing', 'threat_intel_hit', 'canary_triggered', 'report_generated', 'daily_patch_audit']) {
      if (lower.includes(name) || lower.includes(name.replace('_', ' ')) || lower.includes(name.replace('_', '-'))) {
        return { workflowName: name };
      }
    }
    return { workflowName: 'critical_alert' };
  }},


  // ---- New v3.0 Features ----

  // Baseline / Anomaly Detection
  { regex: /\b(?:start|begin|learn)\b.*\bbaseline\b/i, tool: 'baseline_learning_start', confidence: 0.9 },
  { regex: /\b(?:stop|finish|end|complete)\b.*\b(?:baseline|learning)\b/i, tool: 'baseline_learning_stop', confidence: 0.9 },
  { regex: /\b(?:update|refresh)\b.*\bbaseline\b/i, tool: 'update_baseline', confidence: 0.9 },

  // Background Monitor
  { regex: /\b(?:background|monitor|watcher)\b.*\bstatus\b/i, tool: 'get_monitor_status', confidence: 0.9 },
  { regex: /\b(?:pause|stop)\b.*\b(?:monitor|watcher|background)\b/i, tool: 'pause_background_monitor', confidence: 0.85 },
  { regex: /\b(?:resume|start|restart)\b.*\b(?:monitor|watcher|background)\b/i, tool: 'resume_background_monitor', confidence: 0.85 },

  // Session History
  { regex: /\b(?:show|list|view)\b.*\b(?:session|past\s*session|previous\s*session)\b.*\bhistory\b/i, tool: 'get_session_history', confidence: 0.9 },
  { regex: /\bpast\s*sessions?\b/i, tool: 'get_session_history', confidence: 0.85 },
  { regex: /\bprevious\s*sessions?\b/i, tool: 'get_session_history', confidence: 0.85 },
  { regex: /\b(?:compare|diff)\b.*\b(?:last|previous)\b.*\bsession\b/i, tool: 'compare_sessions', confidence: 0.85 },

  // Notifications
  { regex: /\b(?:send|run|trigger)\b.*\btest\b.*\b(?:notification|alert)\b/i, tool: 'send_test_notification', confidence: 0.9 },
  { regex: /\btest\b.*\b(?:notification|alert)\b/i, tool: 'send_test_notification', confidence: 0.85 },

  // PDF Report
  { regex: /\b(?:open|show|view)\b.*\b(?:pdf|report)\b/i, tool: 'open_last_report', confidence: 0.8 },

  // Meta
  { regex: /\b(?:full|complete|comprehensive)\b.*\b(?:audit|scan|security\s*check)\b/i, tool: null, confidence: 0.5, multi: true },
];

function parse(command) {
  if (!command || typeof command !== 'string') {
    return { tool: null, params: {}, confidence: 0 };
  }

  const trimmed = command.trim();

  for (const pattern of PATTERNS) {
    if (pattern.regex.test(trimmed)) {
      const params = pattern.paramExtractor ? pattern.paramExtractor(trimmed) : {};
      const confidence = pattern.confidence || 0.9;

      return {
        tool: pattern.tool,
        params,
        confidence,
        multi: pattern.multi || false,
      };
    }
  }

  // No match
  return { tool: null, params: {}, confidence: 0 };
}

// ---- Parameter extractors ----

function extractPath(command) {
  // Look for quoted paths first
  const quoted = command.match(/['"]([^'"]+)['"]/);
  if (quoted) return { path: quoted[1].trim() };

  // Look for explicit dot "." (e.g. "scan secrets in .", "audit dependencies .")
  if (/(?:^|\s)\.(?:\s|$)/.test(command) || /\b(?:in|at|for|on|path)\s+\./i.test(command)) {
    return { path: '.' };
  }

  // Look for "this", "here", "current", "cwd", "project", "workspace", "repo", "root"
  if (/\b(?:this|here|current|cwd|project|workspace|repo|root)\b/i.test(command)) {
    return { path: '.' };
  }

  // Look for directory/file name after prepositions (e.g. "scan secrets in src", "audit dependencies in data", "scan malware in data/demo-logs")
  const afterPrep = command.match(/\b(?:in|at|for|from|on|path:?)\s+([a-zA-Z0-9_.\-\\/]+)/i);
  if (afterPrep && !['the', 'a', 'an', 'my', 'all', 'any', 'some'].includes(afterPrep[1].toLowerCase())) {
    return { path: afterPrep[1].trim() };
  }

  // Look for path-like strings with slashes or extensions
  const pathLike = command.match(/([a-zA-Z]:[/\\][^\s'"]+|[a-zA-Z0-9_.-]+[/\\][a-zA-Z0-9_.\-\\/]+|[a-zA-Z0-9_.-]+\.[a-zA-Z0-9_]+)/);
  if (pathLike && !['log', 'logs', 'access', 'auth', 'event'].includes(pathLike[0].toLowerCase())) {
    return { path: pathLike[0].trim() };
  }

  // Default to current directory '.' for tools that require a path
  return { path: '.' };
}


function extractSearchQuery(command) {
  const params = extractPath(command);
  // Extract query — everything after "for" or "named" or "called"
  const queryMatch = command.match(/(?:for|named|called)\s+['"]?([^'"]+?)['"]?\s*$/i);
  if (queryMatch) {
    params.query = queryMatch[1].trim();
  }
  return params;
}

function extractAccount(command) {
  // Look for email addresses
  const email = command.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  if (email) return { account: email[0] };
  return {};
}

// ---- SOC Parameter Extractors ----

function extractIp(command) {
  const ip = command.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return ip ? { ipAddress: ip[1] } : {};
}

function extractHash(command) {
  // SHA-256 (64 hex chars) or MD5 (32 hex chars)
  const hash = command.match(/\b([a-fA-F0-9]{64}|[a-fA-F0-9]{32})\b/);
  return hash ? { fileHash: hash[1] } : {};
}

function extractDomain(command) {
  const domain = command.match(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b/);
  return domain ? { domain: domain[1] } : {};
}

function extractCve(command) {
  const cve = command.match(/(CVE-\d{4}-\d{4,})/i);
  return cve ? { cveId: cve[1].toUpperCase() } : {};
}

function extractPlaybook(command) {
  const lower = command.toLowerCase();
  const playbooks = ['ransomware', 'brute_force', 'insider_threat', 'phishing', 'malware_detected'];
  for (const pb of playbooks) {
    if (lower.includes(pb.replace('_', ' ')) || lower.includes(pb)) {
      return { playbookName: pb };
    }
  }
  // Try partial matches
  if (lower.includes('brute')) return { playbookName: 'brute_force' };
  if (lower.includes('insider')) return { playbookName: 'insider_threat' };
  if (lower.includes('malware')) return { playbookName: 'malware_detected' };
  return {};
}

function extractLogPath(command) {
  // 1. Quoted paths
  const quoted = command.match(/['"]([^'"]+)['"]/);
  if (quoted) return { logPath: quoted[1].trim() };

  // 2. Explicit file path with standard log/data extension
  const fileMatch = command.match(/([a-zA-Z0-9_.\-\\/]+\.(?:log|evtx|xml|txt|json|csv))/i);
  if (fileMatch) return { logPath: fileMatch[1].trim() };

  // 3. Path following keyword
  const afterMatch = command.match(/\b(?:log|file|path|in|from|at)\s+([a-zA-Z0-9_.\-\\/]+)/i);
  if (afterMatch && !['the', 'a', 'an', 'my', 'all', 'web', 'syslog', 'windows', 'event'].includes(afterMatch[1].toLowerCase())) {
    return { logPath: afterMatch[1].trim() };
  }

  // 4. Try general extractPath
  const pathResult = extractPath(command);
  if (pathResult.path && pathResult.path !== '.') return { logPath: pathResult.path };

  return {};
}

module.exports = { parse };
