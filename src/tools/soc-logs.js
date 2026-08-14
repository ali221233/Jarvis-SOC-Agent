// ============================================================
// Jarvis SOC — Log Analysis Engine
// parse_windows_event_log, parse_linux_syslog,
// parse_web_server_log, correlate_events
// All Tier 1 (read-only analysis)
// ============================================================

const fs = require('fs');
const path = require('path');
const socAlerts = require('./soc-alerts');
const socMitre = require('./soc-mitre');

// In-memory event store for correlation
const eventStore = [];

function resolveLogPath(inputPath, defaultRel) {
  if (inputPath && typeof inputPath === 'string' && inputPath.trim() !== '.' && inputPath.trim() !== '') {
    const clean = inputPath.trim().replace(/^['"]|['"]$/g, '');
    const candidate = path.isAbsolute(clean) ? clean : path.resolve(process.cwd(), clean);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }
  if (defaultRel) {
    const def = path.resolve(process.cwd(), defaultRel);
    if (fs.existsSync(def)) return def;
  }
  return null;
}

// Critical Windows Event IDs
const CRITICAL_EVENT_IDS = {
  4625: { name: 'Failed Logon', severity: 'HIGH', mitre: 'T1110' },
  4720: { name: 'User Account Created', severity: 'HIGH', mitre: 'T1136' },
  4732: { name: 'User Added to Privileged Group', severity: 'CRITICAL', mitre: 'T1098' },
  7045: { name: 'New Service Installed', severity: 'HIGH', mitre: 'T1543' },
  4698: { name: 'Scheduled Task Created', severity: 'HIGH', mitre: 'T1053' },
  1102: { name: 'Audit Log Cleared', severity: 'CRITICAL', mitre: 'T1070' },
  4624: { name: 'Successful Logon', severity: 'INFO', mitre: 'T1078' },
  4648: { name: 'Logon Using Explicit Credentials', severity: 'MEDIUM', mitre: 'T1078' },
  4672: { name: 'Special Privileges Assigned', severity: 'MEDIUM', mitre: 'T1548' },
};

// ---- TOOL: parse_windows_event_log (Tier 1) ----
async function parseWindowsEventLog(params = {}) {
  const rawPath = params.logPath || params.path || params.file;
  const logPath = resolveLogPath(rawPath, 'data/demo-logs/windows_events.txt') || resolveLogPath(rawPath, 'data/demo-logs/security.evtx');
  if (!logPath || !fs.existsSync(logPath)) {
    return { error: `Windows event log file not found: ${rawPath || 'data/demo-logs/windows_events.txt'}` };
  }


  const content = fs.readFileSync(logPath, 'utf-8');
  const findings = [];
  const stats = { totalEvents: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  // Parse XML-exported event logs
  const eventRegex = /<Event[^>]*>[\s\S]*?<\/Event>/gi;
  const events = content.match(eventRegex) || [];

  // Also parse text-format logs (EventID: NNNN patterns)
  const textEventRegex = /(?:Event\s*ID|EventID)[:\s]*(\d+)/gi;
  let textMatch;
  const textEventIds = [];
  while ((textMatch = textEventRegex.exec(content)) !== null) {
    textEventIds.push(parseInt(textMatch[1]));
  }

  // Process XML events
  for (const eventXml of events) {
    stats.totalEvents++;
    const idMatch = eventXml.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
    const timeMatch = eventXml.match(/<TimeCreated\s+SystemTime='([^']+)'/i) ||
                      eventXml.match(/<TimeCreated>([^<]+)<\/TimeCreated>/i);
    const sourceMatch = eventXml.match(/<Provider\s+Name='([^']+)'/i) ||
                        eventXml.match(/<Source>([^<]+)<\/Source>/i);

    if (idMatch) {
      const eventId = parseInt(idMatch[1]);
      const timestamp = timeMatch ? timeMatch[1] : new Date().toISOString();
      const source = sourceMatch ? sourceMatch[1] : 'Unknown';
      const critical = CRITICAL_EVENT_IDS[eventId];

      if (critical) {
        const finding = {
          type: 'windows_event',
          eventId,
          name: critical.name,
          severity: critical.severity,
          timestamp,
          source,
          mitre: critical.mitre,
        };
        findings.push(finding);
        stats[critical.severity.toLowerCase()]++;

        // Store for correlation
        eventStore.push({ ...finding, logSource: 'windows' });

        // Map to MITRE
        socMitre.recordHit(critical.mitre);
      }
    }
  }

  // Process text events if no XML found
  if (events.length === 0 && textEventIds.length > 0) {
    for (const eventId of textEventIds) {
      stats.totalEvents++;
      const critical = CRITICAL_EVENT_IDS[eventId];
      if (critical) {
        const finding = {
          type: 'windows_event',
          eventId,
          name: critical.name,
          severity: critical.severity,
          timestamp: new Date().toISOString(),
          source: 'Text Log',
          mitre: critical.mitre,
        };
        findings.push(finding);
        stats[critical.severity.toLowerCase()]++;
        eventStore.push({ ...finding, logSource: 'windows' });
        socMitre.recordHit(critical.mitre);
      }
    }
  }

  // Auto-create alerts for critical findings
  for (const f of findings.filter(f => f.severity === 'CRITICAL')) {
    await socAlerts.createAlert({
      title: `${f.name} (Event ID ${f.eventId})`,
      severity: 'CRITICAL',
      source: 'Windows Event Log',
      details: `Event ID ${f.eventId} detected at ${f.timestamp}. Source: ${f.source}. MITRE: ${f.mitre}`,
    });
  }

  if (findings.filter(f => f.severity === 'HIGH').length > 0) {
    await socAlerts.createAlert({
      title: `${findings.filter(f => f.severity === 'HIGH').length} High-severity Windows events detected`,
      severity: 'HIGH',
      source: 'Windows Event Log',
      details: findings.filter(f => f.severity === 'HIGH').map(f => `${f.eventId}: ${f.name}`).join(', '),
    });
  }

  return {
    tool: 'parse_windows_event_log',
    path: logPath,
    stats,
    findings,
    summary: `Parsed ${stats.totalEvents} events. Found ${findings.length} security-relevant event(s): ${stats.critical} critical, ${stats.high} high, ${stats.medium} medium.`,
  };
}

// ---- TOOL: parse_linux_syslog (Tier 1) ----
async function parseLinuxSyslog(params = {}) {
  const rawPath = params.logPath || params.path || params.file;
  const logPath = resolveLogPath(rawPath, 'data/demo-logs/auth.log');
  if (!logPath || !fs.existsSync(logPath)) {
    return { error: `Linux syslog file not found: ${rawPath || 'data/demo-logs/auth.log'}` };
  }

  const content = fs.readFileSync(logPath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());
  const findings = [];
  const stats = { totalLines: lines.length, sshFailures: 0, sudoFailures: 0, rootSu: 0, cronChanges: 0 };

  // Track SSH failures by IP for brute force detection
  const sshFailsByIp = {};

  for (const line of lines) {
    const lower = line.toLowerCase();

    // SSH failures
    if (lower.includes('failed password') || lower.includes('authentication failure')) {
      stats.sshFailures++;
      const ipMatch = line.match(/from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      const ip = ipMatch ? ipMatch[1] : 'unknown';
      sshFailsByIp[ip] = (sshFailsByIp[ip] || 0) + 1;

      eventStore.push({
        type: 'ssh_failure', severity: 'MEDIUM', ip,
        timestamp: new Date().toISOString(), logSource: 'syslog',
        mitre: 'T1110',
      });
    }

    // Sudo failures
    if (lower.includes('sudo') && (lower.includes('incorrect password') || lower.includes('auth failure'))) {
      stats.sudoFailures++;
      findings.push({
        type: 'sudo_failure', severity: 'HIGH',
        line: line.substring(0, 120), mitre: 'T1548',
      });
      socMitre.recordHit('T1548');
    }

    // su to root
    if (lower.includes('su:') && lower.includes('root')) {
      stats.rootSu++;
      findings.push({
        type: 'su_to_root', severity: 'HIGH',
        line: line.substring(0, 120), mitre: 'T1548',
      });
    }

    // Cron changes
    if (lower.includes('crontab') && (lower.includes('replace') || lower.includes('edit') || lower.includes('install'))) {
      stats.cronChanges++;
      findings.push({
        type: 'cron_change', severity: 'MEDIUM',
        line: line.substring(0, 120), mitre: 'T1053',
      });
      socMitre.recordHit('T1053');
    }
  }

  // Detect SSH brute force (5+ failures from same IP)
  for (const [ip, count] of Object.entries(sshFailsByIp)) {
    if (count >= 5) {
      findings.push({
        type: 'ssh_brute_force', severity: 'CRITICAL',
        ip, failureCount: count, mitre: 'T1110',
        description: `${count} failed SSH attempts from ${ip}`,
      });
      socMitre.recordHit('T1110');

      await socAlerts.createAlert({
        title: `SSH Brute Force from ${ip} (${count} failures)`,
        severity: 'HIGH',
        source: 'Linux Syslog',
        details: `${count} failed SSH login attempts detected from IP ${ip}`,
      });
    }
  }

  return {
    tool: 'parse_linux_syslog',
    path: logPath,
    stats,
    findings,
    summary: `Parsed ${stats.totalLines} log lines. SSH failures: ${stats.sshFailures}, Sudo failures: ${stats.sudoFailures}, Root su: ${stats.rootSu}, Cron changes: ${stats.cronChanges}.`,
  };
}

// ---- TOOL: parse_web_server_log (Tier 1) ----
async function parseWebServerLog(params = {}) {
  const rawPath = params.logPath || params.path || params.file;
  const logPath = resolveLogPath(rawPath, 'data/demo-logs/access.log');
  if (!logPath || !fs.existsSync(logPath)) {
    return { error: `Web server access log file not found: ${rawPath || 'data/demo-logs/access.log'}` };
  }


  const content = fs.readFileSync(logPath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());
  const findings = [];
  const stats = { totalRequests: lines.length, sqli: 0, traversal: 0, scanners: 0, errorSpikes: 0 };
  const ipRequestCounts = {};
  const ipErrorCounts = {};

  const SQLI_PATTERNS = [/union\s+select/i, /or\s+1\s*=\s*1/i, /'\s*or\s+'/i, /;\s*drop\s+table/i, /--\s*$/i, /\/\*.*\*\//i, /benchmark\s*\(/i, /sleep\s*\(/i, /waitfor\s+delay/i];
  const TRAVERSAL_PATTERNS = [/\.\.\//g, /\.\.%2f/gi, /\.\.\\/, /%2e%2e/gi, /etc\/passwd/i, /boot\.ini/i];
  const SCANNER_SIGNATURES = ['nikto', 'sqlmap', 'nmap', 'dirbuster', 'gobuster', 'wfuzz', 'burp', 'acunetix', 'nessus', 'openvas'];

  for (const line of lines) {
    // Extract IP
    const ipMatch = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const ip = ipMatch ? ipMatch[1] : 'unknown';
    ipRequestCounts[ip] = (ipRequestCounts[ip] || 0) + 1;

    // Extract status code
    const statusMatch = line.match(/"\s+(\d{3})\s+/);
    const status = statusMatch ? parseInt(statusMatch[1]) : 0;
    if (status >= 400) {
      ipErrorCounts[ip] = (ipErrorCounts[ip] || 0) + 1;
    }

    // SQL injection
    for (const pattern of SQLI_PATTERNS) {
      if (pattern.test(line)) {
        stats.sqli++;
        findings.push({
          type: 'sqli_attempt', severity: 'CRITICAL', ip,
          line: line.substring(0, 150), mitre: 'T1190',
        });
        socMitre.recordHit('T1190');
        break;
      }
    }

    // Directory traversal
    for (const pattern of TRAVERSAL_PATTERNS) {
      if (pattern.test(line)) {
        stats.traversal++;
        findings.push({
          type: 'directory_traversal', severity: 'HIGH', ip,
          line: line.substring(0, 150), mitre: 'T1083',
        });
        socMitre.recordHit('T1083');
        break;
      }
    }

    // Scanner signatures in User-Agent
    const lower = line.toLowerCase();
    for (const sig of SCANNER_SIGNATURES) {
      if (lower.includes(sig)) {
        stats.scanners++;
        findings.push({
          type: 'scanner_detected', severity: 'HIGH', ip,
          scanner: sig, line: line.substring(0, 150), mitre: 'T1046',
        });
        socMitre.recordHit('T1046');
        break;
      }
    }
  }

  // High request rate detection (>100 req from single IP in the log)
  for (const [ip, count] of Object.entries(ipRequestCounts)) {
    if (count > 100) {
      findings.push({
        type: 'high_request_rate', severity: 'HIGH', ip,
        requestCount: count, description: `${count} requests from ${ip}`,
      });
    }
  }

  // Auto-alert for SQLi
  if (stats.sqli > 0) {
    await socAlerts.createAlert({
      title: `SQL Injection Attempts Detected (${stats.sqli})`,
      severity: 'CRITICAL',
      source: 'Web Server Log',
      details: `${stats.sqli} SQLi pattern(s) found in ${logPath}`,
    });
  }

  // Store for correlation
  for (const f of findings) {
    eventStore.push({ ...f, timestamp: new Date().toISOString(), logSource: 'webserver' });
  }

  return {
    tool: 'parse_web_server_log',
    path: logPath,
    stats,
    findings: findings.slice(0, 50), // Cap at 50
    summary: `Parsed ${stats.totalRequests} requests. SQLi: ${stats.sqli}, Traversal: ${stats.traversal}, Scanners: ${stats.scanners}.`,
  };
}

// ---- TOOL: correlate_events (Tier 1) ----
async function correlateEvents({ timeWindowMinutes = 30 }) {
  const windowMs = timeWindowMinutes * 60 * 1000;
  const now = Date.now();
  const recentEvents = eventStore.filter(e => {
    const t = new Date(e.timestamp).getTime();
    return (now - t) < windowMs;
  });

  // Group by IP
  const byIp = {};
  for (const e of recentEvents) {
    const ip = e.ip || 'local';
    if (!byIp[ip]) byIp[ip] = [];
    byIp[ip].push(e);
  }

  // Find attack chains
  const chains = [];
  for (const [ip, events] of Object.entries(byIp)) {
    if (events.length >= 2) {
      const types = [...new Set(events.map(e => e.type))];
      if (types.length >= 2) {
        chains.push({
          ip,
          eventCount: events.length,
          types,
          events: events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)),
          description: `${ip}: ${types.join(' → ')} (${events.length} events in ${timeWindowMinutes}min window)`,
        });
      }
    }
  }

  // Also look for cross-source correlations
  const crossSource = [];
  const sources = [...new Set(recentEvents.map(e => e.logSource))];
  if (sources.length > 1) {
    crossSource.push({
      sources,
      eventCount: recentEvents.length,
      description: `Events correlated across ${sources.join(', ')} (${recentEvents.length} total)`,
    });
  }

  return {
    tool: 'correlate_events',
    timeWindow: `${timeWindowMinutes} minutes`,
    totalEvents: recentEvents.length,
    chains,
    crossSourceCorrelations: crossSource,
    summary: chains.length > 0
      ? `Found ${chains.length} attack chain(s) involving ${Object.keys(byIp).length} IP(s) in the last ${timeWindowMinutes} minutes.`
      : `No correlated attack chains found in the last ${timeWindowMinutes} minutes. ${recentEvents.length} events in store.`,
  };
}

module.exports = {
  parseWindowsEventLog, parseLinuxSyslog,
  parseWebServerLog, correlateEvents,
};
