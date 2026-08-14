// ============================================================
// Jarvis SOC — Report Generator
// Professional SOC Incident Report with SHA-256 integrity hash.
// Prepared for Ali.
// ============================================================

const crypto = require('crypto');
const { getHistory, getSessionActions } = require('./logger');
const cvssScorer = require('./cvss-scorer');

function generateReport(sessionId) {
  const actions = getSessionActions();

  // Get SOC data safely
  let alerts = [], openAlerts = [], closedAlerts = [];
  let mitreSummary = { tactics: {}, totalTechniques: 0, totalHits: 0 };
  let enrichments = [];

  try {
    const socAlerts = require('./tools/soc-alerts');
    alerts = socAlerts.getAllAlerts();
    openAlerts = socAlerts.getOpenAlerts();
    closedAlerts = socAlerts.getClosedAlerts();
  } catch {}

  try {
    const socMitre = require('./tools/soc-mitre');
    const summary = socMitre.getAttackSummary();
    // getAttackSummary is async but we need sync data — use heatmap instead
    const heatmap = socMitre.getHeatmapData();
    const hits = heatmap.filter(t => t.count > 0);
    mitreSummary.totalTechniques = hits.length;
    mitreSummary.totalHits = hits.reduce((sum, t) => sum + t.count, 0);
    // Group by tactic
    for (const h of hits) {
      if (!mitreSummary.tactics[h.tactic]) mitreSummary.tactics[h.tactic] = [];
      mitreSummary.tactics[h.tactic].push({ id: h.id, name: h.name, count: h.count });
    }
  } catch {}

  try {
    const socThreatIntel = require('./tools/soc-threat-intel');
    enrichments = socThreatIntel.getEnrichmentHistory();
  } catch {}

  // Categorize actions
  const byTier = { 1: [], 2: [], 3: [] };
  const findings = { critical: [], high: [], medium: [], low: [] };
  const errors = [];
  const anomalies = [];

  for (const action of actions) {
    const tier = action.tier || 1;
    if (byTier[tier]) byTier[tier].push(action);

    if (action.severity) {
      const sev = action.severity.toLowerCase();
      if (findings[sev]) findings[sev].push(action);
    }

    // Track errors
    if (action.status === 'error' || (action.result && typeof action.result === 'string' && action.result.includes('error'))) {
      errors.push(action);
    }

    if (action.tool === 'deploy_canary_files' || action.tool === 'detect_mass_file_change') {
      if (action.result && typeof action.result === 'string' && action.result.includes('ALERT')) {
        anomalies.push(action);
      }
    }
  }

  const criticalCount = (findings.critical || []).length + openAlerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = (findings.high || []).length + openAlerts.filter(a => a.severity === 'HIGH').length;

  // Calculate risk posture — CVSS v3.1 based scoring
  const alertRisk = cvssScorer.calculateRiskFromAlerts(openAlerts);
  let riskScore = alertRisk.riskScore;
  // Add finding contributions
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    for (const f of findings[sev] || []) {
      const cvss = cvssScorer.getCvssForFinding(f.tool || 'unknown', sev);
      riskScore += cvssScorer.cvssToRiskPoints(cvss.score);
    }
  }
  riskScore = Math.min(100, riskScore);
  let riskPosture = 'LOW';

  if (riskScore >= 75) riskPosture = 'CRITICAL';
  else if (riskScore >= 50) riskPosture = 'HIGH';
  else if (riskScore >= 25) riskPosture = 'MEDIUM';

  const sessionStart = actions.length > 0 ? actions[0].timestamp : new Date().toISOString();
  const sessionEnd = new Date().toISOString();

  // ---- Build Report ----
  const timestamp = new Date().toISOString();
  const hashPrefix = crypto.createHash('sha256').update(timestamp + sessionId).digest('hex').substring(0, 8);

  let report = '';
  report += `# JARVIS SOC — INCIDENT REPORT\n\n`;
  report += `**Report ID:** RPT-${timestamp.slice(0, 10)}-${hashPrefix}\n`;
  report += `**Prepared for:** Boss\n`;
  report += `**Session:** ${sessionStart} → ${sessionEnd}\n`;
  report += `**Generated:** ${timestamp}\n\n`;
  report += `---\n\n`;

  // Executive Summary
  report += `## EXECUTIVE SUMMARY\n\n`;
  const totalAlerts = alerts.length;
  const totalActions = actions.length;
  report += `This session processed ${totalActions} action(s) and generated ${totalAlerts} alert(s). `;
  if (criticalCount > 0) {
    report += `${criticalCount} critical finding(s) require immediate attention. `;
  }
  if (mitreSummary.totalTechniques > 0) {
    report += `${mitreSummary.totalTechniques} unique MITRE ATT&CK technique(s) were triggered across the session. `;
  }
  report += `Overall risk posture: **${riskPosture}** (score: ${riskScore}/100).\n\n`;

  // Open Incidents
  report += `## OPEN INCIDENTS\n\n`;
  if (openAlerts.length > 0) {
    report += `| ID | Title | Severity | Status | Time Open | MITRE Techniques |\n`;
    report += `|---|---|---|---|---|---|\n`;
    for (const a of openAlerts) {
      const timeOpen = timeSince(a.createdAt);
      const mitre = (a.mitreMapping || []).map(m => m.id).join(', ') || '—';
      report += `| ${a.id} | ${a.title} | ${a.severity} | ${a.status} | ${timeOpen} | ${mitre} |\n`;
    }
  } else {
    report += `_No open incidents._\n`;
  }
  report += `\n`;

  // Closed/Resolved Incidents
  report += `## CLOSED/RESOLVED INCIDENTS\n\n`;
  if (closedAlerts.length > 0) {
    report += `| ID | Title | Severity | Resolution | Closed At |\n`;
    report += `|---|---|---|---|---|\n`;
    for (const a of closedAlerts) {
      report += `| ${a.id} | ${a.title} | ${a.severity} | ${a.resolution || '—'} | ${a.closedAt || '—'} |\n`;
    }
  } else {
    report += `_No closed incidents this session._\n`;
  }
  report += `\n`;

  // Threat Intelligence Findings
  report += `## THREAT INTELLIGENCE FINDINGS\n\n`;
  if (enrichments.length > 0) {
    const ips = enrichments.filter(e => e.type === 'ip');
    const hashes = enrichments.filter(e => e.type === 'hash');
    const domains = enrichments.filter(e => e.type === 'domain');
    const cves = enrichments.filter(e => e.type === 'cve');

    if (ips.length > 0) {
      report += `### IPs Enriched (${ips.length})\n`;
      for (const e of ips) {
        report += `- **${e.query}**: Score ${e.abuseScore || 'N/A'}/100${e.knownBad ? ' ⚠️ FLAGGED' : ''}\n`;
      }
      report += `\n`;
    }
    if (hashes.length > 0) {
      report += `### File Hashes Checked (${hashes.length})\n`;
      for (const e of hashes) {
        report += `- \`${e.query.substring(0, 16)}...\`: ${e.found ? `🔴 ${e.malwareName}` : '✅ Clean'}\n`;
      }
      report += `\n`;
    }
    if (domains.length > 0) {
      report += `### Domains Analyzed (${domains.length})\n`;
      for (const e of domains) {
        report += `- **${e.query}**: ${e.flags?.length > 0 ? '⚠️ ' + e.flags.join('; ') : '✅ Clean'}\n`;
      }
      report += `\n`;
    }
    if (cves.length > 0) {
      report += `### CVEs Looked Up (${cves.length})\n`;
      for (const e of cves) {
        report += `- **${e.query}**: CVSS ${e.cvssScore || 'N/A'} — ${e.description?.substring(0, 80) || 'N/A'}...\n`;
      }
      report += `\n`;
    }
  } else {
    report += `_No threat intelligence enrichment performed this session._\n\n`;
  }

  // MITRE ATT&CK Coverage
  report += `## MITRE ATT&CK COVERAGE\n\n`;
  if (Object.keys(mitreSummary.tactics).length > 0) {
    for (const [tactic, techniques] of Object.entries(mitreSummary.tactics)) {
      report += `### ${tactic}\n`;
      for (const t of techniques) {
        report += `- ${t.id} ${t.name} (${t.count} hit${t.count > 1 ? 's' : ''})\n`;
      }
      report += `\n`;
    }
  } else {
    report += `_No MITRE ATT&CK techniques triggered this session._\n\n`;
  }

  // Timeline of Actions
  report += `## TIMELINE OF ACTIONS\n\n`;
  for (const action of actions) {
    const tierBadge = `[T${action.tier || 1}]`;
    report += `- ${tierBadge} \`${action.timestamp}\` — ${action.summary}\n`;
  }
  if (actions.length === 0) report += `_No actions recorded._\n`;
  report += `\n`;

  // Errors & Anomalies
  report += `## ERRORS & ANOMALIES\n\n`;
  if (errors.length > 0 || anomalies.length > 0) {
    for (const e of errors) {
      report += `- ❌ **${e.tool || 'unknown'}** at ${e.timestamp}: ${e.summary || 'Error occurred'}`;
      if (e.result) report += ` — ${typeof e.result === 'string' ? e.result.substring(0, 100) : 'See details'}`;
      report += `\n`;
    }
    for (const a of anomalies) {
      report += `- ⚠️ **Anomaly**: ${a.summary}\n`;
    }
  } else {
    report += `_No errors or anomalies recorded. All tool executions completed successfully._\n`;
  }
  report += `\n`;

  // Risk Posture
  report += `## RISK POSTURE\n\n`;
  report += `**Score: ${riskScore}/100 — ${riskPosture}**\n\n`;
  if (riskPosture === 'CRITICAL') {
    report += `Critical findings demand immediate attention. ${criticalCount} critical issue(s) remain unresolved. Recommend prioritizing triage of all CRITICAL alerts and running relevant incident response playbooks.\n`;
  } else if (riskPosture === 'HIGH') {
    report += `Multiple high-severity findings detected. ${highCount} high-priority issue(s) require review. Consider running the relevant playbook and enriching any flagged indicators.\n`;
  } else if (riskPosture === 'MEDIUM') {
    report += `Some findings require attention but no immediate crisis. Review open alerts and continue monitoring.\n`;
  } else {
    report += `No significant security issues detected this session. Continue standard monitoring posture.\n`;
  }
  report += `\n`;

  // Integrity hash
  report += `---\n\n`;
  const hash = crypto.createHash('sha256').update(report).digest('hex');
  report += `**SHA-256:** \`${hash}\`\n`;
  report += `**Signed:** Jarvis Autonomous SOC Agent\n`;

  return {
    report,
    hash,
    timestamp,
    reportId: `RPT-${timestamp.slice(0, 10)}-${hashPrefix}`,
    stats: {
      totalActions: actions.length,
      byTier: { tier1: byTier[1].length, tier2: byTier[2].length, tier3: byTier[3].length },
      findings: {
        critical: findings.critical.length,
        high: findings.high.length,
        medium: findings.medium.length,
        low: findings.low.length,
      },
      alerts: { total: alerts.length, open: openAlerts.length, closed: closedAlerts.length },
      mitreTechniques: mitreSummary.totalTechniques,
      riskScore,
      riskPosture,
    },
  };
}

function timeSince(dateStr) {
  const ms = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ${mins % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

module.exports = { generateReport };
