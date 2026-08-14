// ============================================================
// Jarvis SOC — CVSS v3.1 Base Score Calculator
// Full implementation of the FIRST.org CVSS v3.1 specification.
// https://www.first.org/cvss/v3.1/specification-document
// ============================================================

/**
 * CVSS v3.1 metric value tables — from the official specification.
 */
const METRIC_VALUES = {
  // Attack Vector
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  // Attack Complexity
  AC: { L: 0.77, H: 0.44 },
  // Privileges Required (scope unchanged / changed)
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.50 },
  },
  // User Interaction
  UI: { N: 0.85, R: 0.62 },
  // Scope
  S: { U: 'UNCHANGED', C: 'CHANGED' },
  // Confidentiality Impact
  C: { H: 0.56, L: 0.22, N: 0 },
  // Integrity Impact
  I: { H: 0.56, L: 0.22, N: 0 },
  // Availability Impact
  A: { H: 0.56, L: 0.22, N: 0 },
};

/**
 * Parse a CVSS v3.1 vector string into metric components.
 * @param {string} vector - e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 * @returns {Object} parsed metrics
 */
function parseVector(vector) {
  if (!vector) return null;
  const clean = vector.replace(/^CVSS:3\.[01]\//i, '');
  const parts = clean.split('/');
  const metrics = {};
  for (const part of parts) {
    const [key, val] = part.split(':');
    if (key && val) metrics[key.toUpperCase()] = val.toUpperCase();
  }
  return metrics;
}

/**
 * Calculate CVSS v3.1 Base Score from a vector string.
 * Implements the exact formula from the FIRST.org specification.
 * @param {string} vectorString - Full CVSS vector
 * @returns {{ score: number, severity: string, vector: string }}
 */
function calculateBaseScore(vectorString) {
  const m = parseVector(vectorString);
  if (!m || !m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) {
    return { score: 0, severity: 'NONE', vector: vectorString || '' };
  }

  const scopeChanged = m.S === 'C';

  // Look up metric values
  const av = METRIC_VALUES.AV[m.AV] || 0;
  const ac = METRIC_VALUES.AC[m.AC] || 0;
  const pr = scopeChanged
    ? (METRIC_VALUES.PR.C[m.PR] || 0)
    : (METRIC_VALUES.PR.U[m.PR] || 0);
  const ui = METRIC_VALUES.UI[m.UI] || 0;
  const c = METRIC_VALUES.C[m.C] || 0;
  const i = METRIC_VALUES.I[m.I] || 0;
  const a = METRIC_VALUES.A[m.A] || 0;

  // Impact Sub Score (ISS)
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));

  // Impact
  let impact;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  // Exploitability
  const exploitability = 8.22 * av * ac * pr * ui;

  // If impact <= 0, base score is 0
  if (impact <= 0) {
    return { score: 0, severity: 'NONE', vector: vectorString };
  }

  // Base Score
  let baseScore;
  if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }

  // Round up to one decimal (CVSS spec: "round up")
  baseScore = roundUp(baseScore);

  const severity = scoreToSeverity(baseScore);

  return { score: baseScore, severity, vector: vectorString };
}

/**
 * CVSS spec "round up" — round to 1 decimal, always rounding up.
 */
function roundUp(val) {
  return Math.ceil(val * 10) / 10;
}

/**
 * Map CVSS score to severity label.
 */
function scoreToSeverity(score) {
  if (score === 0) return 'NONE';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
}

/**
 * Convert a CVSS base score to risk score contribution points.
 * @param {number} cvssScore - 0.0 to 10.0
 * @returns {number} risk points contribution
 */
function cvssToRiskPoints(cvssScore) {
  if (cvssScore >= 9.0) return 30 + Math.round((cvssScore - 9.0) * 5);   // 30-35
  if (cvssScore >= 7.0) return 18 + Math.round((cvssScore - 7.0) * 2);   // 18-22
  if (cvssScore >= 4.0) return 8 + Math.round((cvssScore - 4.0) * 1.4);  // 8-12
  if (cvssScore >= 0.1) return 2 + Math.round((cvssScore - 0.1) * 0.8);  // 2-5
  return 0;
}

// ============================================================
// CVSS Vector Mappings for all Jarvis tools
// Maps (tool_name, finding_type) → CVSS vector string
// ============================================================

const TOOL_CVSS_MAPPINGS = {
  // ---- Code Security ----
  scan_secrets: {
    aws_key:        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  // 10.0
    github_token:   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  // 10.0
    stripe_key:     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',  // 9.3
    jwt_token:      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',  // 8.2
    db_uri:         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    slack_token:    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',  // 6.5
    private_key:    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  // 10.0
    generic_secret: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',  // 7.5
    generic_key:    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
    default:        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',  // 7.5
  },
  run_sast: {
    eval_injection:  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    sql_injection:   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    xss:             'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',  // 6.1
    command_inject:  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    hardcoded_ip:    'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
    insecure_proto:  'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',  // 5.9
    default:         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',  // 6.5
  },
  audit_dependencies: {
    critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    high:     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',  // 9.1
    medium:   'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',  // 5.4
    low:      'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
    default:  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',  // 6.5
  },

  // ---- File Security ----
  scan_malware: {
    match:   'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',  // 8.8 → ~9.9 after scope
    default: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',  // 3.3
  },
  scan_sensitive_files: {
    ssn:         'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',  // 5.5
    credit_card: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',  // 5.5
    password:    'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',  // 5.5
    default:     'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',  // 3.3
  },

  // ---- Network Security ----
  audit_firewall: {
    open_port_no_auth: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
    disabled:          'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',  // 7.3
    broad_rule:        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
    default:           'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },
  monitor_network: {
    suspicious_port:    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
    c2_connection:      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    default:            'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },

  // ---- SOC Log Analysis ----
  parse_windows_event_log: {
    '4625_single':   'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
    '4625_brute':    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    '4720':          'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N',  // 6.0
    '4732':          'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',  // 6.7
    '7045':          'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',  // 6.7
    '4698':          'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',  // 6.7
    '1102':          'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',  // 6.7
    default:         'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },
  parse_linux_syslog: {
    ssh_brute:       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    sudo_fail:       'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',  // 4.4
    su_root:         'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',  // 7.8
    cron_persist:    'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',  // 6.7
    default:         'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },
  parse_web_server_log: {
    sqli:            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    traversal:       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',  // 7.5
    scanner:         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
    error_spike:     'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
    default:         'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
  },

  // ---- Threat Intelligence ----
  enrich_ip: {
    c2_known:     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  // 9.8
    tor_exit:     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',  // 6.5
    high_abuse:   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',  // 8.2
    default:      'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },
  enrich_hash: {
    malware_match: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', // 8.8
    default:       'CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', // 3.7
  },
  check_domain: {
    dga_detected:  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',  // 6.5
    blocklisted:   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',  // 8.2
    default:       'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },
  lookup_cve: {
    // CVE lookup uses the real CVSS score from NVD, not our mapping
    default:       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 5.3
  },

  // ---- Ransomware ----
  deploy_canary_files: {
    triggered:     'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  // 10.0
    default:       'CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',  // 0.0
  },
  detect_mass_file_change: {
    detected:      'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  // 10.0
    default:       'CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N',  // 0.0
  },

  // ---- Privacy ----
  check_breach_status: {
    breached:      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',  // 7.5
    default:       'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  // 3.7
  },
  triage_phishing_email: {
    phishing:      'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N',  // 7.1
    default:       'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',  // 3.1
  },

  // ---- Alerts (severity-based default vectors) ----
  alert: {
    CRITICAL: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',  // 10.0 → 35 pts
    HIGH:     'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',   // 7.1 → 18 pts
    MEDIUM:   'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',   // 5.4 → 10 pts
    LOW:      'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',   // 3.7 → 5 pts
    INFO:     'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N',   // 1.8 → 3 pts
  },
};

/**
 * Get the CVSS vector for a specific tool finding.
 * @param {string} toolName - Tool that produced the finding
 * @param {string} findingType - Specific finding type/key
 * @returns {{ score: number, severity: string, vector: string }}
 */
function getCvssForFinding(toolName, findingType) {
  const toolMap = TOOL_CVSS_MAPPINGS[toolName];
  if (!toolMap) {
    // Unknown tool — return low default
    return calculateBaseScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N');
  }

  const vector = toolMap[findingType] || toolMap.default;
  if (!vector) {
    return calculateBaseScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N');
  }

  return calculateBaseScore(vector);
}

/**
 * Get CVSS for an alert based on its severity level.
 * @param {string} severity - CRITICAL/HIGH/MEDIUM/LOW/INFO
 * @returns {{ score: number, severity: string, vector: string }}
 */
function getCvssForAlert(severity) {
  const vector = TOOL_CVSS_MAPPINGS.alert[severity] || TOOL_CVSS_MAPPINGS.alert.LOW;
  return calculateBaseScore(vector);
}

/**
 * Calculate total risk score from a list of CVSS-scored findings.
 * @param {Array<{cvssScore: number}>} findings - Array of findings with cvssScore
 * @returns {number} Total risk score 0-100
 */
function calculateRiskScore(findings) {
  let total = 0;
  for (const f of findings) {
    total += cvssToRiskPoints(f.cvssScore || 0);
  }
  return Math.min(100, total);
}

/**
 * Calculate risk score from open alerts (used by /api/soc-metrics).
 * @param {Array} alerts - Open alerts with severity field
 * @returns {{ riskScore: number, breakdown: Array }}
 */
function calculateRiskFromAlerts(alerts) {
  const breakdown = [];
  let total = 0;
  for (const alert of alerts) {
    const cvss = getCvssForAlert(alert.severity);
    const points = cvssToRiskPoints(cvss.score);
    total += points;
    breakdown.push({
      alertId: alert.id,
      severity: alert.severity,
      cvssScore: cvss.score,
      cvssVector: cvss.vector,
      riskPoints: points,
    });
  }
  return { riskScore: Math.min(100, total), breakdown };
}

module.exports = {
  calculateBaseScore,
  parseVector,
  cvssToRiskPoints,
  getCvssForFinding,
  getCvssForAlert,
  calculateRiskScore,
  calculateRiskFromAlerts,
  scoreToSeverity,
  TOOL_CVSS_MAPPINGS,
};
