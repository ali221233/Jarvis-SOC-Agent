// ============================================================
// Jarvis SOC — Section Views Controller v4.0
// Powers all 12 navigation sections in the main workspace.
// ============================================================

const views = {
  activeSection: 'overview',

  init() {
    this.container = document.getElementById('viewContainer');
  },

  show(section) {
    this.activeSection = section;
    const overviewWrap = document.getElementById('view-overview');
    const dynamicWrap = document.getElementById('view-dynamic');

    if (!overviewWrap || !dynamicWrap) return;

    if (section === 'overview') {
      overviewWrap.style.display = 'flex';
      dynamicWrap.style.display = 'none';
      dynamicWrap.innerHTML = '';
      return;
    }

    overviewWrap.style.display = 'none';
    dynamicWrap.style.display = 'block';

    switch (section) {
      case 'logs':
        this.renderLogsView(dynamicWrap);
        break;
      case 'alerts':
        this.renderAlertsView(dynamicWrap);
        break;
      case 'intel':
        this.renderIntelView(dynamicWrap);
        break;
      case 'mitre':
        this.renderMitreView(dynamicWrap);
        break;
      case 'playbooks':
        this.renderPlaybooksView(dynamicWrap);
        break;
      case 'code':
        this.renderCodeSecurityView(dynamicWrap);
        break;
      case 'files':
        this.renderFileSecurityView(dynamicWrap);
        break;
      case 'network':
        this.renderNetworkView(dynamicWrap);
        break;
      case 'privacy':
        this.renderPrivacyView(dynamicWrap);
        break;
      case 'reports':
        this.renderReportsView(dynamicWrap);
        break;
      case 'n8n':
        this.renderN8nView(dynamicWrap);
        break;
      default:
        overviewWrap.style.display = 'flex';
        dynamicWrap.style.display = 'none';
    }
  },

  // Helper to execute command with live feedback
  runCommand(cmd, targetBoxId) {
    if (targetBoxId) {
      const box = document.getElementById(targetBoxId);
      if (box) {
        box.innerHTML = `<div class="loading-td"><span class="pulse-dot"></span> Executing: <code>${escapeHtml(cmd)}</code>...</div>`;
      }
    }
    if (typeof terminal !== 'undefined') {
      terminal.addLine(`ali@jarvis ❯ ${cmd}`, 'user');
    }
    if (typeof app !== 'undefined') {
      app.sendCommand(cmd);
    }
  },

  // ============================================================
  // 1. LOG ANALYSIS VIEW
  // ============================================================
  renderLogsView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◈ LOG ANALYSIS &amp; CORRELATION</h2>
          <p class="view-subtitle">Ingest, parse, and correlate Windows event logs, Linux syslog, and Apache/Nginx web server access logs.</p>
        </div>
        <button class="action-btn" onclick="views.runCommand('correlate events', 'logResultsBox')">⚡ Run Event Correlation</button>
      </div>

      <div class="view-grid grid-2">
        <div class="view-card">
          <div class="card-title">Select Log Source to Parse</div>
          <div class="button-group-vertical">
            <button class="tool-btn" onclick="views.runCommand('parse web server log data/demo-logs/access.log', 'logResultsBox')">
              <span class="btn-icon">🌐</span>
              <div class="btn-info">
                <strong>Parse Web Server Access Log</strong>
                <small>data/demo-logs/access.log (SQLi, XSS, Path Traversal, 403 spikes)</small>
              </div>
            </button>
            <button class="tool-btn" onclick="views.runCommand('parse linux syslog data/demo-logs/auth.log', 'logResultsBox')">
              <span class="btn-icon">🐧</span>
              <div class="btn-info">
                <strong>Parse Linux Auth / Syslog</strong>
                <small>data/demo-logs/auth.log (SSH Brute Force, sudo abuse, failed logins)</small>
              </div>
            </button>
            <button class="tool-btn" onclick="views.runCommand('parse windows event log data/demo-logs/security.evtx', 'logResultsBox')">
              <span class="btn-icon">🪟</span>
              <div class="btn-info">
                <strong>Parse Windows Security Event Log</strong>
                <small>data/demo-logs/security.evtx (Event 4624/4625, Privilege Escalation)</small>
              </div>
            </button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">Custom Log Parser</div>
          <div class="input-form">
            <label style="font-size:11px; color:var(--text-muted);">Log File Path:</label>
            <input type="text" id="customLogPath" class="view-input" placeholder="e.g. data/demo-logs/access.log" value="data/demo-logs/access.log" style="margin-top:4px;">
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="action-btn" onclick="views.parseCustomLog('web')">Parse Web</button>
              <button class="action-btn" onclick="views.parseCustomLog('syslog')">Parse Syslog</button>
              <button class="action-btn" onclick="views.parseCustomLog('windows')">Parse Windows</button>
            </div>
          </div>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Live Log Parser Output</div>
        <div class="results-box" id="logResultsBox">Click a parser button above to run automated log ingestion and see findings here.</div>
      </div>
    `;

  },

  // ============================================================
  // 2. ALERT QUEUE VIEW
  // ============================================================
  async renderAlertsView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◉ INCIDENT &amp; ALERT QUEUE</h2>
          <p class="view-subtitle">Manage open alerts, triage threats, escalate incidents, and track resolution timeline.</p>
        </div>
        <button class="action-btn" onclick="views.showCreateAlertModal()">+ Create Alert</button>
      </div>

      <div class="filter-bar">
        <button class="filter-chip active" onclick="views.filterAlerts('all', this)">ALL</button>
        <button class="filter-chip chip-critical" onclick="views.filterAlerts('CRITICAL', this)">CRITICAL</button>
        <button class="filter-chip chip-high" onclick="views.filterAlerts('HIGH', this)">HIGH</button>
        <button class="filter-chip chip-medium" onclick="views.filterAlerts('MEDIUM', this)">MEDIUM</button>
        <button class="filter-chip chip-low" onclick="views.filterAlerts('LOW', this)">LOW</button>
      </div>

      <div class="view-card" style="margin-top:12px;">
        <div class="table-wrap">
          <table class="view-table" id="alertsTable">
            <thead>
              <tr>
                <th>ID</th>
                <th>SEVERITY</th>
                <th>TITLE</th>
                <th>SOURCE</th>
                <th>STATUS</th>
                <th>MITRE</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody id="alertsTableBody">
              <tr><td colspan="7" class="loading-td">Loading alerts from SQLite database...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
    this.loadAlertsTable('all');
  },

  async loadAlertsTable(filter = 'all') {
    try {
      const res = await fetch('/api/alerts?status=all');
      const data = await res.json();
      const tbody = document.getElementById('alertsTableBody');
      if (!tbody) return;

      let alerts = data.alerts || [];
      if (filter !== 'all') {
        alerts = alerts.filter(a => a.severity === filter);
      }

      if (alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-td">No ${filter === 'all' ? '' : filter} alerts found.</td></tr>`;
        return;
      }

      tbody.innerHTML = alerts.map(a => {
        const mitre = (a.mitreMapping || []).map(m => `<span class="badge-mini">${m.id}</span>`).join(' ') || '—';
        return `
          <tr>
            <td><code>${a.id}</code></td>
            <td><span class="alert-sev sev-${a.severity}">${a.severity}</span></td>
            <td><strong>${escapeHtml(a.title)}</strong><br><small class="text-muted">${escapeHtml(a.details || '')}</small></td>
            <td><code>${a.source || 'system'}</code></td>
            <td><span class="status-tag status-${a.status}">${a.status}</span></td>
            <td>${mitre}</td>
            <td>
              <div class="btn-group-row">
                <button class="btn-xs" onclick="views.triageAlertAction('${a.id}')">Triage</button>
                <button class="btn-xs btn-danger" onclick="views.closeAlertAction('${a.id}')">Close</button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      const tbody = document.getElementById('alertsTableBody');
      if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-td">Failed to load alerts: ${err.message}</td></tr>`;
    }
  },

  filterAlerts(severity, btn) {
    document.querySelectorAll('.filter-chip').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    this.loadAlertsTable(severity);
  },

  showCreateAlertModal() {
    const title = prompt('Enter Alert Title:');
    if (!title) return;
    const sev = prompt('Enter Severity (CRITICAL, HIGH, MEDIUM, LOW):', 'HIGH');
    if (!sev) return;
    this.runCommand(`create alert title "${title}" severity ${sev.toUpperCase()} source manual`);
    setTimeout(() => this.loadAlertsTable('all'), 1000);
  },

  triageAlertAction(id) {
    this.runCommand(`triage alert ${id} escalate`);
    setTimeout(() => this.loadAlertsTable('all'), 1000);
  },

  closeAlertAction(id) {
    this.runCommand(`close alert ${id}`);
    setTimeout(() => this.loadAlertsTable('all'), 1000);
  },

  // ============================================================
  // 3. THREAT INTEL VIEW
  // ============================================================
  renderIntelView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◎ MULTI-SOURCE THREAT INTELLIGENCE</h2>
          <p class="view-subtitle">Live enrichment querying AbuseIPDB, VirusTotal, Shodan, AlienVault OTX, URLScan.io, and NVD/OSV.</p>
        </div>
      </div>

      <div class="view-grid grid-2">
        <div class="view-card">
          <div class="card-title">🌐 IP Address Enrichment</div>
          <div class="input-form">
            <input type="text" id="intelIpInput" class="view-input" placeholder="e.g. 8.8.8.8 or 185.220.101.42" value="185.220.101.42">
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="action-btn" onclick="views.runCommand('enrich ip ' + document.getElementById('intelIpInput').value, 'intelResultsBox')">Enrich IP (AbuseIPDB)</button>
              <button class="action-btn btn-secondary" onclick="views.runCommand('enrich ip 8.8.8.8', 'intelResultsBox')">Test Google DNS (Clean)</button>
            </div>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🔍 File Hash Malware Lookup</div>
          <div class="input-form">
            <input type="text" id="intelHashInput" class="view-input" placeholder="MD5 or SHA-256 hash" value="a1b2c3d4e5f678901234567890abcdef">
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="action-btn" onclick="views.runCommand('enrich hash ' + document.getElementById('intelHashInput').value, 'intelResultsBox')">Query Malware DB (VT)</button>
              <button class="action-btn btn-secondary" onclick="views.runCommand('enrich hash 44d88612fea8a8f36de82e1278abb02f', 'intelResultsBox')">Test EICAR Hash</button>
            </div>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🌍 Domain &amp; URL Reputation</div>
          <div class="input-form">
            <input type="text" id="intelDomainInput" class="view-input" placeholder="e.g. evil-domain-c2.com" value="evil-domain-c2.com">
            <button class="action-btn" style="margin-top:8px;" onclick="views.runCommand('check domain ' + document.getElementById('intelDomainInput').value, 'intelResultsBox')">Check Domain (OTX / URLScan)</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🛡️ Vulnerability (CVE) Lookup</div>
          <div class="input-form">
            <input type="text" id="intelCveInput" class="view-input" placeholder="e.g. CVE-2021-44228" value="CVE-2021-44228">
            <button class="action-btn" style="margin-top:8px;" onclick="views.runCommand('lookup cve ' + document.getElementById('intelCveInput').value, 'intelResultsBox')">Lookup CVE Details</button>
          </div>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Threat Intel Investigation Feed</div>
        <div class="results-box" id="intelResultsBox">Enter an indicator above or click an enrichment button to view threat intelligence findings here.</div>
      </div>
    `;
  },

  // ============================================================
  // 4. MITRE ATT&CK VIEW
  // ============================================================
  async renderMitreView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">⬟ MITRE ATT&amp;CK MATRIX &amp; HEATMAP</h2>
          <p class="view-subtitle">Tactics and techniques observed across all parsed logs, active alerts, and incident investigations.</p>
        </div>
        <button class="action-btn" onclick="views.loadMitreMatrix()">Refresh Heatmap</button>
      </div>

      <div class="view-card">
        <div class="card-title">ATT&CK Technique Matrix (14 Enterprise Tactics)</div>
        <div class="mitre-matrix-grid" id="fullMitreGrid">
          <div class="loading-td">Loading MITRE ATT&amp;CK Matrix...</div>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Map New Security Finding to MITRE Technique</div>
        <div class="input-form" style="display:flex; gap:8px;">
          <input type="text" id="mitreFindingInput" class="view-input" style="flex:1" placeholder="Describe finding e.g. unauthorized PowerShell script running encoded payload..." value="unauthorized PowerShell script running encoded payload">
          <button class="action-btn" onclick="views.runCommand('map to mitre: ' + document.getElementById('mitreFindingInput').value, 'mitreResultsBox')">Map Technique</button>
        </div>
        <div class="results-box" id="mitreResultsBox" style="margin-top:10px;">Enter a finding description and click Map Technique to see matching MITRE techniques.</div>
      </div>
    `;
    this.loadMitreMatrix();
  },

  async loadMitreMatrix() {
    try {
      const res = await fetch('/api/mitre-summary');
      const data = await res.json();
      const grid = document.getElementById('fullMitreGrid');
      if (!grid) return;

      const heatmap = data.heatmap || [];
      if (heatmap.length === 0) {
        grid.innerHTML = '<div class="empty-td">No ATT&CK data recorded yet. Run log parsing or trigger an alert.</div>';
        return;
      }

      // Group by tactic
      const tactics = {};
      for (const item of heatmap) {
        const tac = item.tactic || 'General';
        if (!tactics[tac]) tactics[tac] = [];
        tactics[tac].push(item);
      }

      grid.innerHTML = Object.entries(tactics).map(([tactic, techniques]) => `
        <div class="tactic-column">
          <div class="tactic-name">${tactic.toUpperCase()}</div>
          <div class="tactic-techniques">
            ${techniques.map(t => {
              const hit = t.count > 0;
              return `
                <div class="technique-card ${hit ? 'hit' : ''}" onclick="views.runCommand('lookup cve ${t.id}', 'mitreResultsBox')">
                  <div class="tech-id">${t.id}</div>
                  <div class="tech-name">${escapeHtml(t.name)}</div>
                  ${hit ? `<span class="tech-badge">${t.count} hit(s)</span>` : ''}
                </div>
              `;
            }).join('')}
          </div>
        </div>
      `).join('');
    } catch (err) {
      const grid = document.getElementById('fullMitreGrid');
      if (grid) grid.innerHTML = `<div class="empty-td">Error loading MITRE data: ${err.message}</div>`;
    }
  },

  // ============================================================
  // 5. PLAYBOOKS VIEW
  // ============================================================
  renderPlaybooksView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◈ INCIDENT RESPONSE PLAYBOOKS</h2>
          <p class="view-subtitle">Automated, step-by-step containment, eradication, and recovery playbooks for active security incidents.</p>
        </div>
      </div>

      <div class="view-grid grid-2">
        <div class="playbook-card border-critical">
          <div class="playbook-header">
            <span class="playbook-icon">🔴</span>
            <div>
              <div class="playbook-name">Ransomware Outbreak Response</div>
              <div class="playbook-id">PLAYBOOK: ransomware</div>
            </div>
            <button class="action-btn btn-danger" onclick="views.runCommand('run playbook ransomware', 'playbookResultsBox')">Execute ↵</button>
          </div>
          <ol class="playbook-steps">
            <li><strong>Phase 1:</strong> Isolate affected network adapter and block egress.</li>
            <li><strong>Phase 2:</strong> Snapshot canary files and inspect mass file alterations.</li>
            <li><strong>Phase 3:</strong> Terminate malicious process tree and kill shadow-copy deletion.</li>
            <li><strong>Phase 4:</strong> Restore from backup vault and trigger n8n incident webhook.</li>
          </ol>
        </div>

        <div class="playbook-card border-warning">
          <div class="playbook-header">
            <span class="playbook-icon">🟠</span>
            <div>
              <div class="playbook-name">SSH / Authentication Brute Force</div>
              <div class="playbook-id">PLAYBOOK: brute_force</div>
            </div>
            <button class="action-btn" onclick="views.runCommand('run playbook brute_force', 'playbookResultsBox')">Execute ↵</button>
          </div>
          <ol class="playbook-steps">
            <li><strong>Phase 1:</strong> Extract attacker IP from syslog / auth.log failed attempts.</li>
            <li><strong>Phase 2:</strong> Query AbuseIPDB to verify attacker threat score.</li>
            <li><strong>Phase 3:</strong> Push automated firewall rule to drop source IP.</li>
            <li><strong>Phase 4:</strong> Invalidate compromised user session tokens and alert Ali.</li>
          </ol>
        </div>

        <div class="playbook-card border-info">
          <div class="playbook-header">
            <span class="playbook-icon">🔵</span>
            <div>
              <div class="playbook-name">Insider Threat Containment</div>
              <div class="playbook-id">PLAYBOOK: insider_threat</div>
            </div>
            <button class="action-btn" onclick="views.runCommand('run playbook insider_threat', 'playbookResultsBox')">Execute ↵</button>
          </div>
          <ol class="playbook-steps">
            <li><strong>Phase 1:</strong> Audit anomalous file access outside normal business hours.</li>
            <li><strong>Phase 2:</strong> Snapshot user permissions and audit group memberships.</li>
            <li><strong>Phase 3:</strong> Revoke active session tokens and elevate logging level.</li>
            <li><strong>Phase 4:</strong> Generate cryptographically signed audit trail.</li>
          </ol>
        </div>

        <div class="playbook-card border-purple">
          <div class="playbook-header">
            <span class="playbook-icon">🟣</span>
            <div>
              <div class="playbook-name">Phishing Email Triage &amp; Purge</div>
              <div class="playbook-id">PLAYBOOK: phishing</div>
            </div>
            <button class="action-btn" onclick="views.runCommand('run playbook phishing', 'playbookResultsBox')">Execute ↵</button>
          </div>
          <ol class="playbook-steps">
            <li><strong>Phase 1:</strong> Extract email headers, SPF/DKIM/DMARC authentication.</li>
            <li><strong>Phase 2:</strong> Extract URLs and submit to URLScan.io and AlienVault OTX.</li>
            <li><strong>Phase 3:</strong> Search inbox for similar sender domains and quarantine.</li>
            <li><strong>Phase 4:</strong> Send user security awareness notification via Ntfy/Slack.</li>
          </ol>
        </div>

        <div class="playbook-card border-success">
          <div class="playbook-header">
            <span class="playbook-icon">🟢</span>
            <div>
              <div class="playbook-name">Malware Detection &amp; Remediation</div>
              <div class="playbook-id">PLAYBOOK: malware_detected</div>
            </div>
            <button class="action-btn" onclick="views.runCommand('run playbook malware_detected', 'playbookResultsBox')">Execute ↵</button>
          </div>
          <ol class="playbook-steps">
            <li><strong>Phase 1:</strong> Quarantine suspect executable file to secure vault.</li>
            <li><strong>Phase 2:</strong> Calculate SHA-256 hash and query VirusTotal API.</li>
            <li><strong>Phase 3:</strong> Scan parent directory with ClamAV / pattern matching.</li>
            <li><strong>Phase 4:</strong> Log MITRE T1204 / T1059 technique and auto-escalate alert.</li>
          </ol>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Live Playbook Narration &amp; Execution Output</div>
        <div class="results-box" id="playbookResultsBox">Click "Execute" on any playbook to run automated containment steps.</div>
      </div>
    `;
  },

  // ============================================================
  // 6. CODE SECURITY VIEW
  // ============================================================
  renderCodeSecurityView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◉ CODE &amp; SUPPLY CHAIN SECURITY</h2>
          <p class="view-subtitle">Static code analysis, TruffleHog secret scanning, and real OSV.dev dependency CVE auditing.</p>
        </div>
      </div>

      <div class="view-grid grid-2">
        <div class="view-card">
          <div class="card-title">🔑 Secret Scanner (TruffleHog &amp; Regex)</div>
          <p class="card-desc">Detect hardcoded API keys, JWTs, AWS credentials, Slack tokens, and private keys.</p>
          <div style="display:flex; gap:8px; margin-top:12px;">
            <input type="text" id="codeSecretPath" class="view-input" style="flex:1" value="." placeholder="Scan path (default .)">
            <button class="action-btn" onclick="views.runCommand('scan secrets in ' + document.getElementById('codeSecretPath').value, 'codeResultsBox')">Scan Secrets</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">📦 Dependency CVE Audit (OSV.dev API)</div>
          <p class="card-desc">Inspect package.json or requirements.txt and query Open Source Vulnerabilities database.</p>
          <div style="display:flex; gap:8px; margin-top:12px;">
            <input type="text" id="codeAuditPath" class="view-input" style="flex:1" value="." placeholder="Project path (default .)">
            <button class="action-btn" onclick="views.runCommand('audit dependencies ' + document.getElementById('codeAuditPath').value, 'codeResultsBox')">Audit Dependencies</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🛡️ Static Application Security Testing (SAST)</div>
          <p class="card-desc">Scan codebase for code injection, path traversal, weak crypto, and dangerous eval calls.</p>
          <div style="display:flex; gap:8px; margin-top:12px;">
            <input type="text" id="codeSastPath" class="view-input" style="flex:1" value="." placeholder="Scan path (default .)">
            <button class="action-btn" onclick="views.runCommand('run sast in ' + document.getElementById('codeSastPath').value, 'codeResultsBox')">Run SAST</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">📋 Software Bill of Materials (SBOM)</div>
          <p class="card-desc">Generate standard CycloneDX-compatible software inventory from dependency manifests.</p>
          <div style="display:flex; gap:8px; margin-top:12px;">
            <button class="action-btn" onclick="views.runCommand('generate sbom in .', 'codeResultsBox')">Generate SBOM</button>
            <button class="action-btn btn-secondary" onclick="views.runCommand('pre-commit check in .', 'codeResultsBox')">Git Pre-commit Hook</button>
          </div>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Code Security Scan Results</div>
        <div class="results-box" id="codeResultsBox">Run a code security scanner above to view findings and CVSS scores here.</div>
      </div>
    `;
  },

  // ============================================================
  // 7. FILE SECURITY VIEW
  // ============================================================
  renderFileSecurityView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◎ FILE SECURITY &amp; ENCRYPTION</h2>
          <p class="view-subtitle">AES-256-GCM file encryption, ClamAV malware scanning, metadata stripping, and secure shredding.</p>
        </div>
      </div>

      <div class="view-grid grid-2">
        <div class="view-card">
          <div class="card-title">🦠 Malware Scanner (ClamAV &amp; Signatures)</div>
          <div class="input-form">
            <input type="text" id="fileMalwarePath" class="view-input" placeholder="Directory or file path" value="data/demo-logs">
            <button class="action-btn" style="margin-top:8px;" onclick="views.runCommand('scan malware in ' + document.getElementById('fileMalwarePath').value, 'fileResultsBox')">Scan for Malware</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🔍 Sensitive Data Discovery</div>
          <div class="input-form">
            <input type="text" id="fileSensitivePath" class="view-input" placeholder="Search directory" value=".">
            <button class="action-btn" style="margin-top:8px;" onclick="views.runCommand('scan sensitive files in ' + document.getElementById('fileSensitivePath').value, 'fileResultsBox')">Find PII / Credit Cards / SSNs</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🔐 File Encryption (AES-256-GCM)</div>
          <div class="input-form">
            <input type="text" id="fileEncryptPath" class="view-input" placeholder="File to encrypt / decrypt" value="README.md">
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="action-btn" onclick="views.runCommand('encrypt file ' + document.getElementById('fileEncryptPath').value, 'fileResultsBox')">Encrypt File</button>
              <button class="action-btn btn-secondary" onclick="views.runCommand('decrypt file ' + document.getElementById('fileEncryptPath').value + '.enc', 'fileResultsBox')">Decrypt File</button>
            </div>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🧹 Metadata Scrubber &amp; Secure Shredder</div>
          <div class="input-form">
            <input type="text" id="fileShredPath" class="view-input" placeholder="File path" value="test_file.tmp">
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="action-btn" onclick="views.runCommand('scrub metadata from ' + document.getElementById('fileShredPath').value, 'fileResultsBox')">Scrub Metadata</button>
              <button class="action-btn btn-danger" onclick="views.runCommand('secure delete ' + document.getElementById('fileShredPath').value, 'fileResultsBox')">3-Pass Secure Delete</button>
            </div>
          </div>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">File Security Operation Results</div>
        <div class="results-box" id="fileResultsBox">Execute a file security action above to inspect output here.</div>
      </div>
    `;
  },

  // ============================================================
  // 8. NETWORK VIEW
  // ============================================================
  renderNetworkView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">⬡ NETWORK &amp; INFRASTRUCTURE DEFENSE</h2>
          <p class="view-subtitle">Live socket connection monitoring, firewall rule audits, persistence checks, and IoT discovery.</p>
        </div>
      </div>

      <div class="view-grid grid-3">
        <div class="view-card">
          <div class="card-title">🌐 Active Sockets &amp; Ports</div>
          <p class="card-desc">Audit all active TCP/UDP connections and flag suspicious remote ports.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('monitor network', 'netResultsBox')">Monitor Network</button>
        </div>

        <div class="view-card">
          <div class="card-title">🧱 Firewall Audit</div>
          <p class="card-desc">Inspect Windows Defender / iptables rules and check for open inbound ports.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('check firewall', 'netResultsBox')">Audit Firewall</button>
        </div>

        <div class="view-card">
          <div class="card-title">🚀 Startup &amp; Persistence</div>
          <p class="card-desc">Audit autorun entries, registry keys, and startup tasks for unauthorized persistence.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('audit startup processes', 'netResultsBox')">Audit Startup Entries</button>
        </div>

        <div class="view-card">
          <div class="card-title">💾 Disk Encryption</div>
          <p class="card-desc">Verify BitLocker / FileVault volume encryption status across all drives.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('check disk encryption', 'netResultsBox')">Check BitLocker</button>
        </div>

        <div class="view-card">
          <div class="card-title">📡 Router &amp; IoT Discovery</div>
          <p class="card-desc">Discover connected IoT devices and audit router administration security.</p>
          <div style="display:flex; gap:8px; margin-top:12px;">
            <button class="action-btn" onclick="views.runCommand('scan iot devices', 'netResultsBox')">Scan IoT Devices</button>
            <button class="action-btn btn-secondary" onclick="views.runCommand('audit router', 'netResultsBox')">Audit Router</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🔄 Backup Verification</div>
          <p class="card-desc">Check system backup health and local backup integrity against tampering.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('verify backups', 'netResultsBox')">Verify Backups</button>
        </div>
      </div>


      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Network Audit Findings</div>
        <div class="results-box" id="netResultsBox">Run any network audit above to display telemetry and connection logs here.</div>
      </div>
    `;
  },

  // ============================================================
  // 9. PRIVACY VIEW
  // ============================================================
  renderPrivacyView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">◈ PRIVACY &amp; CREDENTIAL DEFENSE</h2>
          <p class="view-subtitle">HaveIBeenPwned breach checks (k-anonymity), browser extension audit, and password vault storage.</p>
        </div>
      </div>

      <div class="view-grid grid-2">
        <div class="view-card">
          <div class="card-title">🔓 HaveIBeenPwned Breach Lookup</div>
          <p class="card-desc">Check if your email or account credentials have appeared in public data breaches.</p>
          <div class="input-form" style="margin-top:12px;">
            <input type="email" id="privacyEmailInput" class="view-input" placeholder="e.g. test@example.com" value="test@example.com">
            <button class="action-btn" style="margin-top:8px;" onclick="views.runCommand('check breach status for ' + document.getElementById('privacyEmailInput').value, 'privacyResultsBox')">Check Breach Status</button>
          </div>
        </div>

        <div class="view-card">
          <div class="card-title">🧩 Browser Extension Security Audit</div>
          <p class="card-desc">Inspect installed Chrome / Edge extensions and audit high-risk permissions.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('audit browser extensions', 'privacyResultsBox')">Audit Installed Extensions</button>
        </div>

        <div class="view-card">
          <div class="card-title">📧 Phishing Email Triage</div>
          <p class="card-desc">Analyze raw email headers, SPF/DKIM/DMARC alignment, and detect deceptive sender domains.</p>
          <button class="action-btn" style="margin-top:12px;" onclick="views.runCommand('triage phishing email data/demo-logs/phishing_sample.eml', 'privacyResultsBox')">Analyze Sample Email</button>
        </div>

        <div class="view-card">
          <div class="card-title">🗝️ Argon2id Encrypted Vault</div>
          <p class="card-desc">Securely store and retrieve sensitive secrets encrypted with AES-256-GCM.</p>
          <div style="display:flex; gap:8px; margin-top:12px;">
            <input type="text" id="vaultKeyInput" class="view-input" style="flex:1" placeholder="Key name (e.g. api_token)">
            <input type="password" id="vaultValInput" class="view-input" style="flex:1" placeholder="Secret value">
            <button class="action-btn" onclick="views.runCommand('store in vault key ' + document.getElementById('vaultKeyInput').value + ' value ' + document.getElementById('vaultValInput').value, 'privacyResultsBox')">Store</button>
          </div>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">Privacy Audit Results</div>
        <div class="results-box" id="privacyResultsBox">Run a privacy check above to display results here.</div>
      </div>
    `;
  },

  // ============================================================
  // 10. REPORTS VIEW
  // ============================================================
  async renderReportsView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">⬟ SOC INCIDENT REPORTS &amp; COMPLIANCE</h2>
          <p class="view-subtitle">Cryptographically signed incident reports with SHA-256 verification and CVSS summary metrics.</p>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="action-btn" onclick="views.loadReportView()">⚡ Generate Fresh Report</button>
          <button class="action-btn btn-secondary" onclick="window.print()">🖨️ Print / Export PDF</button>
        </div>
      </div>

      <div class="view-card" style="margin-top:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:8px; margin-bottom:12px;">
          <div id="reportMetaBadge">Loading report metadata...</div>
          <div id="reportShaBadge" style="font-family:var(--font-mono); font-size:11px; color:var(--accent-primary);"></div>
        </div>
        <div class="report-content-box" id="reportContentArea">
          <div class="loading-td">Generating complete SOC report...</div>
        </div>
      </div>
    `;
    this.loadReportView();
  },

  async loadReportView() {
    try {
      const res = await fetch('/api/report');
      const data = await res.json();
      const meta = document.getElementById('reportMetaBadge');
      const sha = document.getElementById('reportShaBadge');
      const content = document.getElementById('reportContentArea');

      if (meta) {
        meta.innerHTML = `<strong>${data.reportId || 'RPT-2026'}</strong> | Risk: <span class="alert-sev sev-${data.stats?.riskPosture || 'LOW'}">${data.stats?.riskPosture || 'LOW'}</span> (${data.stats?.riskScore || 0}/100) | Actions: ${data.stats?.totalActions || 0}`;
      }
      if (sha) {
        sha.innerHTML = `SHA-256: <code>${(data.hash || '').substring(0, 24)}...</code>`;
      }
      if (content) {
        content.innerHTML = `<pre class="report-pre">${escapeHtml(data.report || 'No report data')}</pre>`;
      }
    } catch (err) {
      const content = document.getElementById('reportContentArea');
      if (content) content.innerHTML = `<div class="empty-td">Failed to generate report: ${err.message}</div>`;
    }
  },

  // ============================================================
  // 11. N8N WORKFLOWS VIEW
  // ============================================================
  async renderN8nView(target) {
    target.innerHTML = `
      <div class="view-header">
        <div>
          <h2 class="view-title">⬡ N8N WORKFLOW AUTOMATION HUB</h2>
          <p class="view-subtitle">8 automated webhook triggers connecting Jarvis SOC to n8n, Slack, Google Sheets, and Ntfy.</p>
        </div>
        <a href="http://localhost:5678" target="_blank" class="action-btn">Open n8n UI ↗</a>
      </div>

      <div class="view-grid grid-2">
        <div class="view-card">
          <div class="card-title">Trigger 1: Critical Security Alerts</div>
          <p class="card-desc">Fires immediately when any CRITICAL alert is generated or detected.</p>
          <button class="action-btn btn-danger" style="margin-top:8px;" onclick="views.testN8nTrigger('critical_alert')">Trigger Test Alert Webhook</button>
        </div>

        <div class="view-card">
          <div class="card-title">Trigger 2: Watch-Drop Directory Ingestion</div>
          <p class="card-desc">Fires within 500ms when any file is placed into <code>data/watch-drop/</code>.</p>
          <button class="action-btn" style="margin-top:8px;" onclick="views.testN8nTrigger('file_drop')">Trigger File-Drop Webhook</button>
        </div>

        <div class="view-card">
          <div class="card-title">Trigger 3: Incident Response Playbook</div>
          <p class="card-desc">Logs playbook execution timeline and containment steps to external tickets.</p>
          <button class="action-btn" style="margin-top:8px;" onclick="views.testN8nTrigger('incident_response')">Trigger Playbook Webhook</button>
        </div>

        <div class="view-card">
          <div class="card-title">Trigger 4: Weekly SOC Executive Briefing</div>
          <p class="card-desc">Scheduled cron job compiling 7-day incident summaries and risk posture.</p>
          <button class="action-btn btn-secondary" style="margin-top:8px;" onclick="views.testN8nTrigger('weekly_briefing')">Trigger Weekly Briefing Webhook</button>
        </div>
      </div>

      <div class="view-card" style="margin-top:16px;">
        <div class="card-title">n8n Webhook Output &amp; Live Telemetry</div>
        <div class="results-box" id="n8nResultsBox" style="margin-bottom:12px;">Click a trigger test button above to send a live webhook.</div>
        <div class="table-wrap">
          <table class="view-table">
            <thead>
              <tr>
                <th>WORKFLOW</th>
                <th>ENDPOINT</th>
                <th>DESCRIPTION</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>critical_alert</strong></td>
                <td><code>POST /webhook/critical_alert</code></td>
                <td>High &amp; Critical alert dispatch to SIEM</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('critical_alert')">Test</button></td>
              </tr>
              <tr>
                <td><strong>incident_response</strong></td>
                <td><code>POST /webhook/incident_response</code></td>
                <td>Playbook post-incident ticketing</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('incident_response')">Test</button></td>
              </tr>
              <tr>
                <td><strong>file_drop</strong></td>
                <td><code>POST /webhook/file_drop</code></td>
                <td>Automatic quarantine &amp; scan pipeline</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('file_drop')">Test</button></td>
              </tr>
              <tr>
                <td><strong>weekly_briefing</strong></td>
                <td><code>POST /webhook/weekly_briefing</code></td>
                <td>Weekly executive SOC metrics export</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('weekly_briefing')">Test</button></td>
              </tr>
              <tr>
                <td><strong>threat_intel_hit</strong></td>
                <td><code>POST /webhook/threat_intel_hit</code></td>
                <td>AbuseIPDB/VT malicious IOC ingestion</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('threat_intel_hit')">Test</button></td>
              </tr>
              <tr>
                <td><strong>canary_triggered</strong></td>
                <td><code>POST /webhook/canary_triggered</code></td>
                <td>Canary tripwire ransomware alert</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('canary_triggered')">Test</button></td>
              </tr>
              <tr>
                <td><strong>report_generated</strong></td>
                <td><code>POST /webhook/report_generated</code></td>
                <td>Audit report archiving &amp; hash signing</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('report_generated')">Test</button></td>
              </tr>
              <tr>
                <td><strong>daily_patch_audit</strong></td>
                <td><code>POST /webhook/daily_patch_audit</code></td>
                <td>OS &amp; CVE patch compliance check</td>
                <td><button class="btn-xs" onclick="views.testN8nTrigger('daily_patch_audit')">Test</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  // Helper to parse custom logs
  parseCustomLog(type) {
    const input = document.getElementById('customLogPath');
    const customPath = (input && input.value.trim()) ? input.value.trim() : '';

    if (type === 'web') {
      this.runCommand('parse web server log ' + (customPath || 'data/demo-logs/access.log'), 'logResultsBox');
    } else if (type === 'syslog') {
      this.runCommand('parse linux syslog ' + (customPath || 'data/demo-logs/auth.log'), 'logResultsBox');
    } else if (type === 'windows') {
      this.runCommand('parse windows event log ' + (customPath || 'data/demo-logs/windows_events.txt'), 'logResultsBox');
    }
  },

  // Helper to test n8n webhooks
  async testN8nTrigger(workflowName) {
    const box = document.getElementById('n8nResultsBox');
    if (box) {
      box.innerHTML = `<div class="loading-td"><span class="pulse-dot"></span> Dispatching n8n webhook: <code>${escapeHtml(workflowName)}</code>...</div>`;
    }
    try {
      let data = null;

      // 1. Try dedicated endpoint first
      try {
        const res = await fetch(`/api/n8n/trigger/${workflowName}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({}),
        });

        const contentType = res.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          data = await res.json();
        }
      } catch {}

      // 2. If endpoint not available on running process, fallback to /api/command
      if (!data) {
        const cmdRes = await fetch('/api/command', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: `trigger n8n webhook ${workflowName}` }),
        });
        const cmdJson = await cmdRes.json();
        data = cmdJson.result || {
          workflowName,
          url: `http://localhost:5678/webhook/${workflowName}`,
          status: cmdJson.status === 'completed' ? 'SUCCESS' : (cmdJson.status || 'TRIGGERED'),
          payload: { workflow: workflowName, timestamp: new Date().toISOString() },
        };
      }

      if (box) {
        const statusVal = data.status || (data.triggered ? 200 : 'OK');
        const isSuccess = statusVal === 200 || statusVal === 'SUCCESS' || statusVal === 'TRIGGERED' || data.triggered;
        box.innerHTML = `
          <div style="color:var(--accent-primary); font-weight:600; margin-bottom:6px;">⚡ Webhook Dispatched: <code>${escapeHtml(data.workflowName || workflowName)}</code></div>
          <div style="font-size:12px; margin-bottom:4px;">Endpoint: <code>${escapeHtml(data.url || 'http://localhost:5678/webhook/' + workflowName)}</code></div>
          <div style="font-size:12px; margin-bottom:6px;">Status: <span class="status-tag ${isSuccess ? 'status-active' : 'status-failed'}">${typeof statusVal === 'number' ? 'HTTP ' + statusVal : escapeHtml(String(statusVal))}</span></div>
          <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px;">Payload Sent:</div>
          <pre class="results-pre" style="max-height:180px; overflow:auto;">${escapeHtml(JSON.stringify(data.payload || {}, null, 2))}</pre>
        `;
      }
    } catch (err) {
      if (box) box.innerHTML = `<div class="empty-td">Webhook dispatch notice: ${escapeHtml(err.message)}</div>`;
    }
  },

};

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

