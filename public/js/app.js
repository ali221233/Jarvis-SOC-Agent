// ============================================================
// Jarvis SOC — Main Application Controller
// Manages UI state, WebSocket, API calls, routing.
// ============================================================

const app = {
  ws: null,
  currentCategory: 'all',
  currentSection: 'overview',
  pendingConfirmation: null,
  commandHistory: [],
  historyIndex: -1,
  sessionStart: Date.now(),

  // ---- Initialization ----
  async init() {
    this.connectWebSocket();
    this.updateClock();
    setInterval(() => this.updateClock(), 1000);
    setInterval(() => this.updateSessionTimer(), 1000);
    await this.checkStatus();
    terminal.init();
    panels.init();

    // Wire command input
    const inp = document.getElementById('commandInput');
    if (inp) {
      inp.addEventListener('input', () => {
        const hint = document.getElementById('enterHint');
        if (hint) hint.classList.toggle('visible', inp.value.trim().length > 0);
      });
    }

    // Start SOC panel refresh loop
    this.refreshSocPanels();
    setInterval(() => this.refreshSocPanels(), 15000);
    setInterval(() => this.refreshWatcherStatus(), 30000);
    setInterval(() => this.refreshN8nPanel(), 20000);

    // Initial watcher + n8n refresh
    setTimeout(() => this.refreshWatcherStatus(), 2000);
    setTimeout(() => this.refreshN8nPanel(), 3000);
    setTimeout(() => this.refreshTtsStatus(), 4000);
    setTimeout(() => this.refreshNotifStatus(), 4000);
  },

  // ---- WebSocket ----
  connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.ws = new WebSocket(`${protocol}//${window.location.host}`);

    this.ws.onopen = () => {
      console.log('[WS] Connected');
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.handleWsMessage(data);
      } catch { /* ignore malformed */ }
    };

    this.ws.onclose = () => {
      console.log('[WS] Disconnected — reconnecting in 3s');
      setTimeout(() => this.connectWebSocket(), 3000);
    };

    this.ws.onerror = () => {
      console.error('[WS] Error');
    };
  },

  handleWsMessage(data) {
    switch (data.type) {
      case 'tts_audio':
        // Kokoro TTS audio — play via voice.js
        if (typeof voice !== 'undefined') voice.handleTTSMessage(data);
        break;
      case 'tts_speak':
        // Web Speech API fallback
        if (typeof voice !== 'undefined') voice.handleTTSMessage(data);
        break;
      case 'thinking':
        this.setStatus('thinking', data.message || 'Thinking...');
        terminal.addLine(data.message, 'system');
        break;
      case 'alert':
        this.setStatus('offline', 'ALERT');
        terminal.addLine(`⚠️ ALERT: ${data.message}`, 'error');
        panels.addFinding({
          severity: data.severity || 'critical',
          title: data.type === 'canary_trigger' ? 'Canary Triggered' : 'Mass File Change',
          detail: data.message,
        });
        break;
      case 'canary_trigger':
        this.showCanaryBanner(data.path || 'unknown path');
        terminal.addLine(`🐦 CANARY TRIGGERED: ${data.message || data.path}`, 'error');
        break;
      case 'watch_drop':
        terminal.addLine(`📂 WATCH-DROP: ${data.message}`, 'warning');
        this.flashN8nPanel();
        break;
      case 'watch_drop_scan':
        if (data.findings && data.findings.length > 0) {
          terminal.addLine(`🔍 ${data.scan.toUpperCase()} SCAN (${data.filename}): ${data.summary}`, 'warning');
        } else {
          terminal.addLine(`✅ ${data.scan.toUpperCase()} SCAN (${data.filename}): Clean`, 'success');
        }
        break;
      case 'alert_created':
        if (typeof socPanels !== 'undefined') socPanels.addAlert(data.alert);
        terminal.addLine(`🚨 Alert created: ${data.alert?.title || 'New alert'}`, 'warning');
        this.refreshSocMetrics();
        this.updateAlertBadge();
        break;
      case 'alert_updated':
      case 'alert_closed':
      case 'alert_escalated':
        if (typeof socPanels !== 'undefined') socPanels.refreshAlerts();
        this.refreshSocMetrics();
        break;
      case 'playbook_narration':
        terminal.addLine(`📋 ${data.message}`, 'system');
        break;
      case 'n8n_trigger':
        this.flashN8nPanel();
        this.addN8nTrigger(data.workflowName, data.status);
        break;
      case 'notification':
        terminal.addLine(`ℹ️ ${data.message}`, data.level === 'warning' ? 'warning' : 'system');
        break;
      case 'progress':
        terminal.addLine(data.message, 'system');
        break;
      default:
        if (data.message) terminal.addLine(data.message, 'system');
    }
  },

  // ---- Status Management ----
  setStatus(state, text) {
    const dot = document.getElementById('statusDot');
    const label = document.getElementById('statusText');
    if (dot) {
      dot.className = 'pulse-dot';
      if (state === 'online') { /* keep default */ }
      else if (state === 'offline') dot.classList.add('offline');
      else if (state === 'thinking') dot.classList.add('thinking');
    }
    if (label) label.textContent = text || state;
  },

  updateClock() {
    const now = new Date();
    const time = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    const el = document.getElementById('headerTime');
    if (el) el.textContent = time;
  },

  // ---- Initial Status Check ----
  async checkStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();

      // Greeting
      const greetEl = document.getElementById('greeting');
      if (greetEl) greetEl.innerHTML = data.greeting || '';

      // Groq status
      const groqEl = document.getElementById('groqStatus');
      if (data.groq?.available) {
        groqEl.textContent = 'Online';
        groqEl.className = 'value on';
        this.setStatus('online', 'Online');
      } else {
        groqEl.textContent = 'Offline';
        groqEl.className = 'value off';
        this.setStatus('online', 'Online (no LLM)');
      }

      // Vault status
      const vaultEl = document.getElementById('vaultStatus');
      if (data.keyManager?.sessionActive) {
        vaultEl.textContent = 'Unlocked';
        vaultEl.className = 'value on';
      } else if (data.keyManager?.initialized) {
        vaultEl.textContent = 'Locked';
        vaultEl.className = 'value off';
        document.getElementById('unlockOverlay').classList.remove('hidden');
      } else {
        vaultEl.textContent = 'Not Set Up';
        vaultEl.className = 'value unknown';
        document.getElementById('setupOverlay').classList.remove('hidden');
      }

      // Tool counts
      if (data.tools?.byCategory) {
        const cats = data.tools.byCategory;
        document.getElementById('badgeAll').textContent = data.tools.total || 0;
        document.getElementById('badgeCode').textContent = cats.code || 0;
        document.getElementById('badgeFiles').textContent = cats.files || 0;
        document.getElementById('badgeNetwork').textContent = cats.network || 0;
        document.getElementById('badgePrivacy').textContent = cats.privacy || 0;
        document.getElementById('badgeDefense').textContent = cats.defense || 0;
        const socBadge = document.getElementById('badgeSoc');
        if (socBadge) socBadge.textContent = cats.soc || 0;
      }

      // Welcome message
      terminal.addLine(data.greeting || 'Jarvis SOC online.', 'jarvis');

      if (data.groq?.available) {
        terminal.addLine(`LLM: ${data.groq.model || 'llama-3.3-70b-versatile'} via Groq LPU — instant inference.`, 'system');
      } else {
        terminal.addLine('Groq offline — using pattern matching only. Set GROQ_API_KEY for full reasoning.', 'warning');
      }

      terminal.addLine(`${data.tools?.total || 0} tools loaded. SOC dashboard active.`, 'system');

    } catch (err) {
      this.setStatus('offline', 'Cannot reach server');
      terminal.addLine('Cannot reach Jarvis server. Is it running?', 'error');
    }
  },

  // ---- SOC Panel Refresh ----
  async refreshSocPanels() {
    if (typeof socPanels !== 'undefined') {
      socPanels.refreshAlerts();
      socPanels.refreshMitre();
      socPanels.refreshThreatIntel();
    }
    this.refreshSocMetrics();
  },

  async refreshSocMetrics() {
    try {
      const res = await fetch('/api/soc-metrics');
      const data = await res.json();

      const el = (id) => document.getElementById(id);
      if (el('metricOpenAlertsVal')) el('metricOpenAlertsVal').textContent = data.openAlerts || 0;
      if (el('metricResolvedTodayVal')) el('metricResolvedTodayVal').textContent = data.resolvedToday || 0;
      if (el('metricMitreVal')) el('metricMitreVal').textContent = data.mitreTechniques || 0;
      if (el('metricRiskVal')) el('metricRiskVal').textContent = data.riskScore || 0;

      // Update risk gauge
      this.updateRiskGauge(data.riskScore || 0);

      // Color-code metrics
      const openEl = el('metricOpenAlertsVal');
      if (openEl) {
        const openCount = data.openAlerts || 0;
        openEl.style.color = openCount > 3 ? 'var(--accent-danger)' : openCount > 0 ? 'var(--accent-warning)' : '';
        const openCard = document.getElementById('metricOpenAlerts');
        if (openCard) openCard.className = 'metric-card' + (openCount > 3 ? ' critical' : openCount > 0 ? ' elevated' : '');
      }
      const riskEl = el('metricRiskVal');
      if (riskEl) {
        riskEl.style.color = data.riskScore >= 75 ? 'var(--accent-danger)' : data.riskScore >= 50 ? 'var(--accent-warning)' : data.riskScore >= 25 ? 'var(--accent-warning)' : 'var(--accent-primary)';
      }

      // Update threat thermometer
      this.updateThreatThermometer(data.riskScore || 0);

      // Update nav alert badge
      const alertBadge = document.getElementById('alertNavBadge');
      if (alertBadge) alertBadge.textContent = data.openAlerts || 0;

    } catch { /* silent fail on metrics */ }
  },

  updateRiskGauge(score) {
    this.updateThreatThermometer(score);
    // Keep legacy arc for any old HTML that might still reference it
    const arc = document.getElementById('riskArc');
    const scoreText = document.getElementById('riskScoreText');
    const label = document.getElementById('riskLabel');
    if (!arc) return;
    const dashLen = (score / 100) * 173;
    arc.setAttribute('stroke-dasharray', `${dashLen} 173`);
    let color = 'var(--accent-success)';
    if (score >= 75) color = 'var(--accent-danger)';
    else if (score >= 50) color = 'var(--accent-warning)';
    arc.setAttribute('stroke', color);
    if (scoreText) scoreText.textContent = score;
  },

  updateThreatThermometer(score) {
    // Thermometer fill: higher score = more red visible (less black cover)
    const fill = document.getElementById('thermoFill');
    const scoreEl = document.getElementById('thermoScore');
    if (!fill || !scoreEl) return;

    const pct = Math.min(100, Math.max(0, score));
    fill.style.height = `${100 - pct}%`;
    scoreEl.textContent = Math.round(score);

    const color = score >= 75 ? 'var(--accent-danger)'
      : score >= 50 ? 'var(--accent-warning)'
      : score >= 25 ? 'var(--accent-info)'
      : 'var(--accent-success)';
    scoreEl.style.color = color;
  },

  // ---- Command Execution ----
  async sendCommand(command) {
    if (!command.trim()) return;

    this.commandHistory.push(command);
    this.historyIndex = this.commandHistory.length;
    terminal.addLine(command, 'user');
    this.setStatus('thinking', 'Processing...');

    try {
      const res = await fetch('/api/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      });
      const data = await res.json();

      this.setStatus('online', 'Online');

      // Handle pending confirmation
      if (data.status === 'pending_confirmation') {
        this.showConfirmationModal(data);
        terminal.addLine(data.message || `Action requires Tier ${data.tier} confirmation.`, 'warning');
        return;
      }

      // Display response
      if (data.response) {
        terminal.addLine(data.response, 'jarvis');
      }

      // Display tool results
      if (data.toolResults) {
        for (const tr of data.toolResults) {
          if (tr.status === 'pending_confirmation') {
            this.showConfirmationModal(tr);
            terminal.addLine(tr.message || `${tr.tool} requires Tier ${tr.tier} confirmation.`, 'warning');
          } else if (tr.result) {
            this.displayToolResult(tr.tool, tr.result);
          }
        }
      } else if (data.result && data.tool) {
        this.displayToolResult(data.tool, data.result);
      }

      // Update panels
      panels.refreshHistory();
      this.refreshSocPanels();

      if (data.source) {
        const sourceLabel = data.source === 'fast-path' ? '⚡ fast-path' : data.source === 'groq' ? '🧠 groq' : `⚡ ${data.source}`;
        terminal.addLine(`[${sourceLabel}]`, 'system');
      }

    } catch (err) {
      this.setStatus('online', 'Online');
      terminal.addLine(`Error: ${err.message}`, 'error');
    }
  },

  displayToolResult(toolName, result) {
    if (!result) return;

    if (result.status === 'not_implemented') {
      terminal.addLine(`${toolName}: ${result.message}`, 'warning');
      return;
    }

    if (result.error) {
      terminal.addLine(`${toolName}: ${result.error}`, 'error');
      return;
    }

    // Summary line
    if (result.summary) {
      terminal.addLine(`${result.summary}`, 'success');
    }

    // Update active dynamic view results box if present
    const activeResBoxes = ['logResultsBox', 'intelResultsBox', 'playbookResultsBox', 'codeResultsBox', 'fileResultsBox', 'netResultsBox', 'privacyResultsBox', 'mitreResultsBox', 'n8nResultsBox'];
    for (const boxId of activeResBoxes) {
      const box = document.getElementById(boxId);
      if (box) {
        let content = `<div class="res-title">✓ ${escapeHtml(toolName || 'Tool Execution')} Completed</div>`;
        if (result.summary) content += `<p class="res-summary">${escapeHtml(result.summary)}</p>`;

        // Log Parser Statistics (Web, Syslog, Windows)
        if (result.stats && (toolName?.startsWith('parse_') || result.tool?.startsWith('parse_'))) {
          content += `
            <div style="display:flex; flex-wrap:wrap; gap:8px; margin:10px 0;">
              ${Object.entries(result.stats).map(([k, v]) => `
                <div style="background:rgba(255,255,255,0.06); border:1px solid var(--border); padding:4px 8px; border-radius:4px; font-size:11px;">
                  <span style="color:var(--text-muted); text-transform:capitalize;">${escapeHtml(k.replace(/([A-Z])/g, ' $1'))}:</span>
                  <strong style="color:var(--accent-primary); margin-left:4px;">${escapeHtml(String(v))}</strong>
                </div>
              `).join('')}
            </div>
          `;
        }

        // Phishing Email Triage Details
        if (result.verdict && (toolName === 'triage_phishing_email' || result.tool === 'triage_phishing_email')) {
          const sevClass = result.verdict === 'LIKELY_PHISHING' ? 'sev-CRITICAL' : result.verdict === 'SUSPICIOUS' ? 'sev-HIGH' : 'sev-LOW';
          content += `
            <div style="display:flex; gap:12px; align-items:center; margin:10px 0;">
              <span class="alert-sev ${sevClass}">${escapeHtml(result.verdict)}</span>
              <span style="font-size:13px; font-weight:600;">Phishing Score: ${result.score || 0}/100</span>
            </div>
            ${result.headers ? `
              <div style="font-size:11px; background:rgba(0,0,0,0.3); padding:8px; border-radius:4px; margin-bottom:8px;">
                <div><strong>From:</strong> <code>${escapeHtml(result.headers.from || 'Unknown')}</code></div>
                ${result.headers.replyTo ? `<div><strong>Reply-To:</strong> <code>${escapeHtml(result.headers.replyTo)}</code></div>` : ''}
                <div><strong>Subject:</strong> <code>${escapeHtml(result.headers.subject || '')}</code></div>
              </div>` : ''}
          `;
          if (result.indicators && result.indicators.length > 0) {
            content += `<div class="res-findings-list">` + result.indicators.map(ind => `
              <div class="res-finding-item ${ind.severity || 'medium'}">
                <span class="badge-mini">${(ind.severity || 'MED').toUpperCase()}</span>
                <strong>${escapeHtml(ind.type || 'Indicator')}</strong>
                <small>${escapeHtml(ind.word ? 'Keyword: ' + ind.word : ind.url ? 'URL: ' + ind.url : ind.details || '')}</small>
              </div>
            `).join('') + `</div>`;
          }
        }

        // IoT Devices List
        if (result.devices && Array.isArray(result.devices)) {
          content += `
            <div class="table-wrap" style="margin-top:8px;">
              <table class="view-table" style="font-size:11px;">
                <thead><tr><th>IP Address</th><th>MAC Address</th><th>Device Type</th><th>Vendor</th><th>Risk</th></tr></thead>
                <tbody>
                  ${result.devices.map(d => `
                    <tr>
                      <td><code>${escapeHtml(d.ip)}</code></td>
                      <td><code>${escapeHtml(d.mac)}</code></td>
                      <td><strong>${escapeHtml(d.deviceType || 'Device')}</strong></td>
                      <td>${escapeHtml(d.vendor || 'Generic')}</td>
                      <td><span class="alert-sev sev-${d.risk || 'LOW'}">${escapeHtml(d.risk || 'LOW')}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }

        // Router Config Checks
        if (result.checks && Array.isArray(result.checks)) {
          content += `
            <div class="table-wrap" style="margin-top:8px;">
              <table class="view-table" style="font-size:11px;">
                <thead><tr><th>Security Check</th><th>Observed Value</th><th>Status</th><th>Recommendation</th></tr></thead>
                <tbody>
                  ${result.checks.map(c => `
                    <tr>
                      <td><strong>${escapeHtml(c.target)}</strong></td>
                      <td><code>${escapeHtml(c.value)}</code></td>
                      <td><span class="status-tag status-active">${escapeHtml(c.status)}</span></td>
                      <td style="font-size:10px; color:var(--text-muted);">${escapeHtml(c.recommendation || 'Standard')}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `;
        }

        // Backups Verification
        if (result.backupLocations || result.vssShadowCopies !== undefined) {
          content += `
            <div style="display:flex; gap:12px; margin:10px 0; font-size:12px;">
              <div>Status: <span class="status-tag ${result.status === 'VERIFIED' ? 'status-active' : 'status-failed'}">${escapeHtml(result.status || 'VERIFIED')}</span></div>
              <div>VSS Shadow Copies: <strong>${result.vssShadowCopies || 0}</strong></div>
              <div>Backup Files: <strong>${result.totalFiles || 0} (${result.totalSizeMB || 0} MB)</strong></div>
            </div>
          `;
        }

        // Standard Findings
        if (result.findings && result.findings.length > 0 && !result.verdict) {
          content += `<div class="res-findings-list">` + result.findings.slice(0, 15).map(f => `
            <div class="res-finding-item ${f.severity || 'low'}">
              <span class="badge-mini">${(f.severity || 'low').toUpperCase()}</span>
              <strong>${escapeHtml(f.pattern || f.type || f.name || f.malwareName || 'Finding')}</strong>
              ${f.mitre ? `<span style="margin-left:6px; color:var(--accent-primary); font-size:10px;">⚔️ ${escapeHtml(f.mitre)}</span>` : ''}
              <small>${escapeHtml(f.file ? f.file + (f.line ? ':' + f.line : '') : f.details || f.description || f.line || '')}</small>
            </div>
          `).join('') + `</div>`;
        }

        // Playbook Step Results
        if (result.results && (result.playbook || result.tool === 'run_playbook' || toolName === 'run_playbook')) {
          content += `<div class="res-playbook-steps">` + (result.results || []).map(s => `
            <div class="res-step-item ${s.status}">
              <span>${s.status === 'completed' ? '✅' : '⚠️'}</span>
              <strong>Step ${s.step}: ${escapeHtml(s.tool || s.action || 'Step')}</strong>
              <small>${escapeHtml(s.summary || '')}</small>
            </div>
          `).join('') + `</div>`;
        }

        box.innerHTML = content;
      }
    }



    // Findings
    if (result.findings && result.findings.length > 0) {
      for (const f of result.findings.slice(0, 15)) {
        const sev = f.severity || 'low';
        const location = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '';
        terminal.addLine(`  [${sev.toUpperCase()}] ${f.pattern || f.type || f.name || 'Finding'} ${location}`, sev === 'critical' || sev === 'high' || sev === 'CRITICAL' || sev === 'HIGH' ? 'error' : 'warning');

        panels.addFinding({
          severity: sev,
          title: f.pattern || f.type || f.name || 'Finding',
          detail: location || f.description || '',
        });
      }
      if (result.findings.length > 15) {
        terminal.addLine(`  ... and ${result.findings.length - 15} more`, 'system');
      }
    }

    // Alerts created by SOC tools
    if (result.alerts && Array.isArray(result.alerts)) {
      for (const a of result.alerts.slice(0, 5)) {
        terminal.addLine(`  🚨 [${a.severity}] ${a.title}`, a.severity === 'CRITICAL' ? 'error' : 'warning');
      }
    }

    // Playbook results
    if (result.results && result.playbook) {
      terminal.addLine(`Playbook: ${result.name} — ${result.completedSteps}/${result.totalSteps} steps`, 'jarvis');
    }

    // MITRE mapping
    if (result.matches && result.tool === 'map_to_attack') {
      for (const m of result.matches) {
        terminal.addLine(`  ⚔️ ${m.techniqueId} ${m.name} (${m.tactic})`, 'warning');
      }
    }

    // Disclosure
    if (result.disclosure) {
      terminal.addLine(`ℹ️ ${result.disclosure}`, 'system');
    }
  },

  // ---- Category Navigation ----
  setCategory(category) {
    this.currentCategory = category;
    document.querySelectorAll('.nav-item[data-category]').forEach(el => {
      el.classList.toggle('active', el.dataset.category === category);
    });
  },

  setSection(section) {
    this.currentSection = section;
    document.querySelectorAll('.nav-item[data-section]').forEach(el => {
      el.classList.toggle('active', el.dataset.section === section);
    });
    if (typeof views !== 'undefined') {
      views.show(section);
    }
    // Focus terminal input after nav
    const inp = document.getElementById('commandInput');
    if (inp && section === 'overview') inp.focus();
  },


  // ---- Canary Banner ----
  showCanaryBanner(triggeredPath) {
    const banner = document.getElementById('canaryBanner');
    const pathEl = document.getElementById('canaryPath');
    if (banner && pathEl) {
      pathEl.textContent = triggeredPath;
      banner.classList.remove('hidden');
    }
  },

  // ---- Alert Badge ----
  updateAlertBadge() {
    try {
      fetch('/api/soc-metrics').then(r => r.json()).then(data => {
        const badge = document.getElementById('alertNavBadge');
        if (badge) badge.textContent = data.openAlerts || 0;
      });
    } catch {}
  },

  // ---- Watcher Status ----
  async refreshWatcherStatus() {
    try {
      const res = await fetch('/api/monitor/status');
      const data = await res.json();
      const w = data.watchers || {};

      const updateWatcher = (id, state) => {
        const row = document.getElementById(id);
        if (!row) return;
        const dot = row.querySelector('.watcher-dot');
        const stateEl = row.querySelector('.watcher-state');
        const active = state && state.active;
        if (dot) {
          dot.className = 'watcher-dot' + (active ? ' active' : '');
        }
        if (stateEl) {
          stateEl.textContent = active ? 'ACTIVE' : 'OFFLINE';
          stateEl.className = 'watcher-state' + (active ? ' active' : '');
        }
      };

      updateWatcher('watcherLogs', w.logs);
      updateWatcher('watcherCanary', w.canary);
      updateWatcher('watcherNetwork', w.network);
      updateWatcher('watcherProcess', w.process);
      updateWatcher('watcherDrop', w.watchDrop);

      // Update monitoring pill
      const monPill = document.getElementById('pillMonitor');
      const anyActive = w.logs?.active || w.canary?.active || w.network?.active || w.process?.active || w.watchDrop?.active || data.active;
      if (monPill) monPill.className = 'pill' + (anyActive ? ' active' : ' inactive');

    } catch {}

  },

  // ---- TTS Status Pill ----
  async refreshTtsStatus() {
    try {
      const res = await fetch('/api/tts-status');
      const data = await res.json();
      const ttsPill = document.getElementById('pillTts');
      if (ttsPill) {
        ttsPill.className = 'pill' + (data.ready ? ' active' : ' unconfigured');
        const txt = ttsPill.querySelector('.pill-text');
        if (txt) txt.textContent = data.engine === 'kokoro' ? 'KOKORO TTS' : 'WEB TTS';
      }
    } catch {}
  },

  // ---- n8n Panel ----
  async refreshN8nPanel() {
    try {
      const res = await fetch('/api/n8n/status');
      const data = await res.json();

      const connDot = document.getElementById('n8nConnDot');
      const connLabel = document.getElementById('n8nConnLabel');
      const countEl = document.getElementById('n8nTriggeredCount');
      const n8nBadge = document.getElementById('n8nNavBadge');
      const n8nPill = document.getElementById('pillN8n');

      if (connDot) connDot.className = 'n8n-conn-dot' + (data.connected ? ' connected' : ' offline');
      if (connLabel) connLabel.textContent = data.connected ? 'CONNECTED' : 'OFFLINE';
      if (countEl) countEl.textContent = data.workflowsTriggered || 0;
      if (n8nBadge) n8nBadge.textContent = data.workflowsTriggered || 0;
      if (n8nPill) n8nPill.className = 'pill' + (data.connected ? ' active' : ' unconfigured');

      // Render recent triggers
      const list = document.getElementById('n8nTriggerList');
      if (list && data.recentTriggers) {
        if (data.recentTriggers.length === 0) {
          list.innerHTML = '<div class="empty-state-sm">No triggers yet</div>';
        } else {
          list.innerHTML = data.recentTriggers.slice(0, 5).map(t => {
            const success = t.status === 'SUCCESS';
            const time = new Date(t.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
            return `<div class="n8n-trigger-item">
              <span class="n8n-trigger-name">${t.workflowName}</span>
              <span class="n8n-trigger-status ${success ? 'success' : 'failed'}">${t.status}</span>
              <span class="n8n-trigger-time">${time}</span>
            </div>`;
          }).join('');
        }
      }
    } catch {}
  },

  flashN8nPanel() {
    const panel = document.getElementById('n8nPanel');
    if (panel) {
      panel.classList.add('triggered');
      setTimeout(() => panel.classList.remove('triggered'), 2000);
    }
  },

  addN8nTrigger(name, status) {
    const list = document.getElementById('n8nTriggerList');
    if (!list) return;
    const empty = list.querySelector('.empty-state-sm');
    if (empty) empty.remove();
    const item = document.createElement('div');
    item.className = 'n8n-trigger-item';
    const time = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    const success = status === 'SUCCESS';
    item.innerHTML = `<span class="n8n-trigger-name">${name}</span><span class="n8n-trigger-status ${success ? 'success' : 'failed'}">${status}</span><span class="n8n-trigger-time">${time}</span>`;
    list.prepend(item);
    if (list.children.length > 5) list.lastChild.remove();
    const count = document.getElementById('n8nTriggeredCount');
    if (count) count.textContent = parseInt(count.textContent || '0') + 1;
    this.flashN8nPanel();
  },

  // ---- Notification Status ----
  async refreshNotifStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      const ntfy = data.ntfy || {};
      const notifNtfy = document.getElementById('notifNtfy');
      if (notifNtfy) notifNtfy.className = 'notif-item' + (ntfy.configured ? ' active' : '');

      const email = data.email || {};
      const notifEmail = document.getElementById('notifEmail');
      if (notifEmail) notifEmail.className = 'notif-item' + (email.configured ? ' active' : '');

      const slack = data.slack || {};
      const notifSlack = document.getElementById('notifSlack');
      if (notifSlack) notifSlack.className = 'notif-item' + (slack.configured ? ' active' : '');

      // Update pills
      const ntfyPill = document.getElementById('pillNtfy');
      if (ntfyPill) ntfyPill.className = 'pill' + (ntfy.configured ? ' active' : ' unconfigured');
      const groqPill = document.getElementById('pillGroq');
      if (groqPill) groqPill.className = 'pill' + (data.groq?.available ? ' active' : ' inactive');
      const dbPill = document.getElementById('pillDb');
      if (dbPill) dbPill.className = 'pill active';
    } catch {}
  },

  // ---- Session Timer ----
  updateSessionTimer() {
    const el = document.getElementById('sessionTimer');
    if (!el) return;
    const secs = Math.floor((Date.now() - this.sessionStart) / 1000);
    const h = Math.floor(secs / 3600).toString().padStart(2, '0');
    const m = Math.floor((secs % 3600) / 60).toString().padStart(2, '0');
    const s = (secs % 60).toString().padStart(2, '0');
    el.textContent = `${h}:${m}:${s}`;
  },

  // ---- Passphrase Management ----
  async initializePassphrase() {
    const pass = document.getElementById('setupPassphrase').value;
    const confirm = document.getElementById('setupPassphraseConfirm').value;

    if (!pass || pass.length < 8) {
      alert('Passphrase must be at least 8 characters.');
      return;
    }
    if (pass !== confirm) {
      alert('Passphrases do not match.');
      return;
    }

    try {
      const res = await fetch('/api/passphrase/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase: pass }),
      });
      const data = await res.json();

      if (data.success) {
        document.getElementById('setupOverlay').classList.add('hidden');
        document.getElementById('vaultStatus').textContent = 'Unlocked';
        document.getElementById('vaultStatus').className = 'value on';
        terminal.addLine(`Vault initialized (${data.method}). Session key active.`, 'success');
      } else {
        alert(data.error || 'Initialization failed.');
      }
    } catch (err) {
      alert('Failed to initialize: ' + err.message);
    }
  },

  async unlockVault() {
    const pass = document.getElementById('unlockPassphrase').value;
    if (!pass) return;

    try {
      const res = await fetch('/api/passphrase/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase: pass }),
      });
      const data = await res.json();

      if (data.verified) {
        document.getElementById('unlockOverlay').classList.add('hidden');
        document.getElementById('vaultStatus').textContent = 'Unlocked';
        document.getElementById('vaultStatus').className = 'value on';
        terminal.addLine('Vault unlocked. Encryption tools ready.', 'success');
      } else {
        alert(data.message || 'Incorrect passphrase.');
      }
    } catch (err) {
      alert('Failed to unlock: ' + err.message);
    }
  },

  skipSetup() {
    document.getElementById('setupOverlay').classList.add('hidden');
    document.getElementById('unlockOverlay').classList.add('hidden');
    terminal.addLine('Vault skipped — encryption tools disabled until passphrase is set.', 'warning');
  },

  // ---- Confirmation Modal ----
  showConfirmationModal(data) {
    this.pendingConfirmation = data;
    if (data.tier === 2) {
      const modal = document.getElementById('tier2Modal');
      const desc = document.getElementById('tier2Desc');
      if (desc) desc.textContent = data.message || `Confirm execution of ${data.toolName || data.tool || 'Action'}`;
      if (modal) modal.classList.remove('hidden');
    } else if (data.tier === 3) {
      const modal = document.getElementById('tier3Modal');
      const desc = document.getElementById('tier3Desc');
      if (desc) desc.textContent = data.message || `Confirm irreversible execution of ${data.toolName || data.tool || 'Action'}`;
      document.getElementById('tier3FirstStep')?.classList.remove('hidden');
      document.getElementById('tier3SecondStep')?.classList.add('hidden');
      if (modal) modal.classList.remove('hidden');
    }
  },

  async submitConfirmation(passphrase = null) {
    if (!this.pendingConfirmation) return;
    const actionId = this.pendingConfirmation.actionId;

    try {
      const res = await fetch(`/api/confirm/${actionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase }),
      });
      const data = await res.json();

      document.getElementById('tier2Modal')?.classList.add('hidden');
      document.getElementById('tier3Modal')?.classList.add('hidden');

      if (data.status === 'completed') {
        terminal.addLine('Action confirmed and executed.', 'success');
        if (data.result) this.displayToolResult(this.pendingConfirmation.tool || this.pendingConfirmation.toolName || '', data.result);
        this.pendingConfirmation = null;
        panels.refreshHistory();
        this.refreshSocPanels();
      } else if (data.status === 'pending_confirmation') {
        terminal.addLine(data.message, 'warning');
      } else if (data.error) {
        terminal.addLine(`Confirmation failed: ${data.error}`, 'error');
      }
    } catch (err) {
      terminal.addLine(`Error: ${err.message}`, 'error');
    }
  },


  cancelConfirmation() {
    if (this.pendingConfirmation?.actionId) {
      fetch(`/api/pending/${this.pendingConfirmation.actionId}`, { method: 'DELETE' });
    }
    document.getElementById('confirmModal')?.classList.add('hidden');
    document.getElementById('tier2Modal')?.classList.add('hidden');
    document.getElementById('tier3Modal')?.classList.add('hidden');
    this.pendingConfirmation = null;
    terminal.addLine('Action cancelled.', 'system');
  },

  cancelTier2() { this.cancelConfirmation(); },
  cancelTier3() { this.cancelConfirmation(); },

  confirmTier2() {
    document.getElementById('tier2Modal')?.classList.add('hidden');
    this.submitConfirmation();
  },

  firstConfirmTier3() {
    document.getElementById('tier3FirstStep')?.classList.add('hidden');
    document.getElementById('tier3SecondStep')?.classList.remove('hidden');
    document.getElementById('tier3Passphrase')?.focus();
  },

  confirmTier3() {
    const pass = document.getElementById('tier3Passphrase')?.value;
    if (!pass) { alert('Passphrase required.'); return; }
    document.getElementById('tier3Modal')?.classList.add('hidden');
    this.submitConfirmation(pass);
  },

  // ---- Sidebar Actions ----
  async showHistory() {
    try {
      const res = await fetch('/api/history?limit=30');
      const data = await res.json();
      terminal.addLine('── Action History ──', 'system');
      if (data.history?.length) {
        for (const h of data.history) {
          const time = new Date(h.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
          terminal.addLine(`  [T${h.tier}] ${time} — ${h.summary}`, h.status === 'error' ? 'error' : 'jarvis');
        }
      } else {
        terminal.addLine('  No actions recorded yet.', 'system');
      }
    } catch { terminal.addLine('Failed to load history.', 'error'); }
  },

  async generateReport() {
    terminal.addLine('Generating SOC report...', 'system');
    try {
      const res = await fetch('/api/report');
      const data = await res.json();
      if (data.report) {
        terminal.addLine('── SOC Incident Report ──', 'system');
        const lines = data.report.split('\n');
        for (const line of lines) {
          if (line.startsWith('#')) terminal.addLine(line, 'jarvis');
          else if (line.includes('CRITICAL') || line.includes('🔴')) terminal.addLine(line, 'error');
          else if (line.includes('HIGH') || line.includes('⚠️')) terminal.addLine(line, 'warning');
          else if (line.includes('✅')) terminal.addLine(line, 'success');
          else terminal.addLine(line, 'system');
        }
        terminal.addLine(`SHA-256: ${data.hash}`, 'system');
      }
    } catch { terminal.addLine('Failed to generate report.', 'error'); }
  },

  async showPending() {
    try {
      const res = await fetch('/api/pending');
      const data = await res.json();
      terminal.addLine('── Pending Actions ──', 'system');
      if (data.pending?.length) {
        for (const p of data.pending) {
          terminal.addLine(`  [T${p.tier}] ${p.toolName} — ${p.description.substring(0, 60)}`, 'warning');
        }
      } else {
        terminal.addLine('  No pending actions.', 'system');
      }
    } catch { terminal.addLine('Failed to load pending actions.', 'error'); }
  },

  async checkGroqHealth() {
    terminal.addLine('Checking Groq status...', 'system');
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      if (data.groq?.available) {
        terminal.addLine(`Groq: Online — ${data.groq.message || 'LPU inference ready'}`, 'success');
      } else {
        terminal.addLine(`Groq: Offline — ${data.groq?.error || 'Set GROQ_API_KEY in .env'}`, 'error');
      }
    } catch { terminal.addLine('Failed to check Groq.', 'error'); }
  },

  async checkVaultStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      const km = data.keyManager;
      if (km?.sessionActive) {
        terminal.addLine('Vault: Unlocked and active.', 'success');
      } else if (km?.initialized) {
        terminal.addLine('Vault: Locked — enter passphrase to unlock.', 'warning');
      } else {
        terminal.addLine('Vault: Not initialized — set up a master passphrase.', 'warning');
      }
    } catch { terminal.addLine('Failed to check vault.', 'error'); }
  },
};

// Boot
document.addEventListener('DOMContentLoaded', () => app.init());
