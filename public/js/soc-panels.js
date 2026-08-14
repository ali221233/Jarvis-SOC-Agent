// ============================================================
// Jarvis SOC — SOC Panel Controllers
// Alert queue, MITRE heatmap, threat intel, metrics bar.
// ============================================================

const socPanels = {

  // ---- Alert Queue ----
  async refreshAlerts() {
    try {
      const res = await fetch('/api/alerts');
      const data = await res.json();
      this.renderAlerts(data.alerts || []);
      const count = document.getElementById('alertQueueCount');
      if (count) count.textContent = data.total || 0;
      const badge = document.getElementById('badgePending');
      if (badge) badge.textContent = data.total || 0;
    } catch { /* silent */ }
  },

  renderAlerts(alerts) {
    const list = document.getElementById('alertQueueList');
    if (!list) return;

    if (alerts.length === 0) {
      list.innerHTML = '<div class="empty-state">No open alerts — all clear, Boss.</div>';
      return;
    }

    list.innerHTML = alerts.map(a => {
      const sevClass = (a.severity || 'INFO').toLowerCase();
      const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }) : '';
      return `
      <div class="alert-card ${sevClass}" onclick="socPanels.showAlertDetail('${a.id}')" title="${a.details || ''}">
        <div class="alert-card-top">
          <span class="alert-sev sev-${a.severity}">${a.severity}</span>
          <span class="alert-id">${a.id}</span>
          ${time ? `<span class="alert-meta" style="margin-left:auto">${time}</span>` : ''}
        </div>
        <div class="alert-title">${this.escapeHtml(a.title)}</div>
      </div>
    `;
    }).join('');
  },

  addAlert(alert) {
    if (!alert) return;
    this.refreshAlerts();
  },

  showAlertDetail(id) {
    if (typeof terminal !== 'undefined') {
      terminal.addLine(`Loading alert ${id}...`, 'system');
      fetch(`/api/alerts/${id}`)
        .then(r => r.json())
        .then(a => {
          terminal.addLine(`── Alert ${a.id} ──`, 'system');
          terminal.addLine(`Title: ${a.title}`, 'jarvis');
          terminal.addLine(`Severity: ${a.severity} | Status: ${a.status} | Priority: ${a.priority}`, a.severity === 'CRITICAL' ? 'error' : 'warning');
          terminal.addLine(`Source: ${a.source}`, 'system');
          if (a.details) terminal.addLine(`Details: ${a.details}`, 'system');
          if (a.triageDecision) terminal.addLine(`Triage: ${a.triageDecision}`, 'system');
          if (a.resolution) terminal.addLine(`Resolution: ${a.resolution}`, 'success');
          if (a.mitreMapping?.length) {
            terminal.addLine(`MITRE: ${a.mitreMapping.map(m => m.id).join(', ')}`, 'system');
          }
          if (a.timelineEvents?.length) {
            terminal.addLine('Timeline:', 'system');
            for (const e of a.timelineEvents) {
              const t = new Date(e.time).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
              terminal.addLine(`  ${t} — ${e.event} (${e.actor})`, 'system');
            }
          }
        })
        .catch(() => terminal.addLine(`Failed to load alert ${id}.`, 'error'));
    }
  },

  // ---- MITRE ATT&CK Heatmap ----
  async refreshMitre() {
    try {
      const res = await fetch('/api/mitre-summary');
      const data = await res.json();
      this.renderMitreHeatmap(data.heatmap || []);
    } catch { /* silent */ }
  },

  renderMitreHeatmap(techniques) {
    const grid = document.getElementById('mitreHeatmap') || document.getElementById('mitreGrid');
    if (!grid) return;

    if (techniques.length === 0) {
      grid.innerHTML = '<div class="empty-state-sm">No ATT&CK data yet</div>';
      return;
    }

    const maxCount = Math.max(1, ...techniques.map(t => t.count));

    grid.innerHTML = techniques.map(t => {
      let heatClass = '';
      if (t.count > 0) {
        const pct = t.count / maxCount;
        if (pct > 0.8) heatClass = 'heat-6';
        else if (pct > 0.6) heatClass = 'heat-5';
        else if (pct > 0.4) heatClass = 'heat-4';
        else if (pct > 0.25) heatClass = 'heat-3';
        else if (pct > 0.1) heatClass = 'heat-2';
        else heatClass = 'heat-1';
      }

      return `
        <div class="mitre-cell ${heatClass}" data-id="${t.id}">
          ${t.id.replace('T', '')}
          <div class="mitre-tooltip">${t.id}: ${t.name} (${t.tactic}) — ${t.count} hit${t.count !== 1 ? 's' : ''}</div>
        </div>
      `;
    }).join('');
  },


  // ---- Threat Intel Panel ----
  async refreshThreatIntel() {
    try {
      const res = await fetch('/api/threat-intel');
      const data = await res.json();
      this.renderThreatIntel(data.enrichments || []);
    } catch { /* silent */ }
  },

  renderThreatIntel(enrichments) {
    const list = document.getElementById('threatIntelList');
    if (!list) return;

    if (enrichments.length === 0) {
      list.innerHTML = '<div class="empty-state-small">No enrichments yet</div>';
      return;
    }

    // Show most recent 8
    const recent = enrichments.slice(-8).reverse();

    list.innerHTML = recent.map(e => {
      let scoreHtml = '';
      let flagged = false;

      if (e.type === 'ip') {
        const score = e.abuseScore;
        flagged = e.knownBad;
        scoreHtml = score !== null ? `<span class="threat-intel-score ${flagged ? 'flagged' : 'clean'}">${score}/100</span>` : '';
      } else if (e.type === 'hash') {
        flagged = e.found;
        scoreHtml = `<span class="threat-intel-score ${flagged ? 'flagged' : 'clean'}">${flagged ? '🔴' : '✅'}</span>`;
      } else if (e.type === 'domain') {
        flagged = e.knownBad || e.dgaLikely;
        scoreHtml = `<span class="threat-intel-score ${flagged ? 'flagged' : 'clean'}">${flagged ? '⚠️' : '✅'}</span>`;
      } else if (e.type === 'cve') {
        const score = e.cvssScore;
        flagged = score >= 7;
        scoreHtml = score ? `<span class="threat-intel-score ${flagged ? 'flagged' : 'clean'}">${score}</span>` : '';
      }

      const queryDisplay = e.query.length > 18 ? e.query.substring(0, 18) + '...' : e.query;

      return `
        <div class="threat-intel-item">
          <span class="threat-intel-badge ${e.type}">${e.type.toUpperCase()}</span>
          <span class="threat-intel-query">${this.escapeHtml(queryDisplay)}</span>
          ${scoreHtml}
        </div>
      `;
    }).join('');
  },

  // ---- Utility ----
  escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  },

  // ============================================================
  // v3.0 Dashboard Panels
  // ============================================================

  // ---- Background Monitor Panel ----
  async refreshMonitorStatus() {
    try {
      const res = await fetch('/api/monitor-status');
      const data = await res.json();
      this.renderMonitorStatus(data);
    } catch {}
  },

  renderMonitorStatus(data) {
    const panel = document.getElementById('monitorStatusPanel');
    if (!panel) return;

    const watchers = data.watchers || {};
    const items = Object.entries(watchers).map(([name, w]) => {
      const statusClass = w.active ? 'active' : 'inactive';
      const dot = w.active ? '🟢' : '🔴';
      return `<div class="monitor-item">
        <span class="monitor-dot">${dot}</span>
        <span class="monitor-name">${name}</span>
        <span class="monitor-findings">${w.findings || 0} findings</span>
      </div>`;
    }).join('');

    panel.innerHTML = `
      <div class="monitor-header">
        <span class="monitor-status-badge ${data.paused ? 'paused' : 'active'}">${data.paused ? 'PAUSED' : 'ACTIVE'}</span>
        <span class="monitor-total">${data.totalFindings || 0} total</span>
      </div>
      ${items}
    `;
  },

  // ---- Anomaly Detection Panel ----
  async refreshAnomalyStatus() {
    try {
      const res = await fetch('/api/anomaly-status');
      const data = await res.json();
      this.renderAnomalyStatus(data);
      // Update anomaly counter in metrics bar
      const counter = document.getElementById('metricAnomalies');
      if (counter) counter.textContent = (data.recentAnomalies || []).length;
    } catch {}
  },

  renderAnomalyStatus(data) {
    const panel = document.getElementById('anomalyPanel');
    if (!panel) return;

    const statusLabel = data.status === 'learning' ? '📚 LEARNING' :
      data.status === 'active' ? '✅ ACTIVE' : '⏳ NOT SET';

    let content = `<div class="anomaly-status-badge">${statusLabel}</div>`;

    if (data.status === 'learning') {
      content += `<div class="anomaly-info">Elapsed: ${data.elapsed} | Remaining: ${data.remaining}</div>`;
    } else if (data.status === 'active') {
      content += `<div class="anomaly-info">Tracking ${data.metricsTracked} metrics (${data.totalSamples} samples)</div>`;
    }

    const anomalies = data.recentAnomalies || [];
    if (anomalies.length > 0) {
      content += anomalies.map(a => `
        <div class="anomaly-item severity-${a.severity}">
          <span class="anomaly-metric">${a.metricName}</span>
          <span class="anomaly-deviation">${a.deviations}σ</span>
          <span class="anomaly-severity ${a.severity}">${a.severity}</span>
        </div>
      `).join('');
    } else if (data.status === 'active') {
      content += '<div class="empty-state">No anomalies — all metrics normal</div>';
    }

    panel.innerHTML = content;
  },

  // ---- Notification Status Panel ----
  async refreshNotificationStatus() {
    try {
      const res = await fetch('/api/notification-status');
      const data = await res.json();
      this.renderNotificationStatus(data);
    } catch {}
  },

  renderNotificationStatus(data) {
    const panel = document.getElementById('notificationPanel');
    if (!panel) return;

    const channels = [
      { name: 'Email', status: data.email, sent: data.emailsSentToday, icon: '📧' },
      { name: 'Slack', status: data.slack, sent: data.slacksSentToday, icon: '💬' },
      { name: 'Phone', status: data.ntfy, sent: data.sentToday, icon: '📱' },
    ];

    panel.innerHTML = channels.map(ch => `
      <div class="notification-channel">
        <span class="notification-icon">${ch.icon}</span>
        <span class="notification-name">${ch.name}</span>
        <span class="notification-status ${ch.status === 'configured' ? 'on' : 'off'}">${ch.status || 'off'}</span>
        ${ch.sent !== undefined ? `<span class="notification-sent">${ch.sent} sent</span>` : ''}
      </div>
    `).join('');
  },

  // ---- Session History Panel ----
  async refreshSessionHistory() {
    try {
      const res = await fetch('/api/session-history?limit=5');
      const data = await res.json();
      this.renderSessionHistory(data.sessions || []);
    } catch {}
  },

  renderSessionHistory(sessions) {
    const panel = document.getElementById('sessionHistoryPanel');
    if (!panel) return;

    if (sessions.length === 0) {
      panel.innerHTML = '<div class="empty-state">No session history yet</div>';
      return;
    }

    panel.innerHTML = sessions.map(s => {
      const date = s.started_at ? new Date(s.started_at).toLocaleString() : 'Unknown';
      const risk = s.risk_score !== null ? s.risk_score : '—';
      const riskClass = risk >= 75 ? 'critical' : risk >= 50 ? 'high' : risk >= 25 ? 'medium' : 'low';
      return `
        <div class="session-item">
          <span class="session-date">${date}</span>
          <span class="session-risk ${riskClass}">Risk: ${risk}</span>
          <span class="session-findings">${s.findings_count || 0} findings</span>
        </div>
      `;
    }).join('');
  },

  // ---- Refresh All v3.0 Panels ----
  refreshAllV3() {
    this.refreshMonitorStatus();
    this.refreshAnomalyStatus();
    this.refreshNotificationStatus();
    this.refreshSessionHistory();
  },
};

