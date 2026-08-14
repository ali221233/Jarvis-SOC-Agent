// ============================================================
// Jarvis — Dashboard Panels
// Risk gauge, system status, findings feed, action timeline.
// ============================================================

const panels = {
  riskScore: 0,

  init() {
    this.updateRiskGauge(0);
    this.refreshHistory();
  },

  // ---- Risk Gauge (SVG arc) ----
  updateRiskGauge(score) {
    this.riskScore = Math.max(0, Math.min(100, score));

    const arc = document.getElementById('riskArc');
    const text = document.getElementById('riskScoreText');
    const label = document.getElementById('riskLabel');

    if (!arc || !text || !label) return;

    // Arc length: 173 is the full semicircle length
    const dashLength = (this.riskScore / 100) * 173;
    arc.setAttribute('stroke-dasharray', `${dashLength} 173`);

    // Color by score
    let color, labelText;
    if (this.riskScore <= 30) {
      color = 'var(--success)';
      labelText = 'LOW RISK';
      text.className = 'risk-score-text';
    } else if (this.riskScore <= 60) {
      color = 'var(--warning)';
      labelText = 'MEDIUM RISK';
      text.className = 'risk-score-text medium';
    } else if (this.riskScore <= 80) {
      color = 'var(--high)';
      labelText = 'HIGH RISK';
      text.className = 'risk-score-text high';
    } else {
      color = 'var(--critical)';
      labelText = 'CRITICAL';
      text.className = 'risk-score-text critical';
    }

    arc.setAttribute('stroke', color);
    text.textContent = this.riskScore;
    label.textContent = labelText;

    // Animate
    arc.style.transition = 'stroke-dasharray 0.8s ease-out';
  },

  // ---- Findings Feed ----
  addFinding({ severity = 'low', title, detail, tool }) {
    const panel = document.getElementById('findingsList') || document.getElementById('findingsPanel');
    if (!panel) return;

    // Remove empty state if present
    const empty = panel.querySelector('.empty-state');
    if (empty) empty.remove();

    const sev = (severity || 'low').toLowerCase();
    const card = document.createElement('div');
    card.className = `finding-card ${sev}`;
    card.innerHTML = `
      <div class="finding-top">
        <span class="finding-tool">${escapeHtml(tool || 'SCAN')}</span>
        <span class="finding-title">${escapeHtml(title || 'Finding')}</span>
      </div>
      <div class="finding-desc">${escapeHtml(detail || '')}</div>
    `;

    panel.prepend(card);

    // Update risk score based on findings
    const weights = { critical: 25, high: 15, medium: 8, low: 3 };
    this.riskScore = Math.min(100, this.riskScore + (weights[sev] || 5));
    if (typeof app !== 'undefined' && app.updateThreatThermometer) {
      app.updateThreatThermometer(this.riskScore);
    }
    this.updateRiskGauge(this.riskScore);

    // Cap visible findings
    while (panel.children.length > 25) {
      panel.removeChild(panel.lastChild);
    }
  },

  clearFindings() {
    const panel = document.getElementById('findingsList') || document.getElementById('findingsPanel');
    if (panel) panel.innerHTML = '<div class="empty-state">No findings yet</div>';
    this.updateRiskGauge(0);
  },


  // ---- Action Timeline ----
  async refreshHistory() {
    const timeline = document.getElementById('actionTimeline');
    if (!timeline) return;

    try {
      const res = await fetch('/api/history?limit=15');
      const data = await res.json();

      if (!data.history?.length) {
        timeline.innerHTML = '<div class="action-item"><span class="action-time">—</span><span class="action-text">No actions yet</span></div>';
        return;
      }

      timeline.innerHTML = '';
      for (const action of data.history.reverse()) {
        const time = new Date(action.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
        const tier = action.tier || 1;

        const item = document.createElement('div');
        item.className = 'action-item';
        item.innerHTML = `
          <span class="action-time">${time}</span>
          <span class="tier-badge t${tier}">T${tier}</span>
          <span class="action-text">${escapeHtml(action.summary?.substring(0, 50) || action.tool || '...')}</span>
        `;
        timeline.appendChild(item);
      }

      // Update pending badge
      try {
        const pendingRes = await fetch('/api/pending');
        const pendingData = await pendingRes.json();
        const badge = document.getElementById('badgePending');
        if (badge) badge.textContent = pendingData.pending?.length || 0;
      } catch {}

    } catch {
      timeline.innerHTML = '<div class="action-item"><span class="action-text">Failed to load</span></div>';
    }
  },

  // ---- System Status Updates ----
  updateStatus(field, value, state) {
    const el = document.getElementById(field);
    if (!el) return;
    el.textContent = value;
    el.className = `value ${state}`;
  },
};

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
