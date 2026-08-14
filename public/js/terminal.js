// ============================================================
// Jarvis — Terminal Component
// Command input, output rendering, autocomplete, history nav.
// ============================================================

const terminal = {
  output: null,
  input: null,
  autocompleteData: [],

  init() {
    this.output = document.getElementById('terminalOutput');
    this.input = document.getElementById('commandInput');

    if (!this.input || !this.output) return;

    // Command submission
    this.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const cmd = this.input.value.trim();
        if (cmd) {
          app.sendCommand(cmd);
          this.input.value = '';
          // Hide enter hint
          const hint = document.getElementById('enterHint');
          if (hint) hint.classList.remove('visible');
        }
      }

      // History navigation
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (app.historyIndex > 0) {
          app.historyIndex--;
          this.input.value = app.commandHistory[app.historyIndex] || '';
        }
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (app.historyIndex < app.commandHistory.length - 1) {
          app.historyIndex++;
          this.input.value = app.commandHistory[app.historyIndex] || '';
        } else {
          app.historyIndex = app.commandHistory.length;
          this.input.value = '';
        }
      }

      // Tab autocomplete
      if (e.key === 'Tab') {
        e.preventDefault();
        this.handleAutocomplete();
      }
    });

    // Focus input on terminal click
    const termPanel = document.querySelector('.terminal-panel');
    if (termPanel) {
      termPanel.addEventListener('click', (e) => {
        if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'A') this.input.focus();
      });
    }

    // Load autocomplete data
    this.loadAutocomplete();
  },

  async loadAutocomplete() {
    try {
      const res = await fetch('/api/tools');
      const data = await res.json();
      if (data.tools) {
        this.autocompleteData = data.tools.map(t => ({
          command: t.name,
          description: t.description,
          tier: t.tier,
        }));

        // Add common command phrases
        this.autocompleteData.push(
          { command: 'scan this for secrets', description: 'Scan current directory for secrets' },
          { command: 'audit dependencies', description: 'Check project dependencies for vulnerabilities' },
          { command: 'check firewall', description: 'Audit firewall configuration' },
          { command: 'monitor network', description: 'Check active network connections' },
          { command: 'run a full audit', description: 'Comprehensive security scan' },
          { command: 'generate report', description: 'Create SOC incident report' },
          // SOC commands
          { command: 'show alert queue', description: 'View all open alerts' },
          { command: 'parse windows event log', description: 'Analyze Windows event log' },
          { command: 'parse web server log', description: 'Analyze Apache/Nginx access log' },
          { command: 'enrich ip', description: 'Enrich IP with threat intelligence' },
          { command: 'enrich hash', description: 'Check file hash against malware DB' },
          { command: 'lookup cve', description: 'Look up CVE details from NVD' },
          { command: 'check domain', description: 'Check domain reputation' },
          { command: 'show mitre summary', description: 'View MITRE ATT&CK heatmap' },
          { command: 'run playbook', description: 'Execute incident response playbook' },
          { command: 'list playbooks', description: 'List available IR playbooks' },
          { command: 'correlate events', description: 'Cross-reference parsed logs' },
        );
      }
    } catch { /* autocomplete unavailable */ }
  },

  handleAutocomplete() {
    const val = this.input.value.toLowerCase();
    if (!val) return;

    const match = this.autocompleteData.find(item =>
      item.command.toLowerCase().startsWith(val)
    );

    if (match) {
      this.input.value = match.command;
    }
  },

  addLine(text, type = 'default') {
    if (!this.output) return;

    const line = document.createElement('div');
    line.className = 'terminal-line';

    switch (type) {
      case 'user':
        line.classList.add('line-user');
        line.innerHTML = `<span class="terminal-prefix">ali@jarvis ❯</span> <span class="terminal-text">${escapeHtml(text)}</span>`;
        break;
      case 'jarvis':
        line.classList.add('line-jarvis');
        line.innerHTML = `<span class="terminal-prefix">JARVIS ›</span> <span class="terminal-text">${escapeHtml(text)}</span>`;
        // Speak short responses
        if (typeof voice !== 'undefined' && voice.speak && text.length < 200) {
          voice.speak(text.replace(/[*_`#]/g, ''));
        }
        break;
      case 'system':
        line.classList.add('line-system');
        line.innerHTML = `<span class="terminal-text">${escapeHtml(text)}</span>`;
        break;
      case 'error':
        line.classList.add('line-error');
        line.innerHTML = `<span class="terminal-text">✖ ${escapeHtml(text)}</span>`;
        break;
      case 'warning':
        line.classList.add('line-warning');
        line.innerHTML = `<span class="terminal-text">⚠ ${escapeHtml(text)}</span>`;
        break;
      case 'success':
        line.classList.add('line-success');
        line.innerHTML = `<span class="terminal-text">✔ ${escapeHtml(text)}</span>`;
        break;
      default:
        line.innerHTML = `<span class="terminal-text">${escapeHtml(text)}</span>`;
    }

    this.output.appendChild(line);
    this.output.scrollTop = this.output.scrollHeight;
  },

  clear() {
    if (this.output) this.output.innerHTML = '';
  },
};

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

