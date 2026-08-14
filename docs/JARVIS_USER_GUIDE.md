# Jarvis SOC Agent v4.0 — User Guide

**Version 4.0** — Mission Control Redesign · Kokoro TTS · n8n Workflows · Watch-Drop · Real OSV/TruffleHog/ClamAV

## What Jarvis Is

Jarvis is a personal Security Operations Center (SOC) agent built as a Node.js web application. It provides 66 security tools organized across 7 categories: code security, file security, network security, privacy, ransomware defense, productivity, and SOC operations. Jarvis runs entirely on your machine — your files, logs, and analysis results never leave the local environment.

The reasoning layer uses Groq's free API running the `llama-3.3-70b-versatile` model at 500+ tokens per second. When you type or speak a command, Jarvis first tries a fast-path pattern matcher for unambiguous single-tool commands. If confidence is below 0.85, it routes the full transcript to the LLM, which selects tools and parameters via native function calling. Every tool execution is governed by a three-tier confirmation system: Tier 1 (runs immediately), Tier 2 (requires one confirmation click), and Tier 3 (requires double confirmation plus passphrase re-entry via Argon2id key derivation). All actions are logged with automatic secret scrubbing, and every session can produce a SHA-256 signed incident report.

---

## What's New in v4.0

### Mission Control UI
- **3-column layout**: Left sidebar (threat level + nav + watcher status), center (metrics strip + terminal + alert/findings panels), right sidebar (threat intel + MITRE heatmap + n8n workflows + notification status)
- **Threat Thermometer**: Animated vertical gauge on the left sidebar showing the CVSS-based risk score (0–100)
- **Status Pills**: Top bar shows live status of GROQ, KOKORO TTS, MONITORING, DB ONLINE, NTFY, and N8N
- **Session Timer**: Elapsed session time tracked in the header
- **Watcher Status Panel**: Real-time status of all 5 background watchers in the left sidebar

### Kokoro TTS (Task 1A)
- Jarvis now speaks responses using the **Kokoro TTS** model (`onnx-community/Kokoro-82M-v1.0-ONNX`, voice: `af_sky`)
- Audio is generated server-side and streamed to the browser via WebSocket as base64 WAV
- Played locally via the **Web Audio API** (no browser permission needed)
- Falls back to **Web Speech API** if Kokoro is unavailable
- Voice: `af_sky` (configurable via `JARVIS_VOICE` in `.env`)

### TruffleHog Integration (Task 1B)
- **`scan_secrets`** now attempts to download the real TruffleHog binary from GitHub releases on first use
- Windows: downloads `trufflehog_windows_amd64.exe`; Linux/Mac: downloads the appropriate binary
- If the download fails (e.g., no internet), falls back to the existing regex scanner with a clear note
- Binary is cached in `data/bin/` and reused on subsequent calls

### ClamAV Integration (Task 1C)
- **`scan_malware`** first checks if `clamscan` is installed and runs a real full scan if available
- If ClamAV is not installed, returns a clear **INFO finding** explaining the limitation and recommending installation
- Also triggers a dashboard notification so you don't miss the gap
- Hash-based fallback still runs in either case for known malware hashes

### Real OSV API (Task 1D)
- **`audit_dependencies`** now queries the real [OSV.dev](https://osv.dev) API for each package
- Returns real CVE IDs, CVSS scores, severity classifications, and reference links
- Scans up to 30 packages per call (to respect rate limits)
- Works with both `package.json` (npm) and `requirements.txt` (PyPI)

### n8n Workflow Automation (Task 3)

Jarvis now integrates with [n8n](https://n8n.io) for no-code workflow automation:

| Event | n8n Webhook | What Happens |
|-------|-------------|--------------|
| CRITICAL alert created | `/webhook/critical_alert` | Ntfy push notification + Slack message |
| Playbook completed | `/webhook/incident_response` | Logs to Google Sheets / ticketing system |
| File dropped in watch-drop | `/webhook/file_drop` | Custom notification / auto-processing |
| Threat intel hit | `/webhook/threat_intel_hit` | Enrichment log / SIEM integration |
| Canary triggered | `/webhook/canary_triggered` | Emergency notification |
| Report generated | `/webhook/report_generated` | Archive / distribute |
| Weekly briefing (Mon 8AM) | `/webhook/weekly_briefing` | Scheduled summary |
| Patch check (Sun 9AM) | `/webhook/patch_check` | Scheduled vulnerability review |

n8n runs at `http://localhost:5678`. Jarvis's `N8N_WEBHOOK_BASE` defaults to `http://localhost:5678/webhook`. All n8n failures are silent — Jarvis never crashes due to n8n being offline.

**To install n8n:** `npx n8n` or `npm install -g n8n && n8n`

Workflow JSON files are in `data/n8n/workflows/` — import them in the n8n UI.

### Watch-Drop Auto-Scanner
- Drop any file into `data/watch-drop/` and Jarvis will automatically:
  1. Alert the dashboard within 500ms
  2. Trigger the n8n `file_drop` webhook
  3. Run `scan_malware` on the file
  4. Run `scan_secrets` on text files (`.txt`, `.js`, `.py`, `.env`, etc.)
  5. Report results in the terminal

### URLScan.io Integration
- Set `URLSCAN_API_KEY` in `.env` to enable URL scanning via URLScan.io
- Used by the `scan_url` tool for website threat analysis

---

## Getting Started

### Prerequisites

- **Node.js** v16 or later
- **Groq API Key** (free — sign up at [console.groq.com](https://console.groq.com), generate a key, no credit card required)
- **Chrome or Edge** browser (for the dashboard)

### Installation

```bash
git clone <repository-url>
cd Jarvis-Cyber-agent
npm install
```

Create a `.env` file in the project root:

```
# Required
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# Optional — Threat Intelligence
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
URLSCAN_API_KEY=
ALIENVAULT_API_KEY=

# Optional — Phone Notifications
NTFY_TOPIC=jarvis-your-unique-topic

# Optional — Email/Slack
EMAIL_FROM=
EMAIL_TO=
EMAIL_APP_PASSWORD=
SLACK_WEBHOOK_URL=

# Optional — n8n Workflow Automation
N8N_WEBHOOK_BASE=http://localhost:5678/webhook
N8N_ENABLED=true

# Optional — Voice
JARVIS_VOICE=af_sky

PORT=3000
```

### Starting the Server

```bash
npm start
```

This starts the server on `http://localhost:3000`. Open that URL in Chrome.

### First Run

When you first load the dashboard, you will see:

1. **Passphrase Setup Overlay** — Set a master passphrase (8+ characters) used for encrypting files and unlocking Tier 3 actions. You can skip this by clicking "Skip" if you don't need encryption features immediately.
2. **SOC Metrics Strip** — Five counters: Open Alerts, Resolved Today, MITRE Techniques, Anomalies, and Risk Score.
3. **Left Sidebar** — Threat thermometer + navigation (Overview, Log Analysis, Alert Queue, Threat Intel, MITRE ATT&CK, Playbooks, Code Security, File Security, Network, Privacy, Reports, N8N Workflows) + watcher status
4. **Center** — Command terminal with voice input button
5. **Right Sidebar** — Threat Intel, MITRE heatmap, Notification status, N8N workflow panel, Session history

---

## Where to Put Your Files

### Code Projects / Source Files

Put source code files or entire project directories anywhere accessible from the project root. When telling Jarvis to scan, provide the relative or absolute path.

```
"scan src/config.js for secrets"
"run SAST on ./my-project"
"audit dependencies for ./my-project"
```

Jarvis scans for: AWS keys (`AKIA...`), GitHub tokens (`ghp_...`), Stripe keys (`sk_live_...`, `sk_test_...`), JWTs, database URIs (`postgres://`, `mongodb://`), Slack tokens (`xoxb-...`), generic API keys, private key headers, and passwords in config files.

### Log Files

Place log files in any directory. The default demo data directory is `data/demo-logs/`. When telling Jarvis to parse logs, include the file path.

**Windows Event Logs:**
- Formats: `.evtx` export, `.xml`, or `.txt`
- Expected format: `TimeCreated: <timestamp> | EventID: <id> | Source: <source> | <description>`
- Example: `data/demo-logs/windows_events.txt`

**Linux Auth Logs:**
- Formats: Raw syslog format
- Expected format: Standard syslog lines (`Jan 15 09:10:01 hostname sshd[PID]: ...`)
- Example: `data/demo-logs/auth.log`

**Web Server Access Logs:**
- Formats: Apache combined log format, Nginx default format
- Expected format: `IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"`
- Example: `data/demo-logs/access.log`

### Files to Encrypt or Secure

Place any file you want to encrypt at any path. Tell Jarvis:

```
"encrypt file documents/report.pdf"
```

After encryption, Jarvis creates a `.enc` file at the same location (e.g., `documents/report.pdf.enc`). The original file is preserved. To decrypt, you need the passphrase.

To scrub metadata: `"scrub metadata from photo.jpg"`
To secure delete: `"securely delete temp/sensitive.doc"` (IRREVERSIBLE — Tier 3)

### Vault Documents

The encrypted vault is stored at `.jarvis/vault/` inside the project directory. To store:

```
"store my SSH key in the vault as ssh_private_key"
```

To retrieve (Tier 3 — requires passphrase):

```
"retrieve ssh_private_key from the vault"
```

### Files to Scan for Malware

Place files at any accessible path. Jarvis checks file hashes against a local database that includes signatures for WannaCry, Emotet, Mimikatz, TrickBot, Ryuk, DarkSide, Cobalt Strike, and other known malware.

```
"scan downloads/ for malware"
```

---

## All Commands and What They Do

### Log Analysis Commands

**Command:** "parse the windows event log data/demo-logs/windows_events.txt"
**What it does:** Reads Windows event log entries and flags critical Event IDs: 4625 (failed login), 4720 (new account), 4732 (privilege escalation), 7045 (new service), 4698 (scheduled task), 1102 (log cleared).
**Tier:** 1 — runs automatically
**Needs:** Path to a Windows event log file (.evtx, .xml, or .txt)
**Output:** List of flagged events with timestamps, severity, and counts per Event ID. Auto-creates alerts for serious findings.

**Command:** "parse the linux syslog data/demo-logs/auth.log"
**What it does:** Parses Linux auth.log/syslog for SSH brute force sequences, sudo failures, su-to-root escalation, and cron-based persistence.
**Tier:** 1
**Needs:** Path to syslog file
**Output:** Flagged entries with severity classification. Creates alerts if brute force pattern detected.

**Command:** "parse the web server access log data/demo-logs/access.log"
**What it does:** Parses Apache/Nginx access logs for SQL injection patterns, directory traversal, scanner signatures (sqlmap, Nikto, Nessus), and error spikes.
**Tier:** 1
**Needs:** Path to access log file
**Output:** Attack attempts listed with source IPs, payloads, and severity.

**Command:** "correlate events"
**What it does:** Cross-references parsed logs from multiple sources within a time window to surface attack chains.
**Tier:** 1
**Needs:** Logs already parsed in the current session. Optional: time window in minutes (default: 30).
**Output:** Correlated attack chain timeline.

### Alert Triage Commands

**Command:** "show the alert queue"
**What it does:** Lists all open alerts sorted by severity.
**Tier:** 1
**Output:** Table of alerts with ID, title, severity, priority, and time open.

**Command:** "create alert" (routed via LLM for parameter extraction)
**What it does:** Creates a new alert in the SOC triage queue.
**Tier:** 1
**Needs:** Title (required), severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), source, details.
**Output:** New incident ID.

**Command:** "triage alert INC-2024-01-15-001 as true positive"
**What it does:** Sets triage decision on an alert: TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_INVESTIGATION.
**Tier:** 2 — requires confirmation click
**Needs:** Incident ID and decision.

**Command:** "escalate alert INC-2024-01-15-001"
**What it does:** Escalates an alert to P1 priority.
**Tier:** 2 — requires confirmation click
**Needs:** Incident ID.

**Command:** "close alert INC-2024-01-15-001"
**What it does:** Closes an alert with resolution summary.
**Tier:** 2 — requires confirmation click
**Needs:** Incident ID and resolution text.

### Threat Intelligence Commands

**Command:** "enrich IP 192.168.1.100"
**What it does:** Scores an IP against AbuseIPDB (if API key configured) and a local blocklist of known Tor exit nodes, C2 ranges, and scanner IPs.
**Tier:** 1
**Needs:** IP address.
**Output:** Threat score, blocklist match, abuse categories.

**Command:** "enrich hash a1b2c3d4e5f6..."
**What it does:** Checks a file hash (MD5 or SHA-256) against the local malware signature database.
**Tier:** 1
**Needs:** File hash string.
**Output:** Match result with malware family name if found.

**Command:** "check domain suspicious-site.com"
**What it does:** Runs Shannon entropy and consonant ratio analysis for DGA detection, plus blocklist check.
**Tier:** 1
**Needs:** Domain name.
**Output:** DGA probability, entropy score, blocklist status.

**Command:** "lookup CVE-2021-44228"
**What it does:** Queries NVD for CVSS score, description, affected software, and remediation guidance.
**Tier:** 1
**Needs:** CVE ID.
**Output:** CVE details, CVSS score, affected products, and remediation links. Auto-creates CRITICAL alert for CVSS >= 9.0.

### MITRE ATT&CK Commands

**Command:** "show MITRE ATT&CK summary"
**What it does:** Gets session technique summary grouped by tactic with hit counts.
**Tier:** 1
**Output:** Tactic-grouped technique list with counts.

**Command:** "map this finding to MITRE ATT&CK" (routed via LLM)
**What it does:** Maps a finding description to MITRE ATT&CK technique(s) using keyword matching across 30 defined techniques in 12 tactics.
**Tier:** 1
**Needs:** Finding description text.

### Incident Response Playbook Commands

**Command:** "list playbooks"
**What it does:** Lists all 5 available incident response playbooks with descriptions.
**Tier:** 1

**Command:** "run the brute force playbook"
**What it does:** Executes 5-step brute force response: parse auth logs → enrich source IP → check firewall → create alert → monitor network.
**Tier:** 2 — requires confirmation before execution
**Output:** Step-by-step narration with results from each tool.

**Command:** "run the ransomware playbook"
**What it does:** Executes 5-step ransomware response: detect mass file changes → audit startup → monitor network → check encryption → verify backups.
**Tier:** 2

**Command:** "run the insider threat playbook"
**What it does:** Executes 5-step insider investigation: audit startup → filter privileged actions → scan sensitive files → check network → generate report.
**Tier:** 2

**Command:** "run the phishing playbook"
**What it does:** Executes 4-step phishing response: triage email → enrich domains → check breach status → create alert.
**Tier:** 2

**Command:** "run the malware detected playbook"
**What it does:** Executes 5-step malware response: enrich hash → check permissions → scan malware → audit startup → monitor network.
**Tier:** 2

### Code Security Commands

**Command:** "scan test_secrets.txt for hardcoded secrets"
**What it does:** Scans the specified file or directory for 10 regex patterns: AWS keys, GitHub tokens, Stripe keys, JWTs, database URIs, Slack tokens, private key headers, generic API keys, and generic secrets/passwords.
**Tier:** 1
**Needs:** File or directory path.
**Output:** List of findings with line numbers, severity, and matched pattern name.

**Command:** "run SAST on src/"
**What it does:** Static analysis for eval injection, SQL injection via template literals, innerHTML XSS, command injection via exec(), hardcoded IPs, and insecure protocols.
**Tier:** 1
**Needs:** File or directory path.

**Command:** "audit dependencies for ./"
**What it does:** Reads package.json and checks dependencies against known vulnerability database.
**Tier:** 1
**Needs:** Project root directory.

**Command:** "generate SBOM for ./"
**What it does:** Generates Software Bill of Materials listing all dependencies.
**Tier:** 1
**Needs:** Project root directory.

**Command:** "run pre-commit check on ./"
**What it does:** Combined secrets + SAST scan suitable for git hooks.
**Tier:** 1
**Needs:** Repository root path.

**Command:** "propose fix for this finding"
**What it does:** Suggests remediation for a security finding without applying it.
**Tier:** 1

**Command:** "apply fix for finding-id-001"
**What it does:** Applies a previously proposed fix.
**Tier:** 2 — requires confirmation

**Command:** "sign the commit"
**What it does:** Signs a git commit with GPG.
**Tier:** 2 — requires confirmation

### File Security Commands

**Command:** "check permissions on config/"
**What it does:** Shows file/directory permissions and metadata.
**Tier:** 1
**Needs:** File or directory path.

**Command:** "scan downloads/ for malware"
**What it does:** Checks file hashes against local malware signature database.
**Tier:** 1
**Needs:** File or directory path.

**Command:** "encrypt file documents/report.pdf"
**What it does:** Encrypts using AES-256-GCM with passphrase-derived key (Argon2id KDF). Output: `.enc` file.
**Tier:** 2 — requires confirmation
**Needs:** File path. Passphrase must be set up.

**Command:** "decrypt file documents/report.pdf.enc"
**What it does:** Decrypts an encrypted file. Requires passphrase re-entry.
**Tier:** 3 — double confirm + passphrase
**Needs:** Path to `.enc` file.

**Command:** "scrub metadata from photo.jpg"
**What it does:** Removes EXIF and other metadata from files.
**Tier:** 2 — requires confirmation
**Needs:** File path.

**Command:** "securely delete temp/sensitive.doc"
**What it does:** Multi-pass overwrite then delete. IRREVERSIBLE.
**Tier:** 3 — double confirm + passphrase
**Needs:** File path.

**Command:** "scan for sensitive files in documents/"
**What it does:** Finds files containing SSNs, credit card numbers, passwords, and other PII.
**Tier:** 1
**Needs:** Directory path.

**Command:** "search files for 'password' in src/"
**What it does:** Searches files by name or content.
**Tier:** 1
**Needs:** Search query and directory path.

**Command:** "organize files in downloads/"
**What it does:** Organizes files according to a plan.
**Tier:** 2 — requires confirmation

### Network Security Commands

**Command:** "check patches"
**What it does:** Lists installed system patches and pending updates.
**Tier:** 1

**Command:** "check firewall status"
**What it does:** Audits system firewall configuration and lists active rules.
**Tier:** 1

**Command:** "monitor network connections"
**What it does:** Lists active network connections and flags suspicious ports.
**Tier:** 1

**Command:** "audit startup processes"
**What it does:** Lists startup/autorun entries and flags suspicious ones.
**Tier:** 1

**Command:** "check disk encryption"
**What it does:** Checks BitLocker/FileVault status.
**Tier:** 1

**Command:** "verify backups"
**What it does:** Checks backup status and integrity.
**Tier:** 1

**Command:** "audit router config"
**What it does:** Audits router/gateway configuration.
**Tier:** 1

**Command:** "scan for IoT devices"
**What it does:** Scans local network for IoT devices.
**Tier:** 1

### Privacy & Identity Commands

**Command:** "check if ali@example.com has been breached"
**What it does:** Checks email/account against known data breach databases.
**Tier:** 1
**Needs:** Email address or account name.

**Command:** "audit browser extensions"
**What it does:** Lists installed browser extensions and flags risky permissions.
**Tier:** 1

**Command:** "triage this phishing email"
**What it does:** Analyzes email content for phishing indicators (urgency language, suspicious links, impersonation patterns).
**Tier:** 1
**Needs:** Email content.

**Command:** "store this API key in the vault as prod_key"
**What it does:** Encrypts and stores an item in the secure vault.
**Tier:** 2 — requires confirmation
**Needs:** Name/label and content.

**Command:** "retrieve prod_key from the vault"
**What it does:** Retrieves and decrypts a vault item.
**Tier:** 3 — double confirm + passphrase
**Needs:** Vault item name.

**Command:** "verify speaker identity"
**What it does:** Voice biometric verification.
**Tier:** 3 — double confirm + passphrase

### Ransomware Defense Commands

**Command:** "deploy canary files in documents/"
**What it does:** Creates honeypot files that trigger alerts if modified by ransomware or unauthorized processes.
**Tier:** 2 — requires confirmation
**Needs:** Array of directory paths.

**Command:** "detect mass file changes in documents/"
**What it does:** Flags rapid file system modifications characteristic of encryption ransomware.
**Tier:** 1
**Needs:** Directory path. Optional: threshold (default: 10 changes).

### Report Commands

**Command:** "generate the incident report"
**What it does:** Produces a comprehensive SOC incident report with: executive summary, open/closed incidents, threat intelligence findings, MITRE ATT&CK coverage, timeline of actions, errors & anomalies, risk posture score, and SHA-256 integrity hash.
**Tier:** 1
**Output:** Markdown report saved to `data/demo_soc_report.md`. SHA-256 hash printed at the bottom.

---

## The Tier System Explained

### Tier 1 — Automatic Execution
Tool runs immediately when you give the command. No confirmation needed. Used for read-only operations: scanning, parsing, enrichment, lookups, status checks.

### Tier 2 — Single Confirmation
A modal dialog appears with the action description and a "Confirm" button. Click "Confirm" to proceed, or "Cancel" to abort. Used for actions that modify state: encrypting files, scrubbing metadata, running playbooks, triaging alerts, applying fixes.

### Tier 3 — Double Confirmation + Passphrase
The most destructive or sensitive actions. A modal requires you to click "Confirm" twice and re-enter your master passphrase. Used for: secure file deletion (irreversible), decrypting files, retrieving vault items, and speaker verification.

If you haven't set a passphrase yet, Jarvis will prompt you on first Tier 3 attempt.

---

## Incident Response Playbooks

### Ransomware Response
**Command:** "run the ransomware playbook"
**Steps:** (1) Detect mass file changes → (2) Audit startup processes → (3) Monitor network for C2 → (4) Check disk encryption → (5) Verify backups
**Confirms:** Tier 2 confirmation before starting

### Brute Force Response
**Command:** "run the brute force playbook"
**Steps:** (1) Parse auth logs → (2) Enrich source IP → (3) Audit firewall → (4) Create consolidated alert → (5) Monitor network
**Confirms:** Tier 2 confirmation before starting

### Insider Threat Investigation
**Command:** "run the insider threat playbook"
**Steps:** (1) Audit startup → (2) Parse privileged actions → (3) Scan sensitive files → (4) Monitor network → (5) Generate report
**Confirms:** Tier 2 confirmation before starting

### Phishing Investigation
**Command:** "run the phishing playbook"
**Steps:** (1) Triage email → (2) Enrich domains → (3) Check breach status → (4) Create alert
**Confirms:** Tier 2 confirmation before starting

### Malware Detection Response
**Command:** "run the malware detected playbook"
**Steps:** (1) Enrich file hash → (2) Check permissions → (3) Scan for more malware → (4) Audit startup → (5) Monitor network
**Confirms:** Tier 2 confirmation before starting

---

## The SOC Dashboard

### SOC Metrics Bar (top)
Four counters across the top of the screen:
- **Open Alerts** — Number of unresolved alerts in the queue
- **Resolved Today** — Alerts closed during today's session
- **MITRE Techniques** — Number of unique ATT&CK techniques triggered
- **Risk Score** — Current risk score (0-100), calculated from alert severity weights

### Alert Queue (center-top)
Shows all open alerts sorted by severity. Each alert card shows:
- Incident ID (INC-YYYY-MM-DD-NNN)
- Title and severity badge (color-coded: red=CRITICAL, orange=HIGH, yellow=MEDIUM, blue=LOW, gray=INFO)
- Source and time since creation
- Click to expand for details and triage options

### Command Terminal (center)
The primary interaction point. Features:
- Type commands in the input field at the bottom
- Press Enter or click the send button to execute
- Use Up/Down arrow keys to browse command history
- Click the microphone button (🎤) to use voice input
- Terminal shows user commands (cyan) and Jarvis responses (white) with colored severity tags

### Findings Panel (center-bottom)
Displays security findings from scans and analysis. Each finding shows:
- Severity icon and color (🔴 critical, 🟠 high, 🟡 medium, 🔵 low)
- Finding description and source tool
- File path and line number where applicable

### MITRE ATT&CK Heatmap (bottom)
Grid of MITRE techniques organized by tactic. Color coding:
- Gray = no hits this session
- Yellow = 1 hit
- Orange = 2-4 hits
- Red = 5+ hits
Shows 30 techniques across 12 tactics.

### Risk Score Gauge (right sidebar)
Semi-circular gauge showing risk score 0-100:
- **Green (0-24):** LOW — No significant issues
- **Yellow (25-49):** MEDIUM — Some findings need attention
- **Orange (50-74):** HIGH — Multiple high-severity findings
- **Red (75-100):** CRITICAL — Critical issues require immediate action

Score formula: `CRITICAL×30 + HIGH×20 + MEDIUM×10 + LOW×5 + INFO×3`, capped at 100.

### System Status (right sidebar)
Four status cards showing:
- **Groq LLM** — ONLINE/OFFLINE
- **Vault** — LOCKED/UNLOCKED/NOT SET
- **Firewall** — ACTIVE/INACTIVE
- **Encryption** — Status of disk encryption

### Threat Intel Panel (right sidebar)
Shows recent IP enrichments, hash lookups, and domain checks with threat scores.

### Recent Actions Timeline (right sidebar)
Chronological list of actions taken this session. Color-coded by tier:
- White = Tier 1 (auto)
- Yellow = Tier 2 (confirmed)
- Red = Tier 3 (double confirmed)

---

## The Session Report

**Generate:** Type "generate the incident report" or click the SOC Report button in the left sidebar.

**Sections included:**
1. Report ID, timestamps, prepared-for attribution
2. Executive Summary — action count, alert count, critical findings, MITRE techniques, risk posture
3. Open Incidents — table of unresolved alerts with severity, status, time open, MITRE mapping
4. Closed/Resolved Incidents — table with resolution summaries
5. Threat Intelligence Findings — enriched IPs, hashes, domains, CVEs
6. MITRE ATT&CK Coverage — technique hit counts organized by tactic
7. Timeline of Actions — chronological log of every tool execution with tier tags
8. Errors & Anomalies — any failed tool executions or anomalous findings
9. Risk Posture — score and posture assessment with recommendations
10. SHA-256 Integrity Hash — computed over the full report content for tamper detection

**File saved to:** `data/demo_soc_report.md`

**Verifying integrity:** The SHA-256 hash at the bottom of the report is computed over all preceding content. To verify, remove the last two lines (hash and signature), compute SHA-256 of the remaining text, and compare.

---

## Voice Commands

### Activation
- **Push-to-Talk:** Click and hold the 🎤 microphone button in the terminal input area, or press and hold the Space bar
- **Wake Word:** Say "Hey Jarvis" to activate continuous listening (browser must have microphone permission)

### Browser Compatibility
- **Chrome:** Full support via Web Speech API. Best recognition accuracy.
- **Edge:** Supported.
- **Firefox/Safari:** Limited or no Web Speech API support. Use typed commands instead.

### Tips for Clear Recognition
- Speak clearly and at normal pace
- Use the exact command phrases listed in this guide
- Avoid background noise
- If recognition fails, use the typed terminal as fallback
- All voice transcription runs locally via the browser's Web Speech API — no audio is sent to any external server

---

## Troubleshooting

### Groq API key not working
- Verify your key starts with `gsk_` and is correctly set in `.env`
- Check: `curl -H "Authorization: Bearer YOUR_KEY" https://api.groq.com/openai/v1/models`
- Ensure no trailing whitespace in the `.env` file
- Groq keys are free but have rate limits — if you hit 429 errors, wait a minute

### Server won't start
- Check that port 3000 is not already in use: `netstat -an | findstr 3000`
- Verify `.env` exists in the project root
- Run `npm install` to ensure all dependencies are installed
- Check Node.js version: `node -v` (requires v16+)

### Voice input not working
- Only works in Chrome and Edge
- Grant microphone permission when prompted
- Check that no other application is using the microphone
- Try the push-to-talk button instead of wake word
- Fallback: type commands directly

### A tool returns "not implemented"
- The productivity tools (dictate_notes, generate_weekly_briefing, search_calendar) are placeholder stubs
- All other 51 tools are fully functional

### Tier 3 passphrase forgotten
- Delete the files `.jarvis/salt.bin` and `.jarvis/verify.bin`
- Restart the server
- Set a new passphrase on next Tier 3 action
- **Warning:** Existing encrypted files and vault items will become unrecoverable

### Dashboard panels not updating in real time
- Ensure the WebSocket connection is active (check browser console for connection errors)
- Try refreshing the page
- If the status indicator shows "Disconnected," the server may have restarted — refresh to reconnect

### Demo seed data not loading correctly
- Run `node scripts/seed-demo-low.js` or `node scripts/seed-demo-high.js` before starting the server
- Seed scripts create files in `data/demo-logs/` and `data/alerts.json`
- The action log is cleared on each seed run — this is intentional for a clean demo session
