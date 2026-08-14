# JARVIS SOC Agent v3.0

> Ali's autonomous Security Operations Center assistant.  
> Groq LPU inference · 66+ security tools · CVSS v3.1 scoring · Multi-source threat intel · Background monitoring.

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure API keys
#    Copy .env.example to .env and fill in your keys
cp .env.example .env

# 3. Seed demo data (optional)
npm run seed

# 4. Start the server
npm start

# 5. Open dashboard
#    http://localhost:3000
```

### Docker Quick Start

```bash
docker-compose up -d
# Dashboard: http://localhost:3000
```

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Dashboard (SPA)                     │
│  Metrics · Alerts · MITRE Heatmap · Terminal · Panels │
├──────────────────────────────────────────────────────┤
│          Express API + WebSocket Server               │
├──────────────────────────────────────────────────────┤
│   Command Parser ──→ Groq LLM ──→ Tool Registry     │
│      (fast-path)     (reasoning)    (66+ tools)      │
├──────────────────────────────────────────────────────┤
│   CVSS Scorer │ Tier Engine │ Logger │ SQLite DB     │
├──────────────────────────────────────────────────────┤
│  Background Monitor │ Anomaly Detector │ Notifier    │
├──────────────────────────────────────────────────────┤
│                  External APIs                        │
│  Groq · AbuseIPDB · VirusTotal · Shodan · AlienVault │
│  URLScan.io · NVD · HIBP · Gmail · Slack · ntfy.sh  │
└──────────────────────────────────────────────────────┘
```

### Processing Flow
1. **Fast-path**: Regex patterns match commands → direct tool execution (no LLM)
2. **Groq fallback**: Complex/ambiguous commands → LLM reasoning with tool-calling
3. **Tier enforcement**: Read-only (T1) → Confirm (T2) → Double-confirm + passphrase (T3)

---

## Features

### Core Security (v1.0+)
| Category | Tools | Description |
|---|---|---|
| Code Security | 8 | Secret scanning, SAST, dependency audit |
| File Security | 9 | Malware scan, sensitive data, encryption |
| Network | 8 | Firewall audit, network monitor, DNS |
| Privacy | 6 | Breach check (HIBP), phishing triage, speaker verify |
| Defense | 2 | Canary files, ransomware detection |

### SOC Operations (v2.0+)
| Feature | Description |
|---|---|
| Log Analysis | Windows Event, Linux syslog, web access logs |
| Alert Triage | CRITICAL → LOW severity, lifecycle tracking |
| Threat Intel | AbuseIPDB, local blocklist, hash DB, DGA detection |
| MITRE ATT&CK | 30 techniques across 12 tactics, session heatmap |
| Playbooks | Ransomware, brute force, insider threat, phishing, malware |

### v3.0 Improvements
| Feature | Description |
|---|---|
| **CVSS v3.1 Scoring** | Full FIRST.org formula, every finding has a vector |
| **Multi-Source Threat Intel** | AbuseIPDB + VirusTotal + Shodan + AlienVault OTX + URLScan.io in parallel |
| **Background Monitoring** | Log files, canary files, network connections, startup processes |
| **Anomaly Detection** | Baseline learning → statistical deviation detection |
| **PDF Reports** | Professional reports with CVSS badges, SHA-256 integrity hash |
| **Email Alerts** | Dark-themed HTML emails via Gmail (nodemailer) |
| **Slack Alerts** | Block Kit formatted messages via webhook |
| **Phone Notifications** | Push alerts via ntfy.sh (priority 5 bypasses DND) |
| **SQLite Database** | Persistent storage, session tracking, date-filtered queries |
| **Docker** | One-command deployment with docker-compose |

---

## API Keys (All Optional Except Groq)

| Service | Free Tier | Where to Get |
|---|---|---|
| **Groq** (required) | 1000 req/day | [console.groq.com](https://console.groq.com) |
| AbuseIPDB | 1000 checks/day | [abuseipdb.com](https://www.abuseipdb.com) |
| VirusTotal | 4 req/min | [virustotal.com](https://www.virustotal.com) |
| Shodan | 1 req/sec | [shodan.io](https://www.shodan.io) |
| AlienVault OTX | Unlimited | [otx.alienvault.com](https://otx.alienvault.com) |
| URLScan.io | 5000/day | [urlscan.io](https://urlscan.io) |
| HIBP | Paid ($3.50/mo) | [haveibeenpwned.com](https://haveibeenpwned.com) |

---

## Notification Channels

| Channel | Setup |
|---|---|
| Email | Gmail app password in .env |
| Slack | Incoming webhook URL |
| Phone | ntfy.sh topic (free, no account) |

All channels trigger on: CRITICAL alerts, canary triggers, 4σ+ anomalies, report generation.

---

## Commands

Jarvis understands natural language. Examples:

```
scan this folder for secrets
enrich IP 185.220.101.42
run the brute force playbook
start baseline learning
monitor status
send test notification
generate PDF report
past sessions
compare last session
```

---

## Tech Stack

- **Runtime**: Node.js 20+
- **LLM**: Groq (llama-3.3-70b-versatile, 500+ tok/sec)
- **Database**: SQLite (better-sqlite3)
- **Frontend**: Vanilla JS SPA, glassmorphism design
- **Notifications**: nodemailer, Slack webhooks, ntfy.sh
- **Scoring**: CVSS v3.1 (FIRST.org specification)

---

## License

MIT — Ali's Jarvis SOC Agent
