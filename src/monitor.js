// ============================================================
// Jarvis SOC — Persistent Background Monitor
// Runs automatically on server start. Never needs a command.
// Watches: log files, canary files, network, processes.
// ============================================================

const fs = require('fs');
const path = require('path');
const { logAction } = require('./logger');

let wsBroadcast = () => {};
let notifier = null;
let ntfyNotifier = null;

// Watcher state
const watchers = {
  logs: { active: false, lastCheck: null, findings: 0, interval: null, watches: [] },
  canary: { active: false, lastCheck: null, findings: 0, watches: [] },
  network: { active: false, lastCheck: null, findings: 0, interval: null },
  process: { active: false, lastCheck: null, findings: 0, interval: null },
  watchDrop: { active: false, lastCheck: null, findings: 0, watches: [] },
};

let paused = false;
let lastKnownConnections = new Set();
let lastKnownStartup = new Set();

// ---- Log file paths to watch ----
const LOG_WATCH_PATHS = [];
const DATA_DIR = path.join(__dirname, '..', 'data');
const DEMO_LOGS_DIR = path.join(DATA_DIR, 'demo-logs');

// Debounce timers
const debounceTimers = {};

/**
 * Initialize and start all background watchers.
 */
function start(broadcastFn) {
  wsBroadcast = broadcastFn || (() => {});

  // Load notifiers safely
  try { notifier = require('./notifier'); } catch {}
  try { ntfyNotifier = require('./ntfy-notifier'); } catch {}

  console.log('  [Monitor] Starting background watchers...');

  startLogWatcher();
  startNetworkWatcher();
  startProcessWatcher();
  startWatchDropWatcher();

  console.log('  [Monitor] All watchers active.');
}

/**
 * Stop all watchers.
 */
function stop() {
  for (const key of Object.keys(watchers)) {
    if (watchers[key].interval) {
      clearInterval(watchers[key].interval);
      watchers[key].interval = null;
    }
    if (watchers[key].watches) {
      for (const w of watchers[key].watches) {
        try { w.close(); } catch {}
      }
      watchers[key].watches = [];
    }
    watchers[key].active = false;
  }
  console.log('  [Monitor] All watchers stopped.');
}

// ---- LOG FILE WATCHER ----

function startLogWatcher() {
  // Watch demo-logs directory for changes
  if (!fs.existsSync(DEMO_LOGS_DIR)) {
    fs.mkdirSync(DEMO_LOGS_DIR, { recursive: true });
  }

  try {
    const watcher = fs.watch(DEMO_LOGS_DIR, { persistent: false }, (eventType, filename) => {
      if (paused || !filename) return;

      // Debounce 500ms
      const key = `log_${filename}`;
      if (debounceTimers[key]) clearTimeout(debounceTimers[key]);
      debounceTimers[key] = setTimeout(() => {
        handleLogChange(filename);
      }, 500);
    });

    watchers.logs.watches = [watcher];
    watchers.logs.active = true;
    watchers.logs.lastCheck = new Date().toISOString();
    console.log(`  [Monitor] Log watcher active on: ${DEMO_LOGS_DIR}`);
  } catch (err) {
    console.error(`  [Monitor] Log watcher error: ${err.message}`);
    // Retry after 5 seconds
    setTimeout(startLogWatcher, 5000);
  }
}

async function handleLogChange(filename) {
  watchers.logs.lastCheck = new Date().toISOString();

  const filePath = path.join(DEMO_LOGS_DIR, filename);
  if (!fs.existsSync(filePath)) return;

  try {
    // Get tool registry for parsing
    const toolRegistry = require('./tool-registry');

    let tool = null;
    if (filename.includes('windows') || filename.includes('event')) {
      tool = toolRegistry.getTool('parse_windows_event_log');
    } else if (filename.includes('auth') || filename.includes('syslog')) {
      tool = toolRegistry.getTool('parse_linux_syslog');
    } else if (filename.includes('access') || filename.includes('nginx') || filename.includes('apache')) {
      tool = toolRegistry.getTool('parse_web_server_log');
    }

    if (tool) {
      const result = await tool.execute({ logPath: filePath });
      const findings = result?.flaggedEvents || result?.findings || [];
      const criticalFindings = findings.filter(f =>
        f.severity === 'CRITICAL' || f.severity === 'HIGH'
      );

      if (criticalFindings.length > 0) {
        watchers.logs.findings += criticalFindings.length;
        const alertData = {
          severity: criticalFindings[0].severity || 'HIGH',
          title: `Background: ${criticalFindings.length} critical finding(s) in ${filename}`,
          details: criticalFindings.map(f => f.description || f.message || f.eventId).join('; '),
          source: 'background_monitor',
        };

        // Create alert
        try {
          const socAlerts = require('./tools/soc-alerts');
          await socAlerts.createAlert(alertData);
        } catch {}

        // Push WebSocket
        wsBroadcast({ type: 'monitor_alert', ...alertData, timestamp: new Date().toISOString() });

        // Notify
        await notifyAll(alertData);

        logAction(`Background monitor: ${criticalFindings.length} finding(s) in ${filename}`, 1, {
          tool: 'background_monitor', status: 'completed', source: 'background_monitor',
          severity: alertData.severity,
        });
      }
    }
  } catch (err) {
    console.error(`  [Monitor] Log parse error: ${err.message}`);
  }
}

// ---- CANARY FILE WATCHER ----

function watchCanaryFiles(paths) {
  // Close existing canary watches
  for (const w of watchers.canary.watches) {
    try { w.close(); } catch {}
  }
  watchers.canary.watches = [];

  for (const canaryPath of paths) {
    if (!fs.existsSync(canaryPath)) continue;

    try {
      const watcher = fs.watch(canaryPath, { persistent: false }, (eventType) => {
        if (paused) return;
        handleCanaryTrigger(canaryPath, eventType);
      });
      watchers.canary.watches.push(watcher);
    } catch (err) {
      console.error(`  [Monitor] Canary watch error for ${canaryPath}: ${err.message}`);
    }
  }

  watchers.canary.active = watchers.canary.watches.length > 0;
  watchers.canary.lastCheck = new Date().toISOString();
  console.log(`  [Monitor] Canary watcher active on ${watchers.canary.watches.length} files`);
}

async function handleCanaryTrigger(filePath, eventType) {
  watchers.canary.findings++;
  watchers.canary.lastCheck = new Date().toISOString();

  const alertData = {
    severity: 'CRITICAL',
    title: `CANARY FILE TRIGGERED: ${path.basename(filePath)}`,
    details: `Canary file ${eventType}: ${filePath}. Possible ransomware or unauthorized file access detected. IMMEDIATE INVESTIGATION REQUIRED.`,
    source: 'canary_watcher',
  };

  // Create alert
  try {
    const socAlerts = require('./tools/soc-alerts');
    await socAlerts.createAlert(alertData);
  } catch {}

  // Push WebSocket — high priority
  wsBroadcast({ type: 'canary_alert', priority: 'interrupt', ...alertData, timestamp: new Date().toISOString() });

  // Notify ALL channels immediately
  await notifyAll(alertData);

  logAction(`CANARY TRIGGERED: ${filePath}`, 1, {
    tool: 'canary_watcher', status: 'completed', source: 'background_monitor',
    severity: 'CRITICAL',
  });

  console.log(`  [Monitor] ⚠️ CANARY TRIGGERED: ${filePath}`);
}

// ---- NETWORK CONNECTION WATCHER ----

function startNetworkWatcher() {
  watchers.network.active = true;
  watchers.network.lastCheck = new Date().toISOString();

  // Every 60 seconds
  watchers.network.interval = setInterval(async () => {
    if (paused) return;
    try {
      await checkNetworkConnections();
    } catch (err) {
      console.error(`  [Monitor] Network check error: ${err.message}`);
    }
  }, 60000);

  // Initial check
  checkNetworkConnections().catch(() => {});
}

async function checkNetworkConnections() {
  watchers.network.lastCheck = new Date().toISOString();

  try {
    const toolRegistry = require('./tool-registry');
    const tool = toolRegistry.getTool('monitor_network');
    if (!tool) return;

    const result = await tool.execute({});
    const connections = result?.connections || [];
    const currentIps = new Set(connections.map(c => c.remoteAddress || c.ip).filter(Boolean));

    // Find new IPs
    const newIps = [];
    for (const ip of currentIps) {
      if (!lastKnownConnections.has(ip) && ip !== '127.0.0.1' && ip !== '::1' && ip !== '0.0.0.0') {
        newIps.push(ip);
      }
    }

    lastKnownConnections = currentIps;

    // Auto-enrich new IPs
    for (const ip of newIps) {
      watchers.network.findings++;

      try {
        const enrichTool = toolRegistry.getTool('enrich_ip');
        if (enrichTool) {
          const enrichResult = await enrichTool.execute({ ipAddress: ip });
          const abuseScore = enrichResult?.abuseScore || enrichResult?.score || 0;

          const severity = abuseScore > 50 ? 'HIGH' : 'MEDIUM';
          const alertData = {
            severity,
            title: `New outbound connection: ${ip}`,
            details: `Abuse score: ${abuseScore}. Auto-enriched by background monitor.`,
            source: 'network_watcher',
          };

          if (abuseScore > 50) {
            try {
              const socAlerts = require('./tools/soc-alerts');
              await socAlerts.createAlert(alertData);
            } catch {}
            wsBroadcast({ type: 'monitor_alert', ...alertData, timestamp: new Date().toISOString() });
            await notifyAll(alertData);
          }

          logAction(`Background: new connection to ${ip} (abuse: ${abuseScore})`, 1, {
            tool: 'background_monitor', source: 'background_monitor', severity,
          });
        }
      } catch {}
    }
  } catch (err) {
    console.error(`  [Monitor] Network error: ${err.message}`);
  }
}

// ---- PROCESS WATCHER ----

function startProcessWatcher() {
  watchers.process.active = true;
  watchers.process.lastCheck = new Date().toISOString();

  // Every 2 minutes
  watchers.process.interval = setInterval(async () => {
    if (paused) return;
    try {
      await checkStartupProcesses();
    } catch (err) {
      console.error(`  [Monitor] Process check error: ${err.message}`);
    }
  }, 120000);

  // Initial check
  checkStartupProcesses().catch(() => {});
}

async function checkStartupProcesses() {
  watchers.process.lastCheck = new Date().toISOString();

  try {
    const toolRegistry = require('./tool-registry');
    const tool = toolRegistry.getTool('audit_startup_processes');
    if (!tool) return;

    const result = await tool.execute({});
    const entries = result?.entries || result?.processes || [];
    const currentEntries = new Set(entries.map(e => e.name || e.path || JSON.stringify(e)));

    // Find new entries
    if (lastKnownStartup.size > 0) {
      for (const entry of currentEntries) {
        if (!lastKnownStartup.has(entry)) {
          watchers.process.findings++;
          const alertData = {
            severity: 'HIGH',
            title: `New startup entry detected: ${entry.substring(0, 80)}`,
            details: `A new startup/autorun entry appeared that was not present 2 minutes ago.`,
            source: 'process_watcher',
          };

          try {
            const socAlerts = require('./tools/soc-alerts');
            await socAlerts.createAlert(alertData);
          } catch {}

          wsBroadcast({ type: 'monitor_alert', ...alertData, timestamp: new Date().toISOString() });
          await notifyAll(alertData);

          logAction(`Background: new startup entry: ${entry.substring(0, 60)}`, 1, {
            tool: 'background_monitor', source: 'background_monitor', severity: 'HIGH',
          });
        }
      }
    }

    lastKnownStartup = currentEntries;
  } catch (err) {
    console.error(`  [Monitor] Process error: ${err.message}`);
  }
}

// ---- Notify All Channels ----

async function notifyAll(alertData) {
  try {
    if (notifier) await notifier.notify(alertData);
  } catch {}
  try {
    if (ntfyNotifier) await ntfyNotifier.sendNtfy(alertData);
  } catch {}
}

// ---- Control API ----

function pause() {
  paused = true;
  console.log('  [Monitor] Paused.');
}

function resume() {
  paused = false;
  console.log('  [Monitor] Resumed.');
}

// ---- WATCH-DROP FOLDER WATCHER ----
// Watches data/watch-drop/ for new files and auto-scans them.

const WATCH_DROP_DIR = path.join(DATA_DIR, 'watch-drop');

function startWatchDropWatcher() {
  if (!fs.existsSync(WATCH_DROP_DIR)) {
    fs.mkdirSync(WATCH_DROP_DIR, { recursive: true });
  }

  try {
    const watcher = fs.watch(WATCH_DROP_DIR, { persistent: false }, (eventType, filename) => {
      if (paused || !filename || eventType !== 'rename') return;

      const filePath = path.join(WATCH_DROP_DIR, filename);
      if (!fs.existsSync(filePath)) return; // file deleted, not added

      const key = `drop_${filename}`;
      if (debounceTimers[key]) clearTimeout(debounceTimers[key]);
      debounceTimers[key] = setTimeout(() => {
        handleWatchDrop(filePath, filename);
      }, 500);
    });

    watchers.watchDrop.watches = [watcher];
    watchers.watchDrop.active = true;
    watchers.watchDrop.lastCheck = new Date().toISOString();
    console.log(`  [Monitor] Watch-drop watcher active on: ${WATCH_DROP_DIR}`);
  } catch (err) {
    console.error(`  [Monitor] Watch-drop watcher error: ${err.message}`);
  }
}

async function handleWatchDrop(filePath, filename) {
  watchers.watchDrop.lastCheck = new Date().toISOString();
  watchers.watchDrop.findings++;

  console.log(`  [Monitor] New file detected in watch-drop: ${filename}`);

  const stat = fs.statSync(filePath);
  const ext = path.extname(filename).toLowerCase();

  // Broadcast to dashboard
  wsBroadcast({
    type: 'watch_drop',
    filename,
    filePath,
    fileSize: stat.size,
    timestamp: new Date().toISOString(),
    message: `New file dropped: ${filename} (${stat.size} bytes) — scanning...`,
  });

  // Trigger n8n file_drop workflow
  setImmediate(async () => {
    try {
      const n8nClient = require('./n8n-client');
      await n8nClient.triggerFileDrop({
        filePath,
        fileName: filename,
        fileSize: stat.size,
        fileExtension: ext,
      });
    } catch {}

    // Auto scan malware
    try {
      const toolRegistry = require('./tool-registry');
      const scanTool = toolRegistry.getTool('scan_malware');
      if (scanTool) {
        const result = await scanTool.execute({ path: filePath });
        wsBroadcast({
          type: 'watch_drop_scan',
          filename,
          scan: 'malware',
          findings: result.findings || [],
          summary: result.summary,
        });

        // Auto scan secrets for text files
        const textExts = ['.txt', '.js', '.py', '.json', '.yaml', '.yml', '.env', '.sh', '.bat', '.ps1', '.xml', '.csv'];
        if (textExts.includes(ext)) {
          const secretTool = toolRegistry.getTool('scan_secrets');
          if (secretTool) {
            const secretResult = await secretTool.execute({ path: filePath });
            wsBroadcast({
              type: 'watch_drop_scan',
              filename,
              scan: 'secrets',
              findings: secretResult.findings || [],
              summary: secretResult.summary,
            });
          }
        }
      }
    } catch (err) {
      console.error(`  [Monitor] Watch-drop scan error: ${err.message}`);
    }
  });
}

function getStatus() {
  return {
    paused,
    watchers: {
      logs: {
        active: watchers.logs.active && !paused,
        lastCheck: watchers.logs.lastCheck,
        findings: watchers.logs.findings,
      },
      canary: {
        active: watchers.canary.active && !paused,
        lastCheck: watchers.canary.lastCheck,
        findings: watchers.canary.findings,
        watchedFiles: watchers.canary.watches.length,
      },
      network: {
        active: watchers.network.active && !paused,
        lastCheck: watchers.network.lastCheck,
        findings: watchers.network.findings,
      },
      process: {
        active: watchers.process.active && !paused,
        lastCheck: watchers.process.lastCheck,
        findings: watchers.process.findings,
      },
      watchDrop: {
        active: watchers.watchDrop.active && !paused,
        lastCheck: watchers.watchDrop.lastCheck,
        findings: watchers.watchDrop.findings,
        directory: WATCH_DROP_DIR,
      },
    },
    totalFindings: Object.values(watchers).reduce((s, w) => s + w.findings, 0),
  };
}

module.exports = {
  start,
  stop,
  pause,
  resume,
  getStatus,
  watchCanaryFiles,
  startWatchDropWatcher,
};
