// ============================================================
// Jarvis — Ransomware & Anomaly Defense
// deploy_canary_files, detect_mass_file_change
// ============================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Active canary watchers
const activeWatchers = new Map();
let alertCallback = null;

// Set callback for canary alerts (called by server to push via WebSocket)
function setAlertCallback(cb) {
  alertCallback = cb;
}

// ---- TOOL: deploy_canary_files (Tier 2) ----
async function deployCanaryFiles({ paths: canaryPaths }) {
  if (!canaryPaths || !Array.isArray(canaryPaths) || canaryPaths.length === 0) {
    return { error: 'Provide an array of directory paths to deploy canary files in.' };
  }

  const deployed = [];
  const errors = [];

  for (const dir of canaryPaths) {
    if (!fs.existsSync(dir)) {
      errors.push({ dir, error: 'Directory not found' });
      continue;
    }

    // Create a canary file with known content
    const canaryName = `.jarvis_canary_${crypto.randomBytes(4).toString('hex')}.txt`;
    const canaryPath = path.join(dir, canaryName);
    const canaryContent = `JARVIS CANARY FILE — DO NOT MODIFY\nHash: ${crypto.randomBytes(32).toString('hex')}\nDeployed: ${new Date().toISOString()}\n`;

    try {
      fs.writeFileSync(canaryPath, canaryContent);

      // Watch for changes
      const watcher = fs.watch(canaryPath, (eventType) => {
        if (eventType === 'change' || eventType === 'rename') {
          const alert = {
            type: 'canary_trigger',
            severity: 'critical',
            path: canaryPath,
            directory: dir,
            event: eventType,
            timestamp: new Date().toISOString(),
            message: `Canary file modified in ${dir}! Possible ransomware or unauthorized file modification detected.`,
          };

          console.error(`[CANARY ALERT] ${alert.message}`);

          if (alertCallback) {
            alertCallback(alert);
          }
        }
      });

      // Prevent crash if the watched file is deleted or becomes inaccessible
      watcher.on('error', (err) => {
        console.error(`[CANARY] Watcher error on ${canaryPath}: ${err.message}`);
        try { watcher.close(); } catch {}
        activeWatchers.delete(canaryPath);
      });

      activeWatchers.set(canaryPath, watcher);
      deployed.push({ dir, canaryFile: canaryName, path: canaryPath });
    } catch (err) {
      errors.push({ dir, error: err.message });
    }
  }

  return {
    tool: 'deploy_canary_files',
    deployed,
    errors,
    activeWatchers: activeWatchers.size,
    summary: `Deployed ${deployed.length} canary file(s) across ${canaryPaths.length} directories. ${errors.length} error(s).`,
  };
}

// ---- TOOL: detect_mass_file_change (Tier 1) ----
// Snapshots a directory and compares to detect rapid modifications
const directorySnapshots = new Map();

async function detectMassFileChange({ path: targetPath, threshold = 10 }) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return { error: `Path not found: ${targetPath}` };
  }

  // Take current snapshot
  const currentSnapshot = {};
  const files = getFilesShallow(targetPath);

  for (const file of files) {
    try {
      const stat = fs.statSync(file);
      currentSnapshot[file] = {
        size: stat.size,
        mtime: stat.mtime.getTime(),
        exists: true,
      };
    } catch {
      currentSnapshot[file] = { exists: false };
    }
  }

  // Compare with previous snapshot
  const previousSnapshot = directorySnapshots.get(targetPath);
  directorySnapshots.set(targetPath, { snapshot: currentSnapshot, timestamp: new Date().toISOString() });

  if (!previousSnapshot) {
    return {
      tool: 'detect_mass_file_change',
      path: targetPath,
      filesTracked: files.length,
      baseline: true,
      summary: `Baseline snapshot taken for ${targetPath} (${files.length} files). Run again to detect changes.`,
    };
  }

  // Find changes
  const changes = { modified: [], created: [], deleted: [], renamed: [] };
  const prev = previousSnapshot.snapshot;

  for (const [file, info] of Object.entries(currentSnapshot)) {
    if (!prev[file]) {
      changes.created.push(file);
    } else if (info.mtime !== prev[file].mtime || info.size !== prev[file].size) {
      changes.modified.push(file);
    }
  }

  for (const file of Object.keys(prev)) {
    if (!currentSnapshot[file]) {
      changes.deleted.push(file);
    }
  }

  const totalChanges = changes.modified.length + changes.created.length + changes.deleted.length;
  const suspicious = totalChanges >= threshold;

  const result = {
    tool: 'detect_mass_file_change',
    path: targetPath,
    changes,
    totalChanges,
    threshold,
    suspicious,
    previousScan: previousSnapshot.timestamp,
    summary: suspicious
      ? `ALERT: ${totalChanges} file changes detected (threshold: ${threshold}). Possible mass-modification attack.`
      : `${totalChanges} file change(s) detected. Below threshold (${threshold}).`,
  };

  // If suspicious, trigger alert
  if (suspicious && alertCallback) {
    alertCallback({
      type: 'mass_file_change',
      severity: 'critical',
      ...result,
    });
  }

  return result;
}

function getFilesShallow(dir, depth = 2) {
  const results = [];
  function walk(d, currentDepth) {
    if (currentDepth > depth) return;
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith('.')) continue;
        const fullPath = path.join(d, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath, currentDepth + 1);
        } else {
          results.push(fullPath);
        }
      }
    } catch { /* skip */ }
  }
  walk(dir, 0);
  return results;
}

function cleanup() {
  for (const [, watcher] of activeWatchers) {
    watcher.close();
  }
  activeWatchers.clear();
}

process.on('exit', cleanup);

module.exports = {
  deployCanaryFiles,
  detectMassFileChange,
  setAlertCallback,
  cleanup,
};
