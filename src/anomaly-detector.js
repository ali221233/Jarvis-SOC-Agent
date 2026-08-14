// ============================================================
// Jarvis SOC — Anomaly Detection Engine
// Learns baseline → detects deviations → alerts on anomalies.
// ============================================================

const os = require('os');
const fs = require('fs');
const path = require('path');
const { logAction } = require('./logger');

const BASELINE_FILE = path.join(__dirname, '..', 'data', 'baseline.json');
const BASELINE_HOURS = parseInt(process.env.BASELINE_HOURS || '24', 10);

let baseline = null;
let learningMode = false;
let learningStartTime = null;
let learningData = {};
let wsBroadcast = () => {};

/**
 * Initialize anomaly detector. Load existing baseline if present.
 */
function init(broadcastFn) {
  wsBroadcast = broadcastFn || (() => {});
  if (fs.existsSync(BASELINE_FILE)) {
    try {
      baseline = JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf-8'));
      console.log(`  [Anomaly] Baseline loaded from ${BASELINE_FILE}`);
    } catch (err) {
      console.error(`  [Anomaly] Failed to load baseline: ${err.message}`);
    }
  }
}

// ---- Baseline Learning ----

function startLearning() {
  learningMode = true;
  learningStartTime = Date.now();
  learningData = {};
  console.log(`  [Anomaly] Baseline learning started. Duration: ${BASELINE_HOURS} hours.`);
  logAction('Baseline learning started', 1, { tool: 'anomaly_detector', source: 'user' });

  return {
    status: 'learning',
    duration: `${BASELINE_HOURS} hours`,
    startedAt: new Date().toISOString(),
    message: `Baseline learning started, Boss. I'll observe this machine for ${BASELINE_HOURS} hours to learn what normal looks like. Use "finish baseline" to complete early.`,
  };
}

function stopLearning() {
  if (!learningMode) {
    return { error: 'Not currently in learning mode.' };
  }

  learningMode = false;
  baseline = computeBaseline(learningData);
  saveBaseline();

  logAction('Baseline learning completed', 1, { tool: 'anomaly_detector', source: 'user' });

  return {
    status: 'established',
    metrics: Object.keys(baseline),
    message: `Baseline established, Boss. I now know what normal looks like on this machine. ${Object.keys(baseline).length} metrics recorded.`,
  };
}

/**
 * Record a metric reading during learning mode.
 */
function recordReading(metricName, value) {
  if (!learningMode) return;

  if (!learningData[metricName]) {
    learningData[metricName] = [];
  }
  learningData[metricName].push(value);
}

/**
 * Take a system snapshot and record all metrics.
 */
function recordSystemSnapshot() {
  const cpuUsage = os.loadavg()[0]; // 1-minute load average
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const memUsagePercent = ((totalMem - freeMem) / totalMem) * 100;
  const uptime = os.uptime();

  if (learningMode) {
    recordReading('cpu_load_1min', cpuUsage);
    recordReading('memory_usage_percent', memUsagePercent);
    recordReading('uptime_seconds', uptime);
  }

  return { cpuUsage, memUsagePercent, uptime, freeMem, totalMem };
}

/**
 * Compute baseline statistics (mean + stddev) from learning data.
 */
function computeBaseline(data) {
  const result = {};
  for (const [metric, values] of Object.entries(data)) {
    if (values.length < 2) continue;

    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stddev = Math.sqrt(variance);

    result[metric] = {
      mean,
      stddev: stddev || 0.001, // Avoid division by zero
      min: Math.min(...values),
      max: Math.max(...values),
      samples: values.length,
      establishedAt: new Date().toISOString(),
    };
  }
  return result;
}

function saveBaseline() {
  try {
    const dir = path.dirname(BASELINE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(BASELINE_FILE, JSON.stringify(baseline, null, 2));
    console.log(`  [Anomaly] Baseline saved to ${BASELINE_FILE}`);
  } catch (err) {
    console.error(`  [Anomaly] Failed to save baseline: ${err.message}`);
  }
}

// ---- Anomaly Detection ----

/**
 * Check a metric reading against the baseline.
 * @param {string} metricName
 * @param {number} value
 * @returns {{ isAnomaly: boolean, deviations: number, severity: string } | null}
 */
function checkAnomaly(metricName, value) {
  if (!baseline || !baseline[metricName]) return null;

  const b = baseline[metricName];
  const deviations = Math.abs(value - b.mean) / b.stddev;

  if (deviations < 2) return null; // Normal

  let severity;
  if (deviations >= 4) severity = 'HIGH';
  else if (deviations >= 3) severity = 'MEDIUM';
  else severity = 'LOW';

  return {
    isAnomaly: true,
    metricName,
    currentValue: value,
    baselineMean: b.mean,
    baselineStddev: b.stddev,
    deviations: Math.round(deviations * 10) / 10,
    severity,
  };
}

/**
 * Run a full anomaly check on current system state.
 * @returns {Array} anomalies found
 */
function runAnomalyCheck() {
  if (!baseline) return [];

  const snapshot = recordSystemSnapshot();
  const anomalies = [];

  const cpuAnomaly = checkAnomaly('cpu_load_1min', snapshot.cpuUsage);
  if (cpuAnomaly) anomalies.push(cpuAnomaly);

  const memAnomaly = checkAnomaly('memory_usage_percent', snapshot.memUsagePercent);
  if (memAnomaly) anomalies.push(memAnomaly);

  // Push HIGH anomalies as WebSocket alerts
  for (const a of anomalies) {
    if (a.severity === 'HIGH') {
      wsBroadcast({
        type: 'anomaly_alert',
        ...a,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return anomalies;
}

/**
 * Update baseline with recent readings.
 */
function updateBaseline() {
  if (!baseline) {
    return { error: 'No baseline exists. Run "start baseline learning" first.' };
  }

  const snapshot = recordSystemSnapshot();

  // Add current readings to baseline
  for (const [metric, value] of Object.entries({
    cpu_load_1min: snapshot.cpuUsage,
    memory_usage_percent: snapshot.memUsagePercent,
  })) {
    if (baseline[metric]) {
      const b = baseline[metric];
      const n = b.samples + 1;
      const newMean = b.mean + (value - b.mean) / n;
      const newVariance = ((n - 1) * (b.stddev * b.stddev) + (value - b.mean) * (value - newMean)) / n;
      b.mean = newMean;
      b.stddev = Math.sqrt(newVariance) || 0.001;
      b.samples = n;
      b.min = Math.min(b.min, value);
      b.max = Math.max(b.max, value);
    }
  }

  saveBaseline();
  return { status: 'updated', metrics: Object.keys(baseline).length };
}

// ---- Status ----

function getStatus() {
  if (learningMode) {
    const elapsed = (Date.now() - learningStartTime) / 3600000;
    const remaining = Math.max(0, BASELINE_HOURS - elapsed);
    return {
      status: 'learning',
      elapsed: `${elapsed.toFixed(1)} hours`,
      remaining: `${remaining.toFixed(1)} hours`,
      metricsCollected: Object.keys(learningData).length,
      samplesCollected: Object.values(learningData).reduce((s, v) => s + v.length, 0),
    };
  }

  if (baseline) {
    return {
      status: 'active',
      establishedAt: Object.values(baseline)[0]?.establishedAt || 'unknown',
      metricsTracked: Object.keys(baseline).length,
      totalSamples: Object.values(baseline).reduce((s, v) => s + v.samples, 0),
    };
  }

  return {
    status: 'not_established',
    message: 'No baseline exists. Run "start baseline learning" to begin.',
  };
}

module.exports = {
  init,
  startLearning,
  stopLearning,
  recordReading,
  recordSystemSnapshot,
  checkAnomaly,
  runAnomalyCheck,
  updateBaseline,
  getStatus,
};
