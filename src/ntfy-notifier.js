// ============================================================
// Jarvis SOC — Ntfy Mobile Push Notifications
// Sends push notifications to phone via ntfy.sh.
// No API key needed — topic name is the secret.
// ============================================================

const fetch = require('node-fetch');

const NTFY_TOPIC = process.env.NTFY_TOPIC || '';
const ntfyConfigured = !!NTFY_TOPIC;
const NTFY_URL = `https://ntfy.sh/${NTFY_TOPIC}`;

// Rate limiting
let lastNtfyTime = 0;
let ntfyCountToday = 0;
let lastResetDay = new Date().getDate();
const NTFY_COOLDOWN_MS = 10000;  // 10 seconds
const MAX_NTFY_PER_DAY = 50;

function resetIfNeeded() {
  const today = new Date().getDate();
  if (today !== lastResetDay) {
    ntfyCountToday = 0;
    lastResetDay = today;
  }
}

/**
 * Priority mapping: CVSS severity → ntfy priority (1-5)
 * Priority 5 bypasses do-not-disturb on most phones.
 */
const PRIORITY_MAP = {
  CRITICAL: '5',   // max — bypasses DND
  HIGH: '4',       // high
  MEDIUM: '3',     // default
  LOW: '2',        // low
  INFO: '2',       // min
};

/**
 * Tag mapping for ntfy notification icons.
 */
function getTags(alert) {
  const tags = [];
  if (alert.severity === 'CRITICAL') tags.push('warning', 'rotating_light');
  const title = (alert.title || '').toLowerCase();
  if (title.includes('brute force') || title.includes('login')) tags.push('lock');
  if (title.includes('malware') || title.includes('virus')) tags.push('bug');
  if (title.includes('ransomware') || title.includes('canary')) tags.push('fire');
  if (title.includes('report')) tags.push('page_facing_up');
  if (tags.length === 0) tags.push('shield');
  return tags.join(',');
}

/**
 * Send a push notification via ntfy.sh.
 * @param {Object} alert - { severity, title, details, id, source }
 */
async function sendNtfy(alert) {
  if (!ntfyConfigured) return;

  resetIfNeeded();
  if (ntfyCountToday >= MAX_NTFY_PER_DAY) return;

  const now = Date.now();
  if (now - lastNtfyTime < NTFY_COOLDOWN_MS) return;

  lastNtfyTime = now;
  ntfyCountToday++;

  const priority = PRIORITY_MAP[alert.severity] || '3';
  const tags = getTags(alert);
  // Ensure ASCII header values for HTTP specification compliance
  const safeTitle = (alert.title || 'Alert').replace(/[^\x20-\x7E]/g, ' ');
  const title = `JARVIS - ${alert.severity}: ${safeTitle}`;
  const message = alert.details
    ? alert.details.substring(0, 200)
    : `Security alert from Jarvis SOC. ID: ${alert.id || 'N/A'}`;

  try {
    await fetch(NTFY_URL, {
      method: 'POST',
      headers: {
        'Title': title,
        'Priority': priority,
        'Tags': tags,
      },
      body: message,
    });
    console.log(`  [Ntfy] Push sent: ${alert.severity} - ${alert.title}`);
  } catch (err) {
    console.error(`  [Ntfy] Push failed: ${err.message}`);
  }
}


/**
 * Send a test notification.
 */
async function sendTestNtfy() {
  if (!ntfyConfigured) return { ntfy: 'not configured' };

  lastNtfyTime = 0; // bypass cooldown for test
  try {
    await sendNtfy({
      severity: 'INFO',
      title: 'Jarvis Test Notification',
      details: 'This is a test push from Jarvis SOC Agent. Your phone notifications are working.',
      id: 'TEST-' + Date.now(),
    });
    return { ntfy: 'sent' };
  } catch (err) {
    return { ntfy: `failed: ${err.message}` };
  }
}

function getStatus() {
  return {
    ntfy: ntfyConfigured ? 'configured' : 'not configured',
    topic: ntfyConfigured ? NTFY_TOPIC : null,
    sentToday: ntfyCountToday,
    remaining: MAX_NTFY_PER_DAY - ntfyCountToday,
  };
}

module.exports = {
  sendNtfy,
  sendTestNtfy,
  getStatus,
  ntfyConfigured,
};
