// ============================================================
// Jarvis — Privacy & Identity Tools
// check_breach_status, audit_browser_extensions,
// triage_phishing_email, vault_store, vault_retrieve,
// verify_speaker
//
// VAULT: Uses KeyManager (Argon2id-derived AES-256-GCM).
// vault_retrieve (Tier 3) requires passphrase re-entry.
// verify_speaker is a stub until real voice biometrics ship.
// ============================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const keyManager = require('../key-manager');

const VAULT_DIR = path.join(__dirname, '..', '..', '.jarvis', 'vault');

function ensureVaultDir() {
  if (!fs.existsSync(VAULT_DIR)) {
    fs.mkdirSync(VAULT_DIR, { recursive: true });
  }
}

// ---- TOOL: check_breach_status (Tier 1) ----
// DISCLOSURE: Simulated with realistic mock data. Real implementation would use HIBP API.
async function checkBreachStatus({ account }) {
  if (!account) return { error: 'No account/email provided.' };

  // Simulated breach database — DISCLOSED as mock data
  const mockBreaches = {
    'demo@example.com': [
      { name: 'ExampleCorp', date: '2024-03-15', dataTypes: ['email', 'password hash', 'username'], severity: 'high' },
      { name: 'SomeService', date: '2023-11-02', dataTypes: ['email'], severity: 'low' },
    ],
  };

  const breaches = mockBreaches[account.toLowerCase()] || [];

  return {
    tool: 'check_breach_status',
    account,
    breaches,
    breachCount: breaches.length,
    disclosure: 'This uses simulated breach data for demonstration. For real breach checking, integrate the Have I Been Pwned API (requires API key).',
    summary: breaches.length > 0
      ? `Found ${breaches.length} breach(es) for ${account}. Review details.`
      : `No known breaches found for ${account}. Note: this is simulated data.`,
  };
}

// ---- TOOL: audit_browser_extensions (Tier 1) ----
async function auditBrowserExtensions() {
  const os = require('os');
  const platform = os.platform();
  const homeDir = os.homedir();
  const extensionPaths = [];

  if (platform === 'win32') {
    extensionPaths.push(
      path.join(homeDir, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions'),
      path.join(homeDir, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions'),
    );
  } else if (platform === 'darwin') {
    extensionPaths.push(
      path.join(homeDir, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions'),
    );
  } else {
    extensionPaths.push(
      path.join(homeDir, '.config', 'google-chrome', 'Default', 'Extensions'),
    );
  }

  const extensions = [];
  for (const extPath of extensionPaths) {
    if (!fs.existsSync(extPath)) continue;
    try {
      const dirs = fs.readdirSync(extPath, { withFileTypes: true });
      for (const dir of dirs) {
        if (!dir.isDirectory()) continue;
        const extId = dir.name;
        // Try to read manifest
        const versionDirs = fs.readdirSync(path.join(extPath, extId)).filter(d =>
          fs.statSync(path.join(extPath, extId, d)).isDirectory()
        );
        for (const ver of versionDirs) {
          const manifestPath = path.join(extPath, extId, ver, 'manifest.json');
          if (fs.existsSync(manifestPath)) {
            try {
              const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
              extensions.push({
                id: extId,
                name: manifest.name || 'Unknown',
                version: manifest.version || ver,
                permissions: manifest.permissions || [],
                browser: extPath.includes('Chrome') ? 'Chrome' : extPath.includes('Edge') ? 'Edge' : 'Other',
              });
            } catch { /* skip malformed manifests */ }
          }
        }
      }
    } catch { /* skip inaccessible */ }
  }

  // Flag extensions with broad permissions
  const riskyPermissions = ['<all_urls>', 'tabs', 'webRequest', 'webRequestBlocking', 'cookies', 'history'];
  const risky = extensions.filter(ext =>
    ext.permissions.some(p => riskyPermissions.includes(p))
  );

  return {
    tool: 'audit_browser_extensions',
    totalExtensions: extensions.length,
    riskyExtensions: risky,
    extensions,
    summary: risky.length > 0
      ? `Found ${extensions.length} extensions, ${risky.length} with broad permissions. Review risky ones.`
      : `Found ${extensions.length} extensions. None flagged as high-risk.`,
  };
}

// ---- TOOL: triage_phishing_email (Tier 1) ----
async function triagePhishingEmail(params = {}) {
  let emailText = params.content || params.email || params.emailContent || '';
  const inputPath = params.filePath || params.path || (typeof params.content === 'string' && params.content.length < 260 ? params.content : null);

  if (inputPath) {
    const candidatePath = path.isAbsolute(inputPath) ? inputPath : path.resolve(process.cwd(), inputPath);
    if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
      try {
        emailText = fs.readFileSync(candidatePath, 'utf-8');
      } catch {}
    }
  }

  // Fallback to sample if empty
  if (!emailText || !emailText.trim()) {
    const samplePath = path.join(process.cwd(), 'data', 'demo-logs', 'phishing_sample.eml');
    if (fs.existsSync(samplePath)) {
      try { emailText = fs.readFileSync(samplePath, 'utf-8'); } catch {}
    }
  }

  if (!emailText || !emailText.trim()) {
    return { error: 'No email content or file path provided to triage.' };
  }

  const indicators = [];
  let score = 0;

  // Extract headers
  const fromMatch = emailText.match(/^From:\s*(.+)$/im);
  const replyToMatch = emailText.match(/^Reply-To:\s*(.+)$/im);
  const subjectMatch = emailText.match(/^Subject:\s*(.+)$/im);
  const authMatch = emailText.match(/^Authentication-Results:\s*(.+)$/im);

  const fromHeader = fromMatch ? fromMatch[1].trim() : 'Unknown';
  const replyToHeader = replyToMatch ? replyToMatch[1].trim() : null;
  const subjectHeader = subjectMatch ? subjectMatch[1].trim() : 'No Subject';

  // Check SPF / DKIM alignment
  if (authMatch && (authMatch[1].includes('spf=fail') || authMatch[1].includes('dkim=fail') || authMatch[1].includes('dmarc=fail'))) {
    indicators.push({ type: 'spf_dkim_failure', details: 'SPF/DKIM/DMARC authentication failed', severity: 'high' });
    score += 35;
  }

  // Reply-To mismatch
  if (replyToHeader && fromHeader && !fromHeader.includes(replyToHeader.split('@')[1] || '---')) {
    indicators.push({ type: 'reply_to_mismatch', from: fromHeader, replyTo: replyToHeader, severity: 'high' });
    score += 25;
  }

  // Urgency language
  const urgencyWords = ['urgent', 'immediately', 'suspend', 'expire', 'verify now', 'act now', 'limited time', 'account will be', 'within 24 hours', 'deactivation'];
  for (const word of urgencyWords) {
    if (emailText.toLowerCase().includes(word)) {
      indicators.push({ type: 'urgency', word, severity: 'medium' });
      score += 15;
    }
  }

  // Suspicious links
  const linkRegex = /https?:\/\/[^\s<>"]+/gi;
  const links = emailText.match(linkRegex) || [];
  for (const link of links) {
    if (link.includes('bit.ly') || link.includes('tinyurl') || link.includes('goo.gl') || link.includes('is.gd')) {
      indicators.push({ type: 'shortened_url', url: link, severity: 'high' });
      score += 25;
    }
    if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(link)) {
      indicators.push({ type: 'ip_url', url: link, severity: 'high' });
      score += 30;
    }
  }

  // Suspicious Top Level Domains
  if (emailText.match(/@.*\.ru\b/i) || emailText.match(/@.*\.cn\b/i) || emailText.match(/@.*\.xyz\b/i) || emailText.match(/@.*\.top\b/i)) {
    indicators.push({ type: 'suspicious_domain_tld', severity: 'medium' });
    score += 20;
  }

  // Request for credentials
  const credWords = ['password', 'credit card', 'social security', 'ssn', 'bank account', 'login credentials', 'verify your identity', 'confirm your login'];
  for (const word of credWords) {
    if (emailText.toLowerCase().includes(word)) {
      indicators.push({ type: 'credential_request', word, severity: 'high' });
      score += 20;
    }
  }

  score = Math.min(score, 100);
  let verdict;
  if (score >= 60) verdict = 'LIKELY_PHISHING';
  else if (score >= 30) verdict = 'SUSPICIOUS';
  else verdict = 'PROBABLY_SAFE';

  return {
    tool: 'triage_phishing_email',
    verdict,
    score,
    headers: { from: fromHeader, replyTo: replyToHeader, subject: subjectHeader },
    indicators,
    recommendations: score >= 60
      ? ['Block sender domain on mail gateway', 'Purge message from all user inboxes', 'Invalidate credentials if link was clicked', 'Block target URL/IP on firewall']
      : ['No immediate action required'],
    summary: `Phishing score: ${score}/100 — ${verdict}. ${indicators.length} indicator(s) identified in email ("${subjectHeader}").`,
  };
}


// ---- TOOL: vault_store (Tier 2) ----
// Encrypts item with KeyManager-derived key
async function vaultStore({ item, name }) {
  if (!item || !name) return { error: 'Both item content and name are required.' };

  if (!keyManager.hasSessionKey()) {
    return { error: 'No active session key. Enter your master passphrase first.' };
  }

  ensureVaultDir();

  const data = Buffer.from(JSON.stringify({ name, content: item, storedAt: new Date().toISOString() }));
  const encrypted = keyManager.encrypt(data);

  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const filePath = path.join(VAULT_DIR, `${safeName}.vault`);
  fs.writeFileSync(filePath, encrypted);

  return {
    tool: 'vault_store',
    name,
    path: filePath,
    summary: `Stored "${name}" in vault (AES-256-GCM encrypted).`,
  };
}

// ---- TOOL: vault_retrieve (Tier 3) ----
// Requires passphrase re-entry — enforced by tier-engine
async function vaultRetrieve({ name }) {
  if (!name) return { error: 'Vault item name required.' };

  if (!keyManager.hasSessionKey()) {
    return { error: 'No active session key. Passphrase re-entry required for vault access.' };
  }

  ensureVaultDir();

  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');
  const filePath = path.join(VAULT_DIR, `${safeName}.vault`);

  if (!fs.existsSync(filePath)) {
    return { error: `Vault item "${name}" not found.` };
  }

  try {
    const encrypted = fs.readFileSync(filePath);
    const decrypted = keyManager.decrypt(encrypted);
    const item = JSON.parse(decrypted.toString());

    return {
      tool: 'vault_retrieve',
      name,
      content: item.content,
      storedAt: item.storedAt,
      summary: `Retrieved "${name}" from vault.`,
    };
  } catch (err) {
    return { error: `Vault retrieval failed: ${err.message}` };
  }
}

// ---- TOOL: verify_speaker (STUB) ----
// Voice biometrics not yet implemented — returns explicit stub response
async function verifySpeaker({ audio_sample }) {
  return {
    tool: 'verify_speaker',
    verified: false,
    status: 'not_implemented',
    message: 'Voice biometrics not yet implemented. Using passphrase verification as the authentication factor for Tier 3 actions until real voice biometrics are integrated.',
  };
}

module.exports = {
  checkBreachStatus,
  auditBrowserExtensions,
  triagePhishingEmail,
  vaultStore,
  vaultRetrieve,
  verifySpeaker,
};
