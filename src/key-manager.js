// ============================================================
// Jarvis — Key Manager
// Argon2id KDF for encryption key derivation.
// Master passphrase never stored in plaintext.
// ============================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const JARVIS_DIR = path.join(__dirname, '..', '.jarvis');
const SALT_FILE = path.join(JARVIS_DIR, 'salt.bin');
const VERIFY_FILE = path.join(JARVIS_DIR, 'verify.bin');

// Session-only key cache — cleared on shutdown
let sessionKey = null;
let useArgon2 = true;
let argon2 = null;

// Try to load argon2, fall back to PBKDF2
try {
  argon2 = require('argon2');
} catch {
  useArgon2 = false;
  console.warn('[KeyManager] argon2 native module not available — falling back to PBKDF2 (600k iterations).');
}

function ensureDir() {
  if (!fs.existsSync(JARVIS_DIR)) {
    fs.mkdirSync(JARVIS_DIR, { recursive: true });
  }
}

function isInitialized() {
  return fs.existsSync(SALT_FILE) && fs.existsSync(VERIFY_FILE);
}

function hasSessionKey() {
  return sessionKey !== null;
}

function getSalt() {
  ensureDir();
  if (fs.existsSync(SALT_FILE)) {
    return fs.readFileSync(SALT_FILE);
  }
  // Generate new random salt on first run
  const salt = crypto.randomBytes(16);
  fs.writeFileSync(SALT_FILE, salt);
  return salt;
}

async function deriveKey(passphrase) {
  const salt = getSalt();

  if (useArgon2 && argon2) {
    // Argon2id — preferred KDF
    const hash = await argon2.hash(passphrase, {
      type: argon2.argon2id,
      salt: salt,
      memoryCost: 65536,  // 64 MB
      timeCost: 3,
      parallelism: 1,
      hashLength: 32,     // 256-bit key
      raw: true,
    });
    return hash;
  }

  // PBKDF2 fallback — 600k iterations as recommended
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(passphrase, salt, 600000, 32, 'sha512', (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

async function initialize(passphrase) {
  ensureDir();
  const key = await deriveKey(passphrase);

  // Store a verification hash (HMAC of a known string with the derived key)
  // This lets us verify future passphrase entries without storing the key
  const verifier = crypto.createHmac('sha256', key).update('jarvis-verify').digest();
  fs.writeFileSync(VERIFY_FILE, verifier);

  sessionKey = key;
  return { success: true, method: useArgon2 ? 'argon2id' : 'pbkdf2' };
}

async function verifyPassphrase(passphrase) {
  if (!isInitialized()) {
    return { verified: false, message: 'Key manager not initialized. Set up a master passphrase first.' };
  }

  const key = await deriveKey(passphrase);
  const verifier = crypto.createHmac('sha256', key).update('jarvis-verify').digest();
  const stored = fs.readFileSync(VERIFY_FILE);

  if (crypto.timingSafeEqual(verifier, stored)) {
    sessionKey = key;
    return { verified: true };
  }

  return { verified: false, message: 'Incorrect passphrase.' };
}

function getSessionKey() {
  if (!sessionKey) {
    throw new Error('No active session key. Passphrase entry required.');
  }
  return sessionKey;
}

function clearSessionKey() {
  if (sessionKey) {
    sessionKey.fill(0); // Zeroize
  }
  sessionKey = null;
}

// Encrypt data with the session key using AES-256-GCM
function encrypt(data) {
  const key = getSessionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Return iv + authTag + ciphertext
  return Buffer.concat([iv, authTag, encrypted]);
}

// Decrypt data with the session key using AES-256-GCM
function decrypt(data) {
  const key = getSessionKey();
  const iv = data.subarray(0, 12);
  const authTag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// Cleanup on process exit
process.on('exit', clearSessionKey);
process.on('SIGINT', () => { clearSessionKey(); process.exit(); });
process.on('SIGTERM', () => { clearSessionKey(); process.exit(); });

module.exports = {
  isInitialized,
  hasSessionKey,
  initialize,
  verifyPassphrase,
  getSessionKey,
  clearSessionKey,
  encrypt,
  decrypt,
};
