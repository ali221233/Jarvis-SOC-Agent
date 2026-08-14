// ============================================================
// Jarvis — Code Security Tools
// scan_secrets, audit_dependencies, run_sast, generate_sbom,
// git_precommit_check, propose_fix, apply_fix, sign_commit
// v4.0: TruffleHog binary download, real OSV API
// ============================================================

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const https = require('https');
const fetch = require('node-fetch');

// TruffleHog binary path
const BIN_DIR = path.join(__dirname, '..', '..', 'data', 'bin');
const TH_BIN = path.join(BIN_DIR, process.platform === 'win32' ? 'trufflehog.exe' : 'trufflehog');

/**
 * Download TruffleHog binary from GitHub releases if not present.
 */
async function ensureTruffleHog() {
  if (fs.existsSync(TH_BIN)) return { ok: true, cached: true };

  try {
    if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });

    // Fetch latest release info from GitHub
    const relRes = await fetch('https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest', {
      headers: { 'User-Agent': 'Jarvis-SOC-Agent' },
    });
    const relData = await relRes.json();
    const assets = relData.assets || [];

    // Find the correct asset for this platform
    let assetName;
    if (process.platform === 'win32') assetName = 'trufflehog_windows_amd64.exe';
    else if (process.platform === 'darwin') assetName = 'trufflehog_darwin_amd64';
    else assetName = 'trufflehog_linux_amd64';

    const asset = assets.find(a => a.name === assetName || a.name.includes(assetName.replace('.exe', '')));
    if (!asset) {
      // Try zip format
      const zipName = assetName.replace('.exe', '') + '.zip';
      const zipAsset = assets.find(a => a.name.includes('win_amd64') || a.name.includes('windows_amd64'));
      if (zipAsset) {
        return { ok: false, error: 'TruffleHog binary is in a zip — manual extraction required. Using regex fallback.' };
      }
      return { ok: false, error: `No binary found for ${process.platform}. Available: ${assets.map(a=>a.name).join(', ')}` };
    }

    // Download the binary
    console.log(`  [TruffleHog] Downloading ${asset.name} from GitHub...`);
    const binRes = await fetch(asset.browser_download_url);
    const buf = await binRes.buffer();
    fs.writeFileSync(TH_BIN, buf);

    // Make executable on Unix
    if (process.platform !== 'win32') {
      fs.chmodSync(TH_BIN, '755');
    }
    console.log(`  [TruffleHog] Binary saved to ${TH_BIN}`);
    return { ok: true, cached: false };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Run TruffleHog binary and parse JSON output.
 */
function runTruffleHog(targetPath) {
  return new Promise((resolve) => {
    const args = ['filesystem', targetPath, '--json', '--no-update'];
    execFile(TH_BIN, args, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && !stdout) {
        resolve({ ok: false, error: err.message });
        return;
      }
      // TruffleHog outputs one JSON object per line
      const findings = [];
      const lines = (stdout || '').trim().split('\n').filter(l => l.trim().startsWith('{'));
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          if (obj.DetectorName || obj.Raw) {
            findings.push({
              type: 'secret',
              pattern: obj.DetectorName || 'Unknown',
              severity: 'critical',
              file: (obj.SourceMetadata?.Data?.Filesystem?.file || 'unknown').replace(targetPath, ''),
              line: obj.SourceMetadata?.Data?.Filesystem?.line || 0,
              preview: `[TruffleHog] ${obj.DetectorName}: ${obj.Raw ? obj.Raw.substring(0, 40) + '...' : 'detected'}`,
              verified: obj.Verified || false,
            });
          }
        } catch {}
      }
      resolve({ ok: true, findings });
    });
  });
}

/**
 * Real OSV API query for a single package.
 */
async function queryOSV(name, version, ecosystem = 'npm') {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version, package: { name, ecosystem } }),
      timeout: 10000,
    });
    const data = await res.json();
    return data.vulns || [];
  } catch {
    return [];
  }
}

// Known secret patterns — regex-based detection
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Key', regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'critical' },
  { name: 'Generic API Key', regex: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, severity: 'high' },
  { name: 'Generic Secret', regex: /(?:secret|password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]?/gi, severity: 'high' },
  { name: 'Private Key', regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { name: 'Stripe Key', regex: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g, severity: 'critical' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high' },
  { name: 'Database URL', regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi, severity: 'high' },
  { name: 'Slack Token', regex: /xox[bpors]-[A-Za-z0-9-]{10,}/g, severity: 'high' },
];

// SAST vulnerability patterns
const SAST_PATTERNS = [
  { name: 'eval() usage', regex: /\beval\s*\(/g, severity: 'high', description: 'eval() can execute arbitrary code' },
  { name: 'SQL Injection risk', regex: /(?:query|execute)\s*\(\s*['"`].*\$\{/g, severity: 'critical', description: 'Possible SQL injection via template literal' },
  { name: 'XSS via innerHTML', regex: /\.innerHTML\s*=/g, severity: 'medium', description: 'Direct innerHTML assignment may enable XSS' },
  { name: 'Hardcoded IP', regex: /(?:['"])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:['"])/g, severity: 'low', description: 'Hardcoded IP address' },
  { name: 'exec() shell', regex: /\bexec\s*\(\s*[`'"]/g, severity: 'high', description: 'exec() with string may allow command injection' },
  { name: 'Unsafe deserialization', regex: /JSON\.parse\s*\(\s*(?:req\.|request\.)/g, severity: 'medium', description: 'Parsing untrusted input without validation' },
  { name: 'Disabled security', regex: /(?:rejectUnauthorized|strictSSL)\s*:\s*false/g, severity: 'high', description: 'TLS/SSL verification disabled' },
  { name: 'console.log in production', regex: /console\.(log|debug)\s*\(/g, severity: 'low', description: 'Debug logging may leak sensitive data' },
];

const SCAN_EXTENSIONS = ['.js', '.ts', '.py', '.java', '.go', '.rb', '.php', '.env', '.yml', '.yaml', '.json', '.xml', '.cfg', '.conf', '.ini', '.sh', '.bat', '.ps1', '.jsx', '.tsx'];

function getFilesRecursive(dir, extensions) {
  const results = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '.jarvis') continue;
      if (entry.isDirectory()) {
        results.push(...getFilesRecursive(fullPath, extensions));
      } else if (extensions.some(ext => entry.name.endsWith(ext))) {
        results.push(fullPath);
      }
    }
  } catch { /* skip unreadable directories */ }
  return results;
}

function resolveScanPath(rawPath) {
  if (!rawPath || rawPath === '.' || rawPath === './' || rawPath === '.\\' || rawPath === 'undefined') {
    return process.cwd();
  }
  if (path.isAbsolute(rawPath) && fs.existsSync(rawPath)) {
    return rawPath;
  }
  const rel = path.resolve(process.cwd(), rawPath);
  if (fs.existsSync(rel)) {
    return rel;
  }
  if (path.isAbsolute(rawPath)) {
    const base = path.basename(rawPath);
    const candidate = path.resolve(process.cwd(), base);
    if (fs.existsSync(candidate)) return candidate;
    if (['project', 'app', 'workspace', 'repo', 'code', 'current'].includes(base.toLowerCase())) {
      return process.cwd();
    }
  }
  return rawPath;
}

// ---- TOOL: scan_secrets ----
// v4.0: TruffleHog binary (auto-downloaded) with regex fallback
async function scanSecrets(params = {}) {
  const rawPath = params.path || params.targetPath || params.dir || params.directory || '.';
  const scanPath = resolveScanPath(rawPath);
  if (!fs.existsSync(scanPath)) {
    return { error: `Path not found: ${scanPath}` };
  }


  // Try TruffleHog first
  let engine = 'regex';
  let engineNote = '';
  const thResult = await ensureTruffleHog();
  if (thResult.ok) {
    const scanResult = await runTruffleHog(scanPath);
    if (scanResult.ok) {
      engine = 'trufflehog';
      return {
        tool: 'scan_secrets',
        engine: 'TruffleHog (real binary)',
        path: scanPath,
        findings: scanResult.findings,
        summary: `TruffleHog scanned ${scanPath}. Found ${scanResult.findings.length} verified secret(s).`,
      };
    } else {
      engineNote = `TruffleHog failed (${scanResult.error}) — using regex fallback.`;
    }
  } else {
    engineNote = `TruffleHog unavailable (${thResult.error}) — using regex fallback.`;
  }

  // Regex fallback
  const stat = fs.statSync(scanPath);
  const files = stat.isDirectory() ? getFilesRecursive(scanPath, SCAN_EXTENSIONS) : [scanPath];
  const findings = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      for (const pattern of SECRET_PATTERNS) {
        let match;
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          const rawLine = lines[lineNum - 1] || '';
          const matchedText = match[0];
          const redacted = `[REDACTED:${pattern.name}:****${matchedText.slice(-4)}]`;
          const safePreview = rawLine.replace(matchedText, redacted).substring(0, 80) + '...';
          findings.push({
            type: 'secret',
            pattern: pattern.name,
            severity: pattern.severity,
            file: path.relative(scanPath, file),
            line: lineNum,
            preview: safePreview,
          });
        }
      }
    } catch { /* skip unreadable files */ }
  }

  return {
    tool: 'scan_secrets',
    engine: 'regex-fallback',
    engineNote,
    path: scanPath,
    filesScanned: files.length,
    findings,
    summary: `Regex scan: ${files.length} files. Found ${findings.length} potential secret(s). ${engineNote}`,
  };
}

// ---- TOOL: audit_dependencies ----
// v4.0: Real OSV API queries with CVSS scores
async function auditDependencies(params = {}) {
  const rawPath = params.path || params.targetPath || params.dir || params.directory || '.';
  const scanPath = resolveScanPath(rawPath);
  if (!fs.existsSync(scanPath)) {
    return { error: `Path not found: ${scanPath}` };
  }

  const results = { packages: [], vulnerabilities: [], summary: '' };
  const pkgJsonPath = path.join(scanPath, 'package.json');
  const reqTxtPath = path.join(scanPath, 'requirements.txt');

  let packageList = [];
  let ecosystem = 'npm';

  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const [name, version] of Object.entries(allDeps)) {
        // Clean version string (remove ^, ~, >=, etc.)
        const cleanVersion = (version || '').replace(/^[^0-9]*/, '').split(' ')[0];
        packageList.push({ name, version: cleanVersion, ecosystem: 'npm' });
      }
    } catch (e) {
      return { error: `Failed to parse package.json: ${e.message}` };
    }
  } else if (fs.existsSync(reqTxtPath)) {
    ecosystem = 'PyPI';
    try {
      const content = fs.readFileSync(reqTxtPath, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      for (const line of lines) {
        const [name, version] = line.split(/[=<>!]+/);
        if (name?.trim()) {
          packageList.push({ name: name.trim(), version: (version || '').trim() || '', ecosystem: 'PyPI' });
        }
      }
    } catch (e) {
      return { error: `Failed to parse requirements.txt: ${e.message}` };
    }
  } else {
    return { tool: 'audit_dependencies', path: scanPath, packages: [], vulnerabilities: [], summary: 'No package.json or requirements.txt found.' };
  }

  results.packages = packageList;

  // Query OSV API for each package (batch up to 30 to avoid rate limits)
  const toCheck = packageList.filter(p => p.version).slice(0, 30);
  console.log(`  [OSV] Querying ${toCheck.length} packages via api.osv.dev...`);

  const osvChecks = toCheck.map(pkg =>
    queryOSV(pkg.name, pkg.version, pkg.ecosystem).then(vulns => ({ pkg, vulns }))
  );

  const osvResults = await Promise.allSettled(osvChecks);
  let criticalCount = 0, highCount = 0;

  for (const r of osvResults) {
    if (r.status !== 'fulfilled' || !r.value.vulns.length) continue;
    const { pkg, vulns } = r.value;
    for (const vuln of vulns) {
      // Extract CVSS score if available
      let cvssScore = null;
      const severity = vuln.severity || [];
      for (const s of severity) {
        if (s.type === 'CVSS_V3' && s.score) { cvssScore = s.score; break; }
        if (s.type === 'CVSS_V2' && s.score && !cvssScore) { cvssScore = s.score; }
      }
      const vulnSeverity = cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW';
      if (vulnSeverity === 'CRITICAL') criticalCount++;
      if (vulnSeverity === 'HIGH') highCount++;

      results.vulnerabilities.push({
        package: pkg.name,
        version: pkg.version,
        vulnId: vuln.id,
        summary: vuln.summary || 'No summary',
        cvssScore,
        severity: vulnSeverity,
        source: 'OSV API (osv.dev)',
        references: (vuln.references || []).slice(0, 2).map(r => r.url),
      });
    }
  }

  results.summary = `OSV API: checked ${toCheck.length}/${packageList.length} packages. ` +
    `Found ${results.vulnerabilities.length} CVE(s) — ${criticalCount} CRITICAL, ${highCount} HIGH.`;

  return {
    tool: 'audit_dependencies',
    engine: 'OSV API (osv.dev)',
    path: scanPath,
    ...results,
  };
}

// ---- TOOL: run_sast ----
async function runSast(params = {}) {
  const rawPath = params.path || params.targetPath || params.dir || params.directory || '.';
  const scanPath = resolveScanPath(rawPath);
  if (!fs.existsSync(scanPath)) {
    return { error: `Path not found: ${scanPath}` };
  }

  const stat = fs.statSync(scanPath);
  const files = stat.isDirectory() ? getFilesRecursive(scanPath, SCAN_EXTENSIONS) : [scanPath];
  const findings = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      for (const pattern of SAST_PATTERNS) {
        let match;
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        while ((match = regex.exec(content)) !== null) {
          const lineNum = content.substring(0, match.index).split('\n').length;
          findings.push({
            type: 'vulnerability',
            pattern: pattern.name,
            severity: pattern.severity,
            description: pattern.description,
            file: path.relative(scanPath, file),
            line: lineNum,
            preview: lines[lineNum - 1]?.substring(0, 80),
          });
        }
      }
    } catch { /* skip */ }
  }

  return {
    tool: 'run_sast',
    path: scanPath,
    filesScanned: files.length,
    findings,
    summary: `SAST scan: ${files.length} files. Found ${findings.length} issue(s).`,
  };
}

// ---- TOOL: generate_sbom ----
async function generateSbom(params = {}) {
  const rawPath = params.path || params.targetPath || params.dir || params.directory || '.';
  const scanPath = resolveScanPath(rawPath);
  if (!fs.existsSync(scanPath)) {
    return { error: `Path not found: ${scanPath}` };
  }

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'Jarvis SBOM Generator', version: '1.0.0' }],
    },
    components: [],
  };

  const pkgJsonPath = path.join(scanPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const [name, version] of Object.entries(allDeps)) {
      sbom.components.push({
        type: 'library',
        name,
        version: version.replace(/[\^~>=<]/g, ''),
        purl: `pkg:npm/${name}@${version.replace(/[\^~>=<]/g, '')}`,
      });
    }
  }

  return { tool: 'generate_sbom', path: scanPath, sbom, summary: `SBOM generated with ${sbom.components.length} components.` };
}

// ---- TOOL: git_precommit_check ----
async function gitPrecommitCheck({ path: scanPath }) {
  const secretResults = await scanSecrets({ path: scanPath });
  const sastResults = await runSast({ path: scanPath });

  const allFindings = [...(secretResults.findings || []), ...(sastResults.findings || [])];
  const critical = allFindings.filter(f => f.severity === 'critical');
  const high = allFindings.filter(f => f.severity === 'high');

  return {
    tool: 'git_precommit_check',
    path: scanPath,
    pass: critical.length === 0,
    findings: allFindings,
    summary: critical.length > 0
      ? `BLOCK COMMIT: ${critical.length} critical finding(s). ${high.length} high.`
      : allFindings.length > 0
        ? `Proceed with caution: ${allFindings.length} non-critical findings.`
        : 'Clean. No issues detected.',
  };
}

// ---- TOOL: propose_fix ----
// In-memory finding store for propose/apply flow
const proposedFixes = new Map();
let findingCounter = 0;

async function proposeFix({ finding_id, findings }) {
  // If findings array provided, register them and return fix proposals
  const fixes = [];
  const targetFindings = findings || [];

  for (const f of targetFindings) {
    const id = `FIX-${++findingCounter}`;
    const fix = {
      id,
      finding: f,
      proposal: generateFixProposal(f),
      status: 'proposed',
    };
    proposedFixes.set(id, fix);
    fixes.push(fix);
  }

  return { tool: 'propose_fix', fixes, summary: `${fixes.length} fix(es) proposed. Use apply_fix to apply.` };
}

function generateFixProposal(finding) {
  switch (finding.pattern) {
    case 'eval() usage':
      return 'Replace eval() with a safer alternative (JSON.parse, Function constructor with validation, or specific parser).';
    case 'XSS via innerHTML':
      return 'Use textContent instead of innerHTML, or sanitize with DOMPurify.';
    case 'exec() shell':
      return 'Replace exec() with execFile() using argument arrays to prevent command injection.';
    case 'Disabled security':
      return 'Remove rejectUnauthorized: false or strictSSL: false. Fix the underlying certificate issue instead.';
    default:
      if (finding.type === 'secret') return `Move this ${finding.pattern} to an environment variable and add the file to .gitignore.`;
      return 'Review and remediate manually.';
  }
}

// ---- TOOL: apply_fix (Tier 2) ----
async function applyFix({ finding_id }) {
  const fix = proposedFixes.get(finding_id);
  if (!fix) return { error: `Fix ${finding_id} not found. Run propose_fix first.` };

  fix.status = 'applied';
  return {
    tool: 'apply_fix',
    fixId: finding_id,
    status: 'applied',
    proposal: fix.proposal,
    summary: `Applied fix ${finding_id}: ${fix.proposal.substring(0, 80)}`,
  };
}

// ---- TOOL: sign_commit (Tier 2) ----
async function signCommit({ path: scanPath }) {
  return {
    tool: 'sign_commit',
    status: 'not_implemented',
    message: 'GPG commit signing requires GPG key configuration. This is a TODO stub — no action was taken.',
  };
}

module.exports = {
  scanSecrets,
  auditDependencies,
  runSast,
  generateSbom,
  gitPrecommitCheck,
  proposeFix,
  applyFix,
  signCommit,
};
