// ============================================================
// Jarvis SOC — Threat Intelligence Enrichment
// enrich_ip, enrich_hash, check_domain, lookup_cve
// All Tier 1
// ============================================================

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const socAlerts = require('./soc-alerts');
const socMitre = require('./soc-mitre');

const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY || '';
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const SHODAN_KEY = process.env.SHODAN_API_KEY || '';
const ALIENVAULT_KEY = process.env.ALIENVAULT_API_KEY || '';
const URLSCAN_KEY = process.env.URLSCAN_API_KEY || '';
const HASHES_PATH = path.join(__dirname, '..', '..', 'data', 'malware-hashes.json');

// Rate limiting trackers
const rateLimits = {
  virustotal: { lastCall: 0, minInterval: 15000 },  // 4/min
  shodan: { lastCall: 0, minInterval: 1000 },        // 1/sec
  alienvault: { lastCall: 0, minInterval: 1000 },
  urlscan: { lastCall: 0, minInterval: 2000 },
};

function canCall(service) {
  const now = Date.now();
  const rl = rateLimits[service];
  if (!rl) return true;
  if (now - rl.lastCall < rl.minInterval) return false;
  rl.lastCall = now;
  return true;
}

let malwareHashes = [];
try { malwareHashes = JSON.parse(fs.readFileSync(HASHES_PATH, 'utf-8')); } catch {}

// Enrichment history for the threat intel panel
const enrichmentHistory = [];

// Known-bad IP ranges (Tor exit nodes, common C2)
const KNOWN_BAD_IPS = [
  '185.220.101.', '185.220.102.', '199.249.230.',  // Tor
  '23.129.64.', '45.154.255.', '91.132.147.',       // Known C2
  '194.26.29.', '45.155.205.', '193.142.146.',       // Bulletproof hosting
  '103.152.220.', '172.104.', '192.42.116.',         // Suspicious ranges
];

// Known phishing/malware domains
const KNOWN_BAD_DOMAINS = [
  'evil.com', 'malware-download.com', 'phishing-site.net',
  'c2-server.xyz', 'data-exfil.com', 'ransomware-pay.onion',
  'fake-login.com', 'credential-harvest.net', 'drive-by-download.com',
  'exploit-kit.biz',
];

// ---- TOOL: enrich_ip (Tier 1) ----
async function enrichIp({ ipAddress }) {
  if (!ipAddress) return { error: 'IP address required.' };

  const result = {
    tool: 'enrich_ip',
    ip: ipAddress,
    source: 'local',
    abuseScore: null,
    country: null,
    isp: null,
    reports: null,
    lastReported: null,
    knownBad: false,
    localMatch: false,
  };

  // Check local known-bad list
  for (const prefix of KNOWN_BAD_IPS) {
    if (ipAddress.startsWith(prefix)) {
      result.knownBad = true;
      result.localMatch = true;
      result.abuseScore = 85;
      result.summary = `${ipAddress} matches known-bad IP range (${prefix}*). Likely Tor exit node or C2 infrastructure.`;
      break;
    }
  }

  // Multi-source enrichment — query all available sources in parallel
  const sourcePromises = [];
  const sources = [];
  const skipped = [];

  // AbuseIPDB
  if (ABUSEIPDB_KEY) {
    sources.push('AbuseIPDB');
    sourcePromises.push(abuseIpDbCheck(ipAddress).catch(e => ({ error: e.message })));
  } else { skipped.push('AbuseIPDB'); }

  // Shodan
  if (SHODAN_KEY && canCall('shodan')) {
    sources.push('Shodan');
    sourcePromises.push(shodanLookup(ipAddress).catch(e => ({ error: e.message })));
  } else { skipped.push('Shodan'); }

  // AlienVault OTX
  if (ALIENVAULT_KEY && canCall('alienvault')) {
    sources.push('AlienVault');
    sourcePromises.push(alienVaultIp(ipAddress).catch(e => ({ error: e.message })));
  } else { skipped.push('AlienVault'); }

  // Query all in parallel
  const responses = await Promise.allSettled(sourcePromises);
  const scores = [];

  for (let i = 0; i < responses.length; i++) {
    const res = responses[i];
    const src = sources[i];
    const data = res.status === 'fulfilled' ? res.value : { error: res.reason?.message };

    if (data && !data.error) {
      if (src === 'AbuseIPDB') {
        result.source = 'AbuseIPDB';
        result.abuseScore = data.abuseConfidenceScore;
        result.country = data.countryCode;
        result.isp = data.isp;
        result.reports = data.totalReports;
        result.lastReported = data.lastReportedAt;
        if (data.abuseConfidenceScore > 50) result.knownBad = true;
        scores.push(data.abuseConfidenceScore);
      } else if (src === 'Shodan') {
        result.shodan = {
          ports: data.ports || [],
          os: data.os || null,
          org: data.org || null,
          vulns: data.vulns || [],
        };
        if (data.vulns && data.vulns.length > 0) {
          result.knownBad = true;
          scores.push(80);
        } else {
          scores.push(20);
        }
      } else if (src === 'AlienVault') {
        result.alienvault = {
          pulseCount: data.pulse_info?.count || 0,
          reputation: data.reputation || 0,
        };
        if ((data.pulse_info?.count || 0) > 5) {
          result.knownBad = true;
          scores.push(75);
        } else {
          scores.push(Math.min(100, (data.pulse_info?.count || 0) * 10));
        }
      }
    }
  }

  // Composite threat score (weighted average of all available)
  if (scores.length > 0) {
    result.compositeScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    result.sourcesQueried = sources;
    result.sourcesSkipped = skipped;
  }

  // Generate summary
  if (!result.summary) {
    if (result.abuseScore !== null) {
      result.summary = `${ipAddress}: Abuse score ${result.abuseScore}/100${result.country ? `, ${result.country}` : ''}${result.isp ? `, ${result.isp}` : ''}. ${result.reports || 0} reports.`;
    } else {
      result.summary = `${ipAddress}: No threat intelligence available. Not in local blocklist.`;
    }
  }

  // Auto-create alert if high risk
  if (result.knownBad || (result.abuseScore && result.abuseScore > 50)) {
    await socAlerts.createAlert({
      title: `Suspicious IP: ${ipAddress} (Score: ${result.abuseScore || 'N/A'})`,
      severity: 'HIGH',
      source: 'Threat Intelligence',
      details: result.summary,
    });
    socMitre.recordHit('T1071'); // C2 communication
  }

  // Store for panel
  enrichmentHistory.push({ type: 'ip', query: ipAddress, ...result, timestamp: new Date().toISOString() });

  return result;
}

// ---- TOOL: enrich_hash (Tier 1) ----
async function enrichHash({ fileHash }) {
  if (!fileHash) return { error: 'File hash required.' };

  const normalizedHash = fileHash.toLowerCase().trim();
  const match = malwareHashes.find(m => m.hash.toLowerCase() === normalizedHash);

  const result = {
    tool: 'enrich_hash',
    hash: normalizedHash,
    hashType: normalizedHash.length === 32 ? 'MD5' : normalizedHash.length === 64 ? 'SHA-256' : 'Unknown',
    found: !!match,
    malwareName: match ? match.name : null,
    malwareType: match ? match.type : null,
    summary: match
      ? `MATCH: ${normalizedHash} is known malware — ${match.name} (${match.type}).`
      : `CLEAN: ${normalizedHash} not found in local malware database.`,
  };

  if (match) {
    await socAlerts.createAlert({
      title: `Known Malware Hash: ${match.name}`,
      severity: 'CRITICAL',
      source: 'Hash Enrichment',
      details: `Hash ${normalizedHash} matches ${match.name} (${match.type})`,
    });
    socMitre.recordHit('T1105'); // Ingress tool transfer
  }

  enrichmentHistory.push({ type: 'hash', query: normalizedHash, ...result, timestamp: new Date().toISOString() });
  return result;
}

// ---- TOOL: check_domain (Tier 1) ----
async function checkDomain({ domain }) {
  if (!domain) return { error: 'Domain required.' };

  const normalizedDomain = domain.toLowerCase().trim();
  const result = {
    tool: 'check_domain',
    domain: normalizedDomain,
    knownBad: false,
    dgaLikely: false,
    suspiciousAge: false,
    flags: [],
  };

  // Check known-bad list
  if (KNOWN_BAD_DOMAINS.includes(normalizedDomain)) {
    result.knownBad = true;
    result.flags.push('Known malicious domain');
  }

  // DGA detection: entropy + consonant ratio
  const domainPart = normalizedDomain.split('.')[0];
  const entropy = calculateEntropy(domainPart);
  const consonantRatio = getConsonantRatio(domainPart);

  if (entropy > 3.5 && consonantRatio > 0.7 && domainPart.length > 8) {
    result.dgaLikely = true;
    result.flags.push(`DGA-like pattern (entropy: ${entropy.toFixed(2)}, consonant ratio: ${consonantRatio.toFixed(2)})`);
  }

  // Very short random-looking domains
  if (domainPart.length > 12 && /^[a-z0-9]+$/.test(domainPart) && !/[aeiou]{2}/i.test(domainPart)) {
    result.dgaLikely = true;
    result.flags.push('Random alphanumeric pattern — possible DGA');
  }

  // Note about age check
  result.ageNote = 'Domain age check requires manual WHOIS lookup or API integration.';

  result.summary = result.flags.length > 0
    ? `${normalizedDomain}: ${result.flags.join('; ')}`
    : `${normalizedDomain}: No indicators found. Appears clean.`;

  if (result.knownBad || result.dgaLikely) {
    await socAlerts.createAlert({
      title: `Suspicious Domain: ${normalizedDomain}`,
      severity: result.knownBad ? 'HIGH' : 'MEDIUM',
      source: 'Domain Analysis',
      details: result.summary,
    });
  }

  enrichmentHistory.push({ type: 'domain', query: normalizedDomain, ...result, timestamp: new Date().toISOString() });
  return result;
}

// ---- TOOL: lookup_cve (Tier 1) ----
async function lookupCve({ cveId }) {
  if (!cveId) return { error: 'CVE ID required (e.g., CVE-2021-44228).' };

  const normalizedCve = cveId.toUpperCase().trim();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalizedCve)) {
    return { error: `Invalid CVE format: ${cveId}. Expected CVE-YYYY-NNNN.` };
  }

  try {
    const nvdResult = await nvdLookup(normalizedCve);

    if (nvdResult.error) {
      return { tool: 'lookup_cve', cveId: normalizedCve, error: nvdResult.error };
    }

    const result = {
      tool: 'lookup_cve',
      cveId: normalizedCve,
      ...nvdResult,
    };

    // Auto-alert for critical CVEs
    if (nvdResult.cvssScore && nvdResult.cvssScore >= 9.0) {
      await socAlerts.createAlert({
        title: `Critical CVE: ${normalizedCve} (CVSS ${nvdResult.cvssScore})`,
        severity: 'CRITICAL',
        source: 'CVE Lookup',
        details: nvdResult.description?.substring(0, 200) || '',
      });
      socMitre.recordHit('T1190'); // Exploit public-facing app
    }

    enrichmentHistory.push({ type: 'cve', query: normalizedCve, ...result, timestamp: new Date().toISOString() });
    return result;
  } catch (err) {
    return { tool: 'lookup_cve', cveId: normalizedCve, error: err.message };
  }
}

// ---- Helpers ----

function abuseIpDbCheck(ip) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.abuseipdb.com',
      path: `/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      method: 'GET',
      headers: {
        'Key': ABUSEIPDB_KEY,
        'Accept': 'application/json',
      },
      timeout: 10000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed.data || parsed);
        } catch { resolve({ error: 'Invalid response' }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('AbuseIPDB timeout')); });
    req.end();
  });
}

function nvdLookup(cveId) {
  return new Promise((resolve, reject) => {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const parsedUrl = new URL(url);

    const options = {
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      timeout: 15000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const vuln = parsed.vulnerabilities?.[0]?.cve;
          if (!vuln) {
            resolve({ error: `CVE ${cveId} not found in NVD.` });
            return;
          }

          // Extract CVSS score
          const metrics = vuln.metrics;
          let cvssScore = null;
          let cvssSeverity = null;
          if (metrics?.cvssMetricV31?.[0]) {
            cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore;
            cvssSeverity = metrics.cvssMetricV31[0].cvssData?.baseSeverity;
          } else if (metrics?.cvssMetricV2?.[0]) {
            cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore;
            cvssSeverity = cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW';
          }

          // Extract description
          const descEn = vuln.descriptions?.find(d => d.lang === 'en');
          const description = descEn?.value || 'No description available.';

          // Extract affected software
          const affected = [];
          for (const config of (vuln.configurations || [])) {
            for (const node of (config.nodes || [])) {
              for (const cpe of (node.cpeMatch || [])) {
                if (cpe.vulnerable) {
                  affected.push(cpe.criteria?.split(':').slice(3, 5).join(' ') || cpe.criteria);
                }
              }
            }
          }

          resolve({
            description: description.substring(0, 500),
            cvssScore,
            cvssSeverity,
            published: vuln.published,
            lastModified: vuln.lastModified,
            affectedSoftware: affected.slice(0, 10),
            references: (vuln.references || []).slice(0, 5).map(r => r.url),
            summary: `${cveId}: CVSS ${cvssScore || 'N/A'} (${cvssSeverity || 'Unknown'}). ${description.substring(0, 100)}...`,
          });
        } catch (err) {
          resolve({ error: `Failed to parse NVD response: ${err.message}` });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('NVD API timeout')); });
    req.end();
  });
}

function calculateEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getConsonantRatio(str) {
  const consonants = str.replace(/[aeiou0-9\-_.]/gi, '').length;
  return str.length > 0 ? consonants / str.length : 0;
}

function getEnrichmentHistory() { return enrichmentHistory.slice(-20); }

// ---- Shodan Integration ----
function shodanLookup(ip) {
  return new Promise((resolve, reject) => {
    const url = `https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}`;
    const urlObj = new URL(url);
    const req = https.request({
      hostname: urlObj.hostname, path: urlObj.pathname + urlObj.search,
      method: 'GET', timeout: 10000,
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve({ error: 'Invalid Shodan response' }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Shodan timeout')); });
    req.end();
  });
}

// ---- AlienVault OTX Integration ----
function alienVaultIp(ip) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'otx.alienvault.com',
      path: `/api/v1/indicators/IPv4/${ip}/general`,
      method: 'GET',
      headers: { 'X-OTX-API-KEY': ALIENVAULT_KEY },
      timeout: 15000,
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve({ error: 'Invalid OTX response' }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('OTX timeout')); });
    req.end();
  });
}

function alienVaultDomain(domain) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'otx.alienvault.com',
      path: `/api/v1/indicators/domain/${domain}/general`,
      method: 'GET',
      headers: { 'X-OTX-API-KEY': ALIENVAULT_KEY },
      timeout: 15000,
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve({ error: 'Invalid OTX response' }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('OTX timeout')); });
    req.end();
  });
}

// ---- VirusTotal Integration ----
function virusTotalHash(hash) {
  if (!VIRUSTOTAL_KEY || !canCall('virustotal')) return Promise.resolve({ error: 'VT rate limited or no key' });
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.virustotal.com',
      path: `/api/v3/files/${hash}`,
      method: 'GET',
      headers: { 'x-apikey': VIRUSTOTAL_KEY },
      timeout: 15000,
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (data.data) {
            const attrs = data.data.attributes || {};
            const stats = attrs.last_analysis_stats || {};
            resolve({
              malicious: stats.malicious || 0,
              suspicious: stats.suspicious || 0,
              undetected: stats.undetected || 0,
              total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0),
              name: attrs.meaningful_name || attrs.names?.[0] || null,
              type: attrs.type_description || null,
              ratio: `${stats.malicious || 0}/${(stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0)}`,
            });
          } else {
            resolve({ error: data.error?.message || 'Not found' });
          }
        } catch { resolve({ error: 'Invalid VT response' }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('VT timeout')); });
    req.end();
  });
}

// ---- URLScan.io Integration ----
function urlscanSubmit(url) {
  if (!URLSCAN_KEY || !canCall('urlscan')) return Promise.resolve({ error: 'URLScan rate limited or no key' });
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ url, visibility: 'unlisted' });
    const req = https.request({
      hostname: 'urlscan.io',
      path: '/api/v1/scan/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': URLSCAN_KEY,
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: 10000,
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve({ error: 'Invalid URLScan response' }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('URLScan timeout')); });
    req.write(postData);
    req.end();
  });
}

module.exports = {
  enrichIp, enrichHash, checkDomain, lookupCve,
  getEnrichmentHistory,
  shodanLookup, alienVaultIp, alienVaultDomain,
  virusTotalHash, urlscanSubmit,
};
