// Verify all API keys from .env
require('dotenv').config();
const https = require('https');
const http = require('http');

function httpReq(url, options = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const urlObj = new URL(url);
    const opts = {
      hostname: urlObj.hostname,
      port: urlObj.port || (url.startsWith('https') ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: 10000,
    };
    const req = mod.request(opts, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function verify() {
  const results = [];

  // 1. GROQ
  try {
    const r = await httpReq('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
      },
      body: JSON.stringify({ model: process.env.GROQ_MODEL, messages: [{ role: 'user', content: 'ping' }], max_tokens: 5 }),
    });
    const data = JSON.parse(r.body);
    results.push(['GROQ', r.status === 200 ? 'VERIFIED' : 'FAILED', data.choices ? data.choices[0]?.message?.content : (data.error?.message || r.status)]);
  } catch (e) { results.push(['GROQ', 'FAILED', e.message]); }

  // 2. ABUSEIPDB
  try {
    const r = await httpReq('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90', {
      headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' },
    });
    results.push(['ABUSEIPDB', r.status === 200 ? 'VERIFIED' : 'FAILED', `HTTP ${r.status}`]);
  } catch (e) { results.push(['ABUSEIPDB', 'FAILED', e.message]); }

  // 3. VIRUSTOTAL
  try {
    const r = await httpReq('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
    });
    results.push(['VIRUSTOTAL', r.status === 200 ? 'VERIFIED' : 'FAILED', `HTTP ${r.status}`]);
  } catch (e) { results.push(['VIRUSTOTAL', 'FAILED', e.message]); }

  // 4. SHODAN
  try {
    const r = await httpReq(`https://api.shodan.io/api-info?key=${process.env.SHODAN_API_KEY}`);
    results.push(['SHODAN', r.status === 200 ? 'VERIFIED' : 'FAILED', `HTTP ${r.status}`]);
  } catch (e) { results.push(['SHODAN', 'FAILED', e.message]); }

  // 5. URLSCAN
  try {
    const r = await httpReq('https://urlscan.io/api/v1/search/?q=domain:google.com&size=1', {
      headers: { 'API-Key': process.env.URLSCAN_API_KEY },
    });
    results.push(['URLSCAN', r.status === 200 ? 'VERIFIED' : 'FAILED', `HTTP ${r.status}`]);
  } catch (e) { results.push(['URLSCAN', 'FAILED', e.message]); }

  // 6. ALIENVAULT
  try {
    const r = await httpReq('https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general', {
      headers: { 'X-OTX-API-KEY': process.env.ALIENVAULT_API_KEY },
    });
    results.push(['ALIENVAULT', r.status === 200 ? 'VERIFIED' : 'FAILED', `HTTP ${r.status}`]);
  } catch (e) { results.push(['ALIENVAULT', 'FAILED', e.message]); }

  // 7. HIBP
  if (!process.env.HIBP_API_KEY) {
    results.push(['HIBP', 'SKIPPED', 'No key set']);
  } else {
    try {
      const r = await httpReq('https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com', {
        headers: { 'hibp-api-key': process.env.HIBP_API_KEY, 'User-Agent': 'Jarvis-SOC' },
      });
      results.push(['HIBP', r.status === 200 || r.status === 404 ? 'VERIFIED' : 'FAILED', `HTTP ${r.status}`]);
    } catch (e) { results.push(['HIBP', 'FAILED', e.message]); }
  }

  // 8. EMAIL (just check SMTP connect)
  if (!process.env.EMAIL_APP_PASSWORD) {
    results.push(['EMAIL', 'SKIPPED', 'No password set']);
  } else {
    results.push(['EMAIL', 'CONFIGURED', `${process.env.EMAIL_FROM} → ${process.env.EMAIL_TO}`]);
  }

  // 9. SLACK
  if (!process.env.SLACK_WEBHOOK_URL) {
    results.push(['SLACK', 'SKIPPED', 'No webhook URL']);
  } else {
    results.push(['SLACK', 'CONFIGURED', 'Webhook URL set']);
  }

  // 10. NTFY
  if (!process.env.NTFY_TOPIC) {
    results.push(['NTFY', 'SKIPPED', 'No topic set']);
  } else {
    results.push(['NTFY', 'CONFIGURED', `Topic: ${process.env.NTFY_TOPIC}`]);
  }

  // Print table
  console.log('\n' + '='.repeat(60));
  console.log('API KEY VERIFICATION RESULTS');
  console.log('='.repeat(60));
  console.log(`${'API'.padEnd(15)} | ${'Status'.padEnd(12)} | Note`);
  console.log('-'.repeat(60));
  for (const [api, status, note] of results) {
    console.log(`${api.padEnd(15)} | ${status.padEnd(12)} | ${note || ''}`);
  }
  console.log('='.repeat(60));

  // Check if GROQ passed
  const groq = results.find(r => r[0] === 'GROQ');
  if (groq && groq[1] !== 'VERIFIED') {
    console.log('\n❌ GROQ FAILED — CANNOT PROCEED');
    process.exit(1);
  } else {
    console.log('\n✓ GROQ VERIFIED — proceeding with implementation');
  }
}

verify().catch(console.error);
