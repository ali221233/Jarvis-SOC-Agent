// Verify installed packages
try {
  const k = require('kokoro-js');
  console.log('kokoro-js OK, type:', typeof k, 'keys:', Object.keys(k || {}).slice(0,5).join(', '));
} catch(e) {
  console.log('kokoro-js FAIL:', e.message);
}

try {
  const c = require('node-cron');
  console.log('node-cron OK, schedule:', typeof c.schedule);
} catch(e) {
  console.log('node-cron FAIL:', e.message);
}

// Test URLScan new key
const https = require('https');
const key = '019ffd3b-6be5-7109-981c-2e6e30f1cd5f';
const req = https.get('https://urlscan.io/api/v1/search/?q=domain:google.com&size=1', {
  headers: { 'API-Key': key }
}, (res) => {
  let b = '';
  res.on('data', c => b += c);
  res.on('end', () => {
    const d = JSON.parse(b);
    console.log('URLScan new key HTTP', res.statusCode, '— results:', (d.results || []).length);
  });
});
req.on('error', e => console.log('URLScan ERR:', e.message));
