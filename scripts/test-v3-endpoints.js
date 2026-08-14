// Quick v3.0 API endpoint test
const http = require('http');

const endpoints = [
  '/api/status',
  '/api/monitor-status',
  '/api/anomaly-status',
  '/api/notification-status',
  '/api/session-history',
  '/api/soc-metrics',
];

async function test() {
  for (const ep of endpoints) {
    try {
      const data = await get(`http://localhost:3000${ep}`);
      const d = JSON.parse(data);
      const keys = Object.keys(d).slice(0, 4).join(', ');
      console.log(`✓ ${ep.padEnd(30)} → ${keys}`);
    } catch (err) {
      console.log(`✗ ${ep.padEnd(30)} → ${err.message}`);
    }
  }
}

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve(body));
    }).on('error', reject);
  });
}

test();
