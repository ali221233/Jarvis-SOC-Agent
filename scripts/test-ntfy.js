// Send test Ntfy notification
const https = require('https');
require('dotenv').config();

const topic = process.env.NTFY_TOPIC || 'jarvis-ali-G195hqv1111';
const message = 'Jarvis SOC health check. Ntfy is working, Boss. You will receive critical alerts here.';

const opts = {
  hostname: 'ntfy.sh',
  port: 443,
  path: `/${topic}`,
  method: 'POST',
  headers: {
    'Title': 'JARVIS SOC - System Test',
    'Priority': 'high',
    'Tags': 'white_check_mark',
  },
};

const req = https.request(opts, (res) => {
  let body = '';
  res.on('data', c => body += c);
  res.on('end', () => {
    console.log(`HTTP ${res.statusCode}`);
    console.log(`Topic: ${topic}`);
    console.log(`Response: ${body.substring(0, 300)}`);
  });
});

req.on('error', (e) => console.log('ERROR:', e.message));
req.write(message);
req.end();
