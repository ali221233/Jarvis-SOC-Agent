// ============================================================
// Jarvis SOC — Demo Recording v4 (Dual Scenario)
// PART 1: Low risk (calm) → PART 2: High risk (incident)
// Commands typed slowly at 60ms/char for visibility.
// Run: npm run demo
// ============================================================

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { spawn, execSync } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const URL = `http://localhost:${PORT}`;
const VIDEO_PATH = path.join(__dirname, '..', 'demo_jarvis_soc.mp4');
const REPORT_PATH = path.join(__dirname, '..', 'data', 'demo_soc_report.md');
const ROOT = path.join(__dirname, '..');

const stepResults = [];

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function waitForServer() {
  return new Promise((resolve) => {
    const check = () => {
      http.get(URL, (res) => {
        if (res.statusCode === 200) resolve();
        else setTimeout(check, 500);
      }).on('error', () => setTimeout(check, 500));
    };
    check();
  });
}

async function run() {
  console.log('\n  ╔═══════════════════════════════════════╗');
  console.log('  ║  JARVIS SOC — Dual Scenario Demo v4   ║');
  console.log('  ╚═══════════════════════════════════════╝\n');

  // ---- Load Puppeteer ----
  const puppeteer = require('puppeteer');
  const { PuppeteerScreenRecorder } = require('puppeteer-screen-recorder');

  const chromePaths = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    (process.env.LOCALAPPDATA || '') + '/Google/Chrome/Application/chrome.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  ];
  let execPath = null;
  for (const p of chromePaths) { if (fs.existsSync(p)) { execPath = p; break; } }
  if (!execPath) { console.error('No Chrome found.'); process.exit(1); }

  // ============================================================
  // Helper: Type command visibly, pause, press Enter, wait
  // ============================================================
  async function typeCmd(page, command, stepLabel, desc, waitMs = 12000) {
    const t0 = Date.now();
    try {
      // Clear input
      await page.evaluate(() => {
        const input = document.getElementById('terminalInput');
        if (input) { input.value = ''; input.focus(); }
      });

      // Click and type slowly
      const input = await page.$('#terminalInput');
      if (input) {
        await input.click();
        await sleep(300);
        await input.type(command, { delay: 60 }); // 60ms per char — readable
        await sleep(1000); // Pause with full command visible
        await page.keyboard.press('Enter');
      }

      // Wait for response
      await sleep(waitMs);

      // Handle confirmation modal
      const hasModal = await page.evaluate(() => {
        const m = document.getElementById('confirmModal');
        if (m && !m.classList.contains('hidden')) {
          const btn = document.getElementById('modalConfirmBtn');
          if (btn) { btn.click(); return true; }
        }
        return false;
      });
      if (hasModal) {
        console.log(`    [${stepLabel}] Confirmed tier action`);
        await sleep(4000);
      }

      // Scroll terminal
      await page.evaluate(() => {
        const o = document.getElementById('terminalOutput');
        if (o) o.scrollTop = o.scrollHeight;
      });

      const elapsed = Date.now() - t0;
      console.log(`  ✓ Step ${stepLabel}: ${desc} (${elapsed}ms)`);
      stepResults.push({ step: stepLabel, status: 'completed', elapsed });

    } catch (err) {
      const elapsed = Date.now() - t0;
      console.log(`  ✗ Step ${stepLabel}: ${err.message} (${elapsed}ms)`);
      stepResults.push({ step: stepLabel, status: 'error', elapsed });
    }
  }

  // ============================================================
  // PART 1: LOW RISK SCENARIO
  // ============================================================
  console.log('━━━ PART 1: LOW RISK SCENARIO ━━━\n');

  // Seed low data
  console.log('[Setup] Seeding low-risk data...');
  execSync('node scripts/seed-demo-low.js', { cwd: ROOT, stdio: 'pipe' });

  // Start server
  console.log('[Setup] Starting server...');
  let server = spawn('node', ['server.js'], { cwd: ROOT, env: process.env, stdio: 'pipe' });
  server.stdout.on('data', () => {});
  server.stderr.on('data', () => {});
  await waitForServer();
  console.log('[Setup] Server ready.\n');

  // Launch browser
  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: execPath,
    defaultViewport: { width: 1280, height: 800 },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'],
  });

  const page = await browser.newPage();
  const recorder = new PuppeteerScreenRecorder(page, {
    fps: 24,
    videoFrame: { width: 1280, height: 800 },
    videoCrf: 18,
    videoCodec: 'libx264',
    videoPreset: 'ultrafast',
    autopad: { color: '#060a11' },
  });
  await recorder.start(VIDEO_PATH);
  console.log('[Recording] Started.\n');

  // ---- Step A: Load low-risk dashboard ----
  console.log('[Step A] Loading low-risk dashboard...');
  await page.goto(URL, { waitUntil: 'networkidle2', timeout: 20000 });
  // Dismiss overlays
  await page.evaluate(() => {
    ['setupOverlay', 'unlockOverlay'].forEach(id => {
      const el = document.getElementById(id);
      if (el && !el.classList.contains('hidden')) el.classList.add('hidden');
    });
  });
  await sleep(4000); // Let viewer see clean state: risk ~36, minor alerts
  console.log('  ✓ Step A: Dashboard loaded (risk ~36, 6 minor alerts)');
  stepResults.push({ step: 'A', status: 'completed', elapsed: 4000 });

  // ---- Step B: Routine log check ----
  console.log('[Step B] Routine log check...');
  await typeCmd(page, 'parse the windows event log data/demo-logs/windows_events.txt', 'B', 'Routine log check', 12000);
  await sleep(3000); // Pause on low-severity output

  // ---- Step C: Firewall check ----
  console.log('[Step C] Firewall check...');
  await typeCmd(page, 'check firewall status', 'C', 'Firewall check', 10000);
  await sleep(2000);

  // ---- Step D: Secrets scan (clean) ----
  console.log('[Step D] Secrets scan (clean file)...');
  await typeCmd(page, 'scan test_secrets.txt for hardcoded secrets', 'D', 'Secrets scan (clean)', 10000);
  await sleep(2000);

  // ---- Step E: Risk posture query ----
  console.log('[Step E] Risk posture query...');
  await typeCmd(page, 'what is the current risk posture', 'E', 'Risk posture query', 10000);
  await sleep(3000); // Let viewer see risk gauge at ~36

  // ============================================================
  // TRANSITION: Switch to high-risk scenario
  // ============================================================
  console.log('\n━━━ TRANSITION ━━━\n');
  console.log('[Transition] Pausing on calm dashboard...');
  await sleep(3000);

  // Kill server, re-seed with high data, restart
  server.kill();
  await sleep(1000);
  console.log('[Transition] Seeding high-risk data...');
  execSync('node scripts/seed-demo-high.js', { cwd: ROOT, stdio: 'pipe' });

  console.log('[Transition] Restarting server with threat data...');
  server = spawn('node', ['server.js'], { cwd: ROOT, env: process.env, stdio: 'pipe' });
  server.stdout.on('data', () => {});
  server.stderr.on('data', () => {});
  await waitForServer();

  // Reload page
  await page.goto(URL, { waitUntil: 'networkidle2', timeout: 20000 });
  await page.evaluate(() => {
    ['setupOverlay', 'unlockOverlay'].forEach(id => {
      const el = document.getElementById(id);
      if (el && !el.classList.contains('hidden')) el.classList.add('hidden');
    });
  });
  await sleep(2000);
  console.log('[Transition] Dashboard updated with threat data.\n');

  // ============================================================
  // PART 2: HIGH RISK SCENARIO
  // ============================================================
  console.log('━━━ PART 2: HIGH RISK SCENARIO ━━━\n');

  // ---- Step F: Show escalated dashboard ----
  console.log('[Step F] Escalated dashboard...');
  await sleep(4000); // Let viewer see: risk ~80, 4 alerts, CRITICAL
  console.log('  ✓ Step F: Escalated dashboard (risk ~80, CRITICAL alerts)');
  stepResults.push({ step: 'F', status: 'completed', elapsed: 4000 });

  // ---- Step G: Parse attack event log ----
  console.log('[Step G] Parse attack event log...');
  await typeCmd(page, 'parse the windows event log data/demo-logs/windows_events.txt', 'G', 'Attack chain log parse', 15000);
  await sleep(4000); // Key moment — attack chain visible

  // ---- Step H: Enrich attacker IP ----
  console.log('[Step H] Enrich attacker IP...');
  await typeCmd(page, 'enrich IP 192.168.1.100', 'H', 'IP enrichment', 12000);
  await sleep(3000);

  // ---- Step I: Secrets scan (dirty) ----
  console.log('[Step I] Secrets scan (dirty file)...');
  await typeCmd(page, 'scan test_secrets.txt for hardcoded secrets', 'I', 'Secrets scan (findings)', 12000);
  await sleep(3000);

  // ---- Step J: Brute force playbook ----
  console.log('[Step J] Brute force playbook...');
  await typeCmd(page, 'run the brute force playbook', 'J', 'Brute force playbook', 20000);
  await sleep(3000);

  // ---- Step K: CVE lookup ----
  console.log('[Step K] CVE lookup...');
  await typeCmd(page, 'lookup CVE-2021-44228', 'K', 'CVE lookup (Log4Shell)', 12000);
  await sleep(3000);

  // ---- Step L: Generate report ----
  console.log('[Step L] Generate incident report...');
  await typeCmd(page, 'generate the incident report', 'L', 'Incident report', 12000);
  await sleep(4000); // SHA-256 hash visible

  // ---- Step M: Final dashboard ----
  console.log('[Step M] Final dashboard shot...');
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    const o = document.getElementById('terminalOutput');
    if (o) o.scrollTop = o.scrollHeight;
  });
  await sleep(6000); // Money shot — 6 seconds on full dashboard
  console.log('  ✓ Step M: Final dashboard captured');
  stepResults.push({ step: 'M', status: 'completed', elapsed: 6000 });

  // ---- Stop recording ----
  await recorder.stop().catch(() => {});
  console.log(`\n[Recording] Video saved: ${VIDEO_PATH}`);

  // ---- Save report ----
  try {
    const reportData = await page.evaluate(async () => {
      const res = await fetch('/api/report');
      return res.json();
    });
    if (reportData?.report) {
      fs.writeFileSync(REPORT_PATH, reportData.report);
      console.log(`[Report] Saved: ${REPORT_PATH}`);
    }
  } catch (err) {
    console.error(`[Report] Failed: ${err.message}`);
  }

  // ---- Cleanup ----
  await browser.close();
  server.kill();

  // ---- Summary ----
  const completed = stepResults.filter(r => r.status === 'completed').length;
  const total = stepResults.length;
  console.log(`\n✓ Demo complete. ${completed}/${total} steps completed.`);
  console.log(`  Video:  ${VIDEO_PATH}`);
  console.log(`  Report: ${REPORT_PATH}\n`);
  for (const r of stepResults) {
    const icon = r.status === 'completed' ? '✓' : '✗';
    console.log(`  ${icon} Step ${r.step}: ${r.status} (${r.elapsed}ms)`);
  }
  console.log('');
}

run().catch(err => { console.error('[Fatal]', err); process.exit(1); });
