process.chdir(__dirname + '/..');
const mods = [
  '../src/monitor',
  '../src/tools/code-security',
  '../src/tools/file-security',
  '../src/tools/soc-alerts',
  '../src/tools/soc-playbooks',
  '../src/n8n-client',
  '../src/tts-engine',
];
for (const m of mods) {
  try {
    require(m);
    console.log('OK:', m);
  } catch(e) {
    console.log('FAIL:', m, '—', e.message.split('\n')[0]);
  }
}
