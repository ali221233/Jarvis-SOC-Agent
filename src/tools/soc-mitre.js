// ============================================================
// Jarvis SOC — MITRE ATT&CK Mapper
// map_to_attack, get_attack_summary
// Offline keyword matching against 30 ATT&CK techniques.
// ============================================================

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', '..', 'data', 'mitre-attack-db.json');
let techniques = [];
const sessionHits = new Map(); // techniqueId -> count

function init() {
  try {
    techniques = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  } catch (err) {
    console.error('[MITRE] Failed to load ATT&CK DB:', err.message);
    techniques = [];
  }
}

// ---- TOOL: map_to_attack (Tier 1) ----
async function mapToAttack({ findingDescription }) {
  if (!findingDescription) return { error: 'Finding description required.' };

  const desc = findingDescription.toLowerCase();
  const matches = [];

  for (const tech of techniques) {
    for (const kw of tech.keywords) {
      if (desc.includes(kw.toLowerCase())) {
        matches.push({
          techniqueId: tech.id,
          name: tech.name,
          tactic: tech.tactic,
          matchedKeyword: kw,
          reason: `Matched keyword "${kw}" in finding description.`,
        });

        // Track session hits
        sessionHits.set(tech.id, (sessionHits.get(tech.id) || 0) + 1);
        break; // One match per technique
      }
    }
  }

  return {
    tool: 'map_to_attack',
    matches,
    total: matches.length,
    summary: matches.length > 0
      ? `Mapped to ${matches.length} ATT&CK technique(s): ${matches.map(m => m.techniqueId).join(', ')}`
      : 'No ATT&CK technique matched for this finding.',
  };
}

// ---- TOOL: get_attack_summary (Tier 1) ----
async function getAttackSummary() {
  const tactics = {};

  for (const tech of techniques) {
    const count = sessionHits.get(tech.id) || 0;
    if (count > 0) {
      if (!tactics[tech.tactic]) tactics[tech.tactic] = [];
      tactics[tech.tactic].push({
        id: tech.id,
        name: tech.name,
        count,
      });
    }
  }

  const totalTechniques = sessionHits.size;
  const totalHits = Array.from(sessionHits.values()).reduce((a, b) => a + b, 0);

  return {
    tool: 'get_attack_summary',
    tactics,
    totalTechniques,
    totalHits,
    summary: `${totalTechniques} unique ATT&CK techniques triggered (${totalHits} total matches) across ${Object.keys(tactics).length} tactic(s).`,
  };
}

// ---- Helpers for other modules ----
function getHeatmapData() {
  return techniques.map(t => ({
    id: t.id,
    name: t.name,
    tactic: t.tactic,
    count: sessionHits.get(t.id) || 0,
  }));
}

function recordHit(techniqueId) {
  sessionHits.set(techniqueId, (sessionHits.get(techniqueId) || 0) + 1);
}

function getSessionHits() {
  return Object.fromEntries(sessionHits);
}

init();

module.exports = {
  mapToAttack, getAttackSummary,
  getHeatmapData, recordHit, getSessionHits,
};
