// ============================================================
// Jarvis — Productivity Tools (TODO STUBS)
// dictate_notes, generate_weekly_briefing, search_calendar
//
// All three return explicit "not_implemented" status.
// They never return fake success data.
// ============================================================

// ---- TOOL: dictate_notes (TODO STUB) ----
async function dictateNotes({ content }) {
  return {
    tool: 'dictate_notes',
    status: 'not_implemented',
    message: 'Note dictation is not yet implemented. This is a TODO stub — no action was taken. Future: save transcribed voice notes to a local notes directory.',
  };
}

// ---- TOOL: generate_weekly_briefing (TODO STUB) ----
async function generateWeeklyBriefing() {
  return {
    tool: 'generate_weekly_briefing',
    status: 'not_implemented',
    message: 'Weekly briefing generation is not yet implemented. This is a TODO stub — no action was taken. Future: compile action history, findings, and system status into a weekly summary.',
  };
}

// ---- TOOL: search_calendar (TODO STUB) ----
async function searchCalendar({ query }) {
  return {
    tool: 'search_calendar',
    status: 'not_implemented',
    message: 'Calendar search is not yet implemented. This is a TODO stub — no action was taken. Future: integrate with local calendar (Outlook/Google Calendar API).',
  };
}

module.exports = {
  dictateNotes,
  generateWeeklyBriefing,
  searchCalendar,
};
