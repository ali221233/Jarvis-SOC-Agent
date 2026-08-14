// ============================================================
// Jarvis SOC — Groq Client (FREE, FAST, NO GPU NEEDED)
// Calls https://api.groq.com/openai/v1/chat/completions
// Uses llama-3.3-70b-versatile with tool-calling.
// Free tier: 1000 req/day. 500+ tok/sec on Groq LPU.
// ============================================================

const https = require('https');
const toolRegistry = require('./tool-registry');
const persona = require('./persona');

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const GROQ_ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions';

/**
 * Send a chat request to Groq with tool-calling support.
 * @param {string} userMessage - The user's command/message
 * @param {Array} conversationHistory - Previous messages for context
 * @returns {Object} { response, toolCalls, error }
 */
async function chat(userMessage, conversationHistory = []) {
  if (!GROQ_API_KEY) {
    return { response: null, toolCalls: [], error: 'GROQ_API_KEY not set. Get a free key at console.groq.com' };
  }

  const systemPrompt = persona.getSystemPrompt();
  const tools = toolRegistry.getToolDefinitions();

  const messages = [
    { role: 'system', content: systemPrompt },
    ...conversationHistory,
    { role: 'user', content: userMessage },
  ];

  try {
    const result = await groqRequest({
      model: GROQ_MODEL,
      messages,
      tools,
      tool_choice: 'auto',
      temperature: 0.1,
      max_tokens: 4096,
    });

    if (result.error) {
      return { response: null, toolCalls: [], error: result.error.message || JSON.stringify(result.error) };
    }

    const choice = result.choices?.[0];
    if (!choice) {
      return { response: null, toolCalls: [], error: 'No response from Groq' };
    }

    const message = choice.message || {};
    const toolCalls = (message.tool_calls || []).map(tc => ({
      id: tc.id,
      function: {
        name: tc.function.name,
        arguments: typeof tc.function.arguments === 'string'
          ? JSON.parse(tc.function.arguments)
          : tc.function.arguments,
      },
    }));

    return {
      response: message.content || '',
      toolCalls,
      error: null,
      usage: result.usage || null,
    };
  } catch (err) {
    return { response: null, toolCalls: [], error: err.message };
  }
}

/**
 * Send tool results back to Groq and get the final response.
 * @param {Array} messages - Full conversation including tool results
 * @returns {Object} { response, toolCalls, error }
 */
async function continueWithToolResults(messages) {
  if (!GROQ_API_KEY) {
    return { response: null, toolCalls: [], error: 'GROQ_API_KEY not set' };
  }

  const tools = toolRegistry.getToolDefinitions();

  try {
    const result = await groqRequest({
      model: GROQ_MODEL,
      messages,
      tools,
      tool_choice: 'auto',
      temperature: 0.1,
      max_tokens: 4096,
    });

    if (result.error) {
      return { response: null, toolCalls: [], error: result.error.message || JSON.stringify(result.error) };
    }

    const choice = result.choices?.[0];
    const message = choice?.message || {};

    return {
      response: message.content || '',
      toolCalls: message.tool_calls || [],
      error: null,
      usage: result.usage || null,
    };
  } catch (err) {
    return { response: null, toolCalls: [], error: err.message };
  }
}

/**
 * Check if Groq API is reachable and the model responds.
 */
async function checkHealth() {
  if (!GROQ_API_KEY) {
    return {
      available: false,
      error: 'GROQ_API_KEY not configured. Get a free key at console.groq.com',
    };
  }

  try {
    const result = await groqRequest({
      model: GROQ_MODEL,
      messages: [{ role: 'user', content: 'ping' }],
      max_tokens: 5,
      temperature: 0,
    });

    if (result.error) {
      return {
        available: false,
        error: result.error.message || JSON.stringify(result.error),
      };
    }

    return {
      available: true,
      modelAvailable: true,
      model: GROQ_MODEL,
      message: `Groq online. Model: ${GROQ_MODEL}. LPU inference — instant responses.`,
    };
  } catch (err) {
    return {
      available: false,
      error: `Cannot reach Groq API: ${err.message}`,
    };
  }
}

// ---- HTTPS request helper ----

function groqRequest(body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const url = new URL(GROQ_ENDPOINT);

    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Length': Buffer.byteLength(data),
      },
      timeout: 30000,
    };

    const req = https.request(options, (res) => {
      let buf = '';
      res.on('data', chunk => { buf += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(buf));
        } catch {
          resolve({ error: { message: `Invalid JSON from Groq: ${buf.substring(0, 200)}` } });
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`Groq connection failed: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Groq request timed out (30s).'));
    });

    req.write(data);
    req.end();
  });
}

module.exports = { chat, continueWithToolResults, checkHealth, GROQ_MODEL };
