// ============================================================
// Jarvis — Ollama Client (LOCAL, OFFLINE, CPU-ONLY)
// Calls http://localhost:11434/api/chat with tool-calling.
// No API key. No cost. No data leaves the machine.
// ============================================================

const http = require('http');
const toolRegistry = require('./tool-registry');
const persona = require('./persona');

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3.2:3b';

/**
 * Send a chat request to Ollama with tool-calling support.
 * @param {string} userMessage - The user's command/message
 * @param {Array} conversationHistory - Previous messages for context
 * @returns {Object} { response, toolCalls, error }
 */
async function chat(userMessage, conversationHistory = []) {
  const systemPrompt = persona.getSystemPrompt();
  const tools = toolRegistry.getOllamaToolDefinitions();

  const messages = [
    { role: 'system', content: systemPrompt },
    ...conversationHistory,
    { role: 'user', content: userMessage },
  ];

  try {
    const result = await ollamaRequest('/api/chat', {
      model: OLLAMA_MODEL,
      messages,
      tools,
      stream: false,
    });

    if (result.error) {
      return { response: null, toolCalls: [], error: result.error };
    }

    const message = result.message || {};
    const toolCalls = message.tool_calls || [];
    const response = message.content || '';

    return { response, toolCalls, error: null };
  } catch (err) {
    return { response: null, toolCalls: [], error: err.message };
  }
}

/**
 * Send tool results back to Ollama and get the final response.
 * @param {Array} messages - Full conversation including tool results
 * @returns {Object} { response, toolCalls, error }
 */
async function continueWithToolResults(messages) {
  const tools = toolRegistry.getOllamaToolDefinitions();

  try {
    const result = await ollamaRequest('/api/chat', {
      model: OLLAMA_MODEL,
      messages,
      tools,
      stream: false,
    });

    if (result.error) {
      return { response: null, toolCalls: [], error: result.error };
    }

    const message = result.message || {};
    return {
      response: message.content || '',
      toolCalls: message.tool_calls || [],
      error: null,
    };
  } catch (err) {
    return { response: null, toolCalls: [], error: err.message };
  }
}

/**
 * Check if Ollama is running and the model is available.
 */
async function checkHealth() {
  try {
    const result = await ollamaRequest('/api/tags', null, 'GET');
    if (result.error) {
      return { available: false, error: result.error };
    }

    const models = (result.models || []).map(m => m.name || m.model);
    const modelAvailable = models.some(m => m.startsWith(OLLAMA_MODEL.split(':')[0]));

    return {
      available: true,
      modelAvailable,
      model: OLLAMA_MODEL,
      availableModels: models,
      message: modelAvailable
        ? `Ollama running. Model ${OLLAMA_MODEL} ready.`
        : `Ollama running but ${OLLAMA_MODEL} not found. Run: ollama pull ${OLLAMA_MODEL}`,
    };
  } catch (err) {
    return {
      available: false,
      error: `Cannot reach Ollama at ${OLLAMA_URL}. Is it running? Error: ${err.message}`,
    };
  }
}

// ---- HTTP helper ----

function ollamaRequest(endpoint, body, method = 'POST') {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, OLLAMA_URL);

    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method,
      headers: { 'Content-Type': 'application/json' },
      timeout: 300000, // 5 min timeout for CPU inference
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve({ error: `Invalid JSON response: ${data.substring(0, 200)}` });
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`Ollama connection failed: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Ollama request timed out (5 min). Model might be too large for this hardware.'));
    });

    if (body && method === 'POST') {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

module.exports = { chat, continueWithToolResults, checkHealth, OLLAMA_MODEL, OLLAMA_URL };
