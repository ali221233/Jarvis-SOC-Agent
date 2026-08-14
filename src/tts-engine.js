// ============================================================
// Jarvis SOC — TTS Engine v4.0 (Kokoro TTS with fallback)
// Uses kokoro-js KokoroTTS class.
// Sends audio to frontend via WebSocket as base64.
// ============================================================

let kokoroTTS = null;
let ttsReady = false;
let ttsEngine = 'none';
let ttsError = null;
let broadcast = () => {};

const JARVIS_VOICE = process.env.JARVIS_VOICE || 'af_sky';
const MAX_TTS_CHARS = 150;

/**
 * Initialize the TTS engine.
 * Attempts Kokoro TTS first, falls back to Web Speech API signal.
 */
async function init(wsBroadcast) {
  broadcast = wsBroadcast || (() => {});

  console.log('  [TTS] Kokoro TTS loading...');

  try {
    const { KokoroTTS } = require('kokoro-js');

    // KokoroTTS constructor: new KokoroTTS(modelId, dtype, device)
    // Models: onnx-community/Kokoro-82M-v1.0-ONNX
    // dtype: 'fp32' or 'q8' (quantized, smaller)
    // device: 'cpu'
    kokoroTTS = await KokoroTTS.from_pretrained(
      'onnx-community/Kokoro-82M-v1.0-ONNX',
      { dtype: 'q8', device: 'cpu' }
    );

    ttsReady = true;
    ttsEngine = 'kokoro';
    console.log(`  [TTS] Kokoro TTS ready — voice: ${JARVIS_VOICE}`);
  } catch (err) {
    ttsError = err.message;
    ttsEngine = 'web-speech-fallback';
    ttsReady = true; // Web Speech API handled by frontend
    console.log(`  [TTS] Kokoro TTS failed — using Web Speech API. Error: ${err.message}`);
  }
}

/**
 * Generate TTS audio for a response and send via WebSocket.
 * Only speaks first 1-2 sentences, max 150 chars.
 */
async function speak(text) {
  if (!text || !ttsReady) return;

  // Extract first 1-2 sentences
  const sentences = text.match(/[^.!?]+[.!?]+/g) || [text];
  let ttsText = sentences.slice(0, 2).join(' ').trim();
  if (ttsText.length > MAX_TTS_CHARS) {
    ttsText = ttsText.substring(0, MAX_TTS_CHARS) + '...';
  }
  // Strip markdown
  ttsText = ttsText.replace(/[*_`#\[\]]/g, '').trim();

  if (ttsEngine === 'kokoro' && kokoroTTS) {
    try {
      const audio = await kokoroTTS.generate(ttsText, { voice: JARVIS_VOICE });
      // audio is a Float32Array or AudioData-like object
      // Convert to WAV buffer
      let wavBuffer;
      if (audio && audio.save) {
        // kokoro-js audio object has .save(path) and .toWav() methods
        if (typeof audio.toBuffer === 'function') {
          wavBuffer = await audio.toBuffer();
        } else {
          // Write to temp buffer via save
          const tempPath = require('path').join(__dirname, '..', 'data', 'tts_temp.wav');
          await audio.save(tempPath);
          wavBuffer = require('fs').readFileSync(tempPath);
          try { require('fs').unlinkSync(tempPath); } catch {}
        }
      } else if (Buffer.isBuffer(audio)) {
        wavBuffer = audio;
      }

      if (wavBuffer) {
        const base64 = wavBuffer.toString('base64');
        broadcast({
          type: 'tts_audio',
          audio: base64,
          text: ttsText,
          engine: 'kokoro',
          voice: JARVIS_VOICE,
        });
        return;
      }
    } catch (err) {
      console.error(`  [TTS] Kokoro generation failed: ${err.message}`);
    }
  }

  // Fallback: tell frontend to use Web Speech API
  broadcast({
    type: 'tts_speak',
    text: ttsText,
    engine: 'web-speech',
  });
}

function getStatus() {
  return {
    engine: ttsEngine,
    ready: ttsReady,
    voice: JARVIS_VOICE,
    error: ttsError,
  };
}

module.exports = { init, speak, getStatus };
