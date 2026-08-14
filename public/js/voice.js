// ============================================================
// Jarvis — Voice Engine
// Kokoro TTS via WebSocket + Web Speech API fallback.
// Speech Recognition: wake word + push-to-talk.
// ============================================================

const voice = {
  recognition: null,
  isListening: false,
  isWakeWordMode: true,
  supported: false,
  audioCtx: null,
  isPlaying: false,

  init() {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      console.warn('[Voice] Speech Recognition not supported in this browser.');
      const btn = document.getElementById('voiceBtn');
      if (btn) btn.title = 'Voice not supported in this browser';
      return;
    }

    this.supported = true;
    this.recognition = new SpeechRecognition();
    this.recognition.lang = 'en-US';
    this.recognition.continuous = true;
    this.recognition.interimResults = false;

    this.recognition.onresult = (event) => {
      const transcript = event.results[event.results.length - 1][0].transcript.trim().toLowerCase();
      this.handleTranscript(transcript);
    };

    this.recognition.onend = () => {
      // Restart if in wake-word listening mode
      if (this.isWakeWordMode && this.supported) {
        try { this.recognition.start(); } catch {}
      } else {
        this.setListeningUI(false);
      }
    };

    this.recognition.onerror = (event) => {
      if (event.error !== 'no-speech' && event.error !== 'aborted') {
        console.error('[Voice] Error:', event.error);
      }
    };

    // Voice button — click to toggle
    const btn = document.getElementById('voiceBtn');
    if (btn) {
      btn.addEventListener('click', () => this.toggleListening());
    }

    // Spacebar push-to-talk
    let spaceDown = false;
    document.addEventListener('keydown', (e) => {
      if (e.code === 'Space' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA' && !spaceDown) {
        spaceDown = true;
        this.startListening();
      }
    });

    document.addEventListener('keyup', (e) => {
      if (e.code === 'Space' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
        spaceDown = false;
        this.stopListening();
      }
    });

    // Initialize Web Audio API context for Kokoro TTS playback
    try {
      this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    } catch (e) {
      console.warn('[Voice] Web Audio API not available:', e.message);
    }

    // Start in passive wake-word mode
    this.startWakeWordMode();
  },

  /**
   * Handle incoming WebSocket TTS messages.
   * Called from app.js WebSocket handler.
   */
  handleTTSMessage(data) {
    if (data.type === 'tts_audio' && data.audio) {
      // Kokoro TTS — decode base64 and play via Web Audio API
      this.playBase64Audio(data.audio);
    } else if (data.type === 'tts_speak' && data.text) {
      // Web Speech API fallback
      this.speakWebSpeech(data.text);
    }
  },

  /**
   * Play base64-encoded audio via Web Audio API.
   */
  async playBase64Audio(base64) {
    if (!this.audioCtx) return;

    try {
      // Resume context if suspended (browser autoplay policy)
      if (this.audioCtx.state === 'suspended') {
        await this.audioCtx.resume();
      }

      const binaryStr = atob(base64);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }

      const audioBuffer = await this.audioCtx.decodeAudioData(bytes.buffer);
      const source = this.audioCtx.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(this.audioCtx.destination);

      this.isPlaying = true;
      this.setPlayingUI(true);

      source.onended = () => {
        this.isPlaying = false;
        this.setPlayingUI(false);
      };

      source.start(0);
    } catch (err) {
      console.error('[Voice] Audio playback failed:', err.message);
      this.isPlaying = false;
      this.setPlayingUI(false);
    }
  },

  startWakeWordMode() {
    if (!this.supported) return;
    this.isWakeWordMode = true;
    try { this.recognition.start(); } catch {}
  },

  handleTranscript(transcript) {
    // Check for wake word
    if (transcript.includes('hey jarvis') || transcript.includes('hey jarves') || transcript.includes('hey travis')) {
      // Remove wake word and get the command
      const command = transcript
        .replace(/hey jarvis/i, '')
        .replace(/hey jarves/i, '')
        .replace(/hey travis/i, '')
        .trim();

      if (command) {
        // Got wake word + command in one go
        this.executeVoiceCommand(command);
      } else {
        // Just wake word — switch to active listening
        this.speakWebSpeech('Yes, Boss?');
        this.setListeningUI(true);
        this.isWakeWordMode = false;
        // Will capture next utterance as command
      }
      return;
    }

    // If we're in active listening mode (after wake word), treat as command
    if (!this.isWakeWordMode && this.isListening) {
      this.executeVoiceCommand(transcript);
      this.isWakeWordMode = true;
      this.setListeningUI(false);
    }
  },

  executeVoiceCommand(command) {
    terminal.addLine(`🎤 ${command}`, 'user');
    app.sendCommand(command);
  },

  toggleListening() {
    if (this.isListening) {
      this.stopListening();
    } else {
      this.startListening();
    }
  },

  startListening() {
    if (!this.supported) return;
    this.isListening = true;
    this.isWakeWordMode = false;
    this.setListeningUI(true);
    try {
      this.recognition.stop();
      setTimeout(() => {
        try { this.recognition.start(); } catch {}
      }, 100);
    } catch {
      try { this.recognition.start(); } catch {}
    }
  },

  stopListening() {
    if (!this.supported) return;
    this.isListening = false;
    this.isWakeWordMode = true;
    this.setListeningUI(false);
    try { this.recognition.stop(); } catch {}
    // Resume wake word mode
    setTimeout(() => this.startWakeWordMode(), 300);
  },

  setListeningUI(listening) {
    const btn = document.getElementById('voiceBtn');
    if (btn) {
      btn.classList.toggle('listening', listening);
      btn.textContent = listening ? '🔴' : '🎤';
    }
  },

  setPlayingUI(playing) {
    const btn = document.getElementById('voiceBtn');
    if (btn) {
      btn.classList.toggle('speaking', playing);
    }
    // Show waveform animation when playing
    const waveform = document.getElementById('voiceWaveform');
    if (waveform) {
      waveform.classList.toggle('active', playing);
    }
  },

  /**
   * Web Speech API fallback — only used when Kokoro is unavailable.
   */
  speakWebSpeech(text) {
    if (!window.speechSynthesis) return;
    window.speechSynthesis.cancel();

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.05;
    utterance.pitch = 0.95;
    utterance.volume = 0.85;

    const voices = window.speechSynthesis.getVoices();
    const preferred = voices.find(v =>
      v.lang.startsWith('en') && (v.name.includes('Google') || v.name.includes('Microsoft') || v.name.includes('Daniel'))
    );
    if (preferred) utterance.voice = preferred;

    this.isPlaying = true;
    this.setPlayingUI(true);

    utterance.onend = () => {
      this.isPlaying = false;
      this.setPlayingUI(false);
    };

    window.speechSynthesis.speak(utterance);
  },

  /**
   * Speak text — delegates to appropriate engine.
   * Called from app.js when Jarvis responds.
   */
  speak(text) {
    // TTS is now handled server-side via WebSocket.
    // This method is a fallback for direct calls (e.g., wake word response).
    this.speakWebSpeech(text);
  },
};

// Init when DOM ready
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => voice.init(), 500);
});
