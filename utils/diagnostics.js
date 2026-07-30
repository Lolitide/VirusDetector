/**
 * Privacy-preserving diagnostic log buffer used by the bug-report workflow.
 */

const MAX_ENTRIES = 40;
const MAX_ENTRY_LENGTH = 500;
const SESSION_STORAGE_KEY = 'diagnostic_logs_v1';
const FILE_LIKE_SUFFIXES = new Set(['js', 'mjs', 'css', 'json', 'html', 'htm', 'txt', 'log']);
const SENSITIVE_KEY_PATTERN = /^(?:authorization|cookie|token|password|passwd|secret|api[_-]?key)$/i;

export function sanitizeDiagnosticText(value) {
  let text = typeof value === 'string' ? value : safeStringify(value);

  return text
    .replace(/https?:\/\/[^\s"'<>]+/gi, (rawUrl) => redactUrl(rawUrl))
    .replace(/\b[\w.+-]+@[\w.-]+\.[a-z]{2,63}\b/gi, '[EMAIL_REDACTED]')
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b/gi, (candidate) => {
      const suffix = candidate.split('.').pop().toLowerCase();
      return FILE_LIKE_SUFFIXES.has(suffix) ? candidate : '[DOMAIN_REDACTED]';
    })
    .replace(/\b(authorization)\b["']?\s*[:=]\s*(?:["']?bearer\s+)?["']?[^\s"',;}]+["']?/gi, '$1=[REDACTED]')
    .replace(/\b(cookie)\b["']?\s*[:=]\s*[^\r\n]+/gi, '$1=[REDACTED]')
    .replace(/\b(token|password|passwd|secret|api[_-]?key)\b["']?\s*[:=]\s*["']?[^\s"',;}]+["']?/gi, '$1=[REDACTED]')
    .replace(/\b[A-Za-z]:\\(?:[^\\\s]+\\)+[^\s]*/g, '[LOCAL_PATH]')
    .replace(/\/(?:Users|home)\/[^\s]+/gi, '[LOCAL_PATH]')
    .substring(0, MAX_ENTRY_LENGTH);
}

function redactUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const port = parsed.port ? `:${parsed.port}` : '';
    return `${parsed.protocol}//${parsed.hostname}${port}/[REDACTED]`;
  } catch (e) {
    return '[URL_REDACTED]';
  }
}

function safeStringify(value) {
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  if (value === null || value === undefined) return String(value);
  if (typeof value !== 'object') return String(value);

  try {
    const seen = new WeakSet();
    return JSON.stringify(value, (key, nestedValue) => {
      if (SENSITIVE_KEY_PATTERN.test(key)) return '[REDACTED]';
      if (typeof nestedValue === 'object' && nestedValue !== null) {
        if (seen.has(nestedValue)) return '[Circular]';
        seen.add(nestedValue);
      }
      return nestedValue;
    });
  } catch (e) {
    return '[Unserializable]';
  }
}

export class DiagnosticLog {
  static _entries = [];
  static _captureInstalled = false;
  static _writeQueue = Promise.resolve();

  static add(level, args) {
    const message = Array.from(args || []).map(sanitizeDiagnosticText).join(' ').trim();
    if (!message) return;

    const entry = {
      time: new Date().toISOString(),
      level: level === 'error' ? 'error' : 'warn',
      message
    };
    this._entries.push(entry);
    if (this._entries.length > MAX_ENTRIES) {
      this._entries.splice(0, this._entries.length - MAX_ENTRIES);
    }

    const sessionStorage = globalThis.chrome?.storage?.session;
    if (!sessionStorage) return;
    this._writeQueue = this._writeQueue.then(async () => {
      const stored = await sessionStorage.get(SESSION_STORAGE_KEY);
      const entries = Array.isArray(stored[SESSION_STORAGE_KEY])
        ? stored[SESSION_STORAGE_KEY]
        : [];
      entries.push(entry);
      await sessionStorage.set({ [SESSION_STORAGE_KEY]: entries.slice(-MAX_ENTRIES) });
    }).catch(() => {});
  }

  static async snapshot() {
    await this._writeQueue;
    const sessionStorage = globalThis.chrome?.storage?.session;
    if (sessionStorage) {
      try {
        const stored = await sessionStorage.get(SESSION_STORAGE_KEY);
        if (Array.isArray(stored[SESSION_STORAGE_KEY])) {
          return stored[SESSION_STORAGE_KEY].slice(-MAX_ENTRIES).map((entry) => ({ ...entry }));
        }
      } catch (e) { }
    }
    return this._entries.map((entry) => ({ ...entry }));
  }

  static installConsoleCapture() {
    if (this._captureInstalled) return;
    this._captureInstalled = true;

    for (const level of ['warn', 'error']) {
      const original = console[level].bind(console);
      console[level] = (...args) => {
        this.add(level, args);
        original(...args);
      };
    }
  }
}
