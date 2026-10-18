/**
 * Evidence is stored in the database and shown in the UI, so it must never contain live secrets.
 * Checks are written not to capture values in the first place; this is the safety net that runs on
 * everything right before it is saved (defence in depth).
 */

// Keys that hold secrets: a bare "value", or anything ENDING in token/secret/password/apiKey/cookie/authorization
// (csrfToken, set-cookie, proxy-authorization…). Matching on the END keeps "cookieName" / "tokenType" readable:
// names are evidence, values are secrets.
const SENSITIVE_KEY = /^value$|(?:token|secret|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|cookie|authorization)$/i;

const MAX_STRING = 500;
const MAX_ITEMS = 50;
const MAX_DEPTH = 6;
const MASK = '[REDACTED]';

const STRING_RULES: [RegExp, string][] = [
  // Cookie / Set-Cookie header lines: keep the name, drop the value
  [/\b((?:Set-)?Cookie:\s*)([^;\r\n=\s]+)=[^;\r\n]*/gi, `$1$2=${MASK}`],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, '[REDACTED:jwt]'],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, `$1 ${MASK}`],
  // credentials embedded in URLs (DATABASE_URL=postgres://user:pass@host/db)
  [/(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi, `$1$2:${MASK}@`],
  // NAME=value / NAME: value where NAME smells like a secret
  [/\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)(["']?)[^\s"';,&]{3,}\3/gi, `$1$2${MASK}`],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '[REDACTED:aws-key-id]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED:github-token]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED:slack-token]'],
  [/\b[sr]k_live_[A-Za-z0-9]{16,}\b/g, '[REDACTED:stripe-key]'],
];

export function redactString(input: string): string {
  let out = input;
  for (const [re, repl] of STRING_RULES) out = out.replace(re, repl);
  return out.length > MAX_STRING ? `${out.slice(0, MAX_STRING)}…[truncated]` : out;
}

export function redactEvidence<T>(value: T): T {
  return walk(value, 0) as T;
}

function walk(v: unknown, depth: number): unknown {
  if (v == null || typeof v === 'boolean' || typeof v === 'number') return v;
  if (typeof v === 'string') return redactString(v);
  if (depth >= MAX_DEPTH) return '[truncated]';
  if (Array.isArray(v)) return v.slice(0, MAX_ITEMS).map((x) => walk(x, depth + 1));
  if (typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>).slice(0, MAX_ITEMS)) {
      out[k] = SENSITIVE_KEY.test(k) ? (val == null ? val : MASK) : walk(val, depth + 1);
    }
    return out;
  }
  return String(v); // bigint, symbol, function → never let non-JSON values reach the database
}
