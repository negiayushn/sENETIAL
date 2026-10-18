import type { Check, ScanContext, ScanFinding, Severity } from '../types';
import { isRedirect } from '../util';

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

/** Parses a Set-Cookie header. The cookie VALUE is dropped here, so it can never end up in evidence. */
export function parseSetCookie(raw: string): ParsedCookie | null {
  const [pair, ...attrs] = raw.split(';');
  const eq = pair.indexOf('=');
  const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
  if (!name) return null;
  const trimmed = attrs.map((a) => a.trim());
  const lower = trimmed.map((a) => a.toLowerCase());
  const sameIdx = lower.findIndex((a) => a === 'samesite' || a.startsWith('samesite='));
  return {
    name,
    secure: lower.includes('secure'),
    httpOnly: lower.includes('httponly'),
    sameSite: sameIdx === -1 ? null : (trimmed[sameIdx].split('=')[1]?.trim() ?? ''),
  };
}

const SESSION_LIKE = /sess|token|(^|[^a-z])sid([^a-z]|$)/i;
export const looksLikeSessionCookie = (name: string) => SESSION_LIKE.test(name);

export class CookiesCheck implements Check {
  readonly id = 'cookies';

  async run(ctx: ScanContext): Promise<ScanFinding[]> {
    const res = await ctx.getRoot();
    if (isRedirect(res)) return [];
    const raw = res.headers['set-cookie'];
    const list = raw == null ? [] : Array.isArray(raw) ? raw : [raw];
    const isHttps = new URL(res.url).protocol === 'https:';

    const out: ScanFinding[] = [];
    for (const header of list) {
      const c = parseSetCookie(header);
      if (!c) continue;
      const session = looksLikeSessionCookie(c.name);
      const confidence = session ? 'CONFIRMED' : 'POTENTIAL';
      const evidence = { cookieName: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, sessionLike: session };
      const add = (flag: 'secure' | 'httponly' | 'samesite', title: string, sev: Severity, remediation: string) =>
        out.push({ type: `cookies.${flag}-missing`, key: c.name, title: `${title}: ${c.name}`, severity: sev, confidence, evidence, remediation });

      // Secure only makes sense on HTTPS; on an HTTP-only site the missing HTTPS is the real finding.
      if (isHttps && !c.secure) add('secure', 'Cookie missing Secure flag', session ? 'MEDIUM' : 'LOW', 'Set the Secure attribute so the cookie is never sent over plain HTTP.');
      if (!c.httpOnly) add('httponly', 'Cookie missing HttpOnly flag', session ? 'MEDIUM' : 'LOW', 'Set the HttpOnly attribute so scripts cannot read the cookie (limits XSS impact).');
      if (c.sameSite === null) add('samesite', 'Cookie missing SameSite attribute', session ? 'LOW' : 'INFO', 'Set SameSite=Lax (or Strict) to reduce CSRF exposure.');
    }
    return out;
  }
}
