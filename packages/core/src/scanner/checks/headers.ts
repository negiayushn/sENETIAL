import type { Check, ScanContext, ScanFinding } from '../types';
import { clip, header, isRedirect } from '../util';

const SIX_MONTHS = 15_552_000;

function parseCsp(csp: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const part of csp.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name) m.set(name.toLowerCase(), vals);
  }
  return m;
}

export class HeadersCheck implements Check {
  readonly id = 'headers';

  async run(ctx: ScanContext): Promise<ScanFinding[]> {
    const res = await ctx.getRoot();
    // A redirect response legitimately lacks most headers; judging it would just produce false positives.
    if (isRedirect(res)) return [];

    const out: ScanFinding[] = [];
    const isHttps = new URL(res.url).protocol === 'https:';
    const base = { url: res.url, status: res.statusCode };

    // CSP
    const csp = header(res, 'content-security-policy');
    if (!csp) {
      out.push({
        type: 'headers.csp-missing', key: 'content-security-policy',
        title: 'Content-Security-Policy header is missing', severity: 'MEDIUM', confidence: 'CONFIRMED',
        evidence: { ...base, header: 'content-security-policy', present: false },
        remediation: "Add a Content-Security-Policy that restricts script sources (start with default-src 'self'), then tighten it.",
      });
    } else {
      const d = parseCsp(csp);
      const script = d.get('script-src') ?? d.get('default-src') ?? [];
      const hasNonceOrHash = script.some((s) => /^'(nonce-|sha(256|384|512)-|strict-dynamic)/.test(s));
      const problems: string[] = [];
      if (script.includes("'unsafe-inline'") && !hasNonceOrHash) problems.push("'unsafe-inline' in script sources");
      if (script.includes('*')) problems.push('wildcard (*) script source');
      if (problems.length) {
        out.push({
          type: 'headers.csp-weak', key: 'content-security-policy',
          title: 'Content-Security-Policy allows unsafe script sources', severity: 'LOW', confidence: 'POTENTIAL',
          evidence: { ...base, header: 'content-security-policy', problems, value: clip(csp) },
          remediation: "Remove 'unsafe-inline' and wildcards from script-src; use nonces or hashes instead.",
        });
      }
    }

    // HSTS (only meaningful on HTTPS)
    if (isHttps) {
      const hsts = header(res, 'strict-transport-security');
      if (!hsts) {
        out.push({
          type: 'headers.hsts-missing', key: 'strict-transport-security',
          title: 'Strict-Transport-Security (HSTS) header is missing', severity: 'MEDIUM', confidence: 'CONFIRMED',
          evidence: { ...base, header: 'strict-transport-security', present: false },
          remediation: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains',
        });
      } else {
        const m = /max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
        const maxAge = m ? Number(m[1]) : null;
        if (maxAge === null || maxAge < SIX_MONTHS) {
          out.push({
            type: 'headers.hsts-weak', key: 'strict-transport-security',
            title: maxAge === 0 ? 'HSTS is explicitly disabled (max-age=0)' : maxAge === null ? 'HSTS header has no max-age' : 'HSTS max-age is shorter than 6 months',
            severity: maxAge === 0 || maxAge === null ? 'MEDIUM' : 'LOW', confidence: 'CONFIRMED',
            evidence: { ...base, header: 'strict-transport-security', value: clip(hsts), maxAge },
            remediation: 'Use max-age of at least 15552000 (6 months); 31536000 (1 year) is the usual target.',
          });
        }
      }
    }

    // X-Content-Type-Options
    const xcto = header(res, 'x-content-type-options');
    if (!xcto || !/\bnosniff\b/i.test(xcto)) {
      out.push({
        type: 'headers.nosniff-missing', key: 'x-content-type-options',
        title: 'X-Content-Type-Options: nosniff is missing', severity: 'LOW', confidence: 'CONFIRMED',
        evidence: { ...base, header: 'x-content-type-options', value: xcto ?? null },
        remediation: 'Send X-Content-Type-Options: nosniff',
      });
    }

    // Referrer-Policy
    if (!header(res, 'referrer-policy')) {
      out.push({
        type: 'headers.referrer-policy-missing', key: 'referrer-policy',
        title: 'Referrer-Policy header is missing', severity: 'LOW', confidence: 'CONFIRMED',
        evidence: { ...base, header: 'referrer-policy', present: false },
        remediation: 'Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).',
      });
    }

    // Permissions-Policy
    if (!header(res, 'permissions-policy')) {
      out.push({
        type: 'headers.permissions-policy-missing', key: 'permissions-policy',
        title: 'Permissions-Policy header is missing', severity: 'INFO', confidence: 'CONFIRMED',
        evidence: { ...base, header: 'permissions-policy', present: false },
        remediation: 'Send a Permissions-Policy that disables browser features the site does not use (camera, microphone, geolocation…).',
      });
    }

    // Clickjacking: X-Frame-Options (DENY/SAMEORIGIN; ALLOW-FROM is obsolete and ignored by browsers) or CSP frame-ancestors
    const xfo = header(res, 'x-frame-options');
    const hasXfo = !!xfo && /^\s*(deny|sameorigin)\b/i.test(xfo);
    const hasFrameAncestors = !!csp && parseCsp(csp).has('frame-ancestors');
    if (!hasXfo && !hasFrameAncestors) {
      out.push({
        type: 'headers.clickjacking', key: 'framing',
        title: 'No clickjacking protection (X-Frame-Options / CSP frame-ancestors)', severity: 'MEDIUM', confidence: 'CONFIRMED',
        evidence: { ...base, xFrameOptions: xfo ?? null, frameAncestors: false },
        remediation: "Send Content-Security-Policy: frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for old browsers).",
      });
    }

    return out;
  }
}
