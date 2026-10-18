import { describe, expect, it } from 'vitest';
import {
  analyzeEnvFile, CookiesCheck, DisclosureCheck, ExposureCheck, findStackTrace, HeadersCheck, looksLikeSessionCookie,
  parseSetCookie, TlsCheck, type SafeResponse, type ScanContext, type TlsProbeResult,
} from '../src';

const resp = (statusCode: number, headers: Record<string, string | string[]> = {}, body = '', url = 'https://example.com/'): SafeResponse => ({
  url, statusCode, headers, body: Buffer.from(body), truncated: false, redirects: [], text: () => body,
});

function ctx(routes: Record<string, SafeResponse>, extra: Partial<ScanContext> = {}): ScanContext {
  const notFound = resp(404, {}, 'Not found');
  return {
    hostname: 'example.com',
    notFoundPath: '/sentinel-probe-test',
    now: () => new Date('2026-06-01T00:00:00Z'),
    origin: async () => 'https://example.com',
    getRoot: async () => routes['/'] ?? resp(200),
    get: async (p) => routes[p] ?? notFound,
    tlsProbe: async () => { throw new Error('tlsProbe not stubbed'); },
    ...extra,
  };
}
const types = (fs: { type: string; key: string }[]) => fs.map((f) => `${f.type}:${f.key}`).sort();

describe('HeadersCheck', () => {
  const good = {
    'content-security-policy': "default-src 'self'; frame-ancestors 'self'",
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=()',
  };
  it('reports nothing for a well-configured site', async () => {
    expect(await new HeadersCheck().run(ctx({ '/': resp(200, good) }))).toEqual([]);
  });
  it('reports every missing header (and clickjacking) on a bare site', async () => {
    const f = await new HeadersCheck().run(ctx({ '/': resp(200) }));
    expect(types(f)).toEqual([
      'headers.clickjacking:framing', 'headers.csp-missing:content-security-policy', 'headers.hsts-missing:strict-transport-security',
      'headers.nosniff-missing:x-content-type-options', 'headers.permissions-policy-missing:permissions-policy', 'headers.referrer-policy-missing:referrer-policy',
    ]);
    expect(f.every((x) => x.confidence === 'CONFIRMED')).toBe(true);
  });
  it('accepts X-Frame-Options OR CSP frame-ancestors, but not ALLOW-FROM', async () => {
    const noCsp = { ...good, 'content-security-policy': "default-src 'self'" };
    expect(types(await new HeadersCheck().run(ctx({ '/': resp(200, { ...noCsp, 'x-frame-options': 'DENY' }) })))).toEqual([]);
    expect(types(await new HeadersCheck().run(ctx({ '/': resp(200, { ...noCsp, 'x-frame-options': 'ALLOW-FROM https://a.com' }) })))).toEqual(['headers.clickjacking:framing']);
  });
  it('checks HSTS max-age', async () => {
    const f = await new HeadersCheck().run(ctx({ '/': resp(200, { ...good, 'strict-transport-security': 'max-age=3600' }) }));
    expect(f.map((x) => x.type)).toEqual(['headers.hsts-weak']);
    const zero = await new HeadersCheck().run(ctx({ '/': resp(200, { ...good, 'strict-transport-security': 'max-age=0' }) }));
    expect(zero[0].severity).toBe('MEDIUM');
  });
  it('does not demand HSTS from an HTTP-only site', async () => {
    const f = await new HeadersCheck().run(ctx({ '/': resp(200, {}, '', 'http://example.com/') }));
    expect(f.map((x) => x.type)).not.toContain('headers.hsts-missing');
  });
  it('flags unsafe-inline unless a nonce/hash is present', async () => {
    const weak = await new HeadersCheck().run(ctx({ '/': resp(200, { ...good, 'content-security-policy': "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'" }) }));
    expect(weak.map((x) => x.type)).toEqual(['headers.csp-weak']);
    const ok = await new HeadersCheck().run(ctx({ '/': resp(200, { ...good, 'content-security-policy': "script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'" }) }));
    expect(ok).toEqual([]);
  });
  it('does not judge a redirect response', async () => {
    expect(await new HeadersCheck().run(ctx({ '/': resp(301, { location: 'https://www.example.com/' }) }))).toEqual([]);
  });
});

describe('CookiesCheck', () => {
  it('parses attributes and never keeps the value', () => {
    const c = parseSetCookie('sid=SECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Lax')!;
    expect(c).toEqual({ name: 'sid', secure: true, httpOnly: true, sameSite: 'Lax' });
    expect(JSON.stringify(c)).not.toContain('SECRETVALUE');
  });
  it.each([['PHPSESSID', true], ['connect.sid', true], ['JSESSIONID', true], ['auth_token', true], ['sid', true], ['_ga', false], ['theme', false], ['residence', false]])(
    'session-like detection: %s -> %s', (name, expected) => expect(looksLikeSessionCookie(name)).toBe(expected),
  );
  it('marks CONFIRMED for session-like names and POTENTIAL otherwise, with no cookie values in evidence', async () => {
    const f = await new CookiesCheck().run(ctx({ '/': resp(200, { 'set-cookie': ['PHPSESSID=topsecret; Path=/', 'theme=dark'] }) }));
    const bySession = f.filter((x) => x.key === 'PHPSESSID');
    const byTheme = f.filter((x) => x.key === 'theme');
    expect(types(bySession)).toEqual(['cookies.httponly-missing:PHPSESSID', 'cookies.samesite-missing:PHPSESSID', 'cookies.secure-missing:PHPSESSID']);
    expect(bySession.every((x) => x.confidence === 'CONFIRMED')).toBe(true);
    expect(byTheme.every((x) => x.confidence === 'POTENTIAL')).toBe(true);
    expect(JSON.stringify(f)).not.toContain('topsecret');
  });
  it('emits nothing for a hardened cookie', async () => {
    expect(await new CookiesCheck().run(ctx({ '/': resp(200, { 'set-cookie': 'sid=x; Secure; HttpOnly; SameSite=Strict' }) }))).toEqual([]);
  });
  it('does not ask for Secure on an HTTP-only site', async () => {
    const f = await new CookiesCheck().run(ctx({ '/': resp(200, { 'set-cookie': 'sid=x; HttpOnly; SameSite=Lax' }, '', 'http://example.com/') }));
    expect(f).toEqual([]);
  });
});

describe('DisclosureCheck', () => {
  it('flags version strings only', async () => {
    const f = await new DisclosureCheck().run(ctx({ '/': resp(200, { server: 'nginx/1.18.0 (Ubuntu)', 'x-powered-by': 'PHP/7.4.3' }) }));
    expect(types(f)).toEqual(['disclosure.server-version:server', 'disclosure.x-powered-by-version:x-powered-by']);
    expect(await new DisclosureCheck().run(ctx({ '/': resp(200, { server: 'nginx', 'x-powered-by': 'Express' }) }))).toEqual([]);
  });
  it('finds stack traces in the 404 probe and in a 5xx root', async () => {
    const trace = 'Traceback (most recent call last):\n  File "/app/x.py", line 3';
    const f = await new DisclosureCheck().run(ctx({ '/': resp(500, {}, 'java.lang.NullPointerException\n\tat com.acme.Foo.bar(Foo.java:42)'), '/sentinel-probe-test': resp(404, {}, trace) }));
    expect(types(f)).toEqual(['disclosure.stack-trace:404-probe', 'disclosure.stack-trace:root-5xx']);
  });
  it.each([
    ['java', 'at com.acme.Foo.bar(Foo.java:42)'],
    ['node', 'at Object.<anonymous> (/srv/app/server.js:10:15)'],
    ['php', 'Fatal error: Uncaught Exception in /var/www/html/index.php on line 12'],
    ['ruby', "/app/models/user.rb:42:in `save'"],
    ['dotnet', 'System.NullReferenceException: Object reference not set'],
    ['go', 'goroutine 1 [running]:'],
  ])('recognises %s traces', (id, body) => expect(findStackTrace(body)?.id).toBe(id));
  it('does not flag ordinary prose or pages', () => {
    expect(findStackTrace('<h1>404 Not Found</h1><p>The page you requested could not be found at this location.</p>')).toBeNull();
    expect(findStackTrace('We are looking for a Java developer. See jobs.java for more.')).toBeNull();
  });
});

describe('ExposureCheck', () => {
  const spa = resp(200, { 'content-type': 'text/html' }, '<!doctype html><html><body><div id="root"></div></body></html>');
  const spaRoutes = { '/.git/': spa, '/.git/HEAD': spa, '/.env': spa, '/backup/': spa, '/uploads/': spa };

  it('does not report anything for an SPA that answers 200 to every path', async () => {
    expect(await new ExposureCheck().run(ctx(spaRoutes))).toEqual([]);
  });
  it('detects an exposed .env and records variable NAMES only', async () => {
    const f = await new ExposureCheck().run(ctx({ '/.env': resp(200, { 'content-type': 'text/plain' }, 'APP_ENV=prod\nDATABASE_URL=postgres://u:hunter2@db/x\nAWS_SECRET_KEY=abc123\n') }));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ type: 'exposure.env-file', severity: 'CRITICAL', confidence: 'CONFIRMED' });
    expect(JSON.stringify(f)).not.toMatch(/hunter2|abc123/);
    expect((f[0].evidence as any).variableNames).toEqual(['APP_ENV', 'DATABASE_URL', 'AWS_SECRET_KEY']);
  });
  it('needs at least two KEY= lines for .env', () => {
    expect(analyzeEnvFile('FOO=bar', 'text/plain')).toBeNull();
    expect(analyzeEnvFile('FOO=1\nBAR=2', 'text/plain')?.hasSecrets).toBe(false);
  });
  it('detects directory listings and git exposure, once', async () => {
    const listing = (p: string) => resp(200, { 'content-type': 'text/html' }, `<html><head><title>Index of ${p}</title></head><body><h1>Index of ${p}</h1></body></html>`);
    const git = resp(200, {}, '<h1>Index of /.git/</h1><a href="HEAD">HEAD</a><a href="objects/">objects/</a><a href="refs/">refs/</a>');
    const f = await new ExposureCheck().run(ctx({ '/.git/': git, '/.git/HEAD': resp(200, {}, 'ref: refs/heads/main\n'), '/backup/': listing('/backup/'), '/uploads/': listing('/uploads/') }));
    expect(types(f)).toEqual(['exposure.directory-listing:/backup/', 'exposure.directory-listing:/uploads/', 'exposure.git:/.git']);
    expect(f.find((x) => x.key === '/backup/')?.severity).toBe('HIGH');
  });
  it('detects .git via HEAD even when /.git/ itself is 403', async () => {
    const f = await new ExposureCheck().run(ctx({ '/.git/': resp(403), '/.git/HEAD': resp(200, {}, 'ref: refs/heads/main\n') }));
    expect(types(f)).toEqual(['exposure.git:/.git']);
  });
  it('probes ONLY the fixed list', async () => {
    const asked: string[] = [];
    await new ExposureCheck().run(ctx({}, { get: async (p) => (asked.push(p), resp(404)) }));
    expect(asked).toEqual(['/.git/', '/.git/HEAD', '/.env', '/backup/', '/uploads/']);
  });
});

describe('TlsCheck (stubbed handshake)', () => {
  const base: TlsProbeResult = {
    protocol: 'TLSv1.3', authorized: true, authorizationError: null, hostnameError: null,
    cert: { subjectCN: 'example.com', issuerO: 'Test CA', validTo: 'Dec 31 23:59:59 2026 GMT', san: 'DNS:example.com' },
  };
  const run = (main: Partial<TlsProbeResult>, legacy: 'refuse' | TlsProbeResult = 'refuse') =>
    new TlsCheck().run(ctx({}, {
      tlsProbe: async (o) => {
        if (o?.maxVersion === 'TLSv1.1') { if (legacy === 'refuse') throw new Error('alert protocol version'); return legacy; }
        return { ...base, ...main };
      },
    }));

  it('is clean for a healthy certificate', async () => expect(await run({})).toEqual([]));
  it('flags expiry under 14 days, with day-count in the title but a stable key', async () => {
    const f = await run({ cert: { ...base.cert, validTo: 'Jun 10 00:00:00 2026 GMT' } });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ type: 'tls.certificate-expiry', key: 'validity', severity: 'MEDIUM' });
    expect(f[0].title).toMatch(/9 days/);
  });
  it('does not flag 14+ days', async () => expect(await run({ cert: { ...base.cert, validTo: 'Jun 15 00:00:00 2026 GMT' } })).toEqual([]));
  it('flags an expired certificate as HIGH without also reporting an untrusted chain', async () => {
    const f = await run({ authorized: false, authorizationError: 'CERT_HAS_EXPIRED', cert: { ...base.cert, validTo: 'May 20 00:00:00 2026 GMT' } });
    expect(f.map((x) => x.type)).toEqual(['tls.certificate-expiry']);
    expect(f[0].severity).toBe('HIGH');
  });
  it('flags hostname mismatch (checked explicitly even when the chain also failed)', async () => {
    const f = await run({ authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT', hostnameError: "Hostname/IP does not match certificate's altnames" });
    expect(f.map((x) => x.type).sort()).toEqual(['tls.hostname-mismatch', 'tls.untrusted-chain']);
    expect(f.find((x) => x.type === 'tls.untrusted-chain')).toMatchObject({ confidence: 'CONFIRMED', title: 'TLS certificate is self-signed' });
  });
  it('treats an incomplete chain as POTENTIAL (could be our trust store)', async () => {
    const f = await run({ authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
    expect(f[0]).toMatchObject({ type: 'tls.untrusted-chain', confidence: 'POTENTIAL', severity: 'MEDIUM' });
  });
  it('flags a server that accepts TLS 1.0/1.1 even though the best handshake was 1.3', async () => {
    const f = await run({}, { ...base, protocol: 'TLSv1' });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ type: 'tls.legacy-protocol', severity: 'MEDIUM' });
    expect(f[0].title).toMatch(/TLSv1/);
  });
  it('legacy-only server: modern handshake fails but the legacy probe succeeds -> finding, cert checked from legacy handshake', async () => {
    const f = await new TlsCheck().run(ctx({}, {
      tlsProbe: async (o) => {
        if (o?.maxVersion === 'TLSv1.1') return { ...base, protocol: 'TLSv1', cert: { ...base.cert, validTo: 'Jun 05 00:00:00 2026 GMT' } };
        throw Object.assign(new Error('handshake failure'), { code: 'ERR_SSL_NO_PROTOCOLS_AVAILABLE' });
      },
    }));
    expect(f.map((x) => x.type).sort()).toEqual(['tls.certificate-expiry', 'tls.legacy-protocol']);
  });
  it('reports unreachable 443 as POTENTIAL instead of erroring', async () => {
    const f = await new TlsCheck().run(ctx({}, { tlsProbe: async () => { throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }); } }));
    expect(f[0]).toMatchObject({ type: 'tls.unavailable', confidence: 'POTENTIAL' });
  });
  it('lets other errors propagate (the runner records them as a failed check)', async () => {
    await expect(new TlsCheck().run(ctx({}, { tlsProbe: async () => { throw Object.assign(new Error('bad'), { code: 'ERR_SSL_WRONG_VERSION_NUMBER' }); } }))).rejects.toThrow('bad');
  });
});
