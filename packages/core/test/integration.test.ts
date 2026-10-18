import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RateLimiter, runScan, tlsProbe, TlsCheck, createScanContext, createSafeFetch } from '../src';
import { LOOPBACK, startServer, testGuard } from './helpers';

let dir: string;
const pem = (name: string) => ({ key: fs.readFileSync(path.join(dir, `${name}.key`)), cert: fs.readFileSync(path.join(dir, `${name}.crt`)) });

function makeCert(name: string, cn: string) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-keyout', path.join(dir, `${name}.key`), '-out', path.join(dir, `${name}.crt`), '-subj', `/CN=${cn}`, '-addext', `subjectAltName=DNS:${cn}`], { stdio: 'ignore' });
}

async function tlsServer(opts: tls.TlsOptions): Promise<{ port: number; close: () => Promise<void> }> {
  const server = tls.createServer(opts, (s) => s.end('ok'));
  server.on('tlsClientError', () => undefined);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { port: (server.address() as AddressInfo).port, close: () => new Promise<void>((r) => server.close(() => r())) };
}

const guard = testGuard({ 'app.test': LOOPBACK });
const closers: (() => Promise<void>)[] = [];
beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-tls-'));
  makeCert('app', 'app.test');
  makeCert('other', 'other.test');
});
afterAll(async () => {
  await Promise.all(closers.map((c) => c()));
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('tlsProbe against real TLS servers', () => {
  it('reports a self-signed certificate and negotiates TLS 1.3 with a modern server', async () => {
    const s = await tlsServer(pem('app')); closers.push(s.close);
    const r = await tlsProbe({ hostname: 'app.test', guard, port: s.port });
    expect(r.protocol).toBe('TLSv1.3');
    expect(r.authorized).toBe(false);
    expect(r.authorizationError).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(r.hostnameError).toBeNull();
    expect(r.cert.subjectCN).toBe('app.test');
    expect(r.cert.validTo).toBeTruthy();
  });

  it('detects a certificate for the wrong hostname via the explicit identity check', async () => {
    const s = await tlsServer(pem('other')); closers.push(s.close);
    const r = await tlsProbe({ hostname: 'app.test', guard, port: s.port });
    expect(r.hostnameError).toMatch(/altnames|does not match/i);
  });

  it('refuses to connect when the hostname resolves to a blocked address (default guard)', async () => {
    const { createGuard } = await import('../src');
    await expect(tlsProbe({ hostname: 'localhost', guard: createGuard(), port: 443 })).rejects.toMatchObject({ name: 'BlockedAddressError' });
  });

  it('legacy probe: succeeds against a TLS1.0/1.1-only server, fails against a modern one', async () => {
    const legacy = await tlsServer({ ...pem('app'), minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'ALL:@SECLEVEL=0' }); closers.push(legacy.close);
    const modern = await tlsServer(pem('app')); closers.push(modern.close);

    const accepted = await tlsProbe({ hostname: 'app.test', guard, port: legacy.port, minVersion: 'TLSv1', maxVersion: 'TLSv1.1' });
    expect(['TLSv1', 'TLSv1.1']).toContain(accepted.protocol);
    await expect(tlsProbe({ hostname: 'app.test', guard, port: modern.port, minVersion: 'TLSv1', maxVersion: 'TLSv1.1' })).rejects.toThrow();
  });

  it('TlsCheck end-to-end: a LEGACY-ONLY server is reported (not treated as a failed check)', async () => {
    const legacy = await tlsServer({ ...pem('app'), minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'ALL:@SECLEVEL=0' }); closers.push(legacy.close);
    const http = createSafeFetch({ guard });
    const ctx = createScanContext({ hostname: 'app.test', guard, http, limiter: new RateLimiter(0, 50), tlsPort: legacy.port });
    const f = await new TlsCheck().run(ctx);
    expect(f.map((x) => x.type).sort()).toEqual(['tls.legacy-protocol', 'tls.untrusted-chain']);
    expect(f.find((x) => x.type === 'tls.legacy-protocol')?.evidence).toMatchObject({ modernHandshakeFailed: true });
    await http.close();
  });

  it('TlsCheck end-to-end: modern self-signed server yields exactly the self-signed finding', async () => {
    const modern = await tlsServer(pem('app')); closers.push(modern.close);
    const http = createSafeFetch({ guard });
    const ctx = createScanContext({ hostname: 'app.test', guard, http, limiter: new RateLimiter(0, 50), tlsPort: modern.port });
    const f = await new TlsCheck().run(ctx);
    expect(f.map((x) => x.type)).toEqual(['tls.untrusted-chain']);
    expect(f[0].title).toMatch(/self-signed/);
    await http.close();
  });
});

describe('runScan end-to-end against a deliberately vulnerable site', () => {
  it('finds the planted problems, dedupes, and keeps secrets out of the result', async () => {
    const tlsSrv = await tlsServer(pem('app')); closers.push(tlsSrv.close);
    const site = await startServer((req, res) => {
      const u = req.url ?? '/';
      if (u === '/') {
        res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
        res.setHeader('X-Powered-By', 'PHP/7.4.3');
        res.setHeader('Set-Cookie', ['PHPSESSID=SUPERSECRETSESSION; Path=/', 'PHPSESSID=SUPERSECRETSESSION; Path=/', 'theme=dark']);
        return void res.end('<html>home</html>');
      }
      if (u === '/.env') return void res.setHeader('content-type', 'text/plain').end('APP_KEY=base64:abcdef\nDB_PASSWORD=hunter2\n');
      if (u === '/.git/HEAD') return void res.end('ref: refs/heads/main\n');
      if (u === '/backup/') return void res.end('<title>Index of /backup</title><h1>Index of /backup/</h1>');
      res.statusCode = 404;
      res.end('Traceback (most recent call last):\n  File "/srv/app.py", line 1, in <module>');
    });
    closers.push(site.close);

    const result = await runScan({
      hostname: 'app.test',
      guard,
      limiter: new RateLimiter(0, 60),
      http: { allowedPorts: [site.port] },
      rootUrls: [`http://app.test:${site.port}/`],
      tlsPort: tlsSrv.port,
    });

    expect(result.checks.map((c) => [c.id, c.status])).toEqual([['tls', 'ok'], ['headers', 'ok'], ['cookies', 'ok'], ['disclosure', 'ok'], ['exposure', 'ok']]);
    const t = result.findings.map((f) => `${f.type}:${f.key}`);
    expect(t).toContain('headers.csp-missing:content-security-policy');
    expect(t).toContain('disclosure.server-version:server');
    expect(t).toContain('disclosure.x-powered-by-version:x-powered-by');
    expect(t).toContain('disclosure.stack-trace:404-probe');
    expect(t).toContain('exposure.env-file:/.env');
    expect(t).toContain('exposure.git:/.git');
    expect(t).toContain('exposure.directory-listing:/backup/');
    expect(t).toContain('cookies.httponly-missing:PHPSESSID');
    expect(t).toContain('tls.untrusted-chain:chain');
    // HSTS is not demanded of an http origin
    expect(t).not.toContain('headers.hsts-missing:strict-transport-security');
    // the duplicated Set-Cookie did not produce duplicate findings
    expect(t.filter((x) => x === 'cookies.httponly-missing:PHPSESSID')).toHaveLength(1);
    expect(new Set(t).size).toBe(t.length);
    // no secret value anywhere in anything we would store
    expect(JSON.stringify(result)).not.toMatch(/SUPERSECRETSESSION|hunter2|abcdef/);
    expect(result.requests).toBeLessThanOrEqual(60);
  });

  it('aborts the whole scan when the target resolves to a private address (default guard)', async () => {
    const { createGuard } = await import('../src');
    const g = createGuard({ resolver: async () => [{ address: '10.0.0.8', family: 4 }] });
    await expect(runScan({ hostname: 'internal.example.com', guard: g })).rejects.toMatchObject({ name: 'BlockedAddressError' });
  });

  it('records a failing check as an error without stopping the others', async () => {
    const result = await runScan({
      hostname: 'app.test', guard, limiter: new RateLimiter(0, 60), http: { allowedPorts: [1] },
      rootUrls: ['http://app.test:1/'], // nothing listens here -> connection refused
      checks: [{ id: 'boom', run: async () => { throw new Error('kaboom'); } }, { id: 'fine', run: async () => [] }],
    });
    expect(result.checks).toMatchObject([{ id: 'boom', status: 'error', error: 'kaboom' }, { id: 'fine', status: 'ok' }]);
  });

  it('enforces the per-scan request budget', async () => {
    const site = await startServer((_q, r) => r.end('x')); closers.push(site.close);
    const result = await runScan({
      hostname: 'app.test', guard, limiter: new RateLimiter(0, 3), http: { allowedPorts: [site.port] },
      rootUrls: [`http://app.test:${site.port}/`], tlsPort: 1,
      checks: [{ id: 'many', run: async (ctx) => { for (const p of ['/a', '/b', '/c', '/d', '/e']) await ctx.get(p); return []; } }],
    });
    expect(result.requests).toBe(3);
    expect(result.checks[0]).toMatchObject({ status: 'error' });
    expect(result.checks[0].error).toMatch(/budget/i);
  });
});
