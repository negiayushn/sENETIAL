import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BlockedAddressError, createSafeFetch, SsrfError, TooManyRedirectsError, UnsafeUrlError } from '../src';
import { LOOPBACK, startServer, testGuard } from './helpers';

describe('safeFetch with the DEFAULT (production) policy – nothing is reachable that should not be', () => {
  const client = createSafeFetch();
  afterAll(() => client.close());

  const blockedUrls = [
    'http://127.0.0.1/',
    'http://127.0.0.1:80/admin',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://[::ffff:169.254.169.254]/',
    'http://10.0.0.1/',
    'http://192.168.0.1/',
    'http://0.0.0.0/',
    'http://2130706433/', // decimal 127.0.0.1
    'http://0x7f.1/', // hex/short form of 127.0.0.1
    'http://017700000001/', // octal 127.0.0.1
    'https://100.64.0.1/',
  ];
  it.each(blockedUrls)('refuses IP literal %s', async (url) => {
    await expect(client.fetch(url)).rejects.toBeInstanceOf(BlockedAddressError);
  });

  it('refuses a name that resolves to loopback (localhost) at connect time', async () => {
    await expect(client.fetch('http://localhost/')).rejects.toBeInstanceOf(SsrfError);
  });

  it.each([
    ['file:///etc/passwd', /Protocol/],
    ['ftp://example.com/', /Protocol/],
    ['gopher://example.com/', /Protocol/],
    ['http://user:pass@example.com/', /Credentials/],
    ['http://example.com:6379/', /Port not allowed: 6379/],
    ['https://example.com:8443/', /Port not allowed: 8443/],
    ['http://example.com:22/', /Port not allowed: 22/],
  ])('refuses %s', async (url, msg) => {
    const p = client.fetch(url);
    await expect(p).rejects.toBeInstanceOf(UnsafeUrlError);
    await expect(p).rejects.toThrow(msg);
  });
});

describe('safeFetch behaviour (fake DNS, local server)', () => {
  const dnsCalls: string[] = [];
  const dnsTable = {
    'app.test': LOOPBACK,
    'other.test': LOOPBACK,
    'meta.test': [{ address: '169.254.169.254', family: 4 as const }],
    'rebind.test': [
      { address: '127.0.0.1', family: 4 as const },
      { address: '10.0.0.7', family: 4 as const },
    ],
  };
  let port = 0;
  let close: () => Promise<void>;
  let lastHeaders: Record<string, unknown> = {};

  beforeAll(async () => {
    const s = await startServer((req, res) => {
      lastHeaders = req.headers;
      const u = req.url ?? '/';
      if (u === '/ok') return void res.end('hello');
      if (u === '/redir-same') return void res.writeHead(302, { location: '/ok' }).end();
      if (u === '/redir-other') return void res.writeHead(302, { location: `http://other.test:${port}/ok` }).end();
      if (u === '/redir-meta-literal') return void res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }).end();
      if (u === '/redir-meta-dns') return void res.writeHead(302, { location: `http://meta.test:${port}/` }).end();
      if (u === '/redir-ftp') return void res.writeHead(302, { location: 'ftp://app.test/x' }).end();
      if (u === '/redir-port') return void res.writeHead(302, { location: 'http://app.test:6379/' }).end();
      if (u === '/loop') return void res.writeHead(302, { location: '/loop' }).end();
      if (u === '/big') return void res.end(Buffer.alloc(5 * 1024 * 1024, 'a'));
      if (u === '/slow-headers') return; // never respond
      if (u === '/trickle') {
        res.writeHead(200);
        const t = setInterval(() => res.write('x'), 50);
        res.on('close', () => clearInterval(t));
        return;
      }
      res.statusCode = 404;
      res.end('nope');
    });
    port = s.port;
    close = s.close;
  });
  afterAll(() => close());

  const make = (extra: Parameters<typeof createSafeFetch>[0] = {}) =>
    createSafeFetch({ guard: testGuard(dnsTable, dnsCalls), allowedPorts: [port], ...extra });

  it('fetches and returns status, headers and body', async () => {
    const c = make();
    const r = await c.fetch(`http://app.test:${port}/ok`);
    expect(r.statusCode).toBe(200);
    expect(r.text()).toBe('hello');
    expect(r.truncated).toBe(false);
    await c.close();
  });

  it('sends identity encoding and an identifiable User-Agent', async () => {
    const c = make();
    await c.fetch(`http://app.test:${port}/ok`);
    expect(lastHeaders['accept-encoding']).toBe('identity');
    expect(String(lastHeaders['user-agent'])).toMatch(/Sentinel/);
    await c.close();
  });

  it('resolves DNS exactly once per connection (validated IP == connected IP)', async () => {
    dnsCalls.length = 0;
    const c = make();
    await c.fetch(`http://app.test:${port}/ok`);
    expect(dnsCalls.filter((h) => h === 'app.test')).toHaveLength(1);
    await c.close();
  });

  it('rejects a host whose DNS answer mixes a good and a private address', async () => {
    const c = make();
    await expect(c.fetch(`http://rebind.test:${port}/ok`)).rejects.toBeInstanceOf(BlockedAddressError);
    await c.close();
  });

  it('follows same-host redirects', async () => {
    const c = make({ allowedHosts: ['app.test'] });
    const r = await c.fetch(`http://app.test:${port}/redir-same`);
    expect(r.statusCode).toBe(200);
    expect(r.redirects).toHaveLength(1);
    expect(r.blockedRedirect).toBeUndefined();
    await c.close();
  });

  it('does NOT follow a redirect to a different host when allowedHosts is set', async () => {
    const c = make({ allowedHosts: ['app.test'] });
    const r = await c.fetch(`http://app.test:${port}/redir-other`);
    expect(r.statusCode).toBe(302);
    expect(r.blockedRedirect?.reason).toMatch(/Host not allowed: other.test/);
    await c.close();
  });

  it('does NOT follow a redirect to the metadata IP (literal) – refused by the IP rule, not just the port rule', async () => {
    const c = make({ allowedPorts: [port, 80] });
    const r = await c.fetch(`http://app.test:${port}/redir-meta-literal`);
    expect(r.statusCode).toBe(302);
    expect(r.blockedRedirect?.reason).toMatch(/169\.254\.169\.254/);
    await c.close();
  });

  it('does NOT follow a redirect to a hostname that resolves to the metadata IP', async () => {
    const c = make();
    const r = await c.fetch(`http://app.test:${port}/redir-meta-dns`);
    expect(r.statusCode).toBe(302);
    expect(r.blockedRedirect?.reason).toMatch(/Blocked address 169\.254\.169\.254/);
    await c.close();
  });

  it('does NOT follow redirects to other protocols or ports', async () => {
    const c = make();
    expect((await c.fetch(`http://app.test:${port}/redir-ftp`)).blockedRedirect?.reason).toMatch(/Protocol/);
    expect((await c.fetch(`http://app.test:${port}/redir-port`)).blockedRedirect?.reason).toMatch(/Port not allowed: 6379/);
    await c.close();
  });

  it('stops redirect loops', async () => {
    const c = make({ maxRedirects: 3 });
    await expect(c.fetch(`http://app.test:${port}/loop`)).rejects.toBeInstanceOf(TooManyRedirectsError);
    await c.close();
  });

  it('caps the body and stops downloading', async () => {
    const c = make({ maxBodyBytes: 1024 * 1024 });
    const r = await c.fetch(`http://app.test:${port}/big`);
    expect(r.truncated).toBe(true);
    expect(r.body.length).toBe(1024 * 1024);
    await c.close();
  });

  it('times out a server that never sends headers', async () => {
    const c = make({ headersTimeoutMs: 300 });
    await expect(c.fetch(`http://app.test:${port}/slow-headers`)).rejects.toThrow();
    await c.close();
  });

  it('enforces a TOTAL deadline against a server that trickles bytes forever', async () => {
    const c = make({ totalTimeoutMs: 600, bodyTimeoutMs: 5000, maxBodyBytes: 10 * 1024 * 1024 });
    const started = Date.now();
    await expect(c.fetch(`http://app.test:${port}/trickle`)).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(3000);
    await c.close();
  });

  it('calls beforeRequest for every hop (rate-limiter hook)', async () => {
    const seen: string[] = [];
    const c = make({ allowedHosts: ['app.test'], beforeRequest: async (u) => void seen.push(u.pathname) });
    await c.fetch(`http://app.test:${port}/redir-same`);
    expect(seen).toEqual(['/redir-same', '/ok']);
    await c.close();
  });

  it('rejects the first URL if its host is not in allowedHosts', async () => {
    const c = make({ allowedHosts: ['app.test'] });
    await expect(c.fetch(`http://other.test:${port}/ok`)).rejects.toBeInstanceOf(UnsafeUrlError);
    await c.close();
  });
});
