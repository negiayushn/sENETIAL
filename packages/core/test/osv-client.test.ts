import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { OsvClient, OsvError } from '../src';

type Handler = (req: http.IncomingMessage, body: any, res: http.ServerResponse) => void;
let server: http.Server | undefined;
async function start(handler: Handler): Promise<string> {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString();
      handler(req, raw ? JSON.parse(raw) : undefined, res);
    });
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
}
afterEach(async () => {
  server?.closeAllConnections();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});
const json = (res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) =>
  res.writeHead(status, { 'content-type': 'application/json', ...headers }).end(JSON.stringify(body));
const noSleep = async () => undefined;
const pkgs = (n: number) => Array.from({ length: n }, (_, i) => ({ name: `p${i}`, version: '1.0.0' }));

describe('OsvClient.queryBatch', () => {
  it('sends npm queries in chunks of 500 and maps results back by position', async () => {
    const sizes: number[] = [];
    const base = await start((_req, body, res) => {
      sizes.push(body.queries.length);
      expect(body.queries[0]).toEqual({ package: { name: expect.any(String), ecosystem: 'npm' }, version: '1.0.0' });
      json(res, 200, { results: body.queries.map((q: any) => (q.package.name === 'p700' ? { vulns: [{ id: 'GHSA-x', modified: '2024-01-01T00:00:00Z' }] } : {})) });
    });
    const out = await new OsvClient({ baseUrl: base }).queryBatch(pkgs(1200));
    expect(sizes).toEqual([500, 500, 200]);
    expect([...out.keys()]).toEqual(['p700@1.0.0']);
    expect(out.get('p700@1.0.0')).toEqual([{ id: 'GHSA-x', modified: '2024-01-01T00:00:00Z' }]);
  });

  it('deduplicates identical name@version pairs before querying', async () => {
    let total = 0;
    const base = await start((_r, body, res) => { total += body.queries.length; json(res, 200, { results: body.queries.map(() => ({})) }); });
    await new OsvClient({ baseUrl: base }).queryBatch([...pkgs(3), ...pkgs(3)]);
    expect(total).toBe(3);
  });

  it('follows next_page_token ONLY for the queries that have one, and merges the pages', async () => {
    const seen: any[] = [];
    const base = await start((_r, body, res) => {
      seen.push(body.queries.map((q: any) => `${q.package.name}${q.page_token ? `#${q.page_token}` : ''}`));
      json(res, 200, {
        results: body.queries.map((q: any) => {
          if (q.package.name !== 'big') return { vulns: [{ id: `V-${q.package.name}` }] };
          if (!q.page_token) return { vulns: [{ id: 'A' }, { id: 'B' }], next_page_token: 't1' };
          if (q.page_token === 't1') return { vulns: [{ id: 'C' }], next_page_token: 't2' };
          return { vulns: [{ id: 'D' }] };
        }),
      });
    });
    const out = await new OsvClient({ baseUrl: base }).queryBatch([{ name: 'big', version: '1.0.0' }, { name: 'small', version: '2.0.0' }]);
    expect(seen).toEqual([['big', 'small'], ['big#t1'], ['big#t2']]);
    expect(out.get('big@1.0.0')!.map((v) => v.id)).toEqual(['A', 'B', 'C', 'D']);
    expect(out.get('small@2.0.0')!.map((v) => v.id)).toEqual(['V-small']);
  });

  it('gives up if the server paginates forever', async () => {
    const base = await start((_r, body, res) => json(res, 200, { results: body.queries.map(() => ({ vulns: [{ id: 'X' }], next_page_token: 'again' })) }));
    await expect(new OsvClient({ baseUrl: base }).queryBatch(pkgs(1))).rejects.toThrow(/did not terminate/);
  });

  it('ignores vulnerability ids that are not safe to put in a URL later', async () => {
    const base = await start((_r, body, res) => json(res, 200, { results: body.queries.map(() => ({ vulns: [{ id: '../../etc/passwd' }, { id: 'GHSA-ok' }, { id: 5 }] })) }));
    const out = await new OsvClient({ baseUrl: base }).queryBatch(pkgs(1));
    expect(out.get('p0@1.0.0')).toEqual([{ id: 'GHSA-ok', modified: null }]);
  });

  it('rejects a response whose result count does not match the query count', async () => {
    const base = await start((_r, _b, res) => json(res, 200, { results: [{}] }));
    await expect(new OsvClient({ baseUrl: base, maxRetries: 0 }).queryBatch(pkgs(2))).rejects.toMatchObject({ name: 'OsvError', retryable: true });
  });
});

describe('OsvClient retries and errors', () => {
  it('retries 503 then succeeds, with exponential backoff between attempts', async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const base = await start((_r, body, res) => { calls++; calls < 3 ? json(res, 503, {}) : json(res, 200, { results: body.queries.map(() => ({})) }); });
    await new OsvClient({ baseUrl: base, sleep: async (ms) => void sleeps.push(ms) }).queryBatch(pkgs(1));
    expect(calls).toBe(3);
    expect(sleeps[1]).toBeGreaterThan(sleeps[0]); // 500ms-ish then 1000ms-ish (plus jitter)
  });

  it('honours Retry-After on 429', async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const base = await start((_r, body, res) => { calls++; calls === 1 ? json(res, 429, {}, { 'retry-after': '7' }) : json(res, 200, { results: body.queries.map(() => ({})) }); });
    await new OsvClient({ baseUrl: base, sleep: async (ms) => void sleeps.push(ms) }).queryBatch(pkgs(1));
    expect(sleeps).toContain(7000);
  });

  it('does NOT retry other 4xx (fails fast, non-retryable)', async () => {
    let calls = 0;
    const base = await start((_r, _b, res) => { calls++; json(res, 400, { message: 'bad' }); });
    const err = await new OsvClient({ baseUrl: base, sleep: noSleep }).queryBatch(pkgs(1)).catch((e) => e);
    expect(err).toBeInstanceOf(OsvError);
    expect(err).toMatchObject({ retryable: false, status: 400 });
    expect(calls).toBe(1);
  });

  it('gives up after maxRetries and reports a retryable error', async () => {
    let calls = 0;
    const base = await start((_r, _b, res) => { calls++; json(res, 500, {}); });
    const err = await new OsvClient({ baseUrl: base, maxRetries: 2, sleep: noSleep }).queryBatch(pkgs(1)).catch((e) => e);
    expect(calls).toBe(3);
    expect(err).toMatchObject({ retryable: true, status: 500 });
  });

  it('treats connection failures and timeouts as retryable', async () => {
    const down = await new OsvClient({ baseUrl: 'http://127.0.0.1:1', maxRetries: 1, sleep: noSleep }).queryBatch(pkgs(1)).catch((e) => e);
    expect(down).toMatchObject({ name: 'OsvError', retryable: true });
    const base = await start(() => undefined); // never answers
    const slow = await new OsvClient({ baseUrl: base, timeoutMs: 150, maxRetries: 0 }).queryBatch(pkgs(1)).catch((e) => e);
    expect(slow).toMatchObject({ name: 'OsvError', retryable: true });
  });

  it('invalid JSON from the server is an error, not a crash', async () => {
    const base = await start((_r, _b, res) => res.writeHead(200).end('<html>nope'));
    await expect(new OsvClient({ baseUrl: base, sleep: noSleep }).queryBatch(pkgs(1))).rejects.toThrow(/invalid JSON/);
  });
});

describe('OsvClient.getVuln / getVulns', () => {
  it('fetches an advisory by id (URL-encoded) and returns null on 404', async () => {
    const urls: string[] = [];
    const base = await start((req, _b, res) => { urls.push(req.url!); req.url!.endsWith('/GONE') ? json(res, 404, {}) : json(res, 200, { id: 'GHSA-1' }); });
    const c = new OsvClient({ baseUrl: base });
    expect(await c.getVuln('GHSA-1')).toEqual({ id: 'GHSA-1' });
    expect(await c.getVuln('GONE')).toBeNull();
    expect(urls[0]).toBe('/v1/vulns/GHSA-1');
  });

  it('refuses malformed ids without making a request', async () => {
    let calls = 0;
    const base = await start((_r, _b, res) => { calls++; json(res, 200, {}); });
    const c = new OsvClient({ baseUrl: base });
    for (const id of ['../x', 'a/b', '', 'a b', 'x'.repeat(300)]) await expect(c.getVuln(id)).rejects.toBeInstanceOf(OsvError);
    expect(calls).toBe(0);
  });

  it('bounds parallelism and dedupes ids', async () => {
    let inFlight = 0, max = 0, calls = 0;
    const base = await start((_r, _b, res) => {
      calls++; inFlight++; max = Math.max(max, inFlight);
      setTimeout(() => { inFlight--; json(res, 200, { id: 'x' }); }, 30);
    });
    const ids = Array.from({ length: 20 }, (_, i) => `ID-${i}`);
    const out = await new OsvClient({ baseUrl: base, concurrency: 4 }).getVulns([...ids, ...ids]);
    expect(out.size).toBe(20);
    expect(calls).toBe(20);
    expect(max).toBeLessThanOrEqual(4);
    expect(max).toBeGreaterThan(1);
  });

  it('fails fast (and stops issuing requests) when one fetch fails permanently', async () => {
    let calls = 0;
    const base = await start((req, _b, res) => { calls++; req.url!.endsWith('/ID-2') ? json(res, 400, {}) : json(res, 200, { id: 'ok' }); });
    await expect(new OsvClient({ baseUrl: base, concurrency: 1, sleep: noSleep }).getVulns(Array.from({ length: 50 }, (_, i) => `ID-${i}`))).rejects.toBeInstanceOf(OsvError);
    expect(calls).toBeLessThan(10);
  });
});
