import net from 'node:net';
import type { Readable } from 'node:stream';
import { Agent, request } from 'undici';
import { createGuard, SsrfError, UnsafeUrlError, type Guard } from './guard';

export class TooManyRedirectsError extends Error {
  constructor(max: number) {
    super(`Too many redirects (max ${max})`);
    this.name = 'TooManyRedirectsError';
  }
}

export interface SafeFetchConfig {
  guard?: Guard;
  /** Only these destination ports may be contacted (initial URL and every redirect). Default: 80, 443. */
  allowedPorts?: number[];
  /**
   * If set, EVERY hop (including the first) must be one of these exact hostnames. The scanner passes the
   * verified target hostname so a redirect can never walk us onto a host the user did not prove they own.
   */
  allowedHosts?: string[];
  maxRedirects?: number;
  maxBodyBytes?: number;
  connectTimeoutMs?: number;
  headersTimeoutMs?: number;
  bodyTimeoutMs?: number;
  /** Wall-clock cap for one fetch() call across all hops. headers/body timeouts only bound *gaps*, not totals. */
  totalTimeoutMs?: number;
  userAgent?: string;
  /** Called before every network request (the scanner plugs its per-target rate limiter in here). */
  beforeRequest?: (url: URL) => Promise<void>;
}

export interface SafeResponse {
  /** URL of the response that was returned (the last hop actually fetched). */
  url: string;
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  /** true if the body was cut at maxBodyBytes */
  truncated: boolean;
  /** URLs followed to get here (excluding the first). */
  redirects: string[];
  /** Set when the response is a redirect we REFUSED to follow; `statusCode`/`headers` are those of the redirect itself. */
  blockedRedirect?: { location: string; reason: string };
  text(): string;
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const normHost = (h: string) => h.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

function findSsrfError(err: unknown): SsrfError | null {
  let cur: unknown = err;
  for (let i = 0; i < 4 && cur; i++) {
    if (cur instanceof SsrfError) return cur;
    cur = (cur as { cause?: unknown }).cause;
  }
  return null;
}

async function readCapped(body: Readable, max: number): Promise<{ buf: Buffer; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of body) {
    const b: Buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    if (size + b.length > max) {
      chunks.push(b.subarray(0, max - size));
      body.destroy(); // stop downloading; do not drain a multi-GB response
      return { buf: Buffer.concat(chunks), truncated: true };
    }
    chunks.push(b);
    size += b.length;
  }
  return { buf: Buffer.concat(chunks), truncated: false };
}

function makeResponse(p: Omit<SafeResponse, 'text'>): SafeResponse {
  return { ...p, text: () => p.body.toString('utf8') };
}

export function createSafeFetch(config: SafeFetchConfig = {}) {
  const guard = config.guard ?? createGuard();
  const allowedPorts = new Set(config.allowedPorts ?? [80, 443]);
  const allowedHosts = config.allowedHosts?.map(normHost);
  const maxRedirects = config.maxRedirects ?? 5;
  const maxBody = config.maxBodyBytes ?? 1024 * 1024;
  const headersTimeout = config.headersTimeoutMs ?? 5000;
  const bodyTimeout = config.bodyTimeoutMs ?? 5000;
  const totalTimeout = config.totalTimeoutMs ?? 20_000;

  const agent = new Agent({
    // Validation and connection happen on the SAME resolution result, so there is no window for DNS rebinding.
    connect: { lookup: guard.lookup, timeout: config.connectTimeoutMs ?? 5000 },
  });

  /** Everything we can decide about a URL without touching the network. Throws SsrfError. */
  function assertUrlAllowed(url: URL): void {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new UnsafeUrlError(`Protocol not allowed: ${url.protocol}`);
    if (url.username || url.password) throw new UnsafeUrlError('Credentials in URL are not allowed');
    const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
    if (!allowedPorts.has(port)) throw new UnsafeUrlError(`Port not allowed: ${port}`);
    const host = normHost(url.hostname);
    if (allowedHosts && !allowedHosts.includes(host)) throw new UnsafeUrlError(`Host not allowed: ${host}`);
    // Node never invokes `lookup` for IP literals, so the connect-time guard would be skipped entirely.
    // WHATWG URL has already normalised 2130706433 / 0x7f.1 / 017700000001 to 127.0.0.1 at this point.
    if (net.isIP(host)) guard.assertIpAllowed(host);
  }

  async function fetchOne(input: string | URL, opts: { maxBodyBytes?: number; headers?: Record<string, string> } = {}): Promise<SafeResponse> {
    const signal = AbortSignal.timeout(totalTimeout);
    const bodyLimit = opts.maxBodyBytes ?? maxBody;
    let current = new URL(String(input));
    const redirects: string[] = [];
    let lastRedirect: { res: { statusCode: number; headers: SafeResponse['headers'] }; url: string; location: string } | null = null;

    const refusedRedirect = (reason: string): SafeResponse =>
      makeResponse({
        url: lastRedirect!.url,
        statusCode: lastRedirect!.res.statusCode,
        headers: lastRedirect!.res.headers,
        body: Buffer.alloc(0),
        truncated: false,
        redirects,
        blockedRedirect: { location: lastRedirect!.location, reason },
      });

    for (let hop = 0; ; hop++) {
      try {
        assertUrlAllowed(current);
      } catch (err) {
        // A redirect we won't follow is reported, not thrown: the response that pointed at it is still useful.
        if (hop > 0 && err instanceof SsrfError) return refusedRedirect(err.message);
        throw err;
      }

      await config.beforeRequest?.(current);

      let res: Awaited<ReturnType<typeof request>>;
      try {
        res = await request(current, {
          method: 'GET',
          dispatcher: agent,
          signal,
          headersTimeout,
          bodyTimeout,
          headers: {
            'user-agent': config.userAgent ?? 'SentinelScanner/0.1',
            accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
            'accept-encoding': 'identity', // never receive compressed bodies (zip-bomb surface)
            ...opts.headers,
          },
        });
      } catch (err) {
        const ssrf = findSsrfError(err);
        if (ssrf) {
          if (hop > 0) return refusedRedirect(ssrf.message);
          throw ssrf;
        }
        throw err;
      }

      // Destroying an unread/partially-read undici body emits 'error' (AbortError). With no listener that is an
      // uncaught exception, i.e. a crashed worker. Real read errors still surface through readCapped's for-await.
      res.body.on('error', () => undefined);

      const location = res.headers.location;
      if (REDIRECT_CODES.has(res.statusCode) && typeof location === 'string') {
        res.body.destroy();
        if (hop >= maxRedirects) throw new TooManyRedirectsError(maxRedirects);
        lastRedirect = { res: { statusCode: res.statusCode, headers: res.headers }, url: current.toString(), location };
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          return refusedRedirect('Invalid redirect location');
        }
        redirects.push(next.toString());
        current = next;
        continue;
      }

      const { buf, truncated } = await readCapped(res.body, bodyLimit);
      return makeResponse({ url: current.toString(), statusCode: res.statusCode, headers: res.headers, body: buf, truncated, redirects });
    }
  }

  return { fetch: fetchOne, assertUrlAllowed, close: () => agent.close() };
}

let defaultClient: ReturnType<typeof createSafeFetch> | undefined;

/** Convenience wrapper with strict defaults (public IPs only, ports 80/443, 5 redirects, 1 MiB body cap). */
export function safeFetch(url: string, opts?: { maxBodyBytes?: number; headers?: Record<string, string> }): Promise<SafeResponse> {
  defaultClient ??= createSafeFetch();
  return defaultClient.fetch(url, opts);
}
