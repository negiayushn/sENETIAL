import { randomBytes } from 'node:crypto';
import type { Guard } from '../net/guard';
import { SsrfError } from '../net/guard';
import type { RateLimiter } from '../net/rate-limiter';
import type { SafeResponse } from '../net/safe-fetch';
import { tlsProbe as realTlsProbe, type TlsProbeOptions, type TlsProbeResult } from '../net/tls-probe';
import type { ScanContext } from './types';

export interface ContextDeps {
  hostname: string;
  guard: Guard;
  /** An already-configured safe client (allowedHosts = [hostname], rate-limiter hook, …). */
  http: { fetch(url: string, opts?: { maxBodyBytes?: number }): Promise<SafeResponse> };
  limiter: RateLimiter;
  now?: () => Date;
  /** Test seams */
  tlsProbeImpl?: (o: TlsProbeOptions) => Promise<TlsProbeResult>;
  tlsPort?: number;
  /** Test seam: candidate root URLs, tried in order. Default: https://host/ then http://host/ */
  rootUrls?: string[];
}

const PROBE_BODY_LIMIT = 256 * 1024;

export function createScanContext(deps: ContextDeps): ScanContext {
  const { hostname, guard, http, limiter } = deps;
  const probe = deps.tlsProbeImpl ?? realTlsProbe;
  const cache = new Map<string, Promise<SafeResponse>>();
  let rootPromise: Promise<SafeResponse> | undefined;

  const getRoot = () => {
    rootPromise ??= (async () => {
      const [first, second] = deps.rootUrls ?? [`https://${hostname}/`, `http://${hostname}/`];
      try {
        return await http.fetch(first);
      } catch (httpsErr) {
        if (httpsErr instanceof SsrfError || !second) throw httpsErr; // never "retry" a blocked destination over another scheme
        try {
          return await http.fetch(second);
        } catch (httpErr) {
          if (httpErr instanceof SsrfError) throw httpErr;
          throw new Error(`Could not reach ${hostname} over HTTPS (${(httpsErr as Error).message}) or HTTP (${(httpErr as Error).message})`);
        }
      }
    })();
    return rootPromise;
  };

  const origin = async () => new URL((await getRoot()).url).origin;

  const get = (path: string) => {
    if (path === '/') return getRoot();
    let p = cache.get(path);
    if (!p) {
      p = origin().then((o) => http.fetch(`${o}${path}`, { maxBodyBytes: PROBE_BODY_LIMIT }));
      cache.set(path, p);
    }
    return p;
  };

  return {
    hostname,
    notFoundPath: `/sentinel-probe-${randomBytes(4).toString('hex')}`,
    now: deps.now ?? (() => new Date()),
    origin,
    getRoot,
    get,
    async tlsProbe(opts = {}) {
      await limiter.acquire();
      return probe({ hostname, guard, port: deps.tlsPort, ...opts });
    },
  };
}
