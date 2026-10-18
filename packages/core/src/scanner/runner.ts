import { createGuard, SsrfError, type Guard } from '../net/guard';
import { RateLimiter } from '../net/rate-limiter';
import { createSafeFetch, type SafeFetchConfig } from '../net/safe-fetch';
import { defaultChecks } from './default-checks';
import { createScanContext } from './context';
import type { Check, ScanContext, ScanFinding } from './types';

export interface CheckResult {
  id: string;
  status: 'ok' | 'error';
  findings: number;
  durationMs: number;
  error?: string;
}

export interface ScanResult {
  findings: ScanFinding[];
  checks: CheckResult[];
  requests: number;
}

export interface RunScanOptions {
  hostname: string;
  checks?: Check[];
  guard?: Guard;
  limiter?: RateLimiter;
  /** Overrides for the safe client (tests). allowedHosts/beforeRequest are always set by the runner. */
  http?: Omit<SafeFetchConfig, 'allowedHosts' | 'beforeRequest' | 'guard'>;
  /** Whole-scan wall clock. Checks that have not started when it expires are reported as errors. */
  deadlineMs?: number;
  checkTimeoutMs?: number;
  /** Test seams (never set in production) */
  contextOverride?: (ctx: ScanContext) => ScanContext;
  rootUrls?: string[];
  tlsPort?: number;
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e)).slice(0, 300);

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let t: NodeJS.Timeout;
  const timeout = new Promise<never>((_, rej) => (t = setTimeout(() => rej(new Error(`${label} timed out after ${ms}ms`)), ms)));
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

/**
 * Runs every check against ONE hostname. The caller (worker) has already established that the target is verified.
 *
 * - The hostname is resolved through the SSRF guard up front: a target that points at a non-public address
 *   aborts the whole scan with an SsrfError instead of producing 5 identical per-check errors.
 * - A check that throws does not stop the others; it is recorded as status "error".
 */
export async function runScan(opts: RunScanOptions): Promise<ScanResult> {
  const guard = opts.guard ?? createGuard();
  const limiter = opts.limiter ?? new RateLimiter();
  const checks = opts.checks ?? defaultChecks();
  const deadlineAt = Date.now() + (opts.deadlineMs ?? 4 * 60_000);
  const checkTimeout = opts.checkTimeoutMs ?? 90_000;

  await guard.resolveSafe(opts.hostname); // throws BlockedAddressError / ENOTFOUND

  const http = createSafeFetch({
    ...opts.http,
    guard,
    allowedHosts: [opts.hostname], // redirects may never leave the verified hostname
    beforeRequest: () => limiter.acquire(),
  });

  let ctx = createScanContext({ hostname: opts.hostname, guard, http, limiter, rootUrls: opts.rootUrls, tlsPort: opts.tlsPort });
  if (opts.contextOverride) ctx = opts.contextOverride(ctx);

  const seen = new Set<string>();
  const findings: ScanFinding[] = [];
  const results: CheckResult[] = [];

  try {
    for (const check of checks) {
      const started = Date.now();
      if (started >= deadlineAt) {
        results.push({ id: check.id, status: 'error', findings: 0, durationMs: 0, error: 'Scan deadline reached before this check ran' });
        continue;
      }
      try {
        const found = await withTimeout(check.run(ctx), checkTimeout, `Check "${check.id}"`);
        let kept = 0;
        for (const f of found) {
          const id = `${f.type}\u0000${f.key}`;
          if (seen.has(id)) continue; // one finding per (type, key) per scan
          seen.add(id);
          findings.push(f);
          kept++;
        }
        results.push({ id: check.id, status: 'ok', findings: kept, durationMs: Date.now() - started });
      } catch (err) {
        results.push({
          id: check.id,
          status: 'error',
          findings: 0,
          durationMs: Date.now() - started,
          error: err instanceof SsrfError ? `Blocked: ${err.message}` : msg(err),
        });
      }
    }
  } finally {
    await http.close();
  }

  return { findings, checks: results, requests: limiter.requestCount };
}
