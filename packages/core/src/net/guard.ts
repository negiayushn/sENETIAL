import dns from 'node:dns/promises';
import net, { type LookupFunction } from 'node:net';
import { blockedReason } from './ip';

export class SsrfError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = 'SsrfError';
  }
}

export class BlockedAddressError extends SsrfError {
  constructor(readonly hostname: string, readonly address: string, readonly reason: string) {
    super(`Blocked address ${address} (${reason}) for host ${hostname}`, 'BLOCKED_ADDRESS');
    this.name = 'BlockedAddressError';
  }
}

export class UnsafeUrlError extends SsrfError {
  constructor(message: string) {
    super(message, 'UNSAFE_URL');
    this.name = 'UnsafeUrlError';
  }
}

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface GuardOptions {
  /** Replace DNS (tests). Production uses the system resolver via dns.lookup. */
  resolver?: (hostname: string) => Promise<ResolvedAddress[]>;
  /**
   * TEST SEAM ONLY: lets unit tests talk to a loopback server. Nothing in the app or worker passes this,
   * and it is deliberately not reachable from env/config.
   */
  blockedReason?: (ip: string) => string | null;
}

export interface Guard {
  /** Resolve `hostname` and throw BlockedAddressError if ANY returned address is non-public. */
  resolveSafe(hostname: string): Promise<ResolvedAddress[]>;
  /** Check a literal IP (Node never calls `lookup` for IP literals, so URLs with IPs need this). */
  assertIpAllowed(ip: string, hostname?: string): void;
  /** Drop-in `connect.lookup` for undici / net / tls. Validates and pins in a single resolution. */
  lookup: LookupFunction;
}

const stripBrackets = (h: string) => h.replace(/^\[|\]$/g, '');

async function systemResolver(hostname: string): Promise<ResolvedAddress[]> {
  const addrs = await dns.lookup(hostname, { all: true, verbatim: true });
  return addrs.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
}

export function createGuard(opts: GuardOptions = {}): Guard {
  const resolver = opts.resolver ?? systemResolver;
  const reasonFor = opts.blockedReason ?? blockedReason;

  const assertIpAllowed = (ip: string, hostname = ip) => {
    const reason = reasonFor(ip);
    if (reason) throw new BlockedAddressError(hostname, ip, reason);
  };

  const resolveSafe = async (hostname: string): Promise<ResolvedAddress[]> => {
    const host = stripBrackets(hostname);
    const literal = net.isIP(host);
    const addrs: ResolvedAddress[] = literal ? [{ address: host, family: literal === 6 ? 6 : 4 }] : await resolver(host);
    if (addrs.length === 0) throw Object.assign(new Error(`ENOTFOUND ${host}`), { code: 'ENOTFOUND' });
    // Reject if ANY record is bad. Otherwise an attacker publishes [public, 169.254.169.254] and hopes we pick wrong.
    for (const a of addrs) assertIpAllowed(a.address, host);
    return addrs;
  };

  const lookup: LookupFunction = (hostname, options, callback) => {
    resolveSafe(hostname).then(
      (addrs) => {
        // Node 20+ (autoSelectFamily / happy eyeballs) calls lookup with { all: true } and expects an ARRAY.
        const want = options.family === 4 || options.family === 'IPv4' ? 4 : options.family === 6 || options.family === 'IPv6' ? 6 : 0;
        const usable = want ? addrs.filter((a) => a.family === want) : addrs;
        if (usable.length === 0) return callback(Object.assign(new Error(`ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' }) as NodeJS.ErrnoException, '', 0);
        if (options.all) return callback(null, usable);
        callback(null, usable[0].address, usable[0].family);
      },
      (err: NodeJS.ErrnoException) => callback(err, '', 0),
    );
  };

  return { resolveSafe, assertIpAllowed, lookup };
}
