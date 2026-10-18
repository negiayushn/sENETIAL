import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { blockedReason, createGuard, type ResolvedAddress } from '../src';

export type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

export async function startServer(handler: Handler): Promise<{ port: number; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

/**
 * A guard for tests: fake DNS, and loopback is allowed so we can talk to a local server.
 * Everything else uses the REAL classifier (so 169.254.169.254, 10.x, ::1-via-name etc. stay blocked).
 */
export function testGuard(dnsTable: Record<string, ResolvedAddress[]>, calls?: string[]) {
  return createGuard({
    resolver: async (host) => {
      calls?.push(host);
      const rec = dnsTable[host];
      if (!rec) throw Object.assign(new Error(`ENOTFOUND ${host}`), { code: 'ENOTFOUND' });
      return rec;
    },
    blockedReason: (ip) => (ip === '127.0.0.1' ? null : blockedReason(ip)),
  });
}

export const LOOPBACK: ResolvedAddress[] = [{ address: '127.0.0.1', family: 4 }];
