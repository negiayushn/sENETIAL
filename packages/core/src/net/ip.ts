import ipaddr from 'ipaddr.js';

/**
 * Why `unicast` is the ONLY range allowed (rather than a deny-list of known-bad names):
 * ipaddr.js labels every special-purpose block (private, loopback, linkLocal – which covers the cloud
 * metadata IP 169.254.169.254 –, carrierGradeNat, multicast, reserved, broadcast, 6to4, teredo, NAT64 …).
 * A deny-list silently misses any label we forget; an allow-list fails closed.
 *
 * `ipaddr.process` first unwraps IPv4-mapped IPv6 (::ffff:127.0.0.1 -> 127.0.0.1), which a plain
 * `parse().range()` would report as the harmless-looking "ipv4Mapped".
 */
export function blockedReason(ip: string): string | null {
  let addr: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    addr = ipaddr.process(ip.replace(/^\[|\]$/g, ''));
  } catch {
    return 'unparseable'; // fail closed
  }
  const range = addr.range();
  return range === 'unicast' ? null : range;
}

export const isBlockedIp = (ip: string): boolean => blockedReason(ip) !== null;
