import { describe, expect, it } from 'vitest';
import { blockedReason, isBlockedIp } from '../src';

describe('isBlockedIp', () => {
  const blocked: [string, string][] = [
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['10.0.0.5', 'RFC1918'],
    ['172.16.0.1', 'RFC1918'],
    ['172.31.255.255', 'RFC1918'],
    ['192.168.1.1', 'RFC1918'],
    ['169.254.169.254', 'cloud metadata (AWS/GCP/Azure)'],
    ['169.254.0.1', 'link-local'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['0.0.0.0', 'unspecified'],
    ['255.255.255.255', 'broadcast'],
    ['224.0.0.1', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['::1', 'IPv6 loopback'],
    ['::', 'IPv6 unspecified'],
    ['fe80::1', 'IPv6 link-local'],
    ['fd00::1', 'IPv6 unique-local'],
    ['fc00::1', 'IPv6 unique-local'],
    ['ff02::1', 'IPv6 multicast'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
    ['::ffff:169.254.169.254', 'IPv4-mapped metadata'],
    ['::ffff:10.0.0.1', 'IPv4-mapped private'],
    ['[::1]', 'bracketed literal'],
    ['64:ff9b::7f00:1', 'NAT64 wrapping 127.0.0.1'],
    ['2002:7f00:1::', '6to4 wrapping 127.0.0.1'],
    ['fe80::1%eth0', 'zone id'],
    ['not-an-ip', 'garbage fails closed'],
    ['', 'empty fails closed'],
  ];
  it.each(blocked)('blocks %s (%s)', (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  const allowed = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '172.15.255.255', '2606:4700:4700::1111', '2a00:1450:4001:81b::200e'];
  it.each(allowed)('allows public address %s', (ip) => {
    expect(blockedReason(ip)).toBeNull();
  });

  it('reports the range name so logs are useful', () => {
    expect(blockedReason('169.254.169.254')).toBe('linkLocal');
    expect(blockedReason('10.1.2.3')).toBe('private');
  });
});
