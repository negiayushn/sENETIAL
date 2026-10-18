import { describe, expect, it } from 'vitest';
import { BlockedAddressError, createGuard } from '../src';

const lookupAsync = (guard: ReturnType<typeof createGuard>, host: string, opts: object) =>
  new Promise<{ err: Error | null; address: unknown; family?: number }>((resolve) =>
    guard.lookup(host, opts as never, (err, address, family) => resolve({ err, address, family })),
  );

describe('guard.resolveSafe', () => {
  it('rejects when ANY answer is non-public (mixed public + metadata records)', async () => {
    const guard = createGuard({
      resolver: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '169.254.169.254', family: 4 },
      ],
    });
    await expect(guard.resolveSafe('rebind.example')).rejects.toBeInstanceOf(BlockedAddressError);
  });

  it('rejects IPv6-only answers that point inside', async () => {
    const guard = createGuard({ resolver: async () => [{ address: '::ffff:10.0.0.1', family: 6 }] });
    await expect(guard.resolveSafe('x.example')).rejects.toBeInstanceOf(BlockedAddressError);
  });

  it('treats IP literals without calling DNS', async () => {
    let called = false;
    const guard = createGuard({ resolver: async () => ((called = true), []) });
    await expect(guard.resolveSafe('127.0.0.1')).rejects.toBeInstanceOf(BlockedAddressError);
    await expect(guard.resolveSafe('[::1]')).rejects.toBeInstanceOf(BlockedAddressError);
    expect(called).toBe(false);
  });

  it('returns public addresses', async () => {
    const guard = createGuard({ resolver: async () => [{ address: '93.184.216.34', family: 4 }] });
    await expect(guard.resolveSafe('example.com')).resolves.toEqual([{ address: '93.184.216.34', family: 4 }]);
  });
});

describe('guard.lookup (the connect-time hook)', () => {
  const pub = createGuard({
    resolver: async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '2606:2800:220:1::1', family: 6 },
    ],
  });

  it('returns an ARRAY when options.all is set (what autoSelectFamily on Node 20+ expects)', async () => {
    const r = await lookupAsync(pub, 'example.com', { all: true });
    expect(r.err).toBeNull();
    expect(Array.isArray(r.address)).toBe(true);
    expect(r.address).toHaveLength(2);
  });

  it('returns a single address otherwise', async () => {
    const r = await lookupAsync(pub, 'example.com', {});
    expect(r.address).toBe('93.184.216.34');
    expect(r.family).toBe(4);
  });

  it('honours the family hint', async () => {
    const r = await lookupAsync(pub, 'example.com', { family: 6 });
    expect(r.address).toBe('2606:2800:220:1::1');
  });

  it('errors (does not connect) for blocked answers', async () => {
    const bad = createGuard({ resolver: async () => [{ address: '10.0.0.1', family: 4 }] });
    const r = await lookupAsync(bad, 'internal.example', { all: true });
    expect(r.err).toBeInstanceOf(BlockedAddressError);
  });
});
