import { describe, expect, it } from 'vitest';
import { challengeRecordName, challengeRecordValue, checkDnsChallenge, fingerprint, redactEvidence, redactString, redisConnectionFromUrl } from '../src';

describe('checkDnsChallenge', () => {
  const token = 'abc123';
  const ok = challengeRecordValue(token);

  it('builds the record name/value the UI shows', () => {
    expect(challengeRecordName('example.com')).toBe('_sentinel-challenge.example.com');
    expect(ok).toBe('sentinel-verify=abc123');
  });
  it('verifies when the token is present among other TXT records', async () => {
    const r = await checkDnsChallenge('example.com', token, async () => [['v=spf1 -all'], [ok]]);
    expect(r).toEqual({ verified: true });
  });
  it('joins TXT chunks before comparing (long records are split at 255 bytes)', async () => {
    const r = await checkDnsChallenge('example.com', token, async () => [[ok.slice(0, 10), ok.slice(10)]]);
    expect(r.verified).toBe(true);
  });
  it('tolerates quotes pasted into the DNS value', async () => {
    expect((await checkDnsChallenge('example.com', token, async () => [[`"${ok}"`]])).verified).toBe(true);
  });
  it('does not accept a prefix/suffix match', async () => {
    expect((await checkDnsChallenge('example.com', token, async () => [[ok + 'x']])).verified).toBe(false);
    expect((await checkDnsChallenge('example.com', token, async () => [['x' + ok]])).verified).toBe(false);
  });
  it('reports a different token as TOKEN_MISMATCH', async () => {
    const r = await checkDnsChallenge('example.com', token, async () => [['sentinel-verify=other']]);
    expect(r).toEqual({ verified: false, reason: 'TOKEN_MISMATCH' });
  });
  it('maps NXDOMAIN / no-data to NO_RECORD and other failures to DNS_ERROR', async () => {
    const nx = async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }); };
    const nd = async () => { throw Object.assign(new Error('x'), { code: 'ENODATA' }); };
    const to = async () => { throw Object.assign(new Error('x'), { code: 'ETIMEOUT' }); };
    expect(await checkDnsChallenge('e.com', token, nx)).toMatchObject({ reason: 'NO_RECORD' });
    expect(await checkDnsChallenge('e.com', token, nd)).toMatchObject({ reason: 'NO_RECORD' });
    expect(await checkDnsChallenge('e.com', token, to)).toMatchObject({ reason: 'DNS_ERROR', detail: 'ETIMEOUT' });
  });
  it('queries the _sentinel-challenge name', async () => {
    let asked = '';
    await checkDnsChallenge('example.com', token, async (n) => ((asked = n), [[ok]]));
    expect(asked).toBe('_sentinel-challenge.example.com');
  });
});

describe('fingerprint', () => {
  const base = { source: 'WEB' as const, owner: 't1', type: 'headers.csp-missing', key: 'csp' };
  it('is deterministic and hex sha256', () => {
    expect(fingerprint(base)).toBe(fingerprint({ ...base }));
    expect(fingerprint(base)).toMatch(/^[0-9a-f]{64}$/);
  });
  it('changes with every component and cannot be confused by concatenation', () => {
    const f = fingerprint(base);
    expect(fingerprint({ ...base, owner: 't2' })).not.toBe(f);
    expect(fingerprint({ ...base, type: 'x' })).not.toBe(f);
    expect(fingerprint({ ...base, key: 'x' })).not.toBe(f);
    expect(fingerprint({ ...base, source: 'DEPENDENCY' })).not.toBe(f);
    expect(fingerprint({ ...base, owner: 'ab', type: 'c' })).not.toBe(fingerprint({ ...base, owner: 'a', type: 'bc' }));
  });
});

describe('redisConnectionFromUrl', () => {
  it('parses host, port, auth, db, tls', () => {
    expect(redisConnectionFromUrl('redis://localhost:6379')).toMatchObject({ host: 'localhost', port: 6379 });
    expect(redisConnectionFromUrl('rediss://u:p%40ss@h:6380/2')).toEqual({ host: 'h', port: 6380, username: 'u', password: 'p@ss', db: 2, tls: {} });
  });
});

describe('redaction', () => {
  it('masks values under sensitive keys but keeps names', () => {
    const out = redactEvidence({ cookieName: 'sessionid', tokenType: 'bearer', value: 'abc', setCookie: 'x', 'set-cookie': 'a=b', authorization: 'Bearer zzzzzzzz', csrfToken: 't0k3n', apiKey: 'k', password: 'p', header: 'server', note: 'fine' });
    expect(out).toMatchObject({ cookieName: 'sessionid', tokenType: 'bearer', setCookie: '[REDACTED]', header: 'server', note: 'fine', value: '[REDACTED]', 'set-cookie': '[REDACTED]', authorization: '[REDACTED]', csrfToken: '[REDACTED]', apiKey: '[REDACTED]', password: '[REDACTED]' });
  });
  it('scrubs secrets that appear inside free text', () => {
    expect(redactString('Set-Cookie: sid=9f8e7d6c5b4a; Path=/; HttpOnly')).toBe('Set-Cookie: sid=[REDACTED]; Path=/; HttpOnly');
    expect(redactString('Authorization: Bearer abcdefghijklmnop')).toContain('Bearer [REDACTED]');
    expect(redactString('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')).toContain('[REDACTED:jwt]');
    expect(redactString('DATABASE_URL=postgres://admin:hunter2@db.internal:5432/app')).not.toContain('hunter2');
    expect(redactString('API_SECRET=supersecretvalue')).toBe('API_SECRET=[REDACTED]');
    expect(redactString('key AKIAIOSFODNN7EXAMPLE here')).toContain('[REDACTED:aws-key-id]');
    expect(redactString('ghp_abcdefghijklmnopqrstuvwxyz0123456789')).toContain('[REDACTED:github-token]');
  });
  it('recurses, bounds size, and never lets non-JSON values through', () => {
    const big = 'a'.repeat(2000);
    const out = redactEvidence({ nested: { list: [{ token: 'x', ok: 1 }], big }, fn: 1n as unknown }) as any;
    expect(out.nested.list[0]).toEqual({ token: '[REDACTED]', ok: 1 });
    expect(out.nested.big.length).toBeLessThan(600);
    expect(typeof out.fn).toBe('string');
  });
  it('leaves ordinary evidence untouched', () => {
    const ev = { header: 'content-security-policy', present: false, status: 200, url: 'https://example.com/' };
    expect(redactEvidence(ev)).toEqual(ev);
  });
});
