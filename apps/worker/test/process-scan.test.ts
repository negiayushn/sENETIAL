import { BlockedAddressError, fingerprint, type ScanResult } from '@sentinel/core';
import { PrismaClient, prismaClientOptions } from '@sentinel/db';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { NOT_VERIFIED_MESSAGE, processScan } from '../src/process-scan';

const url = process.env.DATABASE_URL;
const prisma = url ? new PrismaClient(prismaClientOptions(url)) : (null as unknown as PrismaClient);
const log = { info: () => undefined, warn: () => undefined, error: () => undefined };
const released: string[] = [];
const releaseLock = async (_t: string, scanId: string) => void released.push(scanId);

const result = (over: Partial<ScanResult> = {}): ScanResult => ({
  requests: 5,
  checks: [{ id: 'headers', status: 'ok', findings: 1, durationMs: 1 }],
  findings: [{ type: 'headers.csp-missing', key: 'csp', title: 'CSP missing', severity: 'MEDIUM', confidence: 'CONFIRMED', evidence: { header: 'csp' }, remediation: 'fix' }],
  ...over,
});

let userId = '';
async function setup(status: 'PENDING' | 'VERIFIED') {
  const target = await prisma.target.create({ data: { userId, hostname: `t${Math.random().toString(36).slice(2)}.example.com`, verifyToken: 'x', status } });
  const scan = await prisma.scan.create({ data: { userId, targetId: target.id } });
  return { target, scan };
}

describe.skipIf(!url)('processScan (real database)', () => {
  beforeAll(async () => {
    const u = await prisma.user.create({ data: { id: `u_${Date.now()}`, name: 'Test', email: `t${Date.now()}@example.com` } });
    userId = u.id;
  });
  afterAll(async () => {
    await prisma.user.delete({ where: { id: userId } }); // cascades targets, scans, findings via targets
    await prisma.$disconnect();
  });
  beforeEach(() => void (released.length = 0));

  it('REFUSES an unverified target: never calls the scanner, records FAILED', async () => {
    const { scan } = await setup('PENDING');
    const run = vi.fn(async () => result());
    await processScan(scan.id, { prisma, log, releaseLock, run });
    expect(run).not.toHaveBeenCalled();
    const after = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
    expect(after).toMatchObject({ status: 'FAILED', error: NOT_VERIFIED_MESSAGE });
    expect(released).toEqual([scan.id]);
  });

  it('refuses when the scan owner differs from the target owner', async () => {
    const { scan } = await setup('VERIFIED');
    const other = await prisma.user.create({ data: { id: `o_${Date.now()}`, name: 'O', email: `o${Date.now()}@example.com` } });
    await prisma.scan.update({ where: { id: scan.id }, data: { userId: other.id } });
    const run = vi.fn(async () => result());
    await processScan(scan.id, { prisma, log, releaseLock, run });
    expect(run).not.toHaveBeenCalled();
    expect((await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } })).status).toBe('FAILED');
    await prisma.user.delete({ where: { id: other.id } });
  });

  it('runs a verified target, stores findings with a fingerprint, marks SUCCEEDED', async () => {
    const { scan, target } = await setup('VERIFIED');
    const run = vi.fn(async () => result());
    await processScan(scan.id, { prisma, log, releaseLock, run });
    expect(run).toHaveBeenCalledWith(target.hostname);
    const after = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
    expect(after.status).toBe('SUCCEEDED');
    expect(after.startedAt && after.finishedAt).toBeTruthy();
    const f = await prisma.finding.findMany({ where: { targetId: target.id } });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ source: 'WEB', status: 'OPEN', userId, lastScanId: scan.id, fingerprint: fingerprint({ source: 'WEB', owner: target.id, type: 'headers.csp-missing', key: 'csp' }) });
    expect(released).toEqual([scan.id]);
  });

  it('upserts: a second scan updates the same row, keeps firstSeenAt and the user’s triage status, reopens FIXED', async () => {
    const { scan, target } = await setup('VERIFIED');
    await processScan(scan.id, { prisma, log, releaseLock, run: async () => result() });
    const first = await prisma.finding.findFirstOrThrow({ where: { targetId: target.id } });
    await prisma.finding.update({ where: { id: first.id }, data: { status: 'ACKNOWLEDGED' } });

    const scan2 = await prisma.scan.create({ data: { userId, targetId: target.id } });
    await processScan(scan2.id, { prisma, log, releaseLock, run: async () => result({ findings: [{ ...result().findings[0], title: 'CSP still missing', severity: 'LOW' }] }) });
    const second = await prisma.finding.findMany({ where: { targetId: target.id } });
    expect(second).toHaveLength(1); // no duplicate
    expect(second[0]).toMatchObject({ id: first.id, status: 'ACKNOWLEDGED', title: 'CSP still missing', severity: 'LOW', lastScanId: scan2.id });
    expect(second[0].firstSeenAt).toEqual(first.firstSeenAt);
    expect(second[0].lastSeenAt.getTime()).toBeGreaterThan(first.lastSeenAt.getTime() - 1);

    await prisma.finding.update({ where: { id: first.id }, data: { status: 'FIXED' } });
    const scan3 = await prisma.scan.create({ data: { userId, targetId: target.id } });
    await processScan(scan3.id, { prisma, log, releaseLock, run: async () => result() });
    expect((await prisma.finding.findUniqueOrThrow({ where: { id: first.id } })).status).toBe('REOPENED');
  });

  it('redacts secrets in evidence before saving', async () => {
    const { scan, target } = await setup('VERIFIED');
    const evidence = { cookieName: 'sid', value: 'LIVE-SESSION-VALUE', note: 'Set-Cookie: sid=LIVE-SESSION-VALUE; Path=/', authorization: 'Bearer abcdefghijkl' };
    await processScan(scan.id, { prisma, log, releaseLock, run: async () => result({ findings: [{ ...result().findings[0], evidence }] }) });
    const f = await prisma.finding.findFirstOrThrow({ where: { targetId: target.id } });
    expect(JSON.stringify(f.evidence)).not.toMatch(/LIVE-SESSION-VALUE|abcdefghijkl/);
    expect((f.evidence as any).cookieName).toBe('sid');
  });

  it('a scan where EVERY check errored is FAILED (with the reason), not a clean SUCCEEDED', async () => {
    const { scan, target } = await setup('VERIFIED');
    await processScan(scan.id, { prisma, log, releaseLock, run: async () => result({ findings: [], checks: [{ id: 'tls', status: 'error', findings: 0, durationMs: 1, error: 'Could not reach host' }] }) });
    expect(await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } })).toMatchObject({ status: 'FAILED', error: 'Could not reach host' });
    expect(await prisma.finding.count({ where: { targetId: target.id } })).toBe(0);
  });

  it('partial success (some checks errored) is SUCCEEDED and flagged partial', async () => {
    const { scan } = await setup('VERIFIED');
    await processScan(scan.id, { prisma, log, releaseLock, run: async () => result({ checks: [{ id: 'a', status: 'ok', findings: 1, durationMs: 1 }, { id: 'b', status: 'error', findings: 0, durationMs: 1, error: 'x' }] }) });
    const s = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
    expect(s.status).toBe('SUCCEEDED');
    expect((s.summary as any).partial).toBe(true);
  });

  it('a blocked address is a FAILED scan with a safe message that does not leak the IP; lock still released', async () => {
    const { scan } = await setup('VERIFIED');
    await expect(processScan(scan.id, { prisma, log, releaseLock, run: async () => { throw new BlockedAddressError('h', '10.1.2.3', 'private'); } })).rejects.toThrow();
    const s = await prisma.scan.findUniqueOrThrow({ where: { id: scan.id } });
    expect(s.status).toBe('FAILED');
    expect(s.error).not.toContain('10.1.2.3');
    expect(released).toEqual([scan.id]);
  });

  it('ignores a duplicate delivery of a finished scan', async () => {
    const { scan } = await setup('VERIFIED');
    await processScan(scan.id, { prisma, log, releaseLock, run: async () => result() });
    const run = vi.fn(async () => result());
    await processScan(scan.id, { prisma, log, releaseLock, run });
    expect(run).not.toHaveBeenCalled();
  });

  it('drops a job whose scan no longer exists', async () => {
    await expect(processScan('does-not-exist', { prisma, log, releaseLock })).resolves.toBeUndefined();
  });
});
