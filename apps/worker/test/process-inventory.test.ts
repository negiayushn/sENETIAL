import type { LockfileFetch } from '@sentinel/github';
import { GithubFetchError } from '@sentinel/github';
import { PrismaClient, prismaClientOptions } from '@sentinel/db';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { processInventory, type InventoryDeps } from '../src/process-inventory';

const url = process.env.DATABASE_URL;
const prisma = url ? new PrismaClient(prismaClientOptions(url)) : (null as unknown as PrismaClient);
const log = { info: () => undefined, warn: () => undefined, error: () => undefined };
const LAST = { isLastAttempt: true };
const NOT_LAST = { isLastAttempt: false };

const repoMeta = { fullName: 'acme/app', defaultBranch: 'main', archived: false, private: true };
const lockText = (n = 3) => JSON.stringify({
  lockfileVersion: 3,
  packages: { '': {}, ...Object.fromEntries(Array.from({ length: n }, (_, i) => [`node_modules/pkg${i}`, { version: '1.0.0', dev: i === 2 }])), 'node_modules/pkg0/node_modules/inner': { version: '2.0.0' } },
});
const found = (sha: string, text = lockText(), pkg = '{"dependencies":{"pkg0":"^1"},"devDependencies":{"pkg2":"^1"}}'): LockfileFetch =>
  ({ kind: 'found', repo: repoMeta, commitSha: sha, branch: 'main', path: 'package-lock.json', lockfileText: text, packageJsonText: pkg });

let userId = '';
let installationRowId = '';
async function newRepo(over: object = {}) {
  return prisma.repository.create({ data: { userId, installationId: installationRowId, githubRepoId: String(Math.random()).slice(2, 10), owner: 'acme', name: 'app', fullName: 'acme/app', defaultBranch: 'main', ...over } });
}
const deps = (fetchLockfile: InventoryDeps['fetchLockfile'], extra: Partial<InventoryDeps> = {}): InventoryDeps => ({ prisma, log, fetchLockfile, ...extra });

describe.skipIf(!url)('processInventory (real database)', () => {
  beforeAll(async () => {
    const u = await prisma.user.create({ data: { id: `inv_${Date.now()}`, name: 'Inv', email: `inv${Date.now()}@example.com` } });
    userId = u.id;
    installationRowId = (await prisma.githubInstallation.create({ data: { userId, installationId: String(Date.now()), accountLogin: 'acme', accountType: 'Organization', repositorySelection: 'all' } })).id;
  });
  afterAll(async () => {
    await prisma.user.delete({ where: { id: userId } }); // cascades installation → repositories → snapshots → instances
    await prisma.$disconnect();
  });

  it('stores a snapshot keyed by commit SHA with correctly flagged package instances', async () => {
    const repo = await newRepo();
    await processInventory(repo.id, deps(async () => found('sha-1')), LAST);
    const snap = await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id }, include: { instances: true } });
    expect(snap).toMatchObject({ commitSha: 'sha-1', branch: 'main', lockfilePath: 'package-lock.json', lockfileVersion: 3, packageCount: 4, directCount: 2 });
    const by = (name: string) => snap.instances.find((i) => i.name === name)!;
    expect(by('pkg0')).toMatchObject({ direct: true, dev: false, version: '1.0.0', path: 'node_modules/pkg0', source: 'registry' });
    expect(by('pkg2')).toMatchObject({ direct: true, dev: true });
    expect(by('pkg1')).toMatchObject({ direct: false });
    expect(by('inner')).toMatchObject({ direct: false, path: 'node_modules/pkg0/node_modules/inner' });
    const after = await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } });
    expect(after).toMatchObject({ inventoryStatus: 'SUCCEEDED', inventoryError: null, lastInventorySha: 'sha-1' });
    expect(after.lastInventoryAt).toBeTruthy();
  });

  it('is idempotent for the same commit (no duplicate snapshot, instances untouched)', async () => {
    const repo = await newRepo();
    const fetch = vi.fn(async () => found('same'));
    await processInventory(repo.id, deps(fetch), LAST);
    await processInventory(repo.id, deps(fetch), LAST);
    expect(await prisma.dependencySnapshot.count({ where: { repositoryId: repo.id } })).toBe(1);
    expect(await prisma.packageInstance.count({ where: { snapshot: { repositoryId: repo.id } } })).toBe(4);
  });

  it('a new commit adds a snapshot; only the newest N are kept', async () => {
    const repo = await newRepo();
    for (const sha of ['c1', 'c2', 'c3', 'c4']) {
      await processInventory(repo.id, deps(async () => found(sha), { keepSnapshots: 2 }), LAST);
      await new Promise((r) => setTimeout(r, 15)); // distinct createdAt
    }
    const shas = (await prisma.dependencySnapshot.findMany({ where: { repositoryId: repo.id }, orderBy: { createdAt: 'desc' } })).map((s) => s.commitSha);
    expect(shas).toEqual(['c4', 'c3']);
    expect(await prisma.packageInstance.count({ where: { snapshot: { repositoryId: repo.id } } })).toBe(8); // pruned snapshots' instances cascade away
  });

  it('inserts a large lockfile (6 000 packages) in one transaction', async () => {
    const repo = await newRepo();
    await processInventory(repo.id, deps(async () => found('big', lockText(6000))), LAST);
    expect((await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id } })).packageCount).toBe(6001);
    expect(await prisma.packageInstance.count({ where: { snapshot: { repositoryId: repo.id } } })).toBe(6001);
  });

  it('records NO_LOCKFILE with the reason (yarn.lock, empty repo) instead of failing', async () => {
    const a = await newRepo();
    await processInventory(a.id, deps(async () => ({ kind: 'none', repo: repoMeta, commitSha: 'y1', branch: 'main', note: 'Found yarn.lock, which is not supported yet.' })), LAST);
    expect(await prisma.repository.findUniqueOrThrow({ where: { id: a.id } })).toMatchObject({ inventoryStatus: 'NO_LOCKFILE', inventoryError: expect.stringContaining('yarn.lock'), lastInventorySha: 'y1' });
    const b = await newRepo();
    await processInventory(b.id, deps(async () => ({ kind: 'empty', repo: repoMeta })), LAST);
    expect(await prisma.repository.findUniqueOrThrow({ where: { id: b.id } })).toMatchObject({ inventoryStatus: 'NO_LOCKFILE', inventoryError: 'The repository is empty.' });
  });

  it('refreshes repository metadata (rename/archive) from GitHub', async () => {
    const repo = await newRepo();
    await processInventory(repo.id, deps(async () => ({ ...found('m1'), repo: { fullName: 'acme/renamed', defaultBranch: 'trunk', archived: true, private: false } })), LAST);
    expect(await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } })).toMatchObject({ fullName: 'acme/renamed', owner: 'acme', name: 'renamed', defaultBranch: 'trunk', archived: true, private: false });
  });

  it('an unparseable lockfile is FAILED with a safe message, no retry, no partial snapshot', async () => {
    const repo = await newRepo();
    await expect(processInventory(repo.id, deps(async () => found('bad', 'not json')), NOT_LAST)).resolves.toBeUndefined();
    const after = await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } });
    expect(after).toMatchObject({ inventoryStatus: 'FAILED', inventoryError: expect.stringContaining('could not be read') });
    expect(await prisma.dependencySnapshot.count({ where: { repositoryId: repo.id } })).toBe(0);
  });

  it('transient GitHub error: QUEUED + rethrow while attempts remain, FAILED + rethrow on the last', async () => {
    const repo = await newRepo();
    const boom = async (): Promise<LockfileFetch> => { throw Object.assign(new Error('secret upstream detail 10.0.0.5'), { status: 502 }); };
    await expect(processInventory(repo.id, deps(boom), NOT_LAST)).rejects.toThrow();
    expect(await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } })).toMatchObject({ inventoryStatus: 'QUEUED', inventoryError: expect.stringContaining('temporarily unavailable') });
    await expect(processInventory(repo.id, deps(boom), LAST)).rejects.toThrow();
    const after = await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } });
    expect(after.inventoryStatus).toBe('FAILED');
    expect(after.inventoryError).not.toMatch(/10\.0\.0\.5|secret/); // raw upstream text never reaches the user
  });

  it.each([
    [404, /no longer access/],
    [401, /denied access/],
    [403, /denied access/],
  ])('permanent GitHub error %i: FAILED immediately, job completes (no retry storm)', async (status, msg) => {
    const repo = await newRepo();
    await expect(processInventory(repo.id, deps(async () => { throw Object.assign(new Error('x'), { status }); }), NOT_LAST)).resolves.toBeUndefined();
    expect(await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } })).toMatchObject({ inventoryStatus: 'FAILED', inventoryError: expect.stringMatching(msg) });
  });

  it('an oversized lockfile surfaces its own safe message', async () => {
    const repo = await newRepo();
    await processInventory(repo.id, deps(async () => { throw new GithubFetchError('package-lock.json is larger than 25 MiB', false); }), LAST);
    expect(await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } })).toMatchObject({ inventoryStatus: 'FAILED', inventoryError: 'package-lock.json is larger than 25 MiB' });
  });

  it('never fetches for a suspended installation', async () => {
    const inst = await prisma.githubInstallation.create({ data: { userId, installationId: `s${Date.now()}`, accountLogin: 's', accountType: 'User', repositorySelection: 'all', suspendedAt: new Date() } });
    const repo = await newRepo({ installationId: inst.id });
    const fetch = vi.fn(async () => found('x'));
    await processInventory(repo.id, deps(fetch), LAST);
    expect(fetch).not.toHaveBeenCalled();
    expect((await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } })).inventoryStatus).toBe('FAILED');
  });

  it('passes the GitHub installation id and repo id (not tokens) to the fetcher; drops jobs for unknown repos', async () => {
    const repo = await newRepo();
    const inst = await prisma.githubInstallation.findUniqueOrThrow({ where: { id: installationRowId } });
    const fetch = vi.fn(async () => found('p1'));
    await processInventory(repo.id, deps(fetch), LAST);
    expect(fetch).toHaveBeenCalledWith({ id: repo.id, githubRepoId: repo.githubRepoId, installationId: inst.installationId });
    await expect(processInventory('nope', deps(fetch), LAST)).resolves.toBeUndefined();
  });
});
