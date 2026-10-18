import { fingerprint, OsvError, parseNpmLock } from '@sentinel/core';
import { PrismaClient, prismaClientOptions } from '@sentinel/db';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildRemediation, FINDING_TYPE, processMatch, type MatchDeps } from '../src/process-match';
import { labelOnly, lodashCmdInjection, lodashZipObjectDeep, minimistProto } from './fixtures-osv';

const url = process.env.DATABASE_URL;
const prisma = url ? new PrismaClient(prismaClientOptions(url)) : (null as unknown as PrismaClient);
const log = { info: () => undefined, warn: () => undefined, error: () => undefined };
const LAST = { isLastAttempt: true };
const NOT_LAST = { isLastAttempt: false };

type Ref = { id: string; modified?: string | null };
function fakeOsv(hits: Record<string, Ref[]>, vulns: Record<string, unknown | null>) {
  const calls = { queryBatch: [] as string[][], getVulns: [] as string[][] };
  const osv: MatchDeps['osv'] = {
    async queryBatch(pairs) {
      calls.queryBatch.push(pairs.map((p) => `${p.name}@${p.version}`));
      const m = new Map();
      for (const p of pairs) { const h = hits[`${p.name}@${p.version}`]; if (h) m.set(`${p.name}@${p.version}`, h.map((x) => ({ id: x.id, modified: x.modified ?? null }))); }
      return m;
    },
    async getVulns(ids) { calls.getVulns.push([...ids]); return new Map(ids.map((id) => [id, vulns[id] ?? null])); },
  };
  return { osv, calls };
}

const lock = (pkgs: Record<string, object>) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...pkgs } });
const rootPkg = (deps: string[], dev: string[] = []) => JSON.stringify({ dependencies: Object.fromEntries(deps.map((d) => [d, '*'])), devDependencies: Object.fromEntries(dev.map((d) => [d, '*'])) });
const BASE = lock({
  'node_modules/lodash': { version: '4.17.20', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' },
  'node_modules/mkdirp': { version: '0.5.1', dependencies: { minimist: '0.0.8' } },
  'node_modules/minimist': { version: '0.0.8' },
});
const BASE_PKG = rootPkg(['lodash', 'mkdirp']);

let userId = '';
let installationId = '';
async function newRepo() {
  return prisma.repository.create({ data: { userId, installationId, githubRepoId: String(Math.random()).slice(2, 10), owner: 'acme', name: 'app', fullName: 'acme/app', defaultBranch: 'main' } });
}
let seq = 0;
async function snapshot(repositoryId: string, lockText: string, pkgJson: string, sha = `sha${++seq}`) {
  const parsed = parseNpmLock(lockText, { packageJson: pkgJson });
  await new Promise((r) => setTimeout(r, 5));
  return prisma.dependencySnapshot.create({
    data: {
      repositoryId, commitSha: sha, branch: 'main', lockfilePath: 'package-lock.json', lockfileVersion: 3, packageCount: parsed.packages.length, directCount: parsed.directCount,
      instances: { create: parsed.packages },
    },
  });
}
const findings = (repositoryId: string) => prisma.finding.findMany({ where: { repositoryId }, orderBy: { title: 'asc' } });
const ev = (f: { evidence: unknown }) => f.evidence as any;

describe.skipIf(!url)('processMatch (real database, fake OSV)', () => {
  beforeAll(async () => {
    const u = await prisma.user.create({ data: { id: `m_${Date.now()}`, name: 'M', email: `m${Date.now()}@example.com` } });
    userId = u.id;
    installationId = (await prisma.githubInstallation.create({ data: { userId, installationId: String(Date.now()), accountLogin: 'acme', accountType: 'User', repositorySelection: 'all' } })).id;
  });
  afterAll(async () => {
    await prisma.user.delete({ where: { id: userId } });
    await prisma.advisory.deleteMany({ where: { id: { in: [lodashCmdInjection.id, lodashZipObjectDeep.id, minimistProto.id, labelOnly.id, 'GHSA-withdrawn', 'GHSA-gone'] } } });
    await prisma.$disconnect();
  });

  const hitsFor = { 'lodash@4.17.20': [{ id: lodashCmdInjection.id, modified: lodashCmdInjection.modified }], 'minimist@0.0.8': [{ id: minimistProto.id, modified: minimistProto.modified }] };
  const vulnsFor = { [lodashCmdInjection.id]: lodashCmdInjection, [minimistProto.id]: minimistProto };

  it('creates findings with severity from CVSS, a fix version, and the path to the direct parent', async () => {
    const repo = await newRepo();
    const snap = await snapshot(repo.id, BASE, BASE_PKG);
    const { osv } = fakeOsv(hitsFor, vulnsFor);
    await processMatch(repo.id, { prisma, log, osv }, LAST);

    const fs = await findings(repo.id);
    expect(fs).toHaveLength(2);
    const lodash = fs.find((f) => ev(f).package === 'lodash')!;
    expect(lodash).toMatchObject({ source: 'DEPENDENCY', type: FINDING_TYPE, severity: 'HIGH', confidence: 'CONFIRMED', status: 'OPEN', userId, repositoryId: repo.id, targetId: null });
    expect(lodash.fingerprint).toBe(fingerprint({ source: 'DEPENDENCY', owner: repo.id, type: FINDING_TYPE, key: `${lodashCmdInjection.id}|lodash` }));
    expect(lodash.title).toBe('lodash@4.17.20: Command Injection in lodash');
    expect(lodash.remediation).toBe('Upgrade lodash to 4.17.21 or later (npm install lodash@4.17.21).');
    expect(ev(lodash)).toMatchObject({ direct: true, fixedVersion: '4.17.21', severity: { source: 'cvss', cvssScore: 7.2 }, matcher: 'confirmed', commitSha: snap.commitSha, advisory: { id: lodashCmdInjection.id, aliases: ['CVE-2021-23337'] } });

    const mini = fs.find((f) => ev(f).package === 'minimist')!;
    expect(mini).toMatchObject({ severity: 'CRITICAL', confidence: 'CONFIRMED' });
    expect(ev(mini)).toMatchObject({ direct: false, fixedVersion: '0.2.4', introducedBy: [['mkdirp@0.5.1', 'minimist@0.0.8']] });
    expect(mini.remediation).toContain('pulled in by mkdirp@0.5.1');
    expect(mini.remediation).toContain('"overrides": { "minimist": "0.2.4" }');

    const done = await prisma.dependencySnapshot.findUniqueOrThrow({ where: { id: snap.id } });
    expect(done).toMatchObject({ matchStatus: 'DONE', matchError: null });
    expect(done.matchedAt).toBeTruthy();
    expect((done.matchSummary as any).findings).toMatchObject({ total: 2, potential: 0, bySeverity: { CRITICAL: 1, HIGH: 1 } });
  });

  it('caches advisories: a second run fetches nothing; a newer upstream "modified" refetches', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, BASE, BASE_PKG);
    const first = fakeOsv(hitsFor, vulnsFor);
    await processMatch(repo.id, { prisma, log, osv: first.osv }, LAST);
    const second = fakeOsv(hitsFor, vulnsFor);
    await processMatch(repo.id, { prisma, log, osv: second.osv }, LAST);
    expect(second.calls.getVulns).toEqual([]); // nothing to fetch

    const newer = { ...lodashCmdInjection, modified: '2030-01-01T00:00:00Z', summary: 'Command Injection in lodash (updated)' };
    const third = fakeOsv({ ...hitsFor, 'lodash@4.17.20': [{ id: lodashCmdInjection.id, modified: '2030-01-01T00:00:00Z' }] }, { ...vulnsFor, [lodashCmdInjection.id]: newer });
    await processMatch(repo.id, { prisma, log, osv: third.osv }, LAST);
    expect(third.calls.getVulns).toEqual([[lodashCmdInjection.id]]);
    expect((await findings(repo.id)).find((f) => ev(f).package === 'lodash')!.title).toContain('(updated)');
  });

  it('is idempotent: re-running changes nothing but lastSeenAt', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, BASE, BASE_PKG);
    const { osv } = fakeOsv(hitsFor, vulnsFor);
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    const a = await findings(repo.id);
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    const b = await findings(repo.id);
    expect(b.map((f) => f.id)).toEqual(a.map((f) => f.id));
    expect(b.every((f, i) => f.firstSeenAt.getTime() === a[i].firstSeenAt.getTime())).toBe(true);
  });

  it('OSV says affected but our range check disagrees → kept as POTENTIAL, flagged osv-only', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, BASE, BASE_PKG);
    // zipObjectDeep is fixed in 4.17.19, so 4.17.20 is NOT in its range, yet we make OSV claim it applies
    const { osv } = fakeOsv({ 'lodash@4.17.20': [{ id: lodashZipObjectDeep.id }] }, { [lodashZipObjectDeep.id]: lodashZipObjectDeep });
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    const f = (await findings(repo.id))[0];
    expect(f).toMatchObject({ confidence: 'POTENTIAL' });
    expect(ev(f).matcher).toBe('osv-only');
    expect(((await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id } })).matchSummary as any).findings.potential).toBe(1);
  });

  it('one finding per (advisory, package) even with several copies; the fix covers all of them', async () => {
    const repo = await newRepo();
    const text = lock({
      'node_modules/mkdirp': { version: '0.5.1', dependencies: { minimist: '0.0.8' } },
      'node_modules/minimist': { version: '1.2.0' }, // hoisted, in the 1.x range (fix 1.2.6)
      'node_modules/mkdirp/node_modules/minimist': { version: '0.0.8' }, // nested, in the 0.x range (fix 0.2.4)
    });
    await snapshot(repo.id, text, rootPkg(['mkdirp', 'minimist']));
    const { osv } = fakeOsv({ 'minimist@1.2.0': [{ id: minimistProto.id }], 'minimist@0.0.8': [{ id: minimistProto.id }] }, { [minimistProto.id]: minimistProto });
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    const fs = await findings(repo.id);
    expect(fs).toHaveLength(1);
    expect(ev(fs[0])).toMatchObject({ versions: ['0.0.8', '1.2.0'], instanceCount: 2, fixedVersion: '1.2.6', direct: true });
    expect(fs[0].title).toBe('minimist@0.0.8, 1.2.0: Prototype Pollution in minimist');
  });

  it('upgrading to a fixed version marks the finding FIXED; reappearing reopens it; IGNORED is respected', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, BASE, BASE_PKG);
    await processMatch(repo.id, { prisma, log, osv: fakeOsv(hitsFor, vulnsFor).osv }, LAST);
    const before = await findings(repo.id);
    const lodash = before.find((f) => ev(f).package === 'lodash')!;
    const mini = before.find((f) => ev(f).package === 'minimist')!;
    await prisma.finding.update({ where: { id: lodash.id }, data: { status: 'ACKNOWLEDGED' } });
    await prisma.finding.update({ where: { id: mini.id }, data: { status: 'IGNORED' } });

    // new commit: lodash upgraded, minimist still vulnerable
    const fixed = lock({ 'node_modules/lodash': { version: '4.17.21' }, 'node_modules/mkdirp': { version: '0.5.1', dependencies: { minimist: '0.0.8' } }, 'node_modules/minimist': { version: '0.0.8' } });
    await snapshot(repo.id, fixed, BASE_PKG);
    const run2 = fakeOsv({ 'minimist@0.0.8': hitsFor['minimist@0.0.8'] }, vulnsFor);
    await processMatch(repo.id, { prisma, log, osv: run2.osv }, LAST);
    let after = await findings(repo.id);
    expect(after.find((f) => f.id === lodash.id)!.status).toBe('FIXED'); // was ACKNOWLEDGED
    expect(after.find((f) => f.id === mini.id)!.status).toBe('IGNORED'); // user's decision stands
    expect(((await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id }, orderBy: { createdAt: 'desc' } })).matchSummary as any).resolvedSinceLastMatch).toBe(1);

    // regression: someone reverts to the vulnerable version
    await snapshot(repo.id, BASE, BASE_PKG);
    await processMatch(repo.id, { prisma, log, osv: fakeOsv(hitsFor, vulnsFor).osv }, LAST);
    after = await findings(repo.id);
    expect(after.find((f) => f.id === lodash.id)!.status).toBe('REOPENED');
    expect(after).toHaveLength(2); // same rows, no duplicates
  });

  it('only the NEWEST snapshot is matched', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, BASE, BASE_PKG, 'old');
    await snapshot(repo.id, lock({ 'node_modules/lodash': { version: '4.17.21' } }), rootPkg(['lodash']), 'new');
    const { osv, calls } = fakeOsv(hitsFor, vulnsFor);
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    expect(calls.queryBatch).toEqual([['lodash@4.17.21']]);
    expect(await findings(repo.id)).toEqual([]);
  });

  it('skips git/file dependencies and non-semver versions (nothing to look up)', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, lock({
      'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' },
      'node_modules/g': { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/g.git#abc' },
      'node_modules/f': { version: '1.0.0', resolved: 'file:../f' },
      'node_modules/t': { version: 'latest', resolved: 'https://registry.npmjs.org/t/-/t.tgz' },
    }), rootPkg(['a', 'g', 'f', 't']));
    const { osv, calls } = fakeOsv({}, {});
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    expect(calls.queryBatch).toEqual([['a@1.0.0']]);
    expect(((await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id } })).matchSummary as any).skippedNonRegistry).toBe(3);
  });

  it('ignores withdrawn advisories and advisories OSV can no longer return; counts the latter', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, BASE, BASE_PKG);
    const withdrawn = { ...lodashCmdInjection, id: 'GHSA-withdrawn', withdrawn: '2022-01-01T00:00:00Z' };
    const { osv } = fakeOsv(
      { 'lodash@4.17.20': [{ id: 'GHSA-withdrawn' }, { id: 'GHSA-gone' }], 'minimist@0.0.8': hitsFor['minimist@0.0.8'] },
      { 'GHSA-withdrawn': withdrawn, 'GHSA-gone': null, [minimistProto.id]: minimistProto },
    );
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    expect((await findings(repo.id)).map((f) => ev(f).package)).toEqual(['minimist']);
    expect(((await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id } })).matchSummary as any).advisories.unavailable).toBe(1);
  });

  it('severity falls back to the advisory label, then to MEDIUM; dev-only packages are labelled', async () => {
    const repo = await newRepo();
    await snapshot(repo.id, lock({ 'node_modules/left-pad': { version: '1.1.0', dev: true }, 'node_modules/nosev': { version: '1.0.0' } }), rootPkg([], ['left-pad', 'nosev']));
    const noSeverity = { id: 'GHSA-gone', modified: '2022-01-01T00:00:00Z', summary: 'No severity given', affected: [{ package: { ecosystem: 'npm', name: 'nosev' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] };
    const { osv } = fakeOsv({ 'left-pad@1.1.0': [{ id: labelOnly.id }], 'nosev@1.0.0': [{ id: 'GHSA-gone' }] }, { [labelOnly.id]: labelOnly, 'GHSA-gone': noSeverity });
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    const fs = await findings(repo.id);
    const lp = fs.find((f) => ev(f).package === 'left-pad')!;
    expect(lp).toMatchObject({ severity: 'MEDIUM' });
    expect(ev(lp).severity.source).toBe('database');
    expect(lp.title).toContain('(dev dependency)');
    const ns = fs.find((f) => ev(f).package === 'nosev')!;
    expect(ns.severity).toBe('MEDIUM');
    expect(ev(ns).severity.source).toBe('default');
    expect(ev(ns).fixedVersion).toBeNull();
    expect(ns.remediation).toContain('No fixed version');
  });

  it('batches the whole snapshot in ONE queryBatch call (the client does the chunking)', async () => {
    const repo = await newRepo();
    const many: Record<string, object> = {};
    for (let i = 0; i < 3000; i++) many[`node_modules/p${i}`] = { version: '1.0.0' };
    await snapshot(repo.id, lock(many), rootPkg([]));
    const { osv, calls } = fakeOsv({}, {});
    await processMatch(repo.id, { prisma, log, osv }, LAST);
    expect(calls.queryBatch).toHaveLength(1);
    expect(calls.queryBatch[0]).toHaveLength(3000);
  });

  describe('failure handling never loses or silently resolves findings', () => {
    const boom = (retryable: boolean, status?: number): MatchDeps['osv'] => ({
      queryBatch: async () => { throw new OsvError('upstream detail 10.0.0.9', retryable, status); },
      getVulns: async () => new Map(),
    });

    it('transient OSV error: snapshot back to PENDING + rethrow while attempts remain; FAILED on the last', async () => {
      const repo = await newRepo();
      const snap = await snapshot(repo.id, BASE, BASE_PKG);
      await processMatch(repo.id, { prisma, log, osv: fakeOsv(hitsFor, vulnsFor).osv }, LAST); // establish findings
      await expect(processMatch(repo.id, { prisma, log, osv: boom(true, 503) }, NOT_LAST)).rejects.toThrow();
      expect(await prisma.dependencySnapshot.findUniqueOrThrow({ where: { id: snap.id } })).toMatchObject({ matchStatus: 'PENDING', matchError: expect.stringContaining('temporarily unavailable') });
      await expect(processMatch(repo.id, { prisma, log, osv: boom(true, 503) }, LAST)).rejects.toThrow();
      const failed = await prisma.dependencySnapshot.findUniqueOrThrow({ where: { id: snap.id } });
      expect(failed.matchStatus).toBe('FAILED');
      expect(failed.matchError).not.toMatch(/10\.0\.0\.9|upstream detail/);
      // the crucial part: an outage must NOT mark vulnerabilities as fixed
      expect((await findings(repo.id)).map((f) => f.status)).toEqual(['OPEN', 'OPEN']);
    });

    it('permanent error: FAILED, job completes (no retry storm), findings untouched', async () => {
      const repo = await newRepo();
      await snapshot(repo.id, BASE, BASE_PKG);
      await processMatch(repo.id, { prisma, log, osv: fakeOsv(hitsFor, vulnsFor).osv }, LAST);
      await expect(processMatch(repo.id, { prisma, log, osv: boom(false, 400) }, NOT_LAST)).resolves.toBeUndefined();
      expect((await prisma.dependencySnapshot.findFirstOrThrow({ where: { repositoryId: repo.id } })).matchStatus).toBe('FAILED');
      expect((await findings(repo.id)).map((f) => f.status)).toEqual(['OPEN', 'OPEN']);
    });
  });

  it('drops jobs for unknown repositories and repositories with no snapshot', async () => {
    const { osv } = fakeOsv({}, {});
    await expect(processMatch('nope', { prisma, log, osv }, LAST)).resolves.toBeUndefined();
    const empty = await newRepo();
    await expect(processMatch(empty.id, { prisma, log, osv }, LAST)).resolves.toBeUndefined();
  });
});

describe('buildRemediation', () => {
  it('covers direct/transitive × fix/no-fix', () => {
    const chain = [[{ name: 'express', version: '4.0.0', path: 'p' }, { name: 'qs', version: '1.0.0', path: 'q' }]];
    expect(buildRemediation({ name: 'qs', fixedVersion: '6.0.0', direct: true, chains: [] })).toBe('Upgrade qs to 6.0.0 or later (npm install qs@6.0.0).');
    expect(buildRemediation({ name: 'qs', fixedVersion: null, direct: true, chains: [] })).toContain('No fixed version of qs');
    expect(buildRemediation({ name: 'qs', fixedVersion: '6.0.0', direct: false, chains: chain })).toContain('pulled in by express@4.0.0. Upgrade express');
    expect(buildRemediation({ name: 'qs', fixedVersion: null, direct: false, chains: chain })).toContain('pulled in by express@4.0.0. No fixed version');
    expect(buildRemediation({ name: 'qs', fixedVersion: '6.0.0', direct: false, chains: [] })).toContain('the package that depends on it');
  });
});
