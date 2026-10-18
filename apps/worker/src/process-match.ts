import {
  advisoryAffects, buildDependencyGraph, chainsToDirect, fingerprint, normalizeOsvVuln, OsvError, redactEvidence, smallestFixedVersion,
  type ChainLink, type NormalizedAdvisory, type OsvClient,
} from '@sentinel/core';
import type { Confidence, Prisma, PrismaClient, Severity } from '@sentinel/db';
import semver from 'semver';
import type { Log } from './process-scan';

export interface MatchDeps {
  prisma: PrismaClient;
  log: Log;
  osv: Pick<OsvClient, 'queryBatch' | 'getVulns'>;
}

export const FINDING_TYPE = 'dependency.vulnerability';
const MAX_UNIQUE_PACKAGES = 25_000;
const MAX_PATHS_IN_EVIDENCE = 10;
const MAX_ADVISORY_IDS = 20_000;

type InstanceRow = { id: string; name: string; version: string; path: string; dev: boolean; direct: boolean; source: string; requires: string[] };
type Group = { adv: NormalizedAdvisory; name: string; instances: { inst: InstanceRow; ours: boolean }[] };

const bySeverityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** Fixed, user-safe wording. Never forwards raw upstream text. */
function describeFailure(err: unknown): { message: string; retryable: boolean } {
  if (err instanceof OsvError) {
    return err.retryable
      ? { message: 'The vulnerability database (OSV) was temporarily unavailable. Sentinel will retry shortly.', retryable: true }
      : { message: 'The vulnerability database (OSV) rejected the request.', retryable: false };
  }
  return { message: 'Vulnerability matching failed unexpectedly. Please try again.', retryable: false };
}

export function buildRemediation(p: { name: string; fixedVersion: string | null; direct: boolean; chains: ChainLink[][] }): string {
  const { name, fixedVersion, direct, chains } = p;
  if (direct) {
    return fixedVersion
      ? `Upgrade ${name} to ${fixedVersion} or later (npm install ${name}@${fixedVersion}).`
      : `No fixed version of ${name} has been published yet. Replace the package, or mitigate as described in the advisory.`;
  }
  const parent = chains[0]?.[0];
  const via = parent ? `${name} is pulled in by ${parent.name}@${parent.version}. ` : '';
  if (!fixedVersion) return `${via}No fixed version of ${name} has been published yet. Replace the package that depends on it, or mitigate as described in the advisory.`;
  return (
    `${via}Upgrade ${parent ? parent.name : 'the package that depends on it'} to a release that uses ${name} ${fixedVersion} or later. ` +
    `If no such release exists yet, force the patched version with an "overrides" entry in package.json: { "overrides": { "${name}": "${fixedVersion}" } }.`
  );
}

export async function processMatch(repositoryId: string, deps: MatchDeps, opts: { isLastAttempt: boolean }): Promise<void> {
  const { prisma, log, osv } = deps;
  const repo = await prisma.repository.findUnique({ where: { id: repositoryId } });
  if (!repo) {
    log.warn({ repositoryId }, 'repository not found, dropping match job');
    return;
  }
  const snapshot = await prisma.dependencySnapshot.findFirst({ where: { repositoryId }, orderBy: { createdAt: 'desc' } });
  if (!snapshot) {
    log.info({ repositoryId }, 'no snapshot to match yet');
    return;
  }
  const setSnapshot = (data: Prisma.DependencySnapshotUpdateInput) => prisma.dependencySnapshot.update({ where: { id: snapshot.id }, data });

  await setSnapshot({ matchStatus: 'RUNNING', matchError: null });
  try {
    const instances: InstanceRow[] = await prisma.packageInstance.findMany({
      where: { snapshotId: snapshot.id },
      select: { id: true, name: true, version: true, path: true, dev: true, direct: true, source: true, requires: true },
    });

    // Only registry packages with a real semver version can be looked up (git/file/tarball deps have no advisories).
    const lookable = instances.filter((i) => i.source === 'registry' && semver.valid(i.version) !== null);
    const skipped = instances.length - lookable.length;
    const pairs = [...new Map(lookable.map((i) => [`${i.name}@${i.version}`, { name: i.name, version: i.version }])).values()];
    if (pairs.length > MAX_UNIQUE_PACKAGES) throw new Error(`Snapshot has ${pairs.length} unique packages (limit ${MAX_UNIQUE_PACKAGES})`);

    // 1) Which advisories does OSV say apply? (IDs + modified only)
    const hits = await osv.queryBatch(pairs);
    const refModified = new Map<string, string | null>();
    for (const list of hits.values()) for (const h of list) if (!refModified.has(h.id) || (h.modified ?? '') > (refModified.get(h.id) ?? '')) refModified.set(h.id, h.modified);
    if (refModified.size > MAX_ADVISORY_IDS) throw new Error('Too many advisories referenced');
    const ids = [...refModified.keys()];

    // 2) Advisory cache: fetch what we lack or what OSV says has changed since we stored it.
    const cached = new Map((await prisma.advisory.findMany({ where: { id: { in: ids } }, select: { id: true, modified: true } })).map((a) => [a.id, a.modified]));
    const toFetch = ids.filter((id) => {
      const have = cached.get(id);
      const upstream = refModified.get(id);
      return !have || (upstream !== null && upstream !== undefined && new Date(upstream) > have);
    });
    let unavailable = 0;
    if (toFetch.length) {
      const raw = await osv.getVulns(toFetch);
      for (const [id, record] of raw) {
        const adv = record === null ? null : normalizeOsvVuln(record);
        if (!adv) {
          unavailable++;
          log.warn({ id }, 'advisory unavailable or unusable');
          continue;
        }
        const data = {
          modified: adv.modified, published: adv.published, withdrawn: adv.withdrawn, summary: adv.summary, details: adv.details, aliases: adv.aliases,
          severity: adv.severity, severitySource: adv.severitySource, cvssScore: adv.cvssScore, cvssVector: adv.cvssVector,
          affected: adv.affected as unknown as Prisma.InputJsonValue, packageNames: adv.packageNames, references: adv.references as unknown as Prisma.InputJsonValue, fetchedAt: new Date(),
        };
        await prisma.advisory.upsert({ where: { id: adv.id }, create: { id: adv.id, ...data }, update: data });
      }
    }
    const advisories = new Map<string, NormalizedAdvisory>();
    for (const row of await prisma.advisory.findMany({ where: { id: { in: ids } } })) {
      advisories.set(row.id, {
        id: row.id, modified: row.modified, published: row.published, withdrawn: row.withdrawn, summary: row.summary, details: row.details, aliases: row.aliases,
        severity: row.severity, severitySource: row.severitySource as 'cvss' | 'database' | null, cvssScore: row.cvssScore, cvssVector: row.cvssVector,
        affected: row.affected as unknown as NormalizedAdvisory['affected'], packageNames: row.packageNames, references: (row.references ?? []) as NormalizedAdvisory['references'],
      });
    }

    // 3) Confirm each OSV hit with our own range matcher and group by (advisory, package).
    const groups = new Map<string, Group>();
    for (const inst of lookable) {
      for (const hit of hits.get(`${inst.name}@${inst.version}`) ?? []) {
        const adv = advisories.get(hit.id);
        if (!adv || adv.withdrawn) continue;
        const k = `${adv.id}|${inst.name}`;
        const g = groups.get(k) ?? { adv, name: inst.name, instances: [] };
        g.instances.push({ inst, ours: advisoryAffects(adv, inst.name, inst.version) });
        groups.set(k, g);
      }
    }

    // 4) Build findings.
    const graph = buildDependencyGraph(instances.map((i) => ({ name: i.name, version: i.version, path: i.path, direct: i.direct, dev: i.dev, requires: i.requires })));
    const now = new Date();
    const drafts = [...groups.values()].map((g) => {
      const insts = g.instances.map((x) => x.inst);
      const versions = [...new Set(insts.map((i) => i.version))].sort(semver.compare);
      const direct = insts.some((i) => i.direct);
      const devOnly = insts.every((i) => i.dev);
      const confirmed = g.instances.some((x) => x.ours);

      // One fix must cover every installed copy: the highest of the per-copy "smallest fix above installed".
      const fixes = insts.map((i) => smallestFixedVersion(g.adv, g.name, i.version));
      const fixedVersion = fixes.some((f) => f === null) ? null : fixes.reduce((a, b) => (semver.gt(b!, a!) ? b : a));

      const best = [...insts].sort((a, b) => Number(a.dev) - Number(b.dev) || Number(b.direct) - Number(a.direct) || a.path.length - b.path.length)[0];
      const chains = direct ? [] : chainsToDirect(graph, best.path, 3);
      const severity: Severity = g.adv.severity ?? 'MEDIUM';
      const confidence: Confidence = confirmed ? 'CONFIRMED' : 'POTENTIAL';
      const label = g.adv.summary ?? g.adv.id;

      const evidence = {
        package: g.name,
        versions,
        direct,
        dev: devOnly,
        instanceCount: insts.length,
        paths: insts.map((i) => i.path).slice(0, MAX_PATHS_IN_EVIDENCE),
        introducedBy: chains.map((c) => c.map((l) => `${l.name}@${l.version}`)),
        fixedVersion,
        advisory: { id: g.adv.id, aliases: g.adv.aliases, summary: g.adv.summary, published: g.adv.published, modified: g.adv.modified, references: g.adv.references },
        severity: { value: severity, source: g.adv.severitySource ?? 'default', cvssScore: g.adv.cvssScore, cvssVector: g.adv.cvssVector },
        matcher: confirmed ? 'confirmed' : 'osv-only', // 'osv-only': OSV says it applies but our range check disagrees; treat as potential
        snapshotId: snapshot.id,
        commitSha: snapshot.commitSha,
      };
      return {
        // Stable across upgrades: the same advisory on the same package stays ONE finding (so triage survives a version bump)
        // and only becomes FIXED when the package stops being affected.
        fingerprint: fingerprint({ source: 'DEPENDENCY', owner: repositoryId, type: FINDING_TYPE, key: `${g.adv.id}|${g.name}` }),
        title: `${g.name}@${versions.join(', ')}: ${label}${devOnly ? ' (dev dependency)' : ''}`.slice(0, 250),
        severity, confidence,
        remediation: buildRemediation({ name: g.name, fixedVersion, direct, chains }),
        evidence: redactEvidence(evidence) as Prisma.InputJsonObject,
      };
    });

    // 5) Persist atomically. Findings that are no longer present become FIXED, but ONLY because every step above succeeded.
    const current = drafts.map((d) => d.fingerprint);
    const fixedCount = await prisma.$transaction(
      async (tx) => {
        for (const d of drafts) {
          await tx.finding.updateMany({ where: { fingerprint: d.fingerprint, status: 'FIXED' }, data: { status: 'REOPENED' } });
          const data = { type: FINDING_TYPE, title: d.title, severity: d.severity, confidence: d.confidence, remediation: d.remediation, evidence: d.evidence, lastSeenAt: now };
          await tx.finding.upsert({
            where: { fingerprint: d.fingerprint },
            create: { ...data, fingerprint: d.fingerprint, source: 'DEPENDENCY', userId: repo.userId, repositoryId },
            update: data,
          });
        }
        const { count } = await tx.finding.updateMany({
          where: { repositoryId, source: 'DEPENDENCY', status: { in: ['OPEN', 'ACKNOWLEDGED', 'REOPENED'] }, fingerprint: { notIn: current } },
          data: { status: 'FIXED' },
        });
        return count;
      },
      { timeout: 60_000, maxWait: 10_000 },
    );

    const bySeverity: Record<string, number> = {};
    for (const s of bySeverityOrder) bySeverity[s] = drafts.filter((d) => d.severity === s).length;
    await setSnapshot({
      matchStatus: 'DONE', matchedAt: new Date(), matchError: null,
      matchSummary: {
        packagesQueried: pairs.length, skippedNonRegistry: skipped,
        advisories: { referenced: ids.length, fetched: toFetch.length - unavailable, cached: ids.length - toFetch.length, unavailable },
        findings: { total: drafts.length, bySeverity, potential: drafts.filter((d) => d.confidence === 'POTENTIAL').length },
        resolvedSinceLastMatch: fixedCount,
      },
    });
    log.info({ repositoryId, snapshotId: snapshot.id, findings: drafts.length, fixed: fixedCount }, 'matching finished');
  } catch (err) {
    const { message, retryable } = describeFailure(err);
    log.error({ repositoryId, err, retryable, lastAttempt: opts.isLastAttempt }, 'matching failed');
    if (retryable && !opts.isLastAttempt) {
      await setSnapshot({ matchStatus: 'PENDING', matchError: message });
      throw err; // BullMQ retries with backoff. Existing findings are untouched.
    }
    await setSnapshot({ matchStatus: 'FAILED', matchError: message });
    if (retryable) throw err;
  }
}
