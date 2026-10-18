import { LockfileParseError, parseNpmLock } from '@sentinel/core';
import { classifyGithubError, GithubFetchError, type LockfileFetch } from '@sentinel/github';
import type { InventoryStatus, Prisma, PrismaClient } from '@sentinel/db';
import type { Log } from './process-scan';

/** Everything the inventory needs to know to fetch; deliberately no tokens. */
export interface RepoForFetch {
  id: string;
  githubRepoId: string;
  /** GitHub's installation id (not our row id) */
  installationId: string;
}

export interface InventoryDeps {
  prisma: PrismaClient;
  log: Log;
  /** Injectable for tests. The real one mints a short-lived, single-repo, contents:read token. */
  fetchLockfile: (repo: RepoForFetch) => Promise<LockfileFetch>;
  /** Snapshots to keep per repository (older ones are pruned). */
  keepSnapshots?: number;
  /** Called after a successful inventory so the new snapshot gets matched against advisories. Best effort. */
  enqueueMatch?: (repositoryId: string) => Promise<void>;
}

const INSERT_CHUNK = 1000;

/** User-facing text. Never forwards raw GitHub/Prisma messages. */
function describeFailure(err: unknown): { message: string; retryable: boolean } {
  if (err instanceof LockfileParseError) return { message: `package-lock.json could not be read: ${err.message}.`, retryable: false };
  if (err instanceof GithubFetchError && err.status === undefined) return { message: err.message, retryable: err.retryable };
  const c = classifyGithubError(err);
  if (c.status === 404) return { message: 'Sentinel can no longer access this repository. Check the GitHub App installation.', retryable: false };
  if (c.status === 401 || c.status === 403) {
    return c.retryable
      ? { message: 'GitHub is rate limiting requests. Try again shortly.', retryable: true }
      : { message: 'GitHub denied access. Check that the App still has read access to repository contents.', retryable: false };
  }
  if (c.retryable) return { message: 'GitHub was temporarily unavailable. Try again shortly.', retryable: true };
  return { message: 'The inventory failed unexpectedly. Please try again.', retryable: false };
}

export async function processInventory(repositoryId: string, deps: InventoryDeps, opts: { isLastAttempt: boolean }): Promise<void> {
  const { prisma, log } = deps;
  const repo = await prisma.repository.findUnique({ where: { id: repositoryId }, include: { installation: true } });
  if (!repo) {
    log.warn({ repositoryId }, 'repository not found (disconnected?), dropping job');
    return;
  }

  const set = (inventoryStatus: InventoryStatus, inventoryError: string | null, extra: Prisma.RepositoryUpdateInput = {}) =>
    prisma.repository.update({ where: { id: repo.id }, data: { inventoryStatus, inventoryError, ...extra } });

  if (repo.installation.suspendedAt) {
    await set('FAILED', 'The GitHub installation is suspended.');
    return;
  }

  await set('RUNNING', null);
  log.info({ repositoryId, repo: repo.fullName }, 'inventory started');

  try {
    const res = await deps.fetchLockfile({ id: repo.id, githubRepoId: repo.githubRepoId, installationId: repo.installation.installationId });

    // Repos get renamed/transferred/archived; keep our copy fresh while we have the data.
    const [owner, name] = res.repo.fullName.split('/');
    const meta: Prisma.RepositoryUpdateInput = { fullName: res.repo.fullName, owner, name, defaultBranch: res.repo.defaultBranch, archived: res.repo.archived, private: res.repo.private };

    if (res.kind === 'empty') {
      await set('NO_LOCKFILE', 'The repository is empty.', meta);
      return;
    }
    if (res.kind === 'none') {
      await set('NO_LOCKFILE', res.note, { ...meta, lastInventorySha: res.commitSha, lastInventoryAt: new Date() });
      return;
    }

    const where = { repositoryId_commitSha_lockfilePath: { repositoryId: repo.id, commitSha: res.commitSha, lockfilePath: res.path } };
    const existing = await prisma.dependencySnapshot.findUnique({ where, select: { id: true } });
    if (!existing) {
      const parsed = parseNpmLock(res.lockfileText, { packageJson: res.packageJsonText });
      try {
        await prisma.$transaction(
          async (tx) => {
            const snap = await tx.dependencySnapshot.create({
              data: {
                repositoryId: repo.id, commitSha: res.commitSha, branch: res.branch, lockfilePath: res.path,
                lockfileVersion: parsed.lockfileVersion, packageCount: parsed.packages.length, directCount: parsed.directCount,
              },
            });
            for (let i = 0; i < parsed.packages.length; i += INSERT_CHUNK) {
              await tx.packageInstance.createMany({ data: parsed.packages.slice(i, i + INSERT_CHUNK).map((p) => ({ ...p, snapshotId: snap.id })) });
            }
          },
          { timeout: 120_000, maxWait: 10_000 },
        );
        log.info({ repositoryId, commit: res.commitSha, packages: parsed.packages.length, warnings: parsed.warnings.length }, 'snapshot stored');
      } catch (err) {
        // Two inventories of the same commit raced; the other one won. That is fine: same data.
        if ((err as { code?: string })?.code !== 'P2002') throw err;
      }
      await prune(deps, repo.id);
    } else {
      log.info({ repositoryId, commit: res.commitSha }, 'snapshot for this commit already exists');
    }

    await set('SUCCEEDED', null, { ...meta, lastInventorySha: res.commitSha, lastInventoryAt: new Date() });
    // A failure to queue matching must not turn a good inventory into a failed one; the user can re-run matching.
    await deps.enqueueMatch?.(repo.id).catch((e) => log.error({ repositoryId, err: e }, 'could not enqueue vulnerability matching'));
  } catch (err) {
    const { message, retryable } = describeFailure(err);
    log.error({ repositoryId, err, retryable, lastAttempt: opts.isLastAttempt }, 'inventory failed');
    if (retryable && !opts.isLastAttempt) {
      await set('QUEUED', message); // BullMQ will retry with backoff
      throw err;
    }
    await set('FAILED', message);
    if (retryable) throw err; // out of attempts: let BullMQ record the job as failed
    // non-retryable: recorded on the repository; completing the job normally avoids pointless retries
  }
}

async function prune(deps: InventoryDeps, repositoryId: string) {
  const keep = deps.keepSnapshots ?? 5;
  const old = await deps.prisma.dependencySnapshot.findMany({ where: { repositoryId }, orderBy: { createdAt: 'desc' }, skip: keep, select: { id: true } });
  if (old.length) await deps.prisma.dependencySnapshot.deleteMany({ where: { id: { in: old.map((s) => s.id) } } });
}
