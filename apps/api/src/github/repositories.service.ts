import { ConflictException, Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { INVENTORY_JOB_NAME, inventoryJobId, MATCH_JOB_NAME, matchJobId } from '@sentinel/core';
import { RateLimitService } from '../common/rate-limit.service';
import { PrismaService } from '../prisma/prisma.service';
import { INVENTORY_QUEUE_TOKEN, MATCH_QUEUE_TOKEN, type InventoryQueue, type MatchQueue } from '../queue/queue.module';

/** A QUEUED/RUNNING repository untouched for this long is presumed lost (worker died, job evicted) and may be re-queued. */
const STALE_AFTER_MS = 15 * 60_000;
export const INVENTORIES_PER_REPO_PER_HOUR = 10;

@Injectable()
export class RepositoriesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly rateLimit: RateLimitService,
    @Inject(INVENTORY_QUEUE_TOKEN) private readonly queue: InventoryQueue,
    @Inject(MATCH_QUEUE_TOKEN) private readonly matchQueue: MatchQueue,
  ) {}

  private async owned(userId: string, id: string) {
    const repo = await this.prisma.repository.findFirst({ where: { id, userId }, include: { installation: true } });
    if (!repo) throw new NotFoundException('Repository not found');
    return repo;
  }

  async list(userId: string) {
    const repos = await this.prisma.repository.findMany({
      where: { userId },
      orderBy: [{ fullName: 'asc' }],
      include: {
        installation: { select: { id: true, accountLogin: true, suspendedAt: true } },
        snapshots: { orderBy: { createdAt: 'desc' }, take: 1, select: { id: true, commitSha: true, branch: true, lockfileVersion: true, packageCount: true, directCount: true, createdAt: true, matchStatus: true, matchedAt: true, matchError: true, matchSummary: true } },
      },
    });
    return repos.map(({ snapshots, installation, ...r }) => ({
      ...r,
      installation: { id: installation.id, accountLogin: installation.accountLogin, suspended: installation.suspendedAt !== null },
      latestSnapshot: snapshots[0] ?? null,
    }));
  }

  /** 202 + current state. Calling it while an inventory is already queued/running is a harmless no-op. */
  async requestInventory(userId: string, id: string) {
    const repo = await this.owned(userId, id);
    if (repo.installation.suspendedAt) throw new ConflictException('The GitHub installation is suspended.');

    // Atomic claim: only one caller can move the repo into QUEUED (unless the previous run looks abandoned).
    const claim = await this.prisma.repository.updateMany({
      where: {
        id,
        OR: [{ inventoryStatus: { notIn: ['QUEUED', 'RUNNING'] } }, { updatedAt: { lt: new Date(Date.now() - STALE_AFTER_MS) } }],
      },
      data: { inventoryStatus: 'QUEUED', inventoryError: null },
    });
    if (claim.count === 0) return { id, status: repo.inventoryStatus, alreadyInProgress: true };

    try {
      await this.rateLimit.hit(`inventory:${id}`, INVENTORIES_PER_REPO_PER_HOUR, 3600, 'inventory runs for this repository');
    } catch (err) {
      await this.prisma.repository.update({ where: { id }, data: { inventoryStatus: repo.inventoryStatus, inventoryError: repo.inventoryError } });
      throw err; // 429
    }

    try {
      // Deterministic jobId ⇒ a duplicate add while one is queued/active is ignored by BullMQ.
      await this.queue.add(INVENTORY_JOB_NAME, { repositoryId: id }, {
        jobId: inventoryJobId(id),
        attempts: 3,
        backoff: { type: 'exponential', delay: 10_000 },
        removeOnComplete: true,
        removeOnFail: true,
      });
    } catch {
      await this.prisma.repository.update({ where: { id }, data: { inventoryStatus: 'FAILED', inventoryError: 'Could not queue the inventory.' } });
      throw new ServiceUnavailableException('Inventory is temporarily unavailable. Please try again shortly.');
    }
    return { id, status: 'QUEUED' as const, alreadyInProgress: false };
  }

  /**
   * Re-match the newest snapshot against OSV (it also runs automatically after every inventory). Useful because
   * advisories are published continuously, long after a snapshot was taken.
   */
  async requestMatch(userId: string, id: string) {
    await this.owned(userId, id);
    const snapshot = await this.prisma.dependencySnapshot.findFirst({ where: { repositoryId: id }, orderBy: { createdAt: 'desc' }, select: { id: true, matchStatus: true, createdAt: true } });
    if (!snapshot) throw new ConflictException('Run an inventory first: there is nothing to match yet.');
    if (snapshot.matchStatus === 'RUNNING') return { id, status: 'RUNNING' as const, alreadyInProgress: true };

    await this.rateLimit.hit(`match:${id}`, INVENTORIES_PER_REPO_PER_HOUR, 3600, 'matching runs for this repository');
    try {
      // Deterministic jobId ⇒ a duplicate while one is queued/active is ignored.
      await this.matchQueue.add(MATCH_JOB_NAME, { repositoryId: id }, {
        jobId: matchJobId(id), attempts: 4, backoff: { type: 'exponential', delay: 15_000 }, removeOnComplete: true, removeOnFail: true,
      });
    } catch {
      throw new ServiceUnavailableException('Matching is temporarily unavailable. Please try again shortly.');
    }
    await this.prisma.dependencySnapshot.updateMany({ where: { id: snapshot.id, matchStatus: { not: 'RUNNING' } }, data: { matchStatus: 'PENDING', matchError: null } });
    return { id, status: 'PENDING' as const, alreadyInProgress: false };
  }

  /** Latest snapshot for the repository, with one page of its packages. */
  async inventory(userId: string, id: string, q: { take: number; skip: number; directOnly: boolean }) {
    await this.owned(userId, id);
    const snapshot = await this.prisma.dependencySnapshot.findFirst({ where: { repositoryId: id }, orderBy: { createdAt: 'desc' } });
    if (!snapshot) return { snapshot: null, total: 0, packages: [] };
    const where = { snapshotId: snapshot.id, ...(q.directOnly ? { direct: true } : {}) };
    const [total, packages] = await Promise.all([
      this.prisma.packageInstance.count({ where }),
      this.prisma.packageInstance.findMany({
        where, orderBy: [{ direct: 'desc' }, { name: 'asc' }, { path: 'asc' }], take: q.take, skip: q.skip,
        select: { id: true, name: true, version: true, path: true, dev: true, optional: true, direct: true, source: true },
      }),
    ]);
    return { snapshot, total, packages };
  }
}
