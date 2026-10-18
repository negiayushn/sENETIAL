import { ConflictException, ForbiddenException, Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { ACTIVE_SCAN_LOCK_TTL_SEC, activeScanLockKey, SCAN_JOB_NAME, scanJobId } from '@sentinel/core';
import type Redis from 'ioredis';
import { RateLimitService } from '../common/rate-limit.service';
import { PrismaService } from '../prisma/prisma.service';
import { SCAN_QUEUE_TOKEN, type ScanQueue } from '../queue/queue.module';
import { REDIS } from '../redis/redis.module';

/** Per-target limit on how often scans may be started. Protects the target (and us) from hammering. */
export const SCANS_PER_TARGET_PER_HOUR = 6;

const RELEASE_LOCK = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`;

@Injectable()
export class ScansService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly rateLimit: RateLimitService,
    @Inject(REDIS) private readonly redis: Redis,
    @Inject(SCAN_QUEUE_TOKEN) private readonly queue: ScanQueue,
  ) {}

  private async ownedTarget(userId: string, targetId: string) {
    const target = await this.prisma.target.findFirst({ where: { id: targetId, userId } });
    if (!target) throw new NotFoundException('Target not found'); // 404 (not 403) so other users' ids are not probeable
    return target;
  }

  async create(userId: string, targetId: string) {
    const target = await this.ownedTarget(userId, targetId);

    // 1) Verification gate (the worker checks again).
    if (target.status !== 'VERIFIED') throw new ForbiddenException('Verify ownership of this target before scanning it.');

    // 2) Friendly early exit if a scan is already in flight (the Redis lock below is the authoritative check).
    const active = await this.prisma.scan.findFirst({ where: { targetId, status: { in: ['QUEUED', 'RUNNING'] } }, select: { id: true } });
    if (active) throw new ConflictException({ statusCode: 409, message: 'A scan for this target is already queued or running.', scanId: active.id });

    // 3) Per-target rate limit.
    await this.rateLimit.hit(`scan:${targetId}`, SCANS_PER_TARGET_PER_HOUR, 3600, 'scans for this target');

    // 4) Create the row, then take the one-scan-at-a-time lock keyed by the new scan id (atomic SET NX).
    const scan = await this.prisma.scan.create({ data: { userId, targetId } });
    const lockKey = activeScanLockKey(targetId);
    const locked = await this.redis.set(lockKey, scan.id, 'EX', ACTIVE_SCAN_LOCK_TTL_SEC, 'NX');
    if (locked !== 'OK') {
      await this.prisma.scan.delete({ where: { id: scan.id } });
      throw new ConflictException('A scan for this target is already queued or running.');
    }

    // 5) Enqueue and return immediately. The job carries only the scan id; jobId makes enqueueing idempotent.
    try {
      await this.queue.add(SCAN_JOB_NAME, { scanId: scan.id }, {
        jobId: scanJobId(scan.id),
        attempts: 1,
        removeOnComplete: { age: 3600, count: 1000 },
        removeOnFail: { age: 7 * 24 * 3600 },
      });
    } catch {
      await this.prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED', error: 'Could not queue the scan.', finishedAt: new Date() } });
      await this.redis.eval(RELEASE_LOCK, 1, lockKey, scan.id).catch(() => undefined);
      throw new ServiceUnavailableException('Scanning is temporarily unavailable. Please try again shortly.');
    }

    return { id: scan.id, targetId, status: scan.status, createdAt: scan.createdAt };
  }

  async listForTarget(userId: string, targetId: string) {
    await this.ownedTarget(userId, targetId);
    return this.prisma.scan.findMany({
      where: { targetId, userId },
      orderBy: { createdAt: 'desc' },
      take: 20,
      include: { _count: { select: { findings: true } } },
    });
  }

  async get(userId: string, id: string) {
    const scan = await this.prisma.scan.findFirst({ where: { id, userId }, include: { _count: { select: { findings: true } } } });
    if (!scan) throw new NotFoundException('Scan not found');
    return scan;
  }
}
