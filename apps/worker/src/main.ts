import { INVENTORY_QUEUE, MATCH_JOB_NAME, MATCH_QUEUE, matchJobId, OsvClient, redisConnectionFromUrl, SCAN_QUEUE, type InventoryJobData, type MatchJobData, type ScanJobData } from '@sentinel/core';
import { PrismaClient, prismaClientOptions } from '@sentinel/db';
import { createGithubApp, fetchNpmLockfile } from '@sentinel/github';
import { Queue, Worker } from 'bullmq';
import { Redis } from 'ioredis';
import pino from 'pino';
import { z } from 'zod';
import { loadEnv } from './env';
import { processInventory } from './process-inventory';
import { processMatch } from './process-match';
import { processScan } from './process-scan';

// Compare-and-delete: only release the lock if it still belongs to THIS scan (it may have expired and been re-taken).
const RELEASE_LOCK = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`;

const jobData = z.object({ scanId: z.string().min(1).max(64) });
const inventoryJobData = z.object({ repositoryId: z.string().min(1).max(64) });
const matchJobData = z.object({ repositoryId: z.string().min(1).max(64) });

async function main() {
  const env = loadEnv();
  const log = pino({
    level: env.LOG_LEVEL,
    transport: env.NODE_ENV === 'production' ? undefined : { target: 'pino-pretty', options: { singleLine: true, colorize: true, translateTime: 'SYS:HH:MM:ss' } },
  });

  const prisma = new PrismaClient(prismaClientOptions(env.DATABASE_URL));
  await prisma.$connect();
  const redis = new Redis(env.REDIS_URL);
  redis.on('error', (err) => log.error({ err }, 'redis error'));

  const { activeScanLockKey } = await import('@sentinel/core');

  const worker = new Worker<ScanJobData>(
    SCAN_QUEUE,
    async (job) => {
      // Job data comes out of Redis: treat it as untrusted input.
      const { scanId } = jobData.parse(job.data);
      await processScan(scanId, {
        prisma,
        log,
        releaseLock: async (targetId, id) => {
          await redis.eval(RELEASE_LOCK, 1, activeScanLockKey(targetId), id);
        },
      });
    },
    { connection: redisConnectionFromUrl(env.REDIS_URL), concurrency: env.WORKER_CONCURRENCY },
  );

  worker.on('failed', (job, err) => log.error({ jobId: job?.id, err: err.message }, 'job failed'));
  worker.on('error', (err) => log.error({ err }, 'worker error'));
  log.info({ queue: SCAN_QUEUE, concurrency: env.WORKER_CONCURRENCY }, 'Sentinel worker ready');

  // Vulnerability matching: needs only OSV (public) and the database, so it always runs.
  const connection = redisConnectionFromUrl(env.REDIS_URL);
  const matchQueue = new Queue<MatchJobData>(MATCH_QUEUE, { connection });
  matchQueue.on('error', (err) => log.error({ err }, 'match queue error'));
  const osv = new OsvClient();
  const matchWorker = new Worker<MatchJobData>(
    MATCH_QUEUE,
    async (job) => {
      const { repositoryId } = matchJobData.parse(job.data);
      await processMatch(repositoryId, { prisma, log, osv }, { isLastAttempt: job.attemptsMade + 1 >= (job.opts.attempts ?? 1) });
    },
    { connection, concurrency: 2 },
  );
  matchWorker.on('failed', (job, err) => log.error({ jobId: job?.id, err: err.message }, 'match job failed'));
  matchWorker.on('error', (err) => log.error({ err }, 'match worker error'));
  log.info({ queue: MATCH_QUEUE }, 'matching worker ready');
  const enqueueMatch = async (repositoryId: string) => {
    // Deterministic id: a pending match for the same repository is not duplicated.
    await matchQueue.add(MATCH_JOB_NAME, { repositoryId }, { jobId: matchJobId(repositoryId), attempts: 4, backoff: { type: 'exponential', delay: 15_000 }, removeOnComplete: true, removeOnFail: true });
  };

  // Dependency inventory needs the GitHub App; without credentials this worker is simply not started.
  let inventoryWorker: Worker<InventoryJobData> | undefined;
  if (env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY) {
    const app = createGithubApp({ appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY });
    inventoryWorker = new Worker<InventoryJobData>(
      INVENTORY_QUEUE,
      async (job) => {
        const { repositoryId } = inventoryJobData.parse(job.data);
        await processInventory(
          repositoryId,
          {
            prisma,
            log,
            enqueueMatch,
            // A fresh token per job: scoped to this one repository, read-only, held in memory, expires within the hour.
            fetchLockfile: async (repo) => {
              const requester = await app.installationRequester(repo.installationId, {
                repositoryIds: [Number(repo.githubRepoId)],
                permissions: { contents: 'read' },
              });
              return fetchNpmLockfile(requester, repo.githubRepoId);
            },
          },
          { isLastAttempt: job.attemptsMade + 1 >= (job.opts.attempts ?? 1) },
        );
      },
      { connection: redisConnectionFromUrl(env.REDIS_URL), concurrency: Math.min(env.WORKER_CONCURRENCY, 3) },
    );
    inventoryWorker.on('failed', (job, err) => log.error({ jobId: job?.id, err: err.message }, 'inventory job failed'));
    inventoryWorker.on('error', (err) => log.error({ err }, 'inventory worker error'));
    log.info({ queue: INVENTORY_QUEUE }, 'inventory worker ready');
  } else {
    log.warn('GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY not set: dependency inventory is disabled');
  }

  let stopping = false;
  const shutdown = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    log.info({ signal }, 'shutting down (waiting for running scans to finish)');
    await Promise.all([worker.close(), inventoryWorker?.close(), matchWorker.close()]); // stop taking jobs, wait for active ones
    await matchQueue.close();
    await prisma.$disconnect();
    redis.disconnect();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
