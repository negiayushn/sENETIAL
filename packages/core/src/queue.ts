/** Shared by the API (producer) and the worker (consumer) so the two can never drift apart. */
export const SCAN_QUEUE = 'scans';
export const SCAN_JOB_NAME = 'scan';

/** The job carries ONLY the scan id. The worker loads hostname/status/owner from the database itself. */
export interface ScanJobData {
  scanId: string;
}

export const scanJobId = (scanId: string) => `scan-${scanId}`;

/** One scan at a time per target. Set by the API (SET NX), released by the worker when the scan ends. */
export const activeScanLockKey = (targetId: string) => `sentinel:scan-active:${targetId}`;
/** Safety net if a worker dies without releasing the lock. Must exceed the worker's scan deadline. */
export const ACTIVE_SCAN_LOCK_TTL_SEC = 10 * 60;

export interface RedisConnectionOptions {
  host: string;
  port: number;
  username?: string;
  password?: string;
  db?: number;
  tls?: Record<string, never>;
}

/** BullMQ takes plain connection options; parse REDIS_URL once so both apps agree. */
export function redisConnectionFromUrl(url: string): RedisConnectionOptions {
  const u = new URL(url);
  const db = u.pathname && u.pathname !== '/' ? Number(u.pathname.slice(1)) : undefined;
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 6379,
    username: u.username ? decodeURIComponent(u.username) : undefined,
    password: u.password ? decodeURIComponent(u.password) : undefined,
    db: Number.isInteger(db) ? db : undefined,
    tls: u.protocol === 'rediss:' ? {} : undefined,
  };
}

/* ───────── Phase 3: dependency inventory ───────── */
export const INVENTORY_QUEUE = 'inventory';
export const INVENTORY_JOB_NAME = 'inventory';

/** Like scans, the job carries only an id; the worker reads everything else from the database. */
export interface InventoryJobData {
  repositoryId: string;
}

/** Deterministic: while one is queued or running for a repository, adding another is a no-op. */
export const inventoryJobId = (repositoryId: string) => `inventory-${repositoryId}`;

/* ───────── Phase 4: vulnerability matching ───────── */
export const MATCH_QUEUE = 'matching';
export const MATCH_JOB_NAME = 'match-repository';

/** "Match the newest dependency snapshot of this repository against OSV advisories." */
export interface MatchJobData {
  repositoryId: string;
}

export const matchJobId = (repositoryId: string) => `match-${repositoryId}`;
