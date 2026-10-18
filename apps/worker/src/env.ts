import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  /** How many scans run at once. Each scan is itself paced per target, so this only bounds worker load. */
  /** GitHub App credentials. Optional: without them the inventory worker is simply not started. */
  GITHUB_APP_ID: z.preprocess((v) => (v === '' ? undefined : v), z.string().optional()),
  GITHUB_APP_PRIVATE_KEY: z.preprocess((v) => (v === '' ? undefined : v), z.string().optional()),
  WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(20).default(2),
});

export type WorkerEnv = z.infer<typeof schema>;

export function loadEnv(raw: NodeJS.ProcessEnv = process.env): WorkerEnv {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid worker environment:\n${issues}`);
  }
  return parsed.data;
}
