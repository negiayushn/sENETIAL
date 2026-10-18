import { z } from 'zod';

const emptyToUndefined = (v: unknown) => (v === '' ? undefined : v);

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  API_PORT: z.coerce.number().int().positive().default(4000),
  API_URL: z.string().url().default('http://localhost:4000'),
  WEB_URL: z.string().url().default('http://localhost:3000'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),

  BETTER_AUTH_SECRET: z.string().min(32, 'BETTER_AUTH_SECRET must be at least 32 characters'),
  GITHUB_CLIENT_ID: z.preprocess(emptyToUndefined, z.string().optional()),
  GITHUB_CLIENT_SECRET: z.preprocess(emptyToUndefined, z.string().optional()),

  // GitHub App (Phase 3). All-or-nothing: either every value is set or the integration is off.
  GITHUB_APP_ID: z.preprocess(emptyToUndefined, z.string().optional()),
  GITHUB_APP_SLUG: z.preprocess(emptyToUndefined, z.string().optional()),
  GITHUB_APP_CLIENT_ID: z.preprocess(emptyToUndefined, z.string().optional()),
  GITHUB_APP_CLIENT_SECRET: z.preprocess(emptyToUndefined, z.string().optional()),
  GITHUB_APP_PRIVATE_KEY: z.preprocess(emptyToUndefined, z.string().optional()),
}).superRefine((env, ctx) => {
  const app = ['GITHUB_APP_ID', 'GITHUB_APP_SLUG', 'GITHUB_APP_CLIENT_ID', 'GITHUB_APP_CLIENT_SECRET', 'GITHUB_APP_PRIVATE_KEY'] as const;
  const set = app.filter((k) => env[k]);
  if (set.length > 0 && set.length < app.length) {
    for (const k of app.filter((k) => !env[k])) ctx.addIssue({ code: 'custom', path: [k], message: 'required when any GITHUB_APP_* value is set' });
  }
});

export type Env = z.infer<typeof envSchema>;

/** Used by ConfigModule: fail fast at boot with a readable message. */
export function validateEnv(raw: Record<string, unknown>): Env {
  const parsed = envSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  return parsed.data;
}
