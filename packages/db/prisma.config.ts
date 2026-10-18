import { defineConfig } from 'prisma/config';

// Env vars are injected by `dotenv -e ../../.env` in package scripts.
export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: { path: 'prisma/migrations' },
  datasource: { url: process.env.DATABASE_URL ?? '' },
});
