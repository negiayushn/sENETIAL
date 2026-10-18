import { PrismaPg } from '@prisma/adapter-pg';

export * from './generated/client';

/** Prisma 7 needs a driver adapter. Use this when constructing a PrismaClient. */
export function prismaClientOptions(connectionString: string) {
  return { adapter: new PrismaPg({ connectionString }) };
}
