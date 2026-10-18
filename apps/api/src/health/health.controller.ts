import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';
import Redis from 'ioredis';
import { Public } from '../auth/decorators';
import { PrismaService } from '../prisma/prisma.service';
import { REDIS } from '../redis/redis.module';

type Check = 'up' | 'down';

@Public()
@Controller('health')
export class HealthController {
  constructor(private readonly prisma: PrismaService, @Inject(REDIS) private readonly redis: Redis) {}

  /** Liveness: the process is up. */
  @Get('live')
  live() {
    return { status: 'ok' };
  }

  /** Readiness: dependencies reachable. 503 if any is down. */
  @Get()
  async ready() {
    const [database, redis] = await Promise.all([
      this.prisma.$queryRaw`SELECT 1`.then((): Check => 'up', (): Check => 'down'),
      this.redis.ping().then((r): Check => (r === 'PONG' ? 'up' : 'down'), (): Check => 'down'),
    ]);
    const body = {
      status: database === 'up' && redis === 'up' ? 'ok' : 'degraded',
      uptimeSeconds: Math.round(process.uptime()),
      checks: { database, redis },
    };
    if (body.status !== 'ok') throw new ServiceUnavailableException(body);
    return body;
  }
}
