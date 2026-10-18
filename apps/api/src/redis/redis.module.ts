import { Global, Inject, Injectable, Module, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import type { Env } from '../config/env';

export const REDIS = Symbol('REDIS');

@Injectable()
class RedisShutdown implements OnApplicationShutdown {
  constructor(@Inject(REDIS) private readonly redis: Redis) {}
  async onApplicationShutdown() {
    this.redis.disconnect();
  }
}

/** Shared connection for health checks now; BullMQ (Phase 2+) will build its own connections from REDIS_URL. */
@Global()
@Module({
  providers: [
    {
      provide: REDIS,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) =>
        new Redis(config.get('REDIS_URL', { infer: true }), {
          maxRetriesPerRequest: 1,
          lazyConnect: false,
          enableOfflineQueue: false,
        }).on('error', () => undefined), // errors surface through /health, not as unhandled events
    },
    RedisShutdown,
  ],
  exports: [REDIS],
})
export class RedisModule {}
