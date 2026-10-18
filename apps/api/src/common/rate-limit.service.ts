import { Global, HttpException, HttpStatus, Inject, Injectable, Module } from '@nestjs/common';
import type Redis from 'ioredis';
import { REDIS } from '../redis/redis.module';

// Atomic: INCR and, on first hit, set the expiry. (INCR-then-EXPIRE as two calls can leave a key with no TTL.)
const HIT = `local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end; return {n, redis.call('TTL', KEYS[1])}`;

@Injectable()
export class RateLimitService {
  constructor(@Inject(REDIS) private readonly redis: Redis) {}

  /** Fixed-window counter. Throws 429 once `limit` hits have happened in `windowSec`. */
  async hit(key: string, limit: number, windowSec: number, what: string): Promise<void> {
    const [count, ttl] = (await this.redis.eval(HIT, 1, `sentinel:rl:${key}`, windowSec)) as [number, number];
    if (count > limit) {
      throw new HttpException(
        { statusCode: 429, message: `Too many ${what}. Try again in ${Math.max(ttl, 1)}s.`, retryAfterSeconds: Math.max(ttl, 1) },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }
}

@Global()
@Module({ providers: [RateLimitService], exports: [RateLimitService] })
export class RateLimitModule {}
