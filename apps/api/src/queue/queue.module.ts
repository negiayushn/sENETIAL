import { Global, Inject, Injectable, Module, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { INVENTORY_QUEUE, MATCH_QUEUE, redisConnectionFromUrl, SCAN_QUEUE, type InventoryJobData, type MatchJobData, type ScanJobData } from '@sentinel/core';
import { Queue } from 'bullmq';
import type { Env } from '../config/env';

export const SCAN_QUEUE_TOKEN = Symbol('SCAN_QUEUE');
export type ScanQueue = Queue<ScanJobData>;
export const INVENTORY_QUEUE_TOKEN = Symbol('INVENTORY_QUEUE');
export type InventoryQueue = Queue<InventoryJobData>;
export const MATCH_QUEUE_TOKEN = Symbol('MATCH_QUEUE');
export type MatchQueue = Queue<MatchJobData>;

@Injectable()
class QueueShutdown implements OnApplicationShutdown {
  constructor(@Inject(SCAN_QUEUE_TOKEN) private readonly queue: ScanQueue, @Inject(INVENTORY_QUEUE_TOKEN) private readonly inventory: InventoryQueue, @Inject(MATCH_QUEUE_TOKEN) private readonly match: MatchQueue) {}
  async onApplicationShutdown() {
    await Promise.all([this.queue.close(), this.inventory.close(), this.match.close()]);
  }
}

@Global()
@Module({
  providers: [
    {
      provide: SCAN_QUEUE_TOKEN,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>): ScanQueue =>
        new Queue<ScanJobData>(SCAN_QUEUE, { connection: redisConnectionFromUrl(config.get('REDIS_URL', { infer: true })) }).on('error', () => undefined),
    },
    {
      provide: INVENTORY_QUEUE_TOKEN,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>): InventoryQueue =>
        new Queue<InventoryJobData>(INVENTORY_QUEUE, { connection: redisConnectionFromUrl(config.get('REDIS_URL', { infer: true })) }).on('error', () => undefined),
    },
    {
      provide: MATCH_QUEUE_TOKEN,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>): MatchQueue =>
        new Queue<MatchJobData>(MATCH_QUEUE, { connection: redisConnectionFromUrl(config.get('REDIS_URL', { infer: true })) }).on('error', () => undefined),
    },
    QueueShutdown,
  ],
  exports: [SCAN_QUEUE_TOKEN, INVENTORY_QUEUE_TOKEN, MATCH_QUEUE_TOKEN],
})
export class QueueModule {}
