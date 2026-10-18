import { describe, expect, it } from 'vitest';
import { RateLimiter, RequestBudgetExceededError } from '../src';

describe('RateLimiter', () => {
  it('spaces concurrent callers by the minimum interval', async () => {
    const rl = new RateLimiter(100, 10);
    const t0 = Date.now();
    await Promise.all([rl.acquire(), rl.acquire(), rl.acquire()]);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(190);
  });

  it('enforces a hard request budget', async () => {
    const rl = new RateLimiter(0, 2);
    await rl.acquire();
    await rl.acquire();
    await expect(rl.acquire()).rejects.toBeInstanceOf(RequestBudgetExceededError);
    expect(rl.requestCount).toBe(2);
  });
});
