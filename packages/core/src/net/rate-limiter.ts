export class RequestBudgetExceededError extends Error {
  constructor(max: number) {
    super(`Request budget exceeded (${max} requests per scan)`);
    this.name = 'RequestBudgetExceededError';
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Per-target pacing + hard request budget. One instance is created per scan and shared by every
 * outbound connection the scan makes (HTTP and TLS), so the target never sees more than
 * 1000/minIntervalMs requests per second or more than `maxRequests` in total.
 *
 * Slots are reserved synchronously, so concurrent callers queue up in order rather than racing.
 */
export class RateLimiter {
  private nextSlot = 0;
  private used = 0;

  constructor(private readonly minIntervalMs = 250, private readonly maxRequests = 60) {}

  get requestCount() {
    return this.used;
  }

  async acquire(): Promise<void> {
    if (this.used >= this.maxRequests) throw new RequestBudgetExceededError(this.maxRequests);
    this.used++;
    const now = Date.now();
    const start = Math.max(now, this.nextSlot);
    this.nextSlot = start + this.minIntervalMs;
    if (start > now) await sleep(start - now);
  }
}
