export interface PackageRef {
  name: string;
  version: string;
}
export interface VulnRef {
  id: string;
  /** ISO timestamp of the advisory's last change. Used to decide whether our cached copy is stale. */
  modified: string | null;
}

export class OsvError extends Error {
  constructor(message: string, readonly retryable: boolean, readonly status?: number) {
    super(message);
    this.name = 'OsvError';
  }
}

export interface OsvClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  /** Queries per /v1/querybatch request. OSV allows up to 1000; ~500 keeps requests small. */
  batchSize?: number;
  /** Parallel GET /v1/vulns/{id} requests. */
  concurrency?: number;
  maxRetries?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

const MAX_RESPONSE_BYTES = 20 * 1024 * 1024;
const MAX_PAGE_ROUNDS = 50;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,200}$/;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class OsvClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly batchSize: number;
  private readonly concurrency: number;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(opts: OsvClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? 'https://api.osv.dev').replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.batchSize = Math.min(Math.max(opts.batchSize ?? 500, 1), 1000);
    this.concurrency = Math.max(opts.concurrency ?? 8, 1);
    this.maxRetries = opts.maxRetries ?? 4;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.sleep = opts.sleep ?? defaultSleep;
  }

  /** JSON request with retry on network errors, 429 and 5xx (exponential backoff + jitter, honouring Retry-After). */
  private async request(path: string, init: { method: 'GET' | 'POST'; body?: unknown }): Promise<{ status: number; json: unknown }> {
    let lastErr: OsvError | undefined;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        const backoff = lastErr?.status === 429 || (lastErr?.status ?? 0) >= 500 || lastErr?.status === undefined ? 500 * 2 ** (attempt - 1) : 0;
        await this.sleep(Math.min(backoff + Math.random() * 250, 15_000));
      }
      let res: Response;
      try {
        res = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method: init.method,
          headers: { 'content-type': 'application/json', 'user-agent': 'sentinel/0.1' },
          body: init.body === undefined ? undefined : JSON.stringify(init.body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (err) {
        lastErr = new OsvError(`OSV request failed: ${(err as Error).message}`, true);
        continue;
      }
      if (res.status === 404 && init.method === 'GET') return { status: 404, json: null };
      if (res.status === 429 || res.status >= 500) {
        lastErr = new OsvError(`OSV responded ${res.status}`, true, res.status);
        const ra = Number(res.headers.get('retry-after'));
        if (Number.isFinite(ra) && ra > 0) await this.sleep(Math.min(ra * 1000, 30_000));
        continue;
      }
      if (!res.ok) throw new OsvError(`OSV responded ${res.status}`, false, res.status);
      const text = await res.text();
      if (text.length > MAX_RESPONSE_BYTES) throw new OsvError('OSV response too large', false);
      try {
        return { status: res.status, json: JSON.parse(text) };
      } catch {
        throw new OsvError('OSV returned invalid JSON', true);
      }
    }
    throw lastErr ?? new OsvError('OSV request failed', true);
  }

  /**
   * Which advisories affect each package@version, according to OSV. The response carries IDs (+ modified time) only.
   * Chunks of `batchSize`; any query that comes back with `next_page_token` is asked again with that token until done.
   * Key of the result map is `name@version`.
   */
  async queryBatch(packages: PackageRef[]): Promise<Map<string, VulnRef[]>> {
    const unique = [...new Map(packages.map((p) => [`${p.name}@${p.version}`, p])).values()];
    const result = new Map<string, VulnRef[]>();

    for (let i = 0; i < unique.length; i += this.batchSize) {
      let pending: { pkg: PackageRef; token?: string }[] = unique.slice(i, i + this.batchSize).map((pkg) => ({ pkg }));
      for (let round = 0; pending.length > 0; round++) {
        if (round >= MAX_PAGE_ROUNDS) throw new OsvError('OSV pagination did not terminate', false);
        const { json } = await this.request('/v1/querybatch', {
          method: 'POST',
          body: {
            queries: pending.map(({ pkg, token }) => ({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version, ...(token ? { page_token: token } : {}) })),
          },
        });
        const results = isObj(json) && Array.isArray(json.results) ? json.results : null;
        if (!results || results.length !== pending.length) throw new OsvError('OSV returned a malformed batch response', true);

        const next: typeof pending = [];
        results.forEach((r, idx) => {
          const { pkg } = pending[idx];
          const k = `${pkg.name}@${pkg.version}`;
          if (!isObj(r)) return;
          const list = result.get(k) ?? [];
          for (const v of Array.isArray(r.vulns) ? r.vulns : []) {
            if (isObj(v) && typeof v.id === 'string' && SAFE_ID.test(v.id)) list.push({ id: v.id, modified: typeof v.modified === 'string' ? v.modified : null });
          }
          if (list.length) result.set(k, list);
          if (typeof r.next_page_token === 'string' && r.next_page_token) next.push({ pkg, token: r.next_page_token });
        });
        pending = next;
      }
    }
    return result;
  }

  /** Full advisory record, or null if OSV no longer has it (404). */
  async getVuln(id: string): Promise<unknown | null> {
    if (!SAFE_ID.test(id)) throw new OsvError('Refusing to request a malformed advisory id', false);
    const { json } = await this.request(`/v1/vulns/${encodeURIComponent(id)}`, { method: 'GET' });
    return json;
  }

  /** Fetch many advisories with bounded parallelism. Missing ones map to null. Fails fast on a non-recoverable error. */
  async getVulns(ids: string[]): Promise<Map<string, unknown | null>> {
    const out = new Map<string, unknown | null>();
    const queue = [...new Set(ids)];
    let failure: unknown;
    const worker = async () => {
      while (queue.length && !failure) {
        const id = queue.shift()!;
        try {
          out.set(id, await this.getVuln(id));
        } catch (err) {
          failure = err;
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.concurrency, queue.length) }, worker));
    if (failure) throw failure;
    return out;
  }
}
