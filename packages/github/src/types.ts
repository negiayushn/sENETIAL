/** The only thing the rest of the code needs from Octokit. Lets tests pass a fake. */
export interface GhResponse {
  status: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any;
  headers: Record<string, string | number | undefined>;
}

export interface Requester {
  request(route: string, params?: Record<string, unknown>): Promise<GhResponse>;
}

export interface GithubAppConfig {
  appId: string;
  /** PEM, PEM with literal "\n" sequences (typical in .env files), or base64 of the PEM. */
  privateKey: string;
  /** Needed to verify, during install, that the signed-in user really has access to the installation. */
  clientId?: string;
  clientSecret?: string;
}

export class GithubFetchError extends Error {
  constructor(message: string, readonly retryable: boolean, readonly status?: number) {
    super(message);
    this.name = 'GithubFetchError';
  }
}

/**
 * Transient problems (network, 5xx, rate limiting) → retry. Everything else (revoked access, missing repo,
 * bad permissions) will not fix itself, so retrying only wastes API quota.
 */
export function classifyGithubError(err: unknown): { retryable: boolean; status?: number; message: string } {
  if (err instanceof GithubFetchError) return { retryable: err.retryable, status: err.status, message: err.message };
  const e = err as { status?: number; message?: string; response?: { headers?: Record<string, string | undefined> } };
  const status = typeof e?.status === 'number' ? e.status : undefined;
  const message = e?.message ?? 'GitHub request failed';
  if (status === undefined) return { retryable: true, message }; // network / timeout
  if (status >= 500 || status === 429) return { retryable: true, status, message };
  if (status === 403) {
    const h = e.response?.headers ?? {};
    const limited = h['x-ratelimit-remaining'] === '0' || h['retry-after'] !== undefined || /rate limit|abuse/i.test(message);
    return { retryable: limited, status, message };
  }
  return { retryable: false, status, message };
}
