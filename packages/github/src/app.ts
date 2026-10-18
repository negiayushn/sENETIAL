import { normalizePrivateKey } from './config';
import type { GithubAppConfig, Requester } from './types';

export interface GithubApp {
  /** Authenticated as the App itself (short-lived JWT). Only for /app/* endpoints. */
  appRequester(): Promise<Requester>;
  /**
   * Authenticated as one installation. The token is minted on demand, lives for ≤1 hour, is held in memory only,
   * and can be narrowed to specific repositories / permissions so a job only ever holds the access it needs.
   */
  installationRequester(installationId: string, scope?: { repositoryIds?: number[]; permissions?: Record<string, 'read' | 'write'> }): Promise<Requester>;
  /** Exchange the OAuth `code` from the install redirect for a user token (kept in memory, discarded after use). */
  userRequesterFromCode(code: string): Promise<Requester>;
}

/**
 * Octokit v7/v8 are ESM-only while this repo compiles to CommonJS, so they are loaded with dynamic import().
 * (TypeScript keeps `import()` as-is under module=nodenext.)
 */
export function createGithubApp(config: GithubAppConfig): GithubApp {
  const privateKey = normalizePrivateKey(config.privateKey);

  async function auth() {
    const { createAppAuth } = await import('@octokit/auth-app');
    return createAppAuth({
      appId: config.appId,
      privateKey,
      ...(config.clientId && config.clientSecret ? { clientId: config.clientId, clientSecret: config.clientSecret } : {}),
    });
  }

  async function requesterFor(token: string): Promise<Requester> {
    const { Octokit } = await import('@octokit/core');
    const octokit = new Octokit({ auth: token, userAgent: 'sentinel/0.1', request: { timeout: 20_000 } });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return { request: (route, params) => (octokit.request as any)(route, params) };
  }

  return {
    async appRequester() {
      const a = await auth();
      const { token } = await a({ type: 'app' });
      return requesterFor(token);
    },
    async installationRequester(installationId, scope = {}) {
      const a = await auth();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { token } = await (a as any)({ type: 'installation', installationId: Number(installationId), ...scope });
      return requesterFor(token);
    },
    async userRequesterFromCode(code) {
      if (!config.clientId || !config.clientSecret) throw new Error('GitHub App client id/secret are not configured');
      const a = await auth();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { token } = await (a as any)({ type: 'oauth-user', code });
      return requesterFor(token);
    },
  };
}
