import { randomBytes } from 'node:crypto';
import type { Requester } from './types';

export interface InstallationInfo {
  id: string;
  accountLogin: string;
  accountType: string;
  repositorySelection: string;
  suspendedAt: Date | null;
}

export interface RepoInfo {
  id: string;
  owner: string;
  name: string;
  fullName: string;
  defaultBranch: string;
  private: boolean;
  archived: boolean;
}

const MAX_PAGES = 20; // 2 000 repositories; more than that needs a deliberate design, not an unbounded loop

/* eslint-disable @typescript-eslint/no-explicit-any */
export const toRepoInfo = (r: any): RepoInfo => ({
  id: String(r.id),
  owner: String(r.owner?.login ?? r.full_name?.split('/')[0] ?? ''),
  name: String(r.name),
  fullName: String(r.full_name),
  defaultBranch: String(r.default_branch ?? 'main'),
  private: Boolean(r.private),
  archived: Boolean(r.archived),
});

export async function getInstallation(app: Requester, installationId: string): Promise<InstallationInfo> {
  const { data } = await app.request('GET /app/installations/{installation_id}', { installation_id: Number(installationId) });
  return {
    id: String(data.id),
    accountLogin: String(data.account?.login ?? data.account?.slug ?? 'unknown'),
    accountType: String(data.account?.type ?? 'User'),
    repositorySelection: String(data.repository_selection ?? 'selected'),
    suspendedAt: data.suspended_at ? new Date(data.suspended_at) : null,
  };
}

/** Repositories the installation can see (with an installation token). */
export async function listInstallationRepos(installation: Requester): Promise<RepoInfo[]> {
  const out: RepoInfo[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { data } = await installation.request('GET /installation/repositories', { per_page: 100, page });
    const repos: any[] = data.repositories ?? [];
    out.push(...repos.map(toRepoInfo));
    if (repos.length < 100) break;
  }
  return out;
}

/**
 * THE check that stops installation-id spoofing: the callback URL carries an `installation_id` the user can edit.
 * With "Request user authorization during installation" enabled, GitHub also sends an OAuth `code`; the user token it
 * yields lists only installations that user can really access. Without this, anyone could claim anyone's installation.
 */
export async function userCanAccessInstallation(user: Requester, installationId: string): Promise<boolean> {
  for (let page = 1; page <= 10; page++) {
    const { data } = await user.request('GET /user/installations', { per_page: 100, page });
    const list: any[] = data.installations ?? [];
    if (list.some((i) => String(i.id) === String(installationId))) return true;
    if (list.length < 100) return false;
  }
  return false;
}

/* ───────── CSRF state for the install redirect ───────── */

export interface StateStore {
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  /** Atomic read-and-delete, so a state value can be used exactly once. */
  getdel(key: string): Promise<string | null>;
}

const STATE_TTL = 10 * 60;
const stateKey = (state: string) => `sentinel:gh-install-state:${state}`;

export async function createInstallState(store: StateStore, userId: string): Promise<string> {
  const state = randomBytes(24).toString('hex');
  await store.set(stateKey(state), userId, STATE_TTL);
  return state;
}

/** Returns the user who started the flow, or null if the state is unknown, expired or already used. */
export async function consumeInstallState(store: StateStore, state: string | undefined): Promise<string | null> {
  if (!state || !/^[0-9a-f]{48}$/.test(state)) return null;
  return store.getdel(stateKey(state));
}

export const installUrl = (slug: string, state: string) =>
  `https://github.com/apps/${encodeURIComponent(slug)}/installations/new?state=${encodeURIComponent(state)}`;
