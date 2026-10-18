import { GithubFetchError, type Requester } from './types';

export interface RepoMeta {
  fullName: string;
  defaultBranch: string;
  archived: boolean;
  private: boolean;
}

export type LockfileFetch =
  | { kind: 'found'; repo: RepoMeta; commitSha: string; branch: string; path: 'package-lock.json'; lockfileText: string; packageJsonText?: string }
  /** Repo is readable but has nothing we can inventory. `note` says why (e.g. yarn.lock is not supported yet). */
  | { kind: 'none'; repo: RepoMeta; commitSha: string; branch: string; note: string }
  | { kind: 'empty'; repo: RepoMeta };

export const MAX_LOCKFILE_BYTES = 25 * 1024 * 1024;
const OTHER_LOCKFILES: Record<string, string> = { 'yarn.lock': 'yarn.lock', 'pnpm-lock.yaml': 'pnpm-lock.yaml', 'npm-shrinkwrap.json': 'npm-shrinkwrap.json' };

/* eslint-disable @typescript-eslint/no-explicit-any */

async function readBlob(req: Requester, owner: string, repo: string, sha: string, expectedMax: number): Promise<string> {
  // Git Blobs API (not Contents): works up to 100 MB, whereas Contents only inlines files up to 1 MB and
  // real-world lockfiles are often bigger. Nothing is cloned and no package manager ever runs.
  const { data } = await req.request('GET /repos/{owner}/{repo}/git/blobs/{file_sha}', { owner, repo, file_sha: sha });
  if (typeof data.size === 'number' && data.size > expectedMax) throw new GithubFetchError(`File is larger than ${expectedMax} bytes`, false);
  if (data.encoding !== 'base64') throw new GithubFetchError(`Unexpected blob encoding: ${String(data.encoding)}`, false);
  return Buffer.from(String(data.content).replace(/\s/g, ''), 'base64').toString('utf8');
}

/**
 * Reads the root package-lock.json (and package.json) of the repository's default branch via the Git Trees/Blobs API.
 * Addressed by numeric repository id, so a rename or transfer cannot point us at somebody else's repo.
 */
export async function fetchNpmLockfile(req: Requester, repoId: string, maxLockfileBytes = MAX_LOCKFILE_BYTES): Promise<LockfileFetch> {
  const { data: r } = await req.request('GET /repositories/{repository_id}', { repository_id: Number(repoId) });
  const [owner, name] = String(r.full_name).split('/');
  const repo: RepoMeta = { fullName: String(r.full_name), defaultBranch: String(r.default_branch ?? 'main'), archived: Boolean(r.archived), private: Boolean(r.private) };
  const branch = repo.defaultBranch;

  // Newest commit on the default branch. `sha` is a query parameter, so branch names containing "/" are safe.
  let commit: any;
  try {
    const { data } = await req.request('GET /repos/{owner}/{repo}/commits', { owner, repo: name, sha: branch, per_page: 1 });
    commit = Array.isArray(data) ? data[0] : undefined;
  } catch (err) {
    if ((err as { status?: number }).status === 409) return { kind: 'empty', repo }; // "Git Repository is empty."
    throw err;
  }
  if (!commit) return { kind: 'empty', repo };
  const commitSha = String(commit.sha);
  const treeSha = String(commit.commit?.tree?.sha);

  const { data: tree } = await req.request('GET /repos/{owner}/{repo}/git/trees/{tree_sha}', { owner, repo: name, tree_sha: treeSha });
  const entries: any[] = tree.tree ?? [];
  const blob = (path: string) => entries.find((e) => e.path === path && e.type === 'blob');

  const lock = blob('package-lock.json');
  if (!lock) {
    const other = entries.find((e) => e.type === 'blob' && OTHER_LOCKFILES[e.path]);
    const note = other
      ? `Found ${other.path}, which is not supported yet. Only package-lock.json can be inventoried right now.`
      : 'No package-lock.json in the repository root.';
    return { kind: 'none', repo, commitSha, branch, note };
  }
  if (typeof lock.size === 'number' && lock.size > maxLockfileBytes) {
    throw new GithubFetchError(`package-lock.json is larger than ${Math.round(maxLockfileBytes / 1024 / 1024)} MiB`, false);
  }

  const lockfileText = await readBlob(req, owner, name, lock.sha, maxLockfileBytes);
  const pkg = blob('package.json');
  const packageJsonText = pkg ? await readBlob(req, owner, name, pkg.sha, 5 * 1024 * 1024).catch(() => undefined) : undefined;

  return { kind: 'found', repo, commitSha, branch, path: 'package-lock.json', lockfileText, packageJsonText };
}
