import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  classifyGithubError, consumeInstallState, createInstallState, fetchNpmLockfile, GithubFetchError, installUrl, listInstallationRepos,
  normalizePrivateKey, userCanAccessInstallation, type GhResponse, type Requester, type StateStore,
} from '../src';

type Handler = (p: any) => unknown;
function fake(routes: Record<string, Handler>, calls: string[] = []): Requester {
  return {
    async request(route, params = {}): Promise<GhResponse> {
      calls.push(route);
      const h = routes[route];
      if (!h) throw Object.assign(new Error(`unexpected route ${route}`), { status: 500 });
      return { status: 200, data: await h(params), headers: {} };
    },
  };
}
const b64 = (s: string) => Buffer.from(s).toString('base64');
const repoRoute = { 'GET /repositories/{repository_id}': () => ({ id: 42, full_name: 'acme/app', default_branch: 'main', archived: false, private: true }) };
const commitRoute = { 'GET /repos/{owner}/{repo}/commits': () => [{ sha: 'c0ffee', commit: { tree: { sha: 'tree1' } } }] };
const treeRoute = (entries: object[]) => ({ 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}': () => ({ tree: entries }) });

describe('normalizePrivateKey', () => {
  const pem = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;
  it('accepts a real PEM, a PEM with literal \\n (.env style), and base64', () => {
    expect(normalizePrivateKey(pem)).toBe(pem.trim());
    expect(normalizePrivateKey(pem.trim().replace(/\n/g, '\\n'))).toBe(pem.trim());
    expect(normalizePrivateKey(Buffer.from(pem).toString('base64'))).toBe(pem.trim());
  });
  it('rejects garbage without echoing it', () => {
    expect(() => normalizePrivateKey('hunter2')).toThrow(/not a PEM/);
    try { normalizePrivateKey('hunter2'); } catch (e) { expect(String(e)).not.toContain('hunter2'); }
  });
});

describe('fetchNpmLockfile', () => {
  const lock = '{"lockfileVersion":3,"packages":{"":{}}}';
  const pkg = '{"name":"app"}';

  it('reads package-lock.json and package.json via trees + blobs (no clone, no contents API)', async () => {
    const calls: string[] = [];
    const req = fake({
      ...repoRoute, ...commitRoute,
      ...treeRoute([{ path: 'package-lock.json', type: 'blob', sha: 'L', size: 40 }, { path: 'package.json', type: 'blob', sha: 'P', size: 15 }, { path: 'src', type: 'tree', sha: 'S' }]),
      'GET /repos/{owner}/{repo}/git/blobs/{file_sha}': (p) => ({ encoding: 'base64', size: 1, content: b64(p.file_sha === 'L' ? lock : pkg).replace(/(.{20})/g, '$1\n') }),
    }, calls);
    const r = await fetchNpmLockfile(req, '42');
    expect(r).toMatchObject({ kind: 'found', commitSha: 'c0ffee', branch: 'main', path: 'package-lock.json', lockfileText: lock, packageJsonText: pkg });
    expect(calls.some((c) => c.includes('/contents/'))).toBe(false);
    expect(calls.some((c) => c.includes('clone'))).toBe(false);
  });

  it('addresses the repo by numeric id and takes owner/name from GitHub (rename-safe)', async () => {
    let seen: any;
    const req = fake({ ...repoRoute, 'GET /repos/{owner}/{repo}/commits': (p) => ((seen = p), []) , });
    await fetchNpmLockfile(req, '42');
    expect(seen).toMatchObject({ owner: 'acme', repo: 'app', sha: 'main', per_page: 1 });
  });

  it('reports a missing lockfile, and a yarn/pnpm lockfile as "not supported yet"', async () => {
    const none = await fetchNpmLockfile(fake({ ...repoRoute, ...commitRoute, ...treeRoute([{ path: 'README.md', type: 'blob', sha: 'x' }]) }), '42');
    expect(none).toMatchObject({ kind: 'none', note: expect.stringMatching(/No package-lock\.json/) });
    const yarn = await fetchNpmLockfile(fake({ ...repoRoute, ...commitRoute, ...treeRoute([{ path: 'yarn.lock', type: 'blob', sha: 'y' }]) }), '42');
    expect(yarn).toMatchObject({ kind: 'none', note: expect.stringMatching(/yarn\.lock.*not supported yet/) });
  });

  it('treats an empty repository (409) as empty, not as an error', async () => {
    const req = fake({ ...repoRoute, 'GET /repos/{owner}/{repo}/commits': () => { throw Object.assign(new Error('Git Repository is empty.'), { status: 409 }); } });
    expect(await fetchNpmLockfile(req, '42')).toMatchObject({ kind: 'empty' });
  });

  it('refuses an oversized lockfile BEFORE downloading it, and as non-retryable', async () => {
    const calls: string[] = [];
    const req = fake({ ...repoRoute, ...commitRoute, ...treeRoute([{ path: 'package-lock.json', type: 'blob', sha: 'L', size: 999_999_999 }]) }, calls);
    const err = await fetchNpmLockfile(req, '42').catch((e) => e);
    expect(err).toBeInstanceOf(GithubFetchError);
    expect(err.retryable).toBe(false);
    expect(calls.some((c) => c.includes('git/blobs'))).toBe(false);
  });

  it('ignores a directory called package-lock.json (type must be blob)', async () => {
    const r = await fetchNpmLockfile(fake({ ...repoRoute, ...commitRoute, ...treeRoute([{ path: 'package-lock.json', type: 'tree', sha: 'x' }]) }), '42');
    expect(r.kind).toBe('none');
  });

  it('a broken package.json blob does not fail the inventory', async () => {
    const req = fake({
      ...repoRoute, ...commitRoute,
      ...treeRoute([{ path: 'package-lock.json', type: 'blob', sha: 'L', size: 5 }, { path: 'package.json', type: 'blob', sha: 'P', size: 5 }]),
      'GET /repos/{owner}/{repo}/git/blobs/{file_sha}': (p) => { if (p.file_sha === 'P') throw Object.assign(new Error('boom'), { status: 500 }); return { encoding: 'base64', content: b64(lock) }; },
    });
    expect(await fetchNpmLockfile(req, '42')).toMatchObject({ kind: 'found', packageJsonText: undefined });
  });
});

describe('install flow security', () => {
  const memory = (): StateStore & { data: Map<string, string> } => {
    const data = new Map<string, string>();
    return { data, async set(k, v) { data.set(k, v); }, async getdel(k) { const v = data.get(k) ?? null; data.delete(k); return v; } };
  };

  it('state is bound to the user, unguessable, and single-use', async () => {
    const store = memory();
    const state = await createInstallState(store, 'user-1');
    expect(state).toMatch(/^[0-9a-f]{48}$/);
    expect(await consumeInstallState(store, state)).toBe('user-1');
    expect(await consumeInstallState(store, state)).toBeNull(); // replay
  });
  it('rejects missing, malformed, or unknown state without touching the store', async () => {
    const store = memory();
    for (const s of [undefined, '', 'abc', 'x'.repeat(48), '../../etc']) expect(await consumeInstallState(store, s)).toBeNull();
  });
  it('builds the install URL with an encoded slug and state', () => {
    expect(installUrl('my app', 'abc')).toBe('https://github.com/apps/my%20app/installations/new?state=abc');
  });

  it('userCanAccessInstallation: true only if the USER token can see that installation (blocks id spoofing)', async () => {
    const user = fake({ 'GET /user/installations': () => ({ installations: [{ id: 111 }, { id: 222 }] }) });
    expect(await userCanAccessInstallation(user, '222')).toBe(true);
    expect(await userCanAccessInstallation(user, '999')).toBe(false);
  });
  it('userCanAccessInstallation pages through results', async () => {
    const user = fake({ 'GET /user/installations': (p) => ({ installations: p.page === 1 ? Array.from({ length: 100 }, (_, i) => ({ id: i + 1 })) : [{ id: 5000 }] }) });
    expect(await userCanAccessInstallation(user, '5000')).toBe(true);
  });
});

describe('listInstallationRepos', () => {
  it('maps and paginates', async () => {
    const mk = (i: number) => ({ id: i, name: `r${i}`, full_name: `acme/r${i}`, owner: { login: 'acme' }, default_branch: 'trunk', private: i % 2 === 0, archived: false });
    const inst = fake({ 'GET /installation/repositories': (p) => ({ repositories: p.page === 1 ? Array.from({ length: 100 }, (_, i) => mk(i + 1)) : [mk(101)] }) });
    const repos = await listInstallationRepos(inst);
    expect(repos).toHaveLength(101);
    expect(repos[0]).toEqual({ id: '1', owner: 'acme', name: 'r1', fullName: 'acme/r1', defaultBranch: 'trunk', private: false, archived: false });
  });
});

describe('classifyGithubError', () => {
  it.each([
    [{ status: 500 }, true], [{ status: 502 }, true], [{ status: 429 }, true], [{}, true],
    [{ status: 404 }, false], [{ status: 401 }, false], [{ status: 422 }, false],
    [{ status: 403, message: 'Resource not accessible by integration' }, false],
    [{ status: 403, message: 'API rate limit exceeded' }, true],
    [{ status: 403, response: { headers: { 'x-ratelimit-remaining': '0' } } }, true],
    [{ status: 403, response: { headers: { 'retry-after': '30' } } }, true],
  ])('%j -> retryable=%s', (err, retryable) => expect(classifyGithubError(err).retryable).toBe(retryable));
  it('respects GithubFetchError.retryable', () => {
    expect(classifyGithubError(new GithubFetchError('x', false)).retryable).toBe(false);
  });
});
