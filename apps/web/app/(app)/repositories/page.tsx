'use client';
import { useEffect, useState } from 'react';
import { api, useApi } from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, ErrorNote, PageHeader } from '@/components/ui/card';

type Status = 'NONE' | 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'NO_LOCKFILE' | 'FAILED';
type Repo = {
  id: string; fullName: string; private: boolean; archived: boolean; defaultBranch: string;
  inventoryStatus: Status; inventoryError: string | null; lastInventoryAt: string | null;
  installation: { id: string; accountLogin: string; suspended: boolean };
  latestSnapshot: {
    commitSha: string; packageCount: number; directCount: number; lockfileVersion: number; createdAt: string;
    matchStatus: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED'; matchedAt: string | null; matchError: string | null;
    matchSummary: { findings?: { total: number; potential: number; bySeverity: Record<string, number> }; resolvedSinceLastMatch?: number } | null;
  } | null;
};
type Installation = { id: string; accountLogin: string; accountType: string; repositorySelection: string; suspended: boolean; repositoryCount: number };
type Pkg = { id: string; name: string; version: string; path: string; dev: boolean; optional: boolean; direct: boolean; source: string };
type Inventory = { snapshot: { commitSha: string } | null; total: number; packages: Pkg[] };

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

function VulnLine({ snap }: { snap: NonNullable<Repo['latestSnapshot']> }) {
  if (snap.matchStatus === 'PENDING' || snap.matchStatus === 'RUNNING') {
    return <p className="mt-3 text-xs text-muted">Checking dependencies against known vulnerabilities…{snap.matchError ? ` (${snap.matchError})` : ''}</p>;
  }
  if (snap.matchStatus === 'FAILED') return <p className="mt-3 text-xs text-sev-high">Vulnerability check failed: {snap.matchError ?? 'unknown error'}</p>;
  const f = snap.matchSummary?.findings;
  if (!f) return null;
  if (f.total === 0) return <p className="mt-3 text-xs text-muted">No known vulnerabilities in {snap.packageCount} packages.</p>;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
      <span className="text-muted">{f.total} known {f.total === 1 ? 'vulnerability' : 'vulnerabilities'}:</span>
      {SEV_ORDER.filter((sev) => (f.bySeverity[sev] ?? 0) > 0).map((sev) => (
        <span key={sev} className="flex items-center gap-1"><Badge kind={sev}>{sev}</Badge><span className="font-mono">{f.bySeverity[sev]}</span></span>
      ))}
      {f.potential > 0 && <span className="text-muted">({f.potential} potential)</span>}
      <a href="/findings" className="underline underline-offset-2">View findings</a>
    </div>
  );
}

const STATUS_BADGE: Record<Status, { kind: 'OK' | 'MEDIUM' | 'HIGH' | 'NEUTRAL' | 'INFO'; label: string }> = {
  NONE: { kind: 'NEUTRAL', label: 'Not inventoried' },
  QUEUED: { kind: 'INFO', label: 'Queued' },
  RUNNING: { kind: 'INFO', label: 'Running' },
  SUCCEEDED: { kind: 'OK', label: 'Inventoried' },
  NO_LOCKFILE: { kind: 'MEDIUM', label: 'No lockfile' },
  FAILED: { kind: 'HIGH', label: 'Failed' },
};

// Fixed vocabulary from the API callback redirect; unknown values show nothing.
const BANNERS: Record<string, { text: string; error?: boolean }> = {
  connected: { text: 'GitHub connected. Your repositories are listed below.' },
  pending: { text: 'The installation is waiting for approval from an owner of the GitHub organisation.' },
  invalid_state: { text: 'That GitHub connection link was invalid or already used. Please start again.', error: true },
  no_code: { text: 'GitHub did not send an authorisation code. In the GitHub App settings, enable “Request user authorization (OAuth) during installation”.', error: true },
  no_access: { text: 'Your GitHub account does not have access to that installation.', error: true },
  not_configured: { text: 'The GitHub integration is not configured on this server.', error: true },
  failed: { text: 'Connecting to GitHub failed. Please try again.', error: true },
};

export default function RepositoriesPage() {
  const gh = useApi<{ configured: boolean }>('/github/status');
  const repos = useApi<Repo[]>('/repositories');
  const installs = useApi<Installation[]>('/github/installations');
  const [banner, setBanner] = useState<{ text: string; error?: boolean } | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [inv, setInv] = useState<Inventory | null>(null);

  useEffect(() => {
    const code = new URLSearchParams(window.location.search).get('github');
    if (code && BANNERS[code]) setBanner(BANNERS[code]);
    if (code) window.history.replaceState(null, '', '/repositories');
  }, []);

  // Poll while anything is in flight.
  const active = repos.data?.some((r) => r.inventoryStatus === 'QUEUED' || r.inventoryStatus === 'RUNNING' || r.latestSnapshot?.matchStatus === 'PENDING' || r.latestSnapshot?.matchStatus === 'RUNNING') ?? false;
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => void repos.reload(), 3000);
    return () => clearInterval(t);
  }, [active, repos]);

  async function run<T>(key: string, fn: () => Promise<T>, after?: () => Promise<void>) {
    setBusy(key);
    setActionError(null);
    try {
      await fn();
      await after?.();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Something went wrong');
    } finally {
      setBusy(null);
    }
  }

  const connect = () => run('connect', async () => {
    const { url } = await api<{ url: string }>('/github/install');
    window.location.href = url;
  });
  const reloadAll = async () => { await Promise.all([repos.reload(), installs.reload()]); };
  const inventory = (id: string) => run(`inv:${id}`, () => api(`/repositories/${id}/inventory`, { method: 'POST' }), reloadAll);
  const match = (id: string) => run(`match:${id}`, () => api(`/repositories/${id}/match`, { method: 'POST' }), reloadAll);
  const sync = (id: string) => run(`sync:${id}`, () => api(`/github/installations/${id}/sync`, { method: 'POST' }), reloadAll);
  const disconnect = (id: string) => {
    if (!confirm('Disconnect this GitHub installation? Its repositories and dependency snapshots will be removed from Sentinel. (You can also uninstall the app on GitHub.)')) return;
    return run(`dis:${id}`, () => api(`/github/installations/${id}`, { method: 'DELETE' }), reloadAll);
  };
  async function togglePackages(id: string) {
    if (open === id) return setOpen(null);
    setOpen(id);
    setInv(null);
    try {
      setInv(await api<Inventory>(`/repositories/${id}/inventory?take=100`));
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Could not load packages');
    }
  }

  return (
    <>
      <PageHeader title="Repositories" subtitle="Connect GitHub to inventory your npm dependencies. Sentinel has read-only access and never clones or runs your code." />

      {banner && <div className="mb-4">{banner.error ? <ErrorNote message={banner.text} /> : <Card className="p-3 text-sm">{banner.text}</Card>}</div>}
      {actionError && <div className="mb-4"><ErrorNote message={actionError} /></div>}

      {gh.data && !gh.data.configured && (
        <Card className="mb-6 p-4 text-sm text-muted">The GitHub integration is not configured on this server. See the Phase 3 section of the README to set up the GitHub App.</Card>
      )}

      {gh.data?.configured && (
        <Card className="mb-6 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium">GitHub</p>
              <p className="text-xs text-muted">{installs.data?.length ? 'Add another account or organisation, or change which repositories are shared.' : 'Install the Sentinel GitHub App and choose which repositories it can read.'}</p>
            </div>
            <Button onClick={connect} disabled={busy === 'connect'}>{busy === 'connect' ? 'Redirecting…' : installs.data?.length ? 'Connect another account' : 'Connect GitHub'}</Button>
          </div>
          {installs.data && installs.data.length > 0 && (
            <ul className="mt-4 divide-y divide-line border-t border-line">
              {installs.data.map((i) => (
                <li key={i.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                  <span>
                    <span className="font-mono">{i.accountLogin}</span>
                    <span className="ml-2 text-xs text-muted">{i.accountType} · {i.repositorySelection === 'all' ? 'all repositories' : 'selected repositories'} · {i.repositoryCount} visible</span>
                    {i.suspended && <span className="ml-2"><Badge kind="HIGH">Suspended</Badge></span>}
                  </span>
                  <span className="flex gap-1">
                    <Button variant="ghost" size="sm" disabled={busy === `sync:${i.id}`} onClick={() => sync(i.id)}>{busy === `sync:${i.id}` ? 'Syncing…' : 'Sync repositories'}</Button>
                    <Button variant="ghost" size="sm" disabled={busy === `dis:${i.id}`} onClick={() => disconnect(i.id)}>Disconnect</Button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {repos.error && <ErrorNote message={repos.error} />}
      {repos.loading && !repos.data && <p className="text-sm text-muted">Loading…</p>}
      {repos.data && repos.data.length === 0 && gh.data?.configured && <p className="text-sm text-muted">No repositories yet. Connect GitHub above.</p>}

      <div className="space-y-3">
        {repos.data?.map((r) => {
          const s = STATUS_BADGE[r.inventoryStatus];
          const inFlight = r.inventoryStatus === 'QUEUED' || r.inventoryStatus === 'RUNNING';
          return (
            <Card key={r.id} className="p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-mono text-sm">{r.fullName}</p>
                  <p className="mt-0.5 text-xs text-muted">
                    {r.private ? 'Private' : 'Public'}{r.archived ? ' · archived' : ''} · {r.defaultBranch}
                    {r.latestSnapshot && ` · ${r.latestSnapshot.packageCount} packages (${r.latestSnapshot.directCount} direct) at ${r.latestSnapshot.commitSha.slice(0, 7)}`}
                    {r.lastInventoryAt && ` · ${new Date(r.lastInventoryAt).toLocaleString()}`}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge kind={s.kind}>{s.label}</Badge>
                  {r.latestSnapshot && <Button variant="ghost" size="sm" onClick={() => togglePackages(r.id)}>{open === r.id ? 'Hide packages' : 'Packages'}</Button>}
                  {r.latestSnapshot && (
                    <Button variant="ghost" size="sm" disabled={r.latestSnapshot.matchStatus === 'RUNNING' || r.latestSnapshot.matchStatus === 'PENDING' || busy === `match:${r.id}`} onClick={() => match(r.id)}>
                      Re-check vulnerabilities
                    </Button>
                  )}
                  <Button variant="outline" size="sm" disabled={inFlight || r.installation.suspended || busy === `inv:${r.id}`} onClick={() => inventory(r.id)}>
                    {inFlight ? 'In progress…' : r.latestSnapshot ? 'Re-run inventory' : 'Run inventory'}
                  </Button>
                </div>
              </div>
              {r.inventoryError && (r.inventoryStatus === 'FAILED' || r.inventoryStatus === 'NO_LOCKFILE' || r.inventoryStatus === 'QUEUED') && (
                <p className={`mt-3 text-xs ${r.inventoryStatus === 'FAILED' ? 'text-sev-high' : 'text-muted'}`}>{r.inventoryError}</p>
              )}
              {r.latestSnapshot && <VulnLine snap={r.latestSnapshot} />}
              {open === r.id && (
                <div className="mt-4 overflow-x-auto rounded-md border border-line bg-bg">
                  {!inv ? <p className="p-3 text-xs text-muted">Loading…</p> : (
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="text-muted"><tr><th className="px-3 py-2">Package</th><th className="px-3 py-2">Version</th><th className="px-3 py-2">Kind</th><th className="px-3 py-2">Path</th></tr></thead>
                      <tbody>
                        {inv.packages.map((p) => (
                          <tr key={p.id} className="border-t border-line">
                            <td className="px-3 py-1.5">{p.name}</td>
                            <td className="px-3 py-1.5">{p.version}</td>
                            <td className="px-3 py-1.5 text-muted">{p.direct ? 'direct' : 'transitive'}{p.dev ? ' · dev' : ''}{p.source !== 'registry' ? ` · ${p.source}` : ''}</td>
                            <td className="px-3 py-1.5 text-muted break-all">{p.path}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  {inv && inv.total > inv.packages.length && <p className="border-t border-line p-2 text-xs text-muted">Showing {inv.packages.length} of {inv.total} (direct dependencies first).</p>}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </>
  );
}
