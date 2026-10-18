'use client';
import Link from 'next/link';
import { useApi } from '@/lib/api';
import { Card, ErrorNote, PageHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

type Summary = {
  targets: number;
  verifiedTargets: number;
  repositories: number;
  inventoriedRepositories: number;
  openFindings: number;
  openBySeverity: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO', number>;
  lastIntelligenceSync: string | null;
};

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
const BAR: Record<(typeof SEV)[number], string> = {
  CRITICAL: 'bg-sev-critical', HIGH: 'bg-sev-high', MEDIUM: 'bg-sev-medium', LOW: 'bg-sev-low', INFO: 'bg-sev-info',
};

function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <Card className="p-4">
      <p className="text-xs uppercase tracking-wider text-muted">{label}</p>
      <p className="mt-2 font-mono text-3xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
    </Card>
  );
}

export default function DashboardPage() {
  const { data, error, loading } = useApi<Summary>('/dashboard/summary');

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Your security posture at a glance." />
      {error && <ErrorNote message={error} />}
      {loading && !data && <p className="text-sm text-muted">Loading…</p>}
      {data && (
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <Stat label="Targets" value={data.targets} hint={`${data.verifiedTargets} verified`} />
            <Stat label="Open findings" value={data.openFindings} />
            <Stat
              label="Intelligence sync"
              value={data.lastIntelligenceSync ? new Date(data.lastIntelligenceSync).toLocaleString() : 'Never'}
              hint="Last successful advisory sync (no real-time claims)"
            />
          </div>

          <Card className="p-4">
            <h2 className="mb-3 text-sm font-medium">Open findings by severity</h2>
            {data.openFindings === 0 ? (
              <p className="text-sm text-muted">Nothing open. Findings appear here once scans and dependency checks are running.</p>
            ) : (
              <>
                <div className="flex h-2 overflow-hidden rounded bg-panel-2">
                  {SEV.map((s) => (
                    <div key={s} className={BAR[s]} style={{ width: `${(data.openBySeverity[s] / data.openFindings) * 100}%` }} />
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap gap-4">
                  {SEV.map((s) => (
                    <span key={s} className="flex items-center gap-2 text-sm">
                      <Badge kind={s}>{s}</Badge>
                      <span className="font-mono tabular-nums">{data.openBySeverity[s]}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </Card>

          <Card className="p-4">
            <h2 className="mb-3 text-sm font-medium">Get started</h2>
            <ol className="space-y-2 text-sm">
              <li className="flex items-center gap-2">
                <Badge kind={data.targets > 0 ? 'OK' : 'NEUTRAL'}>{data.targets > 0 ? 'done' : 'todo'}</Badge>
                <Link href="/targets" className="underline-offset-2 hover:underline">Register a website you own</Link>
              </li>
              <li className="flex items-center gap-2">
                <Badge kind={data.verifiedTargets > 0 ? 'OK' : 'NEUTRAL'}>{data.verifiedTargets > 0 ? 'done' : 'todo'}</Badge>
                <span>Verify ownership with a DNS TXT record</span>
              </li>
              <li className="flex items-center gap-2">
                <Badge kind={data.repositories > 0 ? 'OK' : 'NEUTRAL'}>{data.repositories > 0 ? 'done' : 'todo'}</Badge>
                <Link href="/repositories" className="underline-offset-2 hover:underline">Connect GitHub</Link>
              </li>
              <li className="flex items-center gap-2">
                <Badge kind={data.inventoriedRepositories > 0 ? 'OK' : 'NEUTRAL'}>{data.inventoriedRepositories > 0 ? 'done' : 'todo'}</Badge>
                <Link href="/repositories" className="underline-offset-2 hover:underline">Inventory a repository’s dependencies</Link>
                <span className="text-muted">(vulnerability matching arrives in Phase 4)</span>
              </li>
            </ol>
          </Card>
        </div>
      )}
    </>
  );
}
