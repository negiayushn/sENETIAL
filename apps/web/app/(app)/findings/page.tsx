'use client';
import { Fragment, useState } from 'react';
import { useApi } from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Card, ErrorNote, PageHeader } from '@/components/ui/card';

type Sev = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type Finding = {
  id: string;
  title: string;
  source: 'WEB' | 'DEPENDENCY';
  severity: Sev;
  confidence: 'CONFIRMED' | 'POTENTIAL';
  status: string;
  lastSeenAt: string;
  target: { hostname: string } | null;
  repository: { fullName: string } | null;
  remediation: string | null;
  evidence: {
    package?: string; versions?: string[]; direct?: boolean; fixedVersion?: string | null; introducedBy?: string[][];
    advisory?: { id: string; aliases?: string[]; references?: { type: string; url: string }[] };
    severity?: { source?: string; cvssScore?: number | null };
  } | null;
};

const SOURCES = ['WEB', 'DEPENDENCY'];
const STATUSES = ['OPEN', 'ACKNOWLEDGED', 'FIXED', 'IGNORED', 'REOPENED'];
const SEVERITIES: Sev[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const select =
  'h-9 rounded-md border border-line bg-panel-2 px-2 text-sm text-fg focus:border-accent';

export default function FindingsPage() {
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const qs = new URLSearchParams({ ...(status && { status }), ...(severity && { severity }), ...(source && { source }) }).toString();
  const { data, error, loading } = useApi<Finding[]>(`/findings${qs ? `?${qs}` : ''}`);

  return (
    <>
      <PageHeader title="Findings" subtitle="Everything Sentinel has detected, with confirmed and potential issues labelled honestly." />

      <div className="mb-4 flex gap-2">
        <select className={select} value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className={select} value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
          <option value="">All sources</option>
          {SOURCES.map((s) => <option key={s} value={s}>{s === 'WEB' ? 'Website scans' : 'Dependencies'}</option>)}
        </select>
        <select className={select} value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      {error && <ErrorNote message={error} />}
      {loading && !data && <p className="text-sm text-muted">Loading…</p>}

      {data && data.length === 0 && (
        <Card className="p-8 text-center">
          <p className="text-sm">No findings yet.</p>
          <p className="mt-1 text-sm text-muted">Run a website scan or inventory a repository’s dependencies to populate this list.</p>
        </Card>
      )}

      {data && data.length > 0 && (
        <Card className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs uppercase tracking-wider text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Finding</th>
                <th className="px-4 py-2 font-medium">Where</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data.map((f) => (
                <Fragment key={f.id}>
                  <tr className="cursor-pointer border-b border-line last:border-0 hover:bg-panel-2" onClick={() => setOpen(open === f.id ? null : f.id)}>
                    <td className="px-4 py-3"><Badge kind={f.severity}>{f.severity}</Badge></td>
                    <td className="px-4 py-3">
                      {f.title}
                      {f.confidence === 'POTENTIAL' && <span className="ml-2 text-xs text-muted">(potential)</span>}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted">{f.target?.hostname ?? f.repository?.fullName ?? f.source.toLowerCase()}</td>
                    <td className="px-4 py-3"><Badge kind="NEUTRAL">{f.status}</Badge></td>
                    <td className="px-4 py-3 text-xs text-muted">{new Date(f.lastSeenAt).toLocaleDateString()}</td>
                  </tr>
                  {open === f.id && (
                    <tr className="border-b border-line bg-bg">
                      <td colSpan={5} className="px-4 py-3 text-sm">
                        {f.remediation && <p><span className="text-muted">How to fix: </span>{f.remediation}</p>}
                        {f.source === 'DEPENDENCY' && f.evidence && (
                          <div className="mt-2 space-y-1 text-xs text-muted">
                            {f.evidence.fixedVersion && <p>Fixed in <span className="font-mono text-fg">{f.evidence.fixedVersion}</span></p>}
                            {f.evidence.introducedBy && f.evidence.introducedBy.length > 0 && (
                              <p>Introduced by: {f.evidence.introducedBy.map((c, i) => <span key={i} className="mr-3 font-mono text-fg">{c.join(' → ')}</span>)}</p>
                            )}
                            {f.evidence.severity?.cvssScore != null && <p>CVSS score <span className="font-mono text-fg">{f.evidence.severity.cvssScore}</span></p>}
                            {f.evidence.advisory && (
                              <p>
                                Advisory <span className="font-mono text-fg">{f.evidence.advisory.id}</span>
                                {f.evidence.advisory.aliases?.map((a) => <span key={a} className="ml-2 font-mono text-fg">{a}</span>)}
                                {f.evidence.advisory.references?.slice(0, 3).map((r) => (
                                  <a key={r.url} href={r.url} target="_blank" rel="noopener noreferrer" className="ml-3 underline underline-offset-2">{r.type.toLowerCase()}</a>
                                ))}
                              </p>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </>
  );
}
