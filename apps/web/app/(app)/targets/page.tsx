'use client';
import { useState } from 'react';
import { api, useApi } from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, ErrorNote, PageHeader } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

type Target = {
  id: string;
  hostname: string;
  status: 'PENDING' | 'VERIFIED';
  createdAt: string;
  verification: { recordName: string; recordValue: string };
};

export default function TargetsPage() {
  const { data, error, loading, reload } = useApi<Target[]>('/targets');
  const [hostname, setHostname] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      const t = await api<Target>('/targets', { method: 'POST', body: JSON.stringify({ hostname }) });
      setHostname('');
      setOpen(t.id);
      await reload();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not add target');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Targets" subtitle="Websites you own. Sentinel only scans targets whose ownership you have verified." />

      <Card className="mb-6 p-4">
        <form onSubmit={add} className="flex flex-col gap-2 sm:flex-row">
          <Input
            required placeholder="example.com" value={hostname}
            onChange={(e) => setHostname(e.target.value)} aria-label="Hostname" className="sm:max-w-sm"
          />
          <Button type="submit" disabled={busy}>{busy ? 'Adding…' : 'Add target'}</Button>
        </form>
        {formError && <div className="mt-3"><ErrorNote message={formError} /></div>}
      </Card>

      {error && <ErrorNote message={error} />}
      {loading && !data && <p className="text-sm text-muted">Loading…</p>}
      {data && data.length === 0 && <p className="text-sm text-muted">No targets yet. Add your first domain above.</p>}

      <div className="space-y-3">
        {data?.map((t) => (
          <Card key={t.id} className="p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm">{t.hostname}</p>
                <p className="mt-0.5 text-xs text-muted">Added {new Date(t.createdAt).toLocaleDateString()}</p>
              </div>
              <div className="flex items-center gap-3">
                <Badge kind={t.status === 'VERIFIED' ? 'OK' : 'MEDIUM'}>{t.status}</Badge>
                {t.status === 'PENDING' && (
                  <Button variant="ghost" size="sm" onClick={() => setOpen(open === t.id ? null : t.id)}>
                    {open === t.id ? 'Hide steps' : 'How to verify'}
                  </Button>
                )}
              </div>
            </div>
            {open === t.id && t.status === 'PENDING' && (
              <div className="mt-4 space-y-2 rounded-md border border-line bg-bg p-3 text-sm">
                <p className="text-muted">Add this DNS TXT record at your DNS provider. Automatic verification arrives in Phase 2.</p>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-xs">
                  <dt className="text-muted">Type</dt><dd>TXT</dd>
                  <dt className="text-muted">Name</dt><dd className="break-all">{t.verification.recordName}</dd>
                  <dt className="text-muted">Value</dt><dd className="break-all">{t.verification.recordValue}</dd>
                </dl>
              </div>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
