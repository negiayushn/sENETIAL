import { cn } from '@/lib/utils';

const tone = {
  CRITICAL: 'text-sev-critical border-sev-critical/40 bg-sev-critical/10',
  HIGH: 'text-sev-high border-sev-high/40 bg-sev-high/10',
  MEDIUM: 'text-sev-medium border-sev-medium/40 bg-sev-medium/10',
  LOW: 'text-sev-low border-sev-low/40 bg-sev-low/10',
  INFO: 'text-sev-info border-line bg-panel-2',
  OK: 'text-accent border-accent/40 bg-accent/10',
  NEUTRAL: 'text-muted border-line bg-panel-2',
} as const;

export function Badge({ kind, children }: { kind: keyof typeof tone; children: React.ReactNode }) {
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide', tone[kind])}>
      {children}
    </span>
  );
}
