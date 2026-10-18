import { HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

export const Card = ({ className, ...p }: HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('rounded-lg border border-line bg-panel', className)} {...p} />
);

export const PageHeader = ({ title, subtitle }: { title: string; subtitle?: string }) => (
  <header className="mb-6">
    <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
    {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
  </header>
);

export const ErrorNote = ({ message }: { message: string }) => (
  <p role="alert" className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
    {message}
  </p>
);
