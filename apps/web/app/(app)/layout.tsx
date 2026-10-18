'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

const NAV = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/targets', label: 'Targets' },
  { href: '/repositories', label: 'Repositories' },
  { href: '/findings', label: 'Findings' },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { data: session } = authClient.useSession();

  async function signOut() {
    await authClient.signOut();
    router.replace('/login');
    router.refresh();
  }

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-line bg-panel px-3 py-4 md:flex">
        <div className="mb-6 flex items-center gap-2 px-2">
          <span className="grid h-6 w-6 place-items-center rounded bg-accent font-mono text-xs font-bold text-accent-fg">S</span>
          <span className="font-semibold tracking-tight">Sentinel</span>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5">
          {NAV.map((n) => (
            <Link
              key={n.href}
              href={n.href}
              className={cn(
                'rounded-md px-2 py-1.5 text-sm transition-colors',
                pathname.startsWith(n.href) ? 'bg-panel-2 text-fg' : 'text-muted hover:text-fg',
              )}
            >
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="border-t border-line pt-3">
          <p className="truncate px-2 text-xs text-muted">{session?.user.email ?? ' '}</p>
          <Button variant="ghost" size="sm" className="mt-1 w-full justify-start" onClick={signOut}>Sign out</Button>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <nav className="flex items-center gap-1 border-b border-line bg-panel px-3 py-2 md:hidden">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className={cn('rounded px-2 py-1 text-sm', pathname.startsWith(n.href) ? 'bg-panel-2' : 'text-muted')}>
              {n.label}
            </Link>
          ))}
          <button onClick={signOut} className="ml-auto text-sm text-muted cursor-pointer">Sign out</button>
        </nav>
        <main className="mx-auto max-w-5xl px-5 py-8">{children}</main>
      </div>
    </div>
  );
}
