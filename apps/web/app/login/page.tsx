'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { API_URL, authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Card, ErrorNote } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [github, setGithub] = useState(false);

  useEffect(() => {
    fetch(`${API_URL}/auth-config`)
      .then((r) => r.json())
      .then((c) => setGithub(Boolean(c.github)))
      .catch(() => undefined);
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const res =
      mode === 'signin'
        ? await authClient.signIn.email({ email, password })
        : await authClient.signUp.email({ name: name.trim() || email.split('@')[0], email, password });
    setBusy(false);
    if (res.error) return setError(res.error.message ?? 'Could not sign you in');
    router.replace('/dashboard');
    router.refresh();
  }

  async function withGithub() {
    await authClient.signIn.social({ provider: 'github', callbackURL: `${window.location.origin}/dashboard` });
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-4">
      <div className="mb-8">
        <div className="flex items-center gap-2">
          <span className="grid h-7 w-7 place-items-center rounded bg-accent font-mono text-sm font-bold text-accent-fg">S</span>
          <span className="text-lg font-semibold tracking-tight">Sentinel</span>
        </div>
        <p className="mt-3 text-sm text-muted">Scan once. Keep watching.</p>
      </div>

      <Card className="p-5">
        <div className="mb-4 grid grid-cols-2 rounded-md bg-bg p-1 text-sm">
          {(['signin', 'signup'] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => { setMode(m); setError(null); }}
              className={cn('rounded py-1.5 transition-colors cursor-pointer', mode === m ? 'bg-panel-2 text-fg' : 'text-muted hover:text-fg')}
            >
              {m === 'signin' ? 'Sign in' : 'Create account'}
            </button>
          ))}
        </div>

        <form onSubmit={submit} className="space-y-3">
          {mode === 'signup' && (
            <Input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
          )}
          <Input type="email" required placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
          <Input
            type="password" required minLength={8} placeholder="Password (min 8 characters)"
            value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
          />
          {error && <ErrorNote message={error} />}
          <Button type="submit" className="w-full" disabled={busy}>
            {busy ? 'Please wait…' : mode === 'signin' ? 'Sign in' : 'Create account'}
          </Button>
        </form>

        {github && (
          <>
            <div className="my-4 flex items-center gap-3 text-xs text-muted">
              <span className="h-px flex-1 bg-line" /> or <span className="h-px flex-1 bg-line" />
            </div>
            <Button variant="outline" className="w-full" onClick={withGithub}>Continue with GitHub</Button>
          </>
        )}
      </Card>
    </main>
  );
}
