import type { Check, ScanContext, ScanFinding } from '../types';
import { clip, header, isRedirect } from '../util';

const VERSION = /\d+\.\d+/;

/** Server-side error output that should never reach a browser. Patterns are specific to avoid false positives. */
export const STACK_TRACE_PATTERNS: { id: string; re: RegExp }[] = [
  { id: 'java', re: /\bat\s+[\w$.]+\([\w$]+\.java:\d+\)/ },
  { id: 'python', re: /Traceback \(most recent call last\):/ },
  { id: 'django-debug', re: /You're seeing this error because you have\s+DEBUG\s*=\s*True/ },
  { id: 'node', re: /\bat\s+(?:[\w$.<>[\] ]+\s+\()?(?:\/|[A-Za-z]:\\|file:\/\/)[^\s)]*\.(?:js|ts|mjs|cjs):\d+:\d+\)?/ },
  { id: 'dotnet', re: /System\.\w+(?:\.\w+)*Exception|\bat\s+[\w.<>`]+\s+in\s+[A-Za-z]:\\[^\r\n]*:line\s+\d+/ },
  { id: 'php', re: /(?:Fatal error|Parse error|Warning|Notice):[^\r\n]{0,200}\bin\s+(?:\/|[A-Za-z]:\\)\S+\s+on line\s+\d+/ },
  { id: 'ruby', re: /\.rb:\d+:in\s+[`']/ },
  { id: 'go', re: /goroutine \d+ \[running\]:/ },
];

export function findStackTrace(body: string): { id: string; snippet: string } | null {
  for (const { id, re } of STACK_TRACE_PATTERNS) {
    const m = re.exec(body);
    if (m) return { id, snippet: clip(m[0], 160) };
  }
  return null;
}

export class DisclosureCheck implements Check {
  readonly id = 'disclosure';

  async run(ctx: ScanContext): Promise<ScanFinding[]> {
    const out: ScanFinding[] = [];
    const root = await ctx.getRoot();

    // Version strings in response headers (only versions: a bare "nginx" tells an attacker nothing new)
    for (const name of ['server', 'x-powered-by']) {
      const v = header(root, name);
      if (v && VERSION.test(v)) {
        out.push({
          type: `disclosure.${name}-version`, key: name,
          title: `${name === 'server' ? 'Server' : 'X-Powered-By'} header discloses a version: ${clip(v, 80)}`,
          severity: 'LOW', confidence: 'CONFIRMED',
          evidence: { header: name, value: clip(v, 120) },
          remediation: name === 'server'
            ? 'Configure the web server to omit version details (e.g. nginx: server_tokens off; Apache: ServerTokens Prod).'
            : 'Remove the X-Powered-By header in the framework or web-server configuration.',
        });
      }
    }

    // Stack traces: the deliberately-missing page (404), plus the root page if it is itself an error.
    const probes: { source: string; body: string; status: number; path: string }[] = [];
    const nf = await ctx.get(ctx.notFoundPath);
    probes.push({ source: '404-probe', body: nf.text(), status: nf.statusCode, path: ctx.notFoundPath });
    if (root.statusCode >= 500) probes.push({ source: 'root-5xx', body: root.text(), status: root.statusCode, path: '/' });

    for (const p of probes) {
      const hit = findStackTrace(p.body);
      if (!hit) continue;
      out.push({
        type: 'disclosure.stack-trace', key: p.source,
        title: p.source === '404-probe' ? 'Error page exposes a stack trace (404)' : 'Error page exposes a stack trace (5xx)',
        severity: 'MEDIUM', confidence: 'CONFIRMED',
        evidence: { path: p.path === ctx.notFoundPath ? '<random non-existent path>' : p.path, status: p.status, pattern: hit.id, snippet: hit.snippet },
        remediation: 'Disable debug mode and serve a generic error page; log stack traces server-side only.',
      });
    }
    return out;
  }
}
