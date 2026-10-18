import type { Check, ScanContext, ScanFinding } from '../types';
import { header } from '../util';

/** The ENTIRE probe list. Fixed on purpose: this is a misconfiguration check, not a content brute-forcer. */
export const EXPOSURE_PATHS = ['/.git/', '/.git/HEAD', '/.env', '/backup/', '/uploads/'] as const;

const LISTING = [/Index of \//i, /Directory listing for \//i, /\[To Parent Directory\]/i];
export const looksLikeDirectoryListing = (body: string) => LISTING.some((re) => re.test(body));

export const looksLikeGitListing = (body: string) => looksLikeDirectoryListing(body) && /\bHEAD\b/.test(body) && /\b(objects|refs)\//.test(body);
export const looksLikeGitHead = (body: string) => /^\s*ref:\s*refs\/heads\/\S+/.test(body);

const SECRET_KEY = /SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|API_?KEY|ACCESS_?KEY|DATABASE_URL|DB_PASS|CREDENTIAL/i;

/** Returns variable NAMES only – values are never read into evidence. */
export function analyzeEnvFile(body: string, contentType: string | undefined): { keys: string[]; hasSecrets: boolean } | null {
  if (contentType && /text\/html/i.test(contentType)) return null; // SPA catch-all returning index.html
  if (/<\s*(?:!doctype|html|head|body)\b/i.test(body.slice(0, 2048))) return null;
  const keys: string[] = [];
  for (const line of body.split(/\r?\n/).slice(0, 300)) {
    const m = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=/.exec(line);
    if (m) keys.push(m[1]);
  }
  if (keys.length < 2) return null; // one match is too easy to hit by accident
  return { keys: keys.slice(0, 25), hasSecrets: keys.some((k) => SECRET_KEY.test(k)) };
}

export class ExposureCheck implements Check {
  readonly id = 'exposure';

  async run(ctx: ScanContext): Promise<ScanFinding[]> {
    const out: ScanFinding[] = [];
    let gitDone = false;

    for (const path of EXPOSURE_PATHS) {
      const res = await ctx.get(path);
      // Never judge by status code alone: SPAs and CDNs answer 200 for everything. Content signatures only.
      if (res.statusCode !== 200) continue;
      const body = res.text();

      if (path.startsWith('/.git/')) {
        const hit = path === '/.git/' ? looksLikeGitListing(body) : looksLikeGitHead(body);
        if (hit && !gitDone) {
          gitDone = true;
          out.push({
            type: 'exposure.git', key: '/.git',
            title: 'Git repository is publicly accessible (/.git/)', severity: 'HIGH', confidence: 'CONFIRMED',
            evidence: { path, status: res.statusCode, signature: path === '/.git/' ? 'directory listing with HEAD/objects/refs' : 'HEAD file (ref: refs/heads/…)' },
            remediation: 'Block access to /.git/ at the web server and remove it from the web root. Rotate any secrets that were ever committed.',
          });
        }
      } else if (path === '/.env') {
        const env = analyzeEnvFile(body, header(res, 'content-type'));
        if (env) {
          out.push({
            type: 'exposure.env-file', key: '/.env',
            title: 'Environment file is publicly accessible (/.env)', severity: env.hasSecrets ? 'CRITICAL' : 'HIGH', confidence: 'CONFIRMED',
            evidence: { path, status: res.statusCode, variableNames: env.keys, looksLikeSecrets: env.hasSecrets },
            remediation: 'Remove the file from the web root and block dotfiles at the web server. Treat every value in it as compromised and rotate it.',
          });
        }
      } else if (looksLikeDirectoryListing(body)) {
        out.push({
          type: 'exposure.directory-listing', key: path,
          title: `Directory listing is enabled at ${path}`, severity: path === '/backup/' ? 'HIGH' : 'MEDIUM', confidence: 'CONFIRMED',
          evidence: { path, status: res.statusCode, signature: 'Index of /' },
          remediation: 'Disable directory indexing (nginx: autoindex off; Apache: Options -Indexes) and move sensitive files out of the web root.',
        });
      }
    }
    return out;
  }
}
