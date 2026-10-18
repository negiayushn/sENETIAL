import type { Severity } from '../scanner/types';
import { cvss3BaseScore, severityFromLabel, severityFromScore } from './cvss';

export interface RangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}
export interface NormalizedRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  events: RangeEvent[];
}
export interface NormalizedAffected {
  name: string;
  ranges: NormalizedRange[];
  /** Explicit list of affected versions (OSV ORs this with the ranges). */
  versions: string[];
}

export interface NormalizedAdvisory {
  id: string;
  modified: Date;
  published: Date | null;
  withdrawn: Date | null;
  summary: string | null;
  details: string | null;
  aliases: string[];
  severity: Severity | null;
  severitySource: 'cvss' | 'database' | null;
  cvssScore: number | null;
  cvssVector: string | null;
  affected: NormalizedAffected[];
  /** Distinct npm package names this advisory affects (indexed in the DB for name lookups). */
  packageNames: string[];
  references: { type: string; url: string }[];
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.length > 0 ? v.slice(0, max) : null);
const date = (v: unknown): Date | null => {
  if (typeof v !== 'string') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};

const MAX_EVENTS = 200;
const MAX_VERSIONS = 5000;
const MAX_REFS = 10;

function normalizeAffected(raw: unknown): NormalizedAffected | null {
  if (!isObj(raw) || !isObj(raw.package)) return null;
  if (raw.package.ecosystem !== 'npm') return null; // we only ever ask about npm, but a record can list other ecosystems too
  const name = str(raw.package.name, 214);
  if (!name) return null;

  const ranges: NormalizedRange[] = [];
  for (const r of Array.isArray(raw.ranges) ? raw.ranges : []) {
    if (!isObj(r) || (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM' && r.type !== 'GIT')) continue;
    const events: RangeEvent[] = [];
    for (const e of (Array.isArray(r.events) ? r.events : []).slice(0, MAX_EVENTS)) {
      if (!isObj(e)) continue;
      const ev: RangeEvent = {};
      for (const k of ['introduced', 'fixed', 'last_affected', 'limit'] as const) {
        const v = str(e[k], 100);
        if (v) ev[k] = v;
      }
      if (Object.keys(ev).length) events.push(ev);
    }
    ranges.push({ type: r.type, events });
  }
  const versions = (Array.isArray(raw.versions) ? raw.versions : []).filter((v): v is string => typeof v === 'string' && v.length <= 100).slice(0, MAX_VERSIONS);
  return { name, ranges, versions };
}

/**
 * Severity: prefer a CVSS v3 score we can compute from the vector; otherwise the advisory's own label
 * (`database_specific.severity`, which GitHub advisories carry). Returns null if neither exists.
 */
function extractSeverity(raw: Record<string, unknown>): Pick<NormalizedAdvisory, 'severity' | 'severitySource' | 'cvssScore' | 'cvssVector'> {
  let best: { score: number; vector: string } | null = null;
  for (const s of Array.isArray(raw.severity) ? raw.severity : []) {
    if (!isObj(s) || typeof s.score !== 'string') continue;
    const score = cvss3BaseScore(s.score);
    if (score !== null && (!best || score > best.score)) best = { score, vector: s.score.slice(0, 200) };
  }
  if (best) return { severity: severityFromScore(best.score), severitySource: 'cvss', cvssScore: best.score, cvssVector: best.vector };

  const candidates: unknown[] = [isObj(raw.database_specific) ? raw.database_specific.severity : undefined];
  for (const a of Array.isArray(raw.affected) ? raw.affected : []) {
    if (!isObj(a)) continue;
    if (isObj(a.database_specific)) candidates.push(a.database_specific.severity);
    if (isObj(a.ecosystem_specific)) candidates.push(a.ecosystem_specific.severity);
  }
  for (const c of candidates) {
    const sev = severityFromLabel(c);
    if (sev) return { severity: sev, severitySource: 'database', cvssScore: null, cvssVector: null };
  }
  return { severity: null, severitySource: null, cvssScore: null, cvssVector: null };
}

/** Raw OSV record → the small, validated shape we store and match against. Returns null if it is unusable. */
export function normalizeOsvVuln(raw: unknown): NormalizedAdvisory | null {
  if (!isObj(raw)) return null;
  const id = str(raw.id, 200);
  const modified = date(raw.modified);
  if (!id || !modified || !/^[A-Za-z0-9._:-]+$/.test(id)) return null;

  const affected = (Array.isArray(raw.affected) ? raw.affected : []).map(normalizeAffected).filter((a): a is NormalizedAffected => a !== null);
  const references = (Array.isArray(raw.references) ? raw.references : [])
    .filter((r): r is Record<string, unknown> => isObj(r) && typeof r.url === 'string' && /^https?:\/\//i.test(r.url))
    .slice(0, MAX_REFS)
    .map((r) => ({ type: str(r.type, 30) ?? 'WEB', url: String(r.url).slice(0, 500) }));

  return {
    id,
    modified,
    published: date(raw.published),
    withdrawn: date(raw.withdrawn),
    summary: str(raw.summary, 500),
    details: str(raw.details, 4000),
    aliases: (Array.isArray(raw.aliases) ? raw.aliases : []).filter((a): a is string => typeof a === 'string').slice(0, 20),
    ...extractSeverity(raw),
    affected,
    packageNames: [...new Set(affected.map((a) => a.name))],
    references,
  };
}
