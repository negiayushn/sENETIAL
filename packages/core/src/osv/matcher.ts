import semver from 'semver';
import type { NormalizedAdvisory, NormalizedAffected, RangeEvent } from './advisory';

/**
 * OSV range semantics (https://ossf.github.io/osv-schema/#affectedranges-field):
 * sort the events by version, then walk them: `introduced` switches "affected" on once the version has reached it,
 * `fixed` switches it off, `last_affected` switches it off for anything above it. `introduced: "0"` means "from the
 * very beginning". Several introduced/fixed pairs describe several disjoint ranges (e.g. one per major branch).
 * Ranges and the explicit `versions` list are OR-ed. `limit` only matters for git ranges.
 */
const ZERO = '0.0.0-0'; // sorts below every real version, including prereleases of 0.0.0

const parse = (v: string): string | null => semver.valid(v) ?? semver.valid(v, { loose: true });
const key = (v: string): string | null => (v === '0' ? ZERO : parse(v));

function rangeAffects(events: RangeEvent[], version: string): boolean {
  const ordered = events
    .map((e) => {
      const raw = e.introduced ?? e.fixed ?? e.last_affected;
      return { e, k: raw === undefined ? null : key(raw) };
    })
    .filter((x): x is { e: RangeEvent; k: string } => x.k !== null) // unparseable versions can't be ordered: ignore them
    .sort((a, b) => semver.compare(a.k, b.k) || Number(b.e.introduced !== undefined) - Number(a.e.introduced !== undefined)); // at equal versions, introduced first

  let affected = false;
  for (const { e, k } of ordered) {
    if (e.introduced !== undefined) {
      if (e.introduced === '0' || semver.gte(version, k)) affected = true;
    } else if (e.fixed !== undefined) {
      if (semver.gte(version, k)) affected = false;
    } else if (e.last_affected !== undefined) {
      if (semver.gt(version, k)) affected = false;
    }
  }
  return affected;
}

export function isVersionAffected(entries: NormalizedAffected[], name: string, version: string): boolean {
  const v = parse(version);
  if (!v) return false; // git/url/tag "versions" cannot be compared; callers only pass registry versions
  for (const a of entries) {
    if (a.name !== name) continue;
    if (a.versions.some((x) => x === version || parse(x) === v)) return true;
    for (const r of a.ranges) {
      if (r.type === 'GIT') continue; // commit ranges are meaningless for a published npm version
      if (rangeAffects(r.events, v)) return true;
    }
  }
  return false;
}

export function advisoryAffects(adv: Pick<NormalizedAdvisory, 'affected' | 'withdrawn'>, name: string, version: string): boolean {
  if (adv.withdrawn) return false;
  return isVersionAffected(adv.affected, name, version);
}

/**
 * The smallest version above `installed` that this advisory lists as fixed AND is not itself affected by another
 * range of the same advisory. null = no fix is published (e.g. only `last_affected`, or the installed version is
 * already past every fix).
 */
export function smallestFixedVersion(adv: Pick<NormalizedAdvisory, 'affected'>, name: string, installed: string): string | null {
  const inst = parse(installed);
  if (!inst) return null;
  const candidates = new Set<string>();
  for (const a of adv.affected) {
    if (a.name !== name) continue;
    for (const r of a.ranges) {
      if (r.type === 'GIT') continue;
      for (const e of r.events) {
        const f = e.fixed ? parse(e.fixed) : null;
        if (f && semver.gt(f, inst)) candidates.add(f);
      }
    }
  }
  return [...candidates].sort(semver.compare).find((f) => !isVersionAffected(adv.affected, name, f)) ?? null;
}
