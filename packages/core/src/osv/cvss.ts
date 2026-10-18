import type { Severity } from '../scanner/types';

/**
 * OSV gives CVSS as a VECTOR STRING ("CVSS:3.1/AV:N/AC:L/…"), not a number, so the base score has to be computed.
 * Implements the CVSS v3.0 / v3.1 base-score formulas. v2 and v4 vectors return null (callers fall back to the
 * advisory's own `database_specific.severity` label).
 */
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC = { L: 0.77, H: 0.44 } as const;
const UI = { N: 0.85, R: 0.62 } as const;
const CIA = { H: 0.56, L: 0.22, N: 0 } as const;
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 } as const;
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 } as const;

/** CVSS 3.1 Roundup: avoids floating point artefacts (e.g. 4.000000001 → 4.1). */
function roundUp(x: number): number {
  const i = Math.round(x * 100_000);
  return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
}

export function cvss3BaseScore(vector: string): number | null {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(vector.trim());
  if (!m) return null;
  const metrics = new Map<string, string>();
  for (const part of m[1].split('/')) {
    const [k, v] = part.split(':');
    if (!k || !v || metrics.has(k)) return null;
    metrics.set(k, v);
  }
  const get = <T extends Record<string, number>>(key: string, table: T): number | null => {
    const v = metrics.get(key);
    return v !== undefined && Object.prototype.hasOwnProperty.call(table, v) ? table[v] : null;
  };
  const scope = metrics.get('S');
  if (scope !== 'U' && scope !== 'C') return null;
  const av = get('AV', AV), ac = get('AC', AC), ui = get('UI', UI), c = get('C', CIA), i = get('I', CIA), a = get('A', CIA);
  const pr = get('PR', scope === 'U' ? PR_UNCHANGED : PR_CHANGED);
  if ([av, ac, ui, c, i, a, pr].some((x) => x === null)) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  return scope === 'U' ? roundUp(Math.min(impact + exploitability, 10)) : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

/** NVD qualitative bands. */
export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}

/** Labels used by GitHub/OSV `database_specific.severity` ("MODERATE" is GitHub's word for MEDIUM). */
export function severityFromLabel(label: unknown): Severity | null {
  if (typeof label !== 'string') return null;
  switch (label.trim().toUpperCase()) {
    case 'CRITICAL': return 'CRITICAL';
    case 'HIGH': return 'HIGH';
    case 'MODERATE':
    case 'MEDIUM': return 'MEDIUM';
    case 'LOW': return 'LOW';
    default: return null;
  }
}
