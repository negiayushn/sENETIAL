import { describe, expect, it } from 'vitest';
import { advisoryAffects, isVersionAffected, normalizeOsvVuln, smallestFixedVersion, type NormalizedAffected } from '../src';
import { labelOnly, lodashCmdInjection, lodashZipObjectDeep, minimistProto } from './fixtures-osv';

const adv = (r: unknown) => normalizeOsvVuln(r)!;
const entry = (events: object[], extra: Partial<NormalizedAffected> = {}, type: 'SEMVER' | 'GIT' | 'ECOSYSTEM' = 'SEMVER', name = 'pkg'): NormalizedAffected[] =>
  [{ name, ranges: [{ type, events: events as never }], versions: [], ...extra }];

describe('normalizeOsvVuln', () => {
  it('extracts the fields we store, computing severity from the CVSS vector', () => {
    const a = adv(lodashCmdInjection);
    expect(a).toMatchObject({ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], severity: 'HIGH', severitySource: 'cvss', cvssScore: 7.2, packageNames: ['lodash'], withdrawn: null });
    expect(a.modified.toISOString()).toBe('2023-11-08T04:06:46.000Z');
    expect(a.affected[0].ranges[0].events).toEqual([{ introduced: '0' }, { fixed: '4.17.21' }]);
  });
  it('drops non-http(s) reference URLs (no javascript: links in the UI)', () => {
    expect(adv(lodashCmdInjection).references).toEqual([{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }]);
  });
  it('falls back to the database_specific label when there is no usable CVSS', () => {
    expect(adv(labelOnly)).toMatchObject({ severity: 'MEDIUM', severitySource: 'database', cvssScore: null });
    const v4only = { ...labelOnly, severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }], database_specific: { severity: 'HIGH' } };
    expect(adv(v4only)).toMatchObject({ severity: 'HIGH', severitySource: 'database' });
  });
  it('prefers the CVSS score over the label, and the highest of several vectors', () => {
    const r = { ...lodashZipObjectDeep, database_specific: { severity: 'LOW' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }, { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] };
    expect(adv(r)).toMatchObject({ severity: 'CRITICAL', cvssScore: 9.8 });
  });
  it('severity is null when the advisory gives nothing usable', () => {
    expect(adv({ ...labelOnly, database_specific: {} }).severity).toBeNull();
  });
  it('keeps only npm entries and tolerates garbage', () => {
    const r = { ...lodashCmdInjection, affected: [{ package: { ecosystem: 'PyPI', name: 'lodash' } }, 'x', null, { package: { ecosystem: 'npm' } }, ...lodashCmdInjection.affected] };
    expect(adv(r).affected).toHaveLength(1);
  });
  it.each([[null], ['str'], [{}], [{ id: 'x' }], [{ id: 'bad id!', modified: '2020-01-01T00:00:00Z' }], [{ id: 'A', modified: 'not a date' }]])('rejects unusable record %j', (r) => {
    expect(normalizeOsvVuln(r)).toBeNull();
  });
  it('bounds sizes (details clipped, event/version lists capped)', () => {
    const big = { ...lodashCmdInjection, details: 'x'.repeat(50_000), affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, versions: Array.from({ length: 9000 }, (_, i) => `1.0.${i}`), ranges: [{ type: 'SEMVER', events: Array.from({ length: 999 }, (_, i) => ({ introduced: `1.${i}.0` })) }] }] };
    const a = adv(big);
    expect(a.details!.length).toBe(4000);
    expect(a.affected[0].versions).toHaveLength(5000);
    expect(a.affected[0].ranges[0].events).toHaveLength(200);
  });
});

describe('isVersionAffected', () => {
  const lodash = adv(lodashCmdInjection).affected;
  it('single range [0, 4.17.21)', () => {
    expect(['0.0.1', '3.0.0', '4.17.20'].map((v) => isVersionAffected(lodash, 'lodash', v))).toEqual([true, true, true]);
    expect(['4.17.21', '4.17.22', '5.0.0'].map((v) => isVersionAffected(lodash, 'lodash', v))).toEqual([false, false, false]);
  });
  it('a prerelease of the fixed version is still affected (it sorts below it)', () => {
    expect(isVersionAffected(lodash, 'lodash', '4.17.21-beta.1')).toBe(true);
  });

  const minimist = adv(minimistProto).affected;
  it('two introduced/fixed pairs describe two disjoint ranges', () => {
    const v = (x: string) => isVersionAffected(minimist, 'minimist', x);
    expect([v('0.0.8'), v('0.2.3'), v('1.0.0'), v('1.2.0'), v('1.2.5')]).toEqual([true, true, true, true, true]);
    expect([v('0.2.4'), v('0.5.0'), v('0.9.9'), v('1.2.6'), v('1.2.8')]).toEqual([false, false, false, false, false]); // the gap is NOT affected
  });
  it('is independent of the order the events were listed in', () => {
    const shuffled = entry([{ fixed: '1.2.6' }, { introduced: '1.0.0' }, { fixed: '0.2.4' }, { introduced: '0' }], {}, 'SEMVER', 'minimist');
    expect(isVersionAffected(shuffled, 'minimist', '0.5.0')).toBe(false);
    expect(isVersionAffected(shuffled, 'minimist', '1.2.0')).toBe(true);
  });
  it('last_affected is inclusive', () => {
    const e = entry([{ introduced: '2.0.0' }, { last_affected: '2.5.3' }]);
    expect([isVersionAffected(e, 'pkg', '1.9.9'), isVersionAffected(e, 'pkg', '2.0.0'), isVersionAffected(e, 'pkg', '2.5.3'), isVersionAffected(e, 'pkg', '2.5.4')]).toEqual([false, true, true, false]);
  });
  it('an introduced-only range is open-ended', () => {
    expect(isVersionAffected(entry([{ introduced: '3.1.0' }]), 'pkg', '99.0.0')).toBe(true);
  });
  it('explicit versions are OR-ed with ranges', () => {
    const e = entry([{ introduced: '1.0.0' }, { fixed: '1.1.0' }], { versions: ['3.0.0', '3.0.1'] });
    expect([isVersionAffected(e, 'pkg', '1.0.5'), isVersionAffected(e, 'pkg', '3.0.1'), isVersionAffected(e, 'pkg', '2.0.0')]).toEqual([true, true, false]);
  });
  it('GIT ranges are ignored; unparseable events and versions never throw or match', () => {
    expect(isVersionAffected(entry([{ introduced: 'abc123' }], {}, 'GIT'), 'pkg', '1.0.0')).toBe(false);
    expect(isVersionAffected(entry([{ introduced: 'not-a-version' }, { fixed: '2.0.0' }]), 'pkg', '1.0.0')).toBe(false);
    expect(isVersionAffected(lodash, 'lodash', 'github:foo/bar#main')).toBe(false);
    expect(isVersionAffected(lodash, 'lodash', '')).toBe(false);
  });
  it('matches only the same package name (case-sensitive)', () => {
    expect(isVersionAffected(lodash, 'lodash-es', '4.0.0')).toBe(false);
    expect(isVersionAffected(lodash, 'Lodash', '4.0.0')).toBe(false);
  });
  it('a withdrawn advisory affects nothing', () => {
    expect(advisoryAffects({ affected: lodash, withdrawn: new Date() }, 'lodash', '4.0.0')).toBe(false);
    expect(advisoryAffects({ affected: lodash, withdrawn: null }, 'lodash', '4.0.0')).toBe(true);
  });
});

describe('smallestFixedVersion', () => {
  const lodash = adv(lodashCmdInjection);
  const minimist = adv(minimistProto);
  it('picks the fixed version just above the installed one', () => {
    expect(smallestFixedVersion(lodash, 'lodash', '4.17.20')).toBe('4.17.21');
    expect(smallestFixedVersion(lodash, 'lodash', '3.10.1')).toBe('4.17.21');
  });
  it('with several branches, the SMALLEST fix greater than installed (not the newest)', () => {
    expect(smallestFixedVersion(minimist, 'minimist', '0.0.8')).toBe('0.2.4');
    expect(smallestFixedVersion(minimist, 'minimist', '1.2.0')).toBe('1.2.6');
    expect(smallestFixedVersion(minimist, 'minimist', '0.2.4')).toBe('1.2.6');
  });
  it('null when already past every fix, when only last_affected is known, or for another package', () => {
    expect(smallestFixedVersion(minimist, 'minimist', '1.2.6')).toBeNull();
    expect(smallestFixedVersion({ affected: entry([{ introduced: '0' }, { last_affected: '2.0.0' }]) }, 'pkg', '1.0.0')).toBeNull();
    expect(smallestFixedVersion(lodash, 'underscore', '1.0.0')).toBeNull();
  });
  it('skips a "fixed" version that the explicit versions list still marks affected', () => {
    // 2.0.0 is announced as the fix, yet the advisory also lists 2.0.0 itself as affected; 2.1.0 is the real fix.
    const a = { affected: entry([{ introduced: '0' }, { fixed: '2.0.0' }, { introduced: '2.0.1' }, { fixed: '2.1.0' }], { versions: ['2.0.0'] }) };
    expect(smallestFixedVersion(a, 'pkg', '1.0.0')).toBe('2.1.0');
    // and when the only announced fix is itself affected, there is no usable fix
    const only = { affected: entry([{ introduced: '0' }, { fixed: '2.0.0' }], { versions: ['2.0.0'] }) };
    expect(smallestFixedVersion(only, 'pkg', '1.0.0')).toBeNull();
  });
  it('returns null for an unparseable installed version', () => {
    expect(smallestFixedVersion(lodash, 'lodash', 'git+ssh://x')).toBeNull();
  });
});
