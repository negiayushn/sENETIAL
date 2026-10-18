import { describe, expect, it } from 'vitest';
import { cvss3BaseScore, severityFromLabel, severityFromScore } from '../src';

describe('cvss3BaseScore', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1], // the classic reflected-XSS score
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', 9.1], // lodash CVE-2019-10744
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', 7.4], // lodash CVE-2020-8203
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2], // lodash CVE-2021-23337
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8], // 3.0 uses the same base formula
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s -> %s', (vector, score) => expect(cvss3BaseScore(vector)).toBe(score));

  it.each([
    ['CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P'],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    ['9.8'], [''], ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'], // missing A
    ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'], // bad value
    ['CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'], // duplicate metric
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:__proto__/C:H/I:H/A:H'],
  ])('returns null for unsupported/invalid vector %s', (v) => expect(cvss3BaseScore(v)).toBeNull());

  it('maps scores to NVD bands', () => {
    expect([10, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0].map(severityFromScore)).toEqual(['CRITICAL', 'CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW', 'LOW', 'INFO']);
  });
  it('maps GitHub labels (MODERATE = MEDIUM) and rejects junk', () => {
    expect(['critical', 'HIGH', 'Moderate', 'MEDIUM', 'low'].map(severityFromLabel)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW']);
    expect([severityFromLabel('whatever'), severityFromLabel(5), severityFromLabel(undefined)]).toEqual([null, null, null]);
  });
});
