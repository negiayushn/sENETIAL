/**
 * Abbreviated records modelled on real OSV/GHSA advisories for well-known vulnerable npm packages
 * (lodash CVE-2021-23337 / CVE-2020-8203, minimist CVE-2021-44906 / CVE-2020-7598). Trimmed for tests, not verbatim.
 */
export const lodashCmdInjection = {
  id: 'GHSA-35jh-r3h4-6jhm',
  modified: '2023-11-08T04:06:46Z',
  published: '2021-05-06T16:05:51Z',
  aliases: ['CVE-2021-23337'],
  summary: 'Command Injection in lodash',
  details: 'lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77', 'CWE-94'] },
  references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }, { type: 'WEB', url: 'javascript:alert(1)' }],
};

export const lodashZipObjectDeep = {
  id: 'GHSA-p6mc-m468-83gx',
  modified: '2023-01-09T05:05:15Z',
  aliases: ['CVE-2020-8203'],
  summary: 'Prototype Pollution in lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H' }],
  affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }] }],
};

// two disjoint ranges in ONE range object (one per major branch)
export const minimistProto = {
  id: 'GHSA-xvch-5gv4-984h',
  modified: '2022-03-18T00:00:00Z',
  aliases: ['CVE-2021-44906'],
  summary: 'Prototype Pollution in minimist',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [{ package: { ecosystem: 'npm', name: 'minimist' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }, { introduced: '1.0.0' }, { fixed: '1.2.6' }] }] }],
};

// label only, no CVSS; GitHub says MODERATE
export const labelOnly = {
  id: 'GHSA-aaaa-bbbb-cccc',
  modified: '2022-01-01T00:00:00Z',
  summary: 'Label-only severity',
  affected: [{ package: { ecosystem: 'npm', name: 'left-pad' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.3.1' }] }] }],
  database_specific: { severity: 'MODERATE' },
};
