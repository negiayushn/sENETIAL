import { describe, expect, it } from 'vitest';
import { LockfileParseError, nameFromPath, parseNpmLock } from '../src';

const pkgJson = (deps: object = {}, dev: object = {}) => JSON.stringify({ name: 'app', dependencies: deps, devDependencies: dev });
const v3 = (packages: Record<string, unknown>) => JSON.stringify({ name: 'app', lockfileVersion: 3, packages: { '': { name: 'app' }, ...packages } });
const by = (r: ReturnType<typeof parseNpmLock>, path: string) => r.packages.find((p) => p.path === path)!;

describe('nameFromPath', () => {
  it.each([
    ['node_modules/foo', 'foo'],
    ['node_modules/@scope/pkg', '@scope/pkg'],
    ['node_modules/foo/node_modules/bar', 'bar'],
    ['node_modules/foo/node_modules/@s/bar', '@s/bar'],
  ])('%s -> %s', (p, n) => expect(nameFromPath(p)).toBe(n));
});

describe('parseNpmLock v2/v3', () => {
  const lock = v3({
    'node_modules/express': { version: '4.18.2', resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz', dependencies: { accepts: '~1.3.8', qs: '6.11.0' }, optionalDependencies: { fsevents: '*' } },
    'node_modules/accepts': { version: '1.3.8' },
    'node_modules/qs': { version: '6.11.0' },
    'node_modules/express/node_modules/qs': { version: '6.10.0' },
    'node_modules/@types/node': { version: '20.1.0', dev: true },
    'node_modules/fsevents': { version: '2.3.3', optional: true },
    'node_modules/jest/node_modules/qs': { version: '1.0.0', dev: true },
  });

  it('flattens every node_modules key with name, version, path and dev flag', () => {
    const r = parseNpmLock(lock, { packageJson: pkgJson({ express: '^4' }, { '@types/node': '^20' }) });
    expect(r.lockfileVersion).toBe(3);
    expect(r.packages).toHaveLength(7);
    expect(by(r, 'node_modules/express/node_modules/qs')).toMatchObject({ name: 'qs', version: '6.10.0', dev: false });
    expect(by(r, 'node_modules/@types/node')).toMatchObject({ name: '@types/node', dev: true });
    expect(by(r, 'node_modules/fsevents')).toMatchObject({ optional: true });
  });

  it('marks direct from root dependencies AND devDependencies', () => {
    const r = parseNpmLock(lock, { packageJson: pkgJson({ express: '^4' }, { '@types/node': '^20' }) });
    expect(by(r, 'node_modules/express').direct).toBe(true);
    expect(by(r, 'node_modules/@types/node').direct).toBe(true);
    expect(by(r, 'node_modules/accepts').direct).toBe(false);
    expect(r.directCount).toBe(2);
  });

  it('a NESTED copy of a package that is also a root dependency is not direct', () => {
    const r = parseNpmLock(lock, { packageJson: pkgJson({ express: '^4', qs: '^6' }) });
    expect(by(r, 'node_modules/qs').direct).toBe(true);
    expect(by(r, 'node_modules/express/node_modules/qs').direct).toBe(false);
  });

  it('falls back to the lockfile root entry when package.json is missing or broken', () => {
    const l = JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { accepts: '^1' } }, 'node_modules/accepts': { version: '1.3.8' }, 'node_modules/qs': { version: '6.0.0' } } });
    const r = parseNpmLock(l);
    expect(by(r, 'node_modules/accepts').direct).toBe(true);
    expect(by(r, 'node_modules/qs').direct).toBe(false);
    const broken = parseNpmLock(l, { packageJson: '{not json' });
    expect(by(broken, 'node_modules/accepts').direct).toBe(true);
    expect(broken.warnings.join()).toMatch(/package.json is not valid/);
  });

  it('records declared dependencies for later path-to-parent reporting', () => {
    const r = parseNpmLock(lock);
    expect(by(r, 'node_modules/express').requires.sort()).toEqual(['accepts', 'fsevents', 'qs']);
  });

  it('resolves npm aliases to the REAL package name', () => {
    const r = parseNpmLock(v3({ 'node_modules/my-lodash': { name: 'lodash', version: '4.17.20' } }));
    expect(r.packages[0]).toMatchObject({ name: 'lodash', path: 'node_modules/my-lodash' });
  });

  it('classifies sources so git/file deps are not matched against registry advisories', () => {
    const r = parseNpmLock(v3({
      'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' },
      'node_modules/b': { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/b.git#abc' },
      'node_modules/c': { version: '1.0.0', resolved: 'file:../c' },
    }));
    expect(r.packages.map((p) => p.source)).toEqual(['registry', 'git', 'file']);
  });

  it('skips the root, workspace links and workspace members; workspace-declared deps count as direct', () => {
    const l = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'mono', workspaces: ['packages/*'] },
        'packages/web': { name: 'web', version: '1.0.0', dependencies: { react: '^18' } },
        'node_modules/web': { resolved: 'packages/web', link: true },
        'node_modules/react': { version: '18.2.0' },
        'node_modules/loose-envify': { version: '1.4.0' },
      },
    });
    const r = parseNpmLock(l, { packageJson: JSON.stringify({ name: 'mono' }) });
    expect(r.packages.map((p) => p.name).sort()).toEqual(['loose-envify', 'react']);
    expect(by(r, 'node_modules/react').direct).toBe(true);
    expect(by(r, 'node_modules/loose-envify').direct).toBe(false);
  });

  it('tolerates malformed entries and reports them as warnings', () => {
    const r = parseNpmLock(v3({ 'node_modules/ok': { version: '1.0.0' }, 'node_modules/novers': {}, 'node_modules/bad': 'oops' }));
    expect(r.packages.map((p) => p.name)).toEqual(['ok']);
    expect(r.warnings).toHaveLength(2);
  });

  it('treats hostile keys as data: no prototype pollution, no crash', () => {
    const text = '{"lockfileVersion":3,"packages":{"":{},"node_modules/__proto__":{"version":"1.0.0"},"node_modules/constructor":{"version":"2.0.0"}}}';
    const r = parseNpmLock(text, { packageJson: '{"dependencies":{"__proto__":"1","constructor":"1"}}' });
    expect(r.packages.map((p) => p.name).sort()).toEqual(['__proto__', 'constructor']);
    expect(({} as Record<string, unknown>).version).toBeUndefined();
  });

  it('enforces the package cap', () => {
    const many: Record<string, unknown> = {};
    for (let i = 0; i < 50; i++) many[`node_modules/p${i}`] = { version: '1.0.0' };
    expect(() => parseNpmLock(v3(many), { maxPackages: 10 })).toThrow(LockfileParseError);
  });

  it('keeps duplicate name@version at different paths (path matters for remediation)', () => {
    const r = parseNpmLock(v3({ 'node_modules/a': { version: '1.0.0' }, 'node_modules/x/node_modules/a': { version: '1.0.0' } }));
    expect(r.packages).toHaveLength(2);
  });
});

describe('parseNpmLock v1 and edge cases', () => {
  it('walks the nested dependencies tree of a v1 lockfile', () => {
    const l = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        express: { version: '4.16.0', requires: { qs: '6.5.1' }, dependencies: { qs: { version: '6.5.1', dev: false } } },
        mocha: { version: '5.0.0', dev: true },
      },
    });
    const r = parseNpmLock(l, { packageJson: pkgJson({ express: '^4' }, { mocha: '^5' }) });
    expect(r.packages.map((p) => `${p.path}@${p.version}`)).toEqual(['node_modules/express@4.16.0', 'node_modules/express/node_modules/qs@6.5.1', 'node_modules/mocha@5.0.0']);
    expect(by(r, 'node_modules/mocha')).toMatchObject({ dev: true, direct: true });
    expect(by(r, 'node_modules/express/node_modules/qs').direct).toBe(false);
  });

  it('v2 files carry both sections; the modern "packages" section wins', () => {
    const l = JSON.stringify({ lockfileVersion: 2, packages: { '': {}, 'node_modules/a': { version: '1.0.0' } }, dependencies: { a: { version: '1.0.0' }, stale: { version: '0.0.1' } } });
    expect(parseNpmLock(l).packages.map((p) => p.name)).toEqual(['a']);
  });

  it('an empty project is valid and has zero packages', () => {
    expect(parseNpmLock('{"lockfileVersion":3,"packages":{"":{}}}').packages).toEqual([]);
  });

  it.each([['not json'], ['[]'], ['null'], ['{"lockfileVersion":3}']])('rejects %s', (text) => {
    expect(() => parseNpmLock(text)).toThrow(LockfileParseError);
  });
});
