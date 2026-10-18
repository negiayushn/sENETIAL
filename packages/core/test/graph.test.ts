import { describe, expect, it } from 'vitest';
import { buildDependencyGraph, chainsToDirect, resolveDependency, type GraphNode } from '../src';

const n = (path: string, version: string, requires: string[] = [], direct = false): GraphNode => ({ name: path.slice(path.lastIndexOf('node_modules/') + 13), version, path, direct, requires });
const names = (chains: { name: string; version: string }[][]) => chains.map((c) => c.map((l) => `${l.name}@${l.version}`).join(' > '));

describe('resolveDependency (Node resolution)', () => {
  const nodes = [n('node_modules/a', '1.0.0'), n('node_modules/x', '1.0.0'), n('node_modules/x/node_modules/a', '2.0.0'), n('node_modules/@s/p', '1.0.0')];
  const byPath = new Map(nodes.map((x) => [x.path, x]));
  it('prefers the nearest node_modules', () => {
    expect(resolveDependency('node_modules/x', 'a', byPath)).toBe('node_modules/x/node_modules/a');
    expect(resolveDependency('node_modules/a', 'x', byPath)).toBe('node_modules/x');
  });
  it('walks up to the hoisted copy, handles scoped names, and returns null when absent', () => {
    expect(resolveDependency('node_modules/x/node_modules/a', 'x', byPath)).toBe('node_modules/x');
    expect(resolveDependency('node_modules/a', '@s/p', byPath)).toBe('node_modules/@s/p');
    expect(resolveDependency('node_modules/a', 'missing', byPath)).toBeNull();
  });
  it('a workspace member resolves to its own node_modules, then the hoisted root', () => {
    const ws = [n('packages/web/node_modules/lib', '1.0.0'), n('node_modules/react', '18.0.0')];
    const m = new Map(ws.map((x) => [x.path, x]));
    expect(resolveDependency('packages/web/node_modules/lib', 'react', m)).toBe('node_modules/react');
  });
});

describe('chainsToDirect', () => {
  const tree = [
    n('node_modules/express', '4.18.2', ['accepts', 'qs'], true),
    n('node_modules/accepts', '1.3.8', ['negotiator']),
    n('node_modules/negotiator', '0.6.3'),
    n('node_modules/qs', '6.11.0'),
    n('node_modules/jest', '29.0.0', ['accepts'], true),
    n('node_modules/orphan', '1.0.0'),
  ];
  const g = buildDependencyGraph(tree);

  it('a direct dependency is its own one-link chain', () => {
    expect(names(chainsToDirect(g, 'node_modules/express'))).toEqual(['express@4.18.2']);
  });
  it('shows the path from the direct parent down to the transitive package', () => {
    expect(names(chainsToDirect(g, 'node_modules/negotiator'))).toEqual(['express@4.18.2 > accepts@1.3.8 > negotiator@0.6.3', 'jest@29.0.0 > accepts@1.3.8 > negotiator@0.6.3']);
  });
  it('limits the number of chains, one per direct dependency', () => {
    expect(chainsToDirect(g, 'node_modules/negotiator', 1)).toHaveLength(1);
  });
  it('an unreachable package or unknown path yields no chains', () => {
    expect(chainsToDirect(g, 'node_modules/orphan')).toEqual([]);
    expect(chainsToDirect(g, 'node_modules/nope')).toEqual([]);
  });
  it('follows nested copies precisely', () => {
    const nested = buildDependencyGraph([
      n('node_modules/app-dep', '1.0.0', ['shared'], true),
      n('node_modules/app-dep/node_modules/shared', '1.0.0'),
      n('node_modules/shared', '9.9.9'),
    ]);
    expect(names(chainsToDirect(nested, 'node_modules/app-dep/node_modules/shared'))).toEqual(['app-dep@1.0.0 > shared@1.0.0']);
    expect(chainsToDirect(nested, 'node_modules/shared')).toEqual([]); // nobody depends on the hoisted copy
  });
  it('survives dependency cycles', () => {
    const cyc = buildDependencyGraph([n('node_modules/d', '1.0.0', ['a'], true), n('node_modules/a', '1.0.0', ['b']), n('node_modules/b', '1.0.0', ['a'])]);
    expect(names(chainsToDirect(cyc, 'node_modules/b'))).toEqual(['d@1.0.0 > a@1.0.0 > b@1.0.0']);
  });
  it('is fast on a large graph', () => {
    const many: GraphNode[] = [n('node_modules/root', '1.0.0', ['p0'], true)];
    for (let i = 0; i < 20_000; i++) many.push(n(`node_modules/p${i}`, '1.0.0', i < 19_999 ? [`p${i + 1}`] : []));
    const big = buildDependencyGraph(many);
    const t0 = Date.now();
    expect(chainsToDirect(big, 'node_modules/p19999')[0]).toHaveLength(20_001);
    expect(Date.now() - t0).toBeLessThan(1500);
  });
});
