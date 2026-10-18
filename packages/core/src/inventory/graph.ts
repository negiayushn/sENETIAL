/**
 * Dependency graph reconstruction from a snapshot, to answer "which direct dependency pulled this in?".
 * Resolution follows Node's rule: a package's dependency `x` is the nearest `node_modules/x` walking up from the
 * package's own directory to the project root.
 */
export interface GraphNode {
  name: string;
  version: string;
  path: string;
  direct: boolean;
  dev?: boolean;
  requires: string[];
}

export interface ChainLink {
  name: string;
  version: string;
  path: string;
}

export interface DependencyGraph {
  byPath: Map<string, GraphNode>;
  /** child path → paths of the packages that depend on it */
  parents: Map<string, string[]>;
}

/** Directories to look in for `node_modules/<dep>`, nearest first, ending with the project root (''). */
function lookupScopes(path: string): string[] {
  const scopes = [path];
  let cur = path;
  for (;;) {
    const i = cur.lastIndexOf('/node_modules/');
    if (i === -1) break;
    cur = cur.slice(0, i);
    scopes.push(cur);
  }
  if (cur !== '' && !cur.includes('node_modules/')) scopes.push(''); // workspace member → hoisted root
  if (!scopes.includes('')) scopes.push('');
  return scopes;
}

export function resolveDependency(fromPath: string, dep: string, byPath: Map<string, GraphNode>): string | null {
  for (const scope of lookupScopes(fromPath)) {
    const candidate = scope === '' ? `node_modules/${dep}` : `${scope}/node_modules/${dep}`;
    if (byPath.has(candidate)) return candidate;
  }
  return null;
}

export function buildDependencyGraph(nodes: GraphNode[]): DependencyGraph {
  const byPath = new Map(nodes.map((n) => [n.path, n]));
  const parents = new Map<string, string[]>();
  for (const n of nodes) {
    for (const dep of n.requires) {
      const child = resolveDependency(n.path, dep, byPath);
      if (!child || child === n.path) continue;
      const list = parents.get(child);
      if (list) list.push(n.path);
      else parents.set(child, [n.path]);
    }
  }
  return { byPath, parents };
}

const link = (n: GraphNode): ChainLink => ({ name: n.name, version: n.version, path: n.path });

/**
 * Shortest chains from a DIRECT dependency down to `targetPath`, e.g.
 *   express@4.18.2 → accepts@1.3.8 → negotiator@0.6.2
 * Walks the graph backwards from the target (so cost is bounded by the target's ancestors, not the whole tree),
 * at most `max` chains, at most one per direct dependency. A direct dependency yields a one-link chain.
 */
export function chainsToDirect(graph: DependencyGraph, targetPath: string, max = 3): ChainLink[][] {
  const target = graph.byPath.get(targetPath);
  if (!target) return [];
  if (target.direct) return [[link(target)]];

  // `towardTarget.get(p)` = the next package on p's way down to the target. Following it rebuilds a chain in O(length),
  // instead of copying a growing array at every step (which is quadratic in the depth of the tree).
  const towardTarget = new Map<string, string>();
  const chainFrom = (start: string): ChainLink[] => {
    const chain: ChainLink[] = [];
    for (let p: string | undefined = start; p !== undefined; p = towardTarget.get(p)) {
      const node = graph.byPath.get(p);
      if (node) chain.push(link(node));
    }
    return chain;
  };

  const out: ChainLink[][] = [];
  const reachedDirect = new Set<string>();
  const visited = new Set<string>([targetPath]);
  const queue: string[] = [targetPath];

  for (let head = 0; head < queue.length && out.length < max; head++) {
    const path = queue[head];
    for (const parentPath of graph.parents.get(path) ?? []) {
      const parent = graph.byPath.get(parentPath);
      if (!parent) continue;
      if (parent.direct) {
        if (!reachedDirect.has(parentPath)) {
          reachedDirect.add(parentPath);
          const chain = [link(parent), ...chainFrom(path)];
          out.push(chain);
          if (out.length >= max) break;
        }
      } else if (!visited.has(parentPath)) {
        visited.add(parentPath);
        towardTarget.set(parentPath, path);
        queue.push(parentPath);
      }
    }
  }
  return out;
}
