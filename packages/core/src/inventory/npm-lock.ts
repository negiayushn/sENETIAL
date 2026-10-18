/**
 * package-lock.json → flat list of installed packages.
 *
 * Pure function over text we already downloaded: nothing here touches the network, a filesystem or npm.
 * Lockfile content comes from a repository we do not control, so it is treated as hostile input
 * (size caps, Map instead of plain objects keyed by package name, no eval, no install scripts).
 */

export class LockfileParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockfileParseError';
  }
}

export interface PackageEntry {
  /** Real package name (aliases resolved), e.g. "@scope/pkg". This is what advisories are matched on. */
  name: string;
  version: string;
  /** Install location, e.g. "node_modules/foo/node_modules/bar". Disambiguates duplicate versions. */
  path: string;
  /** Only reachable through devDependencies. */
  dev: boolean;
  optional: boolean;
  /** Declared by the root package (or a workspace member) and installed at its top level. */
  direct: boolean;
  /** Where it was fetched from; advisories only make sense for "registry". */
  source: 'registry' | 'git' | 'file' | 'other';
  /** Names this package depends on (dependencies + optionalDependencies). Lets Phase 4 build a path to the direct parent. */
  requires: string[];
}

export interface ParsedLockfile {
  lockfileVersion: number;
  packages: PackageEntry[];
  directCount: number;
  /** Non-fatal oddities (skipped entries etc.) */
  warnings: string[];
}

export interface ParseOptions {
  /** Text of the root package.json, if available. Falls back to the lockfile's own root entry. */
  packageJson?: string;
  maxPackages?: number;
}

const DEFAULT_MAX_PACKAGES = 100_000;
const NM = 'node_modules/';

type RawEntry = {
  name?: unknown;
  version?: unknown;
  resolved?: unknown;
  link?: unknown;
  dev?: unknown;
  devOptional?: unknown;
  optional?: unknown;
  dependencies?: unknown;
  devDependencies?: unknown;
  optionalDependencies?: unknown;
  requires?: unknown;
};

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const keysOf = (v: unknown): string[] => (isObj(v) ? Object.keys(v) : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

function sourceOf(resolved: unknown, version: string): PackageEntry['source'] {
  const r = str(resolved) ?? '';
  if (/^(git\+|git:|github:|git@)/i.test(r) || /^(git\+|git:|github:)/i.test(version)) return 'git';
  if (/^file:/i.test(r) || /^file:/i.test(version)) return 'file';
  if (r === '' || /^https?:\/\//i.test(r)) return 'registry';
  return 'other';
}

/** "node_modules/a/node_modules/@s/b" → "@s/b" */
export function nameFromPath(path: string): string {
  const i = path.lastIndexOf(NM);
  return i === -1 ? path : path.slice(i + NM.length);
}

/** Depth-1 means "node_modules/x" directly under `base` ('' for the root project). */
function isTopLevelOf(path: string, base: string): boolean {
  const prefix = base ? `${base}/${NM}` : NM;
  if (!path.startsWith(prefix)) return false;
  return !path.slice(prefix.length).includes(NM);
}

function rootDirectNames(packageJsonText: string | undefined, rootEntry: RawEntry | undefined, warnings: string[]): Set<string> {
  const names = new Set<string>();
  const addFrom = (o: unknown) => {
    if (!isObj(o)) return;
    // peerDependencies are deliberately ignored: the consumer decides what satisfies them.
    for (const k of [...keysOf(o.dependencies), ...keysOf(o.devDependencies), ...keysOf(o.optionalDependencies)]) names.add(k);
  };
  if (packageJsonText !== undefined) {
    try {
      addFrom(JSON.parse(packageJsonText));
      return names;
    } catch {
      warnings.push('package.json is not valid JSON; using the lockfile’s own root entry to detect direct dependencies');
    }
  }
  addFrom(rootEntry);
  return names;
}

export function parseNpmLock(lockText: string, opts: ParseOptions = {}): ParsedLockfile {
  const max = opts.maxPackages ?? DEFAULT_MAX_PACKAGES;
  let lock: unknown;
  try {
    lock = JSON.parse(lockText);
  } catch {
    throw new LockfileParseError('package-lock.json is not valid JSON');
  }
  if (!isObj(lock)) throw new LockfileParseError('package-lock.json has an unexpected shape');

  const lockfileVersion = typeof lock.lockfileVersion === 'number' ? lock.lockfileVersion : 1;
  const warnings: string[] = [];
  const out: PackageEntry[] = [];

  if (lockfileVersion >= 2 && isObj(lock.packages)) {
    const entries = Object.entries(lock.packages) as [string, RawEntry][];
    const rootEntry = entries.find(([k]) => k === '')?.[1];
    const rootDirect = rootDirectNames(opts.packageJson, rootEntry, warnings);

    // Workspace members are first-party packages (keys that are not under node_modules). What THEY declare is direct too.
    const workspaceDirect = new Map<string, Set<string>>(); // base path → names
    for (const [key, entry] of entries) {
      if (key === '' || key.includes(NM) || !isObj(entry) || entry.link === true) continue;
      const s = new Set<string>();
      for (const k of [...keysOf(entry.dependencies), ...keysOf(entry.devDependencies), ...keysOf(entry.optionalDependencies)]) s.add(k);
      workspaceDirect.set(key, s);
    }

    for (const [key, entry] of entries) {
      if (key === '') continue; // the project itself
      if (!isObj(entry)) {
        warnings.push(`skipped malformed entry "${key}"`);
        continue;
      }
      if (entry.link === true) continue; // symlink to a workspace member
      if (!key.includes(NM)) continue; // workspace member itself
      const version = str(entry.version);
      if (!version) {
        warnings.push(`skipped "${key}": no version`);
        continue;
      }
      if (out.length >= max) throw new LockfileParseError(`Lockfile has more than ${max} packages`);

      const name = str(entry.name) ?? nameFromPath(key); // `name` is present for npm aliases (foo → npm:bar@1)
      let direct = rootDirect.has(nameFromPath(key)) && isTopLevelOf(key, '');
      if (!direct) {
        for (const [base, names] of workspaceDirect) {
          // hoisted to the root node_modules, or installed beside the member when versions conflict
          if (names.has(nameFromPath(key)) && (isTopLevelOf(key, '') || isTopLevelOf(key, base))) {
            direct = true;
            break;
          }
        }
      }
      out.push({
        name,
        version,
        path: key,
        dev: entry.dev === true,
        optional: entry.optional === true || entry.devOptional === true,
        direct,
        source: sourceOf(entry.resolved, version),
        requires: [...new Set([...keysOf(entry.dependencies), ...keysOf(entry.optionalDependencies)])],
      });
    }
  } else if (isObj(lock.dependencies)) {
    // lockfileVersion 1 (npm 5/6): nested "dependencies" tree. Names come from the tree keys.
    const rootDirect = rootDirectNames(opts.packageJson, undefined, warnings);
    const walk = (deps: Record<string, unknown>, parentPath: string, depth: number) => {
      if (depth > 64) {
        warnings.push('dependency tree deeper than 64 levels was truncated');
        return;
      }
      for (const [depName, raw] of Object.entries(deps)) {
        if (!isObj(raw)) continue;
        const entry = raw as RawEntry;
        const version = str(entry.version);
        if (!version) continue;
        if (out.length >= max) throw new LockfileParseError(`Lockfile has more than ${max} packages`);
        const path = `${parentPath}${NM}${depName}`;
        out.push({
          name: depName,
          version,
          path,
          dev: entry.dev === true,
          optional: entry.optional === true,
          direct: depth === 0 && rootDirect.has(depName),
          source: sourceOf(entry.resolved, version),
          requires: keysOf(entry.requires),
        });
        if (isObj(entry.dependencies)) walk(entry.dependencies, `${path}/`, depth + 1);
      }
    };
    walk(lock.dependencies, '', 0);
  } else if (lockfileVersion >= 2) {
    throw new LockfileParseError('package-lock.json has no "packages" section');
  }
  // else: empty lockfile (project with no dependencies) → zero packages, which is valid.

  return { lockfileVersion, packages: out, directCount: out.filter((p) => p.direct).length, warnings };
}
