import type tls from 'node:tls';
import type { SafeResponse } from '../net/safe-fetch';
import type { TlsProbeResult } from '../net/tls-probe';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'CONFIRMED' | 'POTENTIAL';

/** What a check reports. The worker turns this into a database Finding (fingerprint, redaction, upsert). */
export interface ScanFinding {
  /** Machine-readable id, e.g. "headers.csp-missing". Part of the fingerprint. */
  type: string;
  /** Stable identity within `type` (cookie name, path…). Part of the fingerprint: must not change between scans. */
  key: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  evidence?: Record<string, unknown>;
  remediation?: string;
}

export interface ScanContext {
  readonly hostname: string;
  /** Random per scan, e.g. /sentinel-probe-a1b2c3d4 – used to provoke a 404. */
  readonly notFoundPath: string;
  now(): Date;
  /** `https://host` if the site answers on HTTPS, otherwise `http://host` (after any same-host redirects). */
  origin(): Promise<string>;
  /** GET / – memoised, shared by every check. */
  getRoot(): Promise<SafeResponse>;
  /** GET <path> on the site's origin – memoised per path, rate-limited, SSRF-guarded. */
  get(path: string): Promise<SafeResponse>;
  tlsProbe(opts?: { minVersion?: tls.SecureVersion; maxVersion?: tls.SecureVersion }): Promise<TlsProbeResult>;
}

/** Plugin interface: add a class, add it to `defaultChecks()`. */
export interface Check {
  readonly id: string;
  run(ctx: ScanContext): Promise<ScanFinding[]>;
}
