import { createHash } from 'node:crypto';

export interface FingerprintParts {
  source: 'WEB' | 'DEPENDENCY';
  /** Who the finding belongs to: the target id for web findings. */
  owner: string;
  type: string;
  /** Stable identity within the type (a header name, a cookie name + flag, a path…). Never a timestamp or a day count. */
  key: string;
}

/** sha256(source + owner + type + stable key). NUL-separated so ("ab","c") can never collide with ("a","bc"). */
export function fingerprint(p: FingerprintParts): string {
  return createHash('sha256').update([p.source, p.owner, p.type, p.key].join('\u0000')).digest('hex');
}
