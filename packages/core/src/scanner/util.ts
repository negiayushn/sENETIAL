import type { SafeResponse } from '../net/safe-fetch';

/** Header value as a single string (multiple values joined), or undefined. Names are matched case-insensitively. */
export function header(res: Pick<SafeResponse, 'headers'>, name: string): string | undefined {
  const v = res.headers[name.toLowerCase()];
  if (v == null) return undefined;
  return Array.isArray(v) ? v.join(', ') : v;
}

export const isRedirect = (res: Pick<SafeResponse, 'statusCode'>) => res.statusCode >= 300 && res.statusCode < 400;
export const clip = (s: string, n = 200) => (s.length > n ? `${s.slice(0, n)}…` : s);
