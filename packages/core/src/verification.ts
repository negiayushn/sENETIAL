import dns from 'node:dns/promises';

export const CHALLENGE_LABEL = '_sentinel-challenge';
export const challengeRecordName = (hostname: string) => `${CHALLENGE_LABEL}.${hostname}`;
export const challengeRecordValue = (token: string) => `sentinel-verify=${token}`;

export type DnsVerifyResult =
  | { verified: true }
  | { verified: false; reason: 'NO_RECORD' | 'TOKEN_MISMATCH' | 'DNS_ERROR'; detail?: string };

export type TxtResolver = (name: string) => Promise<string[][]>;

const defaultResolver: TxtResolver = (() => {
  const r = new dns.Resolver({ timeout: 4000, tries: 2 });
  return (name: string) => r.resolveTxt(name);
})();

/** Some DNS UIs make people paste the surrounding quotes into the value; be forgiving about exactly that. */
const unquote = (s: string) => s.trim().replace(/^"(.*)"$/s, '$1').trim();

/**
 * Look for `sentinel-verify=<token>` at `_sentinel-challenge.<hostname>`.
 * resolveTxt returns each record as an array of <=255-byte chunks; they must be joined before comparing.
 */
export async function checkDnsChallenge(hostname: string, token: string, resolveTxt: TxtResolver = defaultResolver): Promise<DnsVerifyResult> {
  let records: string[][];
  try {
    records = await resolveTxt(challengeRecordName(hostname));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') return { verified: false, reason: 'NO_RECORD' };
    return { verified: false, reason: 'DNS_ERROR', detail: code ?? 'unknown' };
  }
  const values = records.map((chunks) => unquote(chunks.join('')));
  const expected = challengeRecordValue(token);
  if (values.includes(expected)) return { verified: true };
  if (values.some((v) => v.startsWith('sentinel-verify='))) return { verified: false, reason: 'TOKEN_MISMATCH' };
  return { verified: false, reason: 'NO_RECORD' };
}
