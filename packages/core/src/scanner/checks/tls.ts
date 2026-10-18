import type { TlsProbeResult } from '../../net/tls-probe';
import type { Check, ScanContext, ScanFinding } from '../types';

const DAY_MS = 86_400_000;
const UNREACHABLE = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH']);

export class TlsCheck implements Check {
  readonly id = 'tls';

  async run(ctx: ScanContext): Promise<ScanFinding[]> {
    const out: ScanFinding[] = [];

    let main: TlsProbeResult | null = null;
    let mainError: unknown;
    try {
      main = await ctx.tlsProbe();
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code && UNREACHABLE.has(code)) {
        return [
          {
            type: 'tls.unavailable',
            key: '443',
            title: 'HTTPS is not reachable on port 443',
            severity: 'MEDIUM',
            confidence: 'POTENTIAL', // could be a transient network problem or a firewall in front of the scanner
            evidence: { port: 443, error: code },
            remediation: 'Serve the site over HTTPS (port 443) with a valid certificate and redirect HTTP to HTTPS.',
          },
        ];
      }
      mainError = err; // maybe a legacy-only server: decide after the legacy probe below
    }

    // --- Legacy protocols. The handshake above negotiates the BEST version, so a server that still accepts
    //     TLS 1.0/1.1 would look fine; offer ONLY the old versions and see whether it agrees. A server that
    //     speaks ONLY legacy TLS fails the handshake above and is caught here instead of being an "error". ---
    let legacy: TlsProbeResult | null = null;
    try {
      legacy = await ctx.tlsProbe({ minVersion: 'TLSv1', maxVersion: 'TLSv1.1' });
    } catch {
      // Handshake refused (the expected outcome) or inconclusive network error: nothing to report.
    }

    if (!main && !legacy) throw mainError;
    const inspected = (main ?? legacy)!; // certificate details come from whichever handshake succeeded

    // --- Certificate validity window ---
    if (inspected.cert.validTo) {
      const validTo = new Date(inspected.cert.validTo);
      if (!Number.isNaN(validTo.getTime())) {
        const days = Math.floor((validTo.getTime() - ctx.now().getTime()) / DAY_MS);
        if (days < 0) {
          out.push({
            type: 'tls.certificate-expiry',
            key: 'validity',
            title: `TLS certificate expired ${-days} day${days === -1 ? '' : 's'} ago`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            evidence: { validTo: inspected.cert.validTo, daysRemaining: days, issuer: inspected.cert.issuerO ?? inspected.cert.issuerCN },
            remediation: 'Renew the certificate immediately and enable automatic renewal (e.g. ACME / Let’s Encrypt).',
          });
        } else if (days < 14) {
          out.push({
            type: 'tls.certificate-expiry',
            key: 'validity',
            title: `TLS certificate expires in ${days} day${days === 1 ? '' : 's'}`,
            severity: days <= 3 ? 'HIGH' : 'MEDIUM',
            confidence: 'CONFIRMED',
            evidence: { validTo: inspected.cert.validTo, daysRemaining: days, issuer: inspected.cert.issuerO ?? inspected.cert.issuerCN },
            remediation: 'Renew the certificate and enable automatic renewal so this cannot recur.',
          });
        }
      }
    }

    // --- Hostname match: checked explicitly, because Node skips it when the chain already failed ---
    if (inspected.hostnameError) {
      out.push({
        type: 'tls.hostname-mismatch',
        key: 'hostname',
        title: 'TLS certificate does not match the hostname',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        evidence: { hostname: ctx.hostname, subjectCN: inspected.cert.subjectCN, subjectAltName: inspected.cert.san, error: inspected.hostnameError },
        remediation: 'Issue a certificate that lists this hostname in its Subject Alternative Names.',
      });
    }

    // --- Chain trust (expiry and hostname are reported above, don't double-report them) ---
    const authErr = inspected.authorizationError;
    if (authErr && authErr !== 'CERT_HAS_EXPIRED' && authErr !== 'ERR_TLS_CERT_ALTNAME_INVALID') {
      const selfSigned = authErr === 'DEPTH_ZERO_SELF_SIGNED_CERT' || authErr === 'SELF_SIGNED_CERT_IN_CHAIN';
      const incomplete = authErr === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || authErr === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY';
      out.push({
        type: 'tls.untrusted-chain',
        key: 'chain',
        title: selfSigned
          ? 'TLS certificate is self-signed'
          : incomplete
            ? 'TLS certificate chain is incomplete or not trusted'
            : 'TLS certificate is not trusted',
        severity: incomplete ? 'MEDIUM' : 'HIGH',
        // Self-signed is unambiguous. "Cannot build a chain" could also mean our own trust store lacks the CA.
        confidence: selfSigned ? 'CONFIRMED' : 'POTENTIAL',
        evidence: { verifyError: authErr, issuer: inspected.cert.issuerO ?? inspected.cert.issuerCN },
        remediation: incomplete
          ? 'Serve the full certificate chain (leaf + intermediates) from the web server.'
          : 'Use a certificate issued by a publicly trusted certificate authority.',
      });
    }

    if (legacy) {
      out.push({
        type: 'tls.legacy-protocol',
        key: 'legacy',
        title: `Server accepts deprecated ${legacy.protocol ?? 'TLS 1.0/1.1'}`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        evidence: { accepted: legacy.protocol, modernHandshakeFailed: main === null },
        remediation: 'Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.',
      });
    }

    return out;
  }
}
