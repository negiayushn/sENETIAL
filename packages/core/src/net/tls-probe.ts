import tls, { type PeerCertificate } from 'node:tls';
import type { Guard } from './guard';

export interface TlsProbeResult {
  /** Negotiated protocol, e.g. "TLSv1.3" */
  protocol: string | null;
  /** Node's verdict on the chain against the system CA store (the hostname check only runs if the chain is OK) */
  authorized: boolean;
  authorizationError: string | null;
  /** Result of an explicit tls.checkServerIdentity(); undefined means the hostname matches */
  hostnameError: string | null;
  cert: {
    subjectCN?: string;
    issuerCN?: string;
    issuerO?: string;
    validFrom?: string;
    validTo?: string;
    san?: string;
    fingerprint256?: string;
  };
}

export interface TlsProbeOptions {
  hostname: string;
  guard: Guard;
  port?: number;
  timeoutMs?: number;
  minVersion?: tls.SecureVersion;
  maxVersion?: tls.SecureVersion;
}

/**
 * One TLS handshake, inspected but not trusted. rejectUnauthorized is false on purpose: we WANT to connect to
 * servers with expired / self-signed / mismatched certs so we can report them.
 *
 * SSRF: the hostname is resolved through the guard and we connect to the validated IP directly, passing the
 * hostname only as SNI. (A bare tls.connect({ host }) would do its own unguarded DNS lookup.)
 */
export async function tlsProbe(opts: TlsProbeOptions): Promise<TlsProbeResult> {
  const { hostname, guard } = opts;
  const [target] = await guard.resolveSafe(hostname);
  const timeoutMs = opts.timeoutMs ?? 5000;

  return new Promise<TlsProbeResult>((resolve, reject) => {
    const legacy = opts.minVersion && (opts.minVersion === 'TLSv1' || opts.minVersion === 'TLSv1.1');
    const socket = tls.connect(
      {
        host: target.address,
        port: opts.port ?? 443,
        servername: hostname, // SNI + identity check target
        rejectUnauthorized: false,
        minVersion: opts.minVersion,
        maxVersion: opts.maxVersion,
        // OpenSSL 3 refuses TLS 1.0/1.1 at the default security level; the probe has to be allowed to try.
        ciphers: legacy ? 'ALL:@SECLEVEL=0' : undefined,
      },
      () => {
        const peer: PeerCertificate = socket.getPeerCertificate(true);
        const hasCert = peer && Object.keys(peer).length > 0;
        const hostnameErr = hasCert ? tls.checkServerIdentity(hostname, peer) : undefined;
        const result: TlsProbeResult = {
          protocol: socket.getProtocol(),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          hostnameError: hostnameErr ? hostnameErr.message : null,
          cert: hasCert
            ? {
                subjectCN: peer.subject?.CN as string | undefined,
                issuerCN: peer.issuer?.CN as string | undefined,
                issuerO: peer.issuer?.O as string | undefined,
                validFrom: peer.valid_from,
                validTo: peer.valid_to,
                san: peer.subjectaltname,
                fingerprint256: peer.fingerprint256,
              }
            : {},
        };
        socket.end();
        resolve(result);
      },
    );
    socket.setTimeout(timeoutMs, () => socket.destroy(Object.assign(new Error('TLS handshake timed out'), { code: 'ETIMEDOUT' })));
    socket.once('error', reject);
  });
}
