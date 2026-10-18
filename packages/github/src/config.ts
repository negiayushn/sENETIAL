/** .env files cannot hold multi-line values easily, so accept the three common encodings of the PEM. */
export function normalizePrivateKey(raw: string): string {
  const trimmed = raw.trim();
  let pem = trimmed.includes('-----BEGIN') ? trimmed.replace(/\\n/g, '\n') : Buffer.from(trimmed, 'base64').toString('utf8');
  pem = pem.trim();
  if (!/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(pem)) {
    throw new Error('GITHUB_APP_PRIVATE_KEY is not a PEM private key (expected PEM, PEM with \\n escapes, or base64-encoded PEM)');
  }
  return pem;
}
