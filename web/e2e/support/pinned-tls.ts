// Test code only. TLS stays verified against a lab server's per-install certificate: Chromium ignores
// NODE_EXTRA_CA_CERTS, so trust is pinned to that one certificate's public key
// (--ignore-certificate-errors-spki-list); any other key still fails.
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";

export function pinnedSpkiArgs(caPath: string | undefined): string[] {
  if (!caPath) return [];
  const spki = new X509Certificate(readFileSync(caPath)).publicKey.export({
    type: "spki",
    format: "der",
  });
  return [
    `--ignore-certificate-errors-spki-list=${createHash("sha256").update(spki).digest("base64")}`,
  ];
}
