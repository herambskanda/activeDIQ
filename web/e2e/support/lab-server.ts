// Helpers for the suites that drive a REAL lab-built server (T-0855). Test code only: nothing in src/ imports it.
// They create local accounts and store passkey public keys through the server binary's own commands
// (`account init-local`, and `account add-passkey`, which exists only in a `-tags lab` build), so the
// suite needs no SQL and no fixtures: the console, the API and the database are the product's.
import { execFile, spawn } from "node:child_process";
import { createHmac, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { promisify } from "node:util";

const run = promisify(execFile);

/** The lab server binary, built by boot-lab-server.sh. */
export function serverBin(): string {
  const bin = process.env["ADIQ_E2E_SERVER_BIN"];
  if (!bin)
    throw new Error(
      "ADIQ_E2E_SERVER_BIN is not set (source the env file boot-lab-server.sh wrote)",
    );
  return bin;
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/=+$/, "").toUpperCase()) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error("bad base32 seed");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 (SHA-1, 6 digits, 30 s) for the time step `step`. */
export function totp(seed: Buffer, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", seed).update(counter).digest();
  const o = (h[h.length - 1] ?? 0) & 0x0f;
  const v = (h.readUInt32BE(o) & 0x7fffffff) % 1_000_000;
  return v.toString().padStart(6, "0");
}

export const STEP_SECONDS = 30;

/**
 * A code the server accepts for this seed right now and has never seen: the NEXT time step. The server
 * accepts one step either side of the present (clock drift) and refuses a step at or below the last one it
 * accepted (replay), and enrolment used the current step, so the next one is valid without waiting 30 s
 * and without a clock to fake.
 */
export function nextStepCode(seed: Buffer): string {
  return totp(seed, Math.floor(Date.now() / 1000 / STEP_SECONDS) + 1);
}

export interface LocalAccount {
  readonly id: string;
  readonly username: string;
  readonly password: string;
  readonly seed: Buffer;
}

/** `account init-local`: password on stdin, then the first TOTP code read back from the printed setup key. */
export async function createLocalAccount(username: string): Promise<LocalAccount> {
  const password = `pw-${randomBytes(12).toString("hex")}`;
  const child = spawn(serverBin(), ["account", "init-local", "--username", username], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let out = "";
  let err = "";
  child.stderr.on("data", (d: Buffer) => (err += d.toString()));
  const seedText = await new Promise<string>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) =>
      reject(new Error(`init-local exited ${code} before the setup key: ${err}${out}`)),
    );
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString();
      const m = /setup key: ([A-Z2-7]+)/.exec(out);
      if (m?.[1]) resolve(m[1]);
    });
    child.stdin.write(`${password}\n`);
  });
  const seed = base32Decode(seedText);
  const exit = new Promise<number | null>((resolve) => {
    child.removeAllListeners("close");
    child.on("close", resolve);
  });
  // Enrolment is confirmed with the current step's code; sign-in later uses a different (next) step.
  child.stdin.end(`${totp(seed, Math.floor(Date.now() / 1000 / STEP_SECONDS))}\n`);
  if ((await exit) !== 0) throw new Error(`init-local failed: ${err}${out}`);
  const id = /Account (\S+) created/.exec(out)?.[1];
  if (!id) throw new Error(`init-local printed no account id: ${out}`);
  return { id, username, password, seed };
}

/** A WebAuthn credential the suite made itself: an ES256 key pair, its ID and the account's user handle. */
export interface Passkey {
  readonly credentialId: Buffer;
  readonly userHandle: Buffer;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

export function newPasskey(): Passkey {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { credentialId: randomBytes(32), userHandle: randomBytes(64), privateKey, publicKey };
}

/** The COSE_Key (RFC 9052) of an ES256 public key, {1:2, 3:-7, -1:1, -2:x, -3:y}, hand-encoded as the server's own tests do. */
export function coseES256(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x ?? "", "base64url");
  const y = Buffer.from(jwk.y ?? "", "base64url");
  if (x.length !== 32 || y.length !== 32) throw new Error("not a P-256 public key");
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y,
  ]);
}

/** `account add-passkey` (lab builds only): registers the credential's PUBLIC half for the account. */
export async function addPasskey(
  accountId: string,
  key: Passkey,
  label = "virtual authenticator",
): Promise<void> {
  await run(serverBin(), [
    "account",
    "add-passkey",
    "--account",
    accountId,
    "--credential-id",
    key.credentialId.toString("base64url"),
    "--public-key",
    coseES256(key.publicKey).toString("base64url"),
    "--user-handle",
    key.userHandle.toString("base64url"),
    "--label",
    label,
  ]);
}
