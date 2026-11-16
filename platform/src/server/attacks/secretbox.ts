import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

/**
 * AES-256-GCM for third-party tokens stored in the database (Cloudflare API tokens).
 * Key: RUYA_SECRETS_KEY (at least 32 characters; hashed to 32 bytes). Fails closed: with no key, nothing can be
 * stored or read, so a missing key shows as a source error, never as "no attacks".
 * Format: v1.<iv b64url>.<tag b64url>.<ciphertext b64url>. The org and source id are bound as associated data so a
 * ciphertext copied to another row does not decrypt.
 */
export class SecretKeyMissing extends Error { constructor() { super("secrets_key_not_configured"); } }

function key(raw = process.env.RUYA_SECRETS_KEY): Buffer {
  const k = raw?.trim();
  if (!k || k.length < 32) throw new SecretKeyMissing();
  return createHash("sha256").update(k).digest();
}

export const secretsConfigured = () => { try { key(); return true; } catch { return false; } };

export function seal(plain: string, aad: string, rawKey?: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key(rawKey), iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return ["v1", iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

export function open(sealed: string, aad: string, rawKey?: string): string {
  const [v, iv, tag, ct] = sealed.split(".");
  if (v !== "v1" || !iv || !tag || !ct) throw new Error("secret_malformed");
  const d = createDecipheriv("aes-256-gcm", key(rawKey), Buffer.from(iv, "base64url"));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(Buffer.from(tag, "base64url"));
  try { return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8"); }
  catch { throw new Error("secret_undecryptable"); }
}
