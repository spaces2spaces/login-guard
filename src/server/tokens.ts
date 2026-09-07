import crypto from "node:crypto";

/**
 * Signed, short-lived tokens for anything that must survive one round trip
 * and nothing more: a passkey challenge, a half-finished sign-in waiting for
 * its second step. HMAC-SHA256 over a base64url JSON body; the body is
 * readable, the signature is what makes it unforgeable, and the expiry is
 * inside the signed part.
 */

function sign(secret: string, body: string): string {
  return crypto.createHmac("sha256", secret).update(body).digest("base64url");
}

export function issueToken(secret: string, payload: Record<string, unknown>, ttlMs: number): string {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlMs })).toString("base64url");
  return `${body}.${sign(secret, body)}`;
}

export function readToken<T extends Record<string, unknown>>(secret: string, token: unknown): T | null {
  if (typeof token !== "string") return null;
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;
  const a = Buffer.from(signature), b = Buffer.from(sign(secret, body));
  // Constant-time compare: a byte-by-byte early exit leaks how much of a
  // forged signature was correct, which is enough to construct a valid one.
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, "base64url").toString());
    if (typeof data.exp !== "number" || data.exp < Date.now()) return null;
    return data as T;
  } catch {
    return null;
  }
}

/** A secret that is missing or short is the same as no signature. */
export function assertSecret(secret: unknown): asserts secret is string {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("login-guard: secret must be a string of at least 32 characters");
  }
}
