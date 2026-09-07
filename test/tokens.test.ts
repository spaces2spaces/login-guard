import { describe, it, expect } from "vitest";
import { issueToken, readToken, assertSecret } from "../src/server/tokens.js";

const secret = "a-secret-that-is-long-enough-to-sign-things-with";

describe("signed tokens", () => {
  it("round-trips a payload and keeps the expiry inside the signature", () => {
    const token = issueToken(secret, { uid: "u1", p: "reg" }, 60_000);
    const back = readToken<{ uid: string; p: string; exp: number }>(secret, token);
    expect(back?.uid).toBe("u1");
    expect(back?.p).toBe("reg");
    expect(back!.exp).toBeGreaterThan(Date.now());
  });

  it("refuses a token signed with another secret, a tampered one and a stale one", () => {
    const token = issueToken(secret, { uid: "u1" }, 60_000);
    expect(readToken("another-secret-that-is-also-long-enough-xx", token)).toBeNull();
    const [body, sig] = token.split(".");
    const tampered = Buffer.from(JSON.stringify({ uid: "u2", exp: Date.now() + 60_000 })).toString("base64url");
    expect(readToken(secret, `${tampered}.${sig}`)).toBeNull();
    expect(readToken(secret, `${body}.${sig}x`)).toBeNull();
    expect(readToken(secret, issueToken(secret, { uid: "u1" }, -1))).toBeNull();
    expect(readToken(secret, undefined)).toBeNull();
    expect(readToken(secret, "not.a.token")).toBeNull();
  });

  it("refuses a short secret rather than signing with it", () => {
    expect(() => assertSecret("short")).toThrow(/32/);
    expect(() => assertSecret(secret)).not.toThrow();
  });
});
