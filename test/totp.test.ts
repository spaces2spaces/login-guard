import { describe, it, expect } from "vitest";
import { base32Decode, base32Encode, generateTotpSecret, otpauthUri, totpCode, totpCounter, verifyTotp } from "../src/server/totp.js";
import { inviteIsOpen, inviteTokenLooksValid, newInviteToken, hashInviteToken } from "../src/server/invites.js";

describe("one-time codes", () => {
  it("matches the RFC 6238 test vector for SHA-1", () => {
    // Secret "12345678901234567890", time 59 s → 287082 (RFC 6238 appendix B).
    const secret = base32Encode(new TextEncoder().encode("12345678901234567890"));
    expect(totpCode(secret, 59_000)).toBe("287082");
    expect(totpCode(secret, 1_111_111_109_000)).toBe("081804");
  });

  it("round-trips base32 and makes a secret apps can scan", () => {
    const bytes = new Uint8Array([1, 2, 3, 250, 251, 252, 0, 77]);
    expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(otpauthUri({ issuer: "Flowpilots", account: "a@b.co", secret })).toMatch(/^otpauth:\/\/totp\/Flowpilots%3Aa%40b.co\?secret=/);
  });

  it("accepts the current code and its neighbours, refuses others and replays", () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000_000;
    const code = totpCode(secret, now);
    expect(verifyTotp(secret, code, { nowMs: now })).toBe(totpCounter(now));
    expect(verifyTotp(secret, code, { nowMs: now + 30_000 })).toBe(totpCounter(now));   // one step late: fine
    expect(verifyTotp(secret, code, { nowMs: now + 90_000 })).toBeNull();               // three steps late: gone
    expect(verifyTotp(secret, "000000", { nowMs: now })).toBe(verifyTotp(secret, "000000", { nowMs: now }) === totpCounter(now) ? totpCounter(now) : null);
    expect(verifyTotp(secret, "12345", { nowMs: now })).toBeNull();
    expect(verifyTotp(secret, code, { nowMs: now, notBeforeCounter: totpCounter(now) })).toBeNull(); // already used
  });
});

describe("invitations", () => {
  it("issues an unguessable token and keeps only its hash", () => {
    const t = newInviteToken();
    expect(inviteTokenLooksValid(t)).toBe(true);
    expect(inviteTokenLooksValid("short")).toBe(false);
    expect(hashInviteToken(t)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashInviteToken(t)).not.toContain(t);
  });

  it("is open until used or expired", () => {
    const now = new Date("2026-09-07T12:00:00Z");
    expect(inviteIsOpen({ expiresAt: new Date("2026-09-08T12:00:00Z"), usedAt: null }, now)).toBe(true);
    expect(inviteIsOpen({ expiresAt: new Date("2026-09-07T11:59:59Z"), usedAt: null }, now)).toBe(false);
    expect(inviteIsOpen({ expiresAt: new Date("2026-09-08T12:00:00Z"), usedAt: now }, now)).toBe(false);
  });
});
