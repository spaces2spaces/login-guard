import { describe, it, expect } from "vitest";
import { createLoginGuard, GuardError, type AttemptStore, type PasskeyStore } from "../src/server/index.js";

const secret = "a-secret-that-is-long-enough-to-sign-things-with";

function stores() {
  const attempts: Array<{ email: string | null; ip: string | null; ok: boolean; at: number }> = [];
  const attemptStore: AttemptStore = {
    async record(a) { attempts.push({ email: a.email, ip: a.ip, ok: a.ok, at: Date.now() }); },
    async recentFailures(email, ip, since) {
      const fails = attempts.filter(a => !a.ok && a.at >= since.getTime());
      return {
        account: email ? fails.filter(a => a.email === email).map(a => a.at) : [],
        ip: ip ? fails.filter(a => a.ip === ip).map(a => a.at) : [],
      };
    },
  };
  const passkeyStore: PasskeyStore = {
    async listForUser() { return []; },
    async findByCredentialId() { return null; },
    async create(p) { return { id: "pk1", ...p, transports: p.transports ?? null }; },
    async touch() {},
    async remove() { return true; },
  };
  return { attempts, attemptStore, passkeyStore };
}

describe("the guard", () => {
  it("refuses to start without a real secret or a relying party", () => {
    const { attemptStore, passkeyStore } = stores();
    expect(() => createLoginGuard({ secret: "short", rp: { id: "x", name: "X", origins: ["https://x"] }, attempts: attemptStore, passkeys: passkeyStore })).toThrow(/32/);
    expect(() => createLoginGuard({ secret, rp: { id: "", name: "X", origins: [] }, attempts: attemptStore, passkeys: passkeyStore })).toThrow(/origin/);
  });

  it("counts failures and refuses the eleventh try for an address", async () => {
    const { attemptStore, passkeyStore } = stores();
    const guard = createLoginGuard({ secret, rp: { id: "localhost", name: "Test", origins: ["http://localhost"] }, attempts: attemptStore, passkeys: passkeyStore });
    for (let i = 0; i < 10; i++) await guard.record({ email: "a@b.co", ip: "1.1.1.1", kind: "test", ok: false });
    const d = await guard.check("a@b.co", "1.1.1.1");
    expect(d.allowed).toBe(false);
    expect(d.by).toBe("account");
    expect((await guard.check("other@b.co", "2.2.2.2")).allowed).toBe(true);
  });

  it("issues registration options with a resident key and user verification", async () => {
    const { attemptStore, passkeyStore } = stores();
    const guard = createLoginGuard({ secret, rp: { id: "localhost", name: "Test", origins: ["http://localhost"] }, attempts: attemptStore, passkeys: passkeyStore });
    const cookies: Record<string, string> = {};
    const res = { cookie: (name: string, value: string) => { cookies[name] = value; } } as any;
    const options = await guard.registrationOptions(res, { id: "u1", email: "a@b.co", name: "A" });
    expect(options.rp.id).toBe("localhost");
    expect(options.authenticatorSelection?.residentKey).toBe("required");
    expect(options.authenticatorSelection?.userVerification).toBe("required");
    expect(options.challenge.length).toBeGreaterThan(20);
    expect(cookies.lg_challenge).toBeTruthy();
  });

  it("rejects a registration answer with no challenge behind it", async () => {
    const { attemptStore, passkeyStore } = stores();
    const guard = createLoginGuard({ secret, rp: { id: "localhost", name: "Test", origins: ["http://localhost"] }, attempts: attemptStore, passkeys: passkeyStore });
    const req = { cookies: {} } as any;
    const res = { clearCookie: () => {} } as any;
    await expect(guard.verifyRegistration(req, res, { userId: "u1", response: {} as any })).rejects.toBeInstanceOf(GuardError);
  });
});
