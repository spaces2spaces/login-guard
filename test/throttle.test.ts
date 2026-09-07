import { describe, it, expect } from "vitest";
import { decide, waitMessage, LOGIN_POLICY } from "../src/server/throttle.js";

const now = 1_000_000_000_000;
const min = 60_000;

describe("sign-in throttle", () => {
  it("lets a person who mistypes a few times carry on", () => {
    const fails = [now - 3 * min, now - 2 * min, now - min];
    expect(decide(fails, fails, LOGIN_POLICY, now).allowed).toBe(true);
  });

  it("refuses the address after ten failures in the window, and says how long", () => {
    const fails = Array.from({ length: 10 }, (_, i) => now - (10 - i) * min);
    const d = decide(fails, [], LOGIN_POLICY, now);
    expect(d.allowed).toBe(false);
    expect(d.by).toBe("account");
    expect(d.retryAfterSec).toBe(5 * 60);
  });

  it("refuses the IP after thirty failures across any addresses", () => {
    const fails = Array.from({ length: 30 }, (_, i) => now - i * 1000);
    const d = decide([], fails, LOGIN_POLICY, now);
    expect(d.allowed).toBe(false);
    expect(d.by).toBe("ip");
  });

  it("forgets failures older than the window", () => {
    const old = Array.from({ length: 50 }, (_, i) => now - 16 * min - i * 1000);
    expect(decide(old, old, LOGIN_POLICY, now).allowed).toBe(true);
  });

  it("slides: waiting a minute does not buy ten more tries", () => {
    const fails = Array.from({ length: 10 }, (_, i) => now - (10 - i) * min);
    const later = decide(fails, [], LOGIN_POLICY, now + 60_000);
    expect(later.allowed).toBe(false);
    expect(later.retryAfterSec).toBe(4 * 60);
  });

  it("phrases the wait in minutes", () => {
    expect(waitMessage(1)).toMatch(/1 minute\./);
    expect(waitMessage(61)).toMatch(/2 minutes\./);
  });
});
