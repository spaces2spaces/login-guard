/**
 * How many times somebody may fail to sign in before being told to wait.
 *
 * Two counts over the same window. Per address, so one account cannot be
 * hammered from many machines. Per IP, so one machine cannot walk through
 * every address. Both are counts of FAILURES; a person who types their
 * password right is never counted, and a person who mistypes it a few times
 * is never noticed.
 *
 * Arithmetic over those two counts, nothing more, so it can be tested without
 * a database and used by any app that can count.
 */

export interface ThrottlePolicy {
  /** How far back failures count, in milliseconds. */
  windowMs: number;
  /** Failures per address before a wait. */
  perAccount: number;
  /** Failures per IP before a wait. */
  perIp: number;
}

/** Ten wrong passwords in a quarter of an hour is not a person. Thirty from
 *  one address across any accounts is a script. */
export const LOGIN_POLICY: ThrottlePolicy = {
  windowMs: 15 * 60 * 1000,
  perAccount: 10,
  perIp: 30,
};

export interface ThrottleDecision {
  allowed: boolean;
  /** Seconds until the oldest counted failure leaves the window. */
  retryAfterSec: number;
  /** Which count refused, for the log. */
  by: "account" | "ip" | null;
}

/**
 * Decide from the failures seen in the window.
 *
 * `accountFailures` and `ipFailures` are timestamps (ms) of failed attempts.
 * The wait is until the OLDEST counted one drops out, which is what a sliding
 * window means and what stops "wait a minute, try ten more".
 */
export function decide(
  accountFailures: readonly number[], ipFailures: readonly number[],
  policy: ThrottlePolicy = LOGIN_POLICY, now = Date.now(),
): ThrottleDecision {
  const inWindow = (times: readonly number[]) =>
    times.filter(t => t > now - policy.windowMs).sort((a, b) => a - b);
  const account = inWindow(accountFailures);
  const ip = inWindow(ipFailures);
  const wait = (times: number[]) => Math.max(1, Math.ceil((times[0] + policy.windowMs - now) / 1000));

  if (account.length >= policy.perAccount) return { allowed: false, retryAfterSec: wait(account), by: "account" };
  if (ip.length >= policy.perIp) return { allowed: false, retryAfterSec: wait(ip), by: "ip" };
  return { allowed: true, retryAfterSec: 0, by: null };
}

/** "Too many attempts. Try again in 12 minutes." */
export function waitMessage(retryAfterSec: number): string {
  const minutes = Math.ceil(retryAfterSec / 60);
  return `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
}
