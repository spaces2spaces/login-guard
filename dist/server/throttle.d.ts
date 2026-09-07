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
export declare const LOGIN_POLICY: ThrottlePolicy;
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
export declare function decide(accountFailures: readonly number[], ipFailures: readonly number[], policy?: ThrottlePolicy, now?: number): ThrottleDecision;
/** "Too many attempts. Try again in 12 minutes." */
export declare function waitMessage(retryAfterSec: number): string;
