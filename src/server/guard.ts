import type { Request, Response } from "express";
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON, AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { decide, LOGIN_POLICY, waitMessage, type ThrottleDecision, type ThrottlePolicy } from "./throttle.js";
import { assertSecret, issueToken, readToken } from "./tokens.js";

/**
 * The guard: one object an app creates at boot and uses from its sign-in
 * routes. It knows nothing about the app's users, sessions or database — the
 * app hands it two stores and gets back the arithmetic, the WebAuthn
 * ceremony and the cookies that carry a challenge across a round trip.
 */

// ── What the app provides ───────────────────────────────────────────────────

export interface StoredPasskey {
  id: string;
  userId: string;
  /** base64url, as the browser reports it. */
  credentialId: string;
  /** COSE public key, base64url. */
  publicKey: string;
  counter: number;
  transports?: string[] | null;
  name?: string | null;
  createdAt?: Date;
  lastUsedAt?: Date | null;
}

export interface PasskeyStore {
  listForUser(userId: string): Promise<StoredPasskey[]>;
  findByCredentialId(credentialId: string): Promise<StoredPasskey | null | undefined>;
  create(passkey: {
    userId: string; credentialId: string; publicKey: string; counter: number;
    transports: string[] | undefined; deviceType: string; backedUp: boolean; name: string | null;
  }): Promise<StoredPasskey>;
  touch(id: string, counter: number): Promise<void>;
  /** Only the owner's own key. Returns whether anything was removed. */
  remove(id: string, userId: string): Promise<boolean>;
}

export interface LoginAttempt {
  email: string | null;
  ip: string | null;
  /** The app's own word for the door: "customer", "admin", "passkey"… */
  kind: string;
  ok: boolean;
  reason?: string | null;
}

export interface AttemptStore {
  record(attempt: LoginAttempt): Promise<void>;
  /** Failed attempts since `since`, as timestamps, for the address and the IP. */
  recentFailures(email: string | null, ip: string | null, since: Date): Promise<{ account: number[]; ip: number[] }>;
}

export interface GuardOptions {
  /** Signs challenges and pending sign-ins. At least 32 characters. */
  secret: string;
  rp: {
    /** The site's domain, e.g. "flowpilots.ai". A passkey made for it only
     *  ever signs for it. "localhost" in development. */
    id: string;
    /** Shown by the browser when a passkey is made. */
    name: string;
    /** Every origin the sign-in page is served from. */
    origins: string[];
  };
  attempts: AttemptStore;
  passkeys: PasskeyStore;
  policy?: ThrottlePolicy;
  cookie?: { secure?: boolean; sameSite?: "lax" | "strict" };
}

// ── Cookies that carry one round trip ───────────────────────────────────────

const CHALLENGE_COOKIE = "lg_challenge";
const PENDING_COOKIE = "lg_pending";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const PENDING_TTL_MS = 5 * 60 * 1000;

interface ChallengeClaim extends Record<string, unknown> {
  c: string;
  /** "reg" or "auth". */
  p: string;
  /** The user the registration is for; absent on a sign-in challenge. */
  uid?: string;
}

export interface PendingSignIn extends Record<string, unknown> {
  uid: string;
}

export class LoginGuard {
  private readonly policy: ThrottlePolicy;
  /** For the sibling routers that sign their own short-lived cookies. */
  readonly secret: string;

  constructor(private readonly options: GuardOptions) {
    assertSecret(options.secret);
    if (!options.rp.id || !options.rp.name || options.rp.origins.length === 0) {
      throw new Error("login-guard: rp.id, rp.name and at least one origin are required");
    }
    this.policy = options.policy ?? LOGIN_POLICY;
    this.secret = options.secret;
  }

  /** The app's passkey store, for routers that list on its behalf. */
  get passkeyStore(): PasskeyStore { return this.options.passkeys; }

  /** Whether this person has any second factor at all. `totp` is asked so
   *  the guard need not know how the app stores app secrets. */
  async hasSecondFactor(userId: string, totp?: { get(userId: string): Promise<unknown | null> }): Promise<boolean> {
    if ((await this.options.passkeys.listForUser(userId)).length > 0) return true;
    return Boolean(totp && await totp.get(userId));
  }

  // ── Throttle ──────────────────────────────────────────────────────────────

  /** Whether an attempt for this address from this IP may go ahead. */
  async check(email: string | null, ip: string | null): Promise<ThrottleDecision> {
    const since = new Date(Date.now() - this.policy.windowMs);
    const seen = await this.options.attempts.recentFailures(email, ip, since);
    return decide(seen.account, seen.ip, this.policy);
  }

  record(attempt: LoginAttempt): Promise<void> {
    return this.options.attempts.record(attempt);
  }

  /** Answer a refused attempt: 429, Retry-After, and a sentence. */
  refuse(res: Response, decision: ThrottleDecision): void {
    res.set("Retry-After", String(decision.retryAfterSec));
    res.status(429).json({ error: waitMessage(decision.retryAfterSec) });
  }

  // ── Passkeys ──────────────────────────────────────────────────────────────

  /** Options for the browser to create a passkey for this person. */
  async registrationOptions(
    res: Response, user: { id: string; email: string; name?: string | null },
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const existing = await this.options.passkeys.listForUser(user.id);
    const options = await generateRegistrationOptions({
      rpName: this.options.rp.name,
      rpID: this.options.rp.id,
      userName: user.email,
      userDisplayName: user.name || user.email,
      userID: new TextEncoder().encode(user.id),
      attestationType: "none",
      excludeCredentials: existing.map(p => ({ id: p.credentialId, transports: p.transports ?? undefined })),
      // A resident key with user verification: the passkey can sign in on
      // its own (the browser finds it by site), and the device asks for the
      // person (Face ID, fingerprint, PIN) every time.
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    });
    this.setChallenge(res, { c: options.challenge, p: "reg", uid: user.id });
    return options;
  }

  /** The browser's answer, checked and stored. */
  async verifyRegistration(
    req: Request, res: Response,
    input: { userId: string; response: RegistrationResponseJSON; name?: string | null },
  ): Promise<StoredPasskey> {
    const claim = this.readChallenge(req, "reg");
    this.clearChallenge(res);
    if (!claim || claim.uid !== input.userId) throw new GuardError("The passkey request expired. Try again.");

    const verification = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: claim.c,
      expectedOrigin: this.options.rp.origins,
      expectedRPID: this.options.rp.id,
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo) {
      throw new GuardError("The passkey could not be verified.");
    }
    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    return this.options.passkeys.create({
      userId: input.userId,
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      transports: credential.transports,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      name: input.name?.trim().slice(0, 80) || null,
    });
  }

  /**
   * Options for the browser to sign in with a passkey. Without a user the
   * browser offers whichever passkeys it holds for this site; with one, only
   * that person's — the second step after a password.
   */
  async authenticationOptions(
    res: Response, user?: { id: string } | null,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const allow = user ? await this.options.passkeys.listForUser(user.id) : [];
    const options = await generateAuthenticationOptions({
      rpID: this.options.rp.id,
      userVerification: "required",
      allowCredentials: user ? allow.map(p => ({ id: p.credentialId, transports: p.transports ?? undefined })) : undefined,
    });
    this.setChallenge(res, { c: options.challenge, p: "auth", ...(user ? { uid: user.id } : {}) });
    return options;
  }

  /** The browser's signature, checked against the stored key. Returns the
   *  passkey — and with it the user it belongs to. */
  async verifyAuthentication(
    req: Request, res: Response, response: AuthenticationResponseJSON,
  ): Promise<StoredPasskey> {
    const claim = this.readChallenge(req, "auth");
    this.clearChallenge(res);
    if (!claim) throw new GuardError("The sign-in request expired. Try again.");

    const passkey = await this.options.passkeys.findByCredentialId(response.id);
    if (!passkey) throw new GuardError("That passkey is not registered here.");
    // A challenge issued for one person must not be answered by another's key.
    if (claim.uid && claim.uid !== passkey.userId) throw new GuardError("That passkey belongs to a different account.");

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: claim.c,
      expectedOrigin: this.options.rp.origins,
      expectedRPID: this.options.rp.id,
      requireUserVerification: true,
      credential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(Buffer.from(passkey.publicKey, "base64url")),
        counter: passkey.counter,
        transports: (passkey.transports ?? undefined) as any,
      },
    });
    if (!verification.verified) throw new GuardError("The passkey could not be verified.");
    await this.options.passkeys.touch(passkey.id, verification.authenticationInfo.newCounter);
    return passkey;
  }

  // ── A sign-in waiting for its second step ─────────────────────────────────

  /** After a right password for a person who has a passkey: remember who,
   *  for five minutes, until the passkey confirms it. */
  issuePending(res: Response, pending: PendingSignIn): void {
    res.cookie(PENDING_COOKIE, issueToken(this.options.secret, pending, PENDING_TTL_MS), this.cookieOptions(PENDING_TTL_MS));
  }

  readPending<T extends PendingSignIn>(req: Request): T | null {
    return readToken<T>(this.options.secret, req.cookies?.[PENDING_COOKIE]);
  }

  clearPending(res: Response): void {
    res.clearCookie(PENDING_COOKIE, { path: "/" });
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  private setChallenge(res: Response, claim: ChallengeClaim): void {
    res.cookie(CHALLENGE_COOKIE, issueToken(this.options.secret, claim, CHALLENGE_TTL_MS), this.cookieOptions(CHALLENGE_TTL_MS));
  }

  private readChallenge(req: Request, purpose: "reg" | "auth"): ChallengeClaim | null {
    const claim = readToken<ChallengeClaim>(this.options.secret, req.cookies?.[CHALLENGE_COOKIE]);
    return claim && claim.p === purpose && typeof claim.c === "string" ? claim : null;
  }

  private clearChallenge(res: Response): void {
    res.clearCookie(CHALLENGE_COOKIE, { path: "/" });
  }

  cookieOptions(maxAge: number) {
    return {
      httpOnly: true,
      sameSite: this.options.cookie?.sameSite ?? "lax" as const,
      secure: this.options.cookie?.secure ?? process.env.NODE_ENV === "production",
      maxAge,
      path: "/",
    };
  }
}

/** A refusal the person should read, as opposed to a bug. */
export class GuardError extends Error {
  constructor(message: string, public readonly status = 400) {
    super(message);
    this.name = "GuardError";
  }
}

export function createLoginGuard(options: GuardOptions): LoginGuard {
  return new LoginGuard(options);
}
