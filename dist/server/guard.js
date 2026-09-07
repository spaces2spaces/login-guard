import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse, } from "@simplewebauthn/server";
import { decide, LOGIN_POLICY, waitMessage } from "./throttle.js";
import { assertSecret, issueToken, readToken } from "./tokens.js";
// ── Cookies that carry one round trip ───────────────────────────────────────
const CHALLENGE_COOKIE = "lg_challenge";
const PENDING_COOKIE = "lg_pending";
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const PENDING_TTL_MS = 5 * 60 * 1000;
export class LoginGuard {
    options;
    policy;
    constructor(options) {
        this.options = options;
        assertSecret(options.secret);
        if (!options.rp.id || !options.rp.name || options.rp.origins.length === 0) {
            throw new Error("login-guard: rp.id, rp.name and at least one origin are required");
        }
        this.policy = options.policy ?? LOGIN_POLICY;
    }
    // ── Throttle ──────────────────────────────────────────────────────────────
    /** Whether an attempt for this address from this IP may go ahead. */
    async check(email, ip) {
        const since = new Date(Date.now() - this.policy.windowMs);
        const seen = await this.options.attempts.recentFailures(email, ip, since);
        return decide(seen.account, seen.ip, this.policy);
    }
    record(attempt) {
        return this.options.attempts.record(attempt);
    }
    /** Answer a refused attempt: 429, Retry-After, and a sentence. */
    refuse(res, decision) {
        res.set("Retry-After", String(decision.retryAfterSec));
        res.status(429).json({ error: waitMessage(decision.retryAfterSec) });
    }
    // ── Passkeys ──────────────────────────────────────────────────────────────
    /** Options for the browser to create a passkey for this person. */
    async registrationOptions(res, user) {
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
    async verifyRegistration(req, res, input) {
        const claim = this.readChallenge(req, "reg");
        this.clearChallenge(res);
        if (!claim || claim.uid !== input.userId)
            throw new GuardError("The passkey request expired. Try again.");
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
    async authenticationOptions(res, user) {
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
    async verifyAuthentication(req, res, response) {
        const claim = this.readChallenge(req, "auth");
        this.clearChallenge(res);
        if (!claim)
            throw new GuardError("The sign-in request expired. Try again.");
        const passkey = await this.options.passkeys.findByCredentialId(response.id);
        if (!passkey)
            throw new GuardError("That passkey is not registered here.");
        // A challenge issued for one person must not be answered by another's key.
        if (claim.uid && claim.uid !== passkey.userId)
            throw new GuardError("That passkey belongs to a different account.");
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
                transports: (passkey.transports ?? undefined),
            },
        });
        if (!verification.verified)
            throw new GuardError("The passkey could not be verified.");
        await this.options.passkeys.touch(passkey.id, verification.authenticationInfo.newCounter);
        return passkey;
    }
    // ── A sign-in waiting for its second step ─────────────────────────────────
    /** After a right password for a person who has a passkey: remember who,
     *  for five minutes, until the passkey confirms it. */
    issuePending(res, pending) {
        res.cookie(PENDING_COOKIE, issueToken(this.options.secret, pending, PENDING_TTL_MS), this.cookieOptions(PENDING_TTL_MS));
    }
    readPending(req) {
        return readToken(this.options.secret, req.cookies?.[PENDING_COOKIE]);
    }
    clearPending(res) {
        res.clearCookie(PENDING_COOKIE, { path: "/" });
    }
    // ── Internals ─────────────────────────────────────────────────────────────
    setChallenge(res, claim) {
        res.cookie(CHALLENGE_COOKIE, issueToken(this.options.secret, claim, CHALLENGE_TTL_MS), this.cookieOptions(CHALLENGE_TTL_MS));
    }
    readChallenge(req, purpose) {
        const claim = readToken(this.options.secret, req.cookies?.[CHALLENGE_COOKIE]);
        return claim && claim.p === purpose && typeof claim.c === "string" ? claim : null;
    }
    clearChallenge(res) {
        res.clearCookie(CHALLENGE_COOKIE, { path: "/" });
    }
    cookieOptions(maxAge) {
        return {
            httpOnly: true,
            sameSite: this.options.cookie?.sameSite ?? "lax",
            secure: this.options.cookie?.secure ?? process.env.NODE_ENV === "production",
            maxAge,
            path: "/",
        };
    }
}
/** A refusal the person should read, as opposed to a bug. */
export class GuardError extends Error {
    status;
    constructor(message, status = 400) {
        super(message);
        this.status = status;
        this.name = "GuardError";
    }
}
export function createLoginGuard(options) {
    return new LoginGuard(options);
}
