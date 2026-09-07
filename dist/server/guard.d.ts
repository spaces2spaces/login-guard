import type { Request, Response } from "express";
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON, AuthenticationResponseJSON } from "@simplewebauthn/server";
import { type ThrottleDecision, type ThrottlePolicy } from "./throttle.js";
/**
 * The guard: one object an app creates at boot and uses from its sign-in
 * routes. It knows nothing about the app's users, sessions or database — the
 * app hands it two stores and gets back the arithmetic, the WebAuthn
 * ceremony and the cookies that carry a challenge across a round trip.
 */
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
        userId: string;
        credentialId: string;
        publicKey: string;
        counter: number;
        transports: string[] | undefined;
        deviceType: string;
        backedUp: boolean;
        name: string | null;
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
    recentFailures(email: string | null, ip: string | null, since: Date): Promise<{
        account: number[];
        ip: number[];
    }>;
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
    cookie?: {
        secure?: boolean;
        sameSite?: "lax" | "strict";
    };
}
export interface PendingSignIn extends Record<string, unknown> {
    uid: string;
}
export declare class LoginGuard {
    private readonly options;
    private readonly policy;
    constructor(options: GuardOptions);
    /** Whether an attempt for this address from this IP may go ahead. */
    check(email: string | null, ip: string | null): Promise<ThrottleDecision>;
    record(attempt: LoginAttempt): Promise<void>;
    /** Answer a refused attempt: 429, Retry-After, and a sentence. */
    refuse(res: Response, decision: ThrottleDecision): void;
    /** Options for the browser to create a passkey for this person. */
    registrationOptions(res: Response, user: {
        id: string;
        email: string;
        name?: string | null;
    }): Promise<PublicKeyCredentialCreationOptionsJSON>;
    /** The browser's answer, checked and stored. */
    verifyRegistration(req: Request, res: Response, input: {
        userId: string;
        response: RegistrationResponseJSON;
        name?: string | null;
    }): Promise<StoredPasskey>;
    /**
     * Options for the browser to sign in with a passkey. Without a user the
     * browser offers whichever passkeys it holds for this site; with one, only
     * that person's — the second step after a password.
     */
    authenticationOptions(res: Response, user?: {
        id: string;
    } | null): Promise<PublicKeyCredentialRequestOptionsJSON>;
    /** The browser's signature, checked against the stored key. Returns the
     *  passkey — and with it the user it belongs to. */
    verifyAuthentication(req: Request, res: Response, response: AuthenticationResponseJSON): Promise<StoredPasskey>;
    /** After a right password for a person who has a passkey: remember who,
     *  for five minutes, until the passkey confirms it. */
    issuePending(res: Response, pending: PendingSignIn): void;
    readPending<T extends PendingSignIn>(req: Request): T | null;
    clearPending(res: Response): void;
    private setChallenge;
    private readChallenge;
    private clearChallenge;
    private cookieOptions;
}
/** A refusal the person should read, as opposed to a bug. */
export declare class GuardError extends Error {
    readonly status: number;
    constructor(message: string, status?: number);
}
export declare function createLoginGuard(options: GuardOptions): LoginGuard;
