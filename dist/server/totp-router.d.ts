import { Router, type Request, type Response } from "express";
import { type LoginGuard } from "./guard.js";
/**
 * Authenticator-app codes, ready to mount:
 *
 *   app.use("/api/auth/totp", totpRouter(guard, { issuer, store, currentUser, onSignIn }))
 *
 * Enrolment is two calls — the secret is shown, the person proves the app
 * has it by typing one code — and the secret is stored only after that, so
 * a half-done enrolment leaves nothing behind. Signing in is one call, as
 * the second step after a password.
 */
export interface TotpStore {
    /** The secret and the last counter accepted, or null when not enrolled. */
    get(userId: string): Promise<{
        secret: string;
        lastCounter: number;
    } | null>;
    set(userId: string, secret: string): Promise<void>;
    setLastCounter(userId: string, counter: number): Promise<void>;
    remove(userId: string): Promise<boolean>;
}
export interface TotpRouterOptions {
    /** Shown in the authenticator app next to the account. */
    issuer: string;
    store: TotpStore;
    currentUser(req: Request): Promise<{
        id: string;
        email: string;
        name?: string | null;
    } | null>;
    /** A code has been verified as the second step. `pending` is what was
     *  stored after the password; sign in exactly that. */
    onSignIn(req: Request, res: Response, signIn: {
        userId: string;
        pending: Record<string, unknown>;
    }): Promise<void>;
    kind?: string;
}
export declare function totpRouter(guard: LoginGuard, options: TotpRouterOptions): Router;
