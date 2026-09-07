import { Router, type Request, type Response } from "express";
import { type LoginGuard, type StoredPasskey } from "./guard.js";
/**
 * The passkey routes, ready to mount: an app adds
 *
 *   app.use("/api/auth/passkeys", passkeyRouter(guard, { currentUser, onSignIn }))
 *
 * and gets registration, listing, removal and sign-in. The two callbacks are
 * the only places the app's own model appears: who is signed in now, and
 * what to do once a passkey has proved who somebody is.
 */
export interface PasskeyRouterOptions {
    /** The signed-in person, or null. Registration and listing need one. */
    currentUser(req: Request): Promise<{
        id: string;
        email: string;
        name?: string | null;
    } | null>;
    /**
     * A passkey has been verified. Decide whether this person may sign in for
     * what the body asks (a workspace, the admin) and set the session — or
     * answer with an error. `pending` is set when this is the second step
     * after a password; the app should sign in exactly what it stored then.
     */
    onSignIn(req: Request, res: Response, signIn: {
        userId: string;
        passkey: StoredPasskey;
        pending: Record<string, unknown> | null;
    }): Promise<void>;
    /** The word for the door in the attempt log. Defaults to "passkey". */
    kind?: string;
}
export declare function passkeyRouter(guard: LoginGuard, options: PasskeyRouterOptions): Router;
/** What the page may see of a passkey: never the public key or credential id. */
export declare function publicView(p: StoredPasskey): {
    id: string;
    name: string | null;
    createdAt: Date | null;
    lastUsedAt: Date | null;
};
