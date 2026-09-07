/**
 * The browser half: talks to the routes `passkeyRouter` mounts. Framework-
 * free — a React page, a plain form or a Svelte component call the same
 * four functions.
 *
 *   const passkeys = createPasskeyClient("/api/auth/passkeys");
 *   await passkeys.signIn({ slug: "dwt" });          // discoverable, or the second step
 *   await passkeys.register("Jesper's MacBook");     // while signed in
 */
export interface PasskeyView {
    id: string;
    name: string | null;
    createdAt: string | null;
    lastUsedAt: string | null;
}
/** Whether this browser can do passkeys at all. */
export declare const passkeysSupported: () => boolean;
/** Whether this device has its own (Face ID, Touch ID, Windows Hello). */
export declare const deviceHasPasskeys: () => Promise<boolean>;
/** The person closed the prompt or the device refused — not an error to shout about. */
export declare const wasCancelled: (error: unknown) => boolean;
export declare function createPasskeyClient(base?: string): {
    /**
     * Sign in with a passkey. `extra` is passed to the server's onSignIn
     * with the verified passkey — a workspace slug, a "which door" flag.
     * Resolves to whatever the server answers, typically `{ redirect }`.
     */
    signIn<T = {
        ok: boolean;
        redirect?: string;
    }>(extra?: Record<string, unknown>): Promise<T>;
    /** Register a passkey on this device for the signed-in person. */
    register(name?: string): Promise<PasskeyView>;
    list(): Promise<PasskeyView[]>;
    remove(id: string): Promise<void>;
};
