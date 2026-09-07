import { startAuthentication, startRegistration, browserSupportsWebAuthn, platformAuthenticatorIsAvailable, } from "@simplewebauthn/browser";
async function request(url, init) {
    const response = await fetch(url, { credentials: "same-origin", ...init });
    const body = await response.json().catch(() => ({}));
    if (!response.ok)
        throw new Error(body.error || `Request failed (${response.status})`);
    return body;
}
const json = (data) => ({
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data),
});
/** Whether this browser can do passkeys at all. */
export const passkeysSupported = () => browserSupportsWebAuthn();
/** Whether this device has its own (Face ID, Touch ID, Windows Hello). */
export const deviceHasPasskeys = () => platformAuthenticatorIsAvailable();
/** The person closed the prompt or the device refused — not an error to shout about. */
export const wasCancelled = (error) => error instanceof Error && (error.name === "NotAllowedError" || error.name === "AbortError");
export function createPasskeyClient(base = "/api/auth/passkeys") {
    return {
        /**
         * Sign in with a passkey. `extra` is passed to the server's onSignIn
         * with the verified passkey — a workspace slug, a "which door" flag.
         * Resolves to whatever the server answers, typically `{ redirect }`.
         */
        async signIn(extra = {}) {
            const optionsJSON = await request(`${base}/login/options`, json({}));
            const response = await startAuthentication({ optionsJSON });
            return request(`${base}/login/verify`, json({ response, ...extra }));
        },
        /** Register a passkey on this device for the signed-in person. */
        async register(name) {
            const optionsJSON = await request(`${base}/register/options`, json({}));
            const response = await startRegistration({ optionsJSON });
            const r = await request(`${base}/register/verify`, json({ response, name }));
            return r.passkey;
        },
        async list() {
            return (await request(base)).passkeys;
        },
        async remove(id) {
            await request(`${base}/${encodeURIComponent(id)}`, { method: "DELETE" });
        },
    };
}
