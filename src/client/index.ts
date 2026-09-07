import {
  startAuthentication, startRegistration, browserSupportsWebAuthn, platformAuthenticatorIsAvailable,
} from "@simplewebauthn/browser";

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

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: "same-origin", ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error((body as { error?: string }).error || `Request failed (${response.status})`);
  return body as T;
}

const json = (data: unknown): RequestInit => ({
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data),
});

/** Whether this browser can do passkeys at all. */
export const passkeysSupported = () => browserSupportsWebAuthn();

/** Whether this device has its own (Face ID, Touch ID, Windows Hello). */
export const deviceHasPasskeys = () => platformAuthenticatorIsAvailable();

/** The person closed the prompt or the device refused — not an error to shout about. */
export const wasCancelled = (error: unknown) =>
  error instanceof Error && (error.name === "NotAllowedError" || error.name === "AbortError");

export function createPasskeyClient(base = "/api/auth/passkeys") {
  return {
    /**
     * Sign in with a passkey. `extra` is passed to the server's onSignIn
     * with the verified passkey — a workspace slug, a "which door" flag.
     * Resolves to whatever the server answers, typically `{ redirect }`.
     */
    async signIn<T = { ok: boolean; redirect?: string }>(extra: Record<string, unknown> = {}): Promise<T> {
      const optionsJSON = await request<Parameters<typeof startAuthentication>[0]["optionsJSON"]>(`${base}/login/options`, json({}));
      const response = await startAuthentication({ optionsJSON });
      return request<T>(`${base}/login/verify`, json({ response, ...extra }));
    },

    /** Register a passkey on this device for the signed-in person. */
    async register(name?: string): Promise<PasskeyView> {
      const optionsJSON = await request<Parameters<typeof startRegistration>[0]["optionsJSON"]>(`${base}/register/options`, json({}));
      const response = await startRegistration({ optionsJSON });
      const r = await request<{ passkey: PasskeyView }>(`${base}/register/verify`, json({ response, name }));
      return r.passkey;
    },

    async list(): Promise<PasskeyView[]> {
      return (await request<{ passkeys: PasskeyView[] }>(base)).passkeys;
    },

    async remove(id: string): Promise<void> {
      await request(`${base}/${encodeURIComponent(id)}`, { method: "DELETE" });
    },
  };
}

/** The authenticator-app half, pointed at `totpRouter`. */
export function createTotpClient(base = "/api/auth/totp") {
  return {
    async status(): Promise<{ enrolled: boolean }> { return request(base); },
    /** A fresh secret and the otpauth:// URI to show as a QR code. */
    async enrol(): Promise<{ secret: string; uri: string }> { return request(`${base}/enrol`, json({})); },
    /** The first code from the app proves it holds the secret. */
    async confirm(code: string): Promise<void> { await request(`${base}/confirm`, json({ code })); },
    async remove(): Promise<void> { await request(base, { method: "DELETE" }); },
    /** The second step after a password that answered needsSecondFactor. */
    async verify<T = { ok: boolean; redirect?: string }>(code: string, extra: Record<string, unknown> = {}): Promise<T> {
      return request<T>(`${base}/verify`, json({ code, ...extra }));
    },
  };
}
