/** RFC 4648 base32, no padding — the form authenticator apps take. */
export declare function base32Encode(bytes: Uint8Array): string;
export declare function base32Decode(text: string): Uint8Array;
/** Twenty random bytes, as authenticator apps expect. */
export declare const generateTotpSecret: () => string;
export declare const TOTP_STEP_SECONDS = 30;
/** The counter a moment falls in. Stored after a successful check so the
 *  same code cannot be replayed inside its thirty seconds. */
export declare const totpCounter: (nowMs?: number) => number;
/** The code an app shows right now. For tests and for the enrolment check. */
export declare const totpCode: (secret: string, nowMs?: number) => string;
/**
 * Check a typed code against the secret, allowing one step either side for
 * a phone whose clock is slightly off. Returns the counter that matched, or
 * null — the caller refuses a counter at or below the last one used.
 */
export declare function verifyTotp(secret: string, code: unknown, opts?: {
    window?: number;
    nowMs?: number;
    notBeforeCounter?: number;
}): number | null;
/** What the app scans: otpauth://totp/Issuer:account?secret=…&issuer=Issuer */
export declare function otpauthUri(input: {
    issuer: string;
    account: string;
    secret: string;
}): string;
