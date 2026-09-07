/**
 * Invitation links: a person is told "make your passkey here" rather than
 * given a password. The link carries a random token; only its hash is
 * stored, with an expiry and a used-at, so a database dump is not a list of
 * open doors and a link works exactly once.
 *
 * The storage is the app's. These are the two functions every app would
 * otherwise write slightly differently.
 */
/** 32 random bytes, base64url: 43 characters, no ambiguity. */
export declare const newInviteToken: () => string;
export declare const INVITE_TOKEN_SHAPE: RegExp;
export declare const hashInviteToken: (token: string) => string;
export declare const inviteTokenLooksValid: (token: unknown) => token is string;
/** Expired, or already used: two ways a link stops working. */
export declare function inviteIsOpen(invite: {
    expiresAt: Date;
    usedAt: Date | null;
}, now?: Date): boolean;
