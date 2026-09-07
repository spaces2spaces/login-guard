import crypto from "node:crypto";
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
export const newInviteToken = () => crypto.randomBytes(32).toString("base64url");
export const INVITE_TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;
export const hashInviteToken = (token) => crypto.createHash("sha256").update(token, "utf8").digest("hex");
export const inviteTokenLooksValid = (token) => typeof token === "string" && INVITE_TOKEN_SHAPE.test(token);
/** Expired, or already used: two ways a link stops working. */
export function inviteIsOpen(invite, now = new Date()) {
    return invite.usedAt === null && invite.expiresAt.getTime() > now.getTime();
}
