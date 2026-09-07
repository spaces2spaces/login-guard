import crypto from "node:crypto";
/**
 * Time-based one-time codes (RFC 6238), the six digits an authenticator app
 * shows. The alternative to a passkey as a second step for anyone whose
 * device cannot make one.
 *
 * SHA-1, six digits, thirty-second steps: what every authenticator app
 * expects. Implemented here rather than pulled in, because it is forty lines
 * and the dependency would be a hundred times that.
 */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/** RFC 4648 base32, no padding — the form authenticator apps take. */
export function base32Encode(bytes) {
    let bits = 0, value = 0, out = "";
    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0)
        out += ALPHABET[(value << (5 - bits)) & 31];
    return out;
}
export function base32Decode(text) {
    const clean = text.toUpperCase().replace(/[^A-Z2-7]/g, "");
    let bits = 0, value = 0;
    const out = [];
    for (const ch of clean) {
        value = (value << 5) | ALPHABET.indexOf(ch);
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return new Uint8Array(out);
}
/** Twenty random bytes, as authenticator apps expect. */
export const generateTotpSecret = () => base32Encode(crypto.randomBytes(20));
function hotp(secret, counter, digits = 6) {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    buf.writeUInt32BE(counter >>> 0, 4);
    const mac = crypto.createHmac("sha1", Buffer.from(secret)).update(buf).digest();
    const offset = mac[mac.length - 1] & 0x0f;
    const code = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return String(code % 10 ** digits).padStart(digits, "0");
}
export const TOTP_STEP_SECONDS = 30;
/** The counter a moment falls in. Stored after a successful check so the
 *  same code cannot be replayed inside its thirty seconds. */
export const totpCounter = (nowMs = Date.now()) => Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);
/** The code an app shows right now. For tests and for the enrolment check. */
export const totpCode = (secret, nowMs = Date.now()) => hotp(base32Decode(secret), totpCounter(nowMs));
/**
 * Check a typed code against the secret, allowing one step either side for
 * a phone whose clock is slightly off. Returns the counter that matched, or
 * null — the caller refuses a counter at or below the last one used.
 */
export function verifyTotp(secret, code, opts = {}) {
    const typed = String(code ?? "").replace(/\s+/g, "");
    if (!/^\d{6}$/.test(typed))
        return null;
    const window = opts.window ?? 1;
    const base = totpCounter(opts.nowMs ?? Date.now());
    const key = base32Decode(secret);
    for (let delta = -window; delta <= window; delta++) {
        const counter = base + delta;
        if (opts.notBeforeCounter !== undefined && counter <= opts.notBeforeCounter)
            continue;
        const expected = hotp(key, counter);
        if (expected.length === typed.length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(typed))) {
            return counter;
        }
    }
    return null;
}
/** What the app scans: otpauth://totp/Issuer:account?secret=…&issuer=Issuer */
export function otpauthUri(input) {
    const label = encodeURIComponent(`${input.issuer}:${input.account}`);
    const q = new URLSearchParams({
        secret: input.secret, issuer: input.issuer, algorithm: "SHA1", digits: "6", period: String(TOTP_STEP_SECONDS),
    });
    return `otpauth://totp/${label}?${q}`;
}
