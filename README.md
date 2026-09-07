# @spaces2spaces/login-guard

Sign-in security for Express apps, in one small package:

- **A throttle on failed sign-ins** — per address (10 in 15 minutes) and per IP
  (30 in 15 minutes), sliding window, with a `Retry-After` and a sentence.
- **Passkeys** (WebAuthn: Face ID, Touch ID, Windows Hello, security keys) —
  as a sign-in on their own, and as the second step after a password once a
  person has one.
- **Authenticator-app codes** (TOTP, RFC 6238) as the alternative second step
  for a device that cannot make a passkey.
- **Invitation tokens** — a person is told "make your passkey here" instead
  of being given a password; the link works once and expires.
- **A browser client** for all of it, framework-free.

It knows nothing about your users, sessions or database. You hand it two
small stores and two callbacks; it does the arithmetic, the WebAuthn ceremony
and the cookies that carry a challenge across a round trip.

## Install

```bash
npm install github:spaces2spaces/login-guard#v0.2.0 @simplewebauthn/browser
```

`dist/` is committed, so nothing is built on install.

## Server

```ts
import { createLoginGuard, passkeyRouter } from "@spaces2spaces/login-guard";

const guard = createLoginGuard({
  secret: process.env.SESSION_SECRET!,           // ≥ 32 characters
  rp: { id: "example.com", name: "Example", origins: ["https://example.com"] },
  attempts: {                                     // your table of attempts
    record: a => db.insert(loginAttempts).values(a),
    recentFailures: (email, ip, since) => ...,    // { account: number[], ip: number[] }
  },
  passkeys: {                                     // your table of passkeys
    listForUser, findByCredentialId, create, touch, remove,
  },
});

// Before a password check:
const decision = await guard.check(email, req.ip);
if (!decision.allowed) return guard.refuse(res, decision);
// ...check the password...
await guard.record({ email, ip: req.ip, kind: "customer", ok });
// If the person has a passkey, do not sign them in yet:
if (ok && (await listForUser(user.id)).length > 0) {
  guard.issuePending(res, { uid: user.id, tid: tenant.id });
  return res.json({ ok: false, needsPasskey: true });
}

// The passkey routes, mounted once:
app.use("/api/auth/passkeys", passkeyRouter(guard, {
  currentUser: async req => (await currentSession(req)) ?? null,
  onSignIn: async (req, res, { userId, pending }) => {
    // `pending` is what you stored after the password; otherwise the
    // person signed in with the passkey alone. Decide, set the session, answer.
    setSessionCookie(res, userId, pending?.tid ?? null);
    res.json({ ok: true, redirect: "/" });
  },
}));
```

Cookie-parser must run before the router. Behind a proxy, set
`app.set("trust proxy", 1)` so `req.ip` is the visitor and not the proxy.

The two stores need two tables. Suggested shapes:

```sql
create table login_attempts (
  id text primary key, at timestamp not null default now(),
  email text, ip text, kind text not null, ok text not null, reason text);
create index on login_attempts (email, at);
create index on login_attempts (ip, at);

create table passkeys (
  id text primary key, user_id text not null references users(id) on delete cascade,
  credential_id text not null unique, public_key text not null,
  counter integer not null default 0, transports text, device_type text, backed_up text,
  name text, created_at timestamp not null default now(), last_used_at timestamp);
```

### Authenticator-app codes

```ts
import { totpRouter } from "@spaces2spaces/login-guard";

app.use("/api/auth/totp", totpRouter(guard, {
  issuer: "Example",
  store: { get, set, setLastCounter, remove },   // your table: user_id, secret, last_counter
  currentUser,
  onSignIn: async (req, res, { userId, pending }) => { /* as for passkeys */ },
}));
```

Enrolment is `POST /enrol` (a secret and an `otpauth://` URI to show as a QR
code) then `POST /confirm { code }` — the secret is stored only once a code
from the app has matched. Signing in is `POST /verify { code }` after a
password that answered with a pending second step. A code is accepted once:
the last counter used is stored and anything at or below it is refused.

Store the secret encrypted at rest; it is a shared secret, unlike a passkey.

### Invitations

```ts
import { newInviteToken, hashInviteToken, inviteTokenLooksValid, inviteIsOpen } from "@spaces2spaces/login-guard";

const token = newInviteToken();                       // goes in the link, shown once
await db.insert(invites).values({ userId, tokenHash: hashInviteToken(token), expiresAt });
// On the invite page: look the hash up, check inviteIsOpen(row), let the
// person register a passkey, mark usedAt, sign them in.
```

```sql
create table invites (
  id text primary key, user_id text not null references users(id) on delete cascade,
  token_hash text not null unique, expires_at timestamp not null, used_at timestamp,
  created_at timestamp not null default now(), created_by text);
create table totp_secrets (
  user_id text primary key references users(id) on delete cascade,
  secret_enc text not null, last_counter integer not null default 0,
  created_at timestamp not null default now());
```

## Browser

```ts
import { createPasskeyClient, passkeysSupported, wasCancelled } from "@spaces2spaces/login-guard/client";

const passkeys = createPasskeyClient("/api/auth/passkeys");

// On the sign-in page:
if (passkeysSupported()) {
  const r = await passkeys.signIn({ slug: "dwt" });   // extra fields reach onSignIn via req.body
  window.location.href = r.redirect;
}
// After a password that answered { needsPasskey: true }:
const r = await passkeys.signIn({ slug: "dwt", step: "second" });

// While signed in:
await passkeys.register("Jesper's MacBook");
await passkeys.list();
await passkeys.remove(id);
```

`wasCancelled(error)` tells a closed prompt from a real error.

```ts
import { createTotpClient } from "@spaces2spaces/login-guard/client";
const totp = createTotpClient("/api/auth/totp");
const { uri, secret } = await totp.enrol();   // show uri as a QR code, secret as text
await totp.confirm("123456");                 // first code from the app
const r = await totp.verify("123456", { kind: "admin" });   // second step after a password
```

## What it deliberately does not do

- Store anything itself. Your tables, your queries.
- Decide who may sign in. `onSignIn` is yours.
- Trust the browser. Every challenge is signed server-side with an expiry
  inside the signature; a registration answer for one person cannot be
  finished by another; a sign-in challenge issued as a second step only
  accepts that person's keys.
