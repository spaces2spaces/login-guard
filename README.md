# @spaces2spaces/login-guard

Sign-in security for Express apps, in one small package:

- **A throttle on failed sign-ins** — per address (10 in 15 minutes) and per IP
  (30 in 15 minutes), sliding window, with a `Retry-After` and a sentence.
- **Passkeys** (WebAuthn: Face ID, Touch ID, Windows Hello, security keys) —
  as a sign-in on their own, and as the second step after a password once a
  person has one.
- **A browser client** for both, framework-free.

It knows nothing about your users, sessions or database. You hand it two
small stores and two callbacks; it does the arithmetic, the WebAuthn ceremony
and the cookies that carry a challenge across a round trip.

## Install

```bash
npm install github:spaces2spaces/login-guard#v0.1.0 @simplewebauthn/browser
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

## What it deliberately does not do

- Store anything itself. Your tables, your queries.
- Decide who may sign in. `onSignIn` is yours.
- Trust the browser. Every challenge is signed server-side with an expiry
  inside the signature; a registration answer for one person cannot be
  finished by another; a sign-in challenge issued as a second step only
  accepts that person's keys.
