import { Router, type Request, type Response } from "express";
import { GuardError, type LoginGuard } from "./guard.js";
import { generateTotpSecret, otpauthUri, verifyTotp } from "./totp.js";
import { issueToken, readToken } from "./tokens.js";

/**
 * Authenticator-app codes, ready to mount:
 *
 *   app.use("/api/auth/totp", totpRouter(guard, { issuer, store, currentUser, onSignIn }))
 *
 * Enrolment is two calls — the secret is shown, the person proves the app
 * has it by typing one code — and the secret is stored only after that, so
 * a half-done enrolment leaves nothing behind. Signing in is one call, as
 * the second step after a password.
 */

export interface TotpStore {
  /** The secret and the last counter accepted, or null when not enrolled. */
  get(userId: string): Promise<{ secret: string; lastCounter: number } | null>;
  set(userId: string, secret: string): Promise<void>;
  setLastCounter(userId: string, counter: number): Promise<void>;
  remove(userId: string): Promise<boolean>;
}

export interface TotpRouterOptions {
  /** Shown in the authenticator app next to the account. */
  issuer: string;
  store: TotpStore;
  currentUser(req: Request): Promise<{ id: string; email: string; name?: string | null } | null>;
  /** A code has been verified as the second step. `pending` is what was
   *  stored after the password; sign in exactly that. */
  onSignIn(req: Request, res: Response, signIn: { userId: string; pending: Record<string, unknown> }): Promise<void>;
  kind?: string;
}

const ENROL_COOKIE = "lg_totp_enrol";
const ENROL_TTL_MS = 10 * 60 * 1000;

export function totpRouter(guard: LoginGuard, options: TotpRouterOptions): Router {
  const router = Router();
  const kind = options.kind ?? "totp";
  const secret = guard.secret;
  const fail = (res: Response, error: unknown) => {
    if (error instanceof GuardError) return res.status(error.status).json({ error: error.message });
    console.error("[login-guard]", error instanceof Error ? error.message : error);
    res.status(500).json({ error: "Something went wrong." });
  };

  router.get("/", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      res.json({ enrolled: Boolean(await options.store.get(user.id)) });
    } catch (e) { fail(res, e); }
  });

  /** A fresh secret, held in a signed cookie until a code proves the app has it. */
  router.post("/enrol", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      const totpSecret = generateTotpSecret();
      res.cookie(ENROL_COOKIE, issueToken(secret, { uid: user.id, s: totpSecret }, ENROL_TTL_MS), guard.cookieOptions(ENROL_TTL_MS));
      res.json({ secret: totpSecret, uri: otpauthUri({ issuer: options.issuer, account: user.email, secret: totpSecret }) });
    } catch (e) { fail(res, e); }
  });

  router.post("/confirm", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      const enrol = readToken<{ uid: string; s: string }>(secret, req.cookies?.[ENROL_COOKIE]);
      res.clearCookie(ENROL_COOKIE, { path: "/" });
      if (!enrol || enrol.uid !== user.id) throw new GuardError("The setup expired. Start again.");
      const counter = verifyTotp(enrol.s, req.body?.code);
      if (counter === null) throw new GuardError("That code did not match. Check the app and try again.");
      await options.store.set(user.id, enrol.s);
      await options.store.setLastCounter(user.id, counter);
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  router.delete("/", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      res.json({ ok: await options.store.remove(user.id) });
    } catch (e) { fail(res, e); }
  });

  /** The second step: a code, for the sign-in the password started. */
  router.post("/verify", async (req, res) => {
    const ip = req.ip ?? null;
    try {
      const pending = guard.readPending(req);
      if (!pending) throw new GuardError("Sign in with your password first.", 401);
      const email = typeof pending.email === "string" ? pending.email : null;

      const decision = await guard.check(email, ip);
      if (!decision.allowed) {
        await guard.record({ email, ip, kind, ok: false, reason: `throttled by ${decision.by}` });
        return guard.refuse(res, decision);
      }

      const enrolled = await options.store.get(pending.uid);
      if (!enrolled) throw new GuardError("No authenticator app is set up for this account.", 401);
      const counter = verifyTotp(enrolled.secret, req.body?.code, { notBeforeCounter: enrolled.lastCounter });
      if (counter === null) {
        await guard.record({ email, ip, kind, ok: false, reason: "wrong code" });
        throw new GuardError("That code did not match.", 401);
      }
      await options.store.setLastCounter(pending.uid, counter);
      guard.clearPending(res);
      await guard.record({ email, ip, kind, ok: true, reason: "second step" });
      await options.onSignIn(req, res, { userId: pending.uid, pending });
    } catch (e) { fail(res, e); }
  });

  return router;
}
