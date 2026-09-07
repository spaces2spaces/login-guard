import { Router, type Request, type Response } from "express";
import { GuardError, type LoginGuard, type StoredPasskey } from "./guard.js";

/**
 * The passkey routes, ready to mount: an app adds
 *
 *   app.use("/api/auth/passkeys", passkeyRouter(guard, { currentUser, onSignIn }))
 *
 * and gets registration, listing, removal and sign-in. The two callbacks are
 * the only places the app's own model appears: who is signed in now, and
 * what to do once a passkey has proved who somebody is.
 */

export interface PasskeyRouterOptions {
  /** The signed-in person, or null. Registration and listing need one. */
  currentUser(req: Request): Promise<{ id: string; email: string; name?: string | null } | null>;
  /**
   * A passkey has been verified. Decide whether this person may sign in for
   * what the body asks (a workspace, the admin) and set the session — or
   * answer with an error. `pending` is set when this is the second step
   * after a password; the app should sign in exactly what it stored then.
   */
  onSignIn(req: Request, res: Response, signIn: {
    userId: string; passkey: StoredPasskey; pending: Record<string, unknown> | null;
  }): Promise<void>;
  /** The word for the door in the attempt log. Defaults to "passkey". */
  kind?: string;
}

export function passkeyRouter(guard: LoginGuard, options: PasskeyRouterOptions): Router {
  const router = Router();
  const kind = options.kind ?? "passkey";
  const fail = (res: Response, error: unknown) => {
    if (error instanceof GuardError) return res.status(error.status).json({ error: error.message });
    console.error("[login-guard]", error instanceof Error ? error.message : error);
    res.status(500).json({ error: "Something went wrong." });
  };

  // ── Managing one's own passkeys ───────────────────────────────────────────

  router.get("/", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      const keys = await guard.passkeyStore.listForUser(user.id);
      res.json({ passkeys: keys.map(publicView) });
    } catch (e) { fail(res, e); }
  });

  router.post("/register/options", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      res.json(await guard.registrationOptions(res, user));
    } catch (e) { fail(res, e); }
  });

  router.post("/register/verify", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      const passkey = await guard.verifyRegistration(req, res, {
        userId: user.id, response: req.body?.response, name: typeof req.body?.name === "string" ? req.body.name : null,
      });
      res.json({ passkey: publicView(passkey) });
    } catch (e) { fail(res, e); }
  });

  router.delete("/:id", async (req, res) => {
    const user = await options.currentUser(req);
    if (!user) return res.status(401).json({ error: "Sign in first." });
    try {
      const gone = await guard.passkeyStore.remove(String(req.params.id), user.id);
      if (!gone) return res.status(404).json({ error: "No such passkey." });
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  // ── Signing in ────────────────────────────────────────────────────────────

  /**
   * Options for a sign-in. With a pending password step, only that person's
   * keys are offered; otherwise the browser offers whatever it holds.
   */
  router.post("/login/options", async (req, res) => {
    try {
      const pending = guard.readPending(req);
      res.json(await guard.authenticationOptions(res, pending ? { id: pending.uid } : null));
    } catch (e) { fail(res, e); }
  });

  router.post("/login/verify", async (req, res) => {
    const ip = req.ip ?? null;
    try {
      const decision = await guard.check(null, ip);
      if (!decision.allowed) {
        await guard.record({ email: null, ip, kind, ok: false, reason: `throttled by ${decision.by}` });
        return guard.refuse(res, decision);
      }
      let passkey: StoredPasskey;
      try {
        passkey = await guard.verifyAuthentication(req, res, req.body?.response);
      } catch (error) {
        await guard.record({ email: null, ip, kind, ok: false, reason: error instanceof Error ? error.message : "verify failed" });
        throw error;
      }
      const pending = guard.readPending(req);
      guard.clearPending(res);
      await guard.record({ email: null, ip, kind, ok: true, reason: pending ? "second step" : null });
      await options.onSignIn(req, res, { userId: passkey.userId, passkey, pending });
    } catch (e) { fail(res, e); }
  });

  return router;
}

/** What the page may see of a passkey: never the public key or credential id. */
export function publicView(p: StoredPasskey) {
  return {
    id: p.id, name: p.name ?? null,
    createdAt: p.createdAt ?? null, lastUsedAt: p.lastUsedAt ?? null,
  };
}
