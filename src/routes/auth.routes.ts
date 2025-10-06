import { Router } from "express";
import { z } from "zod";
import {
  createNewUUID,
  hashPassword,
  createSha256Hash,
  verifyPassword,
} from "../utils/crypto.js";
import { prisma } from "../utils/prisma.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "../utils/jwt.js";
import {
  setRefreshCookie,
  clearRefreshCookie,
  getRefreshCookie,
} from "../utils/cookies.js";
import {
  sendPasswordResetEmail,
  sendVerifyEmail,
} from "../services/email.service.js";
import { createUser, findUserByEmail } from "../services/user.service.js";
import { ERR } from "../services/error.service.js";

const router = Router();
/**
 * POST /auth/sign-up
 * - Create user
 * - Issue email verification token
 * - Send verification email
 * - Do NOT sign in (no access/refresh tokens)
 */
router.post("/sign-up", async (req, res, next) => {
  try {
    // 1) validate body
    const { email, password } = z
      .object({
        email: z.email(),
        password: z.string().min(8),
      })
      .parse(req.body);

    // 2) ensure email
    const exists = await findUserByEmail(email);
    if (exists) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // 3) create user
    const user = await createUser(
      email.toLowerCase(),
      await hashPassword(password)
    );

    // 4) create email verification token
    const rawToken = createNewUUID();

    // 5) store token into database (for later verification)
    await prisma.actionToken.create({
      data: {
        userId: user.id,
        kind: "EMAIL_VERIFICATION",
        tokenHash: createSha256Hash(rawToken),
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24), // 24h
      },
    });

    // 5) send verification email (uses raw token)
    await sendVerifyEmail({ to: user.email, token: rawToken });

    // 6) success message with note to verify email
    return res.status(201).json({
      message: "Account created. Check your email to verify before signing in.",
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /auth/sign-in
 */
router.post("/sign-in", async (req, res, next) => {
  try {
    // 1) validate body
    const { email, password } = z
      .object({
        email: z.email(),
        password: z.string().min(8),
      })
      .parse(req.body);

    // 2) retrieve user
    const user = await findUserByEmail(email);
    if (!user) throw ERR.INVALID_CREDENTIALS();

    // 3) check email verification
    if (!user.emailVerified) throw ERR.UNAUTHORIZED();

    // 4) compare passwords
    const ok = await verifyPassword(password, user.passwordHash);
    if (!ok) throw ERR.INVALID_CREDENTIALS();

    // 5) sign access token (does not set it anywhere)
    const { token: accessToken } = await signAccessToken(
      user.id,
      user.tokenVersion
    );

    // 6) sign refresh token
    const sessionId = createNewUUID(); // session to identify each device
    const { token: refreshToken, jti } = await signRefreshToken(
      user.id,
      user.tokenVersion,
      sessionId
    );

    // 7) add refesh token data into database
    await prisma.refreshToken.create({
      data: {
        jti,
        userId: user.id,
        sessionId,
        tokenVersion: user.tokenVersion,
        revoked: false,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      },
    });

    // 8) attach refresh token as a cookie
    setRefreshCookie(res, refreshToken);

    // 9) return access token and a user
    return res.json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /auth/refresh
 * - verify refresh cookie
 * - check DB row (valid, not expired, version match)
 * - rotates: invalidate old row, insert new row (same sessionId, new jti)
 * - return new access + sets new refresh cookie
 */
router.post("/refresh", async (req, res, next) => {
  // 1) retrieve refresh token from cookies
  const rt = getRefreshCookie(req);
  if (!rt) throw ERR.INVALID_REFRESH();

  try {
    // 2) verify refresh token and returns payload
    const payload = await verifyRefreshToken(rt);

    // 3) retrieve refresh token from database
    const row = await prisma.refreshToken.findUnique({
      where: { jti: payload.jti },
    });

    // 4) verify if refresh token from db is still valid
    if (!row || row.revoked || row.expiresAt <= new Date()) {
      throw ERR.INVALID_REFRESH();
    }

    // 5) find user and verify token version
    const user = await prisma.user.findUnique({
      where: { id: payload.user_id },
    });
    if (!user || user.tokenVersion !== payload.token_version) {
      throw ERR.INVALID_REFRESH();
    }

    // rotate refresh tokens automically
    // 6) create new refresh and access tokens (do not change versions as other sessions may still be valid)
    const { token: newRefreshToken, jti: newJti } = await signRefreshToken(
      user.id,
      user.tokenVersion,
      row.sessionId
    );
    const { token: newAccessToken } = await signAccessToken(
      user.id,
      user.tokenVersion
    );

    // 7) revoke the previous refresh token
    await prisma.$transaction([
      prisma.refreshToken.update({
        where: { jti: row.jti },
        data: { revoked: true, revokedAt: new Date(), lastUsedAt: new Date() },
      }),
      // 8) insert the new refresh token
      prisma.refreshToken.create({
        data: {
          jti: newJti,
          userId: user.id,
          sessionId: row.sessionId, // reuse the same sessionId
          tokenVersion: user.tokenVersion,
          revoked: false,
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
        },
      }),
    ]);

    // 9) attach new refresh token
    setRefreshCookie(res, newRefreshToken);

    // 10) return new access token
    return res.json({ accessToken: newAccessToken });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /auth/logout (this device)
 * - revoke all valid rows for this sessionId
 * - clear cookie
 */
router.post("/logout", async (req, res) => {
  // 1) retrieve refresh token
  const rt = getRefreshCookie(req);

  if (rt) {
    // 2) if exists, verify and revoke it
    try {
      const { user_id, session_id } = await verifyRefreshToken(rt);
      await prisma.refreshToken.updateMany({
        where: { userId: user_id, sessionId: session_id, revoked: false },
        data: { revoked: true, revokedAt: new Date() },
      });
    } catch {}
  }
  // 2) clear cookie from refresh token (even if in invalid)
  clearRefreshCookie(res);

  return res.json({ ok: true });
});

/**
 * POST /auth/logout-all (global)
 * - identify user via access token (preferred) or refresh cookie (fallback)
 * - bump tokenVersion and revoke all refresh rows
 */
router.post("/logout-all", async (req, res, next) => {
  let userId: string | null = null;

  // 1) check if access token exists
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    try {
      // 2) verify access token
      const dec = await verifyAccessToken(auth.slice(7));
      userId = dec.user_id;
    } catch (err) {
      next(err);
    }
  }
  // 5) fallback: refresh cookie validation
  if (!userId) {
    // 6) retrieve refresh cookie
    const rt = getRefreshCookie(req);
    // 7) it authorised and refresh token is valid -> continue
    if (rt) {
      try {
        const dec = await verifyRefreshToken(rt);
        userId = dec.user_id;
      } catch (err) {
        next(err);
      }
    }
  }
  // 8) if unauthorised, cannot logout-all
  if (!userId) throw ERR.UNAUTHORIZED();

  // 9) increment token version + revoke all refresh tokens
  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { tokenVersion: { increment: 1 } }, // will not allow using old access/refresh tokens
    }),
    prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true, revokedAt: new Date() },
    }),
  ]);

  // clear refresh cookie on this device
  clearRefreshCookie(res);
  return res.json({ ok: true });
});

/**
 * POST /auth/verify-email
 * body: { token: string }
 */
router.post("/verify-email", async (req, res) => {
  // 1) token validation
  const result = z
    .object({
      token: z.string().min(10),
    })
    .safeParse(req.query);

  if (!result.success) throw ERR.INVALID_TOKEN();

  const { token } = result.data;

  // 2) compare presented token with database token (hashes token to compare against db + checks expiration date)
  const row = await prisma.actionToken.findFirst({
    where: {
      kind: "EMAIL_VERIFICATION",
      tokenHash: createSha256Hash(token),
      usedAt: null,
      expiresAt: { gt: new Date() },
    },
  });

  // 3) if no such token exists, return error
  if (!row) throw ERR.INVALID_TOKEN();

  // 4) otherwise, update token as used
  await prisma.$transaction([
    prisma.actionToken.update({
      where: { id: row.id },
      data: { usedAt: new Date() },
    }),
    // 5) update user to be verified + increment token
    prisma.user.update({
      where: { id: row.userId },
      data: { emailVerified: true, tokenVersion: { increment: 1 } },
    }),
  ]);

  // 6) return success message
  return res.json({ message: "Email verified. Please sign-in." });
});

/**
 * POST /auth/resend-verification
 * body: { email }
 * - no auth required
 */
router.post("/resend-verification", async (req, res) => {
  // 1) validate email
  const { email } = z
    .object({ email: z.email() })
    .parse({ email: req.body.email });

  // 2) find user with such email
  const user = await findUserByEmail(email.toLowerCase());

  // 3) if no user, return success anyway (avoid leaking valid accounts)
  if (!user) {
    return res.json({
      message: "If that account exists, a verification email has been sent.",
    });
  }

  // 4) return that already verified
  if (user.emailVerified) {
    return res.status(400).json({ message: "Already verified" });
  }

  // 5) if not verified, create a new raw token
  const raw = createNewUUID();

  // 6) insert hashed raw token into database and set expiration in 24h
  await prisma.actionToken.create({
    data: {
      userId: user.id,
      kind: "EMAIL_VERIFICATION",
      tokenHash: createSha256Hash(raw),
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24), // 24h
    },
  });

  // 7) send verification email with the raw token (will be hashed and checked when returned)
  await sendVerifyEmail({ to: user.email, token: raw });

  // 8) return success message
  return res.json({
    message: "If that account exists, a verification email has been sent.",
  });
});

/**
 * POST /auth/password-reset/request
 * body: { email }
 * Always 200 to avoid account enumeration
 */
router.post("/password-reset/request", async (req, res) => {
  // 1) validate email
  const { email } = z
    .object({
      email: z.email(),
    })
    .parse(req.body);

  // 2) find user
  const user = await findUserByEmail(email.toLowerCase());

  if (user) {
    // 3) if user exist, create a raw token
    const raw = createNewUUID();
    // 4) insert action token into database
    await prisma.actionToken.create({
      data: {
        userId: user.id,
        kind: "PASSWORD_RESET",
        tokenHash: createSha256Hash(raw),
        expiresAt: new Date(Date.now() + 1000 * 60 * 15), // 15m
      },
    });
    // 5) send password reset email with raw token (when returned, we hash it and compare against db hased token)
    await sendPasswordResetEmail({ to: user.email, token: raw });
  }
  // 6) return success message
  return res.json({ message: "If that email exists, we sent a reset link." });
});

/**
 * POST /auth/password-reset/verify
 * body: { token }
 */
router.post("/password-reset/verify", async (req, res) => {
  // 1) retrieve token
  const result = z
    .object({ token: z.string().min(10) })
    .safeParse({ token: req.body.token ?? req.query.token });
  if (!result.success) throw ERR.INVALID_TOKEN();

  // 2) hashe token and compares against database
  const token = result.data.token;
  const row = await prisma.actionToken.findFirst({
    where: {
      kind: "PASSWORD_RESET",
      tokenHash: createSha256Hash(token),
      usedAt: null,
      expiresAt: { gt: new Date() },
    },
    select: { id: true, userId: true },
  });

  // 3) if such token doesn't exist, return an error
  if (!row) throw ERR.INVALID_TOKEN();

  // 4) create new raw token
  const confirmRaw = createNewUUID();
  const CONFIRM_TTL_MS = 1000 * 60 * 10; // 10 minutes

  // 5) revoke prev token + inserts a new token for later confirmation when sends an updated password
  await prisma.$transaction([
    // revoke prev token
    prisma.actionToken.update({
      where: { id: row.id },
      data: { usedAt: new Date() },
    }),
    // create a new token
    prisma.actionToken.create({
      data: {
        userId: row.userId,
        kind: "PASSWORD_RESET_CONFIRM",
        tokenHash: createSha256Hash(confirmRaw),
        expiresAt: new Date(Date.now() + CONFIRM_TTL_MS),
      },
    }),
  ]);

  // 6) return success message and raw token
  return res.json({
    ok: true,
    token: confirmRaw,
  });
});

/**
 * POST /auth/password-reset/confirm
 * body: { token, newPassword }
 * Consume token, update password, bump tokenVersion, revoke all refresh tokens
 */
router.post("/password-reset/confirm", async (req, res, next) => {
  // 1) retrieve token + new password
  try {
    const result = z
      .object({
        token: z.string().min(10),
        newPassword: z.string().min(8),
      })
      .safeParse({ token: req.body.token, newPassword: req.body.newPassword });

    if (!result.success) throw ERR.INVALID_TOKEN();

    // 2) validate the CONFIRM token
    const { token, newPassword } = result.data;
    const row = await prisma.actionToken.findFirst({
      where: {
        kind: "PASSWORD_RESET_CONFIRM",
        tokenHash: createSha256Hash(token),
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      select: { id: true, userId: true },
    });
    // 3) if no such token, return error
    if (!row) throw ERR.INVALID_TOKEN();

    // 4) hash new password
    const newHash = await hashPassword(newPassword);

    await prisma.$transaction([
      // 5) revoke confirm token as used
      prisma.actionToken.update({
        where: { id: row.id },
        data: { usedAt: new Date() },
      }),
      // 6) update user token version + 1
      prisma.user.update({
        where: { id: row.userId },
        data: { passwordHash: newHash, tokenVersion: { increment: 1 } },
      }),
      // 7) revoke all session
      prisma.refreshToken.updateMany({
        where: { userId: row.userId, revoked: false },
        data: { revoked: true, revokedAt: new Date() },
      }),
    ]);
    // 8) clear the refresh cookie on this device
    clearRefreshCookie(res);
    return res.json({ message: "Password updated. Please sign-in" });
  } catch (err) {
    next(err);
  }
});

export default router;
