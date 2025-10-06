import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import {
  setRefreshCookie,
  clearRefreshCookie,
  getRefreshCookie,
} from "../utils/cookies.js";
import { verifyAccessToken, verifyRefreshToken } from "../utils/jwt.js";
import { hashPassword, verifyPassword } from "../utils/crypto.js";
import { prisma } from "../utils/prisma.js";
import {
  sendPasswordResetEmail,
  sendVerifyEmail,
} from "../services/email.service.js";
import { createUser, findUserByEmail } from "../services/user.service.js";
import * as Tokens from "../services/token.service.js";
import * as ActionTokens from "../services/action-token.service.js";
import {
  signInSchema,
  signUpSchema,
  tokenParamSchema,
  passwordResetConfirmSchema,
} from "../validators/auth.schemas.js";
import { ERR } from "../services/error.service.js";

// POST /auth/sign-up
export async function signUp(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { email, password } = signUpSchema.parse(req.body);

    // check existing user
    if (await findUserByEmail(email.toLowerCase())) {
      res.status(400).json({ message: "Email already registered" });
      return;
    }

    // create user
    const user = await createUser(
      email.toLowerCase(),
      await hashPassword(password)
    );

    // create email verification action token
    const raw = await ActionTokens.createActionToken(
      "EMAIL_VERIFICATION",
      user.id,
      24 * 60 * 60 * 1000 // 24h
    );
    await sendVerifyEmail({ to: user.email, token: raw });

    res.status(201).json({
      message: "Account created. Check your email to verify before signing in.",
    });
  } catch (err) {
    next(err);
  }
}

// POST /auth/sign-in
export async function signIn(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // validate body
    const { email, password } = signInSchema.parse(req.body);

    // find user
    const user = await findUserByEmail(email.toLowerCase());

    // validation
    if (!user) throw ERR.INVALID_CREDENTIALS();
    if (!user.emailVerified) throw ERR.UNAUTHORIZED();
    const ok = await verifyPassword(password, user.passwordHash);
    if (!ok) throw ERR.INVALID_CREDENTIALS();

    // sign tokens
    const { accessToken, refreshToken } = await Tokens.signTokensForUser(
      user.id,
      user.tokenVersion
    );

    // attach cookie
    setRefreshCookie(res, refreshToken);

    // success response
    res.json({
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
}

// POST /auth/refresh
export async function refresh(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // retrieve refresh cookie
    const rt = getRefreshCookie(req);
    if (!rt) throw ERR.INVALID_REFRESH();

    // validates refresh token, rotates versions, returns new tokens
    const { accessToken, refreshToken } = await Tokens.rotateTokens(rt);

    // attach refresh token as a cookie
    setRefreshCookie(res, refreshToken);

    // success response
    res.json({ accessToken });
  } catch (err) {
    next(err);
  }
}

// POST /auth/logout (this device)
export async function logout(req: Request, res: Response): Promise<void> {
  // retrieve refresh token
  const rt = getRefreshCookie(req);

  if (rt) {
    // if found, verify it and revoke
    try {
      const { user_id, session_id } = await verifyRefreshToken(rt);
      await Tokens.revokeSession(user_id, session_id);
    } catch {
      // ignore invalid cookie; we'll still clear it
    }
  }
  // clear the cookie in both cases
  clearRefreshCookie(res);
  res.json({ ok: true });
}

// POST /auth/logout-all (global)
export async function logoutAll(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // userId used to revoke all sessions
    let userId: string | null = null;

    // prefer access token authentication
    const auth = req.headers.authorization;
    if (auth?.startsWith("Bearer ")) {
      try {
        userId = (await verifyAccessToken(auth.slice(7))).user_id;
      } catch {
        // fall through to refresh cookie
      }
    }

    // fallback to refresh cookie
    if (!userId) {
      const rt = getRefreshCookie(req);
      if (rt) {
        try {
          userId = (await verifyRefreshToken(rt)).user_id;
        } catch {
          // still unauthenticated
        }
      }
    }

    // if not authorised, cannot logout
    if (!userId) throw ERR.UNAUTHORIZED();

    // on success, increment token version and revoke all sessions
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: { tokenVersion: { increment: 1 } },
      }),
      prisma.refreshToken.updateMany({
        where: { userId, revoked: false },
        data: { revoked: true, revokedAt: new Date() },
      }),
    ]);

    // clear cookie
    clearRefreshCookie(res);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

// POST /auth/verify-email
export async function verifyEmail(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // accept token from body OR query
    const { token } = tokenParamSchema.parse({
      token: (req.body as any)?.token ?? (req.query as any)?.token,
    });

    // find token
    const row = await ActionTokens.findActionToken("EMAIL_VERIFICATION", token);

    // if no such token found , cannot verify email
    if (!row) throw ERR.INVALID_TOKEN();

    // on success, increment token version + set action token as used
    await prisma.$transaction([
      prisma.actionToken.update({
        where: { id: row.id },
        data: { usedAt: new Date() },
      }),
      prisma.user.update({
        where: { id: row.userId },
        data: { emailVerified: true, tokenVersion: { increment: 1 } },
      }),
    ]);

    // success message
    res.json({ message: "Email verified. Please sign-in." });
  } catch (err) {
    next(err);
  }
}

// POST /auth/resend-verification
export async function resendVerification(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // validate email
    const { email } = z.object({ email: z.email() }).parse(req.body);

    // find user
    const user = await findUserByEmail(email.toLowerCase());

    // generic message even if no user
    if (!user) {
      res.json({
        message: "If that account exists, a verification email has been sent.",
      });
      return;
    }
    // already verified
    if (user.emailVerified) {
      res.status(400).json({ message: "Already verified" });
      return;
    }

    // create new action token
    const raw = await ActionTokens.createActionToken(
      "EMAIL_VERIFICATION",
      user.id,
      24 * 60 * 60 * 1000
    );

    // send verification email with that new raw token
    await sendVerifyEmail({ to: user.email, token: raw });

    // generic success message
    res.json({
      message: "If that account exists, a verification email has been sent.",
    });
  } catch (err) {
    next(err);
  }
}

// POST /auth/password-reset/request
export async function passwordResetRequest(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // validate email
    const { email } = z.object({ email: z.email() }).parse(req.body);

    // find user
    const user = await findUserByEmail(email.toLowerCase());

    // on user found, create new action token
    if (user) {
      const raw = await ActionTokens.createActionToken(
        "PASSWORD_RESET",
        user.id,
        15 * 60 * 1000 // 15m
      );
      // send password reset email
      await sendPasswordResetEmail({ to: user.email, token: raw });
    }
    // success message
    res.json({ message: "If that email exists, we sent a reset link." });
  } catch (err) {
    next(err);
  }
}

// POST /auth/password-reset/verify
export async function passwordResetVerify(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // retrieve raw token passed from frontend
    const { token } = tokenParamSchema.parse({
      token: (req.body as any)?.token ?? (req.query as any)?.token,
    });

    // find action token
    const row = await ActionTokens.findActionToken("PASSWORD_RESET", token);
    if (!row) throw ERR.INVALID_TOKEN();

    // on email confirm, create one more token for password update confirmation
    const confirmRaw = await ActionTokens.createActionToken(
      "PASSWORD_RESET_CONFIRM",
      row.userId,
      10 * 60 * 1000 // 10m
    );

    // mark the original reset token as used
    await prisma.actionToken.update({
      where: { id: row.id },
      data: { usedAt: new Date() },
    });

    // pass the new token
    res.json({ ok: true, token: confirmRaw });
  } catch (err) {
    next(err);
  }
}

// POST /auth/password-reset/confirm
export async function passwordResetConfirm(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // retrieve and token
    const { token, newPassword } = passwordResetConfirmSchema.parse(req.body);

    // find token from db
    const row = await ActionTokens.findActionToken(
      "PASSWORD_RESET_CONFIRM",
      token
    );
    if (!row) throw ERR.INVALID_TOKEN();

    // hash password
    const newHash = await hashPassword(newPassword);

    // reset action token +  update user password + increment user token version + revoke all sessions
    await prisma.$transaction([
      prisma.actionToken.update({
        where: { id: row.id },
        data: { usedAt: new Date() },
      }),
      prisma.user.update({
        where: { id: row.userId },
        data: { passwordHash: newHash, tokenVersion: { increment: 1 } },
      }),
      prisma.refreshToken.updateMany({
        where: { userId: row.userId, revoked: false },
        data: { revoked: true, revokedAt: new Date() },
      }),
    ]);

    // clear cookie
    clearRefreshCookie(res);

    // success message
    res.json({ message: "Password updated successfully. Please sign-in." });
  } catch (err) {
    next(err);
  }
}
