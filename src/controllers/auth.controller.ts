// src/controllers/auth.controller.ts
import { Request, Response, NextFunction } from "express";
import * as Cookies from "../utils/cookies.js";
import * as JWT from "../utils/jwt.js";
import * as Crypto from "../utils/crypto.js";
import { prisma } from "../utils/prisma.js";
import * as EmailService from "../services/email.service.js";
import * as UserService from "../services/user.service.js";
import * as Tokens from "../services/token.service.js";
import * as ActionTokens from "../services/action-token.service.js";
import * as AuthSchemas from "../validators/auth.schemas.js";
import { ERR } from "../services/error.service.js";
import "dotenv/config";

function flattenFieldErrors(zodError: any): Record<string, string> {
  const { fieldErrors } = zodError.flatten();
  const out: Record<string, string> = {};
  for (const [key, arr] of Object.entries(fieldErrors)) {
    const messages = arr as string[] | undefined;
    if (messages?.length) {
      out[key] = messages[0];
    }
  }
  return out;
}

// POST /auth/sign-up
export async function signUp(req: Request, res: Response, next: NextFunction) {
  try {
    const parsed = AuthSchemas.signUpSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { email, password } = parsed.data;

    if (await UserService.findUserByEmail(email)) {
      return res
        .status(400)
        .json({ errors: { email: "Email already registered" } });
    }

    const user = await UserService.createUser(
      email,
      await Crypto.hashPassword(password)
    );

    const raw = await ActionTokens.createActionToken(
      "EMAIL_VERIFICATION",
      user.id,
      24 * 60 * 60 * 1000
    );
    await EmailService.sendVerifyEmail({ to: user.email, token: raw });

    res.status(201).json({
      message: "Account created. Check your email to verify before signing in.",
    });
  } catch (err) {
    next(err);
  }
}

// POST /auth/sign-in
export async function signIn(req: Request, res: Response, next: NextFunction) {
  try {
    const parsed = AuthSchemas.signInSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { email, password } = parsed.data;
    console.log("check validation 1");
    const user = await UserService.findUserByEmail(email);
    console.log("check validation 2");
    if (!user) throw ERR.INVALID_CREDENTIALS();
    if (!user.emailVerified) throw ERR.UNAUTHORIZED();
    console.log("check validation 3");
    const ok = await Crypto.verifyPassword(password, user.passwordHash);
    if (!ok) throw ERR.INVALID_CREDENTIALS();
    console.log("check validation 4");

    const { accessToken, refreshToken } = await Tokens.signTokensForUser(
      user.id,
      user.tokenVersion
    );
    console.log("check validation 5");

    Cookies.setRefreshCookie(res, refreshToken);

    res.json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
      },
    });
  } catch (err) {
    if (process.env.NODE_ENV === "development") {
      console.error(err);
    }
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
    const rt = Cookies.getRefreshCookie(req);
    if (!rt) throw ERR.INVALID_REFRESH();

    const { accessToken, refreshToken } = await Tokens.rotateTokens(rt);
    Cookies.setRefreshCookie(res, refreshToken);

    res.json({ accessToken });
  } catch (err) {
    next(err);
  }
}

// POST /auth/logout (this device)
export async function logout(req: Request, res: Response): Promise<void> {
  const rt = Cookies.getRefreshCookie(req);
  if (rt) {
    try {
      const { user_id, session_id } = await JWT.verifyRefreshToken(rt);
      await Tokens.revokeSession(user_id, session_id);
    } catch {}
  }
  Cookies.clearRefreshCookie(res);
  res.json({ ok: true });
}

// POST /auth/logout-all (global)
export async function logoutAll(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    let userId: string | null = null;

    const auth = req.headers.authorization;
    if (auth?.startsWith("Bearer ")) {
      try {
        userId = (await JWT.verifyAccessToken(auth.slice(7))).user_id;
      } catch {}
    }
    if (!userId) {
      const rt = Cookies.getRefreshCookie(req);
      if (rt) {
        try {
          userId = (await JWT.verifyRefreshToken(rt)).user_id;
        } catch {}
      }
    }
    if (!userId) throw ERR.UNAUTHORIZED();

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

    Cookies.clearRefreshCookie(res);
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
) {
  try {
    const parsed = AuthSchemas.tokenParamSchema.safeParse({
      token: (req.body as any)?.token ?? (req.query as any)?.token,
    });
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { token } = parsed.data;

    const row = await ActionTokens.findActionToken("EMAIL_VERIFICATION", token);
    if (!row) throw ERR.INVALID_TOKEN();

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
) {
  try {
    const parsed = AuthSchemas.emailSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { email } = parsed.data;

    const user = await UserService.findUserByEmail(email);
    if (!user) {
      return res.json({
        message: "If that account exists, a verification email has been sent.",
      });
    }
    if (user.emailVerified) {
      return res.status(400).json({ message: "Already verified" });
    }

    const raw = await ActionTokens.createActionToken(
      "EMAIL_VERIFICATION",
      user.id,
      24 * 60 * 60 * 1000
    );
    await EmailService.sendVerifyEmail({ to: user.email, token: raw });

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
) {
  try {
    const parsed = AuthSchemas.emailSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { email } = parsed.data;

    const user = await UserService.findUserByEmail(email);
    if (user) {
      const raw = await ActionTokens.createActionToken(
        "PASSWORD_RESET",
        user.id,
        15 * 60 * 1000
      );
      await EmailService.sendPasswordResetEmail({ to: user.email, token: raw });
    }
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
) {
  try {
    const parsed = AuthSchemas.tokenParamSchema.safeParse({
      token: (req.body as any)?.token ?? (req.query as any)?.token,
    });
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { token } = parsed.data;

    const row = await ActionTokens.findActionToken("PASSWORD_RESET", token);
    if (!row) throw ERR.INVALID_TOKEN();

    const confirmRaw = await ActionTokens.createActionToken(
      "PASSWORD_RESET_CONFIRM",
      row.userId,
      10 * 60 * 1000
    );
    await prisma.actionToken.update({
      where: { id: row.id },
      data: { usedAt: new Date() },
    });

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
) {
  try {
    const parsed = AuthSchemas.passwordResetConfirmSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: flattenFieldErrors(parsed.error) });
    }
    const { token, newPassword } = parsed.data;

    const row = await ActionTokens.findActionToken(
      "PASSWORD_RESET_CONFIRM",
      token
    );
    if (!row) throw ERR.INVALID_TOKEN();

    const newHash = await Crypto.hashPassword(newPassword);

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

    Cookies.clearRefreshCookie(res);
    res.json({ message: "Password updated successfully. Please sign-in." });
  } catch (err) {
    next(err);
  }
}
