import { prisma } from "../utils/prisma.js";
import { createNewUUID } from "../utils/crypto.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt.js";
import { ERR } from "./error.service.js";

export async function signTokensForUser(userId: string, tokenVersion: number) {
  const sessionId = createNewUUID();
  const { token: refreshToken, jti } = await signRefreshToken(
    userId,
    tokenVersion,
    sessionId
  );
  const { token: accessToken } = await signAccessToken(userId, tokenVersion);

  await prisma.refreshToken.create({
    data: {
      jti,
      userId,
      sessionId,
      tokenVersion,
      revoked: false,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
    },
  });

  return { accessToken, refreshToken };
}

export async function rotateTokens(rtRaw: string) {
  // verify refresh token and returns payload
  const payload = await verifyRefreshToken(rtRaw);

  // retrieve refresh token from database
  const currDatabaseRefreshToken = await prisma.refreshToken.findUnique({
    where: { jti: payload.jti },
  });
  // verify if refresh token from db is still valid
  if (
    !currDatabaseRefreshToken ||
    currDatabaseRefreshToken.revoked ||
    currDatabaseRefreshToken.expiresAt <= new Date()
  )
    throw ERR.INVALID_REFRESH();

  // find user and verify token version
  const user = await prisma.user.findUnique({ where: { id: payload.user_id } });
  if (!user || user.tokenVersion !== payload.token_version)
    throw ERR.INVALID_REFRESH();

  // create new refresh and access tokens (do not change versions as other sessions may still be valid)
  const { token: newRefreshToken, jti: newJti } = await signRefreshToken(
    user.id,
    user.tokenVersion,
    currDatabaseRefreshToken.sessionId
  );
  const { token: newAccessToken } = await signAccessToken(
    user.id,
    user.tokenVersion
  );

  // revoke the previous refresh token
  await prisma.$transaction([
    prisma.refreshToken.update({
      where: { jti: currDatabaseRefreshToken.jti },
      data: { revoked: true, revokedAt: new Date(), lastUsedAt: new Date() },
    }),
    // insert the new refresh token
    prisma.refreshToken.create({
      data: {
        jti: newJti,
        userId: user.id,
        sessionId: currDatabaseRefreshToken.sessionId, // reuse the same sessionId
        tokenVersion: user.tokenVersion,
        revoked: false,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      },
    }),
  ]);

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    userId: user.id,
    sessionId: currDatabaseRefreshToken.sessionId,
  };
}

export async function revokeSession(userId: string, sessionId: string) {
  // revoke current session for the user
  await prisma.refreshToken.updateMany({
    where: { userId, sessionId, revoked: false },
    data: { revoked: true, revokedAt: new Date() },
  });
}

export async function revokeAllSessionsForUser(userId: string) {
  // revoke all sessions for the user
  await prisma.refreshToken.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true, revokedAt: new Date() },
  });
}
