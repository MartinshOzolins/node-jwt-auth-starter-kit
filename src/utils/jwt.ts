import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import { randomUUID } from "crypto";
import { ERR } from "../services/error.service.js";
import "dotenv/config";

export type AccessTokenType = {
  user_id: string;
  token_version: number;
  jti: string;
  issued_at: number;
  exp: number;
};

export type RefreshTokenType = {
  user_id: string;
  token_version: number;
  session_id: string;
  jti: string;
  issued_at: number;
  exp: number;
};

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

const ACCESS_TTL: number = Number(process.env.JWT_ACCESS_TTL) ?? 900;
const REFRESH_TTL: number = Number(process.env.JWT_REFRESH_TTL) ?? 2592000;

/** Create a signed access token  */
export async function signAccessToken(
  userId: string,
  tokenVersion: number
): Promise<{ token: string; jti: string }> {
  // create jti, payload and option
  const jti = randomUUID();
  const payload: JwtPayload = { user_id: userId, token_version: tokenVersion };
  const options: SignOptions = { expiresIn: ACCESS_TTL, jwtid: jti };

  // return the created token
  const token = await new Promise<string>((resolve, reject) => {
    jwt.sign(payload, ACCESS_SECRET, options, (err, encoded) => {
      if (err || !encoded)
        return reject(err ?? new Error("Failed to sign access token"));
      resolve(encoded);
    });
  });

  return { token, jti };
}

/** Verify an access token  */
export async function verifyAccessToken(
  token: string
): Promise<AccessTokenType> {
  const decoded = await new Promise<JwtPayload>((resolve, reject) => {
    jwt.verify(token, ACCESS_SECRET, (err, payload) => {
      if (err || !payload)
        return reject(new Error("Invalid or expired access token"));
      resolve(payload as JwtPayload);
    });
  });

  return {
    user_id: decoded.user_id as string,
    token_version: decoded.token_version as number,
    jti: decoded.jti as string,
    issued_at: decoded.iat as number,
    exp: decoded.exp as number,
  };
}

/** Create a signed refresh token  */
export async function signRefreshToken(
  userId: string,
  tokenVersion: number,
  sessionId: string
): Promise<{ token: string; jti: string }> {
  const jti = randomUUID();
  const payload: JwtPayload = {
    user_id: userId,
    token_version: tokenVersion,
    session_id: sessionId,
  };
  const options: SignOptions = { expiresIn: REFRESH_TTL, jwtid: jti };

  const token = await new Promise<string>((resolve, reject) => {
    jwt.sign(payload, REFRESH_SECRET, options, (err, encoded) => {
      if (err || !encoded)
        return reject(err ?? new Error("Failed to sign refresh token"));
      resolve(encoded);
    });
  });

  return { token, jti };
}

/** Verifies a refresh token  */
export async function verifyRefreshToken(
  token: string
): Promise<RefreshTokenType> {
  const decoded = await new Promise<JwtPayload>((resolve, reject) => {
    jwt.verify(token, REFRESH_SECRET, (err, payload) => {
      if (err || !payload) return reject(ERR.INVALID_REFRESH());
      resolve(payload as JwtPayload);
    });
  });

  return {
    user_id: decoded.user_id as string,
    token_version: decoded.token_version as number,
    session_id: decoded.session_id as string,
    jti: decoded.jti as string,
    issued_at: decoded.iat as number,
    exp: decoded.exp as number,
  };
}
