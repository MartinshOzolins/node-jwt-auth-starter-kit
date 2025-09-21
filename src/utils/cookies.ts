import { Request, Response } from "express";

/**
 * Sets the refresh token cookie.
 */
export function setRefreshCookie(res: Response, token: string) {
  res.cookie("rt", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // production only
    path: "/auth",
    maxAge: daysToMs(Number(process.env.REFRESH_COOKIE_DAYS ?? 30)), // default 30 days
  });
}

/**
 * Clears the refresh token cookie.
 */
export function clearRefreshCookie(res: Response) {
  res.clearCookie("rt", {
    path: "/auth",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  });
}

/**
 * Gets the refresh token value from cookies.
 * Returns `null` if missing.
 */
export function getRefreshCookie(req: Request): string | null {
  if (!req.cookies) return null;
  const token = req.cookies["rt"];
  return typeof token === "string" && token.length > 0 ? token : null;
}

function daysToMs(days: number) {
  return days * 24 * 60 * 60 * 1000;
}
