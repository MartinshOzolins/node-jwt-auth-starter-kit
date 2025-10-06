import { Request, Response } from "express";
import "dotenv/config";

/**
 * Set the refresh token cookie.
 */
export function setRefreshCookie(res: Response, token: string) {
  res.cookie("rt", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    path: "/auth",
    maxAge: daysToMs(Number(process.env.REFRESH_COOKIE_DAYS ?? 30)), // default 30 days
  });
}

/**
 * Clear the refresh token cookie.
 */
export function clearRefreshCookie(res: Response) {
  res.clearCookie("rt", {
    path: "/auth",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  });
}

/**
 * Get the refresh token value from cookies.
 * Return `null` if missing.
 */
export function getRefreshCookie(req: Request): string | null {
  if (!req.cookies) return null;
  const token = req.cookies["rt"];
  return typeof token === "string" && token.length > 0 ? token : null;
}

function daysToMs(days: number) {
  return days * 24 * 60 * 60 * 1000;
}
