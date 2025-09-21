import { Request, Response, NextFunction } from "express";

// map for known errors
const ERROR_MAP: Record<string, { status: number; message: string }> = {
  EMAIL_IN_USE: { status: 400, message: "Email already registered" },
  INVALID_CREDENTIALS: { status: 401, message: "Invalid email or password" },
  INVALID_REFRESH: { status: 401, message: "Invalid refresh token" },
  INVALID_TOKEN: { status: 400, message: "Invalid or expired token" },
  UNAUTHORIZED: { status: 401, message: "Unauthorized" },
};

//
export const ERR = {
  EMAIL_IN_USE: () => new Error("EMAIL_IN_USE"),
  INVALID_CREDENTIALS: () => new Error("INVALID_CREDENTIALS"),
  INVALID_REFRESH: () => new Error("INVALID_REFRESH"),
  INVALID_TOKEN: () => new Error("INVALID_TOKEN"),
  UNAUTHORIZED: () => new Error("UNAUTHORIZED"),
};

/**
 * Global error handler for Express
 */
export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
) {
  // 1. checks for known errors
  if (err instanceof Error && ERROR_MAP[err.message]) {
    const mapped = ERROR_MAP[err.message];
    return res.status(mapped.status).json({ error: mapped.message });
  }

  // 2. checks for zod validation
  if ((err as any).name === "ZodError") {
    return res.status(400).json({ error: "Invalid request", details: err });
  }

  // 3. fallback for unexpected errors
  console.error("Unhandled error:", err);
  return res.status(500).json({ error: "Internal server error" });
}
