// src/validators/auth.schemas.ts
import { z } from "zod";

export const signUpSchema = z.object({
  email: z
    .email({ error: "Please provide a valid email address" })
    .trim()
    .transform((v) => v.toLowerCase()),
  password: z
    .string({ error: "Password is required" })
    .min(8, { error: "Password must be at least 8 characters" }),
});

export const signInSchema = signUpSchema;

export const tokenParamSchema = z.object({
  token: z
    .string({ error: "Token is required" })
    .min(10, { error: "Invalid or malformed token" }),
});

export const passwordResetConfirmSchema = z.object({
  token: z
    .string({ error: "Token is required" })
    .min(10, { error: "Invalid or malformed token" }),
  newPassword: z
    .string({ error: "New password is required" })
    .min(8, { error: "Password must be at least 8 characters" }),
});
