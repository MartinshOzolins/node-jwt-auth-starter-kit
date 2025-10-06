import { z } from "zod";

export const emailSchema = z.object({
  email: z
    .email({ error: "Please provide a valid email address" })
    .trim()
    .transform((v) => v.toLowerCase()),
});

export const passwordSchema = z
  .string({
    error: "Password is required and should contain at least one letter",
  })
  .min(8, { error: "Password must be at least 8 characters" })
  .regex(/[A-Za-z]/, { error: "Password must contain at least one letter" })
  .regex(/[0-9]/, { error: "Password must contain at least one number" });

export const signUpSchema = emailSchema.extend({
  password: passwordSchema,
});

export const signInSchema = signUpSchema;

export const tokenParamSchema = z.object({
  token: z
    .string({ error: "Token is required" })
    .min(10, { error: "Invalid or malformed token" }),
});

export const passwordResetConfirmSchema = tokenParamSchema.extend({
  newPassword: passwordSchema,
});
