import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

interface SendEmailValues {
  to: string;
  token: string;
}

const FROM = process.env.EMAIL_ADDRESS ?? "example@gmail.com";
const CLIENT_URL = process.env.CLIENT_BASE_URL ?? "http://localhost:4000";

function buildVerifyUrl(token: string) {
  return `${CLIENT_URL}/auth/verify-email?token=${encodeURIComponent(token)}`;
}

function buildResetUrl(token: string) {
  return `${CLIENT_URL}/auth/password-reset/verify?token=${encodeURIComponent(
    token
  )}`;
}

/**
 * Send email verification message
 */
export async function sendVerifyEmail({ to, token }: SendEmailValues) {
  const url = buildVerifyUrl(token);
  await resend.emails.send({
    from: FROM,
    to,
    subject: "Verify your email address",
    text: [
      "Welcome to APP NAME",
      "",
      "Please confirm your email by clicking the link below:",
      url,
      "",
      "If you didn’t create an account, you can safely ignore this email.",
    ].join("\n"),
  });
}

/**
 * Send password reset message
 */
export async function sendPasswordResetEmail({ to, token }: SendEmailValues) {
  const url = buildResetUrl(token);
  await resend.emails.send({
    from: FROM,
    to,
    subject: "Reset your password",
    text: [
      "We received a request to reset your APP password.",
      "",
      "Click the link below to set a new password:",
      url,
      "",
      "This link will expire in 15 minutes.",
      "If you didn’t request a password reset, you can safely ignore this email.",
    ].join("\n"),
  });
}
