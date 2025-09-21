import { prisma } from "../utils/prisma.js";

export type ActionTokenKind =
  | "EMAIL_VERIFICATION"
  | "PASSWORD_RESET"
  | "PASSWORD_RESET_CONFIRM";

export async function findUserByEmail(email: string) {
  return prisma.user.findUnique({ where: { email: email.toLowerCase() } });
}

export async function createUser(email: string, passwordHash: string) {
  return prisma.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash,
    },
    select: {
      id: true,
      email: true,
      emailVerified: true,
      tokenVersion: true,
    },
  });
}

export async function findUserById(id: string) {
  return prisma.user.findUnique({ where: { id } });
}

export async function bumpTokenVersion(userId: string) {
  return prisma.user.update({
    where: { id: userId },
    data: { tokenVersion: { increment: 1 } },
  });
}

export async function markEmailVerifiedAndBumpVersion(userId: string) {
  return prisma.user.update({
    where: { id: userId },
    data: { emailVerified: true, tokenVersion: { increment: 1 } },
  });
}
