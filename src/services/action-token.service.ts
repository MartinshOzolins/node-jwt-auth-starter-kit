import { prisma } from "../utils/prisma.js";
import { createNewUUID, createSha256Hash } from "../utils/crypto.js";

export async function createActionToken(
  kind: "EMAIL_VERIFICATION" | "PASSWORD_RESET" | "PASSWORD_RESET_CONFIRM",
  userId: string,
  expiration_in_ms: number
) {
  const raw = createNewUUID();
  await prisma.actionToken.create({
    data: {
      userId,
      kind,
      tokenHash: createSha256Hash(raw),
      expiresAt: new Date(Date.now() + expiration_in_ms),
    },
  });
  return raw;
}

export async function findActionToken(
  kind: "EMAIL_VERIFICATION" | "PASSWORD_RESET" | "PASSWORD_RESET_CONFIRM",
  raw: string
) {
  const row = await prisma.actionToken.findFirst({
    where: {
      kind,
      tokenHash: createSha256Hash(raw),
      usedAt: null,
      expiresAt: { gt: new Date() },
    },
  });

  return row; // caller decides how to update
}
