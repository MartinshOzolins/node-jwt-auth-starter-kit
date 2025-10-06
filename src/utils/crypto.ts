import bcrypt from "bcrypt";
import { createHash } from "crypto";
import { v4 as uuidv4 } from "uuid";
import "dotenv/config";

const saltRounds = process.env.SALT_ROUNDS || 13;

export const createSha256Hash = (s: string) =>
  createHash("sha256").update(s).digest("hex");

/**
 * Hashes user password.
 */
export async function hashPassword(password: string): Promise<string> {
  const hashed = await bcrypt.hash(password, Number(saltRounds));
  return hashed;
}

/**
 * Verifies user's password.
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

/**
 * Generate a random UUID (v4).
 */
export function createNewUUID(): string {
  return uuidv4();
}
