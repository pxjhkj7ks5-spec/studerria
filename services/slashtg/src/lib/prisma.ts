import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  slashTgPrisma?: PrismaClient;
};

export const prisma =
  globalForPrisma.slashTgPrisma ??
  new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["error", "warn"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.slashTgPrisma = prisma;
}
