import type { PrismaClient } from "@prisma/client";

type StaffLookup = Pick<PrismaClient, "staffUser">;

export function authorizeTelegramActor(db: StaffLookup, telegramUserId: string | number) {
  return db.staffUser.findFirst({
    where: { telegramUserId: String(telegramUserId), isActive: true },
    select: { id: true, username: true, displayName: true, role: true, telegramUserId: true },
  });
}
