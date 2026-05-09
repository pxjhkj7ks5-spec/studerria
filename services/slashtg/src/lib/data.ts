import { AnimationType, type Profile, type Wish } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import {
  findAllowedUserByTelegramId,
  getAllowedUsers,
  getOtherUserKey,
  normalizeAnimationType,
  normalizeAvatarUrl,
  normalizeMessage,
  prismaAnimationByUi,
  type SlashUserKey,
} from "@/lib/config";
import type { TelegramUser } from "@/lib/telegram-auth";

const SLASH_TIME_ZONE = "Europe/Kyiv";
const KYIV_DATE_PARTS_FORMATTER = new Intl.DateTimeFormat("en-CA", {
  timeZone: SLASH_TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});

function serializeProfile(profile: Profile) {
  return {
    displayName: profile.displayName,
    avatarUrl: profile.customAvatarUrl || profile.telegramPhotoUrl || "",
    telegramUsername: profile.telegramUsername || "",
  };
}

function serializeReceived(profile: Profile) {
  return {
    text: profile.messageForMe || "",
    animationType: normalizeAnimationType(profile.animationType.replace(/_/g, "-")),
    updatedAt: profile.updatedAt.toISOString(),
    updatedAtLabel: formatSlashDate(profile.updatedAt),
  };
}

function serializeWish(wish: Wish) {
  return {
    id: wish.id,
    text: wish.text,
    animationType: normalizeAnimationType(wish.animationType.replace(/_/g, "-")),
    createdAt: wish.createdAt.toISOString(),
    createdAtLabel: formatSlashDate(wish.createdAt),
  };
}

export function formatSlashDate(value?: Date | string | null) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return "сьогодні";
  try {
    return new Intl.DateTimeFormat("uk-UA", {
      timeZone: SLASH_TIME_ZONE,
      day: "numeric",
      month: "long",
    }).format(date);
  } catch {
    return "сьогодні";
  }
}

function getKyivDateKey(value?: Date | string | null) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return "";
  const parts = KYIV_DATE_PARTS_FORMATTER.formatToParts(date);
  const byType = new Map(parts.map((part) => [part.type, part.value]));
  const year = byType.get("year");
  const month = byType.get("month");
  const day = byType.get("day");
  return year && month && day ? `${year}-${month}-${day}` : "";
}

function shiftKyivDateKey(dateKey: string, days: number) {
  const [year, month, day] = dateKey.split("-").map((part) => Number.parseInt(part, 10));
  if (!year || !month || !day) return "";
  return getKyivDateKey(new Date(Date.UTC(year, month - 1, day + days, 12)));
}

function buildExchangeStreak(
  wishes: Pick<Wish, "senderKey" | "targetKey" | "createdAt">[],
  firstKey: string,
  secondKey: string,
) {
  const firstToSecondDays = new Set<string>();
  const secondToFirstDays = new Set<string>();

  for (const wish of wishes) {
    const dateKey = getKyivDateKey(wish.createdAt);
    if (!dateKey) continue;
    if (wish.senderKey === firstKey && wish.targetKey === secondKey) {
      firstToSecondDays.add(dateKey);
    }
    if (wish.senderKey === secondKey && wish.targetKey === firstKey) {
      secondToFirstDays.add(dateKey);
    }
  }

  const hasExchange = (dateKey: string) => firstToSecondDays.has(dateKey) && secondToFirstDays.has(dateKey);
  const todayKey = getKyivDateKey();
  const todayComplete = hasExchange(todayKey);
  let cursor = todayComplete ? todayKey : shiftKyivDateKey(todayKey, -1);
  let days = 0;

  while (cursor && hasExchange(cursor)) {
    days += 1;
    cursor = shiftKyivDateKey(cursor, -1);
  }

  return {
    days,
    todayComplete,
    timeZone: SLASH_TIME_ZONE,
  };
}

export async function ensureSlashProfiles() {
  const allowedUsers = getAllowedUsers();

  await Promise.all(
    allowedUsers.map((user) =>
      prisma.profile.upsert({
        where: { keyName: user.keyName },
        create: {
          keyName: user.keyName,
          telegramId: user.telegramId,
          displayName: user.label,
        },
        update: {
          telegramId: user.telegramId,
          displayName: user.label,
        },
      }),
    ),
  );
}

export async function syncTelegramProfile(telegramUser: TelegramUser) {
  const telegramId = String(telegramUser.id || "").trim();
  const allowed = findAllowedUserByTelegramId(telegramId);
  if (!allowed) {
    throw new Error("telegram_user_not_allowed");
  }

  await ensureSlashProfiles();
  return prisma.profile.update({
    where: { keyName: allowed.keyName },
    data: {
      telegramId,
      telegramFirstName: String(telegramUser.first_name || ""),
      telegramLastName: String(telegramUser.last_name || ""),
      telegramUsername: String(telegramUser.username || ""),
      telegramPhotoUrl: String(telegramUser.photo_url || ""),
    },
  });
}

export async function buildState(keyName: SlashUserKey) {
  await ensureSlashProfiles();
  const profiles = await prisma.profile.findMany({
    where: {
      keyName: {
        in: ["userA", "userB"],
      },
    },
  });
  const byKey = new Map(profiles.map((profile) => [profile.keyName, profile]));
  const current = byKey.get(keyName);
  const other = byKey.get(getOtherUserKey(keyName));
  if (!current || !other) {
    throw new Error("profiles_unavailable");
  }

  const [sentWishes, receivedWishes, streakWishes] = await Promise.all([
    prisma.wish.findMany({
      where: {
        senderKey: keyName,
        targetKey: other.keyName,
      },
      orderBy: {
        createdAt: "desc",
      },
      take: 12,
    }),
    prisma.wish.findMany({
      where: {
        senderKey: other.keyName,
        targetKey: keyName,
      },
      orderBy: {
        createdAt: "desc",
      },
      take: 12,
    }),
    prisma.wish.findMany({
      where: {
        OR: [
          {
            senderKey: keyName,
            targetKey: other.keyName,
          },
          {
            senderKey: other.keyName,
            targetKey: keyName,
          },
        ],
      },
      orderBy: {
        createdAt: "desc",
      },
      select: {
        senderKey: true,
        targetKey: true,
        createdAt: true,
      },
      take: 1000,
    }),
  ]);

  return {
    ok: true,
    authenticated: true,
    currentUser: serializeProfile(current),
    otherUser: serializeProfile(other),
    receivedMessage: serializeReceived(current),
    draftForOther: {
      text: other.messageForMe || "",
      animationType: normalizeAnimationType(other.animationType.replace(/_/g, "-")),
    },
    history: {
      sent: sentWishes.map(serializeWish),
      received: receivedWishes.map(serializeWish),
    },
    exchangeStreak: buildExchangeStreak(streakWishes, keyName, other.keyName),
  };
}

export async function saveMessage(keyName: SlashUserKey, textRaw: unknown, animationRaw: unknown) {
  await ensureSlashProfiles();
  const targetKey = getOtherUserKey(keyName);
  const animationType = normalizeAnimationType(animationRaw);

  const text = normalizeMessage(textRaw);

  await prisma.$transaction(async (tx) => {
    await tx.profile.update({
      where: { keyName: targetKey },
      data: {
        messageForMe: text,
        animationType: prismaAnimationByUi[animationType] as AnimationType,
        updatedBy: keyName,
      },
    });

    if (text) {
      await tx.wish.create({
        data: {
          senderKey: keyName,
          targetKey,
          text,
          animationType: prismaAnimationByUi[animationType] as AnimationType,
        },
      });
    }
  });

  return buildState(keyName);
}

export async function saveAvatar(keyName: SlashUserKey, avatarRaw: unknown) {
  await ensureSlashProfiles();
  await prisma.profile.update({
    where: { keyName },
    data: {
      customAvatarUrl: normalizeAvatarUrl(avatarRaw),
    },
  });

  return buildState(keyName);
}
