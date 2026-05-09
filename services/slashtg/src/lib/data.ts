import { AnimationType, type Profile } from "@prisma/client";
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

export function formatSlashDate(value?: Date | string | null) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return "сьогодні";
  try {
    return new Intl.DateTimeFormat("uk-UA", {
      day: "numeric",
      month: "long",
    }).format(date);
  } catch {
    return "сьогодні";
  }
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
  };
}

export async function saveMessage(keyName: SlashUserKey, textRaw: unknown, animationRaw: unknown) {
  await ensureSlashProfiles();
  const targetKey = getOtherUserKey(keyName);
  const animationType = normalizeAnimationType(animationRaw);

  await prisma.profile.update({
    where: { keyName: targetKey },
    data: {
      messageForMe: normalizeMessage(textRaw),
      animationType: prismaAnimationByUi[animationType] as AnimationType,
      updatedBy: keyName,
    },
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
