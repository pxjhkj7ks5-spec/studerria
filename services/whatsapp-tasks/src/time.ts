export const WA_TASKS_TIME_ZONE = "Europe/Kyiv";

const datePartsFormatter = new Intl.DateTimeFormat("en-CA", {
  timeZone: WA_TASKS_TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

function partsInKyiv(date: Date) {
  const parts = datePartsFormatter.formatToParts(date);
  const byType = new Map(parts.map((part) => [part.type, part.value]));
  return {
    year: Number(byType.get("year")),
    month: Number(byType.get("month")),
    day: Number(byType.get("day")),
    hour: Number(byType.get("hour")),
    minute: Number(byType.get("minute")),
    second: Number(byType.get("second")),
  };
}

export function kyivDateKey(date: Date) {
  const parts = partsInKyiv(date);
  return `${parts.year}-${String(parts.month).padStart(2, "0")}-${String(parts.day).padStart(2, "0")}`;
}

export function kyivWallTimeToUtc(dateKey: string, hour: number, minute = 0) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateKey);
  if (!match) throw new Error("invalid_date_key");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const guess = new Date(Date.UTC(year, month - 1, day, hour, minute, 0));
  const actual = partsInKyiv(guess);
  const wantedAsUtc = Date.UTC(year, month - 1, day, hour, minute, 0);
  const actualAsUtc = Date.UTC(actual.year, actual.month - 1, actual.day, actual.hour, actual.minute, actual.second);
  return new Date(guess.getTime() - (actualAsUtc - wantedAsUtc));
}

export function shiftDateKey(dateKey: string, days: number) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateKey);
  if (!match) throw new Error("invalid_date_key");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  return kyivDateKey(new Date(Date.UTC(year, month - 1, day + days, 12, 0, 0)));
}

export type ReminderSchedule = {
  assignedAt: Date;
  dayBeforeAt: Date | null;
  dueDayAt: Date | null;
  overdueAt: Date;
};

export function buildReminderSchedule(input: {
  dueDateKey: string;
  dueTime?: string | null;
  now?: Date;
}): ReminderSchedule {
  const now = input.now ?? new Date();
  const dueHasTime = Boolean(input.dueTime);
  let dueAt: Date;
  if (input.dueTime) {
    const [hour, minute] = input.dueTime.split(":").map((part) => Number.parseInt(part, 10));
    dueAt = kyivWallTimeToUtc(input.dueDateKey, hour, minute);
  } else {
    dueAt = kyivWallTimeToUtc(input.dueDateKey, 23, 59);
  }

  const dayBefore = kyivWallTimeToUtc(shiftDateKey(input.dueDateKey, -1), 9, 0);
  const dueDay = dueHasTime ? new Date(dueAt.getTime() - 3 * 60 * 60 * 1000) : kyivWallTimeToUtc(input.dueDateKey, 9, 0);

  return {
    assignedAt: now,
    dayBeforeAt: dayBefore > now ? dayBefore : null,
    dueDayAt: dueDay > now ? dueDay : null,
    overdueAt: dueAt,
  };
}

export function formatKyivDateTime(value: Date | string | null | undefined) {
  if (!value) return "";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("uk-UA", {
    timeZone: WA_TASKS_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}
