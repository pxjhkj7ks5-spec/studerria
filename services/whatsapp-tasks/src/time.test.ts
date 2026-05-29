import assert from "node:assert/strict";
import test from "node:test";
import { buildReminderSchedule, kyivDateKey, kyivWallTimeToUtc, shiftDateKey } from "./time.js";

test("converts Kyiv wall time to UTC across daylight saving time", () => {
  assert.equal(kyivWallTimeToUtc("2026-01-15", 9, 0).toISOString(), "2026-01-15T07:00:00.000Z");
  assert.equal(kyivWallTimeToUtc("2026-06-15", 9, 0).toISOString(), "2026-06-15T06:00:00.000Z");
});

test("builds default D-1, due day, and overdue reminder schedule", () => {
  const schedule = buildReminderSchedule({
    dueDateKey: "2026-06-20",
    dueTime: null,
    now: new Date("2026-06-18T10:00:00.000Z"),
  });
  assert.equal(schedule.dayBeforeAt?.toISOString(), "2026-06-19T06:00:00.000Z");
  assert.equal(schedule.dueDayAt?.toISOString(), "2026-06-20T06:00:00.000Z");
  assert.equal(schedule.overdueAt.toISOString(), "2026-06-20T20:59:00.000Z");
});

test("uses three-hour due-day reminder when task has due time", () => {
  const schedule = buildReminderSchedule({
    dueDateKey: "2026-06-20",
    dueTime: "14:30",
    now: new Date("2026-06-18T10:00:00.000Z"),
  });
  assert.equal(schedule.dueDayAt?.toISOString(), "2026-06-20T08:30:00.000Z");
  assert.equal(schedule.overdueAt.toISOString(), "2026-06-20T11:30:00.000Z");
});

test("date key helpers stay in Kyiv calendar", () => {
  assert.equal(kyivDateKey(new Date("2026-06-20T21:30:00.000Z")), "2026-06-21");
  assert.equal(shiftDateKey("2026-03-01", -1), "2026-02-28");
});
