const { fullWeekDays } = require('./dateUtils');

const MAX_CLASSES_PER_DAY = 7;

function clampNumber(value, fallback) {
  const n = Number(value);
  if (Number.isNaN(n)) return fallback;
  return n;
}

function parseWeekSet(input, maxWeeks) {
  if (!input) return [];
  const limit = clampNumber(maxWeeks, 0);
  const raw = Array.isArray(input) ? input.join(',') : String(input);
  const weeks = new Set();
  raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
    .forEach((part) => {
      if (part.includes('-')) {
        const [startRaw, endRaw] = part.split('-').map((p) => p.trim());
        const start = clampNumber(startRaw, null);
        const end = clampNumber(endRaw, null);
        if (!start || !end) return;
        const from = Math.max(1, Math.min(start, end));
        const to = Math.max(start, end);
        for (let i = from; i <= to; i += 1) {
          if (limit && i > limit) break;
          weeks.add(i);
        }
      } else {
        const week = clampNumber(part, null);
        if (!week) return;
        if (limit && (week < 1 || week > limit)) return;
        weeks.add(week);
      }
    });
  return Array.from(weeks).sort((a, b) => a - b);
}

function buildEvenPriority(weeks, count) {
  const list = [...weeks].sort((a, b) => a - b);
  if (list.length <= 1) return list;
  const capped = Math.max(1, Math.min(count, list.length));
  if (capped === 1) {
    const mid = Math.floor((list.length - 1) / 2);
    const head = list[mid];
    return [head, ...list.filter((_, idx) => idx !== mid)];
  }
  const maxIdx = list.length - 1;
  const targets = [];
  for (let i = 0; i < capped; i += 1) {
    targets.push(Math.round((maxIdx * i) / (capped - 1)));
  }
  const scored = list.map((week, idx) => {
    const dist = targets.reduce((min, target) => Math.min(min, Math.abs(target - idx)), Infinity);
    return { week, idx, dist };
  });
  scored.sort((a, b) => a.dist - b.dist || a.idx - b.idx);
  return scored.map((row) => row.week);
}

function pickWeeks(weeks, targetCount, mode, canUseWeek) {
  if (!weeks.length || targetCount <= 0) return [];
  let ordered = [];
  const asc = [...weeks].sort((a, b) => a - b);
  if (mode === 'end') {
    ordered = [...asc].reverse();
  } else if (mode === 'even') {
    ordered = buildEvenPriority(asc, targetCount);
  } else {
    ordered = asc;
  }
  const picked = [];
  for (const week of ordered) {
    if (picked.length >= targetCount) break;
    if (canUseWeek(week)) {
      picked.push(week);
    }
  }
  return picked;
}

function normalizeDay(day) {
  if (!day) return null;
  const match = fullWeekDays.find((name) => name.toLowerCase() === String(day).toLowerCase());
  return match || null;
}

function getLessonDistribution(lessonType, config) {
  const type = String(lessonType || '').toLowerCase();
  if (type.includes('сем') || type.includes('seminar')) {
    return config.seminar_distribution || config.distribution || 'even';
  }
  return config.distribution || 'even';
}

function generateSchedule({
  items,
  courseContexts,
  teacherLimits,
  config,
}) {
  const results = [];
  const conflicts = [];
  const maxDailyPairs = clampNumber(config.max_daily_pairs, MAX_CLASSES_PER_DAY);
  const targetDailyPairs = clampNumber(config.target_daily_pairs, 4);
  const preferCompactness = Boolean(config.prefer_compactness);
  const specialWeeksMode = config.special_weeks_mode === 'overlay' ? 'overlay' : 'block';
  const blockedWeeksRaw = config.blocked_weeks || '';
  const blockedWeeksCache = new Map();

  const groupSlot = new Map();
  const teacherSlot = new Map();
  const groupDailyCount = new Map();
  const teacherWeeklyCount = new Map();
  const groupDayLoad = new Map();
  const groupDaySlots = new Map();

  const sortedItems = [...items].sort((a, b) => {
    const fixedA = a.fixed_day || a.fixed_class_number || a.weeks_set ? 1 : 0;
    const fixedB = b.fixed_day || b.fixed_class_number || b.weeks_set ? 1 : 0;
    if (fixedA !== fixedB) return fixedB - fixedA;
    const daysA = a.allowed_days ? a.allowed_days.length : 7;
    const daysB = b.allowed_days ? b.allowed_days.length : 7;
    if (daysA !== daysB) return daysA - daysB;
    return (b.pairs_count || 0) - (a.pairs_count || 0);
  });

  const getBlockedWeeks = (weeksCount) => {
    if (specialWeeksMode !== 'block') return [];
    if (blockedWeeksCache.has(weeksCount)) return blockedWeeksCache.get(weeksCount);
    const parsed = parseWeekSet(blockedWeeksRaw, weeksCount);
    blockedWeeksCache.set(weeksCount, parsed);
    return parsed;
  };

  const markGroupSlot = (courseId, groupNum, week, day, classNum) => {
    const key = `${courseId}|${groupNum}|${week}|${day}|${classNum}`;
    groupSlot.set(key, true);
  };
  const hasGroupSlot = (courseId, groupNum, week, day, classNum) =>
    groupSlot.has(`${courseId}|${groupNum}|${week}|${day}|${classNum}`);

  const markTeacherSlot = (teacherId, week, day, classNum) => {
    if (!teacherId) return;
    teacherSlot.set(`${teacherId}|${week}|${day}|${classNum}`, true);
  };
  const hasTeacherSlot = (teacherId, week, day, classNum) => {
    if (!teacherId) return false;
    return teacherSlot.has(`${teacherId}|${week}|${day}|${classNum}`);
  };

  const incGroupDaily = (courseId, groupNum, week, day) => {
    const key = `${courseId}|${groupNum}|${week}|${day}`;
    const next = (groupDailyCount.get(key) || 0) + 1;
    groupDailyCount.set(key, next);
  };
  const getGroupDaily = (courseId, groupNum, week, day) =>
    groupDailyCount.get(`${courseId}|${groupNum}|${week}|${day}`) || 0;

  const incTeacherWeekly = (teacherId, week) => {
    if (!teacherId) return;
    const key = `${teacherId}|${week}`;
    const next = (teacherWeeklyCount.get(key) || 0) + 1;
    teacherWeeklyCount.set(key, next);
  };
  const getTeacherWeekly = (teacherId, week) => {
    if (!teacherId) return 0;
    return teacherWeeklyCount.get(`${teacherId}|${week}`) || 0;
  };

  const incGroupDayLoad = (courseId, groupNum, day, count) => {
    const key = `${courseId}|${groupNum}|${day}`;
    const next = (groupDayLoad.get(key) || 0) + count;
    groupDayLoad.set(key, next);
  };
  const getGroupDayLoad = (courseId, groupNum, day) => groupDayLoad.get(`${courseId}|${groupNum}|${day}`) || 0;

  const addGroupDaySlot = (courseId, groupNum, day, classNum) => {
    const key = `${courseId}|${groupNum}|${day}`;
    if (!groupDaySlots.has(key)) {
      groupDaySlots.set(key, new Set());
    }
    groupDaySlots.get(key).add(classNum);
  };
  const getGroupDaySlots = (courseId, groupNum, day) => groupDaySlots.get(`${courseId}|${groupNum}|${day}`) || new Set();

  const calcSlotPenalty = (courseId, groups, day, classNum) => {
    const penalties = groups.map((groupNum) => {
      const slots = getGroupDaySlots(courseId, groupNum, day);
      if (!slots.size) return 0;
      let min = Infinity;
      slots.forEach((slot) => {
        min = Math.min(min, Math.abs(slot - classNum));
      });
      return min === Infinity ? 0 : min;
    });
    if (!penalties.length) return 0;
    return Math.max(...penalties);
  };

  const calcDayLoadPenalty = (courseId, groups, day, weeksCount) => {
    const loads = groups.map((groupNum) => getGroupDayLoad(courseId, groupNum, day) / Math.max(1, weeksCount));
    if (!loads.length) return 0;
    const maxLoad = Math.max(...loads);
    return Math.abs(maxLoad - targetDailyPairs);
  };

  const getTeacherLimit = (teacherId) => {
    if (!teacherId) return null;
    return teacherLimits.get(String(teacherId)) || null;
  };

  for (const item of sortedItems) {
    const context = courseContexts.get(String(item.course_id));
    if (!context) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'missing_course_context',
      });
      continue;
    }
    const weeksCount = clampNumber(context.weeks_count, 0);
    if (!weeksCount) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'missing_weeks_count',
      });
      continue;
    }
    const allWeeks = Array.from({ length: weeksCount }, (_, idx) => idx + 1);
    const blockedWeeks = getBlockedWeeks(weeksCount);
    const blockedSet = new Set(blockedWeeks);
    const baseWeeks = specialWeeksMode === 'block'
      ? allWeeks.filter((week) => !blockedSet.has(week))
      : allWeeks;
    const fixedWeeks = parseWeekSet(item.weeks_set, weeksCount);
    const fixedSet = new Set(fixedWeeks);
    const availableWeeks = fixedWeeks.length
      ? baseWeeks.filter((week) => fixedSet.has(week))
      : baseWeeks;
    if (!availableWeeks.length) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'no_available_weeks',
      });
      continue;
    }

    const targetPairs = Math.max(1, clampNumber(item.pairs_count, 0));
    const groupCount = Math.max(1, clampNumber(item.group_count, 1));
    const groupList = item.group_number ? [Number(item.group_number)] : Array.from({ length: groupCount }, (_, i) => i + 1);

    const teacherLimit = getTeacherLimit(item.teacher_id);
    const teacherAllowedDays = teacherLimit && teacherLimit.allowed_days
      ? teacherLimit.allowed_days.map((d) => normalizeDay(d)).filter(Boolean)
      : [];
    const allowedDaySet = teacherAllowedDays.length ? new Set(teacherAllowedDays) : null;

    const activeDays = (context.active_days || []).map((d) => normalizeDay(d)).filter(Boolean);
    const baseDays = activeDays.length ? activeDays : fullWeekDays.slice(0, 5);
    const fixedDay = normalizeDay(item.fixed_day);
    let candidateDays = [];
    if (fixedDay) {
      if (allowedDaySet && !allowedDaySet.has(fixedDay)) {
        candidateDays = [];
      } else {
        candidateDays = [fixedDay];
      }
    } else {
      candidateDays = baseDays.filter((day) => !allowedDaySet || allowedDaySet.has(day));
    }
    if (!candidateDays.length) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'no_allowed_days',
      });
      continue;
    }
    const fixedClass = clampNumber(item.fixed_class_number, null);
    const maxClass = Math.max(1, Math.min(MAX_CLASSES_PER_DAY, maxDailyPairs));
    const candidateClasses = fixedClass ? [fixedClass] : Array.from({ length: maxClass }, (_, idx) => idx + 1);

    const distribution = getLessonDistribution(item.lesson_type, config);

    const slotCandidates = [];
    candidateDays.forEach((day) => {
      candidateClasses.forEach((classNum) => {
        const dayPenalty = calcDayLoadPenalty(item.course_id, groupList, day, weeksCount);
        const slotPenalty = calcSlotPenalty(item.course_id, groupList, day, classNum);
        const classPenalty = classNum * 0.05;
        const score = dayPenalty * 1.4 + (preferCompactness ? slotPenalty * 0.6 : slotPenalty * 0.25) + classPenalty;
        slotCandidates.push({ day, classNum, score });
      });
    });
    slotCandidates.sort((a, b) => a.score - b.score);

    let selectedSlot = null;
    let selectedWeeks = [];

    const canUseWeek = (week, day, classNum) => {
      if (item.teacher_id && hasTeacherSlot(item.teacher_id, week, day, classNum)) {
        return false;
      }
      for (const groupNum of groupList) {
        if (hasGroupSlot(item.course_id, groupNum, week, day, classNum)) {
          return false;
        }
        if (getGroupDaily(item.course_id, groupNum, week, day) >= maxDailyPairs) {
          return false;
        }
      }
      if (item.teacher_id && teacherLimit && Number.isFinite(teacherLimit.max_pairs_per_week)) {
        if (getTeacherWeekly(item.teacher_id, week) >= teacherLimit.max_pairs_per_week) {
          return false;
        }
      }
      return true;
    };

    for (const slot of slotCandidates) {
      const tryWeeks = pickWeeks(availableWeeks, targetPairs, distribution, (week) =>
        canUseWeek(week, slot.day, slot.classNum)
      );
      if (!tryWeeks.length) continue;
      selectedSlot = slot;
      selectedWeeks = tryWeeks;
      if (selectedWeeks.length >= Math.min(targetPairs, availableWeeks.length)) break;
    }

    if (!selectedSlot || !selectedWeeks.length) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'no_slot_found',
      });
      continue;
    }

    selectedWeeks.forEach((week) => {
      markTeacherSlot(item.teacher_id, week, selectedSlot.day, selectedSlot.classNum);
      incTeacherWeekly(item.teacher_id, week);
      for (const groupNum of groupList) {
        markGroupSlot(item.course_id, groupNum, week, selectedSlot.day, selectedSlot.classNum);
        incGroupDaily(item.course_id, groupNum, week, selectedSlot.day);
        incGroupDayLoad(item.course_id, groupNum, selectedSlot.day, 1);
        addGroupDaySlot(item.course_id, groupNum, selectedSlot.day, selectedSlot.classNum);
        results.push({
          course_id: item.course_id,
          semester_id: item.semester_id,
          subject_id: item.subject_id,
          teacher_id: item.teacher_id,
          lesson_type: item.lesson_type,
          group_number: groupNum,
          day_of_week: selectedSlot.day,
          class_number: selectedSlot.classNum,
          week_number: week,
        });
      }
    });

    if (selectedWeeks.length < targetPairs) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'partial_schedule',
        scheduled: selectedWeeks.length,
        target: targetPairs,
      });
    }
  }

  return {
    entries: results,
    conflicts,
  };
}

module.exports = {
  parseWeekSet,
  generateSchedule,
};
