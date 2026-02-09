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

function buildMirrorPairs(items, enabled) {
  if (!enabled) return { pairs: [], remaining: items };
  const eligible = items.filter((item) =>
    Number(item.group_number) === 1 || Number(item.group_number) === 2
  ).filter((item) =>
    !item.fixed_day && !item.fixed_class_number && !item.weeks_set
  );
  const buckets = new Map();
  eligible.forEach((item) => {
    const lessonType = String(item.lesson_type || '');
    const count = Number(item.pairs_count || 0);
    if (!count) return;
    const key = `${item.course_id}|${lessonType}|${count}`;
    if (!buckets.has(key)) {
      buckets.set(key, { group1: [], group2: [] });
    }
    const bucket = buckets.get(key);
    if (Number(item.group_number) === 1) {
      bucket.group1.push(item);
    } else if (Number(item.group_number) === 2) {
      bucket.group2.push(item);
    }
  });

  const pairedIds = new Set();
  const pairs = [];
  buckets.forEach((bucket) => {
    bucket.group1.sort((a, b) => String(a.subject_name || '').localeCompare(String(b.subject_name || '')));
    bucket.group2.sort((a, b) => String(a.subject_name || '').localeCompare(String(b.subject_name || '')));
    const length = Math.min(bucket.group1.length, bucket.group2.length);
    for (let i = 0; i < length; i += 1) {
      const a = bucket.group1[i];
      const b = bucket.group2[i];
      if (!a || !b) continue;
      pairedIds.add(a.id);
      pairedIds.add(b.id);
      pairs.push({ a, b });
    }
  });

  const remaining = items.filter((item) => !pairedIds.has(item.id));
  return { pairs, remaining };
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

  const mirrorPairsResult = buildMirrorPairs(items, Boolean(config.mirror_groups));
  const mirrorPairs = mirrorPairsResult.pairs;
  const sortedItems = [...mirrorPairsResult.remaining].sort((a, b) => {
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

  const orderWeeks = (weeks, mode) => {
    const asc = [...weeks].sort((a, b) => a - b);
    if (mode === 'end') return asc.reverse();
    if (mode === 'even') return buildEvenPriority(asc, asc.length);
    return asc;
  };

  const scheduleMirrorPair = (pair) => {
    const itemA = pair.a;
    const itemB = pair.b;
    const context = courseContexts.get(String(itemA.course_id));
    if (!context) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'missing_course_context',
      });
      return;
    }
    const weeksCount = clampNumber(context.weeks_count, 0);
    if (!weeksCount) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'missing_weeks_count',
      });
      return;
    }
    const allWeeks = Array.from({ length: weeksCount }, (_, idx) => idx + 1);
    const blockedWeeks = getBlockedWeeks(weeksCount);
    const blockedSet = new Set(blockedWeeks);
    const baseWeeks = specialWeeksMode === 'block'
      ? allWeeks.filter((week) => !blockedSet.has(week))
      : allWeeks;
    if (baseWeeks.length < 2) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'no_available_weeks',
      });
      return;
    }
    const pairsCount = Math.min(Number(itemA.pairs_count || 0), Number(itemB.pairs_count || 0));
    const mirrorCount = Math.min(pairsCount, Math.floor(baseWeeks.length / 2));
    if (!mirrorCount) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'no_available_weeks',
      });
      return;
    }

    const groupList = [1, 2];
    const limitA = getTeacherLimit(itemA.teacher_id);
    const limitB = getTeacherLimit(itemB.teacher_id);
    const allowedA = limitA && limitA.allowed_days ? limitA.allowed_days.map((d) => normalizeDay(d)).filter(Boolean) : [];
    const allowedB = limitB && limitB.allowed_days ? limitB.allowed_days.map((d) => normalizeDay(d)).filter(Boolean) : [];
    const baseDays = (context.active_days || []).map((d) => normalizeDay(d)).filter(Boolean);
    const fallbackDays = baseDays.length ? baseDays : fullWeekDays.slice(0, 5);
    let candidateDays = fallbackDays;
    if (allowedA.length) {
      const allowedSet = new Set(allowedA);
      candidateDays = candidateDays.filter((day) => allowedSet.has(day));
    }
    if (allowedB.length) {
      const allowedSet = new Set(allowedB);
      candidateDays = candidateDays.filter((day) => allowedSet.has(day));
    }
    if (!candidateDays.length) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'no_allowed_days',
      });
      return;
    }

    const maxClass = Math.max(1, Math.min(MAX_CLASSES_PER_DAY, maxDailyPairs));
    const candidateClasses = Array.from({ length: maxClass }, (_, idx) => idx + 1);
    const distribution = getLessonDistribution(itemA.lesson_type || itemB.lesson_type, config);

    const slotCandidates = [];
    candidateDays.forEach((day) => {
      candidateClasses.forEach((classNum) => {
        const dayPenalty = calcDayLoadPenalty(itemA.course_id, groupList, day, weeksCount);
        const slotPenalty = calcSlotPenalty(itemA.course_id, groupList, day, classNum);
        const classPenalty = classNum * 0.05;
        const score = dayPenalty * 1.4 + (preferCompactness ? slotPenalty * 0.6 : slotPenalty * 0.25) + classPenalty;
        slotCandidates.push({ day, classNum, score });
      });
    });
    slotCandidates.sort((a, b) => a.score - b.score);

    const trySlot = (slot) => {
      const weekOrder = orderWeeks(baseWeeks, distribution);
      const localGroupSlot = new Set();
      const localTeacherSlot = new Set();
      const localGroupDaily = new Map();
      const localTeacherWeekly = new Map();
      const weeksA = [];
      const weeksB = [];

      const keyGroupSlot = (groupNum, week) => `${itemA.course_id}|${groupNum}|${week}|${slot.day}|${slot.classNum}`;
      const keyTeacherSlot = (teacherId, week) => `${teacherId}|${week}|${slot.day}|${slot.classNum}`;
      const keyGroupDaily = (groupNum, week) => `${itemA.course_id}|${groupNum}|${week}|${slot.day}`;
      const keyTeacherWeekly = (teacherId, week) => `${teacherId}|${week}`;

      const getLocalGroupDaily = (groupNum, week) => localGroupDaily.get(keyGroupDaily(groupNum, week)) || 0;
      const getLocalTeacherWeekly = (teacherId, week) => localTeacherWeekly.get(keyTeacherWeekly(teacherId, week)) || 0;

      const canUse = (item, groupNum, week, limit) => {
        if (hasGroupSlot(item.course_id, groupNum, week, slot.day, slot.classNum) || localGroupSlot.has(keyGroupSlot(groupNum, week))) {
          return false;
        }
        if (getGroupDaily(item.course_id, groupNum, week, slot.day) + getLocalGroupDaily(groupNum, week) >= maxDailyPairs) {
          return false;
        }
        if (item.teacher_id) {
          if (hasTeacherSlot(item.teacher_id, week, slot.day, slot.classNum) || localTeacherSlot.has(keyTeacherSlot(item.teacher_id, week))) {
            return false;
          }
          if (limit && Number.isFinite(limit.max_pairs_per_week)) {
            if (getTeacherWeekly(item.teacher_id, week) + getLocalTeacherWeekly(item.teacher_id, week) >= limit.max_pairs_per_week) {
              return false;
            }
          }
        }
        return true;
      };

      const markLocal = (item, groupNum, week) => {
        localGroupSlot.add(keyGroupSlot(groupNum, week));
        localGroupDaily.set(keyGroupDaily(groupNum, week), getLocalGroupDaily(groupNum, week) + 1);
        if (item.teacher_id) {
          localTeacherSlot.add(keyTeacherSlot(item.teacher_id, week));
          localTeacherWeekly.set(keyTeacherWeekly(item.teacher_id, week), getLocalTeacherWeekly(item.teacher_id, week) + 1);
        }
      };

      let turn = 0;
      for (const week of weekOrder) {
        if (weeksA.length >= mirrorCount && weeksB.length >= mirrorCount) break;
        const primary = turn % 2 === 0 ? itemA : itemB;
        const secondary = primary === itemA ? itemB : itemA;
        const primaryGroup = primary === itemA ? 1 : 2;
        const secondaryGroup = secondary === itemA ? 1 : 2;
        const primaryLimit = primary === itemA ? limitA : limitB;
        const secondaryLimit = secondary === itemA ? limitA : limitB;

        if (primary === itemA && weeksA.length < mirrorCount && canUse(primary, primaryGroup, week, primaryLimit)) {
          weeksA.push(week);
          markLocal(primary, primaryGroup, week);
          turn += 1;
          continue;
        }
        if (primary === itemB && weeksB.length < mirrorCount && canUse(primary, primaryGroup, week, primaryLimit)) {
          weeksB.push(week);
          markLocal(primary, primaryGroup, week);
          turn += 1;
          continue;
        }
        if (secondary === itemA && weeksA.length < mirrorCount && canUse(secondary, secondaryGroup, week, secondaryLimit)) {
          weeksA.push(week);
          markLocal(secondary, secondaryGroup, week);
          turn += 1;
          continue;
        }
        if (secondary === itemB && weeksB.length < mirrorCount && canUse(secondary, secondaryGroup, week, secondaryLimit)) {
          weeksB.push(week);
          markLocal(secondary, secondaryGroup, week);
          turn += 1;
        }
      }

      return { weeksA, weeksB };
    };

    let bestSlot = null;
    let bestWeeksA = [];
    let bestWeeksB = [];
    slotCandidates.forEach((slot) => {
      if (bestWeeksA.length >= mirrorCount && bestWeeksB.length >= mirrorCount) return;
      const attempt = trySlot(slot);
      const total = attempt.weeksA.length + attempt.weeksB.length;
      const bestTotal = bestWeeksA.length + bestWeeksB.length;
      if (total > bestTotal) {
        bestSlot = slot;
        bestWeeksA = attempt.weeksA;
        bestWeeksB = attempt.weeksB;
      }
      if (attempt.weeksA.length >= mirrorCount && attempt.weeksB.length >= mirrorCount) {
        bestSlot = slot;
        bestWeeksA = attempt.weeksA;
        bestWeeksB = attempt.weeksB;
      }
    });

    if (!bestSlot || (!bestWeeksA.length && !bestWeeksB.length)) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'no_slot_found',
      });
      return;
    }

    const applyEntry = (item, groupNum, week) => {
      markTeacherSlot(item.teacher_id, week, bestSlot.day, bestSlot.classNum);
      incTeacherWeekly(item.teacher_id, week);
      markGroupSlot(item.course_id, groupNum, week, bestSlot.day, bestSlot.classNum);
      incGroupDaily(item.course_id, groupNum, week, bestSlot.day);
      incGroupDayLoad(item.course_id, groupNum, bestSlot.day, 1);
      addGroupDaySlot(item.course_id, groupNum, bestSlot.day, bestSlot.classNum);
      results.push({
        course_id: item.course_id,
        semester_id: item.semester_id,
        subject_id: item.subject_id,
        teacher_id: item.teacher_id,
        lesson_type: item.lesson_type,
        group_number: groupNum,
        day_of_week: bestSlot.day,
        class_number: bestSlot.classNum,
        week_number: week,
      });
    };

    bestWeeksA.forEach((week) => applyEntry(itemA, 1, week));
    bestWeeksB.forEach((week) => applyEntry(itemB, 2, week));

    if (bestWeeksA.length < pairsCount || bestWeeksB.length < pairsCount) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'partial_schedule',
        scheduled: `${bestWeeksA.length}/${pairsCount} + ${bestWeeksB.length}/${pairsCount}`,
      });
    }
  };

  mirrorPairs.forEach((pair) => scheduleMirrorPair(pair));

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
