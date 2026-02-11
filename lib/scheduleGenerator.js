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

function normalizeMirrorKey(input) {
  const raw = String(input || '').trim();
  return raw ? raw.toLowerCase() : '';
}

function formatMirrorKey(input) {
  const raw = String(input || '').trim();
  return raw || null;
}

function stableHash(input) {
  const raw = String(input || '');
  let hash = 0;
  for (let i = 0; i < raw.length; i += 1) {
    hash = ((hash << 5) - hash + raw.charCodeAt(i)) | 0;
  }
  return hash >>> 0;
}

function getSubjectDayKey(item) {
  if (!item) return '';
  const semId = item.semester_id || 0;
  return `${item.course_id}|${semId}|${item.subject_id}`;
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

function isLectureLesson(lessonType) {
  const type = String(lessonType || '').toLowerCase();
  return type.includes('лек') || type.includes('lecture');
}

function isSeminarLesson(lessonType) {
  const type = String(lessonType || '').toLowerCase();
  return type.includes('сем') || type.includes('seminar');
}

function isGeneralSeminar(item) {
  if (!item) return false;
  const generalFlag = item.is_general === true || Number(item.is_general) === 1;
  if (!generalFlag) return false;
  return isSeminarLesson(item.lesson_type);
}

function buildMirrorPairs(items, enabled) {
  if (!enabled) return { pairs: [], remaining: items };
  const eligible = items.filter((item) =>
    Number(item.group_number) === 1 || Number(item.group_number) === 2
  ).filter((item) =>
    !item.fixed_day && !item.fixed_class_number && !item.weeks_set && normalizeMirrorKey(item.mirror_key)
  );
  const buckets = new Map();
  eligible.forEach((item) => {
    const mirrorKey = normalizeMirrorKey(item.mirror_key);
    if (!mirrorKey) return;
    const lessonType = String(item.lesson_type || '');
    const count = Number(item.pairs_count || 0);
    if (!count) return;
    const key = `${item.course_id}|${item.semester_id || ''}|${mirrorKey}|${lessonType}|${count}`;
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
  const sortForMirror = (a, b) =>
    String(a.subject_name || '').localeCompare(String(b.subject_name || ''), 'uk')
    || Number(a.subject_id || 0) - Number(b.subject_id || 0)
    || Number(a.id) - Number(b.id);
  buckets.forEach((bucket) => {
    bucket.group1.sort(sortForMirror);
    bucket.group2.sort(sortForMirror);
    const usedGroup2 = new Set();
    bucket.group1.forEach((a) => {
      const idx = bucket.group2.findIndex((b, pos) =>
        !usedGroup2.has(pos) && Number(b.subject_id) !== Number(a.subject_id)
      );
      if (idx === -1) return;
      const b = bucket.group2[idx];
      usedGroup2.add(idx);
      pairedIds.add(a.id);
      pairedIds.add(b.id);
      pairs.push({ a, b });
    });
  });

  const remaining = items.filter((item) => !pairedIds.has(item.id));
  return { pairs, remaining };
}

function generateSchedule({
  items,
  courseContexts,
  teacherLimits,
  config,
  existingEntries = [],
}) {
  const results = [];
  const conflicts = [];
  const maxDailyPairs = clampNumber(config.max_daily_pairs, MAX_CLASSES_PER_DAY);
  const targetDailyPairs = clampNumber(config.target_daily_pairs, 4);
  const preferCompactness = Boolean(config.prefer_compactness);
  const evennessBiasRaw = clampNumber(config.evenness_bias, 50);
  const evennessBias = Math.max(0, Math.min(evennessBiasRaw, 100));
  const evennessWeight = 1 + (evennessBias / 100) * 0.8;
  const compactWeightBase = preferCompactness ? 0.6 : 0.25;
  const compactWeight = compactWeightBase * (1.25 - evennessBias / 200);
  const courseWeight = evennessWeight * 0.45;
  const subjectSingleDay = config.subject_single_day !== false;
  const lectureSeminarSameDay = config.lecture_seminar_same_day !== false;
  const autoSubjectDays = Boolean(config.auto_subject_days);
  const lateSlotWeightRaw = clampNumber(config.late_slot_weight, 60);
  const lateSlotWeight = Math.max(0, Math.min(lateSlotWeightRaw, 100));
  const avoidLateSlots = lateSlotWeight > 0;
  const lateSlotPenaltyScale = avoidLateSlots ? (lateSlotWeight / 100) * 0.6 : 0;
  const specialWeeksMode = config.special_weeks_mode === 'overlay' ? 'overlay' : 'block';
  const blockedWeeksRaw = config.blocked_weeks || '';
  const blockedWeeksCache = new Map();

  const expandedItems = items.flatMap((item) => {
    if (!isGeneralSeminar(item)) return [item];
    if (item.group_number) return [item];
    const groupCount = Math.max(1, clampNumber(item.group_count, 1));
    if (groupCount <= 1) return [item];
    return Array.from({ length: groupCount }, (_, idx) => ({
      ...item,
      group_number: idx + 1,
    }));
  });

  const subjectMeta = new Map();
  expandedItems.forEach((item) => {
    const key = getSubjectDayKey(item);
    if (!key) return;
    if (!subjectMeta.has(key)) {
      subjectMeta.set(key, {
        items: [],
        teacherIds: new Set(),
        hasLecture: false,
        hasMirror: false,
        fixedDay: null,
        allowedDays: null,
        courseId: item.course_id,
        semesterId: item.semester_id || 0,
      });
    }
    const meta = subjectMeta.get(key);
    meta.items.push(item);
    if (item.teacher_id) meta.teacherIds.add(item.teacher_id);
    if (isLectureLesson(item.lesson_type)) meta.hasLecture = true;
    if (item.mirror_key) meta.hasMirror = true;
    if (item.fixed_day && !meta.fixedDay) meta.fixedDay = normalizeDay(item.fixed_day);
    const limit = item.teacher_id ? teacherLimits.get(String(item.teacher_id)) : null;
    const allowed = limit && limit.allowed_days ? limit.allowed_days.map((d) => normalizeDay(d)).filter(Boolean) : [];
    if (allowed.length) {
      if (!meta.allowedDays) {
        meta.allowedDays = new Set(allowed);
      } else {
        meta.allowedDays = new Set(allowed.filter((day) => meta.allowedDays.has(day)));
      }
    }
  });

  const multiDaySubjects = new Set();
  subjectMeta.forEach((meta, key) => {
    if (meta.teacherIds.size > 1 && !meta.hasLecture) {
      multiDaySubjects.add(key);
    }
  });

  const shouldLockSubjectKey = (key, meta) => {
    if (!key || !meta) return false;
    if (lectureSeminarSameDay && meta.hasLecture) return true;
    if (!subjectSingleDay) return false;
    if (multiDaySubjects.has(key)) return false;
    return true;
  };
  const shouldLockSubjectDay = (item) => {
    const key = getSubjectDayKey(item);
    if (!key) return false;
    return shouldLockSubjectKey(key, subjectMeta.get(key));
  };

  const courseGroupCounts = new Map();
  expandedItems.forEach((item) => {
    const count = Math.max(1, clampNumber(item.group_count, 1));
    const key = String(item.course_id);
    const current = courseGroupCounts.get(key) || 1;
    courseGroupCounts.set(key, Math.max(current, count));
  });

  const groupSlot = new Map();
  const teacherSlot = new Map();
  const subjectSlot = new Map();
  const courseSlot = new Map();
  const courseLectureSlot = new Map();
  const subjectDayMap = new Map();
  const groupDailyCount = new Map();
  const teacherWeeklyCount = new Map();
  const groupDayLoad = new Map();
  const groupDaySlots = new Map();
  const courseDayLoad = new Map();

  const mirrorPairsResult = buildMirrorPairs(expandedItems, Boolean(config.mirror_groups));
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

  const markCourseSlot = (courseId, week, day, classNum) => {
    if (!courseId) return;
    courseSlot.set(`${courseId}|${week}|${day}|${classNum}`, true);
  };
  const hasCourseSlot = (courseId, week, day, classNum) =>
    courseSlot.has(`${courseId}|${week}|${day}|${classNum}`);

  const markCourseLectureSlot = (courseId, week, day, classNum) => {
    if (!courseId) return;
    courseLectureSlot.set(`${courseId}|${week}|${day}|${classNum}`, true);
  };
  const hasCourseLectureSlot = (courseId, week, day, classNum) =>
    courseLectureSlot.has(`${courseId}|${week}|${day}|${classNum}`);

  const lockSubjectDay = (item, day) => {
    if (!shouldLockSubjectDay(item)) return;
    const key = getSubjectDayKey(item);
    if (!key || !day) return;
    if (!subjectDayMap.has(key)) {
      subjectDayMap.set(key, day);
    }
  };
  const getLockedSubjectDay = (item) => {
    if (!shouldLockSubjectDay(item)) return null;
    const key = getSubjectDayKey(item);
    if (!key) return null;
    return subjectDayMap.get(key) || null;
  };

  if (autoSubjectDays) {
    const subjectDayLoad = new Map();
    subjectMeta.forEach((meta, key) => {
      if (!shouldLockSubjectKey(key, meta)) return;
      if (meta.hasMirror) return;
      const context = courseContexts.get(String(meta.courseId));
      if (!context) return;
      const baseDays = (context.active_days || []).map((d) => normalizeDay(d)).filter(Boolean);
      if (!baseDays.length) return;
      let candidateDays = baseDays;
      if (meta.allowedDays && meta.allowedDays.size) {
        candidateDays = candidateDays.filter((day) => meta.allowedDays.has(day));
      }
      if (meta.fixedDay) {
        candidateDays = candidateDays.filter((day) => day === meta.fixedDay);
      }
      if (!candidateDays.length) return;
      let chosen = candidateDays[0];
      const dayStats = candidateDays.map((day) => {
        const loadKey = `${meta.courseId}|${day}`;
        return {
          day,
          load: subjectDayLoad.get(loadKey) || 0,
        };
      });
      const minLoad = dayStats.reduce((min, row) => Math.min(min, row.load), Infinity);
      const leastLoaded = dayStats.filter((row) => row.load === minLoad);
      if (leastLoaded.length) {
        const idx = stableHash(key) % leastLoaded.length;
        chosen = leastLoaded[idx].day;
      }
      subjectDayMap.set(key, chosen);
      const loadKey = `${meta.courseId}|${chosen}`;
      subjectDayLoad.set(loadKey, (subjectDayLoad.get(loadKey) || 0) + 1);
    });
  }

  const markSubjectSlot = (subjectId, week, day, classNum) => {
    if (!subjectId) return;
    subjectSlot.set(`${subjectId}|${week}|${day}|${classNum}`, true);
  };
  const hasSubjectSlot = (subjectId, week, day, classNum) => {
    if (!subjectId) return false;
    return subjectSlot.has(`${subjectId}|${week}|${day}|${classNum}`);
  };

  const incGroupDaily = (courseId, groupNum, week, day) => {
    const key = `${courseId}|${groupNum}|${week}|${day}`;
    const next = (groupDailyCount.get(key) || 0) + 1;
    groupDailyCount.set(key, next);
  };
  const getGroupDaily = (courseId, groupNum, week, day) =>
    groupDailyCount.get(`${courseId}|${groupNum}|${week}|${day}`) || 0;

  const incCourseDayLoad = (courseId, day, count) => {
    const key = `${courseId}|${day}`;
    const next = (courseDayLoad.get(key) || 0) + count;
    courseDayLoad.set(key, next);
  };
  const getCourseDayLoad = (courseId, day) => courseDayLoad.get(`${courseId}|${day}`) || 0;

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

  const seedExistingEntries = () => {
    if (!Array.isArray(existingEntries) || !existingEntries.length) return;
    existingEntries.forEach((entry) => {
      const day = normalizeDay(entry.day_of_week);
      const classNum = clampNumber(entry.class_number, null);
      const week = clampNumber(entry.week_number, null);
      if (!day || !classNum || !week) return;
      if (entry.teacher_id) {
        markTeacherSlot(entry.teacher_id, week, day, classNum);
        incTeacherWeekly(entry.teacher_id, week);
      }
    });
  };

  seedExistingEntries();

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

  const calcLateSlotPenalty = (classNum) => {
    if (!lateSlotPenaltyScale) return 0;
    const late = Math.max(0, classNum - 4);
    if (!late) return 0;
    const weight = 0.2 + lateSlotPenaltyScale * 1.8;
    return late * late * weight;
  };

  const calcDayLoadPenalty = (courseId, groups, day, weeksCount) => {
    const loads = groups.map((groupNum) => getGroupDayLoad(courseId, groupNum, day) / Math.max(1, weeksCount));
    if (!loads.length) return 0;
    const maxLoad = Math.max(...loads);
    const overTarget = Math.max(0, maxLoad - targetDailyPairs);
    return maxLoad * 0.65 + overTarget * 1.4;
  };

  const calcCourseDayPenalty = (courseId, day, weeksCount) => {
    const load = getCourseDayLoad(courseId, day) / Math.max(1, weeksCount);
    const groupCount = courseGroupCounts.get(String(courseId)) || 1;
    const target = targetDailyPairs * groupCount;
    return Math.max(0, load - target);
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
    const lockedDayA = getLockedSubjectDay(itemA);
    const lockedDayB = getLockedSubjectDay(itemB);
    if (lockedDayA && lockedDayB && lockedDayA !== lockedDayB) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: 'subject_day_mismatch',
      });
      return;
    }
    const forcedDay = lockedDayA || lockedDayB || null;
    if (allowedA.length) {
      const allowedSet = new Set(allowedA);
      candidateDays = candidateDays.filter((day) => allowedSet.has(day));
    }
    if (allowedB.length) {
      const allowedSet = new Set(allowedB);
      candidateDays = candidateDays.filter((day) => allowedSet.has(day));
    }
    if (forcedDay) {
      candidateDays = candidateDays.filter((day) => day === forcedDay);
    }
    if (!candidateDays.length) {
      conflicts.push({
        item_id: `${itemA.id}|${itemB.id}`,
        subject: `${itemA.subject_name} ↔ ${itemB.subject_name}`,
        reason: forcedDay ? 'subject_day_mismatch' : 'no_allowed_days',
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
        const coursePenalty = calcCourseDayPenalty(itemA.course_id, day, weeksCount);
        const slotPenalty = calcSlotPenalty(itemA.course_id, groupList, day, classNum);
        const classPenalty = classNum * 0.05;
        const latePenalty = calcLateSlotPenalty(classNum);
        const jitter = (stableHash(`${itemA.id}|${itemB.id}|${day}|${classNum}`) % 997) / 10000;
        const score = dayPenalty * evennessWeight + coursePenalty * courseWeight + slotPenalty * compactWeight + classPenalty + latePenalty + jitter;
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
      const localCourseSlot = new Set();
      const localCourseLectureSlot = new Set();
      const localSubjectSlot = new Set();
      const weeksA = [];
      const weeksB = [];

      const keyGroupSlot = (groupNum, week) => `${itemA.course_id}|${groupNum}|${week}|${slot.day}|${slot.classNum}`;
      const keyTeacherSlot = (teacherId, week) => `${teacherId}|${week}|${slot.day}|${slot.classNum}`;
      const keyCourseSlot = (week) => `${itemA.course_id}|${week}|${slot.day}|${slot.classNum}`;
      const keyCourseLectureSlot = (week) => `${itemA.course_id}|${week}|${slot.day}|${slot.classNum}`;
      const keySubjectSlot = (subjectId, week) => `${subjectId}|${week}|${slot.day}|${slot.classNum}`;
      const keyGroupDaily = (groupNum, week) => `${itemA.course_id}|${groupNum}|${week}|${slot.day}`;
      const keyTeacherWeekly = (teacherId, week) => `${teacherId}|${week}`;

      const getLocalGroupDaily = (groupNum, week) => localGroupDaily.get(keyGroupDaily(groupNum, week)) || 0;
      const getLocalTeacherWeekly = (teacherId, week) => localTeacherWeekly.get(keyTeacherWeekly(teacherId, week)) || 0;

      const canUse = (item, groupNum, week, limit) => {
        const lecture = isLectureLesson(item.lesson_type);
        if (lecture) {
          if (hasCourseSlot(item.course_id, week, slot.day, slot.classNum) || localCourseSlot.has(keyCourseSlot(week))) {
            return false;
          }
        } else if (hasCourseLectureSlot(item.course_id, week, slot.day, slot.classNum) || localCourseLectureSlot.has(keyCourseLectureSlot(week))) {
          return false;
        }
        if (isGeneralSeminar(item)) {
          if (hasSubjectSlot(item.subject_id, week, slot.day, slot.classNum) || localSubjectSlot.has(keySubjectSlot(item.subject_id, week))) {
            return false;
          }
        }
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
        const lecture = isLectureLesson(item.lesson_type);
        localCourseSlot.add(keyCourseSlot(week));
        if (lecture) {
          localCourseLectureSlot.add(keyCourseLectureSlot(week));
        }
        if (isGeneralSeminar(item)) {
          localSubjectSlot.add(keySubjectSlot(item.subject_id, week));
        }
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
      const mirrorKey = formatMirrorKey(item.mirror_key);
      const lecture = isLectureLesson(item.lesson_type);
      if (isGeneralSeminar(item)) {
        markSubjectSlot(item.subject_id, week, bestSlot.day, bestSlot.classNum);
      }
      lockSubjectDay(item, bestSlot.day);
      markCourseSlot(item.course_id, week, bestSlot.day, bestSlot.classNum);
      if (lecture) {
        markCourseLectureSlot(item.course_id, week, bestSlot.day, bestSlot.classNum);
      }
      markTeacherSlot(item.teacher_id, week, bestSlot.day, bestSlot.classNum);
      incTeacherWeekly(item.teacher_id, week);
      markGroupSlot(item.course_id, groupNum, week, bestSlot.day, bestSlot.classNum);
      incGroupDaily(item.course_id, groupNum, week, bestSlot.day);
      incGroupDayLoad(item.course_id, groupNum, bestSlot.day, 1);
      incCourseDayLoad(item.course_id, bestSlot.day, 1);
      addGroupDaySlot(item.course_id, groupNum, bestSlot.day, bestSlot.classNum);
      results.push({
        item_id: item.id,
        course_id: item.course_id,
        semester_id: item.semester_id,
        subject_id: item.subject_id,
        teacher_id: item.teacher_id,
        lesson_type: item.lesson_type,
        group_number: groupNum,
        day_of_week: bestSlot.day,
        class_number: bestSlot.classNum,
        week_number: week,
        is_mirror: true,
        mirror_key: mirrorKey,
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
    const lockedDay = getLockedSubjectDay(item);
    if (fixedDay && lockedDay && fixedDay !== lockedDay) {
      conflicts.push({
        item_id: item.id,
        subject: item.subject_name,
        reason: 'subject_day_mismatch',
      });
      continue;
    }
    const preferredDay = lockedDay || fixedDay || null;
    let candidateDays = [];
    if (preferredDay) {
      if (allowedDaySet && !allowedDaySet.has(preferredDay)) {
        candidateDays = [];
      } else {
        candidateDays = [preferredDay];
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
        const coursePenalty = calcCourseDayPenalty(item.course_id, day, weeksCount);
        const slotPenalty = calcSlotPenalty(item.course_id, groupList, day, classNum);
        const classPenalty = classNum * 0.05;
        const latePenalty = calcLateSlotPenalty(classNum);
        const jitter = (stableHash(`${item.id}|${day}|${classNum}`) % 997) / 10000;
        const score = dayPenalty * evennessWeight + coursePenalty * courseWeight + slotPenalty * compactWeight + classPenalty + latePenalty + jitter;
        slotCandidates.push({ day, classNum, score });
      });
    });
    slotCandidates.sort((a, b) => a.score - b.score);

    let selectedSlot = null;
    let selectedWeeks = [];

    const canUseWeek = (week, day, classNum) => {
      const lecture = isLectureLesson(item.lesson_type);
      if (lecture) {
        if (hasCourseSlot(item.course_id, week, day, classNum)) {
          return false;
        }
      } else if (hasCourseLectureSlot(item.course_id, week, day, classNum)) {
        return false;
      }
      if (isGeneralSeminar(item) && hasSubjectSlot(item.subject_id, week, day, classNum)) {
        return false;
      }
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
      const lecture = isLectureLesson(item.lesson_type);
      if (isGeneralSeminar(item)) {
        markSubjectSlot(item.subject_id, week, selectedSlot.day, selectedSlot.classNum);
      }
      lockSubjectDay(item, selectedSlot.day);
      markCourseSlot(item.course_id, week, selectedSlot.day, selectedSlot.classNum);
      if (lecture) {
        markCourseLectureSlot(item.course_id, week, selectedSlot.day, selectedSlot.classNum);
      }
      markTeacherSlot(item.teacher_id, week, selectedSlot.day, selectedSlot.classNum);
      incTeacherWeekly(item.teacher_id, week);
      for (const groupNum of groupList) {
        const mirrorKey = formatMirrorKey(item.mirror_key);
        markGroupSlot(item.course_id, groupNum, week, selectedSlot.day, selectedSlot.classNum);
        incGroupDaily(item.course_id, groupNum, week, selectedSlot.day);
        incGroupDayLoad(item.course_id, groupNum, selectedSlot.day, 1);
        incCourseDayLoad(item.course_id, selectedSlot.day, 1);
        addGroupDaySlot(item.course_id, groupNum, selectedSlot.day, selectedSlot.classNum);
        results.push({
          item_id: item.id,
          course_id: item.course_id,
          semester_id: item.semester_id,
          subject_id: item.subject_id,
          teacher_id: item.teacher_id,
          lesson_type: item.lesson_type,
          group_number: groupNum,
          day_of_week: selectedSlot.day,
          class_number: selectedSlot.classNum,
          week_number: week,
          is_mirror: false,
          mirror_key: mirrorKey,
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
