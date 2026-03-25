const defaultNormalizeLocation = (value) =>
  String(value || '').toLowerCase() === 'munich' ? 'munich' : 'kyiv';

const SESSION_GENERATOR_REDIRECT_VALUE_KEYS = [
  'window_mode',
  'start_date',
  'session_days',
  'session_weeks_count',
  'session_weeks_set',
  'max_events_per_day',
  'reserve_every',
  'exam_gap_days',
  'retake_gap_days',
  'retake_window_days',
  'day_grouping_mode',
  'exam_sequence',
  'credit_sequence',
  'strategy',
];

const SESSION_GENERATOR_REDIRECT_BOOLEAN_KEYS = [
  'include_weekends',
  'include_consultations',
  'respect_study_days',
];

function normalizeSessionGeneratorStrategy(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'credits_first') return 'credits_first';
  if (raw === 'balanced') return 'balanced';
  return 'exams_first';
}

function parseSessionGeneratorFlag(value, fallback = false) {
  if (value === undefined || value === null || value === '') return !!fallback;
  const raw = String(value).trim().toLowerCase();
  if (['1', 'true', 't', 'yes', 'on'].includes(raw)) return true;
  if (['0', 'false', 'f', 'no', 'off'].includes(raw)) return false;
  return !!fallback;
}

function parseSessionGeneratorInt(value, fallback, min, max) {
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  const rounded = Math.round(num);
  if (Number.isFinite(min) && rounded < min) return min;
  if (Number.isFinite(max) && rounded > max) return max;
  return rounded;
}

function parseIsoDateList(rawValue, limit = 180) {
  if (rawValue === undefined || rawValue === null || rawValue === '') return [];
  let payload = rawValue;
  if (typeof payload === 'string') {
    const trimmed = payload.trim();
    if (!trimmed) return [];
    try {
      payload = JSON.parse(trimmed);
    } catch (_err) {
      payload = trimmed.split(',');
    }
  }
  if (!Array.isArray(payload)) return [];
  const dates = payload
    .slice(0, Math.max(1, Number(limit) || 1))
    .map((value) => String(value || '').slice(0, 10))
    .filter((value) => /^\d{4}-\d{2}-\d{2}$/.test(value));
  return Array.from(new Set(dates)).sort();
}

function buildSessionGeneratorReturnHref(
  payload = {},
  messageKind = '',
  messageText = '',
  normalizeLocation = defaultNormalizeLocation
) {
  const params = new URLSearchParams();
  const push = (key, value) => {
    if (value === undefined || value === null || value === '') return;
    params.set(key, String(value));
  };
  const locationNormalizer = typeof normalizeLocation === 'function'
    ? normalizeLocation
    : defaultNormalizeLocation;
  push('location', locationNormalizer(payload.location || 'kyiv'));
  push('course_id', parseSessionGeneratorInt(payload.course_id, null, 1, Number.MAX_SAFE_INTEGER));
  push('semester_id', parseSessionGeneratorInt(payload.semester_id, null, 1, Number.MAX_SAFE_INTEGER));
  push('draft_id', parseSessionGeneratorInt(payload.draft_id, null, 1, Number.MAX_SAFE_INTEGER));
  const windowMode = String(payload.window_mode || '').trim().toLowerCase();
  if (windowMode === 'days' || windowMode === 'weeks') {
    push('window_mode', windowMode);
  }
  SESSION_GENERATOR_REDIRECT_VALUE_KEYS.forEach((key) => {
    if (key === 'window_mode') return;
    if (!Object.prototype.hasOwnProperty.call(payload, key)) return;
    push(key, payload[key]);
  });
  SESSION_GENERATOR_REDIRECT_BOOLEAN_KEYS.forEach((key) => {
    if (!Object.prototype.hasOwnProperty.call(payload, key)) return;
    params.set(key, parseSessionGeneratorFlag(payload[key], false) ? '1' : '0');
  });
  if (messageKind && messageText) {
    params.set(messageKind, String(messageText));
  }
  return `/admin/session-generator${params.toString() ? `?${params.toString()}` : ''}`;
}

function resolveSessionGeneratorWindowDates({
  form = {},
  semester = null,
  activeStudyDayNames = [],
  explicitDates = [],
  parseWeekSet,
  buildDatesFromWeekNumbers,
  buildDayBuckets,
}) {
  const windowMode = String(form.window_mode || '').trim().toLowerCase() === 'days' ? 'days' : 'weeks';
  const providedExplicitDates = parseIsoDateList(explicitDates, 366);
  const normalizedStudyDayNames = Array.from(new Set((activeStudyDayNames || [])
    .map((day) => String(day || '').trim())
    .filter(Boolean)));
  let sessionWeekNumbers = [];
  let sessionWeeksSet = String(form.session_weeks_set || '').trim();

  if (windowMode === 'weeks' && semester && Number(semester.weeks_count || 0) > 0 && typeof parseWeekSet === 'function') {
    const semesterWeeksCount = Number(semester.weeks_count || 0);
    const parsedWeeks = parseWeekSet(sessionWeeksSet, semesterWeeksCount);
    if (Array.isArray(parsedWeeks) && parsedWeeks.length) {
      sessionWeekNumbers = parsedWeeks;
    } else {
      const count = Math.min(
        Math.max(parseSessionGeneratorInt(form.session_weeks_count, 1, 1, semesterWeeksCount), 1),
        semesterWeeksCount
      );
      const startWeek = Math.max(1, semesterWeeksCount - count + 1);
      sessionWeekNumbers = Array.from({ length: count }, (_value, index) => startWeek + index);
    }
    sessionWeeksSet = sessionWeekNumbers.join(',');
  }

  if (providedExplicitDates.length) {
    return {
      window_mode: windowMode,
      sessionWeekNumbers,
      sessionWeeksSet,
      explicitSessionDates: providedExplicitDates,
    };
  }

  if (windowMode === 'weeks') {
    const explicitSessionDates = typeof buildDatesFromWeekNumbers === 'function'
      ? parseIsoDateList(
          buildDatesFromWeekNumbers({
            semester,
            weekNumbers: sessionWeekNumbers,
            includeWeekends: parseSessionGeneratorFlag(form.include_weekends, false),
            respectStudyDays: parseSessionGeneratorFlag(form.respect_study_days, false) && normalizedStudyDayNames.length > 0,
            activeStudyDayNames: normalizedStudyDayNames,
          }),
          366
        )
      : [];
    return {
      window_mode: windowMode,
      sessionWeekNumbers,
      sessionWeeksSet,
      explicitSessionDates,
    };
  }

  const buckets = typeof buildDayBuckets === 'function'
    ? buildDayBuckets({
        startDate: form.start_date,
        sessionDays: parseSessionGeneratorInt(form.session_days, 14, 1, 180),
        maxEventsPerDay: parseSessionGeneratorInt(form.max_events_per_day, 1, 1, 7),
        includeWeekends: parseSessionGeneratorFlag(form.include_weekends, false),
        respectStudyDays: parseSessionGeneratorFlag(form.respect_study_days, false) && normalizedStudyDayNames.length > 0,
        activeStudyDayNames: normalizedStudyDayNames,
      })
    : [];
  const explicitSessionDates = Array.from(new Set((buckets || [])
    .map((bucket) => String(bucket && bucket.date ? bucket.date : '').trim())
    .filter(Boolean)))
    .sort();
  return {
    window_mode: windowMode,
    sessionWeekNumbers,
    sessionWeeksSet,
    explicitSessionDates,
  };
}

function formatSessionConflictSummary(report) {
  if (!report) return 'Невідома помилка перевірки конфліктів.';
  const conflicts = Array.isArray(report.conflicts) ? report.conflicts : [];
  const unresolvedRows = Array.isArray(report.unresolvedRows) ? report.unresolvedRows : [];
  if (!conflicts.length && !unresolvedRows.length) {
    return `Конфліктів викладачів або кабінетів не знайдено (${Number(report.checkedRows || 0)} перевірених подій).`;
  }
  const samples = conflicts.slice(0, 4).map((row) => {
    const resourceLabel = String(row.resource_kind || '') === 'room'
      ? (row.room_label || 'Кабінет')
      : (row.teacher_name || 'Викладач');
    if (row.type === 'draft') {
      return `${resourceLabel}: ${row.date}, пара ${row.class_number} (дубль у плані)`;
    }
    const busy = row.details && row.details.busy ? row.details.busy : null;
    const courseLabel = busy && busy.course_name ? busy.course_name : (busy && busy.course_id ? `Курс ${busy.course_id}` : 'інший курс');
    const subjectLabel = busy && busy.subject_name ? busy.subject_name : 'інша подія';
    const groupLabel = busy && Number.isFinite(Number(busy.group_number)) && Number(busy.group_number) > 0
      ? `, група ${busy.group_number}`
      : '';
    return `${resourceLabel}: ${row.date}, пара ${row.class_number} (${courseLabel} · ${subjectLabel}${groupLabel})`;
  });
  const teacherConflicts = conflicts.filter((row) => String(row.resource_kind || 'teacher') !== 'room').length;
  const roomConflicts = conflicts.filter((row) => String(row.resource_kind || '') === 'room').length;
  const parts = [];
  if (conflicts.length) parts.push(`Знайдено конфліктів: ${conflicts.length}.`);
  if (teacherConflicts) parts.push(`Викладачі: ${teacherConflicts}.`);
  if (roomConflicts) parts.push(`Кабінети: ${roomConflicts}.`);
  if (samples.length) parts.push(`Приклади: ${samples.join('; ')}.`);
  if (unresolvedRows.length) parts.push(`Без прив’язаного викладача: ${unresolvedRows.length} подій.`);
  return parts.join(' ').trim();
}

function buildSessionConflictSlotMapV2(report) {
  const slotMap = {};
  const conflicts = Array.isArray(report && report.conflicts) ? report.conflicts : [];
  conflicts.forEach((conflict) => {
    const date = String(conflict && conflict.date ? conflict.date : '');
    const classNumber = Number(conflict && conflict.class_number ? conflict.class_number : 0);
    if (!date || !Number.isFinite(classNumber) || classNumber < 1) return;
    const key = `${date}|${classNumber}`;
    if (!slotMap[key]) {
      slotMap[key] = {
        date,
        class_number: classNumber,
        conflicts_total: 0,
        draft_conflicts: 0,
        occupied_conflicts: 0,
        reasons: [],
      };
    }
    const slotRow = slotMap[key];
    const resourceLabel = String(conflict.resource_kind || '') === 'room'
      ? (conflict.room_label || 'Кабінет')
      : (conflict.teacher_name || 'Викладач');
    slotRow.conflicts_total += 1;
    if (conflict.type === 'draft') {
      slotRow.draft_conflicts += 1;
      slotRow.reasons.push(`${resourceLabel}: дубль у ручному плані`);
      return;
    }
    slotRow.occupied_conflicts += 1;
    const busy = conflict.details && conflict.details.busy ? conflict.details.busy : null;
    const subjectLabel = busy && busy.subject_name ? busy.subject_name : 'інша подія';
    const courseLabel = busy && busy.course_name ? busy.course_name : 'інший курс';
    slotRow.reasons.push(`${resourceLabel}: зайнятий (${courseLabel} · ${subjectLabel})`);
  });
  Object.values(slotMap).forEach((slotRow) => {
    const uniqueReasons = Array.from(new Set((slotRow.reasons || []).map((text) => String(text).trim()).filter(Boolean)));
    slotRow.reasons = uniqueReasons.slice(0, 4);
    slotRow.reason_text = uniqueReasons.slice(0, 2).join('; ');
  });
  return slotMap;
}

module.exports = {
  normalizeSessionGeneratorStrategy,
  parseSessionGeneratorFlag,
  parseSessionGeneratorInt,
  buildSessionGeneratorReturnHref,
  resolveSessionGeneratorWindowDates,
  formatSessionConflictSummary,
  buildSessionConflictSlotMapV2,
};
