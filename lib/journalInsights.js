function roundTo(value, precision = 2) {
  const factor = 10 ** Math.max(0, Number(precision) || 0);
  return Math.round(Number(value || 0) * factor) / factor;
}

function parseSnapshotPayload(value, fallback) {
  if (Array.isArray(fallback)) {
    if (Array.isArray(value)) return value;
  } else if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(fallback)) {
        return Array.isArray(parsed) ? parsed : fallback;
      }
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (_err) {
      return fallback;
    }
  }
  return fallback;
}

function formatScoreLabel(value) {
  return roundTo(value, 2).toFixed(2).replace(/\.00$/, '');
}

function buildRatingLeaderboardRows(ratingRows = [], topN = 10) {
  return (Array.isArray(ratingRows) ? ratingRows : [])
    .slice(0, Math.max(1, Number(topN) || 1))
    .map((row, index) => ({
      rank: index + 1,
      student_id: Number.isFinite(Number(row.student_id)) ? Number(row.student_id) : null,
      full_name: String(row.full_name || '').trim() || 'Student',
      final_score: roundTo(row.final_score, 2),
      subjects_count: Number.isFinite(Number(row.subjects_count)) ? Number(row.subjects_count) : 0,
    }));
}

function buildRatingSnapshotPayload({
  context = {},
  ratingRows = [],
  topN = 10,
  publishedAtIso,
  lang = 'uk',
} = {}) {
  const locale = lang === 'en' ? 'en-US' : 'uk-UA';
  const publishedAt = publishedAtIso || new Date().toISOString();
  const publishedLabel = new Date(publishedAt).toLocaleString(locale);
  const ranking = buildRatingLeaderboardRows(ratingRows, topN);
  const scopeLabel = String(context.scopeLabel || '').trim() || (lang === 'en' ? 'Selected scope' : 'Обраний контур');
  const periodLabel = String(context.periodLabel || '').trim() || (lang === 'en' ? 'Period' : 'Період');
  const lines = ranking.map((row) => {
    const scoreLabel = formatScoreLabel(row.final_score);
    const subjectsSuffix = row.subjects_count > 1
      ? (lang === 'en' ? ` (${row.subjects_count} subjects)` : ` (${row.subjects_count} предмети)`)
      : '';
    return `${row.rank}. ${row.full_name} - ${scoreLabel}${subjectsSuffix}`;
  });
  const body = [
    lang === 'en' ? `Student rating: ${scopeLabel}` : `Рейтинг студентів: ${scopeLabel}`,
    lang === 'en' ? `Period: ${periodLabel}` : `Період: ${periodLabel}`,
    '',
    ...lines,
    '',
    lang === 'en' ? `Updated: ${publishedLabel}` : `Оновлено: ${publishedLabel}`,
  ].join('\n').slice(0, 8000);

  return {
    messageBody: body,
    snapshot: {
      scope_type: String(context.scopeType || '').trim() || 'subject',
      scope_label: scopeLabel,
      period: String(context.period || '').trim() || 'semester',
      period_label: periodLabel,
      compare_mode: String(context.compareMode || '').trim() || 'none',
      target_kind: String(context.targetKind || '').trim() || 'course',
      top_n: ranking.length,
      course_id: Number.isFinite(Number(context.courseId)) ? Number(context.courseId) : null,
      semester_id: Number.isFinite(Number(context.semesterId)) ? Number(context.semesterId) : null,
      subject_id: Number.isFinite(Number(context.subjectId)) ? Number(context.subjectId) : null,
      group_number: Number.isFinite(Number(context.groupNumber)) ? Number(context.groupNumber) : null,
      published_at: publishedAt,
      summary_json: {
        participants_count: Number.isFinite(Number(context.participantsCount))
          ? Number(context.participantsCount)
          : ranking.length,
        generated_at_label: publishedLabel,
      },
      ranking_json: ranking,
    },
  };
}

function describeRatingPublishTarget({
  publishTarget = null,
  scopeLabel = '',
  periodLabel = '',
  participantsCount = 0,
  lang = 'uk',
} = {}) {
  if (!publishTarget || typeof publishTarget !== 'object') {
    return null;
  }
  const isEn = lang === 'en';
  const targetKind = String(publishTarget.kind || '').trim().toLowerCase();
  const groupNumber = Number(publishTarget.group_number || 0);
  const title = targetKind === 'course'
    ? (isEn ? 'Publish to the full course audience' : 'Опублікувати для всього курсу')
    : (groupNumber > 0
      ? (isEn ? `Publish to group ${groupNumber}` : `Опублікувати для групи ${groupNumber}`)
      : (isEn ? 'Publish to the selected audience' : 'Опублікувати для вибраної аудиторії'));
  const subtitle = [scopeLabel, periodLabel].filter(Boolean).join(' · ');
  return {
    kind: targetKind || 'course',
    title,
    subtitle,
    participants_count: Math.max(0, Number(participantsCount || 0)),
    note: targetKind === 'course'
      ? (isEn
        ? 'The same published snapshot will be reused in Journal Insights, My Day, and message surfaces for this course.'
        : 'Той самий published snapshot зʼявиться в Journal Insights, My Day і message surfaces для цього курсу.')
      : (isEn
        ? 'Only this subject scope will receive the snapshot, and the same card stays consistent across Journal Insights, My Day, and messages.'
        : 'Лише цей subject scope отримає snapshot, а одна й та сама картка лишиться консистентною в Journal Insights, My Day і повідомленнях.'),
  };
}

function findRelevantRatingSnapshot(snapshotRows = [], options = {}) {
  const rows = Array.isArray(snapshotRows) ? snapshotRows.filter(Boolean) : [];
  if (!rows.length) return null;

  const courseIds = Array.isArray(options.courseIds)
    ? options.courseIds
    : [options.courseId];
  const normalizedCourseIds = Array.from(new Set(
    courseIds
      .map((value) => Number(value || 0))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedSemesterId = Number(options.semesterId || 0) || null;
  const normalizedSubjectId = Number(options.subjectId || 0) || null;
  const normalizedGroupNumber = Number(options.groupNumber || 0) || null;
  const targetKind = String(options.targetKind || '').trim().toLowerCase();
  const scopeType = String(options.scopeType || '').trim().toLowerCase();
  const workloadKeys = new Set(
    (Array.isArray(options.workloadKeys) ? options.workloadKeys : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  );
  const matchesCourse = (row) => (
    !normalizedCourseIds.length
    || normalizedCourseIds.includes(Number(row.course_id || 0))
  );
  const matchesSemester = (row) => (
    !normalizedSemesterId
    || Number(row.semester_id || 0) === normalizedSemesterId
    || !Number(row.semester_id || 0)
  );
  const byPredicate = (predicate) => rows.find((row) => (
    matchesCourse(row)
    && matchesSemester(row)
    && predicate(row)
  ));

  if (normalizedSubjectId && normalizedGroupNumber) {
    const exactGroup = byPredicate((row) => (
      Number(row.subject_id || 0) === normalizedSubjectId
      && Number(row.group_number || 0) === normalizedGroupNumber
    ));
    if (exactGroup) return exactGroup;
  }

  if (normalizedSubjectId) {
    const exactSubject = byPredicate((row) => (
      Number(row.subject_id || 0) === normalizedSubjectId
      && (!normalizedGroupNumber || Number(row.group_number || 0) < 1)
    ));
    if (exactSubject) return exactSubject;
  }

  if (workloadKeys.size) {
    const workloadMatch = byPredicate((row) => {
      if (String(row.target_kind || '').trim().toLowerCase() === 'course') {
        return true;
      }
      const subjectId = Number(row.subject_id || 0);
      if (!subjectId) return false;
      const groupNumber = Number(row.group_number || 0);
      return workloadKeys.has(`${subjectId}|${groupNumber > 0 ? groupNumber : 'all'}`)
        || (groupNumber > 0 && workloadKeys.has(`${subjectId}|all`));
    });
    if (workloadMatch) return workloadMatch;
  }

  if (targetKind) {
    const targetMatch = byPredicate((row) => String(row.target_kind || '').trim().toLowerCase() === targetKind);
    if (targetMatch) return targetMatch;
  }

  if (scopeType) {
    const scopeMatch = byPredicate((row) => String(row.scope_type || '').trim().toLowerCase() === scopeType);
    if (scopeMatch) return scopeMatch;
  }

  const courseMatch = byPredicate((row) => String(row.target_kind || '').trim().toLowerCase() === 'course');
  if (courseMatch) return courseMatch;

  return rows.find((row) => matchesCourse(row) && matchesSemester(row)) || rows[0] || null;
}

function formatRatingSnapshotCard(snapshotRow = {}, lang = 'uk') {
  const locale = lang === 'en' ? 'en-US' : 'uk-UA';
  const ranking = parseSnapshotPayload(snapshotRow.ranking_json, []);
  const summary = parseSnapshotPayload(snapshotRow.summary_json, {});
  const topEntryRaw = ranking.length ? ranking[0] : null;
  const topEntry = topEntryRaw
    ? {
        ...topEntryRaw,
        rank: Number(topEntryRaw.rank || 1),
        score_label: formatScoreLabel(topEntryRaw.final_score),
      }
    : null;
  const rankingPreview = ranking.slice(0, 3).map((row, index) => ({
    ...row,
    rank: Number(row.rank || index + 1),
    score_label: formatScoreLabel(row.final_score),
  }));
  const scopeLabel = String(snapshotRow.scope_label || '').trim()
    || (lang === 'en' ? 'Latest rating' : 'Останній рейтинг');
  const periodLabel = String(snapshotRow.period_label || snapshotRow.period || '').trim()
    || (lang === 'en' ? 'Current period' : 'Поточний період');
  const publishedAtLabel = snapshotRow.published_at
    ? new Date(snapshotRow.published_at).toLocaleString(locale)
    : '';
  const targetKind = String(snapshotRow.target_kind || '').trim().toLowerCase();
  const groupNumber = Number(snapshotRow.group_number || 0);
  const targetLabel = targetKind === 'course'
    ? (lang === 'en' ? 'Course audience' : 'Весь курс')
    : (groupNumber > 0
      ? (lang === 'en' ? `Group ${groupNumber}` : `Група ${groupNumber}`)
      : (lang === 'en' ? 'Selected audience' : 'Обрана аудиторія'));

  return {
    scope_type: String(snapshotRow.scope_type || '').trim() || 'subject',
    target_kind: targetKind || 'course',
    scope_label: scopeLabel,
    target_label: targetLabel,
    period_label: periodLabel,
    published_at: snapshotRow.published_at || null,
    published_at_label: publishedAtLabel,
    updated_label: publishedAtLabel
      ? (lang === 'en' ? `Updated ${publishedAtLabel}` : `Оновлено ${publishedAtLabel}`)
      : '',
    top_entry: topEntry,
    ranking_count: ranking.length,
    ranking_preview: rankingPreview,
    participants_count: Number(summary.participants_count || ranking.length || 0),
    action_href: '/journal/insights',
  };
}

function buildAttendanceHealthSummary({
  role = 'student',
  counts = {},
  total = null,
  recentCounts = {},
  recentTotal = null,
  lastMarkedAt = null,
  primaryWindowDays = null,
  recentWindowDays = 14,
} = {}) {
  const present = Number(counts.present || 0);
  const late = Number(counts.late || 0);
  const absent = Number(counts.absent || 0);
  const excused = Number(counts.excused || 0);
  const markedTotal = Number.isFinite(Number(total))
    ? Number(total)
    : present + late + absent + excused;
  const attendedTotal = present + late;
  const reliability = markedTotal > 0 ? roundTo((attendedTotal / markedTotal) * 100, 1) : null;
  const absentShare = markedTotal > 0 ? roundTo((absent / markedTotal) * 100, 1) : null;
  const recentPresent = Number(recentCounts.present || 0);
  const recentLate = Number(recentCounts.late || 0);
  const recentAbsent = Number(recentCounts.absent || 0);
  const recentExcused = Number(recentCounts.excused || 0);
  const normalizedRecentTotal = Number.isFinite(Number(recentTotal))
    ? Number(recentTotal)
    : recentPresent + recentLate + recentAbsent + recentExcused;
  const recentAttendedTotal = recentPresent + recentLate;
  const recentReliability = normalizedRecentTotal > 0
    ? roundTo((recentAttendedTotal / normalizedRecentTotal) * 100, 1)
    : null;
  const recentAbsentShare = normalizedRecentTotal > 0
    ? roundTo((recentAbsent / normalizedRecentTotal) * 100, 1)
    : null;
  const flaggedTotal = late + absent;
  const recentFlaggedTotal = recentLate + recentAbsent;
  let tone = 'calm';
  if (
    (absentShare !== null && absentShare >= 20)
    || (recentAbsentShare !== null && recentAbsentShare >= 20)
    || recentFlaggedTotal >= 3
  ) {
    tone = 'risk';
  } else if (
    late >= 3
    || (absentShare !== null && absentShare >= 10)
    || recentFlaggedTotal >= 2
    || recentLate >= 2
  ) {
    tone = 'focus';
  }
  const statusKey = tone === 'risk' ? 'attention' : (tone === 'focus' ? 'watch' : 'stable');
  const noteKey = tone === 'risk'
    ? (String(role || 'student') === 'teacher' ? 'teacher_follow_up' : 'student_follow_up')
    : (
      tone === 'focus'
        ? (String(role || 'student') === 'teacher' ? 'teacher_watch' : 'student_watch')
        : (String(role || 'student') === 'teacher' ? 'teacher_steady' : 'student_steady')
    );
  return {
    role: String(role || 'student'),
    present,
    late,
    absent,
    excused,
    total: markedTotal,
    attended_total: attendedTotal,
    reliability,
    absent_share: absentShare,
    flagged_total: flaggedTotal,
    recent: {
      present: recentPresent,
      late: recentLate,
      absent: recentAbsent,
      excused: recentExcused,
      total: normalizedRecentTotal,
      attended_total: recentAttendedTotal,
      reliability: recentReliability,
      absent_share: recentAbsentShare,
      flagged_total: recentFlaggedTotal,
    },
    last_marked_at: lastMarkedAt ? String(lastMarkedAt).slice(0, 10) : null,
    primary_window_days: Number.isFinite(Number(primaryWindowDays)) ? Number(primaryWindowDays) : null,
    recent_window_days: Number.isFinite(Number(recentWindowDays)) ? Number(recentWindowDays) : 14,
    status_key: statusKey,
    note_key: noteKey,
    tone,
  };
}

module.exports = {
  buildAttendanceHealthSummary,
  buildRatingLeaderboardRows,
  buildRatingSnapshotPayload,
  describeRatingPublishTarget,
  findRelevantRatingSnapshot,
  formatRatingSnapshotCard,
};
