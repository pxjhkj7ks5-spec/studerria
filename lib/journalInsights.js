function roundTo(value, precision = 2) {
  const factor = 10 ** Math.max(0, Number(precision) || 0);
  return Math.round(Number(value || 0) * factor) / factor;
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
    const scoreLabel = roundTo(row.final_score, 2).toFixed(2).replace(/\.00$/, '');
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

function formatRatingSnapshotCard(snapshotRow = {}, lang = 'uk') {
  const ranking = Array.isArray(snapshotRow.ranking_json) ? snapshotRow.ranking_json : [];
  const topEntry = ranking.length ? ranking[0] : null;
  const scopeLabel = String(snapshotRow.scope_label || '').trim()
    || (lang === 'en' ? 'Latest rating' : 'Останній рейтинг');
  return {
    scope_label: scopeLabel,
    period_label: String(snapshotRow.period_label || snapshotRow.period || '').trim()
      || (lang === 'en' ? 'Current period' : 'Поточний період'),
    published_at: snapshotRow.published_at || null,
    published_at_label: snapshotRow.published_at
      ? new Date(snapshotRow.published_at).toLocaleString(lang === 'en' ? 'en-US' : 'uk-UA')
      : '',
    top_entry: topEntry,
    ranking_count: ranking.length,
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
  buildRatingLeaderboardRows,
  buildRatingSnapshotPayload,
  formatRatingSnapshotCard,
  buildAttendanceHealthSummary,
};
