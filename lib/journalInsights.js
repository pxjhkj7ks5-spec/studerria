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

function buildAttendanceHealthSummary({ role = 'student', counts = {}, total = null } = {}) {
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
  let tone = 'calm';
  if (absentShare !== null && absentShare >= 20) tone = 'risk';
  else if (late >= 3 || (absentShare !== null && absentShare >= 10)) tone = 'focus';
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
    tone,
  };
}

module.exports = {
  buildRatingLeaderboardRows,
  buildRatingSnapshotPayload,
  formatRatingSnapshotCard,
  buildAttendanceHealthSummary,
};
