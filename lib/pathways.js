function buildPathwayReadinessSummary({
  mappedCourses = 0,
  visibleSubjects = 0,
  totalSubjects = 0,
  campusBindings = 0,
  pendingUsers = 0,
} = {}) {
  const summary = {
    mapped_courses: Number(mappedCourses || 0),
    visible_subjects: Number(visibleSubjects || 0),
    total_subjects: Number(totalSubjects || 0),
    campus_bindings: Number(campusBindings || 0),
    pending_users: Number(pendingUsers || 0),
    status: 'ready',
    issues: [],
  };
  if (summary.mapped_courses < 1) {
    summary.status = 'blocked';
    summary.issues.push('course_mapping');
  }
  if (summary.total_subjects > 0 && summary.visible_subjects < 1) {
    summary.status = 'blocked';
    summary.issues.push('subject_visibility');
  } else if (summary.total_subjects > 0 && summary.visible_subjects < summary.total_subjects) {
    if (summary.status !== 'blocked') summary.status = 'needs_attention';
    summary.issues.push('partial_visibility');
  }
  if (summary.campus_bindings < 1) {
    if (summary.status !== 'blocked') summary.status = 'needs_attention';
    summary.issues.push('campus_routing');
  }
  if (summary.pending_users > 0) {
    if (summary.status !== 'blocked') summary.status = 'needs_attention';
    summary.issues.push('pending_users');
  }
  return summary;
}

function buildSubjectVisibilityCopy({ visibleSubjects = 0, totalSubjects = 0, lang = 'uk' } = {}) {
  const visible = Number(visibleSubjects || 0);
  const total = Number(totalSubjects || 0);
  if (lang === 'en') {
    if (total < 1) {
      return 'No subjects are available for this pathway yet.';
    }
    if (visible < 1) {
      return 'Subjects exist, but none are visible for student registration yet.';
    }
    if (visible < total) {
      return `${visible} of ${total} subjects are visible in registration.`;
    }
    return `All ${total} subjects are visible in registration.`;
  }
  if (total < 1) {
    return 'Для цього pathway ще немає доступних предметів.';
  }
  if (visible < 1) {
    return 'Предмети існують, але жоден з них ще не відкритий для реєстрації студентів.';
  }
  if (visible < total) {
    return `У реєстрації видно ${visible} з ${total} предметів.`;
  }
  return `Усі ${total} предметів доступні в реєстрації.`;
}

function describeCatalogBinding({ isShared = false, bindingCount = 0, ownerCourseName = '' } = {}) {
  const count = Number(bindingCount || 0);
  if (isShared) {
    return count > 1
      ? `Shared catalog subject linked to ${count} courses`
      : 'Shared catalog subject linked to one course';
  }
  return ownerCourseName ? `Separate subject owned by ${ownerCourseName}` : 'Separate subject instance';
}

module.exports = {
  buildPathwayReadinessSummary,
  buildSubjectVisibilityCopy,
  describeCatalogBinding,
};
