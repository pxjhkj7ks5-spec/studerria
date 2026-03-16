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

function buildRegistrationReadinessAlert({
  summary = {},
  lang = 'uk',
  mappedCourses = 0,
  visibleSubjects = 0,
  totalSubjects = 0,
  campusBindings = 0,
  ambiguousCampuses = 0,
  baseHiddenSubjects = 0,
} = {}) {
  const isEn = lang === 'en';
  const safeSummary = summary && typeof summary === 'object' ? summary : {};
  const status = String(safeSummary.status || 'ready');
  const issues = Array.isArray(safeSummary.issues) ? safeSummary.issues : [];
  const issueLabels = {
    course_mapping: isEn ? 'Course mapping' : 'Мапінг курсів',
    subject_visibility: isEn ? 'Subject visibility' : 'Видимість предметів',
    partial_visibility: isEn ? 'Partial subject visibility' : 'Часткова видимість предметів',
    campus_routing: isEn ? 'Campus routing' : 'Маршрутизація кампусів',
    pending_users: isEn ? 'Existing user migration' : 'Міграція наявних користувачів',
  };
  const statusLabel = status === 'blocked'
    ? (isEn ? 'Blocked' : 'Заблоковано')
    : (status === 'needs_attention'
      ? (isEn ? 'Needs attention' : 'Потрібна увага')
      : (isEn ? 'Ready' : 'Готово'));
  let title = '';
  let body = '';
  if (status === 'blocked') {
    if (issues.includes('course_mapping')) {
      title = isEn ? 'Registration is waiting for course mapping' : 'Реєстрація чекає на мапінг курсів';
      body = isEn
        ? 'The cohort does not have a visible mapped course yet, so students can reach an empty registration path.'
        : 'Для цієї когорти ще немає видимого замапленого курсу, тому студенти приходять у порожній реєстраційний шлях.';
    } else if (issues.includes('subject_visibility')) {
      title = isEn ? 'Registration would show no subjects' : 'Реєстрація показала б порожній список предметів';
      body = isEn
        ? 'Subjects exist in the base course, but none are currently visible for this admission year.'
        : 'У базовому курсі предмети існують, але для цього року вступу зараз не видно жодного з них.';
    } else {
      title = isEn ? 'Registration is not ready yet' : 'Реєстрація ще не готова';
      body = isEn
        ? 'One of the cohort readiness signals is still blocking the student path.'
        : 'Один із readiness-сигналів когорти все ще блокує студентський шлях.';
    }
  } else if (status === 'needs_attention') {
    title = isEn ? 'Registration works, but the cohort still needs cleanup' : 'Реєстрація працює, але когорту ще треба дочистити';
    body = isEn
      ? 'Students can continue, but part of the visible scope, campus routing, or migration setup is still incomplete.'
      : 'Студенти вже можуть рухатися далі, але частина видимого контуру, кампусів або міграції ще не доведена.';
  } else {
    title = isEn ? 'Cohort looks ready for subject selection' : 'Когорта виглядає готовою до вибору предметів';
    body = isEn
      ? 'Course mapping, subject visibility, and campus routing are aligned for this registration step.'
      : 'Для цього кроку реєстрації вже узгоджені мапінг курсу, видимість предметів і маршрутизація кампусів.';
  }
  if (baseHiddenSubjects > 0 && status !== 'blocked') {
    body += isEn
      ? ` ${baseHiddenSubjects} subjects are still hidden in the base course.`
      : ` У базовому курсі ще приховано ${baseHiddenSubjects} предметів.`;
  }
  if (ambiguousCampuses > 0) {
    body += isEn
      ? ` ${ambiguousCampuses} campus routes are still ambiguous.`
      : ` Ще ${ambiguousCampuses} маршрути кампусів лишаються неоднозначними.`;
  }
  return {
    status,
    status_label: statusLabel,
    title,
    body,
    issues: issues.map((issue) => issueLabels[issue] || issue),
    metrics: {
      mapped_courses: Number(mappedCourses || 0),
      visible_subjects: Number(visibleSubjects || 0),
      total_subjects: Number(totalSubjects || 0),
      campus_bindings: Number(campusBindings || 0),
      ambiguous_campuses: Number(ambiguousCampuses || 0),
      base_hidden_subjects: Number(baseHiddenSubjects || 0),
    },
  };
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
  buildRegistrationReadinessAlert,
  buildSubjectVisibilityCopy,
  describeCatalogBinding,
};
