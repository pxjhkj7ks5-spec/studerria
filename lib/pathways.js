const REGISTRATION_TRACK_KEYS = new Set(['bachelor', 'master', 'teacher']);

function normalizeRegistrationTrack(rawTrack, fallback = 'bachelor') {
  const normalized = String(rawTrack || '').trim().toLowerCase();
  if (REGISTRATION_TRACK_KEYS.has(normalized)) {
    return normalized;
  }
  const fallbackTrack = String(fallback || '').trim().toLowerCase();
  if (REGISTRATION_TRACK_KEYS.has(fallbackTrack)) {
    return fallbackTrack;
  }
  return 'bachelor';
}

function inferRegistrationTrackFromCourse(course = {}) {
  const isTeacher = course && (
    course.is_teacher_course === true
    || Number(course.is_teacher_course) === 1
  );
  return isTeacher ? 'teacher' : 'bachelor';
}

function courseMatchesRegistrationTrack(course = {}, trackKey = 'bachelor') {
  const normalizedTrack = normalizeRegistrationTrack(trackKey, 'bachelor');
  const isTeacher = course && (
    course.is_teacher_course === true
    || Number(course.is_teacher_course) === 1
  );
  return normalizedTrack === 'teacher' ? isTeacher : !isTeacher;
}

function compactPathwayText(value, maxLength = 140) {
  const normalized = String(value || '').replace(/\s+/g, ' ').trim();
  if (!normalized) return '';
  const safeMaxLength = Math.max(8, Number(maxLength) || 140);
  if (normalized.length <= safeMaxLength) return normalized;
  return `${normalized.slice(0, safeMaxLength - 3).trim()}...`;
}

function normalizePathwayCampus(value) {
  return String(value || '').trim().toLowerCase() === 'munich' ? 'munich' : 'kyiv';
}

function formatPathwayCampusLabel(campusKey) {
  return normalizePathwayCampus(campusKey) === 'munich' ? 'Munich' : 'Kyiv';
}

function filterCourseRowsForTrack(courseRows = [], trackKey = 'bachelor') {
  return (Array.isArray(courseRows) ? courseRows : []).filter((course) => (
    courseMatchesRegistrationTrack(course, trackKey)
  ));
}

function buildAdmissionCampusChoicesFromCourses(courseRows = [], trackKey = '') {
  const campusMap = new Map();
  filterCourseRowsForTrack(courseRows, trackKey || 'bachelor').forEach((course) => {
    if (!course) return;
    const courseId = Number(course.course_id || course.id || 0);
    if (!Number.isInteger(courseId) || courseId < 1) return;
    const campusKey = normalizePathwayCampus(course.course_location || course.location);
    if (!campusMap.has(campusKey)) {
      campusMap.set(campusKey, {
        campus_key: campusKey,
        campus_label: formatPathwayCampusLabel(campusKey),
        course_ids: [],
        course_labels: [],
      });
    }
    const entry = campusMap.get(campusKey);
    entry.course_ids.push(courseId);
    entry.course_labels.push(
      compactPathwayText(course.course_name || course.name || `Course ${courseId}`, 140)
    );
  });

  return ['kyiv', 'munich']
    .map((campusKey) => campusMap.get(campusKey))
    .filter(Boolean)
    .map((entry) => {
      const courseIds = Array.from(new Set(entry.course_ids));
      const courseLabels = Array.from(new Set(entry.course_labels));
      return {
        campus_key: entry.campus_key,
        campus_label: entry.campus_label,
        course_count: courseIds.length,
        course_id: courseIds.length === 1 ? courseIds[0] : null,
        is_ambiguous: courseIds.length !== 1,
        course_labels: courseLabels,
      };
    });
}

function buildRegistrationFlowError({ issue = 'invalid_pathway', lang = 'uk' } = {}) {
  const isEn = lang === 'en';
  const copy = {
    missing_campus: isEn
      ? 'Choose a campus first. Without a campus, Studerria cannot resolve a course and the student would stop before subject selection.'
      : 'Спершу оберіть кампус. Без кампусу Studerria не зможе визначити курс, і студент зупиниться ще до вибору предметів.',
    campus_not_available: isEn
      ? 'This campus is not available for the selected pathway. Students on this route would not get a valid course for registration.'
      : 'Цей кампус недоступний для обраного pathway. На такому маршруті студент не отримає коректний курс для реєстрації.',
    ambiguous_campus: isEn
      ? 'Campus mapping is ambiguous. Leave exactly one visible course per campus, otherwise students cannot open a stable subject flow.'
      : 'Прив’язка кампусу неоднозначна. Залиште рівно один видимий курс на кампус, інакше студент не зможе відкрити стабільний вибір предметів.',
    invalid_course: isEn
      ? 'The selected course is invalid. Registration cannot continue because the student path no longer resolves to a real course.'
      : 'Обраний курс некоректний. Реєстрація не може продовжитись, бо студентський шлях більше не веде до реального курсу.',
    invalid_pathway: isEn
      ? 'Program, admission year, and course no longer match. Students would be sent into the wrong registration path.'
      : 'Програма, рік вступу й курс більше не збігаються. У такому стані студент потрапить у неправильний шлях реєстрації.',
    invalid_campus_binding: isEn
      ? 'Campus routing no longer matches this program or admission year. Students would either see an empty picker or the wrong course.'
      : 'Маршрутизація кампусу більше не збігається з цією програмою або роком вступу. Студент або побачить порожній вибір, або потрапить не на той курс.',
    missing_admission: isEn
      ? 'Admission year is missing for this pathway. Studerria cannot determine the cohort, so subject registration would stall.'
      : 'Для цього pathway бракує року вступу. Studerria не може визначити когорту, тому реєстрація на предмети зупиниться.',
    empty_subject_scope: isEn
      ? 'This pathway currently exposes no visible subjects. Students would land on an empty subject picker until the admin opens the cohort scope.'
      : 'У цьому pathway зараз немає видимих предметів. Студент потрапить у порожній вибір предметів, доки адміністратор не відкриє контур когорти.',
  };
  return copy[issue] || copy.invalid_pathway;
}

function buildCatalogAssignmentModeSummary({ sharedSubject = false, targetCourseCount = 0, lang = 'uk' } = {}) {
  const count = Math.max(0, Number(targetCourseCount || 0));
  const isEn = lang === 'en';
  if (sharedSubject) {
    return isEn
      ? `One shared subject instance will cover ${count || 1} selected course${count === 1 ? '' : 's'}, so schedule, homework, materials, and teacher context will move together.`
      : `Один shared subject instance покриє ${count || 1} вибраний курс${count === 1 ? '' : 'и'}, тому розклад, ДЗ, матеріали й викладацький контекст рухатимуться разом.`;
  }
  return isEn
    ? `Separate subject instances will be created per selected course, so each course keeps its own schedule, homework, and visibility settings.`
    : `Для кожного вибраного курсу буде створено окремий subject instance, тому кожен курс збереже власний розклад, ДЗ і налаштування видимості.`;
}

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

function buildRegistrationExperienceSummary({
  summary = {},
  lang = 'uk',
  mappedCourses = 0,
  visibleSubjects = 0,
  totalSubjects = 0,
  campusBindings = 0,
  ambiguousCampuses = 0,
  pendingUsers = 0,
  baseHiddenSubjects = 0,
} = {}) {
  const isEn = lang === 'en';
  const safeSummary = summary && typeof summary === 'object' ? summary : {};
  const safeMappedCourses = Number(mappedCourses || 0);
  const safeVisibleSubjects = Number(visibleSubjects || 0);
  const safeTotalSubjects = Number(totalSubjects || 0);
  const safeCampusBindings = Number(campusBindings || 0);
  const safeAmbiguousCampuses = Number(ambiguousCampuses || 0);
  const safePendingUsers = Number(pendingUsers || 0);
  const safeBaseHiddenSubjects = Number(baseHiddenSubjects || 0);
  const issues = Array.isArray(safeSummary.issues) ? safeSummary.issues : [];
  const subjectStageState = safeTotalSubjects > 0 && safeVisibleSubjects < 1
    ? 'blocked'
    : (safeTotalSubjects > 0 && safeVisibleSubjects < safeTotalSubjects ? 'warning' : 'ready');
  const campusStageState = safeAmbiguousCampuses > 0
    ? 'warning'
    : (safeCampusBindings > 0 ? 'ready' : 'muted');
  const migrationStageState = safePendingUsers > 0 ? 'warning' : 'ready';

  let tone = 'success';
  let title = '';
  let body = '';

  if (safeMappedCourses < 1) {
    tone = 'danger';
    title = isEn ? 'Students cannot resolve a course yet' : 'Студенти ще не можуть визначити курс';
    body = isEn
      ? 'Registration stops before subject selection because the cohort has no visible mapped course.'
      : 'Реєстрація зупиняється ще до вибору предметів, бо для когорти немає жодного видимого замапленого курсу.';
  } else if (safeTotalSubjects > 0 && safeVisibleSubjects < 1) {
    tone = 'danger';
    title = isEn ? 'Students would hit an empty subject picker' : 'Студенти потраплять у порожній вибір предметів';
    body = isEn
      ? 'The course route is available, but the current cohort does not expose any visible subjects yet.'
      : 'Маршрут до курсу вже є, але поточна когорта ще не відкриває жодного видимого предмета.';
  } else if (safeAmbiguousCampuses > 0) {
    tone = 'warning';
    title = isEn ? 'Campus-based registration is still ambiguous' : 'Campus-реєстрація ще неоднозначна';
    body = isEn
      ? 'Students can reach the flow, but campus routing still resolves to multiple courses in at least one location.'
      : 'Студенти вже можуть зайти у флоу, але маршрутизація кампусів ще веде до кількох курсів щонайменше в одній локації.';
  } else if (String(safeSummary.status || 'ready') === 'needs_attention' || safeBaseHiddenSubjects > 0 || subjectStageState === 'warning' || safePendingUsers > 0) {
    tone = 'warning';
    title = isEn ? 'Registration is open, but the cohort still needs cleanup' : 'Реєстрація відкрита, але когорту ще треба дочистити';
    body = isEn
      ? 'Students should see a working subject flow, but part of the visible scope or migration setup is still incomplete.'
      : 'Студенти вже мають робочий шлях вибору предметів, але частина видимого контуру або міграції ще не доведена.';
  } else {
    tone = 'success';
    title = isEn ? 'Students should see a stable subject flow' : 'Студенти мають бачити стабільний вибір предметів';
    body = isEn
      ? 'Course mapping, subject visibility, and campus routing are aligned for this cohort.'
      : 'Для цієї когорти вже узгоджені мапінг курсу, видимість предметів і маршрутизація кампусів.';
  }

  if (safeBaseHiddenSubjects > 0) {
    body += isEn
      ? ` ${safeBaseHiddenSubjects} subjects are still hidden in the base course.`
      : ` У базовому курсі ще приховано ${safeBaseHiddenSubjects} предметів.`;
  }

  const stages = [
    {
      key: 'mapping',
      label: isEn ? 'Course route' : 'Маршрут курсу',
      state: safeMappedCourses > 0 ? 'ready' : 'blocked',
      value: safeMappedCourses > 0
        ? (isEn ? `${safeMappedCourses} mapped` : `${safeMappedCourses} замаплено`)
        : (isEn ? 'Blocked' : 'Заблоковано'),
      hint: safeMappedCourses > 0
        ? (isEn ? 'Students can resolve a course from this cohort.' : 'Студенти можуть визначити курс для цієї когорти.')
        : (isEn ? 'Add at least one visible mapped course.' : 'Додайте хоча б один видимий замаплений курс.'),
    },
    {
      key: 'subjects',
      label: isEn ? 'Subject picker' : 'Вибір предметів',
      state: subjectStageState,
      value: safeTotalSubjects > 0
        ? `${safeVisibleSubjects}/${safeTotalSubjects}`
        : (isEn ? 'No subjects yet' : 'Ще немає предметів'),
      hint: subjectStageState === 'blocked'
        ? (isEn ? 'Students will see no subjects after opening the picker.' : 'Після відкриття вибору студенти не побачать жодного предмета.')
        : (subjectStageState === 'warning'
          ? (isEn ? 'Only part of the subject scope is visible right now.' : 'Зараз студентам видно лише частину предметного контуру.')
          : (isEn ? 'Visible subjects are ready for selection.' : 'Видимі предмети готові до вибору.')),
    },
    {
      key: 'campus',
      label: isEn ? 'Campus routing' : 'Маршрути кампусів',
      state: campusStageState,
      value: safeAmbiguousCampuses > 0
        ? (isEn ? `${safeAmbiguousCampuses} ambiguous` : `${safeAmbiguousCampuses} неоднозначних`)
        : (safeCampusBindings > 0
          ? (isEn ? `${safeCampusBindings} ready` : `${safeCampusBindings} готово`)
          : (isEn ? 'Not configured' : 'Не налаштовано')),
      hint: safeAmbiguousCampuses > 0
        ? (isEn ? 'At least one campus resolves to multiple courses.' : 'Щонайменше один кампус веде до кількох курсів.')
        : (safeCampusBindings > 0
          ? (isEn ? 'Each available campus has one registration route.' : 'Кожен доступний кампус має один маршрут реєстрації.')
          : (isEn ? 'Campus routing will appear after visible mapping is set.' : 'Маршрути кампусів з’являться після видимого мапінгу.')),
    },
    {
      key: 'migration',
      label: isEn ? 'Existing users' : 'Наявні користувачі',
      state: migrationStageState,
      value: safePendingUsers > 0
        ? (isEn ? `${safePendingUsers} pending` : `${safePendingUsers} очікує`)
        : (isEn ? 'Aligned' : 'Вирівняно'),
      hint: safePendingUsers > 0
        ? (isEn ? 'Migration backlog still exists for current users.' : 'Для поточних користувачів ще лишається черга міграції.')
        : (isEn ? 'Current users are aligned with this cohort.' : 'Поточні користувачі вже вирівняні з цією когортою.'),
    },
  ];

  return {
    tone,
    title,
    body,
    stages,
    issue_count: issues.length,
    status: String(safeSummary.status || 'ready'),
  };
}

function buildCatalogBindingSummary({ entries = [], lang = 'uk' } = {}) {
  const isEn = lang === 'en';
  const safeEntries = Array.isArray(entries) ? entries : [];
  const metrics = safeEntries.reduce((summary, entry) => {
    const instances = Array.isArray(entry && entry.instances) ? entry.instances : [];
    summary.total_entries += 1;
    if (!instances.length) {
      summary.unassigned_entries += 1;
      return summary;
    }
    instances.forEach((instance) => {
      const bindingCount = Number(instance && instance.course_count ? instance.course_count : 0);
      summary.total_instances += 1;
      if (instance && instance.is_shared) {
        summary.shared_instances += 1;
      } else {
        summary.separate_instances += 1;
      }
      if (bindingCount > 1) {
        summary.multi_course_instances += 1;
      }
      if (!(instance && instance.is_visible)) {
        summary.hidden_instances += 1;
      }
    });
    return summary;
  }, {
    total_entries: 0,
    total_instances: 0,
    shared_instances: 0,
    separate_instances: 0,
    multi_course_instances: 0,
    unassigned_entries: 0,
    hidden_instances: 0,
  });

  if (metrics.total_entries < 1) {
    return {
      tone: 'muted',
      title: isEn ? 'Global subject base is still empty' : 'Глобальна база предметів ще порожня',
      body: isEn
        ? 'Add base subjects first, then decide whether each course assignment should be shared or separate.'
        : 'Спершу додайте базові предмети, а потім вирішуйте, чи має призначення на курси бути спільним або окремим.',
      metrics,
    };
  }

  const hasShared = metrics.shared_instances > 0;
  const hasSeparate = metrics.separate_instances > 0;
  const tone = metrics.unassigned_entries > 0 ? 'warning' : 'success';
  let title = '';
  let body = '';

  if (hasShared && hasSeparate) {
    title = isEn ? 'Shared and separate bindings coexist' : 'У базі одночасно є shared і separate прив’язки';
    body = isEn
      ? 'Check each instance description before editing one course, because only shared bindings propagate schedule and homework changes across linked courses.'
      : 'Перед редагуванням окремого курсу перевіряйте опис кожного інстансу, бо лише shared-прив’язки поширюють зміни розкладу й ДЗ на всі зв’язані курси.';
  } else if (hasShared) {
    title = isEn ? 'Shared bindings are active in the base' : 'У базі вже активні shared-прив’язки';
    body = isEn
      ? 'These instances share schedule, homework, materials, and teacher context across linked courses.'
      : 'Такі інстанси ділять розклад, ДЗ, матеріали й контекст викладачів між зв’язаними курсами.';
  } else {
    title = isEn ? 'Assignments stay separate per course' : 'Призначення залишаються окремими по курсах';
    body = isEn
      ? 'Only the catalog name is shared; each course keeps its own subject instance and settings.'
      : 'Спільною лишається тільки назва в каталозі, а кожен курс зберігає власний інстанс предмета й налаштування.';
  }

  if (metrics.multi_course_instances > 0) {
    body += isEn
      ? ` ${metrics.multi_course_instances} instances already span multiple courses.`
      : ` ${metrics.multi_course_instances} інстансів уже охоплюють кілька курсів.`;
  }

  if (metrics.unassigned_entries > 0) {
    body += isEn
      ? ` ${metrics.unassigned_entries} base subjects are still not assigned to any course.`
      : ` ${metrics.unassigned_entries} базових предметів ще не призначені на жоден курс.`;
  }

  return {
    tone,
    title,
    body,
    metrics,
  };
}

function describeCatalogBinding({ isShared = false, bindingCount = 0, ownerCourseName = '', lang = 'en' } = {}) {
  const count = Number(bindingCount || 0);
  if (lang === 'uk') {
    if (isShared) {
      return count > 1
        ? `Спільний інстанс для ${count} курсів`
        : 'Спільний інстанс для одного курсу';
    }
    return ownerCourseName ? `Окремий інстанс курсу ${ownerCourseName}` : 'Окремий інстанс предмета';
  }
  if (isShared) {
    return count > 1
      ? `Shared catalog subject linked to ${count} courses`
      : 'Shared catalog subject linked to one course';
  }
  return ownerCourseName ? `Separate subject owned by ${ownerCourseName}` : 'Separate subject instance';
}

module.exports = {
  buildAdmissionCampusChoicesFromCourses,
  buildCatalogBindingSummary,
  buildCatalogAssignmentModeSummary,
  buildRegistrationFlowError,
  buildRegistrationExperienceSummary,
  buildPathwayReadinessSummary,
  buildRegistrationReadinessAlert,
  buildSubjectVisibilityCopy,
  courseMatchesRegistrationTrack,
  describeCatalogBinding,
  filterCourseRowsForTrack,
  inferRegistrationTrackFromCourse,
  normalizeRegistrationTrack,
};
