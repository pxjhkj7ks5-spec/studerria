const DEMO_USER_ID = -1001;
const DEMO_ALLOWED_ROLES = new Set(['student', 'teacher']);
const DEMO_ALLOWED_WRITE_PATHS = new Set(['/demo/start', '/demo/switch-role', '/logout']);

function normalizeDemoRole(rawRole = 'student') {
  const role = String(rawRole || '').trim().toLowerCase();
  return DEMO_ALLOWED_ROLES.has(role) ? role : 'student';
}

function isDemoSession(req) {
  return Boolean(req && req.session && req.session.isDemo === true);
}

function getDemoRole(req) {
  if (!isDemoSession(req)) return '';
  return normalizeDemoRole(req.session.demoRole || req.session.role || 'student');
}

function getDemoVisitRoleKey(rawRole = 'student') {
  return `demo-${normalizeDemoRole(rawRole)}`;
}

function buildDemoUser(role = 'student', lang = 'uk') {
  const normalizedRole = normalizeDemoRole(role);
  const isEn = lang === 'en';
  const username = normalizedRole === 'teacher'
    ? (isEn ? 'Demo Teacher' : 'Демо Викладач')
    : (isEn ? 'Demo Student' : 'Демо Студент');
  return {
    id: DEMO_USER_ID,
    username,
    full_name: username,
    role: normalizedRole,
    schedule_group: 'Demo',
    course_id: 1,
    group_id: null,
    language: isEn ? 'en' : 'uk',
  };
}

function shouldAllowDemoWrite(req) {
  if (!isDemoSession(req)) return true;
  const method = String(req && req.method ? req.method : 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return true;
  const path = String(req && req.path ? req.path : '').trim();
  return DEMO_ALLOWED_WRITE_PATHS.has(path);
}

function wantsJson(req) {
  const accept = String(req && req.headers && req.headers.accept ? req.headers.accept : '').toLowerCase();
  return accept.includes('application/json')
    || String(req && req.path ? req.path : '').startsWith('/api')
    || String(req && req.path ? req.path : '').startsWith('/admin/api');
}

function buildDemoReadOnlyMessage(lang = 'uk') {
  return lang === 'en'
    ? 'Demo mode is read-only. You can explore pages, but changes are not saved.'
    : 'Демо-режим доступний лише для перегляду. Можна оглядати сторінки, але зміни не зберігаються.';
}

function buildDemoReadonlyRedirect(req) {
  const fallback = getDemoRole(req) === 'teacher' ? '/teacher' : '/home';
  const referer = String(req && req.headers && req.headers.referer ? req.headers.referer : '');
  let targetPath = fallback;
  try {
    if (referer) {
      const parsed = new URL(referer, 'http://localhost');
      targetPath = `${parsed.pathname || fallback}${parsed.search || ''}`;
    }
  } catch (_err) {
    targetPath = fallback;
  }
  const separator = targetPath.includes('?') ? '&' : '?';
  return `${targetPath}${separator}demo_readonly=1`;
}

function subjectCopy(lang = 'uk') {
  if (lang === 'en') {
    return [
      { id: 101, name: 'Data Analysis', teacher: 'Iryna Kovalenko' },
      { id: 102, name: 'Public Policy Studio', teacher: 'Oleksandr Danyliuk' },
      { id: 103, name: 'Academic Communication', teacher: 'Marta Shevchenko' },
    ];
  }
  return [
    { id: 101, name: 'Аналіз даних', teacher: 'Ірина Коваленко' },
    { id: 102, name: 'Студія публічної політики', teacher: 'Олександр Данилюк' },
    { id: 103, name: 'Академічна комунікація', teacher: 'Марта Шевченко' },
  ];
}

function formatLocalDate(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function addDays(date, days) {
  const next = new Date(date);
  next.setDate(next.getDate() + days);
  return next;
}

function nextWeekdayDate(weekdayIndex) {
  const now = new Date();
  const current = now.getDay();
  const delta = (weekdayIndex - current + 7) % 7;
  return formatLocalDate(addDays(now, delta));
}

function getDemoSubjects(lang = 'uk', role = 'student') {
  return subjectCopy(lang).map((subject, index) => ({
    subject_id: subject.id,
    id: subject.id,
    subject_name: subject.name,
    name: subject.name,
    course_id: 1,
    owner_course_id: 1,
    course_name: lang === 'en' ? 'Demo course' : 'Демо-курс',
    group_count: 3,
    group_number: role === 'teacher' ? null : 1,
    group_numbers: role === 'teacher' ? [1, 2, 3] : [1],
    group_label: role === 'teacher'
      ? (lang === 'en' ? 'All groups' : 'Усі групи')
      : (lang === 'en' ? 'Group 1' : 'Група 1'),
    teacher_name: subject.teacher,
    sort_order: index + 1,
    show_in_teamwork: true,
  }));
}

function getDemoScheduleRows(lang = 'uk') {
  const subjects = subjectCopy(lang);
  return [
    { subject: subjects[0], day_of_week: 'Monday', class_number: 2, lesson_type: 'lecture', room_label: 'Campus A · 201' },
    { subject: subjects[1], day_of_week: 'Tuesday', class_number: 3, lesson_type: 'seminar', room_label: 'Campus B · 114' },
    { subject: subjects[2], day_of_week: 'Wednesday', class_number: 1, lesson_type: 'practice', room_label: 'Online' },
    { subject: subjects[0], day_of_week: 'Thursday', class_number: 4, lesson_type: 'lab', room_label: 'Lab 3' },
  ].map((row, index) => ({
    id: index + 1,
    subject_id: row.subject.id,
    subject_name: row.subject.name,
    subject: row.subject.name,
    group_number: 1,
    group_count: 3,
    day_of_week: row.day_of_week,
    class_number: row.class_number,
    week_number: 1,
    course_id: 1,
    semester_id: 1,
    lesson_type: row.lesson_type,
    room_label: row.room_label,
    class_date: nextWeekdayDate(['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].indexOf(row.day_of_week)),
    is_general: row.lesson_type === 'lecture',
  }));
}

function getDemoHomework(lang = 'uk') {
  const subjects = subjectCopy(lang);
  return [
    {
      id: 9001,
      subject_id: subjects[0].id,
      subject_name: subjects[0].name,
      subject: subjects[0].name,
      description: lang === 'en' ? 'Prepare a short dashboard insight.' : 'Підготувати короткий висновок для дашборда.',
      group_number: 1,
      class_number: 2,
      day: 'Monday',
      day_of_week: 'Monday',
      custom_due_date: formatLocalDate(addDays(new Date(), 3)),
      class_date: formatLocalDate(addDays(new Date(), 3)),
      created_by: subjects[0].teacher,
      created_at: new Date().toISOString(),
      course_id: 1,
      tags: [lang === 'en' ? 'demo' : 'демо'],
      reactions: {},
      reacted: {},
      assets: [],
    },
  ];
}

function getDemoTeamworkTasks(lang = 'uk') {
  const subjects = subjectCopy(lang);
  const title = lang === 'en' ? 'Policy brief prototype' : 'Прототип policy brief';
  return [{
    id: 7001,
    subject_id: subjects[1].id,
    subject_name: subjects[1].name,
    title,
    name: title,
    description: lang === 'en'
      ? 'Split into small teams and outline the problem, stakeholders, and first recommendation.'
      : 'Розділіться на команди та опишіть проблему, стейкхолдерів і першу рекомендацію.',
    due_date: formatLocalDate(addDays(new Date(), 5)),
    created_by: DEMO_USER_ID,
    created_by_name: subjects[1].teacher,
    group_count: 2,
    min_members: 2,
    max_members: 4,
    lesson_scope: 'seminar',
    audience_label: lang === 'en' ? 'Seminar groups 1-2' : 'Семінарські групи 1-2',
    can_create_groups: false,
    is_owner: false,
    group_lock_enabled: true,
    groups: [
      {
        id: 7101,
        task_id: 7001,
        name: lang === 'en' ? 'Research team' : 'Команда дослідження',
        leader_name: lang === 'en' ? 'Demo Student' : 'Демо Студент',
        leader_id: DEMO_USER_ID,
        seminar_group_number: 1,
        max_members: 4,
        is_leader: true,
        is_member: true,
        members: [
          { user_id: DEMO_USER_ID, member_name: lang === 'en' ? 'Demo Student' : 'Демо Студент' },
          { user_id: -1002, member_name: lang === 'en' ? 'Sample Classmate' : 'Демо Одногрупник' },
        ],
      },
    ],
    reactions: {},
    reacted: {},
  }];
}

function getDemoMaterials(lang = 'uk') {
  const subjects = subjectCopy(lang);
  return [
    {
      id: 8101,
      subject_id: subjects[0].id,
      title: lang === 'en' ? 'Demo syllabus overview' : 'Огляд демо-силабусу',
      description: lang === 'en'
        ? 'A short, read-only example of a pinned syllabus item.'
        : 'Короткий read-only приклад закріпленого силабусу.',
      material_type: 'syllabus',
      is_syllabus: true,
      group_label: lang === 'en' ? 'All groups' : 'Усі групи',
      created_by_name: subjects[0].teacher,
      created_at_label: lang === 'en' ? 'Today' : 'Сьогодні',
      link_url: 'https://www.ukma.edu.ua/',
      file_path: '',
    },
    {
      id: 8102,
      subject_id: subjects[0].id,
      title: lang === 'en' ? 'Lecture notes example' : 'Приклад конспекту лекції',
      description: lang === 'en'
        ? 'Shows how learning materials appear without exposing real files.'
        : 'Показує вигляд матеріалів без доступу до реальних файлів.',
      material_type: 'lecture',
      is_syllabus: false,
      group_label: lang === 'en' ? 'Group 1' : 'Група 1',
      created_by_name: subjects[0].teacher,
      created_at_label: lang === 'en' ? 'Yesterday' : 'Учора',
      link_url: '',
      file_path: '',
    },
  ];
}

function buildScheduleLocals({ lang = 'uk', role = 'student', username = '', bellSchedule = {}, daysOfWeek = [] } = {}) {
  const rows = getDemoScheduleRows(lang);
  const activeDays = Array.isArray(daysOfWeek) && daysOfWeek.length ? daysOfWeek : ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
  const scheduleByDay = {};
  const dayDates = {};
  activeDays.forEach((day) => {
    scheduleByDay[day] = rows.filter((row) => row.day_of_week === day);
    const weekdayIndex = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].indexOf(day);
    dayDates[day] = nextWeekdayDate(weekdayIndex > 0 ? weekdayIndex : 1);
  });
  const subjects = getDemoSubjects(lang, role);
  const homework = getDemoHomework(lang);
  const teamworkItems = getDemoTeamworkTasks(lang);
  return {
    scheduleByDay,
    daysOfWeek: activeDays,
    dayDates,
    currentWeek: 1,
    totalWeeks: 15,
    semester: {
      id: 1,
      title: lang === 'en' ? 'Demo semester' : 'Демо-семестр',
      weeks_count: 15,
      start_date: formatLocalDate(addDays(new Date(), -7)),
    },
    bellSchedule,
    group: lang === 'en' ? 'Demo group' : 'Демо-група',
    username,
    homework,
    homeworkMeta: {},
    homeworkMetaAll: {},
    homeworkTags: [lang === 'en' ? 'demo' : 'демо'],
    customDeadlinesByDate: {},
    weekendDeadlineCards: [],
    customDeadlineItems: homework,
    teamworkDeadlinesByDate: {},
    weekendTeamworkDeadlineCards: [],
    teamworkDeadlineItems: teamworkItems,
    customDeadlineSubjects: subjects,
    subgroupError: null,
    role,
    viewAs: null,
    viewAsCourse: null,
    viewAsGroupNumber: null,
    viewAsLabel: '',
    messageSubjects: subjects,
    userId: DEMO_USER_ID,
    selectedCourseId: 1,
    teacherHomeworkTemplates: role === 'teacher' ? getDemoTemplates(lang) : [],
    canCreateHomework: false,
    canUseCustomDeadlinesUi: false,
    scheduleAttendanceMarkers: {},
    canManageAttendance: false,
    projectionAlert: null,
    scheduleDebug: null,
  };
}

function buildMyDayLocals({ lang = 'uk', role = 'student', username = '' } = {}) {
  const subjects = getDemoSubjects(lang, role);
  const homework = getDemoHomework(lang);
  const scheduleRows = getDemoScheduleRows(lang);
  const isTeacher = normalizeDemoRole(role) === 'teacher';
  return {
    role,
    username,
    userId: DEMO_USER_ID,
    homeViewRole: role,
    viewAs: null,
    okMessage: '',
    errMessage: '',
    canUseCustomDeadlinesUi: false,
    myDay: {
      brief: {
        tone: 'focus',
        title: isTeacher
          ? (lang === 'en' ? 'Demo teacher workspace' : 'Демо-кабінет викладача')
          : (lang === 'en' ? 'Demo learning day' : 'Демо навчального дня'),
        subtitle: lang === 'en'
          ? 'Explore the interface with sample academic data.'
          : 'Огляньте інтерфейс на прикладі навчальних даних.',
        reasons: [
          lang === 'en' ? 'Read-only demo contour' : 'Ізольований read-only контур',
          lang === 'en' ? 'Sample schedule and deadlines' : 'Приклад розкладу та дедлайнів',
        ],
      },
      deadline_focus: homework,
      next_classes: scheduleRows.slice(0, 3),
      inbox_items: [],
      competencies: [
        { label: lang === 'en' ? 'Analysis' : 'Аналіз', value: 82, level: 'strong' },
        { label: lang === 'en' ? 'Communication' : 'Комунікація', value: 76, level: 'stable' },
      ],
      competency_manual_total_marks: 8,
      competency_auto_total_marks: 4,
      activity_summary: {
        on_time_share: 88,
        overdue: 0,
        risky_subjects: 1,
        recent_feedback: 2,
      },
      reminders: [
        {
          id: 1,
          title: lang === 'en' ? 'Check teamwork outline' : 'Переглянути план teamwork',
          due_date: formatLocalDate(addDays(new Date(), 2)),
        },
      ],
      review_queue: isTeacher ? {
        enabled: true,
        items: homework.map((item) => ({
          ...item,
          student_name: lang === 'en' ? 'Demo Student' : 'Демо Студент',
          queue_type: 'new',
          submission_status: 'on_time',
        })),
        templates: getDemoTemplates(lang),
        counts: { new: 1, overdue: 0, no_comment: 0 },
      } : { enabled: false, items: [], templates: [], counts: {} },
      progress_dashboard: {
        enabled: !isTeacher,
        subjects: subjects.map((subject, index) => ({
          subject_id: subject.subject_id,
          subject_name: subject.subject_name,
          average_percent: index === 0 ? 84 : 78,
          risk_level: index === 1 ? 'medium' : 'low',
        })),
      },
      teacher_competency_picker: {
        subjects: isTeacher ? subjects : [],
        selected_subject_id: isTeacher && subjects[0] ? subjects[0].subject_id : 0,
      },
      attendance_health: {
        status_key: 'stable',
        note_key: isTeacher ? 'teacher_steady' : 'student_watch',
        primary_window_days: 14,
        recent_window_days: 14,
        recent: { total: 3, absent: 0, late: 1 },
      },
      latest_rating_snapshot: {
        title: lang === 'en' ? 'Demo rating snapshot' : 'Демо-зріз рейтингу',
        updated_label: lang === 'en' ? 'Updated today' : 'Оновлено сьогодні',
      },
      inbox_message_summary: { fresh: 1, fresh_unread: 1 },
      inbox_message_items: [
        {
          message_kind: 'subject',
          message_title: lang === 'en' ? 'Demo announcement' : 'Демо-оголошення',
          body_preview: lang === 'en' ? 'Sample message from a teacher.' : 'Приклад повідомлення від викладача.',
          subject_name: subjects[0] ? subjects[0].subject_name : '',
          created_at: new Date().toISOString(),
        },
      ],
      support_summary: { open: 0, resolved: 1, total: 1, response: '' },
      support_threads: [],
      teacher_quick_actions: isTeacher ? [
        { label: lang === 'en' ? 'Open schedule' : 'Відкрити розклад', href: '/schedule' },
        { label: lang === 'en' ? 'Open templates' : 'Відкрити шаблони', href: '/teacher/workspace' },
      ] : [],
      what_if_subjects: subjects,
      what_if_default_subject_id: subjects[0] ? subjects[0].subject_id : 0,
      subjects,
    },
  };
}

function buildSubjectsLocals({ lang = 'uk', role = 'student', username = '', subjectId = null } = {}) {
  const subjects = getDemoSubjects(lang, role);
  const selectedSubject = subjectId
    ? (subjects.find((subject) => Number(subject.subject_id) === Number(subjectId)) || subjects[0] || null)
    : (subjects[0] || null);
  const materials = getDemoMaterials(lang).filter((item) => !selectedSubject || Number(item.subject_id) === Number(selectedSubject.subject_id));
  return {
    subjects,
    selectedSubjectId: selectedSubject ? selectedSubject.subject_id : null,
    selectedSubject,
    materials,
    materialAudienceOptions: [
      { value: '', label: lang === 'en' ? 'All groups' : 'Усі групи' },
      { value: '1', label: lang === 'en' ? 'Group 1' : 'Група 1' },
    ],
    messages: { error: '', success: '', operationId: '' },
    username,
    role,
    isTeacherMode: role === 'teacher',
    projectionAlert: null,
  };
}

function buildTeamworkLocals({ lang = 'uk', role = 'student', username = '', subjectId = null } = {}) {
  const subjects = getDemoSubjects(lang, role);
  const selectedSubject = subjectId
    ? (subjects.find((subject) => Number(subject.subject_id) === Number(subjectId)) || subjects[1] || subjects[0] || null)
    : (subjects[1] || subjects[0] || null);
  return {
    subjects,
    selectedSubjectId: selectedSubject ? selectedSubject.subject_id : null,
    selectedSubject,
    tasks: getDemoTeamworkTasks(lang),
    freeStudents: {},
    messages: { error: '', success: '', operationId: '' },
    username,
    role,
    isTeacherMode: role === 'teacher',
    projectionAlert: null,
  };
}

function getDemoTemplates(lang = 'uk') {
  const subject = subjectCopy(lang)[0];
  return [
    {
      id: 6101,
      subject_id: subject.id,
      subject_name: subject.name,
      title: lang === 'en' ? 'Weekly reflection template' : 'Шаблон щотижневої рефлексії',
      description: lang === 'en'
        ? 'Reusable homework draft shown only inside the demo.'
        : 'Багаторазова чернетка ДЗ, яка показується тільки в демо.',
      course_id: 1,
      course_name: lang === 'en' ? 'Demo course' : 'Демо-курс',
      group_number: null,
      files: [],
      assets: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];
}

function buildTeacherHubLocals({ lang = 'uk', username = '' } = {}) {
  const teacherCourses = [{ id: 1, name: lang === 'en' ? 'Demo course' : 'Демо-курс' }];
  const subjects = getDemoSubjects(lang, 'teacher');
  const templates = getDemoTemplates(lang);
  return {
    role: 'teacher',
    username,
    settings: {},
    stats: {
      subjects: subjects.length,
      courses: teacherCourses.length,
      templates: templates.length,
      assets: 1,
      created_homework: 3,
      recent_homework: 1,
    },
    teacherCourses,
    recentTemplates: templates,
    teacherAssets: [
      {
        id: 1,
        name: lang === 'en' ? 'Demo attachment pack' : 'Демо-набір матеріалів',
        original_name: '',
        file_path: '',
        created_at: new Date().toISOString(),
      },
    ],
    upcomingClasses: getDemoScheduleRows(lang).slice(0, 3),
    reviewQueue: buildMyDayLocals({ lang, role: 'teacher', username }).myDay.review_queue,
    teacherBrief: buildMyDayLocals({ lang, role: 'teacher', username }).myDay.brief,
    teacherTopPriorities: getDemoHomework(lang).slice(0, 2),
    teacherActivitySummary: { overdue: 0, recent_feedback: 3, on_time_share: 92 },
    latestRatingSnapshot: buildMyDayLocals({ lang, role: 'teacher', username }).myDay.latest_rating_snapshot,
    journalHubLinks: {
      journalHref: '/journal',
      insightsHref: '/journal/insights',
      scheduleHref: '/schedule',
    },
    error: '',
    success: '',
  };
}

function buildTeacherSubjectsLocals({ lang = 'uk', username = '' } = {}) {
  const subjects = getDemoSubjects(lang, 'teacher').map((subject) => ({
    id: subject.subject_id,
    name: subject.subject_name,
    course_id: subject.course_id,
    course_name: subject.course_name,
    group_count: subject.group_count,
    default_group: 1,
  }));
  const selections = new Map(subjects.map((subject) => [Number(subject.id), { group_number: null }]));
  return {
    role: 'teacher',
    username,
    settings: {},
    subjects,
    selections,
    selectionMode: 'legacy',
    workspaceHref: '/teacher/workspace',
    legacyRedirectState: { courseId: 1, studyContextId: null, semesterId: null },
    error: '',
    success: '',
  };
}

function buildTeacherWorkspaceLocals({ lang = 'uk', username = '' } = {}) {
  const teacherCourses = [{ id: 1, name: lang === 'en' ? 'Demo course' : 'Демо-курс' }];
  const teacherSubjects = getDemoSubjects(lang, 'teacher').map((subject) => ({
    id: subject.subject_id,
    name: subject.subject_name,
    course_id: subject.course_id,
    course_name: subject.course_name,
  }));
  return {
    role: 'teacher',
    username,
    settings: {},
    teacherCourses,
    workspaceCourseOptions: [],
    selectedCourseId: null,
    workspaceContextOptions: [],
    workspaceContextCatalog: [],
    selectedWorkspaceContextId: null,
    workspaceSemesterOptions: [],
    selectedWorkspaceSemesterId: null,
    teacherOfferings: [],
    workspaceCatalogOfferings: [],
    workspaceOfferingSelections: new Map(),
    workspaceAssignedOfferingDetails: new Map(),
    workspaceTemplatePlan: {
      visible_count: 0,
      selected_count: 0,
      counts: { create: 0, update: 0, deactivate: 0, keep: 0, idle: 0 },
      items: [],
    },
    teacherSubjects,
    teacherSubjectsAll: teacherSubjects,
    templates: getDemoTemplates(lang),
    assets: [],
    recentHomework: getDemoHomework(lang),
    showWorkspaceAdvancedPanels: false,
    showWorkspaceTemplateOnly: true,
    error: '',
    success: '',
  };
}

function buildProfileLocals({ lang = 'uk', role = 'student', username = '' } = {}) {
  return {
    role,
    username,
    user: {
      id: DEMO_USER_ID,
      full_name: username,
      language: lang === 'en' ? 'en' : 'uk',
    },
    teacherCourse: role === 'teacher',
    profileStats: {
      homeworkCreated: role === 'teacher' ? 3 : 0,
      teamworkCreated: role === 'teacher' ? 1 : 0,
      teamworkJoined: role === 'teacher' ? 0 : 2,
    },
    error: '',
    success: '',
  };
}

module.exports = {
  DEMO_USER_ID,
  normalizeDemoRole,
  isDemoSession,
  getDemoRole,
  getDemoVisitRoleKey,
  buildDemoUser,
  shouldAllowDemoWrite,
  wantsJson,
  buildDemoReadOnlyMessage,
  buildDemoReadonlyRedirect,
  buildScheduleLocals,
  buildMyDayLocals,
  buildSubjectsLocals,
  buildTeamworkLocals,
  buildTeacherHubLocals,
  buildTeacherSubjectsLocals,
  buildTeacherWorkspaceLocals,
  buildProfileLocals,
};
