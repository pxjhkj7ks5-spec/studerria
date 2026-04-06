const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');
const academicV2Helpers = require('../lib/academicV2');

const viewsDir = path.join(__dirname, '..', 'views');

function withFallbackLocals(base = {}) {
  return new Proxy(base, {
    has(target, prop) {
      if (prop === Symbol.unscopables) {
        return false;
      }
      if (Object.prototype.hasOwnProperty.call(target, prop)) {
        return true;
      }
      return !(prop in globalThis);
    },
    get(target, prop) {
      if (prop === Symbol.unscopables) {
        return undefined;
      }
      if (Object.prototype.hasOwnProperty.call(target, prop)) {
        return target[prop];
      }
      return undefined;
    },
  });
}

function baseScope() {
  return {
    track: 'bachelor',
    programId: 0,
    admissionId: 0,
    stage: 1,
    campus: 'kyiv',
    studyContextId: null,
    courseId: 1,
    label: 'Bachelor / Kyiv',
    trackOptions: [{ value: 'bachelor', label: 'Bachelor' }],
    programOptions: [{ id: 0, label: 'All programs' }],
    admissionOptions: [{ id: 0, admission_year: 2025, label: '2025' }],
    stageOptions: [{ value: 1, label: 'Year 1' }],
    campusOptions: [{ value: 'kyiv', label: 'Kyiv' }],
    availableStudyContexts: [],
  };
}

function baseRenderLocals(overrides = {}) {
  return withFallbackLocals({
    lang: 'uk',
    role: 'admin',
    username: 'Smoke User',
    userId: 1,
    t: (key) => key,
    settings: {
      role_permissions: {},
      allow_messages: false,
    },
    changelog: [],
    appVersion: '1.3.01',
    courses: [{ id: 1, name: 'Course 1', location: 'kyiv', is_teacher_course: 0 }],
    selectedCourseId: 1,
    adminAcademicScope: baseScope(),
    adminHomeHref: '/admin?track=bachelor&course=1',
    allowCourseSelect: false,
    limitedStaffView: false,
    allowedSections: null,
    activeAdminTab: '',
    schedule: [],
    homework: [],
    homeworkTags: [],
    users: [],
    subjects: [],
    studentGroups: [],
    logs: [],
    activityLogs: [],
    activityTop: [],
    dashboardStats: {
      users: 0,
      subjects: 0,
      homework: 0,
      teamworkTasks: 0,
      teamworkGroups: 0,
      teamworkMembers: 0,
    },
    teamworkTasks: [],
    adminMessages: [],
    supportRequests: [],
    selectedSupportRequest: null,
    supportSectionVisible: false,
    teacherRequests: [],
    semesters: [],
    semestersByCourse: {},
    activeSemester: null,
    weeklyLabels: [],
    weeklyHomework: [],
    weeklyTeamwork: [],
    weeklyUserRoles: [],
    weeklyUserSeries: [],
    settingsMeta: null,
    rolePermissions: {},
    defaultRolePermissions: {},
    adminSectionOptions: [],
    rbacRoles: [],
    rbacPermissionOptions: [],
    courseKindOptions: [],
    userRoleAssignments: {},
    userPrimaryRoleMap: {},
    activeScheduleDays: ['monday'],
    filters: {},
    usersStatus: 'active',
    sorts: {},
    historyFilters: {},
    activityFilters: {},
    messages: { error: '', success: '', operationId: '' },
    deaneryMonitoring: null,
    backLink: '/admin?track=bachelor&course=1',
    ...overrides,
  });
}

async function renderView(relativePath, locals) {
  const filename = path.join(viewsDir, relativePath);
  return ejs.renderFile(filename, locals, { filename });
}

test('admin shell renders with canonical academic scope helpers', async () => {
  const html = await renderView('admin.ejs', baseRenderLocals());
  assert.match(html, /admin|Overview|Academic Setup/i);
});

test('admin overview renders with canonical scope locals', async () => {
  const html = await renderView('admin-overview.ejs', baseRenderLocals({
    dashboardStats: { users: 1, subjects: 2, homework: 3, teamworkTasks: 0, teamworkGroups: 0, teamworkMembers: 0 },
    coursePulse: { summary: {}, subjects: [] },
  }));
  assert.match(html, /dashboard|overview/i);
});

test('admin overview surfaces compatibility warning text', async () => {
  const html = await renderView('admin-overview.ejs', baseRenderLocals({
    dashboardStats: { users: 0, subjects: 0, homework: 0, teamworkTasks: 0, teamworkGroups: 0, teamworkMembers: 0 },
    overviewCompatibilityWarning: 'Academic V2 scope is missing for this course.',
    coursePulse: { summary: {}, subjects: [] },
  }));
  assert.match(html, /Academic V2 scope is missing for this course\./i);
});

test('admin overview and export routes do not keep legacy course fallback clauses', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const overviewStart = source.indexOf("app.get('/admin/overview'");
  const overviewEnd = source.indexOf("app.get('/__version'", overviewStart);
  const overviewBlock = source.slice(overviewStart, overviewEnd > overviewStart ? overviewEnd : overviewStart + 9000);
  assert.match(overviewBlock, /allowLegacyFallback:\s*false/);
  assert.doesNotMatch(overviewBlock, /legacy_course_id\s*=\s*\?/);

  const exportStart = source.indexOf("app.get('/admin/export/users.csv'");
  const exportEnd = source.indexOf("app.post('/admin/import/users.csv'", exportStart);
  const exportBlock = source.slice(exportStart, exportEnd > exportStart ? exportEnd : exportStart + 4000);
  assert.match(exportBlock, /u\.course_id\s*=\s*\?/);
  assert.doesNotMatch(exportBlock, /legacy_course_id/);
});

test('admin pathways renders moderation and compatibility sections', async () => {
  const html = await renderView('admin-pathways.ejs', baseRenderLocals({
    canManagePathways: true,
    pathwaysPanelHref: '/admin/pathways',
    error: '',
    success: '',
    trackFilter: 'bachelor',
    trackFilterOptions: [{ key: 'bachelor', label: 'Bachelor' }],
    programs: [],
    filteredPrograms: [],
    selectedProgramId: 0,
    admissions: [],
    selectedProgramAdmissions: [],
    admissionHealthCards: [],
    selectedAdmissionId: 0,
    admissionCopyOptions: [],
    courseMappings: [],
    registrationCampusBindings: [],
    ambiguousCampusBindings: [],
    selectedAdmissionLegacyOrdinal: 0,
    legacySuggestedCourseCount: 0,
    mappingSummary: { total: 0, visible: 0 },
    migrationSummary: { total_courses: 0, mapped_courses: 0, candidate_users: 0, already_assigned: 0, pending_users: 0 },
    selectedCourseLabel: '',
    selectedCohortHealth: null,
    registrationExperienceSummary: null,
    cohortAlerts: [],
    subjectVisibilityItems: [],
    subjectCatalogEntries: [],
    subjectCatalogSummary: { metrics: {} },
    migrationCourseOptions: [],
    hiddenSubjectCount: 0,
    visibilitySummary: { total: 0, visible: 0, hidden: 0 },
    moderationQueueList: [],
    moderationStatusValue: 'open',
    studyContextList: [],
    selectedStudyContextValue: 0,
    selectedStudyContextItem: null,
    selectedStudyContextSemestersList: [],
    selectedStudyContextOfferingsList: [],
  }));
  assert.match(html, /Compatibility tools|Moderation|Pathways/i);
});

test('admin academic v2 renders bachelor catalog panel only for bachelor programs', async () => {
  const fallback = academicV2Helpers.buildAcademicSetupPageFallback({
    programId: 1,
    templateStageNumber: 1,
    bachelorCatalogSourceKey: 'bachelor_bp_pled_2025',
  });
  const commonLocals = {
    ...fallback,
    error: '',
    success: '',
    warning: '',
    requestedSubjectId: 0,
    requestedWorkspaceTab: 'subjects',
    requestedScheduleEntryId: 0,
    focus: {
      ...fallback.focus,
      programId: 1,
      bachelorCatalogSourceKey: 'bachelor_bp_pled_2025',
    },
    bachelorCatalogSources: [{
      key: 'bachelor_bp_pled_2025',
      track_key: 'bachelor',
      label: 'БП 2025-2026',
      title: 'Політичне лідерство та економічна дипломатія',
      description: 'Seed source',
      entry_count: 77,
    }],
    bachelorCatalogRows: [{
      source_key: 'bachelor_bp_pled_2025',
      source_code: '1.1.10.',
      template_name: 'Філософія',
      display_title: 'Філософія',
      source_section: '1.1. Обов\'язкові освітні компоненти',
      entry_kind: 'subject',
      suggested_stage_number: 1,
      suggested_term_numbers: [2],
      current_stage_subject_template_id: 0,
      current_stage_number: null,
      current_term_numbers: [],
      current_is_general: true,
      current_is_required: true,
      status: {
        code: 'unassigned',
        label: 'Unassigned',
        tone: 'warm',
      },
    }],
  };

  const bachelorHtml = await renderView('admin-academic-v2.ejs', baseRenderLocals({
    ...commonLocals,
    programs: [{ id: 1, name: 'Bachelor Program', track_key: 'bachelor' }],
    selectedProgram: { id: 1, name: 'Bachelor Program', track_key: 'bachelor' },
  }));
  assert.match(bachelorHtml, /Кодовий бакалаврський каталог/i);
  assert.match(bachelorHtml, /Sync source → program/i);

  const masterHtml = await renderView('admin-academic-v2.ejs', baseRenderLocals({
    ...commonLocals,
    programs: [{ id: 1, name: 'Master Program', track_key: 'master' }],
    selectedProgram: { id: 1, name: 'Master Program', track_key: 'master' },
  }));
  assert.doesNotMatch(masterHtml, /Кодовий бакалаврський каталог/i);
});

test('teacher workspace renders context-first filter surface', async () => {
  const html = await renderView('teacher-workspace.ejs', baseRenderLocals({
    role: 'teacher',
    teacherCourses: [],
    workspaceCourseOptions: [{ id: 1, name: 'Course 1' }],
    workspaceContextOptions: [{ id: 7, label: 'PL 2025 / Year 1 / Kyiv', course_id: 1 }],
    selectedWorkspaceContextId: 7,
    workspaceSemesterOptions: [{ id: 3, title: 'Fall semester', semester_number: 1 }],
    selectedWorkspaceSemesterId: 3,
    teacherOfferings: [],
    workspaceCatalogOfferings: [],
    workspaceOfferingSelections: [],
    workspaceAssignedOfferingDetails: new Map(),
    workspaceTemplatePlan: { create: 0, update: 0, deactivate: 0, keep: 0, items: [] },
    teacherSubjects: [],
    teacherSubjectsAll: [],
    templates: [],
    assets: [],
    recentHomework: [],
    error: '',
    success: '',
  }));
  assert.match(html, /Teacher workspace|study_context_id|Live teaching scope/i);
});

test('teacher subjects renders as compatibility wrapper with workspace escape hatch', async () => {
  const html = await renderView('teacher-subjects.ejs', baseRenderLocals({
    role: 'teacher',
    subjects: [{ id: 11, name: 'Policy Lab', course_name: 'PL 2025', group_count: 2, is_general: 0, pathway_labels: 'Master / 2025' }],
    selections: new Map([[11, 2]]),
    selectionMode: 'offering',
    workspaceHref: '/teacher/workspace?study_context_id=7',
    legacyRedirectState: { courseId: 1, studyContextId: 7, semesterId: 3 },
    error: '',
    success: '',
  }));
  assert.match(html, /Legacy teacher subjects|Open teacher workspace|Compatibility teaching scope/i);
});

test('register teacher subjects renders workspace guidance for profile edit', async () => {
  const html = await renderView('register-teacher-subjects.ejs', baseRenderLocals({
    role: 'teacher',
    subjects: [{ id: 11, name: 'Policy Lab', course_name: 'PL 2025', group_count: 2, is_general: 0, pathway_labels: 'Master / 2025' }],
    selections: new Map([[11, 2]]),
    selectionMode: 'offering',
    error: '',
    isProfileEdit: true,
  }));
  assert.match(html, /Teacher workspace|legacy compatibility picker|selection_mode/i);
});

test('register course renders academic context preview flow', async () => {
  const html = await renderView('register-course.ejs', baseRenderLocals({
    lang: 'en',
    error: '',
    selectedCourseId: null,
    selectedCampus: 'kyiv',
    selectedTrack: 'bachelor',
    selectedProgramId: null,
    selectedAdmissionId: null,
    selectedStudyContextId: null,
    registrationPathways: {
      tracks: [{ key: 'bachelor', enabled: true }],
      programs: [],
      admissions: [],
      links: [],
      courses: [],
    },
    registrationStudyContexts: [],
  }));
  assert.match(html, /Academic context preview|Admission year|Campus/i);
});
