const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const ejs = require('ejs');

const viewsDir = path.join(__dirname, '..', 'views');

test('topbar partial tolerates missing navigation locals', async () => {
  const html = await ejs.renderFile(path.join(viewsDir, 'partials', 'topbar.ejs'), {
    role: 'admin',
    username: 'Test User',
    t: (key) => key,
  }, {
    filename: path.join(viewsDir, 'partials', 'topbar.ejs'),
  });

  assert.match(html, /studerria-navbar|navbar/i);
});

test('admin pathways page renders without explicit nav locals', async () => {
  const html = await ejs.renderFile(path.join(viewsDir, 'admin-pathways.ejs'), {
    lang: 'uk',
    t: (key) => key,
    role: 'admin',
    username: 'test',
    settings: {},
    changelog: [],
    appVersion: '1.2.65',
    error: '',
    success: '',
    courses: [],
    selectedCourseId: 0,
    trackFilter: 'all',
    trackFilterOptions: [
      { key: 'all', label: 'All' },
      { key: 'bachelor', label: 'Bachelor' },
    ],
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
    migrationSummary: {
      total_courses: 0,
      mapped_courses: 0,
      candidate_users: 0,
      already_assigned: 0,
      pending_users: 0,
    },
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
    canManagePathways: true,
    pathwaysPanelHref: '/admin/pathways',
    selectedStudyContextId: 0,
    selectedProgramPresetId: 0,
    moderationStatus: 'open',
    studyContexts: [],
    selectedStudyContext: null,
    selectedStudyContextSemesters: [],
    selectedStudyContextOfferings: [],
    programPresets: [],
    selectedProgramPreset: null,
    presetSubjectCatalogOptions: [],
    selectedContextPresetPreview: null,
    selectedAdmissionPresetPreview: null,
    moderationQueue: [],
  }, {
    filename: path.join(viewsDir, 'admin-pathways.ejs'),
  });

  assert.match(html, /pathways|траєктор/i);
});
