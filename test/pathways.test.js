const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildAdmissionCampusChoicesFromCourses,
  buildCatalogAssignmentModeSummary,
  buildCatalogBindingSummary,
  buildRegistrationExperienceSummary,
  buildPathwayReadinessSummary,
  buildRegistrationReadinessAlert,
  buildSubjectVisibilityCopy,
  describeCatalogBinding,
} = require('../lib/pathways');
const {
  buildFailedPromotionTargetIssue,
  buildRegistrationCourseFallbackIssue,
  resolveAdminAcademicScopeState,
} = require('../lib/academicSetup');

test('pathway readiness becomes blocked without mapped courses', () => {
  const summary = buildPathwayReadinessSummary({
    mappedCourses: 0,
    visibleSubjects: 2,
    totalSubjects: 2,
    campusBindings: 1,
  });
  assert.equal(summary.status, 'blocked');
  assert.ok(summary.issues.includes('course_mapping'));
});

test('registration experience summary explains empty subject picker state', () => {
  const summary = buildPathwayReadinessSummary({
    mappedCourses: 1,
    visibleSubjects: 0,
    totalSubjects: 4,
    campusBindings: 1,
  });
  const experience = buildRegistrationExperienceSummary({
    summary,
    lang: 'en',
    mappedCourses: 1,
    visibleSubjects: 0,
    totalSubjects: 4,
    campusBindings: 1,
  });
  assert.equal(experience.tone, 'danger');
  assert.match(experience.title, /empty subject picker/i);
  assert.equal(experience.stages[1].state, 'blocked');
});

test('catalog binding summary counts shared and unassigned entries', () => {
  const summary = buildCatalogBindingSummary({
    lang: 'en',
    entries: [
      {
        id: 1,
        instances: [
          { is_shared: true, course_count: 3, is_visible: true },
          { is_shared: false, course_count: 1, is_visible: true },
        ],
      },
      {
        id: 2,
        instances: [],
      },
    ],
  });
  assert.equal(summary.metrics.shared_instances, 1);
  assert.equal(summary.metrics.separate_instances, 1);
  assert.equal(summary.metrics.unassigned_entries, 1);
  assert.match(summary.body, /not assigned to any course/i);
});

test('subject visibility copy explains partial visibility', () => {
  assert.match(buildSubjectVisibilityCopy({ visibleSubjects: 2, totalSubjects: 5 }), /2/);
});

test('catalog binding description distinguishes shared subjects', () => {
  assert.equal(
    describeCatalogBinding({ isShared: true, bindingCount: 3 }),
    'Shared catalog subject linked to 3 courses'
  );
});

test('registration readiness alert explains blocked mapping state', () => {
  const summary = buildPathwayReadinessSummary({
    mappedCourses: 0,
    visibleSubjects: 2,
    totalSubjects: 4,
    campusBindings: 0,
  });
  const alert = buildRegistrationReadinessAlert({
    summary,
    mappedCourses: 0,
    visibleSubjects: 2,
    totalSubjects: 4,
    campusBindings: 0,
  });
  assert.equal(alert.status, 'blocked');
  assert.match(alert.title, /mapping|мап/i);
});

test('admission campus choices mark ambiguous campuses and filter teacher track', () => {
  const choices = buildAdmissionCampusChoicesFromCourses([
    { id: 1, name: 'Course A', location: 'kyiv', is_teacher_course: 0 },
    { id: 2, name: 'Course B', location: 'kyiv', is_teacher_course: 0 },
    { id: 3, name: 'Teacher Course', location: 'munich', is_teacher_course: 1 },
  ], 'bachelor');
  assert.equal(choices.length, 1);
  assert.equal(choices[0].campus_key, 'kyiv');
  assert.equal(choices[0].is_ambiguous, true);

  const teacherChoices = buildAdmissionCampusChoicesFromCourses([
    { id: 3, name: 'Teacher Course', location: 'munich', is_teacher_course: 1 },
  ], 'teacher');
  assert.equal(teacherChoices[0].campus_key, 'munich');
  assert.equal(teacherChoices[0].is_ambiguous, false);
});

test('catalog assignment mode summary explains shared course propagation', () => {
  const summary = buildCatalogAssignmentModeSummary({
    sharedSubject: true,
    targetCourseCount: 3,
    lang: 'en',
  });
  assert.match(summary, /shared subject instance/i);
  assert.match(summary, /3 selected courses/i);
});

test('admin academic scope resolves explicit study context into derived course scope', () => {
  const state = resolveAdminAcademicScopeState({
    courses: [
      { id: 11, name: 'Course 1' },
      { id: 22, name: 'Course 2' },
    ],
    studyContexts: [
      {
        id: 77,
        course_id: 22,
        program_id: 9,
        admission_id: 15,
        admission_year: 2025,
        stage_number: 2,
        track_key: 'master',
        campus_key: 'munich',
        program_name: 'Public Leadership',
        program_code: 'PL',
      },
    ],
    requestedScope: {
      study_context_id: 77,
    },
    buildStudyContextLabel: (context) => `ctx:${context.id}`,
  });

  assert.equal(state.studyContextId, 77);
  assert.equal(state.courseId, 22);
  assert.equal(state.programId, 9);
  assert.equal(state.admissionId, 15);
  assert.equal(state.stage, 2);
  assert.equal(state.track, 'master');
  assert.equal(state.campus, 'munich');
});

test('registration fallback moderation issue keeps canonical payload contract', () => {
  const issue = buildRegistrationCourseFallbackIssue({
    userId: 4,
    programId: 10,
    admissionId: 25,
    trackKey: 'bachelor',
    campusKey: 'kyiv',
    stageNumber: 1,
    courseId: 3,
    studyContextId: null,
    fallbackSource: 'legacy_course_input',
  });

  assert.equal(issue.issueCode, 'registration_course_fallback');
  assert.match(issue.dedupeKey, /registration-course-fallback/);
  assert.equal(issue.payload.user_id, 4);
  assert.equal(issue.payload.program_id, 10);
  assert.equal(issue.payload.admission_id, 25);
  assert.equal(issue.payload.course_id, 3);
  assert.equal(issue.payload.study_context_id, null);
  assert.equal(issue.payload.fallback_source, 'legacy_course_input');
});

test('failed promotion moderation issue distinguishes missing placement case', () => {
  const issue = buildFailedPromotionTargetIssue({
    userId: 8,
    admissionId: 31,
    programId: 6,
    trackKey: 'master',
    courseId: 4,
    studyContextId: null,
    missingPlacement: true,
  });

  assert.equal(issue.issueCode, 'failed_promotion_target');
  assert.match(issue.title, /without canonical study context/i);
  assert.match(issue.dedupeKey, /missing-placement/);
  assert.equal(issue.payload.user_id, 8);
  assert.equal(issue.payload.admission_id, 31);
  assert.equal(issue.payload.program_id, 6);
});
