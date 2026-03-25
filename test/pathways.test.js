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
