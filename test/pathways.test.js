const test = require('node:test');
const assert = require('node:assert/strict');

const {
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
