const test = require('node:test');
const assert = require('node:assert/strict');
const { collapseAcademicCourseOptions } = require('../lib/adminCourseOptions');

test('admin course switcher keeps one canonical PLED option per intake and campus', () => {
  const result = collapseAcademicCourseOptions([
    { id: 1, name: 'ПЛЕД 26 Київ', location: 'kyiv' },
    { id: 2, name: 'ПЛЕД 25 Київ', location: 'kyiv' },
    { id: 3, name: 'ПЛЕД 25 Мюнхен', location: 'munich' },
    { id: 4, name: 'Викладацький трек', is_teacher_course: 1 },
    { id: 11, name: '26 Київ', location: 'kyiv' },
    { id: 12, name: '25 Київ', location: 'kyiv' },
    { id: 13, name: '25 Мюнхен', location: 'munich' },
  ], [
    { course_id: 11, admission_year: 2026, campus_key: 'kyiv', program_code: 'PLED' },
    { course_id: 12, admission_year: 2025, campus_key: 'kyiv', program_code: 'PLED' },
    { course_id: 13, admission_year: 2025, campus_key: 'munich', program_code: 'PLED' },
  ]);

  assert.deepEqual(result.courses.map((course) => course.id), [4, 11, 12, 13]);
  assert.equal(result.resolveCourseId(1), 11);
  assert.equal(result.resolveCourseId(2), 12);
  assert.equal(result.resolveCourseId(3), 13);
  assert.equal(result.resolveCourseId(4), 4);
});
