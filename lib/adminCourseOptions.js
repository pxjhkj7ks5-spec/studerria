function normalizeText(value) {
  return String(value || '')
    .normalize('NFKC')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function normalizeCampus(value, label = '') {
  const combined = `${normalizeText(value)} ${normalizeText(label)}`;
  return /munich|мюнхен/.test(combined) ? 'munich' : 'kyiv';
}

function extractAdmissionYear(value) {
  const normalized = normalizeText(value);
  const fullYear = normalized.match(/\b(20\d{2})\b/);
  if (fullYear) return Number(fullYear[1]);
  const shortYear = normalized.match(/(?:^|\D)(\d{2})(?=\D|$)/);
  if (!shortYear) return null;
  return 2000 + Number(shortYear[1]);
}

function buildGroupIdentity(group = {}) {
  const programIdentity = normalizeText(`${group.program_code || ''} ${group.program_name || ''}`);
  if (!/\bpled\b|плед/.test(programIdentity)) return '';
  const admissionYear = Number(group.admission_year || 0);
  const courseId = Number(group.course_id || group.legacy_course_id || 0);
  if (!Number.isInteger(admissionYear) || admissionYear < 2000 || !Number.isInteger(courseId) || courseId < 1) {
    return '';
  }
  return `${admissionYear}:${normalizeCampus(group.campus_key || group.campus_label, group.group_label || group.label)}`;
}

function buildCourseIdentity(course = {}) {
  const label = normalizeText(course.name || course.label);
  if (!label || (!/\bpled\b|плед/.test(label) && !/^\d{2}\s+(київ|киев|kyiv|мюнхен|munich)\b/.test(label))) {
    return '';
  }
  const admissionYear = extractAdmissionYear(label);
  if (!admissionYear) return '';
  return `${admissionYear}:${normalizeCampus(course.location, label)}`;
}

function collapseAcademicCourseOptions(courses = [], academicGroups = []) {
  const courseList = Array.isArray(courses) ? courses : [];
  const groupList = Array.isArray(academicGroups) ? academicGroups : [];
  const canonicalCourseIdByIdentity = new Map();
  groupList.forEach((group) => {
    const identity = buildGroupIdentity(group);
    const courseId = Number(group.course_id || group.legacy_course_id || 0);
    if (identity && courseId > 0 && !canonicalCourseIdByIdentity.has(identity)) {
      canonicalCourseIdByIdentity.set(identity, courseId);
    }
  });

  const aliases = new Map();
  const visibleCourses = courseList.filter((course) => {
    if (course && (course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
      return true;
    }
    const identity = buildCourseIdentity(course);
    const canonicalCourseId = identity ? Number(canonicalCourseIdByIdentity.get(identity) || 0) : 0;
    const courseId = Number(course && course.id || 0);
    if (!canonicalCourseId || canonicalCourseId === courseId) {
      return true;
    }
    aliases.set(courseId, canonicalCourseId);
    return false;
  });

  return {
    courses: visibleCourses,
    aliases,
    resolveCourseId(courseId) {
      const normalizedCourseId = Number(courseId || 0);
      return Number(aliases.get(normalizedCourseId) || normalizedCourseId || 0) || null;
    },
  };
}

module.exports = {
  collapseAcademicCourseOptions,
  extractAdmissionYear,
};
