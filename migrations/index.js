const init = require('./001_init');
const teachers = require('./002_teachers');
const weekTime = require('./003_week_time');
const scheduleGenerator = require('./004_schedule_generator');
const scheduleGeneratorMirror = require('./005_schedule_generator_mirror');
const coursesLocation = require('./006_courses_location');
const scheduleGeneratorRepair = require('./007_schedule_generator_repair');
const scheduleGeneratorEntryItem = require('./008_schedule_generator_entry_item');
const scheduleEntryLessonType = require('./009_schedule_entry_lesson_type');
const mergeSubjectsByType = require('./010_merge_subjects_by_type');
const scheduleGeneratorIndexes = require('./011_schedule_generator_indexes');
const rbacRoles = require('./012_rbac_roles');
const siteVisitEvents = require('./013_site_visit_events');
const teamworkTeacherTaskConfig = require('./014_teamwork_teacher_task_config');
const teamworkTaskScopeLock = require('./015_teamwork_task_scope_lock');
const teamworkGroupsSeminarGroupNumber = require('./016_teamwork_groups_seminar_group_number');
const subjectMaterials = require('./017_subject_materials');
const subjectMaterialsSyllabus = require('./018_subject_materials_syllabus');
const journalGradebook = require('./019_journal_gradebook');
const journalWeightedConfig = require('./020_journal_weighted_config');
const journalGradeUndoAndLock = require('./021_journal_grade_undo_and_lock');
const attendanceMvp = require('./022_attendance_mvp');
const journalRetakeAttempts = require('./023_journal_retake_attempts');
const journalGradeAppeals = require('./024_journal_grade_appeals');
const adminChangeAudit = require('./025_admin_change_audit');
const journalSubjectClosure = require('./026_journal_subject_closure');
const journalModerationCompetencies = require('./027_journal_moderation_competencies');

module.exports = [
  init,
  teachers,
  weekTime,
  scheduleGenerator,
  scheduleGeneratorMirror,
  coursesLocation,
  scheduleGeneratorRepair,
  scheduleGeneratorEntryItem,
  scheduleEntryLessonType,
  mergeSubjectsByType,
  scheduleGeneratorIndexes,
  rbacRoles,
  siteVisitEvents,
  teamworkTeacherTaskConfig,
  teamworkTaskScopeLock,
  teamworkGroupsSeminarGroupNumber,
  subjectMaterials,
  subjectMaterialsSyllabus,
  journalGradebook,
  journalWeightedConfig,
  journalGradeUndoAndLock,
  attendanceMvp,
  journalRetakeAttempts,
  journalGradeAppeals,
  adminChangeAudit,
  journalSubjectClosure,
  journalModerationCompetencies,
];
