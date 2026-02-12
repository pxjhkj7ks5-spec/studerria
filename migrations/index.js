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
];
