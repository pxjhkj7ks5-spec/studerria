const init = require('./001_init');
const teachers = require('./002_teachers');
const weekTime = require('./003_week_time');
const scheduleGenerator = require('./004_schedule_generator');
const scheduleGeneratorMirror = require('./005_schedule_generator_mirror');
const coursesLocation = require('./006_courses_location');

module.exports = [init, teachers, weekTime, scheduleGenerator, scheduleGeneratorMirror, coursesLocation];
