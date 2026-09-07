const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('schedule preferences migration defaults full view off and supports three day formats', () => {
  const source = fs.readFileSync(path.join(__dirname, '../migrations/068_studerria_schedule_preferences.js'), 'utf8');
  assert.match(source, /show_full_schedule BOOLEAN NOT NULL DEFAULT false/);
  assert.match(source, /delivery_mode IN \('offline', 'online', 'mixed'\)/);
});

test('mini subject picker clears the old group when not taught is selected', () => {
  const source = fs.readFileSync(path.join(__dirname, '../public/js/tg-mini.js'), 'utf8');
  assert.match(source, /input\[type="checkbox"\]\[name\^="optout_"\][\s\S]*?radio\.checked = false/);
  assert.match(source, /input\[type="radio"\]\[name\^="subject_"\][\s\S]*?optout\.checked = false/);
});

test('student and course schedule loaders expose room and delivery mode', () => {
  for (const file of ['academicV2Students.js', 'academicV2Runtime.js']) {
    const source = fs.readFileSync(path.join(__dirname, `../lib/${file}`), 'utf8');
    assert.match(source, /LEFT JOIN rooms room ON room\.id = se\.room_id/);
    assert.match(source, /academic_v2_group_day_formats day_format/);
    assert.match(source, /delivery_mode:/);
  }
});
