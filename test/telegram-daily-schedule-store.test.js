const test = require('node:test');
const assert = require('node:assert/strict');
const { Pool } = require('pg');
const { createDailyScheduleStore } = require('../lib/studerriaTelegramDailyScheduleStore');
const migration = require('../migrations/067_telegram_daily_schedule_deliveries');

// Run against an isolated local PostgreSQL socket; never use the app's database credentials.
test('daily schedule roster and delivery claims use PostgreSQL constraints', {
  skip: !process.env.STUDERRIA_TEST_PG_SOCKET,
}, async (t) => {
  const schema = `daily_schedule_test_${process.pid}`;
  const pool = new Pool({ host: process.env.STUDERRIA_TEST_PG_SOCKET, database: 'postgres',
    user: process.env.USER, max: 3, options: `-c search_path=${schema}` });
  t.after(async () => {
    try { await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); } finally { await pool.end(); }
  });
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(`
    CREATE TABLE academic_v2_programs (id INTEGER PRIMARY KEY, name TEXT, is_active BOOLEAN, track_key TEXT);
    CREATE TABLE academic_v2_cohorts (id INTEGER PRIMARY KEY, program_id INTEGER, admission_year INTEGER, is_active BOOLEAN);
    CREATE TABLE academic_v2_groups (id INTEGER PRIMARY KEY, cohort_id INTEGER, legacy_course_id INTEGER,
      campus_key TEXT, label TEXT, is_active BOOLEAN);
    CREATE TABLE users (id INTEGER PRIMARY KEY, full_name TEXT, role TEXT, group_id INTEGER, course_id INTEGER,
      schedule_group TEXT, study_context_id INTEGER, telegram_id TEXT, telegram_username TEXT, is_active INTEGER);
    CREATE TABLE access_roles (id INTEGER PRIMARY KEY, key TEXT, is_active BOOLEAN);
    CREATE TABLE user_roles (user_id INTEGER, role_id INTEGER);
    INSERT INTO academic_v2_programs VALUES (1, 'ПЛЕД', true, 'bachelor');
    INSERT INTO academic_v2_cohorts VALUES (1, 1, 2025, true), (2, 1, 2026, true);
    INSERT INTO academic_v2_groups VALUES (20, 1, 10, 'kyiv', 'ПЛЕД 2025', true),
      (21, 2, 11, 'kyiv', 'ПЛЕД 2026', true), (22, 1, 12, 'kyiv', 'Архів', false);
    INSERT INTO access_roles VALUES (1, 'student', true), (2, 'starosta', true), (3, 'teacher', true);
    INSERT INTO users (id, full_name, role, group_id, course_id, telegram_id, is_active) VALUES
      (1, 'Stale legacy course', 'student', 20, 999, '1001', 1),
      (2, 'Starosta', 'starosta', 20, 10, '1002', 1),
      (3, 'Other current course', 'student', 21, 10, '1003', 1),
      (4, 'Inactive student', 'student', 20, 10, '1004', 0),
      (5, 'No Telegram', 'student', 20, 10, NULL, 1),
      (6, 'Teacher', 'teacher', 20, 10, '1006', 1),
      (7, 'Current student role', 'teacher', 20, 10, '1007', 1),
      (8, 'Current teacher role', 'student', 20, 10, '1008', 1),
      (9, 'Inactive group', 'student', 22, 10, '1009', 1),
      (10, 'Missing current group', 'student', NULL, 10, '1010', 1),
      (11, 'Malformed Telegram', 'student', 20, 10, 'unknown', 1);
    INSERT INTO user_roles VALUES (7, 1), (8, 3), (2, 2);
  `);
  let parameterQueries = 0;
  const query = (sql, params = []) => {
    parameterQueries += 1;
    let n = 0;
    return pool.query(sql.replace(/\?/g, () => `$${++n}`), params);
  };
  const store = createDailyScheduleStore({
    all: async (...args) => (await query(...args)).rows,
    get: async (...args) => (await query(...args)).rows[0] || null,
    run: query,
  });

  await t.test('uses the current academic group, active linked students and current student/starosta roles', async () => {
    const course = await store.loadCourse({ courseId: 10 });
    assert.equal(course.group_id, 20);
    assert.deepEqual((await store.loadStudents(course)).map((person) => person.id), [1, 2, 7]);
    const actorCourse = await store.loadCourse({ actorTelegramId: '1001' });
    assert.equal(actorCourse.course_id, 10);
    await assert.rejects(store.loadCourse({ courseId: 12 }), /активний студентський курс/);
    await assert.rejects(store.loadCourse({ courseId: 404 }), /активний студентський курс/);
  });

  await t.test('ambiguous course mapping is rejected instead of mixing student groups', async () => {
    await pool.query("INSERT INTO academic_v2_groups VALUES (23, 1, 10, 'munich', 'Мюнхен', true)");
    await assert.rejects(store.loadCourse({ courseId: 10 }), /один активний/);
    await pool.query('DELETE FROM academic_v2_groups WHERE id = 23');
  });

  await t.test('migration is repeatable and concurrent claims admit exactly one sender', async () => {
    await migration.up(pool);
    await migration.up(pool);
    const delivery = { key: 'automatic|2026-09-02|-100111|10', mode: 'automatic',
      targetIso: '2026-09-02', chatId: '-100111', threadId: null, courseId: 10 };
    const claims = await Promise.all(Array.from({ length: 8 }, () => store.claimDelivery(delivery)));
    assert.equal(claims.filter(Boolean).length, 1);
    const id = claims.find(Boolean).id;
    await store.finishDelivery(id, 'sent', 123);
    const recorded = (await pool.query('SELECT * FROM telegram_daily_schedule_deliveries WHERE id = $1', [id])).rows[0];
    assert.equal(recorded.status, 'sent');
    assert.equal(Number(recorded.message_id), 123);
    assert.equal(await store.claimDelivery(delivery), null);
    const manual = await store.claimDelivery({ ...delivery, key: 'manual|99:1', mode: 'manual' });
    assert.ok(manual);
    await store.finishDelivery(manual.id, 'uncertain', null, 'timeout');
    assert.equal(await store.claimDelivery({ ...delivery, key: 'manual|99:1', mode: 'manual' }), null);
    await assert.rejects(store.finishDelivery(manual.id, 'not_a_status'), /check constraint/);
    assert.ok(parameterQueries > 0);
  });
});
