const test = require('node:test');
const assert = require('node:assert/strict');
const { listBachelorCatalogEntries } = require('../lib/bachelorCatalog');
const academic = require('../lib/academicV2');
const migration = require('../migrations/066_pled_year2_first_term_catalog');

const scheduleTitles = [
  'Академічна іноземна мова', 'Мікроекономіка', 'Політичні системи сучасності. Політична компаративістика',
  'Соціологія', 'Міжнародні економічні відносини', 'Історія європейської цивілізації. Культурна спадщина Європи',
  'Політична психологія та нейромаркетинг', 'Іспанська мова', 'Німецька мова',
];
const militaryTitle = 'Базова загальна військова підготовка громадян України, які здобувають вищу освіту (теоретична підготовка)*';
const targetEntries = () => listBachelorCatalogEntries().filter((e) => e.suggested_stage_number === 2 && e.suggested_term_numbers.includes(1));

test('year 2 first-term defaults contain exactly the PDF subjects plus optional BZVP', () => {
  const entries = targetEntries();
  assert.deepEqual(entries.map((e) => e.display_title).sort(), [...scheduleTitles, militaryTitle].sort());
  assert.equal(entries.find((e) => e.source_code === '2.2.2.').default_flags.is_required, false);
  for (const name of ['Академічна іноземна мова', 'Іспанська мова']) {
    assert.equal(entries.find((e) => e.display_title === name).default_activity_preset, 'seminar_only');
  }
  const expected = [[3, true], [2, true], [2, true], [2, true], [2, true], [1, false], [1, false], [2, false], [1, false], [1, false]];
  [...scheduleTitles, militaryTitle].forEach((title, index) => {
    const entry = entries.find((e) => e.display_title === title);
    assert.deepEqual([entry.default_group_count, entry.default_flags.is_required], expected[index]);
  });
  const academicLanguage = listBachelorCatalogEntries().filter((e) => e.template_name === scheduleTitles[0]);
  assert.equal(academicLanguage.length, 2);
  assert.deepEqual(academicLanguage.find((e) => e.suggested_stage_number === 1).suggested_term_numbers, [1, 2]);
  for (const code of ['1.1.16.', '1.1.20.', '2.2.1.1.', '2.2.1.2.', '2.2.2.']) {
    assert.ok(listBachelorCatalogEntries().find((e) => e.source_code === code).suggested_term_numbers.includes(2));
  }
});

test('catalog reconciliation requires a transaction', async () => {
  await assert.rejects(academic.alignPledYear2FirstTermCatalog({}), /TRANSACTION_REQUIRED/);
});

test('required-subject lectures are common while seminars follow the selected group', async () => {
  const vm = require('node:vm');
  const fs = require('node:fs');
  const modulePath = require.resolve('../lib/academicV2Students');
  const subject = { subject_id: 1, group_count: 2, default_group: 1, selected_group: 1, is_required: true };
  const context = vm.createContext({
    require: require('node:module').createRequire(modulePath), module: { exports: {} }, console,
    fixtureState: { scope: { group_id: 1, legacy_course_id: 1 }, term: { id: 1, legacy_semester_id: 1 }, subjects: [subject], allSubjects: [subject], projectionIssues: {} },
  });
  vm.runInContext(fs.readFileSync(modulePath, 'utf8') + '\nloadStudentSubjectCatalog = async () => fixtureState;', context);
  const rows = [
    { schedule_entry_id: 1, activity_type: 'lecture', target_group_numbers: [], group_number: 1 },
    { schedule_entry_id: 2, activity_type: 'seminar', target_group_numbers: [1], group_number: 1 },
    { schedule_entry_id: 3, activity_type: 'seminar', target_group_numbers: [2], group_number: 2 },
  ].map((row) => ({ ...row, group_subject_id: 1, group_subject_activity_id: 1, legacy_subject_id: 1, is_visible: true, is_required: true, group_count: 2, default_group: 1, day_of_week: 'Monday', class_number: row.schedule_entry_id, week_number: 1 }));
  for (const group of [1, 2]) {
    subject.selected_group = group;
    const result = await context.module.exports.loadStudentScheduleData({ all: async () => rows }, 1, { weekNumber: 1 });
    assert.equal(result.scheduleRows.length, 2);
    assert.ok(result.scheduleRows.some((row) => row.schedule_entry_id === 1));
    assert.ok(result.scheduleRows.some((row) => row.schedule_entry_id === group + 1));
  }
});

// Optional integration test: always creates its own disposable database on an isolated Unix socket.
test('PostgreSQL migration aligns existing catalogs without deleting subjects or changing other semesters', {
  skip: !process.env.KMA_CATALOG_TEST_PGSOCKET,
}, async (t) => {
  const { Pool } = require('pg');
  const host = process.env.KMA_CATALOG_TEST_PGSOCKET;
  assert.match(host, /^\/tmp\/kma-catalog-pg\.[a-zA-Z0-9]+$/);
  const config = { host, port: 55487, user: process.env.USER, max: 4 };
  const admin = new Pool({ ...config, database: 'postgres' });
  const database = `kma_catalog_test_${process.pid}`;
  await admin.query(`CREATE DATABASE ${database}`);
  const pool = new Pool({ ...config, database });
  t.after(async () => { await pool.end(); await admin.query(`DROP DATABASE ${database}`); await admin.end(); });
  for (const item of require('../migrations').filter((m) => m.id < migration.id)) await item.up(pool);
  const get = async (sql, params) => (await pool.query(sql, params)).rows[0];
  const rows = async (sql, params) => (await pool.query(sql, params)).rows;
  const program = await get("INSERT INTO academic_v2_programs (track_key, code, name) VALUES ('bachelor','PLED','ПЛЕД') RETURNING id");
  const otherProgram = await get("INSERT INTO academic_v2_programs (track_key, code, name) VALUES ('master','OTHER','Other') RETURNING id");
  const stage = await get('INSERT INTO academic_v2_program_stage_templates (program_id, stage_number) VALUES ($1,2) RETURNING id', [program.id]);
  const firstYear = await get('INSERT INTO academic_v2_program_stage_templates (program_id, stage_number) VALUES ($1,1) RETURNING id', [program.id]);
  const otherStage = await get('INSERT INTO academic_v2_program_stage_templates (program_id, stage_number) VALUES ($1,2) RETURNING id', [otherProgram.id]);
  const terms = [];
  for (const stageId of [stage.id, firstYear.id, otherStage.id]) for (const n of [1, 2]) {
    terms.push(await get('INSERT INTO academic_v2_program_stage_term_templates (stage_template_id,term_number,title,start_date,weeks_count) VALUES ($1,$2,$3,\'2026-09-01\',15) RETURNING *', [stageId, n, `Term ${n}`]));
  }
  const cohort = await get('INSERT INTO academic_v2_cohorts (program_id,admission_year,label) VALUES ($1,2025,\'25\') RETURNING id', [program.id]);
  const groups = [];
  for (const campus of ['kyiv', 'munich']) {
    const group = await get('INSERT INTO academic_v2_groups (cohort_id,stage_number,campus_key,label) VALUES ($1,2,$2,$2) RETURNING id', [cohort.id, campus]);
    group.terms = [];
    for (const n of [1, 2]) group.terms.push(await get('INSERT INTO academic_v2_terms (group_id,term_number,title,start_date,weeks_count,is_active) VALUES ($1,$2,$3,\'2026-09-01\',15,$4) RETURNING *', [group.id, n, `Term ${n}`, n === 1]));
    groups.push(group);
  }
  const extra = listBachelorCatalogEntries().find((e) => e.source_code === '1.1.17.');
  // Existing data omits academic foreign language and psychology and includes an extra subject.
  const oldEntries = [...targetEntries().filter((e) => !e.source_code.startsWith('schedule.')), extra];
  for (const entry of oldEntries) {
    const template = await get('INSERT INTO academic_v2_subject_templates (name,normalized_name) VALUES ($1,$2) RETURNING id', [entry.template_name, entry.template_name.toLowerCase()]);
    for (const stageId of [stage.id, firstYear.id, otherStage.id]) {
      const subject = await get('INSERT INTO academic_v2_program_stage_subject_templates (stage_template_id,subject_template_id,title,group_count,is_required) VALUES ($1,$2,$3,2,TRUE) RETURNING id', [stageId, template.id, entry.display_title]);
      for (const type of ['lecture', 'seminar']) await pool.query('INSERT INTO academic_v2_program_stage_subject_activities (stage_subject_template_id,activity_type) VALUES ($1,$2)', [subject.id, type]);
      for (const term of terms.filter((term) => term.stage_template_id === stageId)) await pool.query('INSERT INTO academic_v2_program_stage_subject_terms (stage_subject_template_id,stage_term_template_id) VALUES ($1,$2)', [subject.id, term.id]);
    }
    for (const group of groups) {
      const subject = await get('INSERT INTO academic_v2_group_subjects (group_id,subject_template_id,title,group_count,is_required) VALUES ($1,$2,$3,2,TRUE) RETURNING id', [group.id, template.id, entry.display_title]);
      for (const type of ['lecture', 'seminar']) await pool.query('INSERT INTO academic_v2_group_subject_activities (group_subject_id,activity_type) VALUES ($1,$2)', [subject.id, type]);
      for (const term of group.terms) await pool.query('INSERT INTO academic_v2_group_subject_terms (group_subject_id,term_id) VALUES ($1,$2)', [subject.id, term.id]);
    }
  }
  const targetTerm = terms.find((term) => term.stage_template_id === stage.id && term.term_number === 1);
  const otherLinks = () => rows('SELECT * FROM academic_v2_program_stage_subject_terms WHERE stage_term_template_id <> $1 ORDER BY 1,2', [targetTerm.id]);
  const otherGroupLinks = () => rows('SELECT * FROM academic_v2_group_subject_terms WHERE term_id = ANY($1::int[]) ORDER BY 1,2', [groups.map((g) => g.terms[1].id)]);
  const oldStageLinks = await otherLinks();
  const oldGroupLinks = await otherGroupLinks();
  const originalTermRows = await rows('SELECT * FROM academic_v2_terms ORDER BY id');
  const oldSubjectIds = (await rows('SELECT id FROM academic_v2_group_subjects ORDER BY id')).map((s) => s.id);
  const scheduledSubject = await get("SELECT s.id,a.id AS activity_id FROM academic_v2_group_subjects s JOIN academic_v2_group_subject_activities a ON a.group_subject_id=s.id WHERE s.title='Мікроекономіка' AND a.activity_type='lecture' ORDER BY s.id LIMIT 1");
  await pool.query(`INSERT INTO academic_v2_schedule_entries (group_subject_id,group_subject_activity_id,term_id,day_of_week,class_number,week_number,lesson_type,target_group_numbers)
    VALUES ($1,$2,$3,'Tuesday',4,1,'lecture',ARRAY[]::int[])`, [scheduledSubject.id, scheduledSubject.activity_id, groups[0].terms[0].id]);
  const originalSchedule = await rows('SELECT * FROM academic_v2_schedule_entries ORDER BY id');

  // Inject a failure after backups/partial writes and prove the entire operation rolls back.
  await pool.query(`CREATE FUNCTION reject_catalog_link() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced migration failure'; END $$`);
  await pool.query('CREATE TRIGGER reject_catalog_link BEFORE INSERT ON academic_v2_group_subject_terms FOR EACH ROW EXECUTE FUNCTION reject_catalog_link()');
  await assert.rejects(migration.up(pool), /forced migration failure/);
  assert.deepEqual(await otherLinks(), oldStageLinks);
  assert.equal(Number((await get("SELECT COUNT(*) FROM history_log WHERE action='pled_year2_term1_catalog_align_2026'")).count), 0);
  await pool.query('DROP TRIGGER reject_catalog_link ON academic_v2_group_subject_terms');
  await migration.up(pool);

  const currentTitles = await rows(`SELECT s.title FROM academic_v2_program_stage_subject_terms l
    JOIN academic_v2_program_stage_subject_templates s ON s.id=l.stage_subject_template_id
    WHERE l.stage_term_template_id=$1 ORDER BY s.title`, [targetTerm.id]);
  assert.deepEqual(currentTitles.map((r) => r.title).sort(), [...scheduleTitles, militaryTitle].sort());
  assert.deepEqual(await otherLinks(), oldStageLinks);
  assert.deepEqual(await otherGroupLinks(), oldGroupLinks);
  assert.deepEqual(await rows('SELECT * FROM academic_v2_terms ORDER BY id'), originalTermRows);
  assert.deepEqual(await rows('SELECT * FROM academic_v2_schedule_entries ORDER BY id'), originalSchedule);
  for (const group of groups) {
    const subjects = await rows(`SELECT s.* FROM academic_v2_group_subject_terms l JOIN academic_v2_group_subjects s ON s.id=l.group_subject_id WHERE l.term_id=$1`, [group.terms[0].id]);
    assert.equal(subjects.length, 10);
    assert.ok(subjects.every((s) => s.legacy_subject_id));
    assert.equal(subjects.find((s) => s.title === militaryTitle).is_required, false);
    for (const entry of targetEntries()) {
      const subject = subjects.find((s) => s.title === entry.display_title);
      assert.equal(subject.group_count, entry.default_group_count);
      assert.equal(subject.is_required, entry.default_flags.is_required);
      const legacy = await get('SELECT group_count,is_required FROM subjects WHERE id=$1', [subject.legacy_subject_id]);
      assert.equal(legacy.group_count, entry.default_group_count);
      assert.equal(legacy.is_required, entry.default_flags.is_required);
      const activities = await rows('SELECT activity_type FROM academic_v2_group_subject_activities WHERE group_subject_id=$1 ORDER BY activity_type', [subject.id]);
      assert.deepEqual(activities.map((a) => a.activity_type), entry.default_activity_preset === 'seminar_only' ? ['seminar'] : ['lecture', 'seminar']);
    }
  }
  const remainingIds = new Set((await rows('SELECT id FROM academic_v2_group_subjects')).map((s) => s.id));
  assert.ok(oldSubjectIds.every((id) => remainingIds.has(id)));
  const audit = await get("SELECT details FROM history_log WHERE action='pled_year2_term1_catalog_align_2026' ORDER BY id DESC LIMIT 1");
  assert.ok(JSON.parse(audit.details).backup.stage_links.length);
  const english = await get("SELECT id FROM academic_v2_group_subjects WHERE title='Академічна іноземна мова' ORDER BY id LIMIT 1");
  const wrongActivity = await get("INSERT INTO academic_v2_group_subject_activities (group_subject_id,activity_type) VALUES ($1,'lecture') RETURNING id", [english.id]);
  const wrongEntry = await get(`INSERT INTO academic_v2_schedule_entries (group_subject_id,group_subject_activity_id,term_id,day_of_week,class_number)
    VALUES ($1,$2,$3,'Monday',3) RETURNING id`, [english.id, wrongActivity.id, groups[0].terms[0].id]);
  await assert.rejects(migration.up(pool), /PLED_LANGUAGE_NON_SEMINAR_SCHEDULE_REQUIRES_REVIEW/);
  assert.ok(await get('SELECT id FROM academic_v2_schedule_entries WHERE id=$1', [wrongEntry.id]));
  await pool.query('DELETE FROM academic_v2_schedule_entries WHERE id=$1', [wrongEntry.id]);
  await pool.query('DELETE FROM academic_v2_group_subject_activities WHERE id=$1', [wrongActivity.id]);
  // Reapplying and subsequent source sync must not reintroduce removed semester-1 defaults.
  await migration.up(pool);
  let placeholder = (sql) => { let n=0; return sql.replace(/\?/g, () => `$${++n}`); };
  await academic.syncBachelorCatalogSource({
    get: (sql, params) => get(placeholder(sql), params),
    all: (sql, params) => rows(placeholder(sql), params),
    run: (sql, params) => pool.query(placeholder(sql), params),
  }, { program_id: program.id });
  assert.equal(Number((await get('SELECT COUNT(*) FROM academic_v2_program_stage_subject_terms WHERE stage_term_template_id=$1', [targetTerm.id])).count), 10);
});
