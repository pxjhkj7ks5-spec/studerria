const test = require('node:test');
const assert = require('node:assert/strict');

const academicV2Helpers = require('../lib/academicV2');
const {
  DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
  buildMinorCourseworkTemplateName,
  isBachelorCatalogContainerTitle,
  listBachelorCatalogEntries,
  listBachelorCatalogSources,
  mapBachelorSemesterColumnToStageTerm,
  normalizeBachelorCatalogEntry,
} = require('../lib/bachelorCatalog');

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function compactSql(sql) {
  return String(sql || '').replace(/\s+/g, ' ').trim();
}

function normalizeTemplateName(value) {
  return String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
}

function createMockAcademicV2Store(options = {}) {
  const programId = Number(options.programId || 11);
  const programTrack = String(options.programTrack || 'bachelor');
  const state = {
    subjectTemplates: cloneJson(options.subjectTemplates || []).map((row) => ({
      ...row,
      id: Number(row.id || 0),
      normalized_name: row.normalized_name || normalizeTemplateName(row.name),
      is_active: row.is_active !== false,
    })),
    stageTemplates: cloneJson(options.stageTemplates || []).map((row) => ({
      ...row,
      id: Number(row.id || 0),
      program_id: Number(row.program_id || programId),
      stage_number: Number(row.stage_number || 1),
    })),
    stageTermTemplates: cloneJson(options.stageTermTemplates || []).map((row) => ({
      ...row,
      id: Number(row.id || 0),
      stage_template_id: Number(row.stage_template_id || 0),
      term_number: Number(row.term_number || 1),
    })),
    stageSubjects: cloneJson(options.stageSubjects || []).map((row) => ({
      ...row,
      id: Number(row.id || 0),
      stage_template_id: Number(row.stage_template_id || 0),
      subject_template_id: Number(row.subject_template_id || 0),
      group_count: Number(row.group_count || 1) || 1,
      default_group: Number(row.default_group || 1) || 1,
      sort_order: Number(row.sort_order || 0) || 0,
      is_visible: row.is_visible !== false,
      is_required: row.is_required !== false,
      is_general: row.is_general !== false,
      show_in_teamwork: row.show_in_teamwork !== false,
    })),
    stageSubjectTerms: cloneJson(options.stageSubjectTerms || []).map((row) => ({
      stage_subject_template_id: Number(row.stage_subject_template_id || 0),
      stage_term_template_id: Number(row.stage_term_template_id || 0),
    })),
    stageSubjectActivities: cloneJson(options.stageSubjectActivities || []).map((row) => ({
      ...row,
      id: Number(row.id || 0),
      stage_subject_template_id: Number(row.stage_subject_template_id || 0),
      sort_order: Number(row.sort_order || 0) || 0,
    })),
  };

  const nextIds = {
    subjectTemplate: Math.max(0, ...state.subjectTemplates.map((row) => Number(row.id || 0))) + 1,
    stageTemplate: Math.max(0, ...state.stageTemplates.map((row) => Number(row.id || 0))) + 1,
    stageTermTemplate: Math.max(0, ...state.stageTermTemplates.map((row) => Number(row.id || 0))) + 1,
    stageSubject: Math.max(0, ...state.stageSubjects.map((row) => Number(row.id || 0))) + 1,
    stageSubjectActivity: Math.max(0, ...state.stageSubjectActivities.map((row) => Number(row.id || 0))) + 1,
  };

  const getStageTemplateById = (stageTemplateId) => (
    state.stageTemplates.find((row) => Number(row.id || 0) === Number(stageTemplateId || 0)) || null
  );

  const materializeStageSubject = (row) => {
    if (!row) {
      return null;
    }
    const stageTemplate = getStageTemplateById(row.stage_template_id) || {};
    return {
      ...row,
      program_id: Number(stageTemplate.program_id || 0),
      stage_number: Number(stageTemplate.stage_number || 0),
    };
  };

  const findStageSubject = ({ subjectTemplateId, stageNumber = null }) => (
    state.stageSubjects
      .map((row) => materializeStageSubject(row))
      .find((row) => (
        Number(row.program_id || 0) === programId
        && Number(row.subject_template_id || 0) === Number(subjectTemplateId || 0)
        && (stageNumber == null || Number(row.stage_number || 0) === Number(stageNumber || 0))
      ))
      || null
  );

  const tx = {
    get: async (sql, params = []) => {
      const query = compactSql(sql);

      if (query.includes('FROM academic_v2_programs')) {
        return Number(params[0] || 0) === programId
          ? { id: programId, name: 'Bachelor Program', track_key: programTrack }
          : null;
      }

      if (
        query.includes('FROM academic_v2_subject_templates')
        && query.includes('WHERE normalized_name = ?')
      ) {
        return state.subjectTemplates.find((row) => row.normalized_name === String(params[0] || '')) || null;
      }

      if (query.includes('INSERT INTO academic_v2_subject_templates')) {
        const row = {
          id: nextIds.subjectTemplate,
          name: String(params[0] || ''),
          normalized_name: String(params[1] || ''),
          is_active: true,
        };
        nextIds.subjectTemplate += 1;
        state.subjectTemplates.push(row);
        return { ...row };
      }

      if (
        query.includes('FROM academic_v2_program_stage_templates')
        && query.includes('WHERE program_id = ?')
        && query.includes('AND stage_number = ?')
      ) {
        return state.stageTemplates.find((row) => (
          Number(row.program_id || 0) === Number(params[0] || 0)
          && Number(row.stage_number || 0) === Number(params[1] || 0)
        )) || null;
      }

      if (query.includes('INSERT INTO academic_v2_program_stage_templates')) {
        const row = {
          id: nextIds.stageTemplate,
          program_id: Number(params[0] || 0),
          stage_number: Number(params[1] || 1),
        };
        nextIds.stageTemplate += 1;
        state.stageTemplates.push(row);
        return { ...row };
      }

      if (
        query.includes('FROM academic_v2_program_stage_subject_templates stage_subject')
        && query.includes('WHERE stage_template.program_id = ?')
        && query.includes('AND stage_template.stage_number = ?')
        && query.includes('AND stage_subject.subject_template_id = ?')
      ) {
        return findStageSubject({
          subjectTemplateId: params[2],
          stageNumber: params[1],
        });
      }

      if (
        query.includes('FROM academic_v2_program_stage_subject_templates stage_subject')
        && query.includes('WHERE stage_template.program_id = ?')
        && query.includes('AND stage_subject.subject_template_id = ?')
        && !query.includes('AND stage_template.stage_number = ?')
      ) {
        return findStageSubject({
          subjectTemplateId: params[1],
        });
      }

      if (
        query.includes('FROM academic_v2_program_stage_subject_templates stage_subject')
        && query.includes('WHERE stage_subject.id = ?')
        && query.includes('AND stage_template.program_id = ?')
      ) {
        const matched = materializeStageSubject(
          state.stageSubjects.find((row) => Number(row.id || 0) === Number(params[0] || 0))
        );
        if (!matched || Number(matched.program_id || 0) !== Number(params[1] || 0)) {
          return null;
        }
        return matched;
      }

      if (
        query.includes('FROM academic_v2_program_stage_subject_activities')
        && query.includes('WHERE stage_subject_template_id = ?')
        && query.includes('AND activity_type = ?')
      ) {
        return state.stageSubjectActivities.find((row) => (
          Number(row.stage_subject_template_id || 0) === Number(params[0] || 0)
          && String(row.activity_type || '') === String(params[1] || '')
        )) || null;
      }

      if (query.includes('INSERT INTO academic_v2_program_stage_term_templates')) {
        const row = {
          id: nextIds.stageTermTemplate,
          stage_template_id: Number(params[0] || 0),
          term_number: Number(params[1] || 1),
          title: String(params[2] || ''),
          weeks_count: Number(params[3] || 0) || 15,
          is_active_default: Boolean(params[4]),
          sort_order: Number(params[5] || 0),
        };
        nextIds.stageTermTemplate += 1;
        state.stageTermTemplates.push(row);
        return { id: row.id, term_number: row.term_number };
      }

      if (query.includes('INSERT INTO academic_v2_program_stage_subject_templates')) {
        const row = {
          id: nextIds.stageSubject,
          stage_template_id: Number(params[0] || 0),
          subject_template_id: Number(params[1] || 0),
          title: String(params[2] || ''),
          group_count: 1,
          default_group: 1,
          is_visible: Boolean(params[3]),
          is_required: Boolean(params[4]),
          is_general: Boolean(params[5]),
          show_in_teamwork: Boolean(params[6]),
          sort_order: 0,
        };
        nextIds.stageSubject += 1;
        state.stageSubjects.push(row);
        return { ...row };
      }

      if (
        query.includes('UPDATE academic_v2_program_stage_subject_templates')
        && query.includes('SET stage_template_id = ?')
      ) {
        const row = state.stageSubjects.find((item) => Number(item.id || 0) === Number(params[3] || 0));
        if (!row) {
          return null;
        }
        row.stage_template_id = Number(params[0] || 0);
        row.is_required = Boolean(params[1]);
        row.is_general = Boolean(params[2]);
        return { ...row };
      }

      if (
        query.includes('UPDATE academic_v2_program_stage_subject_templates')
        && !query.includes('SET stage_template_id = ?')
      ) {
        const row = state.stageSubjects.find((item) => Number(item.id || 0) === Number(params[2] || 0));
        if (!row) {
          return null;
        }
        row.is_required = Boolean(params[0]);
        row.is_general = Boolean(params[1]);
        return { ...row };
      }

      throw new Error(`Unhandled get query in bachelor catalog test: ${query}`);
    },
    all: async (sql, params = []) => {
      const query = compactSql(sql);

      if (
        query.includes('FROM academic_v2_program_stage_term_templates')
        && query.includes('WHERE stage_template_id = ?')
      ) {
        return state.stageTermTemplates
          .filter((row) => Number(row.stage_template_id || 0) === Number(params[0] || 0))
          .sort((left, right) => (
            Number(left.term_number || 0) - Number(right.term_number || 0)
            || Number(left.id || 0) - Number(right.id || 0)
          ))
          .map((row) => ({ ...row }));
      }

      throw new Error(`Unhandled all query in bachelor catalog test: ${query}`);
    },
    run: async (sql, params = []) => {
      const query = compactSql(sql);

      if (query.includes('INSERT INTO academic_v2_program_stage_subject_terms')) {
        const stageSubjectTemplateId = Number(params[0] || 0);
        const stageTermTemplateId = Number(params[1] || 0);
        const exists = state.stageSubjectTerms.some((row) => (
          Number(row.stage_subject_template_id || 0) === stageSubjectTemplateId
          && Number(row.stage_term_template_id || 0) === stageTermTemplateId
        ));
        if (!exists) {
          state.stageSubjectTerms.push({
            stage_subject_template_id: stageSubjectTemplateId,
            stage_term_template_id: stageTermTemplateId,
          });
        }
        return;
      }

      if (query.includes('INSERT INTO academic_v2_program_stage_subject_activities')) {
        state.stageSubjectActivities.push({
          id: nextIds.stageSubjectActivity,
          stage_subject_template_id: Number(params[0] || 0),
          activity_type: String(params[1] || ''),
          sort_order: Number(params[2] || 0),
        });
        nextIds.stageSubjectActivity += 1;
        return;
      }

      if (query === 'DELETE FROM academic_v2_program_stage_subject_terms WHERE stage_subject_template_id = ?') {
        const stageSubjectTemplateId = Number(params[0] || 0);
        state.stageSubjectTerms = state.stageSubjectTerms.filter((row) => (
          Number(row.stage_subject_template_id || 0) !== stageSubjectTemplateId
        ));
        return;
      }

      if (
        query.includes('UPDATE academic_v2_program_stage_term_templates')
        && query.includes('SET title = ?')
        && query.includes('weeks_count = ?')
        && query.includes('sort_order = ?')
      ) {
        const row = state.stageTermTemplates.find((item) => Number(item.id || 0) === Number(params[3] || 0));
        if (!row) {
          return;
        }
        row.title = String(params[0] || '');
        row.weeks_count = Number(params[1] || 0) || row.weeks_count;
        row.sort_order = Number(params[2] || 0);
        return;
      }

      if (query === 'DELETE FROM academic_v2_program_stage_subject_templates WHERE id = ?') {
        const stageSubjectTemplateId = Number(params[0] || 0);
        state.stageSubjects = state.stageSubjects.filter((row) => Number(row.id || 0) !== stageSubjectTemplateId);
        state.stageSubjectTerms = state.stageSubjectTerms.filter((row) => (
          Number(row.stage_subject_template_id || 0) !== stageSubjectTemplateId
        ));
        state.stageSubjectActivities = state.stageSubjectActivities.filter((row) => (
          Number(row.stage_subject_template_id || 0) !== stageSubjectTemplateId
        ));
        return;
      }

      throw new Error(`Unhandled run query in bachelor catalog test: ${query}`);
    },
  };

  return {
    state,
    withTransaction: async (work) => work(tx),
  };
}

test('bachelor catalog container-title helper excludes minor and block headers', () => {
  assert.equal(isBachelorCatalogContainerTitle('Minor "Африканістика"'), true);
  assert.equal(isBachelorCatalogContainerTitle('Навчальні дисципліни вільного вибору'), true);
  assert.equal(isBachelorCatalogContainerTitle('Філософія'), false);
});

test('bachelor semester-column mapper resolves stage and term pairs', () => {
  assert.deepEqual(mapBachelorSemesterColumnToStageTerm(10), { stage_number: 1, term_number: 1 });
  assert.deepEqual(mapBachelorSemesterColumnToStageTerm(17), { stage_number: 3, term_number: 2 });
  assert.equal(mapBachelorSemesterColumnToStageTerm(12), null);
});

test('minor coursework template builder appends the minor suffix for duplicate titles', () => {
  assert.equal(
    buildMinorCourseworkTemplateName('Міждисциплінарна курсова робота за Minor', 'Африканістика'),
    'Міждисциплінарна курсова робота за Minor (Африканістика)'
  );
  assert.equal(
    buildMinorCourseworkTemplateName('Філософія', 'Африканістика'),
    'Філософія'
  );
});

test('bachelor catalog entry normalizer adds default flags and lecture+seminar preset', () => {
  const normalized = normalizeBachelorCatalogEntry({
    source_code: '1.1.10.',
    template_name: 'Філософія',
    display_title: 'Філософія',
    source_section: '1.1. Обов\'язкові освітні компоненти',
    suggested_stage_number: 1,
    suggested_term_numbers: [2],
    entry_kind: 'subject',
  });

  assert.equal(normalized.source_key, DEFAULT_BACHELOR_CATALOG_SOURCE_KEY);
  assert.equal(normalized.default_activity_preset, 'lecture_seminar');
  assert.equal(normalized.default_flags.is_required, true);
  assert.equal(normalized.default_flags.is_general, true);
});

test('bachelor catalog entry normalizer auto-suffixes duplicated minor coursework template names', () => {
  const normalized = normalizeBachelorCatalogEntry({
    source_code: '2.1.1.7.',
    template_name: 'Міждисциплінарна курсова робота за Minor',
    display_title: 'Міждисциплінарна курсова робота за Minor',
    source_section: '2.1. Minor',
    entry_kind: 'coursework',
    minor_name: 'Африканістика',
  });

  assert.equal(normalized.template_name, 'Міждисциплінарна курсова робота за Minor (Африканістика)');
  assert.equal(normalized.display_title, 'Міждисциплінарна курсова робота за Minor');
});

test('bachelor catalog source registry exposes the expected seed size', () => {
  const sources = listBachelorCatalogSources();
  const source = sources.find((item) => item.key === DEFAULT_BACHELOR_CATALOG_SOURCE_KEY);

  assert.ok(source);
  assert.equal(source.entry_count, 77);
  assert.equal(listBachelorCatalogEntries(DEFAULT_BACHELOR_CATALOG_SOURCE_KEY).length, 77);
});

test('buildBachelorCatalogRows marks default row as seeded when stage, terms, flags, and activities match', async () => {
  const rows = await academicV2Helpers.buildBachelorCatalogRows({}, {
    programId: 11,
    sourceKey: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
    subjectTemplates: [
      { id: 7, name: 'Філософія' },
    ],
    stageTermTemplates: [
      { id: 101, program_id: 11, stage_number: 1, term_number: 2 },
    ],
    stageSubjectTemplates: [
      {
        id: 201,
        program_id: 11,
        stage_number: 1,
        subject_template_name: 'Філософія',
        stage_term_template_ids: [101],
        is_required: true,
        is_general: true,
        activity_types: ['lecture', 'seminar'],
        title: 'Філософія',
      },
    ],
  });

  const row = rows.find((item) => item.source_code === '1.1.10.');
  assert.ok(row);
  assert.equal(row.status.code, 'seeded');
  assert.deepEqual(row.current_term_numbers, [2]);
});

test('buildBachelorCatalogRows marks manual overrides as customized', async () => {
  const rows = await academicV2Helpers.buildBachelorCatalogRows({}, {
    programId: 11,
    sourceKey: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
    subjectTemplates: [
      { id: 7, name: 'Філософія' },
    ],
    stageTermTemplates: [
      { id: 102, program_id: 11, stage_number: 4, term_number: 1 },
    ],
    stageSubjectTemplates: [
      {
        id: 202,
        program_id: 11,
        stage_number: 4,
        subject_template_name: 'Філософія',
        stage_term_template_ids: [102],
        is_required: false,
        is_general: false,
        activity_types: ['lecture', 'seminar', 'practice'],
        title: 'Філософія',
      },
    ],
  });

  const row = rows.find((item) => item.source_code === '1.1.10.');
  assert.ok(row);
  assert.equal(row.status.code, 'customized');
  assert.equal(row.current_stage_number, 4);
  assert.equal(row.current_is_general, false);
  assert.equal(row.current_is_required, false);
});

test('syncBachelorCatalogSource creates missing templates, term 1/2/3, and lecture+seminar activities', async () => {
  const store = createMockAcademicV2Store();

  const result = await academicV2Helpers.syncBachelorCatalogSource(store, {
    program_id: 11,
    source_key: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
  });

  const philosophyTemplate = store.state.subjectTemplates.find((row) => row.name === 'Філософія');
  assert.ok(philosophyTemplate);
  assert.ok(result.createdTemplateCount > 0);
  assert.ok(result.createdStageSubjectCount > 0);

  const stageOneTemplate = store.state.stageTemplates.find((row) => row.program_id === 11 && row.stage_number === 1);
  assert.ok(stageOneTemplate);
  const stageOneTerms = store.state.stageTermTemplates
    .filter((row) => row.stage_template_id === stageOneTemplate.id)
    .map((row) => row.term_number)
    .sort((left, right) => left - right);
  assert.deepEqual(stageOneTerms, [1, 2, 3]);

  const philosophyStageSubject = store.state.stageSubjects.find((row) => (
    row.stage_template_id === stageOneTemplate.id
    && row.subject_template_id === philosophyTemplate.id
  ));
  assert.ok(philosophyStageSubject);

  const philosophyActivities = store.state.stageSubjectActivities
    .filter((row) => row.stage_subject_template_id === philosophyStageSubject.id)
    .map((row) => row.activity_type)
    .sort();
  assert.deepEqual(philosophyActivities, ['lecture', 'seminar']);
});

test('syncBachelorCatalogSource does not overwrite manual required/general flags or extra activities', async () => {
  const store = createMockAcademicV2Store({
    subjectTemplates: [
      { id: 7, name: 'Філософія' },
    ],
    stageTemplates: [
      { id: 21, program_id: 11, stage_number: 1 },
    ],
    stageTermTemplates: [
      { id: 31, stage_template_id: 21, term_number: 1, title: 'Term 1', weeks_count: 15, is_active_default: true, sort_order: 1 },
      { id: 32, stage_template_id: 21, term_number: 2, title: 'Term 2', weeks_count: 15, is_active_default: false, sort_order: 2 },
    ],
    stageSubjects: [
      {
        id: 41,
        stage_template_id: 21,
        subject_template_id: 7,
        title: 'Філософія',
        is_required: false,
        is_general: false,
      },
    ],
    stageSubjectTerms: [
      { stage_subject_template_id: 41, stage_term_template_id: 32 },
    ],
    stageSubjectActivities: [
      { id: 51, stage_subject_template_id: 41, activity_type: 'lecture', sort_order: 10 },
      { id: 52, stage_subject_template_id: 41, activity_type: 'seminar', sort_order: 20 },
      { id: 53, stage_subject_template_id: 41, activity_type: 'practice', sort_order: 30 },
    ],
  });

  await academicV2Helpers.syncBachelorCatalogSource(store, {
    program_id: 11,
    source_key: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
  });

  const row = store.state.stageSubjects.find((item) => item.id === 41);
  assert.ok(row);
  assert.equal(row.is_required, false);
  assert.equal(row.is_general, false);
  assert.deepEqual(
    store.state.stageSubjectActivities
      .filter((item) => item.stage_subject_template_id === 41)
      .map((item) => item.activity_type)
      .sort(),
    ['lecture', 'practice', 'seminar']
  );
});

test('saveBachelorCatalogRow creates a row, auto-creates term 1/2/3, and applies lecture+seminar by default', async () => {
  const store = createMockAcademicV2Store();

  await academicV2Helpers.saveBachelorCatalogRow(store, {
    program_id: 11,
    source_key: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
    source_code: '1.1.10.',
    stage_number: 3,
    term_numbers: [1],
    is_required: '1',
    is_general: '0',
  });

  const philosophyTemplate = store.state.subjectTemplates.find((row) => row.name === 'Філософія');
  assert.ok(philosophyTemplate);

  const stageTemplate = store.state.stageTemplates.find((row) => row.program_id === 11 && row.stage_number === 3);
  assert.ok(stageTemplate);
  assert.deepEqual(
    store.state.stageTermTemplates
      .filter((row) => row.stage_template_id === stageTemplate.id)
      .map((row) => row.term_number)
      .sort((left, right) => left - right),
    [1, 2, 3]
  );

  const stageSubject = store.state.stageSubjects.find((row) => (
    row.stage_template_id === stageTemplate.id
    && row.subject_template_id === philosophyTemplate.id
  ));
  assert.ok(stageSubject);
  assert.equal(stageSubject.is_required, true);
  assert.equal(stageSubject.is_general, false);

  const assignedTerms = store.state.stageSubjectTerms
    .filter((row) => row.stage_subject_template_id === stageSubject.id)
    .map((row) => store.state.stageTermTemplates.find((term) => term.id === row.stage_term_template_id))
    .filter(Boolean)
    .map((row) => row.term_number)
    .sort((left, right) => left - right);
  assert.deepEqual(assignedTerms, [1]);

  assert.deepEqual(
    store.state.stageSubjectActivities
      .filter((row) => row.stage_subject_template_id === stageSubject.id)
      .map((row) => row.activity_type)
      .sort(),
    ['lecture', 'seminar']
  );
});

test('saveBachelorCatalogRow preserves extra practice activity on existing rows while updating flags and terms', async () => {
  const store = createMockAcademicV2Store({
    subjectTemplates: [
      { id: 7, name: 'Філософія' },
    ],
    stageTemplates: [
      { id: 21, program_id: 11, stage_number: 1 },
    ],
    stageTermTemplates: [
      { id: 31, stage_template_id: 21, term_number: 1, title: 'Term 1', weeks_count: 15, is_active_default: true, sort_order: 1 },
      { id: 32, stage_template_id: 21, term_number: 2, title: 'Term 2', weeks_count: 15, is_active_default: false, sort_order: 2 },
    ],
    stageSubjects: [
      {
        id: 41,
        stage_template_id: 21,
        subject_template_id: 7,
        title: 'Філософія',
        is_required: true,
        is_general: true,
      },
    ],
    stageSubjectTerms: [
      { stage_subject_template_id: 41, stage_term_template_id: 31 },
    ],
    stageSubjectActivities: [
      { id: 51, stage_subject_template_id: 41, activity_type: 'lecture', sort_order: 10 },
      { id: 52, stage_subject_template_id: 41, activity_type: 'seminar', sort_order: 20 },
      { id: 53, stage_subject_template_id: 41, activity_type: 'practice', sort_order: 30 },
    ],
  });

  await academicV2Helpers.saveBachelorCatalogRow(store, {
    program_id: 11,
    source_key: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
    source_code: '1.1.10.',
    stage_subject_template_id: 41,
    stage_number: 1,
    term_numbers: [2],
    is_required: '0',
    is_general: '0',
  });

  const stageSubject = store.state.stageSubjects.find((row) => row.id === 41);
  assert.ok(stageSubject);
  assert.equal(stageSubject.is_required, false);
  assert.equal(stageSubject.is_general, false);

  const assignedTerms = store.state.stageSubjectTerms
    .filter((row) => row.stage_subject_template_id === 41)
    .map((row) => store.state.stageTermTemplates.find((term) => term.id === row.stage_term_template_id))
    .filter(Boolean)
    .map((row) => row.term_number)
    .sort((left, right) => left - right);
  assert.deepEqual(assignedTerms, [2]);

  assert.deepEqual(
    store.state.stageSubjectActivities
      .filter((row) => row.stage_subject_template_id === 41)
      .map((row) => row.activity_type)
      .sort(),
    ['lecture', 'practice', 'seminar']
  );
});
