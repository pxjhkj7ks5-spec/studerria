const test = require('node:test');
const assert = require('node:assert/strict');

const academicV2Helpers = require('../lib/academicV2');
const academicV2StudentHelpers = require('../lib/academicV2Students');

function compactSql(sql) {
  return String(sql || '').replace(/\s+/g, ' ').trim();
}

function createOverlayStore(stageRows = []) {
  return {
    all: async (sql) => {
      const query = compactSql(sql);
      if (query.includes('FROM academic_v2_program_stage_subject_templates')) {
        return stageRows;
      }
      throw new Error(`Unexpected query: ${query}`);
    },
  };
}

function createLiveRow(overrides = {}) {
  return {
    group_subject_id: 91,
    subject_template_id: 17,
    subject_title: 'Філософія',
    template_name: 'Філософія',
    group_count: 2,
    default_group: 1,
    is_visible: true,
    is_required: true,
    is_general: true,
    show_in_teamwork: true,
    sort_order: 10,
    legacy_subject_id: 501,
    ...overrides,
  };
}

function createStageRow(overrides = {}) {
  return {
    stage_subject_template_id: 31,
    subject_template_id: 17,
    subject_title: 'Філософія',
    template_name: 'Філософія',
    group_count: 2,
    default_group: 1,
    is_visible: true,
    is_required: true,
    is_general: true,
    show_in_teamwork: true,
    sort_order: 10,
    term_numbers: [2],
    ...overrides,
  };
}

test('bachelor overlay keeps a row when stage match exists and current term is selected', async () => {
  const rows = await academicV2StudentHelpers.overlayBachelorCatalogSubjectRows(
    createOverlayStore([createStageRow({ term_numbers: [2] })]),
    [createLiveRow()],
    {
      programId: 11,
      stageNumber: 1,
      termNumber: 2,
    }
  );

  assert.equal(rows.length, 1);
  assert.equal(rows[0].subject_title, 'Філософія');
  assert.equal(rows[0].group_count, 2);
});

test('bachelor overlay hides a row when the matched stage row has zero selected terms', async () => {
  const rows = await academicV2StudentHelpers.overlayBachelorCatalogSubjectRows(
    createOverlayStore([createStageRow({ term_numbers: [] })]),
    [createLiveRow()],
    {
      programId: 11,
      stageNumber: 1,
      termNumber: 2,
    }
  );

  assert.deepEqual(rows, []);
});

test('bachelor overlay hides a live row when no stage-template row matches the subject template', async () => {
  const rows = await academicV2StudentHelpers.overlayBachelorCatalogSubjectRows(
    createOverlayStore([createStageRow({ subject_template_id: 44 })]),
    [createLiveRow({ subject_template_id: 17 })],
    {
      programId: 11,
      stageNumber: 1,
      termNumber: 2,
    }
  );

  assert.deepEqual(rows, []);
});

test('bachelor overlay ignores stale live term coverage when catalog terms do not include the current term', async () => {
  const rows = await academicV2StudentHelpers.overlayBachelorCatalogSubjectRows(
    createOverlayStore([createStageRow({ term_numbers: [1] })]),
    [createLiveRow()],
    {
      programId: 11,
      stageNumber: 1,
      termNumber: 2,
    }
  );

  assert.deepEqual(rows, []);
});

test('bachelor stage-template projection resolves zero live term links when no catalog terms are selected', () => {
  const termMap = new Map([
    [101, { id: 201 }],
    [102, { id: 202 }],
    [103, { id: 203 }],
  ]);

  assert.deepEqual(
    academicV2Helpers.resolveProjectedStageSubjectTermIds(
      { stage_term_template_ids: [] },
      termMap,
      { trackKey: 'bachelor' }
    ),
    []
  );
});

test('non-bachelor stage-template projection keeps the previous all-terms fallback when no term links are specified', () => {
  const termMap = new Map([
    [101, { id: 201 }],
    [102, { id: 202 }],
    [103, { id: 203 }],
  ]);

  assert.deepEqual(
    academicV2Helpers.resolveProjectedStageSubjectTermIds(
      { stage_term_template_ids: [] },
      termMap,
      { trackKey: 'master' }
    ),
    [201, 202, 203]
  );
});
