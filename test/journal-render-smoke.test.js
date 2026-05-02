const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const ejs = require('ejs');

const viewsDir = path.join(__dirname, '..', 'views');

function withFallbackLocals(base = {}) {
  return new Proxy(base, {
    has(target, prop) {
      if (prop === Symbol.unscopables) return false;
      if (Object.prototype.hasOwnProperty.call(target, prop)) return true;
      return !(prop in globalThis);
    },
    get(target, prop) {
      if (prop === Symbol.unscopables) return undefined;
      if (Object.prototype.hasOwnProperty.call(target, prop)) return target[prop];
      return undefined;
    },
  });
}

async function renderJournal(locals) {
  const filename = path.join(viewsDir, 'journal.ejs');
  return ejs.renderFile(filename, locals, { filename });
}

function baseSelectedSubject(overrides = {}) {
  return {
    subject_id: 101,
    legacy_subject_id: 501,
    subject_name: 'Академічна іноземна мова',
    course_id: 25,
    course_name: 'ПЛЕД 25 Київ',
    group_label: 'Група 2',
    group_numbers: [2],
    has_all_groups: true,
    ...overrides,
  };
}

function baseColumns() {
  return [{
    id: 11,
    title: 'Есе 1',
    max_points: 20,
    include_in_final: 1,
    is_locked: 0,
    is_credit: 0,
    is_archived: 0,
    source_homework_id: 0,
    homework_meeting_url: '',
  }];
}

function baseRows() {
  return [{
    student: {
      id: 7,
      full_name: 'Іван Петренко',
      group_number: 2,
    },
    cells: [{
      column_id: 11,
      student_id: 7,
      score: 18,
      status: 'manual',
      teacher_comment: '',
      graded_at: null,
      submission: null,
    }],
    raw_earned: 18,
    raw_max: 20,
    weighted_earned: 90,
    final_score: 90,
  }];
}

function baseGradingSettings() {
  return {
    homework_enabled: 1,
    homework_max_points: 20,
    homework_weight_points: 100,
    seminar_enabled: 0,
    seminar_max_points: 10,
    seminar_weight_points: 0,
    exam_enabled: 0,
    exam_max_points: 40,
    exam_weight_points: 0,
    credit_enabled: 0,
    credit_max_points: 20,
    credit_weight_points: 0,
    custom_enabled: 0,
    custom_max_points: 10,
    custom_weight_points: 0,
  };
}

function baseJournalLocals(overrides = {}) {
  const selectedSubject = overrides.selectedSubject === undefined
    ? baseSelectedSubject()
    : overrides.selectedSubject;
  const columns = overrides.columns === undefined ? baseColumns() : overrides.columns;
  const journalRows = overrides.journalRows === undefined ? baseRows() : overrides.journalRows;
  const subjectClosure = overrides.subjectClosure === undefined
    ? { is_closed: false, closed_at: null, latest_event: null }
    : overrides.subjectClosure;
  const journalPageMeta = overrides.journalPageMeta === undefined
    ? {
        renderMode: 'full',
        headerSubtitle: 'Компактний shell для оцінювання з чітким subject, closure і matrix state.',
        healthBanner: null,
        scopeChips: [
          { label: 'ПЛЕД 25 Київ', tone: 'info' },
          { label: 'Другий семестр', tone: 'neutral' },
          { label: 'Група 2', tone: 'neutral' },
          { label: 'Журнал відкрито', tone: 'success' },
          { label: 'Повний доступ', tone: 'success' },
        ],
        primaryActions: [
          { kind: 'link', href: '/journal/insights?subject_id=101', label: 'Рейтинг журналу', variant: 'outline-secondary' },
        ],
        summaryCards: [
          { key: 'columns', label: 'Колонки', value: '1', meta: 'Активні колонки оцінювання', tone: 'neutral' },
          { key: 'students', label: 'Студенти', value: '1', meta: 'Студенти в поточному scope', tone: 'neutral' },
          { key: 'snapshot', label: 'Знімок', value: '—', meta: 'Буде згенерований при закритті', tone: 'neutral' },
        ],
        emptyStateKind: 'none',
        emptyState: null,
      }
    : overrides.journalPageMeta;

  return withFallbackLocals({
    lang: 'uk',
    role: 'admin',
    username: 'Smoke User',
    userId: 1,
    t: (key) => key,
    settings: { role_permissions: {}, allow_messages: false },
    changelog: [],
    appVersion: '1.5.16',
    messages: { error: '', success: '', operationId: '' },
    subjects: selectedSubject ? [selectedSubject] : [],
    selectedSubject,
    columns,
    journalRows,
    gradingSettings: baseGradingSettings(),
    attendanceContext: {
      date: '',
      class_number: 0,
      rows: [],
      summary: {},
      statuses: [],
      student_summary: null,
      class_options: [],
      reason_max_length: 240,
      quick_current_slot: { available: false, class_date: '', class_number: null, label: '' },
    },
    canEditJournal: true,
    canEditAttendance: false,
    teacherJournalMode: true,
    attendanceQuickAutoOpen: false,
    canManageAllSubjects: true,
    subjectClosure,
    canCloseSubject: !subjectClosure.is_closed,
    canReopenSubject: Boolean(subjectClosure.is_closed),
    selectedSemester: selectedSubject ? { title: 'Другий семестр' } : null,
    undoGrade: null,
    gradingTypeMeta: {},
    journalWorkflowLinks: {
      insightsHref: '/journal/insights?subject_id=101',
      closeExportHref: '/journal/subject/close-export?subject_id=101',
    },
    journalPageMeta,
    ...overrides,
  });
}

test('journal teacher/admin full render smoke keeps shell and matrix without health banner', async () => {
  const html = await renderJournal(baseJournalLocals());
  assert.match(html, /journal-control-bar/);
  assert.match(html, /journal-table/);
  assert.doesNotMatch(html, /journal-health-banner/);
});

test('journal simplified render smoke shows one health banner and simplified empty state', async () => {
  const html = await renderJournal(baseJournalLocals({
    canEditJournal: false,
    columns: [],
    journalRows: [],
    journalPageMeta: {
      renderMode: 'simplified',
      headerSubtitle: 'Працює спрощений shell, поки повний рендер журналу відновлюється.',
      healthBanner: {
        tone: 'warning',
        title: 'Рендер журналу тимчасово спрощено',
        body: 'Повний layout журналу тимчасово спрощено після внутрішньої render-помилки. Оновіть сторінку, щоб повторити повний shell.',
        actionLabel: 'Оновити',
        actionHref: '/journal',
      },
      scopeChips: [{ label: 'ПЛЕД 25 Київ', tone: 'info' }],
      primaryActions: [],
      summaryCards: [],
      emptyStateKind: 'simplified-render',
      emptyState: {
        tone: 'warning',
        title: 'Журнал працює у спрощеному render mode',
        body: 'Повний layout журналу тимчасово спрощено після внутрішньої render-помилки. Оновіть сторінку, щоб повторити повний shell.',
        actions: [{ kind: 'link', href: '/journal', label: 'Оновити', variant: 'outline-secondary' }],
      },
    },
  }));
  assert.match(html, /Рендер журналу тимчасово спрощено/);
  assert.match(html, /Журнал працює у спрощеному render mode/);
});

test('journal compatibility render smoke shows compatibility banner and shell state', async () => {
  const html = await renderJournal(baseJournalLocals({
    canEditJournal: false,
    columns: [],
    journalRows: [],
    journalPageMeta: {
      renderMode: 'compatibility',
      headerSubtitle: 'Працює режим сумісності, поки для журналу не доступна потрібна схема БД.',
      healthBanner: {
        tone: 'warning',
        title: 'Увімкнено режим сумісності журналу',
        body: 'У схемі БД бракує структур журналу. Оновіть міграції та перезавантажте сервіс.',
        actionLabel: 'Оновити',
        actionHref: '/journal',
      },
      scopeChips: [{ label: 'ПЛЕД 25 Київ', tone: 'info' }],
      primaryActions: [],
      summaryCards: [],
      emptyStateKind: 'compatibility-mode',
      emptyState: {
        tone: 'warning',
        title: 'Журнал працює в режимі сумісності',
        body: 'У схемі БД бракує структур журналу. Оновіть міграції та перезавантажте сервіс.',
        actions: [{ kind: 'link', href: '/journal', label: 'Оновити', variant: 'outline-secondary' }],
      },
    },
  }));
  assert.match(html, /Увімкнено режим сумісності журналу/);
  assert.match(html, /Журнал працює в режимі сумісності/);
});

test('journal no-columns state renders action card with template import and create-column CTA', async () => {
  const html = await renderJournal(baseJournalLocals({
    columns: [],
    journalRows: [],
    journalPageMeta: {
      renderMode: 'full',
      headerSubtitle: 'Компактний shell для оцінювання з чітким subject, closure і matrix state.',
      healthBanner: null,
      scopeChips: [{ label: 'ПЛЕД 25 Київ', tone: 'info' }],
      primaryActions: [],
      summaryCards: [
        { key: 'columns', label: 'Колонки', value: '0', meta: 'Активні колонки оцінювання', tone: 'neutral' },
      ],
      emptyStateKind: 'no-columns',
      emptyState: {
        tone: 'info',
        title: 'У журналі ще немає колонок оцінювання',
        body: 'Імпортуйте шаблон з попереднього семестру або створіть першу ручну колонку, щоб почати оцінювання.',
        actions: [
          { kind: 'link', href: '#journalCreateColumnCard', label: 'Створити ручну колонку', variant: 'primary' },
          {
            kind: 'form',
            action: '/journal/template/import-previous',
            method: 'POST',
            label: 'Імпортувати шаблон',
            variant: 'outline-secondary',
            confirm: 'Імпортувати ручні колонки з попереднього семестру?',
            hiddenFields: { subject_id: 101 },
          },
        ],
      },
    },
  }));
  assert.match(html, /У журналі ще немає колонок оцінювання/);
  assert.match(html, /Створити ручну колонку/);
  assert.match(html, /Імпортувати шаблон/);
});

test('journal closed-subject shell keeps reopen and export affordances', async () => {
  const html = await renderJournal(baseJournalLocals({
    subjectClosure: {
      is_closed: true,
      closed_at: '2026-04-08T10:00:00.000Z',
      latest_event: { export_rows_count: 12, export_columns_count: 5 },
    },
    canCloseSubject: false,
    canReopenSubject: true,
    journalPageMeta: {
      renderMode: 'full',
      headerSubtitle: 'Компактний shell для оцінювання з чітким subject, closure і matrix state.',
      healthBanner: null,
      scopeChips: [
        { label: 'ПЛЕД 25 Київ', tone: 'info' },
        { label: 'Предмет закрито', tone: 'danger' },
      ],
      primaryActions: [{ kind: 'link', href: '/journal/insights?subject_id=101', label: 'Рейтинг журналу', variant: 'outline-secondary' }],
      summaryCards: [
        { key: 'columns', label: 'Колонки', value: '1', meta: 'Активні колонки оцінювання', tone: 'neutral' },
        { key: 'students', label: 'Студенти', value: '1', meta: 'Студенти в поточному scope', tone: 'neutral' },
        { key: 'snapshot', label: 'Знімок', value: '12 × 5', meta: 'Готовий до аудиту', tone: 'info' },
      ],
      emptyStateKind: 'none',
      emptyState: null,
    },
  }));
  assert.match(html, /Відкрити предмет/);
  assert.match(html, /\/journal\/subject\/close-export\?subject_id=101/);
});
