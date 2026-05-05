const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const ejs = require('ejs');

const demoMode = require('../lib/demoMode');

const viewsDir = path.join(__dirname, '..', 'views');
const testTranslations = (key) => ({
  'demo.badge': 'Demo',
  'demo.role.student': 'Student',
  'demo.role.teacher': 'Teacher',
}[key] || key);

function buildRenderBase(role = 'student') {
  const isTeacher = role === 'teacher';
  const name = isTeacher ? 'Demo Teacher' : 'Demo Student';
  return {
    lang: 'en',
    appVersion: '0.0.0',
    buildStamp: '',
    changelog: [],
    settings: { allow_messages: true, allow_custom_deadlines: true },
    t: testTranslations,
    isDemo: true,
    demoRole: role,
    demoReadOnlyMessage: 'Demo mode is read-only.',
    messages: { error: '', success: '', operationId: '' },
    sessionSecurity: {},
    hasCustomAdminPanelAccess: false,
    customAdminPanelHref: '/admin',
    canManagePathways: false,
    pathwaysPanelHref: '/admin/pathways',
    userNav: {
      isAuthenticated: true,
      isDemo: true,
      demoRole: role,
      role,
      roles: [role],
      name,
      flags: { allowMessages: true },
    },
  };
}

const demoReq = (overrides = {}) => ({
  session: {
    isDemo: true,
    demoRole: 'student',
    role: 'student',
    ...overrides.session,
  },
  method: overrides.method || 'GET',
  path: overrides.path || '/home',
  headers: overrides.headers || {},
});

test('demo user is session-only shaped and never a real user id', () => {
  const student = demoMode.buildDemoUser('student', 'en');
  const teacher = demoMode.buildDemoUser('teacher', 'en');

  assert.equal(student.id, demoMode.DEMO_USER_ID);
  assert.ok(student.id < 0);
  assert.equal(student.role, 'student');
  assert.equal(student.username, 'Demo Student');
  assert.equal(student.language, 'en');
  assert.equal(teacher.id, demoMode.DEMO_USER_ID);
  assert.equal(teacher.role, 'teacher');
  assert.equal(teacher.username, 'Demo Teacher');
});

test('demo read-only policy blocks writes and allows navigation plus role/logout posts', () => {
  assert.equal(demoMode.shouldAllowDemoWrite(demoReq({ method: 'GET', path: '/schedule' })), true);
  assert.equal(demoMode.shouldAllowDemoWrite(demoReq({ method: 'HEAD', path: '/subjects' })), true);
  assert.equal(demoMode.shouldAllowDemoWrite(demoReq({ method: 'POST', path: '/demo/switch-role' })), true);
  assert.equal(demoMode.shouldAllowDemoWrite(demoReq({ method: 'POST', path: '/logout' })), true);
  assert.equal(demoMode.shouldAllowDemoWrite(demoReq({ method: 'POST', path: '/homework/add' })), false);
  assert.equal(demoMode.shouldAllowDemoWrite(demoReq({ method: 'DELETE', path: '/api/teamwork/1' })), false);
});

test('demo role switch helpers normalize role and expose analytics role keys', () => {
  const nextRole = demoMode.normalizeDemoRole('teacher');
  const switchedUser = demoMode.buildDemoUser(nextRole, 'en');

  assert.equal(nextRole, 'teacher');
  assert.equal(switchedUser.role, 'teacher');
  assert.equal(demoMode.getDemoVisitRoleKey('student'), 'demo-student');
  assert.equal(demoMode.getDemoVisitRoleKey('teacher'), 'demo-teacher');
  assert.equal(demoMode.getDemoVisitRoleKey('admin'), 'demo-student');
});

test('demo fixtures provide localized filled screens', () => {
  const schedule = demoMode.buildScheduleLocals({
    lang: 'en',
    role: 'student',
    bellSchedule: ['08:30-09:50', '10:00-11:20', '11:40-13:00'],
    daysOfWeek: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
  });
  const subjects = demoMode.buildSubjectsLocals({ lang: 'en', role: 'student' });
  const teamwork = demoMode.buildTeamworkLocals({ lang: 'en', role: 'student' });

  assert.equal(schedule.role, 'student');
  assert.ok(Object.values(schedule.scheduleByDay).some((items) => items.length > 0));
  assert.equal(subjects.subjects[0].subject_name, 'Data Analysis');
  assert.ok(subjects.materials.length > 0);
  assert.ok(teamwork.tasks.some((task) => String(task.title).toLowerCase().includes('policy')));
});

test('demo JSON/API requests receive JSON-style denial', () => {
  assert.equal(demoMode.wantsJson(demoReq({ path: '/api/homework', headers: {} })), true);
  assert.equal(demoMode.wantsJson(demoReq({ path: '/schedule', headers: { accept: 'application/json' } })), true);
  assert.equal(demoMode.wantsJson(demoReq({ path: '/schedule', headers: { accept: 'text/html' } })), false);
});

test('navbar partial renders demo role switch and keeps GET forms available', async () => {
  const html = await ejs.renderFile(path.join(viewsDir, 'partials', 'navbar.ejs'), {
    role: 'student',
    username: 'Demo Student',
    lang: 'en',
    t: testTranslations,
    userNav: {
      isAuthenticated: true,
      isDemo: true,
      demoRole: 'student',
      role: 'student',
      roles: ['student'],
      name: 'Demo Student',
    },
    currentPath: '/home',
    activePage: 'home',
  }, {
    filename: path.join(viewsDir, 'partials', 'navbar.ejs'),
  });

  assert.match(html, /action="\/demo\/switch-role"/);
  assert.match(html, /method === 'get'/);
  assert.match(html, /Demo/);
});

test('demo fixtures render the supported student and teacher pages', async () => {
  const studentBase = buildRenderBase('student');
  const teacherBase = buildRenderBase('teacher');
  const bellSchedule = ['08:30-09:50', '10:00-11:20', '11:40-13:00', '13:30-14:50', '15:00-16:20'];
  const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
  const pages = [
    ['my-day.ejs', {
      ...studentBase,
      ...demoMode.buildMyDayLocals({ lang: 'en', role: 'student', username: 'Demo Student' }),
    }],
    ['schedule.ejs', {
      ...studentBase,
      ...demoMode.buildScheduleLocals({
        lang: 'en',
        role: 'student',
        username: 'Demo Student',
        bellSchedule,
        daysOfWeek,
      }),
    }],
    ['subjects.ejs', {
      ...studentBase,
      ...demoMode.buildSubjectsLocals({ lang: 'en', role: 'student', username: 'Demo Student' }),
    }],
    ['teamwork.ejs', {
      ...studentBase,
      ...demoMode.buildTeamworkLocals({ lang: 'en', role: 'student', username: 'Demo Student' }),
    }],
    ['profile.ejs', {
      ...studentBase,
      ...demoMode.buildProfileLocals({ lang: 'en', role: 'student', username: 'Demo Student' }),
    }],
    ['teacher-hub.ejs', {
      ...teacherBase,
      ...demoMode.buildTeacherHubLocals({ lang: 'en', role: 'teacher', username: 'Demo Teacher' }),
      settings: teacherBase.settings,
    }],
    ['teacher-subjects.ejs', {
      ...teacherBase,
      ...demoMode.buildTeacherSubjectsLocals({ lang: 'en', role: 'teacher', username: 'Demo Teacher' }),
      settings: teacherBase.settings,
    }],
    ['teacher-workspace.ejs', {
      ...teacherBase,
      ...demoMode.buildTeacherWorkspaceLocals({ lang: 'en', role: 'teacher', username: 'Demo Teacher' }),
      settings: teacherBase.settings,
    }],
  ];

  for (const [file, locals] of pages) {
    const filename = path.join(viewsDir, file);
    const html = await ejs.renderFile(filename, locals, { filename });
    assert.match(html, /Studerria|Demo/);
  }
});
