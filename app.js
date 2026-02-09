const express = require('express');
const http = require('http');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { Pool } = require('pg');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const pkg = require('./package.json');
const versionFile = path.join(__dirname, 'version.json');
const changelogFile = path.join(__dirname, 'changelog.json');
let appVersion = pkg.version || '0.0.0';
try {
  const raw = fs.readFileSync(versionFile, 'utf8');
  const parsed = JSON.parse(raw);
  if (parsed && typeof parsed.version === 'string') {
    appVersion = parsed.version;
  }
} catch (err) {
  // keep package.json version as fallback
}
let appChangelog = [];
try {
  const raw = fs.readFileSync(changelogFile, 'utf8');
  const parsed = JSON.parse(raw);
  if (parsed && Array.isArray(parsed.items)) {
    appChangelog = parsed.items;
  }
} catch (err) {
  appChangelog = [];
}
const buildStamp = new Date().toISOString();
const localesDir = path.join(__dirname, 'locales');
const locales = {};
['en', 'uk'].forEach((code) => {
  try {
    const raw = fs.readFileSync(path.join(localesDir, `${code}.json`), 'utf8');
    locales[code] = JSON.parse(raw);
  } catch (err) {
    locales[code] = {};
  }
});

const getPreferredLang = (req) => {
  const queryLang = typeof req.query.lang === 'string' ? req.query.lang.toLowerCase() : '';
  if (queryLang && locales[queryLang]) {
    req.session.lang = queryLang;
    return queryLang;
  }
  if (req.session && req.session.user && req.session.user.language && locales[req.session.user.language]) {
    return req.session.user.language;
  }
  if (req.session && req.session.lang && locales[req.session.lang]) {
    return req.session.lang;
  }
  const header = req.headers['accept-language'];
  if (typeof header === 'string' && header.length) {
    const preferred = header.split(',')[0].trim().slice(0, 2).toLowerCase();
    if (locales[preferred]) return preferred;
  }
  return locales.uk ? 'uk' : 'en';
};

const translate = (lang, key) => {
  if (!key) return '';
  const dict = locales[lang] || {};
  if (dict && Object.prototype.hasOwnProperty.call(dict, key)) {
    return dict[key];
  }
  const fallback = locales.en || {};
  if (fallback && Object.prototype.hasOwnProperty.call(fallback, key)) {
    return fallback[key];
  }
  return key;
};

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

const adminSeed = process.env.ADMIN_HASHED_PASS
  ? {
      full_name: process.env.ADMIN_NAME || 'Марченко Андрій Юрійович',
      role: 'admin',
      password_hash: process.env.ADMIN_HASHED_PASS,
    }
  : null;

const userSeed = adminSeed ? [adminSeed] : [];

const DEFAULT_SETTINGS = {
  session_duration_days: 14,
  max_file_size_mb: 20,
  allow_homework_creation: true,
  min_team_members: 2,
  allow_custom_deadlines: true,
  allow_messages: true,
  schedule_refresh_minutes: 5,
};
let settingsCache = { ...DEFAULT_SETTINGS };

const bellSchedule = {
  1: { start: '08:30', end: '09:50' },
  2: { start: '10:00', end: '11:20' },
  3: { start: '11:40', end: '13:00' },
  4: { start: '13:30', end: '14:50' },
  5: { start: '15:00', end: '16:20' },
  6: { start: '16:30', end: '17:50' },
  7: { start: '18:00', end: '19:20' },
};

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const isProd = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);


app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
    },
  })
);

app.use((req, res, next) => {
  const lang = getPreferredLang(req);
  res.locals.messages = {
    error: req.query && req.query.err ? req.query.err : '',
    success: req.query && req.query.ok ? req.query.ok : '',
  };
  res.locals.appVersion = appVersion;
  res.locals.buildStamp = buildStamp;
  res.locals.authorName = 'Andrii Marchenko';
  res.locals.changelog = appChangelog;
  res.locals.settings = settingsCache;
  res.locals.lang = lang;
  res.locals.t = (key) => translate(lang, key);
  next();
});

const pool = new Pool({
  host: process.env.DB_HOST || `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

const convertPlaceholders = (sql) => {
  let index = 0;
  return sql.replace(/\?/g, () => {
    index += 1;
    return `$${index}`;
  });
};

const normalizeArgs = (sql, params, cb) => {
  let finalParams = params;
  let callback = cb;
  if (typeof params === 'function') {
    callback = params;
    finalParams = [];
  }
  return { sql, params: finalParams || [], cb: callback };
};

const db = {
  async run(sql, params, cb) {
    const { params: finalParams, cb: callback } = normalizeArgs(sql, params, cb);
    const query = convertPlaceholders(sql);
    try {
      const result = await pool.query(query, finalParams);
      const lastID = result.rows && result.rows[0] ? result.rows[0].id : undefined;
      if (callback) {
        callback.call({ lastID }, null);
      }
      return { changes: result.rowCount, lastID };
    } catch (err) {
      if (callback) {
        callback(err);
        return { changes: 0 };
      }
      throw err;
    }
  },
  async get(sql, params, cb) {
    const { params: finalParams, cb: callback } = normalizeArgs(sql, params, cb);
    const query = convertPlaceholders(sql);
    try {
      const result = await pool.query(query, finalParams);
      const row = result.rows[0];
      if (callback) {
        callback(null, row);
      }
      return row;
    } catch (err) {
      if (callback) {
        callback(err);
        return undefined;
      }
      throw err;
    }
  },
  async all(sql, params, cb) {
    const { params: finalParams, cb: callback } = normalizeArgs(sql, params, cb);
    const query = convertPlaceholders(sql);
    try {
      const result = await pool.query(query, finalParams);
      if (callback) {
        callback(null, result.rows);
      }
      return result.rows;
    } catch (err) {
      if (callback) {
        callback(err, []);
        return [];
      }
      throw err;
    }
  },
  prepare(sql) {
    const pending = [];
    return {
      run: (...params) => {
        const promise = db.run(sql, params);
        pending.push(promise);
        return promise;
      },
      get: (...params) => db.get(sql, params),
      all: (...params) => db.all(sql, params),
      finalize: async (cb) => {
        try {
          await Promise.all(pending);
          if (cb) cb();
        } catch (err) {
          if (cb) cb(err);
        }
      },
    };
  },
};

let usersHasIsActive = true;

const refreshSettingsCache = async () => {
  const settingsRows = await pool.query('SELECT key, value FROM settings');
  const parsed = { ...DEFAULT_SETTINGS };
  for (const row of settingsRows.rows) {
    if (!row || !row.key) continue;
    if (row.key === 'session_duration_days') {
      const n = Number(row.value);
      if (!Number.isNaN(n) && n > 0) parsed.session_duration_days = n;
    } else if (row.key === 'max_file_size_mb') {
      const n = Number(row.value);
      if (!Number.isNaN(n) && n > 0) parsed.max_file_size_mb = n;
    } else if (row.key === 'allow_homework_creation') {
      parsed.allow_homework_creation = String(row.value).toLowerCase() === 'true';
    } else if (row.key === 'min_team_members') {
      const n = Number(row.value);
      if (!Number.isNaN(n) && n > 0) parsed.min_team_members = n;
    } else if (row.key === 'allow_custom_deadlines') {
      parsed.allow_custom_deadlines = String(row.value).toLowerCase() === 'true';
    } else if (row.key === 'allow_messages') {
      parsed.allow_messages = String(row.value).toLowerCase() === 'true';
    } else if (row.key === 'schedule_refresh_minutes') {
      const n = Number(row.value);
      if (!Number.isNaN(n) && n > 0) parsed.schedule_refresh_minutes = n;
    }
  }
  settingsCache = parsed;
};

const ensureUser = async (fullName, role, passwordHash, options = {}) => {
  const { courseId = 1 } = options;
  const { forcePassword = false, forceRole = false } = options;
  if (!passwordHash) {
    return;
  }
  const existing = await db.get('SELECT id, password_hash, role FROM users WHERE full_name = ?', [fullName]);
  if (!existing) {
    await db.run(
      'INSERT INTO users (full_name, role, password_hash, is_active, schedule_group, course_id, language) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [fullName, role, passwordHash, 1, 'A', courseId, 'uk']
    );
    return;
  }
  if (forcePassword || !existing.password_hash) {
    await db.run('UPDATE users SET password_hash = ?, is_active = 1 WHERE id = ?', [
      passwordHash,
      existing.id,
    ]);
  } else {
    await db.run('UPDATE users SET is_active = 1 WHERE id = ?', [existing.id]);
  }
  if (forceRole && existing.role !== role) {
    await db.run('UPDATE users SET role = ? WHERE id = ?', [role, existing.id]);
  }
};

const initDb = async () => {
  await runMigrations(pool);

  await pool.query('UPDATE subjects SET is_required = true WHERE is_required IS NULL');

  await pool.query("UPDATE courses SET location = 'kyiv' WHERE location IS NULL");
  await pool.query('UPDATE users SET course_id = 1 WHERE course_id IS NULL');
  await pool.query("UPDATE users SET language = 'uk' WHERE language IS NULL");
  await pool.query('UPDATE users SET created_at = NOW() WHERE created_at IS NULL');
  await pool.query('UPDATE subjects SET course_id = 1 WHERE course_id IS NULL');
  await pool.query('UPDATE subjects SET visible = 1 WHERE visible IS NULL');
  await pool.query('UPDATE schedule_entries SET course_id = 1 WHERE course_id IS NULL');
  await pool.query('UPDATE homework SET course_id = 1 WHERE course_id IS NULL');
  await pool.query("UPDATE homework SET status = 'published' WHERE status IS NULL");
  await pool.query('UPDATE history_log SET course_id = 1 WHERE course_id IS NULL');
  await pool.query('UPDATE login_history SET course_id = 1 WHERE course_id IS NULL');
  await pool.query('UPDATE teamwork_tasks SET course_id = 1 WHERE course_id IS NULL');
  await pool.query('UPDATE messages SET course_id = 1 WHERE course_id IS NULL');
  await pool.query("UPDATE messages SET status = 'published' WHERE status IS NULL");
  await pool.query('UPDATE personal_reminders SET course_id = 1 WHERE course_id IS NULL');
  await pool.query('UPDATE personal_reminders SET updated_at = created_at WHERE updated_at IS NULL');
  await pool.query('UPDATE users SET password = NULL WHERE password IS NOT NULL');

  const courseRows = await pool.query('SELECT id, name FROM courses ORDER BY id');
  for (const course of courseRows.rows) {
    const activeRow = await pool.query(
      'SELECT id, is_active FROM semesters WHERE course_id = $1 ORDER BY is_active DESC, id ASC LIMIT 1',
      [course.id]
    );
    if (!activeRow.rows.length) {
      await pool.query(
        'INSERT INTO semesters (course_id, title, start_date, weeks_count, is_active, is_archived) VALUES ($1, $2, $3, $4, 1, 0)',
        [course.id, `${course.name} семестр`, '2026-01-19', 15]
      );
    } else if (activeRow.rows[0].is_active !== 1) {
      await pool.query('UPDATE semesters SET is_active = 1 WHERE id = $1', [activeRow.rows[0].id]);
    }

    const currentActive = await pool.query(
      'SELECT id FROM semesters WHERE course_id = $1 AND is_active = 1 ORDER BY id ASC LIMIT 1',
      [course.id]
    );
    if (currentActive.rows.length) {
      const semesterId = currentActive.rows[0].id;
      await pool.query('UPDATE schedule_entries SET semester_id = $1 WHERE semester_id IS NULL AND course_id = $2', [
        semesterId,
        course.id,
      ]);
      await pool.query('UPDATE homework SET semester_id = $1 WHERE semester_id IS NULL AND course_id = $2', [
        semesterId,
        course.id,
      ]);
      await pool.query('UPDATE teamwork_tasks SET semester_id = $1 WHERE semester_id IS NULL AND course_id = $2', [
        semesterId,
        course.id,
      ]);
      await pool.query('UPDATE messages SET semester_id = $1 WHERE semester_id IS NULL AND course_id = $2', [
        semesterId,
        course.id,
      ]);
      await pool.query('UPDATE personal_reminders SET semester_id = $1 WHERE semester_id IS NULL AND course_id = $2', [
        semesterId,
        course.id,
      ]);
    }
  }

  for (const user of userSeed) {
    const isAdmin = user.role === 'admin';
    await ensureUser(user.full_name, user.role, user.password_hash, {
      forcePassword: isAdmin,
      forceRole: isAdmin,
    });
  }

  await refreshSettingsCache();
};

let initPromise;
let initStatus = 'pending';
let initError = null;
const ensureDbReady = async () => {
  if (initPromise) {
    return initPromise;
  }
  initPromise = (async () => {
    const maxAttempts = 8;
    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        initStatus = 'pending';
        await initDb();
        initStatus = 'ok';
        initError = null;
        return true;
      } catch (err) {
        lastError = err;
        initStatus = 'error';
        initError = err;
        const delay = Math.min(1000 * 2 ** (attempt - 1), 15000);
        console.error(`DB init attempt ${attempt} failed, retrying in ${delay}ms`, err);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    throw lastError;
  })();
  try {
    return await initPromise;
  } catch (err) {
    initPromise = null;
    throw err;
  }
};

app.use(async (req, res, next) => {
  if (!req.session || !req.session.user) {
    return next();
  }
  if (req.session.role === 'admin') {
    return next();
  }
  const allowedPrefixes = [
    '/teacher/pending',
    '/teacher/subjects',
    '/profile',
    '/logout',
    '/login',
    '/register',
    '/register/course',
    '/register/teacher-subjects',
    '/register/subjects',
  ];
  if (allowedPrefixes.some((prefix) => req.path === prefix || req.path.startsWith(`${prefix}/`))) {
    return next();
  }
  try {
    await ensureDbReady();
    const courseId = req.session.user.course_id;
    if (!courseId) {
      return next();
    }
    const isTeacher = await isTeacherCourse(courseId);
    if (!isTeacher) {
      return next();
    }
    const request = await db.get('SELECT status FROM teacher_requests WHERE user_id = ?', [req.session.user.id]);
    if (!request) {
      return next();
    }
    if (request.status === 'approved') {
      if (req.session.role !== 'teacher') {
        req.session.role = 'teacher';
      }
      return next();
    }
    return res.redirect('/teacher/pending');
  } catch (err) {
    console.error('Teacher gate error', err);
    return next();
  }
});

const uploadsDir = path.join(__dirname, 'uploads');
try {
  fs.mkdirSync(uploadsDir, { recursive: true });
} catch (err) {
  console.error('Failed to ensure uploads directory', err);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      fs.mkdirSync(uploadsDir, { recursive: true });
    } catch (err) {
      return cb(err);
    }
    return cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9-_]/g, '_');
    const stamp = Date.now();
    cb(null, `${base}-${stamp}${ext}`);
  },
});

const allowedTypes = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  'text/plain',
]);

const upload = multer({
  storage,
  limits: { fileSize: (settingsCache.max_file_size_mb || 20) * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!allowedTypes.has(file.mimetype)) {
      return cb(new Error('Invalid file type'));
    }
    return cb(null, true);
  },
});

const csvUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const okTypes = new Set(['text/csv', 'application/vnd.ms-excel', 'application/csv', 'text/plain', 'application/octet-stream']);
    if (!okTypes.has(file.mimetype)) {
      return cb(new Error('Invalid file type'));
    }
    return cb(null, true);
  },
});

const referenceCache = {
  courses: { data: null, expiresAt: 0 },
  subjects: new Map(),
  semesters: new Map(),
  activeSemester: new Map(),
  studyDays: new Map(),
  weekTime: new Map(),
};
const REFERENCE_TTL_MS = 5 * 60 * 1000;

function cacheGet(store, key) {
  const entry = store instanceof Map ? store.get(key) : store[key];
  if (!entry || !entry.expiresAt || entry.expiresAt < Date.now()) {
    return null;
  }
  return entry.data;
}

function cacheSet(store, key, data, ttlMs = REFERENCE_TTL_MS) {
  const entry = { data, expiresAt: Date.now() + ttlMs };
  if (store instanceof Map) {
    store.set(key, entry);
  } else {
    store[key] = entry;
  }
  return data;
}

function cacheDelete(store, key) {
  if (store instanceof Map) {
    store.delete(key);
  } else {
    store[key] = { data: null, expiresAt: 0 };
  }
}

function invalidateCoursesCache() {
  cacheDelete(referenceCache.courses, 'courses');
}

function invalidateSubjectsCache(courseId) {
  if (!courseId) {
    referenceCache.subjects.clear();
    return;
  }
  referenceCache.subjects.delete(`${courseId}|all`);
  referenceCache.subjects.delete(`${courseId}|visible`);
}

function invalidateSemestersCache(courseId) {
  if (!courseId) {
    referenceCache.semesters.clear();
  } else {
    referenceCache.semesters.delete(courseId);
  }
  invalidateActiveSemesterCache(courseId);
}

function invalidateActiveSemesterCache(courseId) {
  if (!courseId) {
    referenceCache.activeSemester.clear();
  } else {
    referenceCache.activeSemester.delete(courseId);
  }
}

function invalidateStudyDaysCache(courseId) {
  if (!courseId) {
    referenceCache.studyDays.clear();
  } else {
    referenceCache.studyDays.delete(courseId);
  }
}

function invalidateWeekTimeCache() {
  referenceCache.weekTime.clear();
}

async function getCoursesCached() {
  const cached = cacheGet(referenceCache.courses, 'courses');
  if (cached) return cached;
  const rows = await db.all('SELECT id, name, is_teacher_course, location FROM courses ORDER BY id');
  return cacheSet(referenceCache.courses, 'courses', rows || []);
}

async function getCourseById(courseId) {
  const courses = await getCoursesCached();
  return (courses || []).find((c) => Number(c.id) === Number(courseId)) || null;
}

async function isTeacherCourse(courseId) {
  if (!courseId) return false;
  const course = await getCourseById(courseId);
  if (!course) return false;
  return course.is_teacher_course === true || Number(course.is_teacher_course) === 1;
}

async function getSubjectsCached(courseId, options = {}) {
  const key = `${courseId}|${options.visibleOnly ? 'visible' : 'all'}`;
  const cached = cacheGet(referenceCache.subjects, key);
  if (cached) return cached;
  const sql = options.visibleOnly
    ? 'SELECT * FROM subjects WHERE course_id = ? AND visible = 1 ORDER BY name'
    : 'SELECT * FROM subjects WHERE course_id = ? ORDER BY name';
  const rows = await db.all(sql, [courseId]);
  return cacheSet(referenceCache.subjects, key, rows || []);
}

async function getSemestersCached(courseId) {
  const cached = cacheGet(referenceCache.semesters, courseId);
  if (cached) return cached;
  const rows = await db.all('SELECT * FROM semesters WHERE course_id = ? ORDER BY start_date DESC', [courseId]);
  return cacheSet(referenceCache.semesters, courseId, rows || []);
}

const DEFAULT_GENERATOR_CONFIG = {
  distribution: 'even',
  seminar_distribution: 'start',
  max_daily_pairs: 7,
  target_daily_pairs: 4,
  blocked_weeks: '',
  special_weeks_mode: 'block',
  prefer_compactness: true,
  mirror_groups: false,
  active_location: 'kyiv',
  course_semesters: {},
  course_semesters_by_location: {
    kyiv: {},
    munich: {},
  },
};

const parseGeneratorConfig = (raw) => {
  if (!raw) return { ...DEFAULT_GENERATOR_CONFIG };
  try {
    const parsed = JSON.parse(raw) || {};
    if (parsed.course_semesters && !parsed.course_semesters_by_location) {
      parsed.course_semesters_by_location = {
        kyiv: parsed.course_semesters,
        munich: {},
      };
    }
    const merged = {
      ...DEFAULT_GENERATOR_CONFIG,
      ...parsed,
    };
    if (!merged.course_semesters_by_location) {
      merged.course_semesters_by_location = { kyiv: {}, munich: {} };
    }
    merged.course_semesters_by_location = {
      kyiv: {
        ...(DEFAULT_GENERATOR_CONFIG.course_semesters_by_location || {}).kyiv,
        ...(merged.course_semesters_by_location.kyiv || {}),
      },
      munich: {
        ...(DEFAULT_GENERATOR_CONFIG.course_semesters_by_location || {}).munich,
        ...(merged.course_semesters_by_location.munich || {}),
      },
    };
    merged.active_location = merged.active_location === 'munich' ? 'munich' : 'kyiv';
    return merged;
  } catch (err) {
    return { ...DEFAULT_GENERATOR_CONFIG };
  }
};

const serializeGeneratorConfig = (config) => JSON.stringify({ ...DEFAULT_GENERATOR_CONFIG, ...(config || {}) });

const normalizeGeneratorDays = (days) =>
  (Array.isArray(days) ? days : typeof days === 'string' ? [days] : [])
    .map((d) => String(d))
    .filter(Boolean);

const normalizeWeekdayName = (value) => {
  if (!value) return null;
  const match = fullWeekDays.find((day) => day.toLowerCase() === String(value).toLowerCase());
  return match || null;
};

async function getCoursesByLocation(location) {
  const target = String(location || 'kyiv').toLowerCase();
  const courses = await getCoursesCached();
  return (courses || []).filter((course) => {
    const isTeacher = course.is_teacher_course === true || Number(course.is_teacher_course) === 1;
    const courseLocation = String(course.location || 'kyiv').toLowerCase();
    return !isTeacher && courseLocation === target;
  });
}

const { createRateLimiter, getClientIp } = require('./lib/rateLimit');
const {
  requireLogin,
  requireAdmin,
  requireStaff,
  requireOverviewAccess,
  requireDeanery,
  requireAdminOrDeanery,
  requireHomeworkBulkAccess,
} = require('./lib/auth');
const {
  daysOfWeek,
  fullWeekDays,
  studyDayLabels,
  parseDateUTC,
  isValidDateString,
  isValidTimeString,
  parseCsvText,
  getWeekDayForDate,
  getAcademicWeekForSemester,
  getDateForWeekDay,
  getDateForWeekIndex,
  getDayNameFromDate,
  formatLocalDate,
  addDays,
} = require('./lib/dateUtils');
const { generateSchedule } = require('./lib/scheduleGenerator');
const { runMigrations } = require('./lib/migrations');

const authLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 8,
  keyFn: (req) => `auth:${getClientIp(req)}`,
  onLimit: (req, res) => res.redirect('/login?error=1'),
});

const registerLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFn: (req) => `register:${getClientIp(req)}`,
  onLimit: (req, res) => res.redirect('/register?error=Too%20many%20requests'),
});

const writeLimiter = createRateLimiter({
  windowMs: 30 * 1000,
  max: 30,
  keyFn: (req) => `write:${req.session?.user?.id || getClientIp(req)}`,
});

const readLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 90,
  keyFn: (req) => `read:${req.session?.user?.id || getClientIp(req)}`,
});

const uploadLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 6,
  keyFn: (req) => `upload:${req.session?.user?.id || getClientIp(req)}`,
});

function logAction(dbRef, req, action, details) {
  const actorId = req.session.user ? req.session.user.id : null;
  const actorName = req.session.user ? req.session.user.username : null;
  const courseId = req.session && req.session.adminCourse
    ? Number(req.session.adminCourse)
    : req.session && req.session.user
    ? req.session.user.course_id || 1
    : null;
  const createdAt = new Date().toISOString();
  dbRef.run(
    'INSERT INTO history_log (actor_id, actor_name, action, details, created_at, course_id) VALUES (?, ?, ?, ?, ?, ?)',
    [actorId, actorName, action, details ? JSON.stringify(details) : null, createdAt, courseId]
  );
  broadcast('history_updated');
}

function logActivity(dbRef, req, actionType, targetType, targetId, details, courseIdOverride, semesterIdOverride) {
  const userId = req.session.user ? req.session.user.id : null;
  const userName = req.session.user ? req.session.user.username : null;
  const courseId = Number.isFinite(courseIdOverride)
    ? courseIdOverride
    : req.session && req.session.adminCourse
    ? Number(req.session.adminCourse)
    : req.session && req.session.user
    ? req.session.user.course_id || 1
    : null;
  const semesterId = Number.isFinite(semesterIdOverride) ? semesterIdOverride : null;
  const createdAt = new Date().toISOString();
  dbRef.run(
    'INSERT INTO activity_log (user_id, user_name, action_type, target_type, target_id, details, created_at, course_id, semester_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      userId,
      userName,
      actionType,
      targetType,
      targetId,
      details ? JSON.stringify(details) : null,
      createdAt,
      courseId,
      semesterId,
    ]
  );
}

function applyRememberMe(req, remember) {
  const ttlDays = settingsCache.session_duration_days || 14;
  if (remember) {
    req.session.cookie.maxAge = ttlDays * 24 * 60 * 60 * 1000;
  } else {
    req.session.cookie.expires = false;
    req.session.cookie.maxAge = null;
  }
}

const ACTIVITY_POINTS_CASE =
  "CASE WHEN action_type = 'homework_create' THEN 1 " +
  "WHEN action_type = 'teamwork_task_create' THEN 2 " +
  "WHEN action_type = 'teamwork_group_create' THEN 1 " +
  "ELSE 0 END";

function handleDbError(res, err, label) {
  console.error(`Database error (${label})`, err);
  if (!res.headersSent) {
    if (process.env.DB_DEBUG === 'true') {
      return res.status(500).send(`Database error (${label})`);
    }
    return res.status(500).send('Database error');
  }
}

function ensureUsersSchema(cb) {
  usersHasIsActive = true;
  return cb(true);
}

function getAdminCourse(req) {
  const queryCourse = Number(req.query.course);
  if (!Number.isNaN(queryCourse)) {
    req.session.adminCourse = queryCourse;
  }
  const sessionCourse = Number(req.session.adminCourse);
  return Number.isNaN(sessionCourse) ? 1 : sessionCourse;
}

async function getActiveSemester(courseId) {
  const cached = cacheGet(referenceCache.activeSemester, courseId);
  if (cached) return cached;
  const row = await db.get(
    'SELECT id, title, start_date, weeks_count, is_active, is_archived FROM semesters WHERE course_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1',
    [courseId]
  );
  return cacheSet(referenceCache.activeSemester, courseId, row || null);
}

async function ensureCourseStudyDays(courseId) {
  const existing = await db.get('SELECT COUNT(*) AS count FROM course_study_days WHERE course_id = ?', [courseId]);
  if (existing && Number(existing.count) > 0) return;
  const now = new Date().toISOString();
  const inserts = [];
  for (let i = 1; i <= 7; i += 1) {
    const isActive = i <= 5 ? 1 : 0;
    inserts.push(
      db.run(
        `INSERT INTO course_study_days (course_id, weekday, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?) ON CONFLICT(course_id, weekday) DO NOTHING`,
        [courseId, i, isActive, now, now]
      )
    );
  }
  await Promise.all(inserts);
}

async function getCourseStudyDays(courseId) {
  const cached = cacheGet(referenceCache.studyDays, courseId);
  if (cached) return cached;
  await ensureCourseStudyDays(courseId);
  const rows = await db.all(
    `SELECT d.id, d.weekday, d.is_active, s.id AS subject_id, s.name AS subject_name
     FROM course_study_days d
     LEFT JOIN course_day_subjects cds ON cds.course_study_day_id = d.id
     LEFT JOIN subjects s ON s.id = cds.subject_id
     WHERE d.course_id = ?
     ORDER BY d.weekday, cds.sort_order, s.name`,
    [courseId]
  );
  const map = new Map();
  (rows || []).forEach((row) => {
    if (!map.has(row.weekday)) {
      map.set(row.weekday, {
        weekday: row.weekday,
        label: studyDayLabels[row.weekday - 1] || String(row.weekday),
        day_name: fullWeekDays[row.weekday - 1],
        is_active: !!row.is_active,
        subjects: [],
      });
    }
    if (row.subject_id) {
      map.get(row.weekday).subjects.push({ id: row.subject_id, name: row.subject_name });
    }
  });
  const result = Array.from(map.values()).sort((a, b) => a.weekday - b.weekday);
  return cacheSet(referenceCache.studyDays, courseId, result);
}

async function getCourseWeekTimeMap(courseId, semesterId) {
  if (!courseId || !semesterId) return new Map();
  const key = `${courseId}|${semesterId}`;
  const cached = cacheGet(referenceCache.weekTime, key);
  if (cached) return cached;
  const rows = await db.all(
    'SELECT week_number, use_local_time FROM course_week_time_modes WHERE course_id = ? AND semester_id = ?',
    [courseId, semesterId]
  );
  const map = new Map();
  (rows || []).forEach((row) => {
    map.set(Number(row.week_number), row.use_local_time === true || Number(row.use_local_time) === 1);
  });
  return cacheSet(referenceCache.weekTime, key, map);
}

async function getCourseWeekTimeList(courseId, semester) {
  if (!courseId || !semester || !semester.id) return [];
  const totalWeeks = Number(semester.weeks_count || 0);
  if (!totalWeeks) return [];
  const weekMap = await getCourseWeekTimeMap(courseId, semester.id);
  return Array.from({ length: totalWeeks }, (_, idx) => ({
    week_number: idx + 1,
    use_local_time: weekMap.get(idx + 1) === true,
  }));
}

async function isCourseDayActive(courseId, dayName) {
  if (!courseId || !dayName) return false;
  const studyDays = await getCourseStudyDays(courseId);
  return (studyDays || []).some((d) => d.is_active && d.day_name === dayName);
}

async function getTeacherSubjectCatalog() {
  return db.all(
    `
      SELECT s.id, s.name, s.group_count, s.is_general, s.course_id, c.name AS course_name
      FROM subjects s
      JOIN courses c ON c.id = s.course_id
      WHERE s.visible = 1
        AND EXISTS (
          SELECT 1
          FROM semesters sem
          WHERE sem.course_id = s.course_id AND sem.is_active = 1
        )
      ORDER BY c.id, s.name
    `
  );
}

async function getTeacherSelections(userId) {
  const rows = await db.all(
    'SELECT subject_id, group_number FROM teacher_subjects WHERE user_id = ?',
    [userId]
  );
  const map = new Map();
  (rows || []).forEach((row) => {
    map.set(Number(row.subject_id), row.group_number === null ? null : Number(row.group_number));
  });
  return map;
}

async function saveTeacherSubjects(userId, body, options = {}) {
  const catalog = await getTeacherSubjectCatalog();
  const selections = [];
  let hasAny = false;
  for (const subject of catalog) {
    const selected = body[`subject_${subject.id}`];
    if (!selected) {
      continue;
    }
    hasAny = true;
    const isGeneral = subject.is_general === true || Number(subject.is_general) === 1;
    if (isGeneral) {
      selections.push({ subject_id: subject.id, group_number: null });
      continue;
    }
    const groupVal = body[`group_${subject.id}`];
    const groupNum = Number(groupVal);
    if (!groupVal || Number.isNaN(groupNum) || groupNum < 1 || groupNum > Number(subject.group_count || 1)) {
      return { ok: false, error: 'Select%20group' };
    }
    selections.push({ subject_id: subject.id, group_number: groupNum });
  }
  if (!hasAny) {
    return { ok: false, error: 'Select%20subject' };
  }
  await db.run('DELETE FROM teacher_subjects WHERE user_id = ?', [userId]);
  for (const item of selections) {
    await db.run(
      'INSERT INTO teacher_subjects (user_id, subject_id, group_number) VALUES (?, ?, ?)',
      [userId, item.subject_id, item.group_number]
    );
  }
  const existing = await db.get('SELECT status FROM teacher_requests WHERE user_id = ?', [userId]);
  let nextStatus = existing ? String(existing.status || 'pending') : 'pending';
  if (nextStatus === 'rejected') {
    nextStatus = 'pending';
  }
  if (existing) {
    if (nextStatus !== 'approved' || options.allowPendingReset) {
      await db.run(
        'UPDATE teacher_requests SET status = ?, updated_at = NOW() WHERE user_id = ?',
        [nextStatus, userId]
      );
    } else {
      await db.run('UPDATE teacher_requests SET updated_at = NOW() WHERE user_id = ?', [userId]);
    }
  } else {
    await db.run(
      'INSERT INTO teacher_requests (user_id, status) VALUES (?, ?)',
      [userId, nextStatus]
    );
  }
  return { ok: true, status: nextStatus, selections };
}

function broadcast(type, payload) {
  const message = JSON.stringify({ type, payload });
  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(message);
    }
  });
}

function sortSchedule(schedule, sortKey) {
  if (!sortKey) return schedule;
  const copy = [...schedule];
  if (sortKey === 'day') {
    const order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    copy.sort(
      (a, b) =>
        order.indexOf(a.day_of_week) - order.indexOf(b.day_of_week) || a.class_number - b.class_number
    );
  } else if (sortKey === 'time') {
    copy.sort((a, b) => a.class_number - b.class_number);
  } else if (sortKey === 'group') {
    copy.sort((a, b) => a.group_number - b.group_number || a.day_of_week.localeCompare(b.day_of_week));
  }
  return copy;
}

function sortHomework(homework, sortKey) {
  if (!sortKey) return homework;
  const copy = [...homework];
  if (sortKey === 'created') {
    copy.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  } else if (sortKey === 'subject') {
    copy.sort((a, b) => a.subject.localeCompare(b.subject));
  }
  return copy;
}

app.get('/', (req, res) => {
  res.render('login', { error: req.query.error === '1' });
});

app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error === '1' });
});

app.get('/_health', (req, res) => {
  res.json({
    status: 'ok',
    db: {
      initStatus,
      error: initError ? String(initError.message || initError) : null,
    },
  });
});

app.get('/__version', (req, res) => {
  res.json({
    version: appVersion,
    buildStamp,
    node: process.version,
  });
});

app.post('/_bootstrap', async (req, res) => {
  const token = process.env.BOOTSTRAP_TOKEN;
  const provided = req.get('x-bootstrap-token') || req.query.token || '';
  if (!token || provided !== token) {
    return res.status(403).json({ ok: false, error: 'Forbidden' });
  }
  try {
    await ensureDbReady();
    return res.json({ ok: true, initStatus });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.post('/login', authLimiter, async (req, res) => {
  const { full_name, password, remember_me } = req.body;
  if (!full_name || !password) {
    return res.redirect('/login?error=1');
  }
  try {
    await ensureDbReady();
  } catch (err) {
    console.error('DB init failed', err);
    return res.redirect('/login?error=1');
  }
  ensureUsersSchema(() => {
    const normalizedName = full_name.trim().replace(/\s+/g, ' ');
    const activeClause = usersHasIsActive ? ' AND is_active = 1' : '';
    const normalizeRole = (rawRole) => {
      const normalized = String(rawRole || 'student').trim().toLowerCase();
      const map = {
        admin: 'admin',
        administrator: 'admin',
        адмін: 'admin',
        администратор: 'admin',
        starosta: 'starosta',
        староста: 'starosta',
        deanery: 'deanery',
        деканат: 'deanery',
        student: 'student',
        студент: 'student',
      };
      return map[normalized] || 'student';
    };
    db.get(
      `SELECT id, full_name, role, password_hash, schedule_group, course_id, language FROM users WHERE LOWER(full_name) = LOWER(?)${activeClause}`,
      [normalizedName],
      (err, user) => {
        const validHash = user && user.password_hash ? bcrypt.compareSync(password, user.password_hash) : false;
        if (err || !user || !validHash) {
          return res.redirect('/login?error=1');
        }
        const role = normalizeRole(user.role);
        if (role !== user.role) {
          db.run('UPDATE users SET role = ? WHERE id = ?', [role, user.id]);
        }
        const loginAt = new Date().toISOString();
        db.run(
          'UPDATE users SET last_login_ip = ?, last_user_agent = ?, last_login_at = ? WHERE id = ?',
          [req.ip, req.headers['user-agent'] || null, loginAt, user.id]
        );
        db.run(
          'INSERT INTO login_history (user_id, full_name, ip, user_agent, created_at, course_id) VALUES (?, ?, ?, ?, ?, ?)',
          [user.id, user.full_name, req.ip, req.headers['user-agent'] || null, loginAt, user.course_id || 1]
        );
        req.session.user = {
          id: user.id,
          username: user.full_name,
          schedule_group: user.schedule_group,
          course_id: user.course_id || 1,
          language: user.language || getPreferredLang(req),
        };
        req.session.role = role;
        const remember = remember_me === '1' || remember_me === 'on' || remember_me === true;
        req.session.rememberMe = remember;
        applyRememberMe(req, remember);

        req.session.save(() => {
          if (role === 'admin') {
            return res.redirect('/admin');
          }
          return res.redirect('/schedule');
        });
      }
    );
  });
});

app.get('/register', (req, res) => {
  res.render('register', { error: req.query.error || '' });
});

app.post('/register', registerLimiter, async (req, res) => {
  const { full_name, password, confirm_password, agree, remember_me } = req.body;
  if (!full_name || !password || !confirm_password || !agree) {
    return res.redirect('/register?error=Missing%20fields');
  }
  if (password !== confirm_password) {
    return res.redirect('/register?error=Passwords%20do%20not%20match');
  }

  try {
    await ensureDbReady();
    const normalizedName = full_name.trim().replace(/\s+/g, ' ');
    const existing = await db.get('SELECT id FROM users WHERE LOWER(full_name) = LOWER(?)', [normalizedName]);
    if (existing) {
      return res.redirect('/register?error=User%20already%20exists');
    }
    const hash = await bcrypt.hash(password, 10);
    const preferredLang = getPreferredLang(req);
    const row = await db.get(
      'INSERT INTO users (full_name, role, password_hash, is_active, schedule_group, course_id, language) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id',
      [normalizedName, 'student', hash, 1, 'A', null, preferredLang]
    );
    if (!row || !row.id) {
      return res.redirect('/register?error=Database%20error');
    }
    req.session.pendingUserId = row.id;
    req.session.rememberMe = remember_me === '1' || remember_me === 'on' || remember_me === true;
    logAction(db, req, 'register_user', { user_id: row.id, full_name: normalizedName });
    broadcast('users_updated');
    return res.redirect('/register/course');
  } catch (err) {
    console.error('Register failed', err);
    return res.redirect('/register?error=Database%20error');
  }
});

app.get('/register/course', (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect('/register');
  }
  ensureDbReady().catch((err) => {
    console.error('DB init failed', err);
  });
  (async () => {
    try {
      const courses = await getCoursesCached();
      return res.render('register-course', { courses, error: req.query.error || '' });
    } catch (err) {
      return res.status(500).send('Database error');
    }
  })();
});

app.post('/register/course', registerLimiter, (req, res) => {
  const userId = req.session.pendingUserId;
  if (!userId) {
    return res.redirect('/register');
  }
  const courseId = Number(req.body.course_id);
  if (Number.isNaN(courseId)) {
    return res.redirect('/register/course?error=Select%20course');
  }
  db.get('SELECT id, is_teacher_course FROM courses WHERE id = ?', [courseId], (err, course) => {
    if (err || !course) {
      return res.redirect('/register/course?error=Invalid%20course');
    }
    db.run('UPDATE users SET course_id = ? WHERE id = ?', [courseId, userId], (updErr) => {
      if (updErr) {
        return res.redirect('/register/course?error=Database%20error');
      }
      if (course.is_teacher_course === true || Number(course.is_teacher_course) === 1) {
        return res.redirect('/register/teacher-subjects');
      }
      return res.redirect('/register/subjects');
    });
  });
});

app.get('/register/subjects', (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect('/register');
  }
  ensureDbReady().catch((err) => {
    console.error('DB init failed', err);
  });
  db.get('SELECT course_id FROM users WHERE id = ?', [req.session.pendingUserId], (uErr, user) => {
    if (uErr || !user || !user.course_id) {
      return res.redirect('/register/course');
    }
    db.get('SELECT is_teacher_course FROM courses WHERE id = ?', [user.course_id], (cErr, course) => {
      if (!cErr && course && (course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
        return res.redirect('/register/teacher-subjects');
      }
    (async () => {
      try {
        const subjects = await getSubjectsCached(user.course_id, { visibleOnly: true });
        const isRequired = (s) => s && (s.is_required === true || s.is_required === 1 || s.is_required === '1');
        const requiredAuto = (subjects || []).filter((s) => isRequired(s) && Number(s.group_count) === 1);
        await Promise.all(
          requiredAuto.map((s) =>
            db.run(
              `INSERT INTO student_groups (student_id, subject_id, group_number)
               VALUES (?, ?, 1)
               ON CONFLICT(student_id, subject_id) DO NOTHING`,
              [req.session.pendingUserId, s.id]
            )
          )
        );
        const optoutRows = await db.all(
          'SELECT subject_id FROM user_subject_optouts WHERE user_id = ?',
          [req.session.pendingUserId]
        );
        const optouts = (optoutRows || []).map((r) => r.subject_id);
        res.render('register-subjects', { subjects, optouts, error: req.query.error || '' });
      } catch (err) {
        res.status(500).send('Database error');
      }
    })();
    });
  });
});

app.post('/register/subjects', registerLimiter, (req, res) => {
  const userId = req.session.pendingUserId;
  if (!userId) {
    return res.redirect('/register');
  }

  db.get('SELECT course_id FROM users WHERE id = ?', [userId], (uErr, userRow) => {
    if (uErr || !userRow || !userRow.course_id) {
      return res.redirect('/register/course');
    }
    db.all(
      'SELECT id, group_count, default_group, is_required FROM subjects WHERE course_id = ? AND visible = 1',
      [userRow.course_id],
      (err, subjects) => {
      if (err) {
        return res.status(500).send('Database error');
      }
      let hasMissingRequired = false;
      const stmt = db.prepare(
        `
          INSERT INTO student_groups (student_id, subject_id, group_number)
          VALUES (?, ?, ?)
          ON CONFLICT(student_id, subject_id)
          DO UPDATE SET group_number = excluded.group_number
        `
      );
      const deleteStmt = db.prepare('DELETE FROM student_groups WHERE student_id = ? AND subject_id = ?');
      const optoutStmt = db.prepare(
        `INSERT INTO user_subject_optouts (user_id, subject_id) VALUES (?, ?)
         ON CONFLICT(user_id, subject_id) DO NOTHING`
      );
      const optoutDeleteStmt = db.prepare('DELETE FROM user_subject_optouts WHERE user_id = ? AND subject_id = ?');
      const isRequired = (s) => s && (s.is_required === true || s.is_required === 1 || s.is_required === '1');
      subjects.forEach((s) => {
        const value = req.body[`subject_${s.id}`];
        const requiredFlag = isRequired(s);
        const optout = req.body[`optout_${s.id}`] === '1' || req.body[`optout_${s.id}`] === 'on';
        if (requiredFlag) {
          optoutDeleteStmt.run(userId, s.id);
          if (Number(s.group_count) === 1) {
            stmt.run(userId, s.id, 1);
            return;
          }
          if (!value) {
            hasMissingRequired = true;
            return;
          }
          const groupNum = Number(value);
          if (groupNum >= 1 && groupNum <= s.group_count) {
            stmt.run(userId, s.id, groupNum);
          } else {
            hasMissingRequired = true;
          }
          return;
        }
        if (optout) {
          deleteStmt.run(userId, s.id);
          optoutStmt.run(userId, s.id);
          return;
        }
        optoutDeleteStmt.run(userId, s.id);
        if (!value) {
          if (Number(s.group_count) === 1) {
            stmt.run(userId, s.id, 1);
            return;
          }
          return;
        }
        const groupNum = Number(value);
        if (groupNum >= 1 && groupNum <= s.group_count) {
          stmt.run(userId, s.id, groupNum);
        } else {
          hasMissingRequired = true;
        }
      });
      stmt.finalize(() => {
        deleteStmt.finalize();
        optoutStmt.finalize();
        optoutDeleteStmt.finalize();
        if (hasMissingRequired) {
          return res.redirect('/register/subjects?error=Select%20group');
        }
        db.get('SELECT id, full_name, role, schedule_group, course_id, language FROM users WHERE id = ?', [userId], (uErr2, user) => {
          if (uErr2 || !user) {
            return res.redirect('/login');
          }
          req.session.user = {
            id: user.id,
            username: user.full_name,
            schedule_group: user.schedule_group,
            course_id: user.course_id || 1,
            language: user.language || getPreferredLang(req),
          };
          req.session.role = user.role;
          applyRememberMe(req, Boolean(req.session.rememberMe));
          req.session.pendingUserId = null;
          req.session.rememberMe = null;
          logAction(db, req, 'register_subjects', { user_id: user.id });
          broadcast('users_updated');
          return req.session.save(() => res.redirect('/schedule?welcome=1'));
        });
      });
    });
  });
});

app.get('/register/teacher-subjects', (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect('/register');
  }
  ensureDbReady().catch((err) => {
    console.error('DB init failed', err);
  });
  db.get('SELECT id, course_id FROM users WHERE id = ?', [req.session.pendingUserId], (uErr, user) => {
    if (uErr || !user || !user.course_id) {
      return res.redirect('/register/course');
    }
    db.get('SELECT is_teacher_course FROM courses WHERE id = ?', [user.course_id], async (cErr, course) => {
      if (cErr || !course) {
        return res.redirect('/register/course');
      }
      if (!(course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
        return res.redirect('/register/subjects');
      }
      try {
        const subjects = await getTeacherSubjectCatalog();
        const selections = await getTeacherSelections(user.id);
        return res.render('register-teacher-subjects', {
          subjects,
          selections,
          error: req.query.error || '',
          isProfileEdit: false,
        });
      } catch (err) {
        return res.status(500).send('Database error');
      }
    });
  });
});

app.post('/register/teacher-subjects', registerLimiter, async (req, res) => {
  const userId = req.session.pendingUserId;
  if (!userId) {
    return res.redirect('/register');
  }
  try {
    const userRow = await db.get('SELECT id, full_name, role, schedule_group, course_id, language FROM users WHERE id = ?', [userId]);
    if (!userRow || !userRow.course_id) {
      return res.redirect('/register/course');
    }
    const course = await db.get('SELECT is_teacher_course FROM courses WHERE id = ?', [userRow.course_id]);
    if (!course || !(course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
      return res.redirect('/register/subjects');
    }
    const result = await saveTeacherSubjects(userId, req.body);
    if (!result.ok) {
      return res.redirect(`/register/teacher-subjects?error=${result.error || 'Select%20subject'}`);
    }
    req.session.user = {
      id: userRow.id,
      username: userRow.full_name,
      schedule_group: userRow.schedule_group,
      course_id: userRow.course_id || 1,
      language: userRow.language || getPreferredLang(req),
    };
    req.session.role = userRow.role || 'student';
    applyRememberMe(req, Boolean(req.session.rememberMe));
    req.session.pendingUserId = null;
    req.session.rememberMe = null;
    logAction(db, req, 'register_teacher_subjects', { user_id: userRow.id });
    broadcast('users_updated');
    return req.session.save(() => res.redirect('/teacher/pending'));
  } catch (err) {
    console.error('Register teacher subjects failed', err);
    return res.redirect('/register/teacher-subjects?error=Database%20error');
  }
});

app.get('/teacher/subjects', requireLogin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'teacher.subjects.init');
  }
  const { id: userId, course_id: courseId } = req.session.user;
  try {
    const course = await db.get('SELECT is_teacher_course FROM courses WHERE id = ?', [courseId]);
    if (!course || !(course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
      return res.redirect('/schedule');
    }
    const subjects = await getTeacherSubjectCatalog();
    const selections = await getTeacherSelections(userId);
    return res.render('register-teacher-subjects', {
      subjects,
      selections,
      error: req.query.error || '',
      isProfileEdit: true,
    });
  } catch (err) {
    return handleDbError(res, err, 'teacher.subjects');
  }
});

app.post('/teacher/subjects', requireLogin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'teacher.subjects.save.init');
  }
  const { id: userId, course_id: courseId } = req.session.user;
  try {
    const course = await db.get('SELECT is_teacher_course FROM courses WHERE id = ?', [courseId]);
    if (!course || !(course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
      return res.redirect('/schedule');
    }
    const result = await saveTeacherSubjects(userId, req.body);
    if (!result.ok) {
      return res.redirect(`/teacher/subjects?error=${result.error || 'Select%20subject'}`);
    }
    logAction(db, req, 'teacher_subjects_update', { user_id: userId });
    broadcast('users_updated');
    return res.redirect('/profile?ok=Subjects%20updated');
  } catch (err) {
    console.error('Failed to save teacher subjects', err);
    return res.redirect('/teacher/subjects?error=Database%20error');
  }
});

app.get('/teacher/pending', requireLogin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'teacher.pending.init');
  }
  try {
    const { id: userId, course_id: courseId } = req.session.user;
    const course = await db.get('SELECT is_teacher_course FROM courses WHERE id = ?', [courseId]);
    if (!course || !(course.is_teacher_course === true || Number(course.is_teacher_course) === 1)) {
      return res.redirect('/schedule');
    }
    const request = await db.get('SELECT status FROM teacher_requests WHERE user_id = ?', [userId]);
    if (request && request.status === 'approved') {
      req.session.role = 'teacher';
      return res.redirect('/schedule');
    }
    return res.render('teacher-pending', {
      status: request ? request.status : 'pending',
    });
  } catch (err) {
    return handleDbError(res, err, 'teacher.pending');
  }
});

app.get('/profile', requireLogin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'profile.init');
  }
  const { id, role, username } = req.session.user;
  try {
    const user = await db.get('SELECT id, full_name, course_id, language FROM users WHERE id = ?', [id]);
    if (!user) {
      return res.status(500).send('Database error');
    }
    let teacherStatus = null;
    let teacherCourse = false;
    if (user.course_id) {
      teacherCourse = await isTeacherCourse(user.course_id);
      if (teacherCourse) {
        const tr = await db.get('SELECT status FROM teacher_requests WHERE user_id = ?', [id]);
        teacherStatus = tr ? tr.status : null;
      }
    }
    const activeSemester = await getActiveSemester(user.course_id || 1);
    const pointsRow = await db.get(
      `
        SELECT COALESCE(SUM(${ACTIVITY_POINTS_CASE}), 0) AS points
        FROM activity_log
        WHERE user_id = ?${activeSemester ? ' AND semester_id = ?' : ''}
      `,
      activeSemester ? [id, activeSemester.id] : [id]
    );
    const activityPoints = pointsRow ? Number(pointsRow.points || 0) : 0;
    const analyticsParams = activeSemester ? [id, user.course_id || 1, activeSemester.id] : [id, user.course_id || 1];
    const [
      homeworkCreatedRow,
      teamworkCreatedRow,
      teamworkJoinedRow,
    ] = await Promise.all([
      db.get(
        `SELECT COUNT(*) AS count
         FROM homework
         WHERE created_by_id = ? AND course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}`,
        analyticsParams
      ),
      db.get(
        `SELECT COUNT(*) AS count
         FROM teamwork_tasks
         WHERE created_by = ? AND course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}`,
        analyticsParams
      ),
      db.get(
        `SELECT COUNT(*) AS count
         FROM teamwork_members m
         JOIN teamwork_tasks t ON t.id = m.task_id
         WHERE m.user_id = ? AND t.course_id = ?${activeSemester ? ' AND t.semester_id = ?' : ''}`,
        analyticsParams
      ),
    ]);
    const profileStats = {
      homeworkCreated: Number(homeworkCreatedRow?.count || 0),
      teamworkCreated: Number(teamworkCreatedRow?.count || 0),
      teamworkJoined: Number(teamworkJoinedRow?.count || 0),
    };
    res.render('profile', {
      user,
      activityPoints,
      profileStats,
      teacherStatus,
      teacherCourse,
      error: req.query.error || '',
      success: req.query.ok || '',
      role,
      username,
    });
  } catch (err) {
    return handleDbError(res, err, 'profile');
  }
});

app.post('/profile', requireLogin, (req, res) => {
  const { full_name, password, confirm_password, language } = req.body;
  const { id } = req.session.user;
  if (!full_name) {
    return res.redirect('/profile?error=Full%20name%20required');
  }
  if ((password || confirm_password) && password !== confirm_password) {
    return res.redirect('/profile?error=Passwords%20do%20not%20match');
  }

  const updates = [];
  const params = [];
  updates.push('full_name = ?');
  params.push(full_name.trim());

  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    updates.push('password_hash = ?');
    params.push(hash);
  }

  if (language && ['uk', 'en'].includes(language)) {
    updates.push('language = ?');
    params.push(language);
  }

  params.push(id);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, (err) => {
    if (err) {
      return res.redirect('/profile?error=Name%20already%20exists');
    }
    req.session.user.username = full_name.trim();
    if (language && ['uk', 'en'].includes(language)) {
      req.session.user.language = language;
      req.session.lang = language;
    }
    logAction(db, req, 'update_profile', { user_id: id });
    broadcast('users_updated');
    return res.redirect('/profile?ok=Profile%20updated');
  });
});

app.post('/profile/reset-subjects', requireLogin, async (req, res) => {
  const { id } = req.session.user;
  try {
    await db.run('DELETE FROM student_groups WHERE student_id = ?', [id]);
    await db.run('DELETE FROM user_subject_optouts WHERE user_id = ?', [id]);
    req.session.pendingUserId = id;
    logAction(db, req, 'reset_subjects', { user_id: id });
    broadcast('users_updated');
    return req.session.save(() => res.redirect('/register/subjects'));
  } catch (err) {
    console.error('Failed to reset subjects', err);
    return res.redirect('/profile?error=Database%20error');
  }
});

async function buildMyDayData(user) {
  const courseId = user.course_id || 1;
  const activeSemester = await getActiveSemester(courseId);
  const now = new Date();
  const todayStr = formatLocalDate(now);
  const tomorrowStr = formatLocalDate(addDays(now, 1));
  const dayName = getDayNameFromDate(todayStr);
  const weekNumber = getAcademicWeekForSemester(now, activeSemester);
  const nowIso = new Date().toISOString();

  const studentGroups = await db.all(
    `
      SELECT sg.subject_id, sg.group_number, s.name AS subject_name
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      WHERE sg.student_id = ? AND s.course_id = ? AND s.visible = 1
    `,
    [user.id, courseId]
  );

  let classesToday = [];
  if (studentGroups.length && dayName) {
    const conditions = studentGroups.map(() => '(se.subject_id = ? AND se.group_number = ?)').join(' OR ');
    const params = [weekNumber, courseId, activeSemester ? activeSemester.id : null, dayName];
    studentGroups.forEach((sg) => params.push(sg.subject_id, sg.group_number));
    const rows = await db.all(
      `
        SELECT se.*, s.name AS subject_name
        FROM schedule_entries se
        JOIN subjects s ON s.id = se.subject_id
        WHERE se.week_number = ?
          AND se.course_id = ?
          AND se.semester_id = ?
          AND se.day_of_week = ?
          AND s.visible = 1
          AND (${conditions})
        ORDER BY se.class_number ASC
      `,
      params
    );
    classesToday = (rows || []).map((row) => {
      const slot = bellSchedule[row.class_number] || {};
      return {
        id: row.id,
        subject_id: row.subject_id,
        subject_name: row.subject_name,
        class_number: row.class_number,
        group_number: row.group_number,
        day_of_week: row.day_of_week,
        start: slot.start || '',
        end: slot.end || '',
      };
    });
  }

  let currentClass = null;
  let nextClass = null;
  const nowMs = now.getTime();
  classesToday.forEach((cls) => {
    if (!cls.start || !cls.end) return;
    const startAt = new Date(`${todayStr}T${cls.start}:00`);
    const endAt = new Date(`${todayStr}T${cls.end}:00`);
    if (nowMs >= startAt.getTime() && nowMs <= endAt.getTime()) {
      currentClass = { ...cls, startAt: startAt.toISOString(), endAt: endAt.toISOString() };
    } else if (nowMs < startAt.getTime() && !nextClass) {
      nextClass = { ...cls, startAt: startAt.toISOString(), endAt: endAt.toISOString() };
    }
  });

  let homeworkItems = [];
  if (studentGroups.length) {
    const conditions = studentGroups.map(() => '(h.subject_id = ? AND h.group_number = ?)').join(' OR ');
    const params = [user.id];
    studentGroups.forEach((sg) => params.push(sg.subject_id, sg.group_number));
    params.push(courseId, activeSemester ? activeSemester.id : null, nowIso);
    const rows = await db.all(
      `
        SELECT h.id, h.description, h.custom_due_date, h.class_date, h.subject_id, h.group_number,
               h.created_by, h.created_at, subj.name AS subject_name, hc.id AS completion_id
        FROM homework h
        JOIN subjects subj ON subj.id = h.subject_id
        LEFT JOIN homework_completions hc ON hc.homework_id = h.id AND hc.user_id = ?
        WHERE (${conditions})
          AND h.course_id = ?
          AND h.semester_id = ?
          AND COALESCE(h.status, 'published') = 'published'
          AND (h.scheduled_at IS NULL OR h.scheduled_at <= ?)
          AND (h.custom_due_date IS NOT NULL OR h.class_date IS NOT NULL)
        ORDER BY COALESCE(h.custom_due_date, h.class_date) ASC, h.created_at DESC
      `,
      params
    );
    homeworkItems = (rows || []).map((row) => {
      const deadline = row.custom_due_date || row.class_date;
      return {
        id: row.id,
        description: row.description,
        subject_id: row.subject_id,
        subject_name: row.subject_name,
        group_number: row.group_number,
        deadline_date: deadline,
        created_by: row.created_by,
        created_at: row.created_at,
        completed: Boolean(row.completion_id),
      };
    });
  }

  const homeworkDeadlines = homeworkItems
    .filter((item) => item.deadline_date === todayStr || item.deadline_date === tomorrowStr)
    .map((item) => ({ ...item, type: 'homework' }));

  let teamworkDeadlines = [];
  if (studentGroups.length) {
    const subjectIds = Array.from(new Set(studentGroups.map((sg) => sg.subject_id)));
    if (subjectIds.length) {
      const placeholders = subjectIds.map(() => '?').join(',');
      const params = [courseId, activeSemester ? activeSemester.id : null, todayStr, tomorrowStr, ...subjectIds];
      const rows = await db.all(
        `
          SELECT t.id, t.title, t.due_date, t.subject_id, s.name AS subject_name
          FROM teamwork_tasks t
          JOIN subjects s ON s.id = t.subject_id
          WHERE t.course_id = ?
            AND t.semester_id = ?
            AND t.due_date IS NOT NULL
            AND t.due_date >= ?
            AND t.due_date <= ?
            AND t.subject_id IN (${placeholders})
          ORDER BY t.due_date ASC, t.created_at DESC
        `,
        params
      );
      teamworkDeadlines = (rows || []).map((row) => ({
        id: row.id,
        description: row.title,
        subject_id: row.subject_id,
        subject_name: row.subject_name,
        deadline_date: row.due_date,
        type: 'teamwork',
      }));
    }
  }

  const deadlines = [...homeworkDeadlines, ...teamworkDeadlines].sort((a, b) =>
    String(a.deadline_date || '').localeCompare(String(b.deadline_date || ''))
  );

  const upcomingWindowEnd = formatLocalDate(addDays(now, 7));
  const upcomingItems = homeworkItems.filter((item) => {
    if (!item.deadline_date) return false;
    return item.deadline_date >= todayStr && item.deadline_date <= upcomingWindowEnd;
  });
  let topPriorities = [];
  if (upcomingItems.length) {
    const earliest = upcomingItems[0];
    const subjectCounts = {};
    upcomingItems.forEach((item) => {
      const key = String(item.subject_id);
      subjectCounts[key] = (subjectCounts[key] || 0) + 1;
    });
    let topSubjectId = null;
    let topCount = 0;
    Object.entries(subjectCounts).forEach(([key, count]) => {
      if (count > topCount) {
        topCount = count;
        topSubjectId = Number(key);
      }
    });
    topPriorities.push({ type: 'earliest', ...earliest });
    if (topSubjectId && topSubjectId !== earliest.subject_id) {
      const topSubjectItem = upcomingItems.find((item) => item.subject_id === topSubjectId);
      if (topSubjectItem) {
        topPriorities.push({ type: 'workload', ...topSubjectItem });
      }
    }
  }

  let reminders = [];
  if (activeSemester) {
    const rows = await db.all(
      `
        SELECT id, title, note, remind_date, remind_time, is_done, created_at
        FROM personal_reminders
        WHERE user_id = ?
          AND course_id = ?
          AND semester_id = ?
          AND remind_date >= ?
          AND remind_date <= ?
        ORDER BY remind_date ASC, remind_time ASC NULLS LAST, created_at DESC
      `,
      [user.id, courseId, activeSemester.id, todayStr, upcomingWindowEnd]
    );
    reminders = (rows || []).map((row) => ({
      id: row.id,
      title: row.title,
      note: row.note,
      remind_date: row.remind_date,
      remind_time: row.remind_time,
      is_done: Boolean(row.is_done),
    }));
  }

  return {
    today: todayStr,
    tomorrow: tomorrowStr,
    day_name: dayName,
    week_number: weekNumber,
    classes_today: classesToday,
    current_class: currentClass,
    next_class: nextClass,
    deadlines,
    top_priorities: topPriorities,
    reminders,
    reminders_window_end: upcomingWindowEnd,
  };
}

app.get('/my-day', requireLogin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'myday.init');
  }
  try {
    const myDay = await buildMyDayData(req.session.user);
    return res.render('my-day', {
      username: req.session.user.username,
      role: req.session.role,
      viewAs: req.session.viewAs || null,
      myDay,
    });
  } catch (err) {
    return handleDbError(res, err, 'myday');
  }
});

app.get('/api/my-day', requireLogin, readLimiter, async (req, res) => {
  try {
    const myDay = await buildMyDayData(req.session.user);
    return res.json(myDay);
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/reminders', requireLogin, readLimiter, async (req, res) => {
  const { from, to, status } = req.query;
  if (from && !isValidDateString(String(from))) {
    return res.status(400).json({ error: 'Invalid from date' });
  }
  if (to && !isValidDateString(String(to))) {
    return res.status(400).json({ error: 'Invalid to date' });
  }
  const filterStatus = status === 'all' || status === 'done' ? status : 'open';
  try {
    const { id: userId, course_id: courseId } = req.session.user;
    const activeSemester = await getActiveSemester(courseId || 1);
    if (!activeSemester) {
      return res.status(400).json({ error: 'No active semester' });
    }
    const clauses = ['user_id = ?', 'course_id = ?', 'semester_id = ?'];
    const params = [userId, courseId || 1, activeSemester.id];
    if (from) {
      clauses.push('remind_date >= ?');
      params.push(String(from));
    }
    if (to) {
      clauses.push('remind_date <= ?');
      params.push(String(to));
    }
    if (filterStatus !== 'all') {
      clauses.push('is_done = ?');
      params.push(filterStatus === 'done' ? 1 : 0);
    }
    const rows = await db.all(
      `
        SELECT id, title, note, remind_date, remind_time, is_done
        FROM personal_reminders
        WHERE ${clauses.join(' AND ')}
        ORDER BY remind_date ASC, remind_time ASC NULLS LAST, created_at DESC
      `,
      params
    );
    return res.json({ reminders: rows || [] });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/reminders', requireLogin, writeLimiter, async (req, res) => {
  const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
  const note = typeof req.body.note === 'string' ? req.body.note.trim() : '';
  const remindDate = typeof req.body.remind_date === 'string' ? req.body.remind_date.trim() : '';
  const remindTime = typeof req.body.remind_time === 'string' ? req.body.remind_time.trim() : '';
  if (!title) {
    return res.status(400).json({ error: 'Title required' });
  }
  if (title.length > 160) {
    return res.status(400).json({ error: 'Title too long' });
  }
  if (!isValidDateString(remindDate)) {
    return res.status(400).json({ error: 'Invalid date' });
  }
  if (remindTime && !isValidTimeString(remindTime)) {
    return res.status(400).json({ error: 'Invalid time' });
  }
  if (note.length > 500) {
    return res.status(400).json({ error: 'Note too long' });
  }
  try {
    const { id: userId, course_id: courseId } = req.session.user;
    const activeSemester = await getActiveSemester(courseId || 1);
    if (!activeSemester) {
      return res.status(400).json({ error: 'No active semester' });
    }
    const nowIso = new Date().toISOString();
    const row = await db.get(
      `
        INSERT INTO personal_reminders
          (user_id, title, note, remind_date, remind_time, is_done, created_at, updated_at, course_id, semester_id)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        RETURNING id, title, note, remind_date, remind_time, is_done
      `,
      [
        userId,
        title,
        note || null,
        remindDate,
        remindTime || null,
        nowIso,
        nowIso,
        courseId || 1,
        activeSemester.id,
      ]
    );
    if (!row) {
      return res.status(500).json({ error: 'Database error' });
    }
    return res.json({ reminder: row });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/api/reminders/:id', requireLogin, writeLimiter, async (req, res) => {
  const reminderId = Number(req.params.id);
  if (Number.isNaN(reminderId)) {
    return res.status(400).json({ error: 'Invalid reminder' });
  }
  const updates = [];
  const params = [];
  if (typeof req.body.title === 'string') {
    const title = req.body.title.trim();
    if (!title) {
      return res.status(400).json({ error: 'Title required' });
    }
    if (title.length > 160) {
      return res.status(400).json({ error: 'Title too long' });
    }
    updates.push('title = ?');
    params.push(title);
  }
  if (typeof req.body.note === 'string') {
    const note = req.body.note.trim();
    if (note.length > 500) {
      return res.status(400).json({ error: 'Note too long' });
    }
    updates.push('note = ?');
    params.push(note || null);
  }
  if (typeof req.body.remind_date === 'string') {
    const remindDate = req.body.remind_date.trim();
    if (!isValidDateString(remindDate)) {
      return res.status(400).json({ error: 'Invalid date' });
    }
    updates.push('remind_date = ?');
    params.push(remindDate);
  }
  if (typeof req.body.remind_time === 'string') {
    const remindTime = req.body.remind_time.trim();
    if (remindTime && !isValidTimeString(remindTime)) {
      return res.status(400).json({ error: 'Invalid time' });
    }
    updates.push('remind_time = ?');
    params.push(remindTime || null);
  }
  if (typeof req.body.is_done !== 'undefined') {
    const done = req.body.is_done === true || req.body.is_done === 'true' || req.body.is_done === 1 || req.body.is_done === '1';
    updates.push('is_done = ?');
    params.push(done ? 1 : 0);
  }
  if (!updates.length) {
    return res.status(400).json({ error: 'No changes' });
  }
  try {
    const { id: userId, course_id: courseId } = req.session.user;
    const activeSemester = await getActiveSemester(courseId || 1);
    if (!activeSemester) {
      return res.status(400).json({ error: 'No active semester' });
    }
    updates.push('updated_at = ?');
    params.push(new Date().toISOString());
    params.push(reminderId, userId, courseId || 1, activeSemester.id);
    const row = await db.get(
      `
        UPDATE personal_reminders
        SET ${updates.join(', ')}
        WHERE id = ? AND user_id = ? AND course_id = ? AND semester_id = ?
        RETURNING id, title, note, remind_date, remind_time, is_done
      `,
      params
    );
    if (!row) {
      return res.status(404).json({ error: 'Not found' });
    }
    return res.json({ reminder: row });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/reminders/:id', requireLogin, writeLimiter, async (req, res) => {
  const reminderId = Number(req.params.id);
  if (Number.isNaN(reminderId)) {
    return res.status(400).json({ error: 'Invalid reminder' });
  }
  try {
    const { id: userId, course_id: courseId } = req.session.user;
    const activeSemester = await getActiveSemester(courseId || 1);
    if (!activeSemester) {
      return res.status(400).json({ error: 'No active semester' });
    }
    const result = await db.run(
      'DELETE FROM personal_reminders WHERE id = ? AND user_id = ? AND course_id = ? AND semester_id = ?',
      [reminderId, userId, courseId || 1, activeSemester.id]
    );
    if (!result || !result.changes) {
      return res.status(404).json({ error: 'Not found' });
    }
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/homework/:id/complete', requireLogin, writeLimiter, async (req, res) => {
  const homeworkId = Number(req.params.id);
  if (Number.isNaN(homeworkId)) {
    return res.status(400).json({ error: 'Invalid homework' });
  }
  const { id: userId, course_id: courseId } = req.session.user;
  const activeSemester = await getActiveSemester(courseId || 1);
  const nowIso = new Date().toISOString();
  try {
    const homework = await db.get(
      `SELECT id, subject_id, group_number
       FROM homework
       WHERE id = ? AND course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}
         AND COALESCE(status, 'published') = 'published'
         AND (scheduled_at IS NULL OR scheduled_at <= ?)`,
      activeSemester ? [homeworkId, courseId || 1, activeSemester.id, nowIso] : [homeworkId, courseId || 1, nowIso]
    );
    if (!homework) {
      return res.status(404).json({ error: 'Not found' });
    }
    const access = await db.get(
      'SELECT 1 FROM student_groups WHERE student_id = ? AND subject_id = ? AND group_number = ?',
      [userId, homework.subject_id, homework.group_number]
    );
    if (!access) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const existing = await db.get(
      'SELECT id FROM homework_completions WHERE homework_id = ? AND user_id = ?',
      [homeworkId, userId]
    );
    if (existing) {
      await db.run('DELETE FROM homework_completions WHERE id = ?', [existing.id]);
      return res.json({ completed: false });
    }
    await db.run(
      'INSERT INTO homework_completions (user_id, homework_id, done_at) VALUES (?, ?, ?)',
      [userId, homeworkId, new Date().toISOString()]
    );
    return res.json({ completed: true });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/schedule', requireLogin, async (req, res) => {
  const { id: userId, schedule_group: group, username, course_id: courseId } = req.session.user;
  if (req.session.role === 'teacher') {
    try {
      await ensureDbReady();
      const teacherSubjects = await db.all(
        `
          SELECT ts.subject_id, ts.group_number, s.name AS subject_name, s.group_count, s.is_general,
                 s.course_id, c.name AS course_name
          FROM teacher_subjects ts
          JOIN subjects s ON s.id = ts.subject_id
          JOIN courses c ON c.id = s.course_id
          WHERE ts.user_id = ? AND s.visible = 1
          ORDER BY c.id, s.name
        `,
        [userId]
      );
      const teacherCourseMap = new Map();
      teacherSubjects.forEach((row) => {
        if (!teacherCourseMap.has(row.course_id)) {
          teacherCourseMap.set(row.course_id, { id: row.course_id, name: row.course_name });
        }
      });
      const teacherCourses = Array.from(teacherCourseMap.values());
      const courseFilter = req.query.course ? Number(req.query.course) : null;
      const selectedCourse = teacherCourses.find((c) => Number(c.id) === Number(courseFilter)) || null;
      const courseIds = selectedCourse ? [selectedCourse.id] : teacherCourses.map((c) => c.id);
      const semesterMap = new Map();
      for (const cid of courseIds) {
        semesterMap.set(cid, await getActiveSemester(cid));
      }
      const courseWeekTime = new Map();
      for (const cid of courseIds) {
        const sem = semesterMap.get(cid);
        if (sem && sem.id) {
          courseWeekTime.set(cid, await getCourseWeekTimeMap(cid, sem.id));
        }
      }
      const primaryCourseId = selectedCourse ? selectedCourse.id : (courseIds[0] || null);
      const primarySemester = primaryCourseId ? semesterMap.get(primaryCourseId) : null;
      const totalWeeks = primarySemester && primarySemester.weeks_count ? Number(primarySemester.weeks_count) : 15;
      let selectedWeek = parseInt(req.query.week, 10);
      if (Number.isNaN(selectedWeek)) {
        selectedWeek = getAcademicWeekForSemester(new Date(), primarySemester);
      }
      if (selectedWeek < 1) selectedWeek = 1;
      if (selectedWeek > totalWeeks) selectedWeek = totalWeeks;

      let activeDaysSet = new Set();
      if (primaryCourseId) {
        if (selectedCourse) {
          const studyDays = await getCourseStudyDays(primaryCourseId);
          (studyDays || []).filter((d) => d.is_active).forEach((d) => {
            if (d.day_name) activeDaysSet.add(d.day_name);
          });
        } else {
          for (const cid of courseIds) {
            const studyDays = await getCourseStudyDays(cid);
            (studyDays || []).filter((d) => d.is_active).forEach((d) => {
              if (d.day_name) activeDaysSet.add(d.day_name);
            });
          }
        }
      }
      let activeDays = fullWeekDays.filter((day) => activeDaysSet.has(day));
      if (!activeDays.length) {
        activeDays = [...daysOfWeek];
      }
      const weekDates = fullWeekDays.map((_, idx) =>
        getDateForWeekIndex(selectedWeek, idx, primarySemester ? primarySemester.start_date : null)
      );
      const weekStartDate = weekDates[0];
      const weekEndDate = weekDates[6];
      const dayDates = {};
      activeDays.forEach((day) => {
        const idx = fullWeekDays.indexOf(day);
        dayDates[day] = idx >= 0 ? weekDates[idx] : null;
      });
      const scheduleByDay = {};
      activeDays.forEach((day) => {
        scheduleByDay[day] = [];
      });

      const selectionMap = new Map();
      teacherSubjects.forEach((row) => {
        const existing = selectionMap.get(row.subject_id) || {
          general: false,
          groups: new Set(),
          course_id: row.course_id,
          course_name: row.course_name,
          subject_name: row.subject_name,
        };
        if (row.group_number === null || typeof row.group_number === 'undefined') {
          existing.general = true;
        } else {
          existing.groups.add(Number(row.group_number));
        }
        selectionMap.set(row.subject_id, existing);
      });

      const courseNameMap = new Map(teacherCourses.map((c) => [Number(c.id), c.name]));
      const groupedMap = new Map();
      const scheduleRows = [];

      for (const cid of courseIds) {
        const subjectIds = teacherSubjects.filter((s) => Number(s.course_id) === Number(cid)).map((s) => s.subject_id);
        if (!subjectIds.length) continue;
        const sem = semesterMap.get(cid);
        const weekTimeMap = courseWeekTime.get(cid);
        const useLocalTime = weekTimeMap ? weekTimeMap.get(selectedWeek) === true : false;
        const placeholders = subjectIds.map(() => '?').join(',');
        const params = [selectedWeek, cid];
        let sql = `
          SELECT se.*, s.name AS subject_name
          FROM schedule_entries se
          JOIN subjects s ON s.id = se.subject_id
          WHERE se.week_number = ? AND se.course_id = ?
        `;
        if (sem) {
          sql += ' AND se.semester_id = ?';
          params.push(sem.id);
        }
        sql += ` AND se.subject_id IN (${placeholders})`;
        params.push(...subjectIds);
        const rows = await db.all(sql, params);
        rows.forEach((row) => {
          const selection = selectionMap.get(row.subject_id);
          if (!selection) return;
          if (!selection.general && !selection.groups.has(Number(row.group_number))) return;
          row.course_id = cid;
          row.course_name = courseNameMap.get(Number(cid)) || '';
          row.class_date = getDateForWeekDay(selectedWeek, row.day_of_week, sem ? sem.start_date : null);
          row.use_local_time = useLocalTime;
          scheduleRows.push(row);
        });
      }

      scheduleRows.forEach((row) => {
        const key = `${row.course_id}|${row.subject_id}|${row.day_of_week}|${row.class_number}`;
        if (!groupedMap.has(key)) {
          groupedMap.set(key, {
            ...row,
            group_numbers: new Set(),
          });
        }
        groupedMap.get(key).group_numbers.add(Number(row.group_number));
      });

      const teacherTargets = [];
      const targetSeen = new Set();
      teacherSubjects.forEach((row) => {
        const sem = semesterMap.get(row.course_id);
        const semId = sem ? sem.id : 0;
        if (row.group_number === null || typeof row.group_number === 'undefined') {
          const maxGroups = Number(row.group_count || 1);
          for (let g = 1; g <= maxGroups; g += 1) {
            const key = `${row.subject_id}|${g}|${row.course_id}|${semId}`;
            if (targetSeen.has(key)) continue;
            targetSeen.add(key);
            teacherTargets.push({
              subject_id: row.subject_id,
              group_number: g,
              course_id: row.course_id,
              semester_id: semId,
            });
          }
          return;
        }
        const groupNum = Number(row.group_number);
        const key = `${row.subject_id}|${groupNum}|${row.course_id}|${semId}`;
        if (targetSeen.has(key)) return;
        targetSeen.add(key);
        teacherTargets.push({
          subject_id: row.subject_id,
          group_number: groupNum,
          course_id: row.course_id,
          semester_id: semId,
        });
      });
      groupedMap.forEach((entry) => {
        const groups = Array.from(entry.group_numbers).sort((a, b) => a - b);
        const selection = selectionMap.get(entry.subject_id);
        let groupLabel = '';
        if (selection && selection.general) {
          groupLabel = 'Усі групи';
        } else if (groups.length === 1) {
          groupLabel = `Група ${groups[0]}`;
        } else {
          groupLabel = `Групи: ${groups.join(', ')}`;
        }
        const normalized = {
          ...entry,
          group_numbers: groups,
          group_number: groups[0] || null,
          group_label: groupLabel,
          is_general: selection ? selection.general : false,
        };
        if (scheduleByDay[entry.day_of_week]) {
          scheduleByDay[entry.day_of_week].push(normalized);
        }
      });

      activeDays.forEach((day) => {
        scheduleByDay[day].sort((a, b) => a.class_number - b.class_number);
      });

      const nowIso = new Date().toISOString();
      const homeworkMeta = {};
      const homeworkMetaAll = {};
      let homework = [];
      let homeworkTags = [];

      if (teacherTargets.length) {
        const hwConditions = teacherTargets
          .map(() => '(h.subject_id = ? AND h.group_number = ? AND h.course_id = ? AND COALESCE(h.semester_id, 0) = ?)')
          .join(' OR ');
        const hwParams = [];
        teacherTargets.forEach((t) => {
          hwParams.push(t.subject_id, t.group_number, t.course_id, t.semester_id);
        });
        const hwRows = await db.all(
          `
            SELECT h.*, subj.name AS subject_name, s.id AS subgroup_id, s.name AS subgroup_name, m.member_username AS subgroup_member
            FROM homework h
            JOIN subjects subj ON subj.id = h.subject_id
            LEFT JOIN subgroups s ON s.homework_id = h.id
            LEFT JOIN subgroup_members m ON m.subgroup_id = s.id
            WHERE (${hwConditions})
              AND COALESCE(h.status, 'published') = 'published'
              AND (h.scheduled_at IS NULL OR h.scheduled_at <= ?)
              AND (h.is_custom_deadline IS NULL OR h.is_custom_deadline = 0)
            ORDER BY h.created_at DESC
          `,
          [...hwParams, nowIso]
        );
        const homeworkMap = new Map();
        (hwRows || []).forEach((row) => {
          if (!homeworkMap.has(row.id)) {
            homeworkMap.set(row.id, {
              id: row.id,
              group_number: row.group_number,
              subject_id: row.subject_id,
              subject: row.subject_name,
              day: row.day_of_week,
              class_number: row.class_number,
              description: row.description,
              class_date: row.class_date,
              meeting_url: row.meeting_url,
              link_url: row.link_url,
              file_path: row.file_path,
              file_name: row.file_name,
              created_by: row.created_by,
              created_at: row.created_at,
              is_control: Number(row.is_control || 0),
              course_id: row.course_id,
              subgroups: {},
            });
          }
          if (row.subgroup_id) {
            const hw = homeworkMap.get(row.id);
            if (!hw.subgroups[row.subgroup_id]) {
              hw.subgroups[row.subgroup_id] = {
                id: row.subgroup_id,
                name: row.subgroup_name,
                members: [],
              };
            }
            if (row.subgroup_member) {
              hw.subgroups[row.subgroup_id].members.push(row.subgroup_member);
            }
          }
        });
        homework = Array.from(homeworkMap.values()).map((hw) => ({
          ...hw,
          subgroups: Object.values(hw.subgroups),
        }));
        homework.forEach((hw) => {
          const legacyKey = `${hw.subject_id}|${hw.group_number}|${hw.day}|${hw.class_number}`;
          const key = hw.class_date ? `${legacyKey}|${hw.class_date}` : legacyKey;
          if (!homeworkMeta[key]) {
            homeworkMeta[key] = { count: 0, preview: [], control: false };
          }
          homeworkMeta[key].count += 1;
          if (hw.is_control) {
            homeworkMeta[key].control = true;
          }
          if (hw.description && homeworkMeta[key].preview.length < 2) {
            homeworkMeta[key].preview.push(hw.description);
          }
          const allKey = hw.class_date
            ? `${hw.subject_id}|${hw.day}|${hw.class_number}|${hw.class_date}`
            : `${hw.subject_id}|${hw.day}|${hw.class_number}`;
          if (!homeworkMetaAll[allKey]) {
            homeworkMetaAll[allKey] = { count: 0, preview: [], control: false };
          }
          homeworkMetaAll[allKey].count += 1;
          if (hw.is_control) {
            homeworkMetaAll[allKey].control = true;
          }
          if (hw.description && homeworkMetaAll[allKey].preview.length < 2) {
            homeworkMetaAll[allKey].preview.push(hw.description);
          }
        });
        const homeworkIds = homework.map((h) => h.id);
        if (homeworkIds.length) {
          const placeholders = homeworkIds.map(() => '?').join(',');
          const tagRows = await db.all(
            `SELECT ht.homework_id, t.name
             FROM homework_tag_map ht
             JOIN homework_tags t ON t.id = ht.tag_id
             WHERE ht.homework_id IN (${placeholders})`,
            homeworkIds
          );
          if (tagRows && tagRows.length) {
            const tagMap = {};
            tagRows.forEach((row) => {
              if (!tagMap[row.homework_id]) tagMap[row.homework_id] = [];
              tagMap[row.homework_id].push(row.name);
            });
            homework.forEach((hw) => {
              hw.tags = tagMap[hw.id] || [];
            });
          }
          const tagList = await db.all('SELECT name FROM homework_tags ORDER BY name');
          homeworkTags = (tagList || []).map((row) => row.name);
          const reactRows = await db.all(
            `SELECT homework_id, emoji, COUNT(*) AS count
             FROM homework_reactions
             WHERE homework_id IN (${placeholders})
             GROUP BY homework_id, emoji`,
            homeworkIds
          );
          const reactionMap = {};
          (reactRows || []).forEach((row) => {
            if (!reactionMap[row.homework_id]) reactionMap[row.homework_id] = {};
            reactionMap[row.homework_id][row.emoji] = Number(row.count || 0);
          });
          const myRows = await db.all(
            `SELECT homework_id, emoji
             FROM homework_reactions
             WHERE homework_id IN (${placeholders}) AND user_id = ?`,
            [...homeworkIds, userId]
          );
          const reactedMap = {};
          (myRows || []).forEach((row) => {
            if (!reactedMap[row.homework_id]) reactedMap[row.homework_id] = {};
            reactedMap[row.homework_id][row.emoji] = true;
          });
          homework.forEach((hw) => {
            hw.reactions = reactionMap[hw.id] || {};
            hw.reacted = reactedMap[hw.id] || {};
          });
        }
      }

      let customDeadlinesByDate = {};
      let weekendDeadlineCards = [];
      let customDeadlineItems = [];
      if (settingsCache.allow_custom_deadlines && teacherTargets.length && weekStartDate && weekEndDate) {
        const cdConditions = teacherTargets
          .map(() => '(h.subject_id = ? AND h.group_number = ? AND h.course_id = ? AND COALESCE(h.semester_id, 0) = ?)')
          .join(' OR ');
        const cdParams = [];
        teacherTargets.forEach((t) => {
          cdParams.push(t.subject_id, t.group_number, t.course_id, t.semester_id);
        });
        const cdRows = await db.all(
          `
            SELECT h.*, subj.name AS subject_name, c.name AS course_name
            FROM homework h
            JOIN subjects subj ON subj.id = h.subject_id
            JOIN courses c ON c.id = h.course_id
            WHERE (${cdConditions})
              AND COALESCE(h.status, 'published') = 'published'
              AND (h.scheduled_at IS NULL OR h.scheduled_at <= ?)
              AND h.is_custom_deadline = 1
              AND h.custom_due_date IS NOT NULL
              AND h.custom_due_date >= ?
              AND h.custom_due_date <= ?
            ORDER BY h.custom_due_date ASC, h.created_at DESC
          `,
          [...cdParams, nowIso, weekStartDate, weekEndDate]
        );
        customDeadlineItems = cdRows || [];
        const ids = customDeadlineItems.map((row) => row.id);
        const byDate = {};
        customDeadlineItems.forEach((row) => {
          const key = row.custom_due_date;
          if (!byDate[key]) byDate[key] = [];
          byDate[key].push(row);
        });
        const weekendCards = [];
        ['Saturday', 'Sunday'].forEach((day) => {
          const idx = fullWeekDays.indexOf(day);
          const date = idx >= 0 ? weekDates[idx] : null;
          if (!date) return;
          const items = byDate[date] || [];
          if (items.length) {
            weekendCards.push({ day, date, items });
          }
        });
        customDeadlinesByDate = byDate;
        weekendDeadlineCards = weekendCards;
        if (ids.length) {
          const placeholders = ids.map(() => '?').join(',');
          const reactRows = await db.all(
            `SELECT homework_id, emoji, COUNT(*) AS count
             FROM homework_reactions
             WHERE homework_id IN (${placeholders})
             GROUP BY homework_id, emoji`,
            ids
          );
          const reactionMap = {};
          (reactRows || []).forEach((row) => {
            if (!reactionMap[row.homework_id]) reactionMap[row.homework_id] = {};
            reactionMap[row.homework_id][row.emoji] = Number(row.count || 0);
          });
          const myRows = await db.all(
            `SELECT homework_id, emoji
             FROM homework_reactions
             WHERE homework_id IN (${placeholders}) AND user_id = ?`,
            [...ids, userId]
          );
          const reactedMap = {};
          (myRows || []).forEach((row) => {
            if (!reactedMap[row.homework_id]) reactedMap[row.homework_id] = {};
            reactedMap[row.homework_id][row.emoji] = true;
          });
          customDeadlineItems.forEach((row) => {
            row.reactions = reactionMap[row.id] || {};
            row.reacted = reactedMap[row.id] || {};
          });
        }
      }

      let customDeadlineSubjects = [];
      if (settingsCache.allow_custom_deadlines) {
        const seenCustom = new Set();
        teacherSubjects.forEach((row) => {
          const key = `${row.subject_id}|${row.group_number || 'all'}`;
          if (seenCustom.has(key)) return;
          seenCustom.add(key);
          const generalFlag = row.is_general === false || Number(row.is_general) === 0 ? 0 : 1;
          customDeadlineSubjects.push({
            id: row.subject_id,
            name: row.subject_name,
            course_id: row.course_id,
            course_name: row.course_name,
            group_number: row.group_number,
            is_general: generalFlag,
            group_count: row.group_count,
          });
        });
      }

      return res.render('schedule', {
        scheduleByDay,
        daysOfWeek: activeDays,
        dayDates,
        currentWeek: selectedWeek,
        totalWeeks,
        semester: primarySemester,
        bellSchedule,
        group: group || 'A',
        username,
        homework,
        homeworkMeta,
        homeworkMetaAll,
        homeworkTags,
        customDeadlinesByDate,
        weekendDeadlineCards,
        customDeadlineItems,
        customDeadlineSubjects,
        subgroupError: req.query.sg || null,
        role: req.session.role,
        viewAs: req.session.viewAs || null,
        messageSubjects: [],
        userId,
        teacherCourses,
        selectedCourseId: selectedCourse ? selectedCourse.id : null,
      });
    } catch (err) {
      return handleDbError(res, err, 'teacher.schedule');
    }
  }
  const activeSemester = await getActiveSemester(courseId || 1);
  const totalWeeks = activeSemester && activeSemester.weeks_count ? Number(activeSemester.weeks_count) : 15;
  let selectedWeek = parseInt(req.query.week, 10);
  if (Number.isNaN(selectedWeek)) {
    selectedWeek = getAcademicWeekForSemester(new Date(), activeSemester);
  }
  if (selectedWeek < 1) selectedWeek = 1;
  if (selectedWeek < 1) selectedWeek = 1;
  if (selectedWeek > totalWeeks) selectedWeek = totalWeeks;
  const weekTimeMap = activeSemester && activeSemester.id
    ? await getCourseWeekTimeMap(courseId || 1, activeSemester.id)
    : new Map();
  const useLocalTime = weekTimeMap.get(selectedWeek) === true;
  const studyDays = await getCourseStudyDays(courseId || 1);
  let activeDays = studyDays
    .filter((day) => day.is_active)
    .map((day) => fullWeekDays[day.weekday - 1])
    .filter(Boolean);
  if (!activeDays.length) {
    activeDays = [...daysOfWeek];
  }
  const weekDates = fullWeekDays.map((_, idx) =>
    getDateForWeekIndex(selectedWeek, idx, activeSemester ? activeSemester.start_date : null)
  );
  const weekStartDate = weekDates[0];
  const weekEndDate = weekDates[6];
  const nowIso = new Date().toISOString();

  db.all(
    `
      SELECT sg.subject_id, sg.group_number, s.name AS subject_name
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      WHERE sg.student_id = ? AND s.course_id = ? AND s.visible = 1
    `,
    [userId, courseId || 1],
    (groupErr, studentGroups) => {
      if (groupErr) {
        return res.status(500).send('Database error');
      }

      const scheduleByDay = {};
      activeDays.forEach((day) => {
        scheduleByDay[day] = [];
      });
      const dayDates = {};
      activeDays.forEach((day) => {
        const idx = fullWeekDays.indexOf(day);
        dayDates[day] = idx >= 0 ? weekDates[idx] : null;
      });
      const customDeadlineSubjects = [];
      if (settingsCache.allow_custom_deadlines) {
        const subjectSeen = new Set();
        studentGroups.forEach((sg) => {
          if (!subjectSeen.has(sg.subject_id)) {
            subjectSeen.add(sg.subject_id);
            customDeadlineSubjects.push({ id: sg.subject_id, name: sg.subject_name });
          }
        });
      }

      const loadCustomDeadlines = (cb) => {
        if (!settingsCache.allow_custom_deadlines) {
          return cb({}, [], []);
        }
        if (!studentGroups.length || !weekStartDate || !weekEndDate) {
          return cb({}, [], []);
        }
        const conditions = studentGroups
          .map(() => '(h.subject_id = ? AND h.group_number = ?)')
          .join(' OR ');
        const params = [];
        studentGroups.forEach((sg) => {
          params.push(sg.subject_id, sg.group_number);
        });
        params.push(courseId || 1, activeSemester ? activeSemester.id : null, nowIso, weekStartDate, weekEndDate);
        const sql = `
          SELECT h.*, subj.name AS subject_name
          FROM homework h
          JOIN subjects subj ON subj.id = h.subject_id
          WHERE (${conditions})
            AND h.course_id = ?
            AND h.semester_id = ?
            AND COALESCE(h.status, 'published') = 'published'
            AND (h.scheduled_at IS NULL OR h.scheduled_at <= ?)
            AND h.is_custom_deadline = 1
            AND h.custom_due_date IS NOT NULL
            AND h.custom_due_date >= ?
            AND h.custom_due_date <= ?
          ORDER BY h.custom_due_date ASC, h.created_at DESC
        `;
        db.all(sql, params, (err, rows) => {
          if (err) {
            return cb({}, [], []);
          }
          const rowsList = rows || [];
          const ids = rowsList.map((row) => row.id);
          const byDate = {};
          rowsList.forEach((row) => {
            const key = row.custom_due_date;
            if (!byDate[key]) byDate[key] = [];
            byDate[key].push(row);
          });
          const weekendCards = [];
          ['Saturday', 'Sunday'].forEach((day) => {
            const idx = fullWeekDays.indexOf(day);
            const date = idx >= 0 ? weekDates[idx] : null;
            if (!date) return;
            const items = byDate[date] || [];
            if (items.length) {
              weekendCards.push({ day, date, items });
            }
          });
          if (!ids.length) {
            return cb(byDate, weekendCards, rowsList);
          }
          const placeholders = ids.map(() => '?').join(',');
          db.all(
            `SELECT homework_id, emoji, COUNT(*) AS count
             FROM homework_reactions
             WHERE homework_id IN (${placeholders})
             GROUP BY homework_id, emoji`,
            ids,
            (reactErr, reactRows) => {
              const reactionMap = {};
              if (!reactErr && reactRows) {
                reactRows.forEach((row) => {
                  if (!reactionMap[row.homework_id]) reactionMap[row.homework_id] = {};
                  reactionMap[row.homework_id][row.emoji] = Number(row.count || 0);
                });
              }
              db.all(
                `SELECT homework_id, emoji
                 FROM homework_reactions
                 WHERE homework_id IN (${placeholders}) AND user_id = ?`,
                [...ids, userId],
                (myErr, myRows) => {
                  const reactedMap = {};
                  if (!myErr && myRows) {
                    myRows.forEach((row) => {
                      if (!reactedMap[row.homework_id]) reactedMap[row.homework_id] = {};
                      reactedMap[row.homework_id][row.emoji] = true;
                    });
                  }
                  rowsList.forEach((row) => {
                    row.reactions = reactionMap[row.id] || {};
                    row.reacted = reactedMap[row.id] || {};
                  });
                  return cb(byDate, weekendCards, rowsList);
                }
              );
            }
          );
        });
      };

      const loadHomework = () => {
        if (!studentGroups.length) {
          return loadCustomDeadlines((customDeadlinesByDate, weekendDeadlineCards, customDeadlineItems) =>
            res.render('schedule', {
            scheduleByDay,
            daysOfWeek: activeDays,
            dayDates,
              currentWeek: selectedWeek,
              totalWeeks,
              semester: activeSemester,
              bellSchedule,
              group: group || 'A',
              username,
              homework: [],
              homeworkMeta: {},
              homeworkMetaAll: null,
              homeworkTags: [],
              customDeadlinesByDate,
              weekendDeadlineCards,
              customDeadlineItems,
              customDeadlineSubjects,
              subgroupError: req.query.sg || null,
              role: req.session.role,
              viewAs: req.session.viewAs || null,
              messageSubjects: studentGroups || [],
              userId,
              selectedCourseId: courseId || 1,
            })
          );
        }

        const hwConditions = studentGroups
          .map(() => '(h.subject_id = ? AND h.group_number = ?)')
          .join(' OR ');
        const hwParams = [];
        studentGroups.forEach((sg) => {
          hwParams.push(sg.subject_id, sg.group_number);
        });

        db.all(
          `
            SELECT h.*, subj.name AS subject_name, s.id AS subgroup_id, s.name AS subgroup_name, m.member_username AS subgroup_member
            FROM homework h
            JOIN subjects subj ON subj.id = h.subject_id
            LEFT JOIN subgroups s ON s.homework_id = h.id
            LEFT JOIN subgroup_members m ON m.subgroup_id = s.id
            WHERE (${hwConditions})
              AND h.course_id = ?
              AND h.semester_id = ?
              AND COALESCE(h.status, 'published') = 'published'
              AND (h.scheduled_at IS NULL OR h.scheduled_at <= ?)
              AND (h.is_custom_deadline IS NULL OR h.is_custom_deadline = 0)
            ORDER BY h.created_at DESC
          `,
          [...hwParams, courseId || 1, activeSemester ? activeSemester.id : null, nowIso],
          (err, rows) => {
            if (err) {
              return res.status(500).send('Database error');
            }

            const homeworkMap = new Map();
            rows.forEach((row) => {
              if (!homeworkMap.has(row.id)) {
                homeworkMap.set(row.id, {
                  id: row.id,
                  group_number: row.group_number,
                  subject_id: row.subject_id,
                  subject: row.subject_name,
                  day: row.day_of_week,
                  class_number: row.class_number,
                  description: row.description,
                  class_date: row.class_date,
                  meeting_url: row.meeting_url,
                  link_url: row.link_url,
                  file_path: row.file_path,
                  file_name: row.file_name,
                  created_by: row.created_by,
                  created_at: row.created_at,
                  is_control: Number(row.is_control || 0),
                  course_id: row.course_id,
                  subgroups: {},
                });
              }
              if (row.subgroup_id) {
                const hw = homeworkMap.get(row.id);
                if (!hw.subgroups[row.subgroup_id]) {
                  hw.subgroups[row.subgroup_id] = {
                    id: row.subgroup_id,
                    name: row.subgroup_name,
                    members: [],
                  };
                }
                if (row.subgroup_member) {
                  hw.subgroups[row.subgroup_id].members.push(row.subgroup_member);
                }
              }
            });

            const homework = Array.from(homeworkMap.values()).map((hw) => ({
              ...hw,
              subgroups: Object.values(hw.subgroups),
            }));
            const homeworkMeta = {};
            homework.forEach((hw) => {
              const legacyKey = `${hw.subject_id}|${hw.group_number}|${hw.day}|${hw.class_number}`;
              const key = hw.class_date ? `${legacyKey}|${hw.class_date}` : legacyKey;
              if (!homeworkMeta[key]) {
                homeworkMeta[key] = { count: 0, preview: [], control: false };
              }
              homeworkMeta[key].count += 1;
              if (hw.is_control) {
                homeworkMeta[key].control = true;
              }
              if (hw.description && homeworkMeta[key].preview.length < 2) {
                homeworkMeta[key].preview.push(hw.description);
              }
            });

            const homeworkIds = homework.map((h) => h.id);
            const finalizeRender = (tagOptions = [], customDeadlinesByDate = {}, weekendDeadlineCards = [], customDeadlineItems = []) => {
              res.render('schedule', {
                scheduleByDay,
                daysOfWeek: activeDays,
                dayDates,
                currentWeek: selectedWeek,
                totalWeeks,
                semester: activeSemester,
                bellSchedule,
                group: group || 'A',
                username,
                homework,
                homeworkMeta,
                homeworkMetaAll: null,
                homeworkTags: tagOptions,
                customDeadlinesByDate,
                weekendDeadlineCards,
                customDeadlineItems,
                customDeadlineSubjects,
                subgroupError: req.query.sg || null,
                role: req.session.role,
                viewAs: req.session.viewAs || null,
                messageSubjects: studentGroups || [],
                userId,
                selectedCourseId: courseId || 1,
              });
            };

            if (!homeworkIds.length) {
              return loadCustomDeadlines((customDeadlinesByDate, weekendDeadlineCards, customDeadlineItems) =>
                finalizeRender([], customDeadlinesByDate, weekendDeadlineCards, customDeadlineItems)
              );
            }
            const placeholders = homeworkIds.map(() => '?').join(',');
            db.all(
              `SELECT ht.homework_id, t.name
               FROM homework_tag_map ht
               JOIN homework_tags t ON t.id = ht.tag_id
               WHERE ht.homework_id IN (${placeholders})`,
              homeworkIds,
              (tagErr, tagRows) => {
                if (!tagErr && tagRows) {
                  const tagMap = {};
                  tagRows.forEach((row) => {
                    if (!tagMap[row.homework_id]) tagMap[row.homework_id] = [];
                    tagMap[row.homework_id].push(row.name);
                  });
                  homework.forEach((hw) => {
                    hw.tags = tagMap[hw.id] || [];
                  });
                }
                db.all('SELECT name FROM homework_tags ORDER BY name', (tagListErr, tagList) => {
                  const tagOptions = !tagListErr && tagList ? tagList.map((t) => t.name) : [];
                  db.all(
                    `SELECT homework_id, emoji, COUNT(*) AS count
                     FROM homework_reactions
                     WHERE homework_id IN (${placeholders})
                     GROUP BY homework_id, emoji`,
                    homeworkIds,
                    (reactErr, reactRows) => {
                      const reactionMap = {};
                      if (!reactErr && reactRows) {
                        reactRows.forEach((row) => {
                          if (!reactionMap[row.homework_id]) reactionMap[row.homework_id] = {};
                          reactionMap[row.homework_id][row.emoji] = Number(row.count || 0);
                        });
                      }
                      db.all(
                        `SELECT homework_id, emoji
                         FROM homework_reactions
                         WHERE homework_id IN (${placeholders}) AND user_id = ?`,
                        [...homeworkIds, userId],
                        (myErr, myRows) => {
                          const reactedMap = {};
                          if (!myErr && myRows) {
                            myRows.forEach((row) => {
                              if (!reactedMap[row.homework_id]) reactedMap[row.homework_id] = {};
                              reactedMap[row.homework_id][row.emoji] = true;
                            });
                          }
                          homework.forEach((hw) => {
                            hw.reactions = reactionMap[hw.id] || {};
                            hw.reacted = reactedMap[hw.id] || {};
                          });
                          loadCustomDeadlines((customDeadlinesByDate, weekendDeadlineCards, customDeadlineItems) =>
                            finalizeRender(tagOptions, customDeadlinesByDate, weekendDeadlineCards, customDeadlineItems)
                          );
                        }
                      );
                    }
                  );
                });
              }
            );
          }
        );
      };

      if (!studentGroups.length) {
        return loadHomework();
      }

      const conditions = studentGroups
        .map(() => '(se.subject_id = ? AND se.group_number = ?)')
        .join(' OR ');
      const params = [selectedWeek, courseId || 1, activeSemester ? activeSemester.id : null];
      studentGroups.forEach((sg) => {
        params.push(sg.subject_id, sg.group_number);
      });

      const sql = `
        SELECT se.*, s.name AS subject_name
        FROM schedule_entries se
        JOIN subjects s ON s.id = se.subject_id
        WHERE se.week_number = ? AND se.course_id = ? AND se.semester_id = ? AND s.visible = 1 AND (${conditions})
      `;

      db.all(sql, params, (scheduleErr, rows) => {
        if (scheduleErr) {
          return res.status(500).send('Database error');
        }
        rows.forEach((row) => {
          row.class_date = getDateForWeekDay(selectedWeek, row.day_of_week, activeSemester ? activeSemester.start_date : null);
          row.use_local_time = useLocalTime;
          if (scheduleByDay[row.day_of_week]) {
            scheduleByDay[row.day_of_week].push(row);
          }
        });
        activeDays.forEach((day) => {
          scheduleByDay[day].sort((a, b) => a.class_number - b.class_number);
        });
        return loadHomework();
      });
    }
  );
});

app.get('/teamwork', requireLogin, async (req, res) => {
  const { id: userId, username, role, course_id: courseId } = req.session.user;
  const activeSemester = await getActiveSemester(courseId || 1);
  const selectedSubjectId = req.query.subject_id ? Number(req.query.subject_id) : null;
  db.all(
    `
      SELECT sg.subject_id, s.name AS subject_name
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      WHERE sg.student_id = ? AND s.show_in_teamwork = 1 AND s.visible = 1 AND s.course_id = ?
      ORDER BY s.name ASC
    `,
    [userId, courseId || 1],
    (err, subjects) => {
      if (err) {
        return res.status(500).send('Database error');
      }

      if (!selectedSubjectId) {
        return res.render('teamwork', {
          subjects,
          selectedSubjectId: null,
          tasks: [],
          freeStudents: [],
          messages: res.locals.messages,
          username,
          role,
        });
      }

      db.all(
        `
          SELECT t.*, s.name AS subject_name
          FROM teamwork_tasks t
          JOIN subjects s ON s.id = t.subject_id
          WHERE t.subject_id = ? AND t.course_id = ? AND t.semester_id = ?
          ORDER BY t.created_at DESC
        `,
        [selectedSubjectId, courseId || 1, activeSemester ? activeSemester.id : null],
        (taskErr, tasks) => {
          if (taskErr) {
            return res.status(500).send('Database error');
          }
          if (!tasks.length) {
            return res.render('teamwork', {
              subjects,
              selectedSubjectId,
              tasks: [],
              freeStudents: [],
              messages: res.locals.messages,
              username,
              role,
            });
          }

          const taskIds = tasks.map((t) => t.id);
          const placeholders = taskIds.map(() => '?').join(',');
          db.all(
            `
              SELECT g.*, u.full_name AS leader_name
              FROM teamwork_groups g
              JOIN users u ON u.id = g.leader_id
              WHERE g.task_id IN (${placeholders})
            `,
            taskIds,
            (groupErr, groups) => {
              if (groupErr) {
                return res.status(500).send('Database error');
              }
              db.all(
                `
                  SELECT m.*, u.full_name AS member_name
                  FROM teamwork_members m
                  JOIN users u ON u.id = m.user_id
                  WHERE m.task_id IN (${placeholders})
                `,
                taskIds,
                (memErr, members) => {
                  if (memErr) {
                    return res.status(500).send('Database error');
                  }

                  const groupsByTask = {};
                  groups.forEach((g) => {
                    if (!groupsByTask[g.task_id]) groupsByTask[g.task_id] = [];
                    groupsByTask[g.task_id].push({
                      ...g,
                      members: [],
                    });
                  });
                  members.forEach((m) => {
                    const list = groupsByTask[m.task_id] || [];
                    const group = list.find((g) => g.id === m.group_id);
                    if (group) {
                      group.members.push(m);
                    }
                  });

                  const taskData = tasks.map((t) => ({
                    ...t,
                    groups: (groupsByTask[t.id] || []).map((g) => {
                      const isLeader = g.leader_id === userId;
                      return {
                        ...g,
                        is_leader: isLeader,
                        is_member: g.members.some((m) => m.user_id === userId),
                      };
                    }),
                  }));

                  db.all(
                    `
                      SELECT task_id, emoji, COUNT(*) AS count
                      FROM teamwork_reactions
                      WHERE task_id IN (${placeholders})
                      GROUP BY task_id, emoji
                    `,
                    taskIds,
                    (reactErr, reactRows) => {
                      const reactionMap = {};
                      if (!reactErr && reactRows) {
                        reactRows.forEach((row) => {
                          if (!reactionMap[row.task_id]) reactionMap[row.task_id] = {};
                          reactionMap[row.task_id][row.emoji] = Number(row.count || 0);
                        });
                      }
                      db.all(
                        `
                          SELECT task_id, emoji
                          FROM teamwork_reactions
                          WHERE task_id IN (${placeholders}) AND user_id = ?
                        `,
                        [...taskIds, userId],
                        (myErr, myRows) => {
                          const reactedMap = {};
                          if (!myErr && myRows) {
                            myRows.forEach((row) => {
                              if (!reactedMap[row.task_id]) reactedMap[row.task_id] = {};
                              reactedMap[row.task_id][row.emoji] = true;
                            });
                          }
                          taskData.forEach((task) => {
                            task.reactions = reactionMap[task.id] || {};
                            task.reacted = reactedMap[task.id] || {};
                          });
                          db.all(
                            `
                              SELECT u.id, u.full_name
                              FROM users u
                              JOIN student_groups sg ON sg.student_id = u.id
                              WHERE sg.subject_id = ? AND u.course_id = ?
                              ORDER BY u.full_name ASC
                            `,
                            [selectedSubjectId, courseId || 1],
                            (stuErr, students) => {
                              if (stuErr) {
                                return res.status(500).send('Database error');
                              }

                              const membersByTask = {};
                              members.forEach((m) => {
                                if (!membersByTask[m.task_id]) membersByTask[m.task_id] = new Set();
                                membersByTask[m.task_id].add(m.user_id);
                              });

                              const freeStudents = tasks.reduce((acc, task) => {
                                const used = membersByTask[task.id] || new Set();
                                acc[task.id] = students.filter((s) => !used.has(s.id));
                                return acc;
                              }, {});

                              return res.render('teamwork', {
                                subjects,
                                selectedSubjectId,
                                tasks: taskData,
                                freeStudents,
                                messages: res.locals.messages,
                                username,
                                role,
                              });
                            }
                          );
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
});

app.post('/teamwork/task/create', requireLogin, writeLimiter, async (req, res) => {
  const { title, subject_id, due_date } = req.body;
  const subjectId = Number(subject_id);
  if (!title || Number.isNaN(subjectId)) {
    return res.redirect('/teamwork?err=Missing%20fields');
  }
  const dueDate = due_date ? String(due_date).slice(0, 10) : null;
  if (dueDate && !/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) {
    return res.redirect('/teamwork?err=Invalid%20date');
  }
  const { id: userId, course_id: courseId } = req.session.user;
  const createdAt = new Date().toISOString();
  try {
    const activeSemester = await getActiveSemester(courseId || 1);
    if (!activeSemester) {
      return res.redirect('/teamwork?err=No%20active%20semester');
    }
    const taskRow = await db.get(
      'INSERT INTO teamwork_tasks (subject_id, title, created_by, created_at, due_date, course_id, semester_id) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id',
      [subjectId, title.trim(), userId, createdAt, dueDate, courseId || 1, activeSemester.id]
    );
    if (!taskRow || !taskRow.id) {
      return res.redirect('/teamwork?err=Database%20error');
    }
    const groupRow = await db.get(
      'INSERT INTO teamwork_groups (task_id, name, leader_id, max_members, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id',
      [taskRow.id, 'Команда 1', userId, null, createdAt]
    );
    if (!groupRow || !groupRow.id) {
      return res.redirect(`/teamwork?subject_id=${subjectId}&err=Group%20create%20failed`);
    }
    logActivity(db, req, 'teamwork_task_create', 'teamwork_task', taskRow.id, { subject_id: subjectId }, courseId || 1, activeSemester.id);
    logActivity(db, req, 'teamwork_group_create', 'teamwork_group', groupRow.id, { task_id: taskRow.id }, courseId || 1, activeSemester.id);
    await db.run(
      'INSERT INTO teamwork_members (task_id, group_id, user_id, joined_at) VALUES (?, ?, ?, ?)',
      [taskRow.id, groupRow.id, userId, createdAt]
    );
    return res.redirect(`/teamwork?subject_id=${subjectId}`);
  } catch (err) {
    return res.redirect('/teamwork?err=Database%20error');
  }
});

app.post('/teamwork/group/create', requireLogin, writeLimiter, async (req, res) => {
  const { task_id, name, max_members } = req.body;
  const taskId = Number(task_id);
  const maxMembers = max_members ? Number(max_members) : null;
  if (Number.isNaN(taskId)) {
    return res.redirect('/teamwork?err=Invalid%20task');
  }
  const { id: userId } = req.session.user;
  const createdAt = new Date().toISOString();
  try {
    const taskRow = await db.get('SELECT subject_id FROM teamwork_tasks WHERE id = ?', [taskId]);
    if (!taskRow) {
      return res.redirect('/teamwork?err=Task%20not%20found');
    }
    const memRow = await db.get('SELECT id FROM teamwork_members WHERE task_id = ? AND user_id = ?', [
      taskId,
      userId,
    ]);
    if (memRow) {
      return res.redirect(`/teamwork?subject_id=${taskRow.subject_id}&err=Already%20in%20group`);
    }
    const countRow = await db.get('SELECT COUNT(*) AS cnt FROM teamwork_groups WHERE task_id = ?', [taskId]);
    const nextIndex = (countRow && countRow.cnt ? Number(countRow.cnt) : 0) + 1;
    const groupName = name && name.trim().length ? name.trim() : `Команда ${nextIndex}`;
    const groupRow = await db.get(
      'INSERT INTO teamwork_groups (task_id, name, leader_id, max_members, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id',
      [taskId, groupName, userId, maxMembers, createdAt]
    );
    if (!groupRow || !groupRow.id) {
      return res.redirect(`/teamwork?subject_id=${taskRow.subject_id}&err=Group%20create%20failed`);
    }
    await db.run('INSERT INTO teamwork_members (task_id, group_id, user_id, joined_at) VALUES (?, ?, ?, ?)', [
      taskId,
      groupRow.id,
      userId,
      createdAt,
    ]);
    return res.redirect(`/teamwork?subject_id=${taskRow.subject_id}`);
  } catch (err) {
    return res.redirect(`/teamwork?subject_id=${taskId}&err=Database%20error`);
  }
});

app.post('/teamwork/group/join', requireLogin, writeLimiter, (req, res) => {
  const { group_id } = req.body;
  const groupId = Number(group_id);
  if (Number.isNaN(groupId)) {
    return res.redirect('/teamwork?err=Invalid%20group');
  }
  const { id: userId } = req.session.user;
  const joinedAt = new Date().toISOString();
  db.get(
    `
      SELECT g.task_id, g.max_members, t.subject_id
      FROM teamwork_groups g
      JOIN teamwork_tasks t ON t.id = g.task_id
      WHERE g.id = ?
    `,
    [groupId],
    (grpErr, grpRow) => {
      if (grpErr || !grpRow) {
        return res.redirect('/teamwork?err=Group%20not%20found');
      }
      db.get(
        'SELECT id FROM teamwork_members WHERE task_id = ? AND user_id = ?',
        [grpRow.task_id, userId],
        (memErr, memRow) => {
          if (memErr) {
            return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Database%20error`);
          }
          if (memRow) {
            return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Already%20in%20group`);
          }
          if (grpRow.max_members) {
            db.get(
              'SELECT COUNT(*) AS cnt FROM teamwork_members WHERE group_id = ?',
              [groupId],
              (cntErr, cntRow) => {
                if (cntErr) {
                  return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Database%20error`);
                }
                if (Number(cntRow.cnt) >= grpRow.max_members) {
                  return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Group%20is%20full`);
                }
                db.run(
                  'INSERT INTO teamwork_members (task_id, group_id, user_id, joined_at) VALUES (?, ?, ?, ?)',
                  [grpRow.task_id, groupId, userId, joinedAt],
                  () => res.redirect(`/teamwork?subject_id=${grpRow.subject_id}`)
                );
              }
            );
          } else {
            db.run(
              'INSERT INTO teamwork_members (task_id, group_id, user_id, joined_at) VALUES (?, ?, ?, ?)',
              [grpRow.task_id, groupId, userId, joinedAt],
              () => res.redirect(`/teamwork?subject_id=${grpRow.subject_id}`)
            );
          }
        }
      );
    }
  );
});

app.post('/teamwork/group/leave', requireLogin, writeLimiter, (req, res) => {
  const { group_id } = req.body;
  const groupId = Number(group_id);
  if (Number.isNaN(groupId)) {
    return res.redirect('/teamwork?err=Invalid%20group');
  }
  const { id: userId } = req.session.user;
  db.get(
    `
      SELECT g.task_id, g.leader_id, t.subject_id
      FROM teamwork_groups g
      JOIN teamwork_tasks t ON t.id = g.task_id
      WHERE g.id = ?
    `,
    [groupId],
    (grpErr, grpRow) => {
      if (grpErr || !grpRow) {
        return res.redirect('/teamwork?err=Group%20not%20found');
      }
      if (grpRow.leader_id === userId) {
        return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Leader%20cannot%20leave`);
      }
      db.run(
        'DELETE FROM teamwork_members WHERE group_id = ? AND user_id = ?',
        [groupId, userId],
        () => res.redirect(`/teamwork?subject_id=${grpRow.subject_id}`)
      );
    }
  );
});

app.post('/teamwork/group/disband', requireLogin, writeLimiter, (req, res) => {
  const { group_id } = req.body;
  const groupId = Number(group_id);
  if (Number.isNaN(groupId)) {
    return res.redirect('/teamwork?err=Invalid%20group');
  }
  const { id: userId } = req.session.user;
  db.get(
    `
      SELECT g.task_id, g.leader_id, t.subject_id
      FROM teamwork_groups g
      JOIN teamwork_tasks t ON t.id = g.task_id
      WHERE g.id = ?
    `,
    [groupId],
    (grpErr, grpRow) => {
      if (grpErr || !grpRow) {
        return res.redirect('/teamwork?err=Group%20not%20found');
      }
      if (grpRow.leader_id !== userId) {
        return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Only%20leader%20can%20disband`);
      }
      db.run('DELETE FROM teamwork_members WHERE group_id = ?', [groupId], () => {
        db.run('DELETE FROM teamwork_groups WHERE id = ?', [groupId], () => {
          res.redirect(`/teamwork?subject_id=${grpRow.subject_id}`);
        });
      });
    }
  );
});

app.post('/teamwork/group/update', requireLogin, writeLimiter, (req, res) => {
  const { group_id, name, max_members } = req.body;
  const groupId = Number(group_id);
  const maxMembers = max_members ? Number(max_members) : null;
  if (Number.isNaN(groupId)) {
    return res.redirect('/teamwork?err=Invalid%20group');
  }
  const { id: userId } = req.session.user;
  db.get(
    `
      SELECT g.task_id, g.leader_id, t.subject_id
      FROM teamwork_groups g
      JOIN teamwork_tasks t ON t.id = g.task_id
      WHERE g.id = ?
    `,
    [groupId],
    (grpErr, grpRow) => {
      if (grpErr || !grpRow) {
        return res.redirect('/teamwork?err=Group%20not%20found');
      }
      if (grpRow.leader_id !== userId) {
        return res.redirect(`/teamwork?subject_id=${grpRow.subject_id}&err=Only%20leader%20can%20edit`);
      }
      const newName = name && name.trim().length ? name.trim() : null;
      db.run(
        'UPDATE teamwork_groups SET name = COALESCE(?, name), max_members = ? WHERE id = ?',
        [newName, maxMembers, groupId],
        () => res.redirect(`/teamwork?subject_id=${grpRow.subject_id}`)
      );
    }
  );
});

app.post('/admin/teamwork/delete/:id', requireStaff, (req, res) => {
  const taskId = Number(req.params.id);
  if (Number.isNaN(taskId)) {
    return res.redirect('/admin?err=Invalid%20task');
  }
  db.run('DELETE FROM teamwork_members WHERE task_id = ?', [taskId], () => {
    db.run('DELETE FROM teamwork_groups WHERE task_id = ?', [taskId], () => {
      db.run('DELETE FROM teamwork_tasks WHERE id = ?', [taskId], () => {
        logAction(db, req, 'teamwork_task_delete', { id: taskId });
        res.redirect('/admin?ok=Task%20deleted');
      });
    });
  });
});

app.post('/admin/messages/send', requireStaff, writeLimiter, async (req, res) => {
  if (!settingsCache.allow_messages) {
    return res.redirect('/admin?err=Messages%20disabled');
  }
  const { target_type, target_all, subject_id, group_number, body, user_ids, status, scheduled_at } = req.body;
  if (!body || !body.trim()) {
    return res.redirect('/admin?err=Message%20is%20empty');
  }
  const createdAt = new Date().toISOString();
  const createdBy = req.session.user.id;
  const courseId = getAdminCourse(req);
  const activeSemester = await getActiveSemester(courseId);
  const target = target_type || (String(target_all) === '1' ? 'all' : 'subject');
  const isAll = target === 'all';
  let messageStatus = (status || 'published').toLowerCase();
  if (!['draft', 'scheduled', 'published'].includes(messageStatus)) {
    messageStatus = 'published';
  }
  let scheduledAt = null;
  let publishedAt = createdAt;
  if (messageStatus === 'scheduled') {
    const parsed = scheduled_at ? new Date(scheduled_at) : null;
    if (!parsed || Number.isNaN(parsed.getTime())) {
      return res.redirect('/admin?err=Schedule%20date%20required');
    }
    scheduledAt = parsed.toISOString();
    publishedAt = null;
  }
  if (messageStatus === 'draft') {
    publishedAt = null;
  }
  const subjectId = subject_id ? Number(subject_id) : null;
  const groupNum = group_number ? Number(group_number) : null;
  const users = Array.isArray(user_ids) ? user_ids : user_ids ? [user_ids] : [];
  if (target === 'subject' && (Number.isNaN(subjectId) || Number.isNaN(groupNum))) {
    return res.redirect('/admin?err=Select%20subject%20and%20group');
  }
  if (target === 'users' && !users.length) {
    return res.redirect('/admin?err=Select%20users');
  }
  try {
    const row = await db.get(
      `
        INSERT INTO messages (subject_id, group_number, target_all, body, created_by_id, created_at, course_id, semester_id, status, scheduled_at, published_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
      `,
      [
        isAll || target === 'users' ? null : subjectId,
        isAll || target === 'users' ? null : groupNum,
        isAll ? 1 : 0,
        body.trim(),
        createdBy,
        createdAt,
        courseId,
        activeSemester ? activeSemester.id : null,
        messageStatus,
        scheduledAt,
        publishedAt,
      ]
    );
    if (!row || !row.id) {
      return res.redirect('/admin?err=Database%20error');
    }
    const messageId = row.id;
    if (target === 'users' && users.length) {
      await Promise.all(users.map((id) => db.run('INSERT INTO message_targets (message_id, user_id) VALUES (?, ?)', [
        messageId,
        Number(id),
      ])));
      logAction(db, req, 'message_send', {
        target_type: target,
        target_all: isAll,
        subject_id: subjectId,
        group_number: groupNum,
        user_ids: users,
      });
      return res.redirect('/admin?ok=Message%20sent');
    }
    logAction(db, req, 'message_send', {
      target_type: target,
      target_all: isAll,
      subject_id: subjectId,
      group_number: groupNum,
    });
    return res.redirect('/admin?ok=Message%20sent');
  } catch (err) {
    return res.redirect('/admin?err=Database%20error');
  }
});

app.post('/admin/messages/delete/:id', requireStaff, writeLimiter, (req, res) => {
  if (!settingsCache.allow_messages) {
    return res.redirect('/admin?err=Messages%20disabled');
  }
  const id = Number(req.params.id);
  if (Number.isNaN(id)) {
    return res.redirect('/admin?err=Invalid%20message');
  }
  db.run('DELETE FROM message_reads WHERE message_id = ?', [id], () => {
    db.run('DELETE FROM message_targets WHERE message_id = ?', [id], () => {
      db.run('DELETE FROM messages WHERE id = ?', [id], (err) => {
        if (err) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'message_delete', { id });
        return res.redirect('/admin?ok=Message%20deleted');
      });
    });
  });
});

app.get('/messages.json', requireLogin, readLimiter, async (req, res) => {
  if (!settingsCache.allow_messages) {
    return res.json({ messages: [], unread_count: 0 });
  }
  const { id: userId, course_id: courseId } = req.session.user;
  const activeSemester = await getActiveSemester(courseId || 1);
  const filterSubjectId = req.query.subject_id ? Number(req.query.subject_id) : null;
  db.all(
    `
      SELECT sg.subject_id, sg.group_number
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      WHERE sg.student_id = ? AND s.course_id = ?
    `,
    [userId, courseId || 1],
    (sgErr, groups) => {
      if (sgErr) {
        return res.status(500).json({ error: 'Database error' });
      }
      const conditions = [];
      const params = [];
      conditions.push('m.target_all = 1');
      if (groups.length) {
        const groupConditions = groups.map(() => '(m.subject_id = ? AND m.group_number = ?)').join(' OR ');
        groups.forEach((g) => params.push(g.subject_id, g.group_number));
        conditions.push(groupConditions);
      }
      conditions.push('mt.user_id = ?');
      params.push(userId);
      const baseWhere = conditions.length ? `WHERE ${conditions.map((c) => `(${c})`).join(' OR ')}` : '';
      const courseFilter = ' AND m.course_id = ?';
      const semesterFilter = activeSemester ? ' AND m.semester_id = ?' : '';
      const statusFilter = " AND COALESCE(m.status, 'published') = 'published' AND (m.scheduled_at IS NULL OR m.scheduled_at <= ?)";
      const subjectFilter = !Number.isNaN(filterSubjectId) ? ' AND m.subject_id = ?' : '';
      const finalParams = [...params, courseId || 1];
      if (activeSemester) {
        finalParams.push(activeSemester.id);
      }
      if (!Number.isNaN(filterSubjectId)) {
        finalParams.push(filterSubjectId);
      }
      finalParams.push(new Date().toISOString());
      db.all(
        `
          SELECT m.*, s.name AS subject_name, u.full_name AS created_by, mr.id AS read_id
          FROM messages m
          LEFT JOIN subjects s ON s.id = m.subject_id
          LEFT JOIN users u ON u.id = m.created_by_id
          LEFT JOIN message_reads mr ON mr.message_id = m.id AND mr.user_id = ?
          LEFT JOIN message_targets mt ON mt.message_id = m.id
          ${baseWhere}${courseFilter}${semesterFilter}${subjectFilter}${statusFilter}
          ORDER BY m.created_at DESC
          LIMIT 50
        `,
        [userId, ...finalParams],
        (msgErr, rows) => {
          if (msgErr) {
            return res.status(500).json({ error: 'Database error' });
          }
          const unreadCount = rows.filter((r) => !r.read_id).length;
          if (!rows.length) {
            return res.json({ messages: rows, unread_count: unreadCount });
          }
          const messageIds = rows.map((r) => r.id);
          const placeholders = messageIds.map(() => '?').join(',');
          db.all(
            `SELECT message_id, emoji, COUNT(*) AS count
             FROM message_reactions
             WHERE message_id IN (${placeholders})
             GROUP BY message_id, emoji`,
            messageIds,
            (reactErr, reactRows) => {
              const reactionMap = {};
              if (!reactErr && reactRows) {
                reactRows.forEach((row) => {
                  if (!reactionMap[row.message_id]) reactionMap[row.message_id] = {};
                  reactionMap[row.message_id][row.emoji] = Number(row.count || 0);
                });
              }
              db.all(
                `SELECT message_id, emoji
                 FROM message_reactions
                 WHERE message_id IN (${placeholders}) AND user_id = ?`,
                [...messageIds, userId],
                (myErr, myRows) => {
                  const reactedMap = {};
                  if (!myErr && myRows) {
                    myRows.forEach((row) => {
                      if (!reactedMap[row.message_id]) reactedMap[row.message_id] = {};
                      reactedMap[row.message_id][row.emoji] = true;
                    });
                  }
                  rows.forEach((row) => {
                    row.reactions = reactionMap[row.id] || {};
                    row.reacted = reactedMap[row.id] || {};
                  });
                  return res.json({ messages: rows, unread_count: unreadCount });
                }
              );
            }
          );
        }
      );
    }
  );
});

app.post('/messages/read', requireLogin, writeLimiter, (req, res) => {
  if (!settingsCache.allow_messages) {
    return res.status(403).json({ error: 'Messages disabled' });
  }
  const { message_ids } = req.body;
  const ids = Array.isArray(message_ids) ? message_ids : message_ids ? [message_ids] : [];
  const { id: userId } = req.session.user;
  if (!ids.length) {
    return res.json({ ok: true });
  }
  const readAt = new Date().toISOString();
  const stmt = db.prepare(
    'INSERT INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?) ON CONFLICT(message_id, user_id) DO NOTHING'
  );
  ids.forEach((mid) => {
    stmt.run(Number(mid), userId, readAt);
  });
  stmt.finalize(() => res.json({ ok: true }));
});

app.get('/admin/api/messages/:id/reads', requireStaff, readLimiter, async (req, res) => {
  if (!settingsCache.allow_messages) {
    return res.status(403).json({ error: 'Messages disabled' });
  }
  try {
    await ensureDbReady();
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
  const messageId = Number(req.params.id);
  if (Number.isNaN(messageId)) {
    return res.status(400).json({ error: 'Invalid message' });
  }
  const courseId = getAdminCourse(req);
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
  try {
    const message = await db.get(
      `SELECT id, subject_id, group_number, target_all
       FROM messages
       WHERE id = ? AND course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}`,
      activeSemester ? [messageId, courseId, activeSemester.id] : [messageId, courseId]
    );
    if (!message) {
      return res.status(404).json({ error: 'Not found' });
    }
    const activeFilter = usersHasIsActive ? ' AND u.is_active = 1' : '';
    let recipients = [];
    if (message.target_all === 1) {
      recipients = await db.all(
        `SELECT u.id, u.full_name
         FROM users u
         WHERE u.course_id = ? AND u.role = 'student'${activeFilter}
         ORDER BY u.full_name`,
        [courseId]
      );
    } else if (message.subject_id) {
      recipients = await db.all(
        `SELECT DISTINCT u.id, u.full_name
         FROM student_groups sg
         JOIN users u ON u.id = sg.student_id
         WHERE sg.subject_id = ? AND sg.group_number = ? AND u.course_id = ?${activeFilter}
         ORDER BY u.full_name`,
        [message.subject_id, message.group_number, courseId]
      );
    } else {
      recipients = await db.all(
        `SELECT u.id, u.full_name
         FROM message_targets mt
         JOIN users u ON u.id = mt.user_id
         WHERE mt.message_id = ? AND u.course_id = ?${activeFilter}
         ORDER BY u.full_name`,
        [message.id, courseId]
      );
    }
    const recipientIds = new Set((recipients || []).map((row) => String(row.id)));
    const readRows = await db.all(
      `SELECT mr.user_id, mr.read_at, u.full_name
       FROM message_reads mr
       JOIN users u ON u.id = mr.user_id
       WHERE mr.message_id = ?
       ORDER BY mr.read_at DESC`,
      [message.id]
    );
    const reads = (readRows || [])
      .filter((row) => recipientIds.has(String(row.user_id)))
      .map((row) => ({
        user_id: row.user_id,
        full_name: row.full_name,
        read_at: row.read_at,
      }));
    const readIdSet = new Set(reads.map((row) => String(row.user_id)));
    const unread = (recipients || [])
      .filter((row) => !readIdSet.has(String(row.id)))
      .map((row) => ({ user_id: row.id, full_name: row.full_name }));
    return res.json({
      message_id: message.id,
      target_count: recipients.length,
      read_count: reads.length,
      reads,
      unread,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

const allowedReactions = new Set(['🔥', '👍']);

app.post('/homework/react', requireLogin, writeLimiter, async (req, res) => {
  const homeworkId = Number(req.body.homework_id);
  const emoji = req.body.emoji;
  const { id: userId } = req.session.user;
  if (Number.isNaN(homeworkId) || !allowedReactions.has(emoji)) {
    return res.status(400).json({ error: 'Invalid data' });
  }
  try {
    const existing = await db.get(
      'SELECT 1 FROM homework_reactions WHERE homework_id = ? AND user_id = ? AND emoji = ?',
      [homeworkId, userId, emoji]
    );
    if (existing) {
      await db.run('DELETE FROM homework_reactions WHERE homework_id = ? AND user_id = ? AND emoji = ?', [
        homeworkId,
        userId,
        emoji,
      ]);
    } else {
      await db.run(
        'INSERT INTO homework_reactions (homework_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)',
        [homeworkId, userId, emoji, new Date().toISOString()]
      );
    }
    const reactionRows = await db.all(
      'SELECT emoji, COUNT(*) AS count FROM homework_reactions WHERE homework_id = ? GROUP BY emoji',
      [homeworkId]
    );
    const reactedRows = await db.all(
      'SELECT emoji FROM homework_reactions WHERE homework_id = ? AND user_id = ?',
      [homeworkId, userId]
    );
    const reactions = {};
    reactionRows.forEach((row) => {
      reactions[row.emoji] = Number(row.count || 0);
    });
    const reacted = {};
    reactedRows.forEach((row) => {
      reacted[row.emoji] = true;
    });
    return res.json({ ok: true, reactions, reacted });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/messages/react', requireLogin, writeLimiter, async (req, res) => {
  if (!settingsCache.allow_messages) {
    return res.status(403).json({ error: 'Messages disabled' });
  }
  const messageId = Number(req.body.message_id);
  const emoji = req.body.emoji;
  const { id: userId } = req.session.user;
  if (Number.isNaN(messageId) || !allowedReactions.has(emoji)) {
    return res.status(400).json({ error: 'Invalid data' });
  }
  try {
    const existing = await db.get(
      'SELECT 1 FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?',
      [messageId, userId, emoji]
    );
    if (existing) {
      await db.run('DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?', [
        messageId,
        userId,
        emoji,
      ]);
    } else {
      await db.run(
        'INSERT INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)',
        [messageId, userId, emoji, new Date().toISOString()]
      );
    }
    const reactionRows = await db.all(
      'SELECT emoji, COUNT(*) AS count FROM message_reactions WHERE message_id = ? GROUP BY emoji',
      [messageId]
    );
    const reactedRows = await db.all(
      'SELECT emoji FROM message_reactions WHERE message_id = ? AND user_id = ?',
      [messageId, userId]
    );
    const reactions = {};
    reactionRows.forEach((row) => {
      reactions[row.emoji] = Number(row.count || 0);
    });
    const reacted = {};
    reactedRows.forEach((row) => {
      reacted[row.emoji] = true;
    });
    return res.json({ ok: true, reactions, reacted });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/teamwork/react', requireLogin, writeLimiter, async (req, res) => {
  const taskId = Number(req.body.task_id);
  const emoji = req.body.emoji;
  const { id: userId } = req.session.user;
  if (Number.isNaN(taskId) || !allowedReactions.has(emoji)) {
    return res.status(400).json({ error: 'Invalid data' });
  }
  try {
    const existing = await db.get(
      'SELECT 1 FROM teamwork_reactions WHERE task_id = ? AND user_id = ? AND emoji = ?',
      [taskId, userId, emoji]
    );
    if (existing) {
      await db.run('DELETE FROM teamwork_reactions WHERE task_id = ? AND user_id = ? AND emoji = ?', [
        taskId,
        userId,
        emoji,
      ]);
    } else {
      await db.run(
        'INSERT INTO teamwork_reactions (task_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)',
        [taskId, userId, emoji, new Date().toISOString()]
      );
    }
    const reactionRows = await db.all(
      'SELECT emoji, COUNT(*) AS count FROM teamwork_reactions WHERE task_id = ? GROUP BY emoji',
      [taskId]
    );
    const reactedRows = await db.all(
      'SELECT emoji FROM teamwork_reactions WHERE task_id = ? AND user_id = ?',
      [taskId, userId]
    );
    const reactions = {};
    reactionRows.forEach((row) => {
      reactions[row.emoji] = Number(row.count || 0);
    });
    const reacted = {};
    reactedRows.forEach((row) => {
      reacted[row.emoji] = true;
    });
    return res.json({ ok: true, reactions, reacted });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/admin', requireAdmin, async (req, res, next) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'init');
  }
  const courseId = getAdminCourse(req);
  const {
    group_number,
    day,
    subject,
    q,
    sort_schedule,
    sort_homework,
    history_actor,
    history_action,
    history_q,
    history_from,
    history_to,
    users_status,
    users_q,
    users_group,
    homework_from,
    homework_to,
    homework_tag,
    teamwork_subject,
    teamwork_from,
    teamwork_to,
    schedule_date,
  } = req.query;
  const scheduleFilters = [];
  const scheduleParams = [];
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return handleDbError(res, err, 'admin.semester');
  }
  let activeScheduleDays = [];
  try {
    const studyDays = await getCourseStudyDays(courseId);
    activeScheduleDays = (studyDays || [])
      .filter((d) => d.is_active)
      .map((d) => d.day_name)
      .filter(Boolean);
  } catch (err) {
    console.error('Failed to load study days', err);
  }
  if (!activeScheduleDays.length) {
    activeScheduleDays = [...daysOfWeek];
  }

  scheduleFilters.push('se.course_id = ?');
  scheduleParams.push(courseId);
  if (activeSemester) {
    scheduleFilters.push('se.semester_id = ?');
    scheduleParams.push(activeSemester.id);
  }

  if (group_number) {
    scheduleFilters.push('se.group_number = ?');
    scheduleParams.push(group_number);
  }
  if (day) {
    scheduleFilters.push('se.day_of_week = ?');
    scheduleParams.push(day);
  }
  if (subject) {
    scheduleFilters.push('s.name LIKE ?');
    scheduleParams.push(`%${subject}%`);
  }
  if (schedule_date && activeSemester && activeSemester.start_date) {
    const mapped = getWeekDayForDate(schedule_date, activeSemester.start_date);
    if (mapped) {
      scheduleFilters.push('se.week_number = ?');
      scheduleParams.push(mapped.weekNumber);
      scheduleFilters.push('se.day_of_week = ?');
      scheduleParams.push(mapped.dayName);
    }
  }

  const scheduleWhere = scheduleFilters.length ? `WHERE ${scheduleFilters.join(' AND ')}` : '';
  const scheduleSql = `
    SELECT se.*, s.name AS subject_name
    FROM schedule_entries se
    JOIN subjects s ON s.id = se.subject_id
    ${scheduleWhere}
    ORDER BY se.week_number, se.day_of_week, se.class_number
  `;

  let courses = [];
  let semesters = [];
  let teacherRequests = [];
  try {
    courses = await getCoursesCached();
    semesters = await getSemestersCached(courseId);
    teacherRequests = await db.all(
      `
        SELECT tr.user_id, tr.status, tr.created_at,
               u.full_name,
               COALESCE(
                 array_agg(DISTINCT (s.name || ' (' || c.name || ')'))
                   FILTER (WHERE s.id IS NOT NULL),
                 ARRAY[]::text[]
               ) AS subjects
        FROM teacher_requests tr
        JOIN users u ON u.id = tr.user_id
        LEFT JOIN teacher_subjects ts ON ts.user_id = tr.user_id
        LEFT JOIN subjects s ON s.id = ts.subject_id
        LEFT JOIN courses c ON c.id = s.course_id
        GROUP BY tr.user_id, tr.status, tr.created_at, u.full_name
        ORDER BY tr.created_at DESC
      `
    );
  } catch (err) {
    return handleDbError(res, err, 'admin.reference');
  }
  db.all(scheduleSql, scheduleParams, (scheduleErr, scheduleRows) => {
    if (scheduleErr) {
      return handleDbError(res, scheduleErr, 'admin.schedule');
    }
    const schedule = sortSchedule(scheduleRows, sort_schedule);

    const homeworkFilters = [];
    const homeworkParams = [];
    homeworkFilters.push('h.course_id = ?');
    homeworkParams.push(courseId);
  if (activeSemester) {
    homeworkFilters.push('h.semester_id = ?');
    homeworkParams.push(activeSemester.id);
  }
    if (group_number) {
      homeworkFilters.push('h.group_number = ?');
      homeworkParams.push(group_number);
    }
    if (subject) {
      homeworkFilters.push('h.subject LIKE ?');
      homeworkParams.push(`%${subject}%`);
    }
    if (q) {
      homeworkFilters.push('(h.description LIKE ? OR h.created_by LIKE ?)');
      homeworkParams.push(`%${q}%`, `%${q}%`);
    }
    if (homework_from) {
      const start = new Date(homework_from);
      if (!Number.isNaN(start.getTime())) {
        start.setHours(0, 0, 0, 0);
        homeworkFilters.push('h.created_at >= ?');
        homeworkParams.push(start.toISOString());
      }
    }
    if (homework_to) {
      const end = new Date(homework_to);
      if (!Number.isNaN(end.getTime())) {
        end.setHours(23, 59, 59, 999);
        homeworkFilters.push('h.created_at <= ?');
        homeworkParams.push(end.toISOString());
      }
    }
    if (homework_tag) {
      homeworkFilters.push(
        `EXISTS (
          SELECT 1
          FROM homework_tag_map ht
          JOIN homework_tags t ON t.id = ht.tag_id
          WHERE ht.homework_id = h.id AND t.name = ?
        )`
      );
      homeworkParams.push(homework_tag);
    }

    const homeworkWhere = homeworkFilters.length ? `WHERE ${homeworkFilters.join(' AND ')}` : '';
    const homeworkSql = `
      SELECT h.*, subj.name AS subject_name,
             COALESCE(taglist.tags, ARRAY[]::text[]) AS tags
      FROM homework h
      JOIN subjects subj ON subj.id = h.subject_id
      LEFT JOIN LATERAL (
        SELECT array_agg(t.name ORDER BY t.name) AS tags
        FROM homework_tag_map ht
        JOIN homework_tags t ON t.id = ht.tag_id
        WHERE ht.homework_id = h.id
      ) taglist ON true
      ${homeworkWhere}
      ORDER BY h.created_at DESC
    `;

    db.all(homeworkSql, homeworkParams, (homeworkErr, homeworkRows) => {
      if (homeworkErr) {
        return handleDbError(res, homeworkErr, 'admin.homework');
      }
      const homework = sortHomework(homeworkRows, sort_homework);
      db.all('SELECT name FROM homework_tags ORDER BY name', (tagErr, tagRows) => {
        if (tagErr) {
          console.error('Error fetching homework_tags:', tagErr);
          return handleDbError(res, tagErr, 'admin.homework.tags');
        }
        if (res.headersSent) {
          return;
        }
        const homeworkTags = Array.isArray(tagRows) ? tagRows.map((row) => row.name) : [];
        ensureUsersSchema(() => {
        const userFilters = ['course_id = ?'];
        const userParams = [courseId];
        if (usersHasIsActive) {
          if (users_status === 'inactive') {
            userFilters.push('is_active = 0');
          } else if (users_status !== 'all') {
            userFilters.push('is_active = 1');
          }
        }
        if (users_q) {
          userFilters.push('full_name ILIKE ?');
          userParams.push(`%${users_q}%`);
        }
        if (users_group) {
          userFilters.push('schedule_group = ?');
          userParams.push(users_group);
        }
        const userWhere = userFilters.length ? `WHERE ${userFilters.join(' AND ')}` : '';
        db.all(
          `SELECT id, full_name, role, schedule_group, course_id, ${usersHasIsActive ? 'is_active,' : ''} last_login_ip, last_user_agent, last_login_at FROM users ${userWhere} ORDER BY full_name`,
          userParams,
          (userErr, users) => {
            if (userErr) {
              return handleDbError(res, userErr, 'admin.users');
            }
            if (res.headersSent) {
              return;
            }
            getSubjectsCached(courseId)
              .then((subjects) => {
                db.all(
                  `
                    SELECT sg.student_id, sg.subject_id, sg.group_number, s.name AS subject_name
                    FROM student_groups sg
                    JOIN subjects s ON s.id = sg.subject_id
                    WHERE s.course_id = ?
                  `,
                  [courseId],
                  (sgErr, studentGroups) => {
                    if (sgErr) {
                      return handleDbError(res, sgErr, 'admin.studentGroups');
                    }
                    if (res.headersSent) {
                      return;
                    }
                  const historyFilters = [];
                  const historyParams = [];
                  historyFilters.push('course_id = ?');
                  historyParams.push(courseId);
                  if (history_actor) {
                    historyFilters.push('actor_name LIKE ?');
                    historyParams.push(`%${history_actor}%`);
                  }
                  if (history_action) {
                    historyFilters.push('action LIKE ?');
                    historyParams.push(`%${history_action}%`);
                  }
                  if (history_q) {
                    historyFilters.push('details LIKE ?');
                    historyParams.push(`%${history_q}%`);
                  }
                  if (history_from) {
                    historyFilters.push('created_at >= ?');
                    historyParams.push(new Date(history_from).toISOString());
                  }
                  if (history_to) {
                    const end = new Date(history_to);
                    end.setHours(23, 59, 59, 999);
                    historyFilters.push('created_at <= ?');
                    historyParams.push(end.toISOString());
                  }
                  const historyWhere = historyFilters.length ? `WHERE ${historyFilters.join(' AND ')}` : '';
  db.all(
    `SELECT * FROM history_log ${historyWhere} ORDER BY created_at DESC LIMIT 500`,
    historyParams,
    (logErr, logs) => {
      if (logErr) {
        return handleDbError(res, logErr, 'admin.history');
      }
      if (res.headersSent) {
        return;
      }
      const activityFilters = [];
      const activityParams = [];
      activityFilters.push('course_id = ?');
      activityParams.push(courseId);
      if (req.query.activity_user) {
        activityFilters.push('user_name ILIKE ?');
        activityParams.push(`%${req.query.activity_user}%`);
      }
      if (req.query.activity_action) {
        activityFilters.push('action_type = ?');
        activityParams.push(req.query.activity_action);
      }
      if (req.query.activity_from) {
        const start = new Date(req.query.activity_from);
        start.setHours(0, 0, 0, 0);
        activityFilters.push('created_at >= ?');
        activityParams.push(start.toISOString());
      }
      if (req.query.activity_to) {
        const end = new Date(req.query.activity_to);
        end.setHours(23, 59, 59, 999);
        activityFilters.push('created_at <= ?');
        activityParams.push(end.toISOString());
      }
      if (activeSemester) {
        activityFilters.push('semester_id = ?');
        activityParams.push(activeSemester.id);
      }
      const activityWhere = activityFilters.length ? `WHERE ${activityFilters.join(' AND ')}` : '';
      db.all(
        `SELECT * FROM activity_log ${activityWhere} ORDER BY created_at DESC LIMIT 500`,
        activityParams,
        (actErr, activityLogs) => {
          if (actErr) {
            return handleDbError(res, actErr, 'admin.activity');
          }
          if (res.headersSent) {
            return;
          }
          const topParams = activeSemester ? [courseId, activeSemester.id] : [courseId];
          db.all(
            `
              SELECT user_id, user_name,
                     SUM(${ACTIVITY_POINTS_CASE}) AS points,
                     COUNT(*) AS actions_count
              FROM activity_log
              WHERE course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}
              GROUP BY user_id, user_name
              HAVING SUM(${ACTIVITY_POINTS_CASE}) > 0
              ORDER BY points DESC, actions_count DESC, user_name ASC
              LIMIT 5
            `,
            topParams,
            (topErr, activityTop) => {
              if (topErr) {
                return handleDbError(res, topErr, 'admin.activityTop');
              }
              if (res.headersSent) {
                return;
              }
          const teamworkFilters = ['t.course_id = ?'];
          const teamworkParams = [courseId];
          if (activeSemester) {
            teamworkFilters.push('t.semester_id = ?');
            teamworkParams.push(activeSemester.id);
          }
          if (teamwork_subject) {
            teamworkFilters.push('s.name ILIKE ?');
            teamworkParams.push(`%${teamwork_subject}%`);
          }
          if (teamwork_from) {
            const start = new Date(teamwork_from);
            if (!Number.isNaN(start.getTime())) {
              start.setHours(0, 0, 0, 0);
              teamworkFilters.push('t.created_at >= ?');
              teamworkParams.push(start.toISOString());
            }
          }
          if (teamwork_to) {
            const end = new Date(teamwork_to);
            if (!Number.isNaN(end.getTime())) {
              end.setHours(23, 59, 59, 999);
              teamworkFilters.push('t.created_at <= ?');
              teamworkParams.push(end.toISOString());
            }
          }
          const teamworkWhere = teamworkFilters.length ? `WHERE ${teamworkFilters.join(' AND ')}` : '';
          db.all(
                        `
                          SELECT t.id, t.title, t.created_at, s.name AS subject_name,
                                 COUNT(DISTINCT g.id) AS group_count,
                                 COUNT(DISTINCT m.user_id) AS member_count
                          FROM teamwork_tasks t
                          JOIN subjects s ON s.id = t.subject_id
                          LEFT JOIN teamwork_groups g ON g.task_id = t.id
                          LEFT JOIN teamwork_members m ON m.task_id = t.id
                          ${teamworkWhere}
                          GROUP BY t.id, t.title, t.created_at, s.name
                          ORDER BY t.created_at DESC
                        `,
                        teamworkParams,
                        (taskErr, teamworkTasks) => {
                          if (taskErr) {
                            return handleDbError(res, taskErr, 'admin.teamwork');
                          }
                          if (res.headersSent) {
                            return;
                          }
                          db.all(
                            `
                              SELECT m.*, s.name AS subject_name, u.full_name AS created_by,
                                     COALESCE(reads.read_count, 0) AS read_count,
                                     COALESCE(targets.target_count, 0) AS target_count
                              FROM messages m
                              LEFT JOIN subjects s ON s.id = m.subject_id
                              LEFT JOIN users u ON u.id = m.created_by_id
                              LEFT JOIN LATERAL (
                                SELECT COUNT(*) AS read_count
                                FROM message_reads mr
                                WHERE mr.message_id = m.id
                              ) reads ON true
                              LEFT JOIN LATERAL (
                                SELECT CASE
                                  WHEN m.target_all = 1 THEN (
                                    SELECT COUNT(*)
                                    FROM users u2
                                    WHERE u2.course_id = ? AND u2.role = 'student' AND u2.is_active = 1
                                  )
                                  WHEN m.subject_id IS NOT NULL THEN (
                                    SELECT COUNT(DISTINCT sg.student_id)
                                    FROM student_groups sg
                                    JOIN users u3 ON u3.id = sg.student_id
                                    WHERE sg.subject_id = m.subject_id AND sg.group_number = m.group_number
                                      AND u3.course_id = ? AND u3.is_active = 1
                                  )
                                  ELSE (
                                    SELECT COUNT(*)
                                    FROM message_targets mt
                                    JOIN users u4 ON u4.id = mt.user_id
                                    WHERE mt.message_id = m.id AND u4.course_id = ? AND u4.is_active = 1
                                  )
                                END AS target_count
                              ) targets ON true
                              WHERE m.course_id = ?${activeSemester ? ' AND m.semester_id = ?' : ''}
                              ORDER BY m.created_at DESC
                              LIMIT 200
                            `,
                            activeSemester
                              ? [courseId, courseId, courseId, courseId, activeSemester.id]
                              : [courseId, courseId, courseId, courseId],
                            (msgErr, messages) => {
                              if (msgErr) {
                                return handleDbError(res, msgErr, 'admin.messages');
                              }
                              if (res.headersSent) {
                                return;
                              }
                              const statsParams = activeSemester ? [courseId, activeSemester.id] : [courseId];
                              (async () => {
                                try {
                                  const [
                                    usersRow,
                                    subjectsRow,
                                    homeworkRow,
                                    teamworkTasksRow,
                                    teamworkGroupsRow,
                                    teamworkMembersRow,
                                  ] = await Promise.all([
                                    db.get('SELECT COUNT(*) AS count FROM users WHERE course_id = ?', [courseId]),
                                    db.get('SELECT COUNT(*) AS count FROM subjects WHERE course_id = ?', [courseId]),
                                    db.get(
                                      `SELECT COUNT(*) AS count FROM homework WHERE course_id = ?${
                                        activeSemester ? ' AND semester_id = ?' : ''
                                      }`,
                                      statsParams
                                    ),
                                    db.get(
                                      `SELECT COUNT(*) AS count FROM teamwork_tasks WHERE course_id = ?${
                                        activeSemester ? ' AND semester_id = ?' : ''
                                      }`,
                                      statsParams
                                    ),
                                    db.get(
                                      `SELECT COUNT(*) AS count
                                       FROM teamwork_groups g
                                       JOIN teamwork_tasks t ON t.id = g.task_id
                                       WHERE t.course_id = ?${activeSemester ? ' AND t.semester_id = ?' : ''}`,
                                      statsParams
                                    ),
                                    db.get(
                                      `SELECT COUNT(*) AS count
                                       FROM teamwork_members m
                                       JOIN teamwork_tasks t ON t.id = m.task_id
                                       WHERE t.course_id = ?${activeSemester ? ' AND t.semester_id = ?' : ''}`,
                                      statsParams
                                    ),
                                  ]);

    const dashboardStats = {
      users: Number(usersRow?.count || 0),
      subjects: Number(subjectsRow?.count || 0),
      homework: Number(homeworkRow?.count || 0),
      teamworkTasks: Number(teamworkTasksRow?.count || 0),
      teamworkGroups: Number(teamworkGroupsRow?.count || 0),
      teamworkMembers: Number(teamworkMembersRow?.count || 0),
    };

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const weekStart = new Date(today);
    weekStart.setDate(weekStart.getDate() - 6);
    const weeklyLabels = [];
    for (let i = 0; i < 7; i += 1) {
      const d = new Date(weekStart);
      d.setDate(weekStart.getDate() + i);
      weeklyLabels.push(d.toISOString().slice(0, 10));
    }
    let weeklyHomework = weeklyLabels.map(() => 0);
    let weeklyTeamwork = weeklyLabels.map(() => 0);
    let weeklyUserRoles = ['student', 'starosta', 'deanery', 'admin'];
    let weeklyUserSeries = weeklyUserRoles.map(() => weeklyLabels.map(() => 0));
    try {
      const weeklyParams = activeSemester
        ? [courseId, weekStart.toISOString(), activeSemester.id]
        : [courseId, weekStart.toISOString()];
      const [weeklyHomeworkRows, weeklyTeamworkRows, weeklyUsersRows] = await Promise.all([
        db.all(
          `SELECT DATE(created_at::timestamp) AS day, COUNT(*) AS count
           FROM homework
           WHERE course_id = ? AND created_at::timestamp >= ?${activeSemester ? ' AND semester_id = ?' : ''}
           GROUP BY day
           ORDER BY day`,
          weeklyParams
        ),
        db.all(
          `SELECT DATE(created_at::timestamp) AS day, COUNT(*) AS count
           FROM teamwork_tasks
           WHERE course_id = ? AND created_at::timestamp >= ?${activeSemester ? ' AND semester_id = ?' : ''}
           GROUP BY day
           ORDER BY day`,
          weeklyParams
        ),
        db.all(
          `SELECT DATE(created_at) AS day, role, COUNT(*) AS count
           FROM users
           WHERE course_id = ? AND created_at >= ?
           GROUP BY day, role
           ORDER BY day`,
          [courseId, weekStart.toISOString()]
        ),
      ]);

      const homeworkMap = {};
      (weeklyHomeworkRows || []).forEach((row) => {
        const key = String(row.day);
        homeworkMap[key] = Number(row.count || 0);
      });
      const teamworkMap = {};
      (weeklyTeamworkRows || []).forEach((row) => {
        const key = String(row.day);
        teamworkMap[key] = Number(row.count || 0);
      });

      weeklyHomework = weeklyLabels.map((key) => homeworkMap[key] || 0);
      weeklyTeamwork = weeklyLabels.map((key) => teamworkMap[key] || 0);

      const roleOrder = ['student', 'teacher', 'starosta', 'deanery', 'admin'];
      const roleMap = {};
      (weeklyUsersRows || []).forEach((row) => {
        const key = String(row.day);
        if (!roleMap[row.role]) {
          roleMap[row.role] = {};
        }
        roleMap[row.role][key] = Number(row.count || 0);
      });
      weeklyUserRoles = roleOrder.filter((role) => roleMap[role]);
      if (!weeklyUserRoles.length) {
        weeklyUserRoles.push(...roleOrder);
      }
      weeklyUserSeries = weeklyUserRoles.map((role) =>
        weeklyLabels.map((key) => (roleMap[role] && roleMap[role][key]) || 0)
      );
    } catch (weeklyErr) {
      console.error('Database error (admin.overview.weekly)', weeklyErr);
    }

    try {
        res.render('admin', {
          username: req.session.user.username,
          userId: req.session.user.id,
          role: req.session.role,
                                      schedule,
                                      homework,
                                      homeworkTags,
                                      users,
                                      subjects,
                                      studentGroups,
                                      logs,
                                      activityLogs,
                                      activityTop,
                                      dashboardStats,
                                      teamworkTasks,
                                      adminMessages: messages,
                                      courses,
                                      teacherRequests,
        semesters,
        activeSemester,
        selectedCourseId: courseId,
        limitedStaffView: false,
        weeklyLabels,
        weeklyHomework,
        weeklyTeamwork,
        weeklyUserRoles,
        weeklyUserSeries,
        settings: settingsCache,
        activeScheduleDays,
        filters: {
          group_number: group_number || '',
          day: day || '',
          subject: subject || '',
                                        q: q || '',
                                        schedule_date: schedule_date || '',
                                      homework_from: homework_from || '',
                                      homework_to: homework_to || '',
                                      homework_tag: homework_tag || '',
                                      users_q: users_q || '',
                                      users_group: users_group || '',
                                        teamwork_subject: teamwork_subject || '',
                                        teamwork_from: teamwork_from || '',
                                        teamwork_to: teamwork_to || '',
                                      },
                                      usersStatus: users_status || 'active',
                                      sorts: {
                                        schedule: sort_schedule || '',
                                        homework: sort_homework || '',
                                      },
                                      historyFilters: {
                                        actor: history_actor || '',
                                        action: history_action || '',
                                        q: history_q || '',
                                        from: history_from || '',
                                        to: history_to || '',
                                      },
                                      activityFilters: {
                                        user: req.query.activity_user || '',
                                        action: req.query.activity_action || '',
                                        from: req.query.activity_from || '',
                                        to: req.query.activity_to || '',
                                      },
                                      messages: {
                                        error: req.query.err || '',
                                        success: req.query.ok || '',
                                      },
                                    });
                                  } catch (renderErr) {
                                    return handleDbError(res, renderErr, 'admin.render');
                                  }
                                } catch (statsErr) {
                                  return handleDbError(res, statsErr, 'admin.dashboard');
                                }
                              })();
                  }
                );
              })
              .catch((subjectErr) => handleDbError(res, subjectErr, 'admin.subjects'));
            }
          );
                    }
                  );
                }
              );
            });
          });
        }
      );
});

app.get('/admin/schedule-list', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleList.init');
  }
  const courseId = getAdminCourse(req);
  const {
    group_number,
    day,
    subject,
    schedule_date,
    sort_schedule,
    page,
  } = req.query;

  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleList.semester');
  }
  let activeScheduleDays = [];
  try {
    const studyDays = await getCourseStudyDays(courseId);
    activeScheduleDays = (studyDays || [])
      .filter((d) => d.is_active)
      .map((d) => d.day_name)
      .filter(Boolean);
  } catch (err) {
    console.error('Failed to load study days', err);
  }
  if (!activeScheduleDays.length) {
    activeScheduleDays = [...daysOfWeek];
  }

  const scheduleFilters = ['se.course_id = ?'];
  const scheduleParams = [courseId];
  if (activeSemester) {
    scheduleFilters.push('se.semester_id = ?');
    scheduleParams.push(activeSemester.id);
  }
  if (group_number) {
    scheduleFilters.push('se.group_number = ?');
    scheduleParams.push(group_number);
  }
  if (day) {
    scheduleFilters.push('se.day_of_week = ?');
    scheduleParams.push(day);
  }
  if (subject) {
    scheduleFilters.push('s.name LIKE ?');
    scheduleParams.push(`%${subject}%`);
  }
  if (schedule_date && activeSemester && activeSemester.start_date) {
    const mapped = getWeekDayForDate(schedule_date, activeSemester.start_date);
    if (mapped) {
      scheduleFilters.push('se.week_number = ?');
      scheduleParams.push(mapped.weekNumber);
      scheduleFilters.push('se.day_of_week = ?');
      scheduleParams.push(mapped.dayName);
    }
  }

  const scheduleWhere = scheduleFilters.length ? `WHERE ${scheduleFilters.join(' AND ')}` : '';
  let orderClause = 'se.week_number, se.day_of_week, se.class_number';
  if (sort_schedule === 'group') {
    orderClause = 'se.group_number, se.day_of_week, se.class_number';
  } else if (sort_schedule === 'day') {
    orderClause = 'se.day_of_week, se.class_number, se.group_number';
  } else if (sort_schedule === 'time') {
    orderClause = 'se.class_number, se.day_of_week, se.group_number';
  }

  const perPage = 30;
  const rawPage = Number(page || 1);
  let currentPage = Number.isNaN(rawPage) || rawPage < 1 ? 1 : rawPage;

  try {
    const countRow = await db.get(
      `
        SELECT COUNT(*) AS count
        FROM schedule_entries se
        JOIN subjects s ON s.id = se.subject_id
        ${scheduleWhere}
      `,
      scheduleParams
    );
    const totalCount = Number(countRow?.count || 0);
    const totalPages = Math.max(1, Math.ceil(totalCount / perPage));
    if (currentPage > totalPages) currentPage = totalPages;
    const offset = (currentPage - 1) * perPage;
    const rows = await db.all(
      `
        SELECT se.*, s.name AS subject_name
        FROM schedule_entries se
        JOIN subjects s ON s.id = se.subject_id
        ${scheduleWhere}
        ORDER BY ${orderClause}
        LIMIT ? OFFSET ?
      `,
      [...scheduleParams, perPage, offset]
    );

    const courses = await getCoursesCached();
    const semesters = await getSemestersCached(courseId);
    const subjects = await getSubjectsCached(courseId);

    const queryParams = new URLSearchParams();
    if (courseId) queryParams.set('course', courseId);
    if (group_number) queryParams.set('group_number', group_number);
    if (day) queryParams.set('day', day);
    if (subject) queryParams.set('subject', subject);
    if (schedule_date) queryParams.set('schedule_date', schedule_date);
    if (sort_schedule) queryParams.set('sort_schedule', sort_schedule);
    const baseQuery = queryParams.toString();
    const pageBase = baseQuery ? `?${baseQuery}&page=` : '?page=';

    return res.render('admin-schedule-list', {
      username: req.session.user.username,
      role: req.session.role,
      courses,
      subjects,
      semesters,
      activeSemester,
      selectedCourseId: courseId,
      activeScheduleDays,
      schedule: rows || [],
      perPage,
      filters: {
        group_number: group_number || '',
        day: day || '',
        subject: subject || '',
        schedule_date: schedule_date || '',
      },
      sorts: {
        schedule: sort_schedule || '',
      },
      pagination: {
        page: currentPage,
        totalPages,
        pageBase,
      },
    });
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleList');
  }
});

app.get('/admin/schedule-generator', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.init');
  }
  const userId = req.session.user.id;
  const runId = Number(req.query.run);
  let run = null;
  try {
    if (Number.isFinite(runId) && runId > 0) {
      run = await db.get('SELECT * FROM schedule_generator_runs WHERE id = ?', [runId]);
    }
    if (!run) {
      run = await db.get(
        'SELECT * FROM schedule_generator_runs WHERE created_by_id = ? ORDER BY created_at DESC LIMIT 1',
        [userId]
      );
    }
    if (!run) {
      const insert = await db.run(
        'INSERT INTO schedule_generator_runs (status, created_by_id, config) VALUES (?, ?, ?) RETURNING id',
        ['draft', userId, serializeGeneratorConfig(DEFAULT_GENERATOR_CONFIG)]
      );
      const newId = insert.lastID;
      return res.redirect(`/admin/schedule-generator?run=${newId}`);
    }

    const config = parseGeneratorConfig(run.config);
    const requestedLocation = String(req.body.active_location || '');
    const activeLocation = requestedLocation.toLowerCase() === 'munich'
      ? 'munich'
      : requestedLocation
      ? 'kyiv'
      : config.active_location === 'munich'
      ? 'munich'
      : 'kyiv';
    if (activeLocation !== config.active_location) {
      config.active_location = activeLocation;
    }
    const coursesByLocation = {
      kyiv: await getCoursesByLocation('kyiv'),
      munich: await getCoursesByLocation('munich'),
    };
    const courseSemestersByLocation = { kyiv: [], munich: [] };
    const courseDaysByLocation = { kyiv: {}, munich: {} };
    const subjectsByCourse = {};
    const semestersByCourse = {};
    const selectedSemestersByLocation = { kyiv: {}, munich: {} };
    for (const location of ['kyiv', 'munich']) {
      const courses = coursesByLocation[location] || [];
      for (const course of courses) {
        const semesters = await getSemestersCached(course.id);
        semestersByCourse[course.id] = semesters || [];
        const configuredId = config.course_semesters_by_location
          ? config.course_semesters_by_location[location]?.[course.id]
            || config.course_semesters_by_location[location]?.[String(course.id)]
          : null;
        let semester = null;
        if (configuredId) {
          semester = (semesters || []).find((s) => Number(s.id) === Number(configuredId)) || null;
        }
        if (!semester) {
          semester = await getActiveSemester(course.id);
        }
        if (semester) {
          selectedSemestersByLocation[location][course.id] = semester.id;
        }
        courseSemestersByLocation[location].push({ course, semester });
        const studyDays = await getCourseStudyDays(course.id);
        const activeDays = (studyDays || [])
          .filter((d) => d.is_active)
          .map((d) => d.day_name)
          .filter(Boolean);
        courseDaysByLocation[location][course.id] = activeDays.length ? activeDays : [...daysOfWeek];
        subjectsByCourse[course.id] = await getSubjectsCached(course.id);
      }
    }

    const teachers = await db.all(
      "SELECT id, full_name FROM users WHERE role = 'teacher' ORDER BY full_name"
    );
    const items = await db.all(
      `
        SELECT sgi.*, s.name AS subject_name, s.group_count, u.full_name AS teacher_name
        FROM schedule_generator_items sgi
        JOIN subjects s ON s.id = sgi.subject_id
        LEFT JOIN users u ON u.id = sgi.teacher_id
        WHERE sgi.run_id = ?
        ORDER BY sgi.id DESC
      `,
      [run.id]
    );
    const courseLocationMap = {};
    Object.entries(coursesByLocation).forEach(([location, list]) => {
      (list || []).forEach((course) => {
        courseLocationMap[course.id] = location;
      });
    });
    const limitsRows = await db.all(
      'SELECT * FROM schedule_generator_teacher_limits WHERE run_id = ?',
      [run.id]
    );
    const limitsByTeacher = {};
    limitsRows.forEach((row) => {
      limitsByTeacher[row.teacher_id] = {
        allowed_weekdays: row.allowed_weekdays ? row.allowed_weekdays.split(',') : [],
        max_pairs_per_week: row.max_pairs_per_week,
      };
    });
    const lastConflicts = Array.isArray(config.last_conflicts) ? config.last_conflicts : [];
    const lastStats = config.last_stats || null;

    return res.render('admin-schedule-generator', {
      username: req.session.user.username,
      role: req.session.role,
      run,
      config,
      activeLocation,
      coursesByLocation,
      courseSemestersByLocation,
      courseDaysByLocation,
      subjectsByCourse,
      semestersByCourse,
      selectedSemestersByLocation,
      courseLocationMap,
      teachers,
      items,
      limitsByTeacher,
      lastConflicts,
      lastStats,
      dayOptions: fullWeekDays,
      dayLabels: studyDayLabels,
      classOptions: [1, 2, 3, 4, 5, 6, 7],
    });
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.render');
  }
});

app.post('/admin/schedule-generator/new', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.create');
  }
  const userId = req.session.user.id;
  try {
    const insert = await db.run(
      'INSERT INTO schedule_generator_runs (status, created_by_id, config) VALUES (?, ?, ?) RETURNING id',
      ['draft', userId, serializeGeneratorConfig(DEFAULT_GENERATOR_CONFIG)]
    );
    const runId = insert.lastID;
    return res.redirect(`/admin/schedule-generator?run=${runId}`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.create');
  }
});

app.post('/admin/schedule-generator/config', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.config');
  }
  const runId = Number(req.body.run_id);
  if (!Number.isFinite(runId) || runId <= 0) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20run');
  }
  try {
    const run = await db.get('SELECT * FROM schedule_generator_runs WHERE id = ?', [runId]);
    if (!run) return res.redirect('/admin/schedule-generator?err=Run%20not%20found');
    const existing = parseGeneratorConfig(run.config);
    const maxDailyRaw = Number(req.body.max_daily_pairs);
    const targetDailyRaw = Number(req.body.target_daily_pairs);
    const maxDailyPairs = Number.isNaN(maxDailyRaw)
      ? existing.max_daily_pairs
      : Math.min(Math.max(maxDailyRaw, 1), 7);
    const targetDailyPairs = Number.isNaN(targetDailyRaw)
      ? existing.target_daily_pairs
      : Math.min(Math.max(targetDailyRaw, 1), 7);
    const activeLocation = String(req.body.active_location || existing.active_location || 'kyiv').toLowerCase() === 'munich'
      ? 'munich'
      : 'kyiv';
    const courseSemesterInput = req.body.course_semesters || {};
    const sanitizedCourseSemesters = {};
    const entries = Object.entries(courseSemesterInput);
    for (const [courseIdRaw, semesterIdRaw] of entries) {
      const courseId = Number(courseIdRaw);
      const semesterId = Number(semesterIdRaw);
      if (!Number.isFinite(courseId) || !Number.isFinite(semesterId)) continue;
      const row = await db.get('SELECT id FROM semesters WHERE id = ? AND course_id = ?', [semesterId, courseId]);
      if (row) {
        sanitizedCourseSemesters[String(courseId)] = semesterId;
      }
    }
    const nextCourseSemestersByLocation = {
      ...(existing.course_semesters_by_location || { kyiv: {}, munich: {} }),
      [activeLocation]: sanitizedCourseSemesters,
    };
    const nextConfig = {
      ...existing,
      active_location: activeLocation,
      distribution: String(req.body.distribution || existing.distribution || 'even'),
      seminar_distribution: String(req.body.seminar_distribution || existing.seminar_distribution || 'start'),
      max_daily_pairs: maxDailyPairs || 7,
      target_daily_pairs: targetDailyPairs || 4,
      blocked_weeks: String(req.body.blocked_weeks || ''),
      special_weeks_mode: String(req.body.special_weeks_mode || existing.special_weeks_mode || 'block'),
      prefer_compactness: String(req.body.prefer_compactness || '') === 'on',
      mirror_groups: String(req.body.mirror_groups || '') === 'on',
      course_semesters: sanitizedCourseSemesters,
      course_semesters_by_location: nextCourseSemestersByLocation,
    };
    await db.run(
      'UPDATE schedule_generator_runs SET config = ?, updated_at = NOW() WHERE id = ?',
      [serializeGeneratorConfig(nextConfig), runId]
    );
    const semesterPairs = Object.entries(sanitizedCourseSemesters);
    for (const [courseId, semesterId] of semesterPairs) {
      await db.run(
        'UPDATE schedule_generator_items SET semester_id = ? WHERE run_id = ? AND course_id = ?',
        [Number(semesterId), runId, Number(courseId)]
      );
    }
    return res.redirect(`/admin/schedule-generator?run=${runId}&ok=Settings%20saved`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.config.save');
  }
});

app.post('/admin/schedule-generator/items/add', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.item');
  }
  const runId = Number(req.body.run_id);
  const courseId = Number(req.body.course_id);
  const subjectId = Number(req.body.subject_id);
  const teacherIdRaw = req.body.teacher_id ? Number(req.body.teacher_id) : null;
  const lessonTypeRaw = String(req.body.lesson_type || 'lecture').trim();
  const lessonType = lessonTypeRaw || 'lecture';
  const groupRaw = String(req.body.group_number || 'all');
  const groupNumber = groupRaw === 'all' || groupRaw === '0' ? null : Number(groupRaw);
  const pairsCount = Number(req.body.pairs_count);
  const weeksSet = String(req.body.weeks_set || '').trim();
  const fixedDay = normalizeWeekdayName(req.body.fixed_day);
  const fixedClass = req.body.fixed_class_number ? Number(req.body.fixed_class_number) : null;

  if (!Number.isFinite(runId) || runId <= 0 || !Number.isFinite(courseId) || !Number.isFinite(subjectId)) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20data`);
  }
  if (!Number.isFinite(pairsCount) || pairsCount <= 0) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20pairs`);
  }
  if (groupNumber && (Number.isNaN(groupNumber) || groupNumber < 1)) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20group`);
  }
  if (fixedClass && (fixedClass < 1 || fixedClass > 7)) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20slot`);
  }

  try {
    const subjectRow = await db.get('SELECT id, group_count FROM subjects WHERE id = ? AND course_id = ?', [subjectId, courseId]);
    if (!subjectRow) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Subject%20not%20found`);
    }
    if (groupNumber && Number(groupNumber) > Number(subjectRow.group_count || 1)) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20group`);
    }
    const run = await db.get('SELECT config FROM schedule_generator_runs WHERE id = ?', [runId]);
    if (!run) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Run%20not%20found`);
    }
    const runConfig = parseGeneratorConfig(run.config);
    const courseRow = await db.get('SELECT location FROM courses WHERE id = ?', [courseId]);
    const courseLocation = String(courseRow?.location || 'kyiv').toLowerCase() === 'munich' ? 'munich' : 'kyiv';
    const configuredSemesterId = runConfig.course_semesters_by_location
      ? runConfig.course_semesters_by_location[courseLocation]?.[courseId]
        || runConfig.course_semesters_by_location[courseLocation]?.[String(courseId)]
      : null;
    let semester = null;
    if (configuredSemesterId) {
      semester = await db.get('SELECT id FROM semesters WHERE id = ? AND course_id = ?', [configuredSemesterId, courseId]);
    }
    if (!semester) {
      semester = await getActiveSemester(courseId);
    }
    if (!semester) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Semester%20not%20found`);
    }
    await db.run(
      `
        INSERT INTO schedule_generator_items
          (run_id, course_id, semester_id, subject_id, teacher_id, lesson_type, group_number, pairs_count, weeks_set, fixed_day, fixed_class_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        runId,
        courseId,
        semester.id,
        subjectId,
        teacherIdRaw || null,
        lessonType,
        groupNumber,
        pairsCount,
        weeksSet || null,
        fixedDay,
        fixedClass || null,
      ]
    );
    return res.redirect(`/admin/schedule-generator?run=${runId}&ok=Item%20added`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.item.add');
  }
});

app.post('/admin/schedule-generator/items/edit/:id', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.item.edit');
  }
  const itemId = Number(req.params.id);
  const runId = Number(req.body.run_id);
  const courseId = Number(req.body.course_id);
  const subjectId = Number(req.body.subject_id);
  const teacherIdRaw = req.body.teacher_id ? Number(req.body.teacher_id) : null;
  const lessonTypeRaw = String(req.body.lesson_type || 'lecture').trim();
  const lessonType = lessonTypeRaw || 'lecture';
  const groupRaw = String(req.body.group_number || 'all');
  const groupNumber = groupRaw === 'all' || groupRaw === '0' ? null : Number(groupRaw);
  const pairsCount = Number(req.body.pairs_count);
  const weeksSet = String(req.body.weeks_set || '').trim();
  const fixedDay = normalizeWeekdayName(req.body.fixed_day);
  const fixedClass = req.body.fixed_class_number ? Number(req.body.fixed_class_number) : null;

  if (!Number.isFinite(itemId) || !Number.isFinite(runId) || runId <= 0) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20item');
  }
  if (!Number.isFinite(pairsCount) || pairsCount <= 0) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20pairs`);
  }
  if (groupNumber && (Number.isNaN(groupNumber) || groupNumber < 1)) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20group`);
  }
  if (fixedClass && (fixedClass < 1 || fixedClass > 7)) {
    return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20slot`);
  }

  try {
    const subjectRow = await db.get('SELECT id, group_count FROM subjects WHERE id = ? AND course_id = ?', [subjectId, courseId]);
    if (!subjectRow) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Subject%20not%20found`);
    }
    if (groupNumber && Number(groupNumber) > Number(subjectRow.group_count || 1)) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Invalid%20group`);
    }
    const run = await db.get('SELECT config FROM schedule_generator_runs WHERE id = ?', [runId]);
    if (!run) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Run%20not%20found`);
    }
    const runConfig = parseGeneratorConfig(run.config);
    const courseRow = await db.get('SELECT location FROM courses WHERE id = ?', [courseId]);
    const courseLocation = String(courseRow?.location || 'kyiv').toLowerCase() === 'munich' ? 'munich' : 'kyiv';
    const configuredSemesterId = runConfig.course_semesters_by_location
      ? runConfig.course_semesters_by_location[courseLocation]?.[courseId]
        || runConfig.course_semesters_by_location[courseLocation]?.[String(courseId)]
      : null;
    let semester = null;
    if (configuredSemesterId) {
      semester = await db.get('SELECT id FROM semesters WHERE id = ? AND course_id = ?', [configuredSemesterId, courseId]);
    }
    if (!semester) {
      semester = await getActiveSemester(courseId);
    }
    if (!semester) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=Semester%20not%20found`);
    }
    await db.run(
      `
        UPDATE schedule_generator_items
        SET course_id = ?, semester_id = ?, subject_id = ?, teacher_id = ?, lesson_type = ?, group_number = ?, pairs_count = ?, weeks_set = ?, fixed_day = ?, fixed_class_number = ?
        WHERE id = ? AND run_id = ?
      `,
      [
        courseId,
        semester.id,
        subjectId,
        teacherIdRaw || null,
        lessonType,
        groupNumber,
        pairsCount,
        weeksSet || null,
        fixedDay,
        fixedClass || null,
        itemId,
        runId,
      ]
    );
    return res.redirect(`/admin/schedule-generator?run=${runId}&ok=Item%20saved`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.item.edit');
  }
});

app.post('/admin/schedule-generator/items/delete/:id', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.item.delete');
  }
  const itemId = Number(req.params.id);
  const runId = Number(req.body.run_id);
  if (!Number.isFinite(itemId) || !Number.isFinite(runId) || runId <= 0) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20item');
  }
  try {
    await db.run('DELETE FROM schedule_generator_items WHERE id = ? AND run_id = ?', [itemId, runId]);
    return res.redirect(`/admin/schedule-generator?run=${runId}&ok=Item%20deleted`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.item.delete');
  }
});

app.post('/admin/schedule-generator/teachers/save', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.teacher');
  }
  const runId = Number(req.body.run_id);
  const teacherId = Number(req.body.teacher_id);
  if (!Number.isFinite(runId) || runId <= 0 || !Number.isFinite(teacherId)) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20teacher');
  }
  const allowedDaysRaw = normalizeGeneratorDays(req.body.allowed_days);
  const allowedDays = allowedDaysRaw
    .map((day) => normalizeWeekdayName(day))
    .filter(Boolean);
  const maxPairsRaw = Number(req.body.max_pairs_per_week);
  const maxPairs = Number.isNaN(maxPairsRaw) || maxPairsRaw <= 0 ? null : maxPairsRaw;

  try {
    await db.run(
      `
        INSERT INTO schedule_generator_teacher_limits (run_id, teacher_id, allowed_weekdays, max_pairs_per_week)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (run_id, teacher_id)
        DO UPDATE SET allowed_weekdays = EXCLUDED.allowed_weekdays, max_pairs_per_week = EXCLUDED.max_pairs_per_week, updated_at = NOW()
      `,
      [runId, teacherId, allowedDays.join(','), maxPairs]
    );
    return res.redirect(`/admin/schedule-generator?run=${runId}&ok=Teacher%20saved`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.teacher.save');
  }
});

app.post('/admin/schedule-generator/run', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.run');
  }
  const runId = Number(req.body.run_id);
  if (!Number.isFinite(runId) || runId <= 0) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20run');
  }
  try {
    const run = await db.get('SELECT * FROM schedule_generator_runs WHERE id = ?', [runId]);
    if (!run) return res.redirect('/admin/schedule-generator?err=Run%20not%20found');
    const config = parseGeneratorConfig(run.config);
    const activeLocation = config.active_location === 'munich' ? 'munich' : 'kyiv';
    const locationCourses = await getCoursesByLocation(activeLocation);
    const locationCourseIds = new Set((locationCourses || []).map((c) => Number(c.id)));
    const itemsAll = await db.all(
      `
        SELECT sgi.*, s.name AS subject_name, s.group_count
        FROM schedule_generator_items sgi
        JOIN subjects s ON s.id = sgi.subject_id
        WHERE sgi.run_id = ?
      `,
      [runId]
    );
    const items = (itemsAll || []).filter((item) => locationCourseIds.has(Number(item.course_id)));
    if (!items.length) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=No%20items%20for%20location`);
    }

    const courseContexts = new Map();
    const courseIds = Array.from(new Set(items.map((item) => String(item.course_id))));
    for (const courseId of courseIds) {
      const configuredSemesterId = config.course_semesters
        ? config.course_semesters[courseId] || config.course_semesters[String(courseId)]
        : null;
      let semester = null;
      if (configuredSemesterId) {
        semester = await db.get('SELECT * FROM semesters WHERE id = ? AND course_id = ?', [configuredSemesterId, courseId]);
      }
      if (!semester) {
        semester = await getActiveSemester(courseId);
      }
      if (!semester) continue;
      const studyDays = await getCourseStudyDays(courseId);
      const activeDays = (studyDays || [])
        .filter((d) => d.is_active)
        .map((d) => d.day_name)
        .filter(Boolean);
      courseContexts.set(String(courseId), {
        course_id: Number(courseId),
        semester_id: semester.id,
        weeks_count: Number(semester.weeks_count || 15),
        active_days: activeDays.length ? activeDays : [...daysOfWeek],
      });
    }

    const limitsRows = await db.all(
      'SELECT * FROM schedule_generator_teacher_limits WHERE run_id = ?',
      [runId]
    );
    const limitsMap = new Map();
    limitsRows.forEach((row) => {
      limitsMap.set(String(row.teacher_id), {
        allowed_days: row.allowed_weekdays ? row.allowed_weekdays.split(',') : [],
        max_pairs_per_week: row.max_pairs_per_week,
      });
    });

    const normalizedItems = items.map((item) => ({
      ...item,
      semester_id: (courseContexts.get(String(item.course_id)) || {}).semester_id || item.semester_id,
    }));

    const result = generateSchedule({
      items: normalizedItems,
      courseContexts,
      teacherLimits: limitsMap,
      config,
    });

    if (courseIds.length) {
      const placeholders = courseIds.map(() => '?').join(',');
      await db.run(
        `DELETE FROM schedule_generator_entries WHERE run_id = ? AND course_id IN (${placeholders})`,
        [runId, ...courseIds]
      );
    }
    if (result.entries.length) {
      const stmt = db.prepare(
        `
          INSERT INTO schedule_generator_entries
            (run_id, course_id, semester_id, subject_id, teacher_id, lesson_type, group_number, day_of_week, class_number, week_number)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
      );
      result.entries.forEach((entry) => {
        stmt.run(
          runId,
          entry.course_id,
          entry.semester_id,
          entry.subject_id,
          entry.teacher_id,
          entry.lesson_type || null,
          entry.group_number,
          entry.day_of_week,
          entry.class_number,
          entry.week_number
        );
      });
      await stmt.finalize();
    }

    const nextConfig = {
      ...config,
      last_stats: {
        generated_at: new Date().toISOString(),
        items: normalizedItems.length,
        entries: result.entries.length,
        conflicts: result.conflicts.length,
      },
      last_conflicts: result.conflicts,
    };
    await db.run(
      'UPDATE schedule_generator_runs SET config = ?, updated_at = NOW() WHERE id = ?',
      [serializeGeneratorConfig(nextConfig), runId]
    );

    const firstCourse = normalizedItems[0] ? normalizedItems[0].course_id : courseIds[0];
    return res.redirect(`/admin/schedule-generator/${runId}/preview?course=${firstCourse}&week=1`);
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.run');
  }
});

app.get('/admin/schedule-generator/:runId/preview', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.preview');
  }
  const runId = Number(req.params.runId);
  const courseId = Number(req.query.course);
  if (!Number.isFinite(runId) || runId <= 0) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20run');
  }
  try {
    const run = await db.get('SELECT * FROM schedule_generator_runs WHERE id = ?', [runId]);
    if (!run) return res.redirect('/admin/schedule-generator?err=Run%20not%20found');
    const config = parseGeneratorConfig(run.config);
    const activeLocation = config.active_location === 'munich' ? 'munich' : 'kyiv';
    const coursesByLocation = {
      kyiv: await getCoursesByLocation('kyiv'),
      munich: await getCoursesByLocation('munich'),
    };
    const allCourses = [...(coursesByLocation.kyiv || []), ...(coursesByLocation.munich || [])];
    const availableCourseIds = allCourses.map((c) => Number(c.id));
    const preferredList = coursesByLocation[activeLocation] || [];
    const fallbackCourseId = preferredList.length ? Number(preferredList[0].id) : availableCourseIds[0];
    const selectedCourseId = availableCourseIds.includes(courseId) ? courseId : fallbackCourseId;
    if (!selectedCourseId) {
      return res.redirect('/admin/schedule-generator?run=' + runId);
    }
    const configuredSemesterId = config.course_semesters
      ? config.course_semesters[selectedCourseId] || config.course_semesters[String(selectedCourseId)]
      : null;
    let activeSemester = null;
    if (configuredSemesterId) {
      activeSemester = await db.get('SELECT * FROM semesters WHERE id = ? AND course_id = ?', [configuredSemesterId, selectedCourseId]);
    }
    if (!activeSemester) {
      activeSemester = await getActiveSemester(selectedCourseId);
    }
    const totalWeeks = activeSemester && activeSemester.weeks_count ? Number(activeSemester.weeks_count) : 15;
    let selectedWeek = Number(req.query.week);
    if (Number.isNaN(selectedWeek) || selectedWeek < 1) selectedWeek = 1;
    if (selectedWeek > totalWeeks) selectedWeek = totalWeeks;

    const studyDays = await getCourseStudyDays(selectedCourseId);
    let activeDays = (studyDays || [])
      .filter((d) => d.is_active)
      .map((d) => d.day_name)
      .filter(Boolean);
    if (!activeDays.length) {
      activeDays = [...daysOfWeek];
    }
    const weekDates = fullWeekDays.map((_, idx) =>
      getDateForWeekIndex(selectedWeek, idx, activeSemester ? activeSemester.start_date : null)
    );
    const dayDates = {};
    activeDays.forEach((day) => {
      const idx = fullWeekDays.indexOf(day);
      dayDates[day] = idx >= 0 ? weekDates[idx] : null;
    });

    const scheduleByDay = {};
    activeDays.forEach((day) => {
      scheduleByDay[day] = [];
    });

    const rows = await db.all(
      `
        SELECT sge.*, s.name AS subject_name, u.full_name AS teacher_name
        FROM schedule_generator_entries sge
        JOIN subjects s ON s.id = sge.subject_id
        LEFT JOIN users u ON u.id = sge.teacher_id
        WHERE sge.run_id = ? AND sge.course_id = ? AND sge.week_number = ?
      `,
      [runId, selectedCourseId, selectedWeek]
    );
    const grouped = new Map();
    (rows || []).forEach((row) => {
      const key = `${row.subject_id}|${row.day_of_week}|${row.class_number}|${row.teacher_id || 0}|${row.lesson_type || ''}`;
      if (!grouped.has(key)) {
        grouped.set(key, { ...row, group_numbers: new Set() });
      }
      grouped.get(key).group_numbers.add(Number(row.group_number));
    });
    grouped.forEach((entry) => {
      const groups = Array.from(entry.group_numbers).sort((a, b) => a - b);
      const groupLabel = groups.length === 1 ? `Група ${groups[0]}` : `Групи: ${groups.join(', ')}`;
      const normalized = {
        ...entry,
        group_numbers: groups,
        group_label: groupLabel,
      };
      if (scheduleByDay[entry.day_of_week]) {
        scheduleByDay[entry.day_of_week].push(normalized);
      }
    });
    activeDays.forEach((day) => {
      scheduleByDay[day].sort((a, b) => a.class_number - b.class_number);
    });

    return res.render('admin-schedule-generator-preview', {
      username: req.session.user.username,
      role: req.session.role,
      run,
      courses: allCourses,
      selectedCourseId,
      scheduleByDay,
      daysOfWeek: activeDays,
      dayDates,
      currentWeek: selectedWeek,
      totalWeeks,
      semester: activeSemester,
      bellSchedule,
      config,
    });
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.preview');
  }
});

app.post('/admin/schedule-generator/:runId/publish', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.publish');
  }
  const runId = Number(req.params.runId);
  if (!Number.isFinite(runId) || runId <= 0) {
    return res.redirect('/admin/schedule-generator?err=Invalid%20run');
  }
  const replace = String(req.body.replace || '') === '1' || String(req.body.replace || '') === 'on';
  try {
    const entries = await db.all(
      `
        SELECT run_id, course_id, semester_id, subject_id, group_number, day_of_week, class_number, week_number
        FROM schedule_generator_entries
        WHERE run_id = ?
      `,
      [runId]
    );
    if (!entries.length) {
      return res.redirect(`/admin/schedule-generator?run=${runId}&err=No%20entries`);
    }
    if (replace) {
      const pairs = new Map();
      entries.forEach((entry) => {
        const key = `${entry.course_id}|${entry.semester_id}`;
        pairs.set(key, { course_id: entry.course_id, semester_id: entry.semester_id });
      });
      for (const pair of pairs.values()) {
        await db.run(
          'DELETE FROM schedule_entries WHERE course_id = ? AND semester_id = ?',
          [pair.course_id, pair.semester_id]
        );
      }
    }
    const stmt = db.prepare(
      `
        INSERT INTO schedule_entries (subject_id, group_number, day_of_week, class_number, week_number, course_id, semester_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    );
    entries.forEach((entry) => {
      stmt.run(
        entry.subject_id,
        entry.group_number,
        entry.day_of_week,
        entry.class_number,
        entry.week_number,
        entry.course_id,
        entry.semester_id
      );
    });
    await stmt.finalize();
    await db.run('UPDATE schedule_generator_runs SET status = ?, updated_at = NOW() WHERE id = ?', ['published', runId]);
    logAction(db, req, 'schedule_generator_publish', { run_id: runId, replace });
    return res.redirect('/admin?ok=Schedule%20published');
  } catch (err) {
    return handleDbError(res, err, 'admin.scheduleGenerator.publish');
  }
});

let schedulerRunning = false;
const publishScheduledItems = async () => {
  if (schedulerRunning) {
    return { messages: 0, homework: 0, skipped: true };
  }
  schedulerRunning = true;
  try {
    await ensureDbReady();
    const nowIso = new Date().toISOString();
    const msgResult = settingsCache.allow_messages
      ? await db.run(
          `UPDATE messages
           SET status = 'published', published_at = ?
           WHERE status = 'scheduled' AND scheduled_at IS NOT NULL AND scheduled_at <= ?`,
          [nowIso, nowIso]
        )
      : { changes: 0 };
    const hwResult = await db.run(
      `UPDATE homework
       SET status = 'published', published_at = ?
       WHERE status = 'scheduled' AND scheduled_at IS NOT NULL AND scheduled_at <= ?`,
      [nowIso, nowIso]
    );
    const messages = Number(msgResult?.changes || 0);
    const homework = Number(hwResult?.changes || 0);
    if (messages) {
      broadcast('messages_updated');
    }
    if (homework) {
      broadcast('homework_updated');
    }
    return { messages, homework };
  } finally {
    schedulerRunning = false;
  }
};

app.post('/admin/api/scheduler/run', requireAdmin, async (req, res) => {
  try {
    const result = await publishScheduledItems();
    return res.json({ ok: true, ...result });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});
      }
    );
  });
});
});

app.post('/admin/settings', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.settings.init');
  }
  const sessionDays = Number(req.body.session_duration_days);
  const maxFileSize = Number(req.body.max_file_size_mb);
  const minTeamMembers = Number(req.body.min_team_members);
  const allowHomework = String(req.body.allow_homework_creation).toLowerCase() === 'true';
  const allowCustomDeadlines = String(req.body.allow_custom_deadlines).toLowerCase() === 'true';
  const allowMessages = String(req.body.allow_messages).toLowerCase() === 'true';
  const scheduleRefreshMinutes = Number(req.body.schedule_refresh_minutes);
  if (
    Number.isNaN(sessionDays) || sessionDays <= 0 ||
    Number.isNaN(maxFileSize) || maxFileSize <= 0 ||
    Number.isNaN(minTeamMembers) || minTeamMembers <= 0 ||
    Number.isNaN(scheduleRefreshMinutes) || scheduleRefreshMinutes <= 0
  ) {
    return res.redirect('/admin?err=Invalid%20settings');
  }
  if (scheduleRefreshMinutes > 120) {
    return res.redirect('/admin?err=Invalid%20settings');
  }
  try {
    const stmt = db.prepare(
      'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value'
    );
    stmt.run('session_duration_days', String(sessionDays));
    stmt.run('max_file_size_mb', String(maxFileSize));
    stmt.run('allow_homework_creation', allowHomework ? 'true' : 'false');
    stmt.run('min_team_members', String(minTeamMembers));
    stmt.run('allow_custom_deadlines', allowCustomDeadlines ? 'true' : 'false');
    stmt.run('allow_messages', allowMessages ? 'true' : 'false');
    stmt.run('schedule_refresh_minutes', String(scheduleRefreshMinutes));
    await refreshSettingsCache();
    return res.redirect('/admin?ok=Settings%20saved');
  } catch (err) {
    return handleDbError(res, err, 'admin.settings.save');
  }
});

app.get('/admin/overview', requireOverviewAccess, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'admin.overview.init');
  }
  const role = req.session.role;
  const isAdmin = role === 'admin';
  const isDeanery = role === 'deanery';
  const isStarosta = role === 'starosta';
  let courses = [];
  try {
    courses = await getCoursesCached();
  } catch (err) {
    return handleDbError(res, err, 'admin.overview.courses');
  }
  let courseId = isAdmin ? getAdminCourse(req) : Number(req.session.user.course_id || 1);
  if (isDeanery) {
    const requested = Number(req.query.course);
    if (!Number.isNaN(requested)) {
      courseId = requested;
    }
  }
  if (courses.length && !courses.some((c) => Number(c.id) === Number(courseId))) {
    courseId = courses[0].id;
  }
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return handleDbError(res, err, 'admin.overview.semester');
  }
  try {
    const statsParams = activeSemester ? [courseId, activeSemester.id] : [courseId];
    const [
      usersRow,
      subjectsRow,
      homeworkRow,
      teamworkTasksRow,
      teamworkGroupsRow,
      teamworkMembersRow,
    ] = await Promise.all([
      db.get('SELECT COUNT(*) AS count FROM users WHERE course_id = ?', [courseId]),
      db.get('SELECT COUNT(*) AS count FROM subjects WHERE course_id = ?', [courseId]),
      db.get(
        `SELECT COUNT(*) AS count FROM homework WHERE course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}`,
        statsParams
      ),
      db.get(
        `SELECT COUNT(*) AS count FROM teamwork_tasks WHERE course_id = ?${activeSemester ? ' AND semester_id = ?' : ''}`,
        statsParams
      ),
      db.get(
        `SELECT COUNT(*) AS count
         FROM teamwork_groups g
         JOIN teamwork_tasks t ON t.id = g.task_id
         WHERE t.course_id = ?${activeSemester ? ' AND t.semester_id = ?' : ''}`,
        statsParams
      ),
      db.get(
        `SELECT COUNT(*) AS count
         FROM teamwork_members m
         JOIN teamwork_tasks t ON t.id = m.task_id
         WHERE t.course_id = ?${activeSemester ? ' AND t.semester_id = ?' : ''}`,
        statsParams
      ),
                                  ]);

    const dashboardStats = {
      users: Number(usersRow?.count || 0),
      subjects: Number(subjectsRow?.count || 0),
      homework: Number(homeworkRow?.count || 0),
      teamworkTasks: Number(teamworkTasksRow?.count || 0),
      teamworkGroups: Number(teamworkGroupsRow?.count || 0),
      teamworkMembers: Number(teamworkMembersRow?.count || 0),
    };

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const weekStart = new Date(today);
    weekStart.setDate(weekStart.getDate() - 6);
    const weeklyLabels = [];
    for (let i = 0; i < 7; i += 1) {
      const d = new Date(weekStart);
      d.setDate(weekStart.getDate() + i);
      weeklyLabels.push(d.toISOString().slice(0, 10));
    }
    let weeklyHomework = weeklyLabels.map(() => 0);
    let weeklyTeamwork = weeklyLabels.map(() => 0);
    let weeklyUserRoles = ['student', 'starosta', 'deanery', 'admin'];
    let weeklyUserSeries = weeklyUserRoles.map(() => weeklyLabels.map(() => 0));
    try {
      const weeklyParams = activeSemester
        ? [courseId, weekStart.toISOString(), activeSemester.id]
        : [courseId, weekStart.toISOString()];
      const [weeklyHomeworkRows, weeklyTeamworkRows, weeklyUsersRows] = await Promise.all([
        db.all(
          `SELECT DATE(created_at::timestamp) AS day, COUNT(*) AS count
           FROM homework
           WHERE course_id = ? AND created_at::timestamp >= ?${activeSemester ? ' AND semester_id = ?' : ''}
           GROUP BY day
           ORDER BY day`,
          weeklyParams
        ),
        db.all(
          `SELECT DATE(created_at::timestamp) AS day, COUNT(*) AS count
           FROM teamwork_tasks
           WHERE course_id = ? AND created_at::timestamp >= ?${activeSemester ? ' AND semester_id = ?' : ''}
           GROUP BY day
           ORDER BY day`,
          weeklyParams
        ),
        db.all(
          `SELECT DATE(created_at) AS day, role, COUNT(*) AS count
           FROM users
           WHERE course_id = ? AND created_at >= ?
           GROUP BY day, role
           ORDER BY day`,
          [courseId, weekStart.toISOString()]
        ),
      ]);

      const homeworkMap = {};
      (weeklyHomeworkRows || []).forEach((row) => {
        const key = String(row.day);
        homeworkMap[key] = Number(row.count || 0);
      });
      const teamworkMap = {};
      (weeklyTeamworkRows || []).forEach((row) => {
        const key = String(row.day);
        teamworkMap[key] = Number(row.count || 0);
      });
      weeklyHomework = weeklyLabels.map((key) => homeworkMap[key] || 0);
      weeklyTeamwork = weeklyLabels.map((key) => teamworkMap[key] || 0);

      const roleOrder = ['student', 'starosta', 'deanery', 'admin'];
      const roleMap = {};
      (weeklyUsersRows || []).forEach((row) => {
        const key = String(row.day);
        if (!roleMap[row.role]) {
          roleMap[row.role] = {};
        }
        roleMap[row.role][key] = Number(row.count || 0);
      });
      weeklyUserRoles = roleOrder.filter((role) => roleMap[role]);
      if (!weeklyUserRoles.length) {
        weeklyUserRoles.push(...roleOrder);
      }
      weeklyUserSeries = weeklyUserRoles.map((role) =>
        weeklyLabels.map((key) => (roleMap[role] && roleMap[role][key]) || 0)
      );
    } catch (weeklyErr) {
      console.error('Database error (admin.dashboard.weekly)', weeklyErr);
    }

    return res.render('admin-overview', {
      username: req.session.user.username,
      role: req.session.role,
      courses,
      selectedCourseId: courseId,
      dashboardStats,
      weeklyLabels,
      weeklyHomework,
      weeklyTeamwork,
      weeklyUserRoles,
      weeklyUserSeries,
      limitedStaffView: isStarosta,
      allowCourseSelect: isAdmin || isDeanery,
      backLink: isAdmin ? `/admin?course=${courseId}` : (isDeanery ? `/deanery?course=${courseId}` : '/starosta'),
    });
  } catch (err) {
    return handleDbError(res, err, 'admin.overview.stats');
  }
});

app.get('/admin/users.json', requireAdmin, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
  const status = req.query.status;
  const q = req.query.q;
  const group = req.query.group;
  const courseId = getAdminCourse(req);
  ensureUsersSchema(() => {
    const userFilters = ['course_id = ?'];
    const userParams = [courseId];
    if (usersHasIsActive) {
      if (status === 'inactive') {
        userFilters.push('is_active = 0');
      } else if (status !== 'all') {
        userFilters.push('is_active = 1');
      }
    }
    if (q) {
      userFilters.push('full_name ILIKE ?');
      userParams.push(`%${q}%`);
    }
    if (group) {
      userFilters.push('schedule_group = ?');
      userParams.push(group);
    }
    const userWhere = userFilters.length ? `WHERE ${userFilters.join(' AND ')}` : '';
    const cols = usersHasIsActive ? 'id, full_name, role, schedule_group, is_active, last_login_ip, last_user_agent, last_login_at'
      : 'id, full_name, role, schedule_group, last_login_ip, last_user_agent, last_login_at';
    db.all(
      `SELECT ${cols}, course_id FROM users ${userWhere} ORDER BY full_name`,
      userParams,
      (userErr, users) => {
        if (userErr) {
          console.error('Database error (admin.users.json.users)', userErr);
          return res.status(500).json({ error: 'Database error' });
        }
        getSubjectsCached(courseId)
          .then((subjects) => {
            getCoursesCached()
              .then((courses) => {
                db.all(
                  `
                    SELECT sg.student_id, sg.subject_id, sg.group_number
                    FROM student_groups sg
                    JOIN subjects s ON s.id = sg.subject_id
                    WHERE s.course_id = ?
                  `,
                  [courseId],
                  (sgErr, studentGroups) => {
                    if (sgErr) {
                      console.error('Database error (admin.users.json.studentGroups)', sgErr);
                      return res.status(500).json({ error: 'Database error' });
                    }
                    res.json({ users, subjects, studentGroups, courses, selectedCourseId: courseId });
                  }
                );
              })
              .catch((courseErr) => {
                console.error('Database error (admin.users.json.courses)', courseErr);
                return res.status(500).json({ error: 'Database error' });
              });
          })
          .catch((subjectErr) => {
            console.error('Database error (admin.users.json.subjects)', subjectErr);
            return res.status(500).json({ error: 'Database error' });
          });
      }
    );
  });
});

app.get('/admin/export/schedule.csv', requireAdmin, async (req, res) => {
  const courseId = getAdminCourse(req);
  const activeSemester = await getActiveSemester(courseId);
  db.all(
    `
      SELECT se.id, s.name AS subject, se.group_number, se.day_of_week, se.class_number, se.week_number
      FROM schedule_entries se
      JOIN subjects s ON s.id = se.subject_id
      WHERE se.course_id = ?${activeSemester ? ' AND se.semester_id = ?' : ''}
      ORDER BY se.week_number, se.day_of_week, se.class_number
    `,
    activeSemester ? [courseId, activeSemester.id] : [courseId],
    (err, rows) => {
      if (err) {
        return res.status(500).send('Database error');
      }
      const header = 'id,subject,group_number,day_of_week,class_number,week_number';
      const lines = rows.map((r) =>
        [r.id, r.subject, r.group_number, r.day_of_week, r.class_number, r.week_number]
          .map((v) => `"${String(v ?? '').replace(/\"/g, '""')}"`)
          .join(',')
      );
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="schedule.csv"');
      res.send([header, ...lines].join('\n'));
    }
  );
});

app.post('/admin/import/schedule.csv', requireAdmin, writeLimiter, csvUpload.single('csv_file'), async (req, res) => {
  if (!req.file || !req.file.buffer) {
    return res.redirect('/admin?err=Missing%20CSV');
  }
  const courseId = getAdminCourse(req);
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return res.redirect('/admin?err=Semester%20error');
  }
  if (!activeSemester) {
    return res.redirect('/admin?err=No%20active%20semester');
  }
  let subjects = [];
  try {
    subjects = await getSubjectsCached(courseId);
  } catch (err) {
    return res.redirect('/admin?err=Subjects%20error');
  }
  const subjectMap = new Map(
    (subjects || []).map((s) => [String(s.name || '').trim().toLowerCase(), s])
  );
  let rows = [];
  try {
    const text = req.file.buffer.toString('utf8');
    rows = parseCsvText(text);
  } catch (err) {
    return res.redirect('/admin?err=Invalid%20CSV');
  }
  if (!rows.length) {
    return res.redirect('/admin?err=Empty%20CSV');
  }
  let inserted = 0;
  let updated = 0;
  let skipped = 0;
  for (const row of rows) {
    const subjectName = String(row.subject || '').trim().toLowerCase();
    const subject = subjectMap.get(subjectName);
    const groupNumber = Number(row.group_number);
    const classNumber = Number(row.class_number);
    const weekNumber = Number(row.week_number);
    const dayOfWeek = String(row.day_of_week || '').trim();
    if (!subject || Number.isNaN(groupNumber) || Number.isNaN(classNumber) || Number.isNaN(weekNumber) || !dayOfWeek) {
      skipped += 1;
      continue;
    }
    const existing = await db.get(
      `SELECT id FROM schedule_entries
       WHERE course_id = ? AND semester_id = ? AND week_number = ?
         AND day_of_week = ? AND class_number = ? AND group_number = ?`,
      [courseId, activeSemester.id, weekNumber, dayOfWeek, classNumber, groupNumber]
    );
    if (existing && existing.id) {
      await db.run('UPDATE schedule_entries SET subject_id = ? WHERE id = ?', [subject.id, existing.id]);
      updated += 1;
    } else {
      await db.run(
        `INSERT INTO schedule_entries
         (subject_id, group_number, day_of_week, class_number, week_number, course_id, semester_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [subject.id, groupNumber, dayOfWeek, classNumber, weekNumber, courseId, activeSemester.id]
      );
      inserted += 1;
    }
  }
  logAction(db, req, 'schedule_import_csv', { inserted, updated, skipped, course_id: courseId });
  return res.redirect(`/admin?ok=Schedule%20imported%20(${inserted}%2F${updated}%2F${skipped})`);
});

app.get('/admin/export/users.csv', requireAdmin, (req, res) => {
  const courseId = Number(req.query.course || getAdminCourse(req));
  const semesterId = req.query.semester_id ? Number(req.query.semester_id) : null;
  const group = req.query.group;
  const filters = ['u.course_id = ?'];
  const params = [courseId];
  if (group) {
    filters.push('u.schedule_group = ?');
    params.push(group);
  }
  if (semesterId) {
    filters.push(
      `EXISTS (
        SELECT 1
        FROM student_groups sg
        JOIN schedule_entries se
          ON se.subject_id = sg.subject_id
         AND se.group_number = sg.group_number
         AND se.semester_id = ?
        WHERE sg.student_id = u.id
      )`
    );
    params.push(semesterId);
  }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  db.all(
    `SELECT u.id, u.full_name, u.role, u.schedule_group, u.is_active, u.course_id
     FROM users u
     ${where}
     ORDER BY u.full_name`,
    params,
    (err, rows) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    const header = 'id,full_name,role,schedule_group,is_active,course_id';
    const lines = rows.map((r) =>
      [r.id, r.full_name, r.role, r.schedule_group, r.is_active, r.course_id]
        .map((v) => `"${String(v ?? '').replace(/\"/g, '""')}"`)
        .join(',')
    );
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
    res.send([header, ...lines].join('\n'));
  });
});

app.post('/admin/import/users.csv', requireAdmin, writeLimiter, csvUpload.single('csv_file'), async (req, res) => {
  if (!req.file || !req.file.buffer) {
    return res.redirect('/admin?err=Missing%20CSV');
  }
  const courseId = getAdminCourse(req);
  let rows = [];
  let courses = [];
  try {
    const text = req.file.buffer.toString('utf8');
    rows = parseCsvText(text);
    courses = await getCoursesCached();
  } catch (err) {
    return res.redirect('/admin?err=Invalid%20CSV');
  }
  if (!rows.length) {
    return res.redirect('/admin?err=Empty%20CSV');
  }
  const courseSet = new Set((courses || []).map((c) => Number(c.id)));
  let inserted = 0;
  let updated = 0;
  let skipped = 0;
  for (const row of rows) {
    const fullName = String(row.full_name || '').trim().replace(/\s+/g, ' ');
    if (!fullName) {
      skipped += 1;
      continue;
    }
    const role = String(row.role || 'student').trim().toLowerCase();
    const scheduleGroup = String(row.schedule_group || 'A').trim();
    const isActive = row.is_active === '' ? 1 : Number(row.is_active) ? 1 : 0;
    const rowCourse = row.course_id ? Number(row.course_id) : courseId;
    const finalCourse = courseSet.has(rowCourse) ? rowCourse : courseId;
    const existing = await db.get('SELECT id FROM users WHERE LOWER(full_name) = LOWER(?)', [fullName]);
    if (existing && existing.id) {
      await db.run(
        `UPDATE users
         SET role = ?, schedule_group = ?, is_active = ?, course_id = ?, language = COALESCE(language, ?)
         WHERE id = ?`,
        [role || 'student', scheduleGroup || 'A', isActive, finalCourse, 'uk', existing.id]
      );
      updated += 1;
    } else {
      await db.run(
        `INSERT INTO users (full_name, role, password_hash, is_active, schedule_group, course_id, language)
         VALUES (?, ?, NULL, ?, ?, ?, ?)`,
        [fullName, role || 'student', isActive, scheduleGroup || 'A', finalCourse, 'uk']
      );
      inserted += 1;
    }
  }
  logAction(db, req, 'users_import_csv', { inserted, updated, skipped, course_id: courseId });
  broadcast('users_updated');
  return res.redirect(`/admin?ok=Users%20imported%20(${inserted}%2F${updated}%2F${skipped})`);
});

app.get('/admin/export/subjects.csv', requireAdmin, (req, res) => {
  const courseId = getAdminCourse(req);
  db.all(
    'SELECT id, name, group_count, default_group, is_required, is_general FROM subjects WHERE course_id = ? ORDER BY name',
    [courseId],
    (err, rows) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    const header = 'id,name,group_count,default_group,is_required,is_general';
    const lines = rows.map((r) =>
      [r.id, r.name, r.group_count, r.default_group, r.is_required ? 1 : 0, r.is_general ? 1 : 0]
        .map((v) => `"${String(v ?? '').replace(/\"/g, '""')}"`)
        .join(',')
    );
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="subjects.csv"');
    res.send([header, ...lines].join('\n'));
  });
});

app.post('/admin/import/subjects.csv', requireAdmin, writeLimiter, csvUpload.single('csv_file'), async (req, res) => {
  if (!req.file || !req.file.buffer) {
    return res.redirect('/admin?err=Missing%20CSV');
  }
  const courseId = getAdminCourse(req);
  let rows = [];
  try {
    const text = req.file.buffer.toString('utf8');
    rows = parseCsvText(text);
  } catch (err) {
    return res.redirect('/admin?err=Invalid%20CSV');
  }
  if (!rows.length) {
    return res.redirect('/admin?err=Empty%20CSV');
  }
  let inserted = 0;
  let updated = 0;
  let skipped = 0;
  for (const row of rows) {
    const name = String(row.name || '').trim();
    const groupCount = row.group_count ? Number(row.group_count) : 1;
    const defaultGroup = row.default_group ? Number(row.default_group) : 1;
    const isRequired = String(row.is_required ?? '1');
    const isGeneral = String(row.is_general ?? '1');
    const requiredFlag = ['0', 'false', 'no', 'off'].includes(isRequired.toLowerCase()) ? 0 : 1;
    const generalFlag = ['0', 'false', 'no', 'off'].includes(isGeneral.toLowerCase()) ? 0 : 1;
    if (!name || Number.isNaN(groupCount) || groupCount < 1 || groupCount > 3 || Number.isNaN(defaultGroup) || defaultGroup < 1 || defaultGroup > groupCount) {
      skipped += 1;
      continue;
    }
    const existing = await db.get('SELECT id FROM subjects WHERE name = ?', [name]);
    if (existing && existing.id) {
      await db.run(
        'UPDATE subjects SET group_count = ?, default_group = ?, is_required = ?, is_general = ?, course_id = ? WHERE id = ?',
        [groupCount, defaultGroup, requiredFlag, generalFlag, courseId, existing.id]
      );
      updated += 1;
    } else {
      await db.run(
        'INSERT INTO subjects (name, group_count, default_group, show_in_teamwork, visible, is_required, is_general, course_id) VALUES (?, ?, ?, 1, 1, ?, ?, ?)',
        [name, groupCount, defaultGroup, requiredFlag, generalFlag, courseId]
      );
      inserted += 1;
    }
  }
  invalidateSubjectsCache(courseId);
  logAction(db, req, 'subjects_import_csv', { inserted, updated, skipped, course_id: courseId });
  return res.redirect(`/admin?ok=Subjects%20imported%20(${inserted}%2F${updated}%2F${skipped})`);
});

app.get('/admin/history.csv', requireAdmin, (req, res) => {
  const { history_actor, history_action, history_q, history_from, history_to } = req.query;
  const filters = [];
  const params = [];
  if (history_actor) {
    filters.push('actor_name LIKE ?');
    params.push(`%${history_actor}%`);
  }
  if (history_action) {
    filters.push('action LIKE ?');
    params.push(`%${history_action}%`);
  }
  if (history_q) {
    filters.push('details LIKE ?');
    params.push(`%${history_q}%`);
  }
  if (history_from) {
    filters.push('created_at >= ?');
    params.push(new Date(history_from).toISOString());
  }
  if (history_to) {
    const end = new Date(history_to);
    end.setHours(23, 59, 59, 999);
    filters.push('created_at <= ?');
    params.push(end.toISOString());
  }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  db.all(`SELECT * FROM history_log ${where} ORDER BY created_at DESC`, params, (err, rows) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    const header = 'id,actor_name,action,details,created_at';
    const lines = rows.map((r) =>
      [r.id, r.actor_name, r.action, r.details, r.created_at]
        .map((v) => `"${String(v ?? '').replace(/\"/g, '""')}"`)
        .join(',')
    );
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="history.csv"');
    res.send([header, ...lines].join('\n'));
  });
});

app.get('/admin/history.json', requireAdmin, (req, res) => {
  const { history_actor, history_action, history_q, history_from, history_to } = req.query;
  const filters = [];
  const params = [];
  if (history_actor) {
    filters.push('actor_name LIKE ?');
    params.push(`%${history_actor}%`);
  }
  if (history_action) {
    filters.push('action LIKE ?');
    params.push(`%${history_action}%`);
  }
  if (history_q) {
    filters.push('details LIKE ?');
    params.push(`%${history_q}%`);
  }
  if (history_from) {
    filters.push('created_at >= ?');
    params.push(new Date(history_from).toISOString());
  }
  if (history_to) {
    const end = new Date(history_to);
    end.setHours(23, 59, 59, 999);
    filters.push('created_at <= ?');
    params.push(end.toISOString());
  }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  db.all(`SELECT * FROM history_log ${where} ORDER BY created_at DESC LIMIT 500`, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ logs: rows });
  });
});

app.get('/admin/user-logins.json', requireAdmin, (req, res) => {
  const { user_id } = req.query;
  if (!user_id) {
    return res.status(400).json({ error: 'Missing user_id' });
  }
  db.all(
    'SELECT id, ip, user_agent, created_at FROM login_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
    [user_id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ logins: rows });
    }
  );
});

app.post('/homework/add', requireLogin, uploadLimiter, upload.single('attachment'), async (req, res) => {
  const {
    description,
    link_url,
    meeting_url,
    tags,
    is_control,
    subject_id,
    group_number,
    day_of_week,
    class_number,
    class_date,
    time,
  } = req.body;
  const filePath = req.file ? `/uploads/${req.file.filename}` : null;
  const fileName = req.file ? req.file.originalname : null;
  const classNum = Number(class_number);
  const groupNum = Number(group_number);
  const subjectId = Number(subject_id);
  const isControl = String(is_control || '').toLowerCase() === '1' ? 1 : 0;
  const sessionCourseId = req.session.user?.course_id || 1;
  const inputCourseId = Number(req.body.course_id);
  const isTeacher = req.session.role === 'teacher';
  const courseId = isTeacher && !Number.isNaN(inputCourseId) ? inputCourseId : sessionCourseId;

  if (
    !description ||
    !day_of_week ||
    !class_date ||
    Number.isNaN(classNum) ||
    Number.isNaN(groupNum) ||
    Number.isNaN(subjectId)
  ) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(400).send('Missing fields');
  }
  const dayAllowed = await isCourseDayActive(courseId, day_of_week);
  if (!dayAllowed || classNum < 1 || classNum > 7) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(400).send('Invalid data');
  }

  const { schedule_group: group, username, id: userId } = req.session.user;
  const createdAt = new Date().toISOString();
  const activeSemester = await getActiveSemester(courseId || 1);
  const isStaff = ['admin', 'deanery', 'starosta', 'teacher'].includes(req.session.role);
  let homeworkStatus = isStaff ? String(req.body.status || 'published').toLowerCase() : 'published';
  if (!['draft', 'scheduled', 'published'].includes(homeworkStatus)) {
    homeworkStatus = 'published';
  }
  let scheduledAt = null;
  let publishedAt = createdAt;
  if (homeworkStatus === 'scheduled') {
    const parsed = req.body.scheduled_at ? new Date(req.body.scheduled_at) : null;
    if (!parsed || Number.isNaN(parsed.getTime())) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Schedule date required');
    }
    scheduledAt = parsed.toISOString();
    publishedAt = null;
  }
  if (homeworkStatus === 'draft') {
    publishedAt = null;
  }
  if (!settingsCache.allow_homework_creation && req.session.role !== 'admin') {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(403).send('Homework disabled');
  }

  try {
    const subjectRow = await db.get(
      'SELECT name, course_id, group_count, is_general FROM subjects WHERE id = ?',
      [subjectId]
    );
    if (!subjectRow || (subjectRow.course_id && subjectRow.course_id !== (courseId || 1))) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Invalid subject');
    }
    const maxGroups = Number(subjectRow.group_count || 1);
    let targetGroups = [];
    if (isTeacher) {
      const teacherRow = await db.get(
        'SELECT group_number FROM teacher_subjects WHERE user_id = ? AND subject_id = ?',
        [userId, subjectId]
      );
      if (!teacherRow) {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(400).send('Invalid subject');
      }
      const isGeneral = subjectRow.is_general === true || Number(subjectRow.is_general) === 1;
      if (isGeneral) {
        targetGroups = Array.from({ length: maxGroups }, (_, idx) => idx + 1);
      } else {
        const resolvedGroup = teacherRow.group_number !== null ? Number(teacherRow.group_number) : groupNum;
        if (!resolvedGroup || Number.isNaN(resolvedGroup)) {
          if (req.file) {
            fs.unlink(req.file.path, () => {});
          }
          return res.status(400).send('Invalid group');
        }
        if (teacherRow.group_number !== null && Number(teacherRow.group_number) !== groupNum) {
          if (req.file) {
            fs.unlink(req.file.path, () => {});
          }
          return res.status(400).send('Invalid group');
        }
        targetGroups = [Number(resolvedGroup)];
      }
    } else {
      targetGroups = [groupNum];
    }
    if (targetGroups.some((g) => Number.isNaN(g) || g < 1 || g > maxGroups)) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Invalid group');
    }

    const createdIds = [];
    for (const targetGroup of targetGroups) {
      const row = await db.get(
        `
          INSERT INTO homework
          (group_name, subject, day, time, class_number, subject_id, group_number, day_of_week, created_by_id, description, class_date, meeting_url, link_url, file_path, file_name, created_by, created_at, course_id, semester_id, status, scheduled_at, published_at, is_control)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          RETURNING id
        `,
        [
          group,
          subjectRow.name,
          day_of_week,
          time,
          classNum,
          subjectId,
          targetGroup,
          day_of_week,
          userId,
          description,
          class_date,
          meeting_url || null,
          link_url || null,
          filePath,
          fileName,
          username,
          createdAt,
          courseId || 1,
          activeSemester ? activeSemester.id : null,
          homeworkStatus,
          scheduledAt,
          publishedAt,
          isControl,
        ]
      );
      if (!row || !row.id) {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(500).send('Database error');
      }
      createdIds.push(row.id);
    }

    const tagList = String(tags || '')
      .split(',')
      .map((t) => t.trim())
      .filter((t) => t.length);
    for (const tag of tagList) {
      const tagRow = await db.get(
        'INSERT INTO homework_tags (name) VALUES (?) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id',
        [tag]
      );
      if (tagRow && tagRow.id && createdIds.length) {
        for (const hwId of createdIds) {
          await db.run(
            'INSERT INTO homework_tag_map (homework_id, tag_id) VALUES (?, ?) ON CONFLICT DO NOTHING',
            [hwId, tagRow.id]
          );
        }
      }
    }

    const logGroup = targetGroups.length === 1 ? targetGroups[0] : null;
    logActivity(
      db,
      req,
      'homework_create',
      'homework',
      createdIds[0] || null,
      {
        subject_id: subjectId,
        group_number: logGroup,
        day_of_week,
        class_number: classNum,
        tags: tagList,
        is_control: isControl,
      },
      courseId || 1,
      activeSemester ? activeSemester.id : null
    );
    return res.redirect('/schedule');
  } catch (err) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(500).send('Database error');
  }
});

app.post('/homework/custom', requireLogin, uploadLimiter, upload.single('attachment'), async (req, res) => {
  if (!settingsCache.allow_custom_deadlines && req.session.role !== 'admin') {
    return res.status(403).send('Custom deadlines disabled');
  }
  const { description, link_url, meeting_url, subject_id, custom_due_date } = req.body;
  const filePath = req.file ? `/uploads/${req.file.filename}` : null;
  const fileName = req.file ? req.file.originalname : null;
  const subjectId = Number(subject_id);
  const groupInput = req.body.group_number ? Number(req.body.group_number) : null;
  const dueDate = String(custom_due_date || '').slice(0, 10);
  if (!description || Number.isNaN(subjectId) || !dueDate) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(400).send('Missing fields');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(400).send('Invalid date');
  }

  const { schedule_group: group, username, id: userId } = req.session.user;
  const sessionCourseId = req.session.user.course_id || 1;
  const isTeacher = req.session.role === 'teacher';
  const courseId = isTeacher && !Number.isNaN(Number(req.body.course_id)) ? Number(req.body.course_id) : sessionCourseId;
  const createdAt = new Date().toISOString();
  const activeSemester = await getActiveSemester(courseId || 1);
  const isStaff = ['admin', 'deanery', 'starosta', 'teacher'].includes(req.session.role);
  let homeworkStatus = isStaff ? String(req.body.status || 'published').toLowerCase() : 'published';
  if (!['draft', 'scheduled', 'published'].includes(homeworkStatus)) {
    homeworkStatus = 'published';
  }
  let scheduledAt = null;
  let publishedAt = createdAt;
  if (homeworkStatus === 'scheduled') {
    const parsed = req.body.scheduled_at ? new Date(req.body.scheduled_at) : null;
    if (!parsed || Number.isNaN(parsed.getTime())) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Schedule date required');
    }
    scheduledAt = parsed.toISOString();
    publishedAt = null;
  }
  if (homeworkStatus === 'draft') {
    publishedAt = null;
  }
  if (!settingsCache.allow_homework_creation && req.session.role !== 'admin') {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(403).send('Homework disabled');
  }

  try {
    const subjectRow = await db.get('SELECT name, course_id, group_count, is_general FROM subjects WHERE id = ?', [subjectId]);
    if (!subjectRow || (subjectRow.course_id && subjectRow.course_id !== (courseId || 1))) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Invalid subject');
    }
    let targetGroups = [];
    if (isTeacher) {
      const teacherRow = await db.get(
        'SELECT group_number FROM teacher_subjects WHERE user_id = ? AND subject_id = ?',
        [userId, subjectId]
      );
      if (!teacherRow) {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(400).send('Invalid subject');
      }
      const resolvedGroup = groupInput && !Number.isNaN(groupInput) ? groupInput : teacherRow.group_number;
      if (resolvedGroup && teacherRow.group_number !== null && Number(teacherRow.group_number) !== Number(resolvedGroup)) {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(400).send('Invalid group');
      }
      if (resolvedGroup && !Number.isNaN(resolvedGroup)) {
        targetGroups = [Number(resolvedGroup)];
      } else if (subjectRow.is_general === true || Number(subjectRow.is_general) === 1) {
        const maxGroups = Number(subjectRow.group_count || 1);
        targetGroups = Array.from({ length: maxGroups }, (_, idx) => idx + 1);
      } else {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(400).send('Select group');
      }
    } else {
      const groupRow = await db.get(
        'SELECT group_number FROM student_groups WHERE student_id = ? AND subject_id = ?',
        [userId, subjectId]
      );
      if (!groupRow) {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(400).send('Invalid group');
      }
      targetGroups = [groupRow.group_number];
    }
    const maxGroups = Number(subjectRow.group_count || 1);
    if (targetGroups.some((g) => Number.isNaN(g) || g < 1 || g > maxGroups)) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Invalid group');
    }
    const dayName = getDayNameFromDate(dueDate);
    let createdId = null;
    for (const targetGroup of targetGroups) {
      const row = await db.get(
        `
          INSERT INTO homework
          (group_name, subject, day, time, class_number, subject_id, group_number, day_of_week, created_by_id, description, class_date, meeting_url, link_url, file_path, file_name, created_by, created_at, course_id, semester_id, is_custom_deadline, custom_due_date, status, scheduled_at, published_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          RETURNING id
        `,
        [
          group,
          subjectRow.name,
          dayName || 'Deadline',
          'Deadline',
          null,
          subjectId,
          targetGroup,
          dayName,
          userId,
          description,
          null,
          meeting_url || null,
          link_url || null,
          filePath,
          fileName,
          username,
          createdAt,
          courseId || 1,
          activeSemester ? activeSemester.id : null,
          1,
          dueDate,
          homeworkStatus,
          scheduledAt,
          publishedAt,
        ]
      );
      if (!row || !row.id) {
        if (req.file) {
          fs.unlink(req.file.path, () => {});
        }
        return res.status(500).send('Database error');
      }
      createdId = row.id;
    }
    logActivity(
      db,
      req,
      'homework_create',
      'homework',
      createdId,
      { subject_id: subjectId, custom_due_date: dueDate, is_custom_deadline: true },
      courseId || 1,
      activeSemester ? activeSemester.id : null
    );
    return res.redirect('/schedule');
  } catch (err) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(500).send('Database error');
  }
});

app.post('/subgroup/create', requireLogin, async (req, res) => {
  const { homework_id, name } = req.body;
  const { username } = req.session.user;

  if (!homework_id || !name) {
    return res.status(400).send('Missing fields');
  }

  try {
    const existing = await db.get(
      `
        SELECT sm.id
        FROM subgroup_members sm
        JOIN subgroups s ON s.id = sm.subgroup_id
        WHERE s.homework_id = ? AND sm.member_username = ?
        LIMIT 1
      `,
      [homework_id, username]
    );
    if (existing) {
      return res.redirect('/schedule?sg=exists');
    }
    const createdAt = new Date().toISOString();
    const row = await db.get(
      'INSERT INTO subgroups (homework_id, name, created_at) VALUES (?, ?, ?) RETURNING id',
      [homework_id, name, createdAt]
    );
    if (!row || !row.id) {
      return res.status(500).send('Database error');
    }
    await db.run(
      'INSERT INTO subgroup_members (subgroup_id, member_username, joined_at) VALUES (?, ?, ?) ON CONFLICT(subgroup_id, member_username) DO NOTHING',
      [row.id, username, createdAt]
    );
    return res.redirect('/schedule');
  } catch (err) {
    return res.status(500).send('Database error');
  }
});

app.get('/starosta', requireStaff, async (req, res) => {
  try {
    await ensureDbReady();
  } catch (err) {
    return handleDbError(res, err, 'starosta.init');
  }

  const courseId = req.session.user.course_id || 1;
  const {
    group_number,
    subject,
    q,
    sort_homework,
    homework_from,
    homework_to,
    homework_tag,
  } = req.query;
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return handleDbError(res, err, 'starosta.activeSemester');
  }
  db.all('SELECT id, name FROM courses WHERE id = ?', [courseId], (courseErr, courses) => {
    if (courseErr) {
      return handleDbError(res, courseErr, 'starosta.courses');
    }
    db.all(
      'SELECT * FROM semesters WHERE course_id = ? ORDER BY start_date DESC',
      [courseId],
      (semErr, semesters) => {
        if (semErr) {
          return handleDbError(res, semErr, 'starosta.semesters');
        }
    db.all(
      'SELECT id, full_name, role, schedule_group, is_active, last_login_ip, last_user_agent, last_login_at, course_id FROM users WHERE course_id = ? ORDER BY full_name',
      [courseId],
      (userErr, users) => {
        if (userErr) {
          return handleDbError(res, userErr, 'starosta.users');
        }
        db.all('SELECT * FROM subjects WHERE course_id = ? ORDER BY name', [courseId], (subjectErr, subjects) => {
          if (subjectErr) {
            return handleDbError(res, subjectErr, 'starosta.subjects');
          }
          const homeworkFilters = [];
          const homeworkParams = [];
          homeworkFilters.push('h.course_id = ?');
          homeworkParams.push(courseId);
          if (activeSemester) {
            homeworkFilters.push('h.semester_id = ?');
            homeworkParams.push(activeSemester.id);
          }
          if (group_number) {
            homeworkFilters.push('h.group_number = ?');
            homeworkParams.push(group_number);
          }
          if (subject) {
            homeworkFilters.push('h.subject LIKE ?');
            homeworkParams.push(`%${subject}%`);
          }
          if (q) {
            homeworkFilters.push('(h.description LIKE ? OR h.created_by LIKE ?)');
            homeworkParams.push(`%${q}%`, `%${q}%`);
          }
          if (homework_from) {
            const start = new Date(homework_from);
            if (!Number.isNaN(start.getTime())) {
              start.setHours(0, 0, 0, 0);
              homeworkFilters.push('h.created_at >= ?');
              homeworkParams.push(start.toISOString());
            }
          }
          if (homework_to) {
            const end = new Date(homework_to);
            if (!Number.isNaN(end.getTime())) {
              end.setHours(23, 59, 59, 999);
              homeworkFilters.push('h.created_at <= ?');
              homeworkParams.push(end.toISOString());
            }
          }
          if (homework_tag) {
            homeworkFilters.push(
              `EXISTS (
                SELECT 1
                FROM homework_tag_map ht
                JOIN homework_tags t ON t.id = ht.tag_id
                WHERE ht.homework_id = h.id AND t.name = ?
              )`
            );
            homeworkParams.push(homework_tag);
          }
          const homeworkWhere = homeworkFilters.length ? `WHERE ${homeworkFilters.join(' AND ')}` : '';
          const homeworkSql = `
            SELECT h.*, subj.name AS subject_name,
                   COALESCE(taglist.tags, ARRAY[]::text[]) AS tags
            FROM homework h
            JOIN subjects subj ON subj.id = h.subject_id
            LEFT JOIN LATERAL (
              SELECT array_agg(t.name ORDER BY t.name) AS tags
              FROM homework_tag_map ht
              JOIN homework_tags t ON t.id = ht.tag_id
              WHERE ht.homework_id = h.id
            ) taglist ON true
            ${homeworkWhere}
            ORDER BY h.created_at DESC
          `;
          db.all(homeworkSql, homeworkParams, (homeworkErr, homeworkRows) => {
            if (homeworkErr) {
              return handleDbError(res, homeworkErr, 'starosta.homework');
            }
            const homework = sortHomework(homeworkRows, sort_homework);
            db.all('SELECT name FROM homework_tags ORDER BY name', (tagErr, tagRows) => {
              if (tagErr) {
                return handleDbError(res, tagErr, 'starosta.homework.tags');
              }
              const homeworkTags = (tagRows || []).map((row) => row.name);
          db.all(
            `
              SELECT t.id, t.title, t.created_at, s.name AS subject_name,
                     COUNT(DISTINCT g.id) AS group_count,
                     COUNT(DISTINCT m.user_id) AS member_count
              FROM teamwork_tasks t
              JOIN subjects s ON s.id = t.subject_id
              LEFT JOIN teamwork_groups g ON g.task_id = t.id
              LEFT JOIN teamwork_members m ON m.task_id = t.id
              WHERE t.course_id = ?${activeSemester ? ' AND t.semester_id = ?' : ''}
              GROUP BY t.id, t.title, t.created_at, s.name
              ORDER BY t.created_at DESC
            `,
            activeSemester ? [courseId, activeSemester.id] : [courseId],
            (taskErr, teamworkTasks) => {
              if (taskErr) {
                return handleDbError(res, taskErr, 'starosta.teamwork');
              }
              db.all(
                `
                  SELECT m.*, s.name AS subject_name, u.full_name AS created_by,
                         COALESCE(reads.read_count, 0) AS read_count,
                         COALESCE(targets.target_count, 0) AS target_count
                  FROM messages m
                  LEFT JOIN subjects s ON s.id = m.subject_id
                  LEFT JOIN users u ON u.id = m.created_by_id
                  LEFT JOIN LATERAL (
                    SELECT COUNT(*) AS read_count
                    FROM message_reads mr
                    WHERE mr.message_id = m.id
                  ) reads ON true
                  LEFT JOIN LATERAL (
                    SELECT CASE
                      WHEN m.target_all = 1 THEN (
                        SELECT COUNT(*)
                        FROM users u2
                        WHERE u2.course_id = ? AND u2.role = 'student' AND u2.is_active = 1
                      )
                      WHEN m.subject_id IS NOT NULL THEN (
                        SELECT COUNT(DISTINCT sg.student_id)
                        FROM student_groups sg
                        JOIN users u3 ON u3.id = sg.student_id
                        WHERE sg.subject_id = m.subject_id AND sg.group_number = m.group_number
                          AND u3.course_id = ? AND u3.is_active = 1
                      )
                      ELSE (
                        SELECT COUNT(*)
                        FROM message_targets mt
                        JOIN users u4 ON u4.id = mt.user_id
                        WHERE mt.message_id = m.id AND u4.course_id = ? AND u4.is_active = 1
                      )
                    END AS target_count
                  ) targets ON true
                  WHERE m.course_id = ?${activeSemester ? ' AND m.semester_id = ?' : ''}
                  ORDER BY m.created_at DESC
                  LIMIT 200
                `,
                activeSemester
                  ? [courseId, courseId, courseId, courseId, activeSemester.id]
                  : [courseId, courseId, courseId, courseId],
                (msgErr, messages) => {
                  if (msgErr) {
                    return handleDbError(res, msgErr, 'starosta.messages');
                  }
                  try {
                    return res.render('admin', {
                      username: req.session.user.username,
                      userId: req.session.user.id,
                      role: req.session.role,
                      schedule: [],
                      homework,
                      homeworkTags,
                      users,
                      subjects,
                      studentGroups: [],
                      logs: [],
                      teamworkTasks,
                      adminMessages: messages,
                      courses,
                      semesters,
                      activeSemester,
                      selectedCourseId: courseId,
                      limitedStaffView: true,
                      allowedSections: ['admin-homework', 'admin-teamwork', 'admin-messages', 'admin-overview'],
                      filters: {
                        group_number: group_number || '',
                        day: '',
                        subject: subject || '',
                        q: q || '',
                        homework_from: homework_from || '',
                        homework_to: homework_to || '',
                        homework_tag: homework_tag || '',
                      },
                      usersStatus: 'active',
                      sorts: {
                        schedule: '',
                        homework: sort_homework || '',
                      },
                    });
                  } catch (renderErr) {
                    return handleDbError(res, renderErr, 'starosta.render');
                  }
                }
              );
            }
          );
            });
          });
        });
      }
    );
      }
    );
  });
});

app.get('/deanery', requireDeanery, (req, res) => {
  (async () => {
    try {
      await ensureDbReady();
    } catch (err) {
      return handleDbError(res, err, 'deanery.init');
    }
    const courseId = Number(req.query.course || req.session.user.course_id || 1);
    const { group_number, day, subject, sort_schedule, schedule_date } = req.query;
    let activeSemester = null;
    try {
      activeSemester = await getActiveSemester(courseId);
    } catch (err) {
      return handleDbError(res, err, 'deanery.activeSemester');
    }
    const scheduleFilters = [];
    const scheduleParams = [];
    scheduleFilters.push('se.course_id = ?');
    scheduleParams.push(courseId);
    if (activeSemester) {
      scheduleFilters.push('se.semester_id = ?');
      scheduleParams.push(activeSemester.id);
    }
    if (group_number) {
      scheduleFilters.push('se.group_number = ?');
      scheduleParams.push(group_number);
    }
    if (day) {
      scheduleFilters.push('se.day_of_week = ?');
      scheduleParams.push(day);
    }
    if (subject) {
      scheduleFilters.push('s.name LIKE ?');
      scheduleParams.push(`%${subject}%`);
    }
    if (schedule_date && activeSemester && activeSemester.start_date) {
      const mapped = getWeekDayForDate(schedule_date, activeSemester.start_date);
      if (mapped) {
        scheduleFilters.push('se.week_number = ?');
        scheduleParams.push(mapped.weekNumber);
        scheduleFilters.push('se.day_of_week = ?');
        scheduleParams.push(mapped.dayName);
      }
    }
    const scheduleWhere = scheduleFilters.length ? `WHERE ${scheduleFilters.join(' AND ')}` : '';
    const scheduleSql = `
      SELECT se.*, s.name AS subject_name
      FROM schedule_entries se
      JOIN subjects s ON s.id = se.subject_id
      ${scheduleWhere}
      ORDER BY se.week_number, se.day_of_week, se.class_number
    `;
    db.all('SELECT id, name FROM courses ORDER BY id', [], (courseErr, courses) => {
      if (courseErr) {
        return handleDbError(res, courseErr, 'deanery.courses');
      }
      db.all(
        'SELECT * FROM semesters WHERE course_id = ? ORDER BY start_date DESC',
        [courseId],
        (semErr, semesters) => {
          if (semErr) {
            return handleDbError(res, semErr, 'deanery.semesters');
          }
          db.all('SELECT * FROM subjects WHERE course_id = ? ORDER BY name', [courseId], (subjectErr, subjects) => {
            if (subjectErr) {
              return handleDbError(res, subjectErr, 'deanery.subjects');
            }
            db.all(scheduleSql, scheduleParams, (scheduleErr, scheduleRows) => {
              if (scheduleErr) {
                return handleDbError(res, scheduleErr, 'deanery.schedule');
              }
              const schedule = sortSchedule(scheduleRows, sort_schedule);
              try {
                return res.render('admin', {
                  username: req.session.user.username,
                  userId: req.session.user.id,
                  role: req.session.role,
                  schedule,
                  homework: [],
                  users: [],
                  subjects,
                  studentGroups: [],
                  logs: [],
                  teamworkTasks: [],
                  adminMessages: [],
                  courses,
                  semesters,
                  activeSemester,
                  selectedCourseId: courseId,
                  limitedStaffView: true,
                  allowedSections: ['admin-schedule', 'admin-subjects', 'admin-semesters', 'admin-courses', 'admin-overview'],
                  filters: {
                    group_number: group_number || '',
                    day: day || '',
                    subject: subject || '',
                    schedule_date: schedule_date || '',
                  },
                  usersStatus: 'active',
                  sorts: {
                    schedule: sort_schedule || '',
                    homework: '',
                  },
                });
              } catch (renderErr) {
                return handleDbError(res, renderErr, 'deanery.render');
              }
            });
          });
        }
      );
    });
  })();
});

app.post('/subgroup/join', requireLogin, (req, res) => {
  const { subgroup_id } = req.body;
  const { username } = req.session.user;

  if (!subgroup_id) {
    return res.status(400).send('Missing fields');
  }

  db.get(
    `
      SELECT s.homework_id
      FROM subgroups s
      WHERE s.id = ?
      LIMIT 1
    `,
    [subgroup_id],
    (homeErr, row) => {
      if (homeErr || !row) {
        return res.status(500).send('Database error');
      }
      db.get(
        `
          SELECT sm.id
          FROM subgroup_members sm
          JOIN subgroups s ON s.id = sm.subgroup_id
          WHERE s.homework_id = ? AND sm.member_username = ?
          LIMIT 1
        `,
        [row.homework_id, username],
        (existingErr, existing) => {
          if (existingErr) {
            return res.status(500).send('Database error');
          }
          if (existing) {
            return res.redirect('/schedule?sg=exists');
          }
          const joinedAt = new Date().toISOString();
          db.run(
            'INSERT INTO subgroup_members (subgroup_id, member_username, joined_at) VALUES (?, ?, ?) ON CONFLICT(subgroup_id, member_username) DO NOTHING',
            [subgroup_id, username, joinedAt],
            (err) => {
              if (err) {
                return res.status(500).send('Database error');
              }
              return res.redirect('/schedule');
            }
          );
        }
      );
    }
  );
});

app.post('/admin/schedule/add', requireAdmin, async (req, res) => {
  const { subject_id, group_number, day_of_week, class_number, week_numbers, semester_id } = req.body;
  const groupNum = Number(group_number);
  const classNum = Number(class_number);
  const courseId = getAdminCourse(req);
  const semesterId = Number(semester_id);

  if (!subject_id || !day_of_week || !week_numbers || Number.isNaN(groupNum) || Number.isNaN(classNum) || Number.isNaN(semesterId)) {
    return res.redirect('/admin?err=Missing%20fields');
  }
  const dayAllowed = await isCourseDayActive(courseId, day_of_week);
  if (!dayAllowed) {
    return res.redirect('/admin?err=Invalid%20day');
  }
  if (classNum < 1 || classNum > 7) {
    return res.redirect('/admin?err=Invalid%20class%20number');
  }
  try {
    const semRow = await db.get('SELECT weeks_count FROM semesters WHERE id = ? AND course_id = ?', [semesterId, courseId]);
    if (!semRow) {
      return res.redirect('/admin?err=Invalid%20semester');
    }
    const maxWeeks = Number(semRow.weeks_count) || 15;
    const weeks = week_numbers
      .split(',')
      .map((w) => Number(w.trim()))
      .filter((w) => !Number.isNaN(w) && w >= 1 && w <= maxWeeks);
    const uniqueWeeks = Array.from(new Set(weeks));
    if (!uniqueWeeks.length) {
      return res.redirect('/admin?err=Invalid%20weeks');
    }

    const stmt = db.prepare(
      'INSERT INTO schedule_entries (subject_id, group_number, day_of_week, class_number, week_number, course_id, semester_id) VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    uniqueWeeks.forEach((week) => {
      stmt.run(subject_id, groupNum, day_of_week, classNum, week, courseId, semesterId);
    });
    stmt.finalize((err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'schedule_add', {
        subject_id,
        group_number: groupNum,
        day_of_week,
        class_number: classNum,
        weeks: uniqueWeeks,
        semester_id: semesterId,
      });
      logActivity(db, req, 'schedule_add', 'schedule', null, {
        subject_id,
        group_number: groupNum,
        day_of_week,
        class_number: classNum,
        weeks: uniqueWeeks,
        semester_id: semesterId,
      });
      return res.redirect('/admin?ok=Class%20added');
    });
  } catch (err) {
    console.error('Failed to add schedule entry', err);
    return res.redirect('/admin?err=Database%20error');
  }
});

app.post('/admin/schedule/edit/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { subject_id, group_number, day_of_week, class_number, week_number, semester_id } = req.body;
  const groupNum = Number(group_number);
  const classNum = Number(class_number);
  const weekNum = Number(week_number);
  const courseId = getAdminCourse(req);
  const semesterId = Number(semester_id);

  if (!subject_id || !day_of_week || Number.isNaN(groupNum) || Number.isNaN(classNum) || Number.isNaN(weekNum) || Number.isNaN(semesterId)) {
    return res.redirect('/admin?err=Missing%20fields');
  }
  const dayAllowed = await isCourseDayActive(courseId, day_of_week);
  if (!dayAllowed) {
    return res.redirect('/admin?err=Invalid%20day');
  }
  if (classNum < 1 || classNum > 7) {
    return res.redirect('/admin?err=Invalid%20class%20or%20week');
  }
  try {
    const semRow = await db.get('SELECT weeks_count FROM semesters WHERE id = ? AND course_id = ?', [semesterId, courseId]);
    if (!semRow) {
      return res.redirect('/admin?err=Invalid%20semester');
    }
    const maxWeeks = Number(semRow.weeks_count) || 15;
    if (weekNum < 1 || weekNum > maxWeeks) {
      return res.redirect('/admin?err=Invalid%20class%20or%20week');
    }
    db.run(
      `
        UPDATE schedule_entries
        SET subject_id = ?, group_number = ?, day_of_week = ?, class_number = ?, week_number = ?, semester_id = ?
        WHERE id = ? AND course_id = ?
      `,
      [subject_id, groupNum, day_of_week, classNum, weekNum, semesterId, id, courseId],
      (err) => {
        if (err) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'schedule_edit', { id, subject_id, group_number: groupNum, day_of_week, class_number: classNum, week_number: weekNum, semester_id: semesterId });
        logActivity(db, req, 'schedule_edit', 'schedule', Number(id) || null, {
          subject_id,
          group_number: groupNum,
          day_of_week,
          class_number: classNum,
          week_number: weekNum,
          semester_id: semesterId,
        });
        return res.redirect('/admin?ok=Class%20updated');
      }
    );
  } catch (err) {
    console.error('Failed to update schedule entry', err);
    return res.redirect('/admin?err=Database%20error');
  }
});

app.post('/admin/schedule/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = getAdminCourse(req);
  const referer = req.get('referer');
  const redirectBase = referer && referer.includes('/admin/schedule-list') ? referer : '/admin';
  const withStatus = (base, status) => (base.includes('?') ? `${base}&${status}` : `${base}?${status}`);
  db.run('DELETE FROM schedule_entries WHERE id = ? AND course_id = ?', [id, courseId], (err) => {
    if (err) {
      return res.redirect(withStatus(redirectBase, 'err=Database%20error'));
    }
    logActivity(db, req, 'schedule_delete', 'schedule', Number(id) || null, null, courseId);
    logAction(db, req, 'schedule_delete', { id });
    return res.redirect(withStatus(redirectBase, 'ok=Class%20deleted'));
  });
});

app.post('/admin/schedule/delete-multiple', requireAdmin, (req, res) => {
  const ids = req.body.delete_ids;
  const returnTo = req.body.return_to || req.query.return_to || '';
  const referer = req.get('referer');
  const fallback = '/admin';
  const redirectBase =
    (returnTo && returnTo.startsWith('/admin/schedule-list') ? returnTo : null) ||
    (referer && referer.includes('/admin/schedule-list') ? referer : null) ||
    fallback;
  const withStatus = (base, status) => (base.includes('?') ? `${base}&${status}` : `${base}?${status}`);
  if (!ids) {
    return res.redirect(withStatus(redirectBase, 'err=No%20items%20selected'));
  }
  const list = Array.isArray(ids) ? ids : [ids];
  const placeholders = list.map(() => '?').join(',');
  const courseId = getAdminCourse(req);
  db.run(`DELETE FROM schedule_entries WHERE course_id = ? AND id IN (${placeholders})`, [courseId, ...list], (err) => {
    if (err) {
      return res.redirect(withStatus(redirectBase, 'err=Database%20error'));
    }
    logActivity(db, req, 'schedule_delete_multiple', 'schedule', null, { ids: list }, courseId);
    logAction(db, req, 'schedule_delete_multiple', { ids: list });
    return res.redirect(withStatus(redirectBase, 'ok=Selected%20classes%20deleted'));
  });
});

app.post('/admin/schedule/clear-all', requireAdmin, (req, res) => {
  const courseId = getAdminCourse(req);
  const referer = req.get('referer');
  const redirectBase = referer && referer.includes('/admin/schedule-list') ? referer : '/admin';
  const withStatus = (base, status) => (base.includes('?') ? `${base}&${status}` : `${base}?${status}`);
  db.run('DELETE FROM schedule_entries WHERE course_id = ?', [courseId], (err) => {
    if (err) {
      return res.redirect(withStatus(redirectBase, 'err=Database%20error'));
    }
    logActivity(db, req, 'schedule_clear_all', 'schedule', null, null, courseId);
    logAction(db, req, 'schedule_clear_all');
    return res.redirect(withStatus(redirectBase, 'ok=Schedule%20cleared'));
  });
});

app.post('/admin/homework/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.get('SELECT file_path FROM homework WHERE id = ?', [id], (err, row) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    db.all('SELECT id FROM subgroups WHERE homework_id = ?', [id], (sgErr, subgroups) => {
      if (sgErr) {
        return res.redirect('/admin?err=Database%20error');
      }
      const subgroupIds = subgroups.map((sg) => sg.id);
      const placeholders = subgroupIds.map(() => '?').join(',');
      const deleteMembers = subgroupIds.length
        ? `DELETE FROM subgroup_members WHERE subgroup_id IN (${placeholders})`
        : null;

      const afterMembers = () => {
        const deleteSubgroups = subgroupIds.length
          ? `DELETE FROM subgroups WHERE id IN (${placeholders})`
          : null;
        const afterSubgroups = () => {
          db.run('DELETE FROM homework WHERE id = ?', [id], (delErr) => {
            if (delErr) {
              return res.redirect('/admin?err=Database%20error');
            }
            if (row && row.file_path) {
              const relativePath = row.file_path.replace(/^\/+/, '');
              const absPath = path.join(__dirname, relativePath);
              fs.unlink(absPath, () => {});
            }
            logActivity(db, req, 'homework_delete', 'homework', Number(id) || null, null);
            logAction(db, req, 'homework_delete', { id });
            return res.redirect('/admin?ok=Homework%20deleted');
          });
        };

        if (deleteSubgroups) {
          db.run(deleteSubgroups, subgroupIds, (delSgErr) => {
            if (delSgErr) {
              return res.redirect('/admin?err=Database%20error');
            }
            return afterSubgroups();
          });
        } else {
          return afterSubgroups();
        }
      };

      if (deleteMembers) {
        db.run(deleteMembers, subgroupIds, (delMemErr) => {
          if (delMemErr) {
            return res.redirect('/admin?err=Database%20error');
          }
          return afterMembers();
        });
      } else {
        return afterMembers();
      }
    });
  });
});

app.post('/admin/subjects/add', requireAdmin, (req, res) => {
  const { name, group_count, default_group, show_in_teamwork, visible, is_required, is_general } = req.body;
  const count = Number(group_count);
  const def = Number(default_group);
  const teamworkFlag = String(show_in_teamwork) === '1' ? 1 : 0;
  const visibleFlag = String(visible) === '0' ? 0 : 1;
  const requiredFlag = String(is_required) === '0' ? 0 : 1;
  const generalFlag = String(is_general) === '1' || String(is_general) === 'on' ? 1 : 0;
  const courseId = getAdminCourse(req);
  if (!name || Number.isNaN(count) || count < 1 || count > 3) {
    return res.redirect('/admin?err=Invalid%20subject%20data');
  }
  if (Number.isNaN(def) || def < 1 || def > count) {
    return res.redirect('/admin?err=Invalid%20default%20group');
  }
  db.run(
    'INSERT INTO subjects (name, group_count, default_group, show_in_teamwork, visible, is_required, is_general, course_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [name, count, def, teamworkFlag, visibleFlag, requiredFlag, generalFlag, courseId],
    (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'subject_add', { name, group_count: count, default_group: def, show_in_teamwork: teamworkFlag, visible: visibleFlag, is_required: requiredFlag, is_general: generalFlag });
    logActivity(db, req, 'subject_add', 'subject', null, { name, group_count: count, default_group: def, visible: visibleFlag, is_required: requiredFlag, is_general: generalFlag }, courseId);
    invalidateSubjectsCache(courseId);
    return res.redirect('/admin?ok=Subject%20added');
    }
  );
});

app.post('/admin/subjects/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, group_count, default_group, show_in_teamwork, visible, is_required, is_general } = req.body;
  const count = Number(group_count);
  const def = Number(default_group);
  const teamworkFlag = String(show_in_teamwork) === '1' ? 1 : 0;
  const visibleFlag = String(visible) === '0' ? 0 : 1;
  const requiredFlag = String(is_required) === '0' ? 0 : 1;
  const generalFlag = String(is_general) === '1' || String(is_general) === 'on' ? 1 : 0;
  const courseId = getAdminCourse(req);
  if (!name || Number.isNaN(count) || count < 1 || count > 3) {
    return res.redirect('/admin?err=Invalid%20subject%20data');
  }
  if (Number.isNaN(def) || def < 1 || def > count) {
    return res.redirect('/admin?err=Invalid%20default%20group');
  }
  db.run(
    'UPDATE subjects SET name = ?, group_count = ?, default_group = ?, show_in_teamwork = ?, visible = ?, is_required = ?, is_general = ? WHERE id = ? AND course_id = ?',
    [name, count, def, teamworkFlag, visibleFlag, requiredFlag, generalFlag, id, courseId],
    (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'subject_edit', { id, name, group_count: count, default_group: def, show_in_teamwork: teamworkFlag, visible: visibleFlag, is_required: requiredFlag, is_general: generalFlag });
      logActivity(db, req, 'subject_edit', 'subject', Number(id) || null, { name, group_count: count, default_group: def, visible: visibleFlag, is_required: requiredFlag, is_general: generalFlag }, courseId);
      invalidateSubjectsCache(courseId);
      return res.redirect('/admin?ok=Subject%20updated');
    }
  );
});

app.post('/admin/api/subjects/:subjectId/clone', requireAdminOrDeanery, async (req, res) => {
  const subjectId = Number(req.params.subjectId);
  const { new_name, copy_settings } = req.body || {};
  if (Number.isNaN(subjectId) || !new_name || !new_name.trim()) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const role = req.session.role;
  const courseId = role === 'admin' ? getAdminCourse(req) : (req.session.user.course_id || 1);
  try {
    const subject = await db.get('SELECT * FROM subjects WHERE id = ? AND course_id = ?', [subjectId, courseId]);
    if (!subject) return res.status(404).json({ error: 'Subject not found' });
    const copySettings = copy_settings !== false;
    const row = await db.get(
      `INSERT INTO subjects (name, group_count, default_group, show_in_teamwork, visible, is_general, course_id)
       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
      [
        new_name.trim(),
        copySettings ? subject.group_count : 1,
        copySettings ? subject.default_group : 1,
        copySettings ? subject.show_in_teamwork : 1,
        copySettings ? subject.visible : 1,
        copySettings ? (subject.is_general === false || subject.is_general === 0 ? 0 : 1) : 1,
        courseId,
      ]
    );
    invalidateSubjectsCache(courseId);
    return res.json({ ok: true, id: row?.id });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/admin/api/schedule/weeks/clone', requireAdminOrDeanery, async (req, res) => {
  const { source_week, target_week, mode } = req.body || {};
  const srcWeek = Number(source_week);
  const tgtWeek = Number(target_week);
  if (Number.isNaN(srcWeek) || Number.isNaN(tgtWeek) || srcWeek < 1 || tgtWeek < 1) {
    return res.status(400).json({ error: 'Invalid week' });
  }
  const role = req.session.role;
  const courseId = role === 'admin' ? getAdminCourse(req) : (req.session.user.course_id || 1);
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return res.status(500).json({ error: 'Semester error' });
  }
  try {
    const studyDays = await getCourseStudyDays(courseId);
    const activeDaySet = new Set((studyDays || []).filter((d) => d.is_active).map((d) => d.day_name));
    const rows = await db.all(
      `SELECT * FROM schedule_entries
       WHERE course_id = ? AND semester_id = ? AND week_number = ?`,
      [courseId, activeSemester ? activeSemester.id : null, srcWeek]
    );
    let inserted = 0;
    for (const row of rows) {
      if (activeDaySet.size && !activeDaySet.has(row.day_of_week)) continue;
      const conflict = await db.get(
        `SELECT id FROM schedule_entries
         WHERE course_id = ? AND semester_id = ? AND week_number = ?
           AND day_of_week = ? AND class_number = ? AND group_number = ?`,
        [courseId, activeSemester ? activeSemester.id : null, tgtWeek, row.day_of_week, row.class_number, row.group_number]
      );
      if (conflict && mode !== 'overwrite') {
        continue;
      }
      if (conflict && mode === 'overwrite') {
        await db.run('DELETE FROM schedule_entries WHERE id = ?', [conflict.id]);
      }
      await db.run(
        `INSERT INTO schedule_entries
         (subject_id, group_number, day_of_week, class_number, week_number, course_id, semester_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          row.subject_id,
          row.group_number,
          row.day_of_week,
          row.class_number,
          tgtWeek,
          courseId,
          activeSemester ? activeSemester.id : null,
        ]
      );
      inserted += 1;
    }
    return res.json({ ok: true, inserted });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/admin/api/homework/:homeworkId/clone', requireHomeworkBulkAccess, async (req, res) => {
  const homeworkId = Number(req.params.homeworkId);
  if (Number.isNaN(homeworkId)) return res.status(400).json({ error: 'Invalid homework' });
  const role = req.session.role;
  const courseId = role === 'admin' ? getAdminCourse(req) : (req.session.user.course_id || 1);
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return res.status(500).json({ error: 'Semester error' });
  }
  const { target = {}, copy_attachments = true, copy_links = true } = req.body || {};
  try {
    const hw = await db.get(
      `SELECT * FROM homework WHERE id = ? AND course_id = ? AND semester_id = ?`,
      [homeworkId, courseId, activeSemester ? activeSemester.id : null]
    );
    if (!hw) return res.status(404).json({ error: 'Not found' });
    const createdAt = new Date().toISOString();
    let classDate = null;
    let customDue = null;
    let isCustom = 0;
    let weekNumber = hw.week_number || null;
    let dayOfWeek = hw.day_of_week;
    if (target.week) {
      const w = Number(target.week);
      if (Number.isFinite(w) && w > 0 && dayOfWeek) {
        classDate = getDateForWeekDay(w, dayOfWeek, activeSemester ? activeSemester.start_date : null);
        weekNumber = w;
      }
    } else if (target.class_date) {
      classDate = String(target.class_date).slice(0, 10);
      const mapped = getWeekDayForDate(classDate, activeSemester ? activeSemester.start_date : null);
      if (mapped) {
        weekNumber = mapped.weekNumber;
        dayOfWeek = mapped.dayName;
      }
    } else if (target.deadline) {
      customDue = String(target.deadline).slice(0, 10);
      isCustom = 1;
    }
    const row = await db.get(
      `INSERT INTO homework
       (group_name, subject, day, time, week_number, class_number, subject_id, group_number, day_of_week,
        created_by_id, description, class_date, meeting_url, link_url, file_path, file_name, created_by, created_at,
        course_id, semester_id, is_custom_deadline, custom_due_date, status, scheduled_at, published_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       RETURNING id`,
      [
        hw.group_name,
        hw.subject,
        hw.day,
        hw.time,
        weekNumber,
        hw.class_number,
        hw.subject_id,
        hw.group_number,
        dayOfWeek,
        hw.created_by_id,
        hw.description,
        classDate || hw.class_date,
        copy_links ? hw.meeting_url : null,
        copy_links ? hw.link_url : null,
        copy_attachments ? hw.file_path : null,
        copy_attachments ? hw.file_name : null,
        hw.created_by,
        createdAt,
        courseId,
        activeSemester ? activeSemester.id : null,
        isCustom,
        customDue,
        'published',
        null,
        createdAt,
      ]
    );
    return res.json({ ok: true, id: row?.id });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/admin/subjects/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = getAdminCourse(req);
  db.run('DELETE FROM student_groups WHERE subject_id = ?', [id], (delErr) => {
    if (delErr) {
      return res.redirect('/admin?err=Database%20error');
    }
    db.run('DELETE FROM subjects WHERE id = ? AND course_id = ?', [id, courseId], (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'subject_delete', { id });
      logActivity(db, req, 'subject_delete', 'subject', Number(id) || null, null, courseId);
      invalidateSubjectsCache(courseId);
      return res.redirect('/admin?ok=Subject%20deleted');
    });
  });
});

app.post('/admin/courses/add', requireAdmin, (req, res) => {
  const { id, name, is_teacher_course, location } = req.body;
  const courseId = Number(id);
  const teacherFlag = String(is_teacher_course) === '1' ? 1 : 0;
  const campus = String(location || 'kyiv').toLowerCase() === 'munich' ? 'munich' : 'kyiv';
  if (Number.isNaN(courseId) || courseId < 1 || !name || !name.trim()) {
    return res.redirect('/admin?err=Invalid%20course');
  }
  db.run(
    'INSERT INTO courses (id, name, is_teacher_course, location) VALUES (?, ?, ?, ?)',
    [courseId, name.trim(), teacherFlag, campus],
    (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'course_add', { id: courseId, name: name.trim(), is_teacher_course: teacherFlag, location: campus });
    invalidateCoursesCache();
    return res.redirect('/admin?ok=Course%20created');
    }
  );
});

app.post('/admin/courses/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, is_teacher_course, location } = req.body;
  const courseId = Number(id);
  const teacherFlag = String(is_teacher_course) === '1' ? 1 : 0;
  const campus = String(location || 'kyiv').toLowerCase() === 'munich' ? 'munich' : 'kyiv';
  if (Number.isNaN(courseId) || !name || !name.trim()) {
    return res.redirect('/admin?err=Invalid%20course');
  }
  db.run(
    'UPDATE courses SET name = ?, is_teacher_course = ?, location = ? WHERE id = ?',
    [name.trim(), teacherFlag, campus, courseId],
    (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'course_edit', { id: courseId, name: name.trim(), is_teacher_course: teacherFlag, location: campus });
    invalidateCoursesCache();
    return res.redirect('/admin?ok=Course%20updated');
  });
});

app.post('/admin/courses/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = Number(id);
  if (Number.isNaN(courseId)) {
    return res.redirect('/admin?err=Invalid%20course');
  }
  db.get('SELECT COUNT(*) AS cnt FROM users WHERE course_id = ?', [courseId], (userErr, userRow) => {
    if (userErr) {
      return res.redirect('/admin?err=Database%20error');
    }
    if (Number(userRow.cnt) > 0) {
      return res.redirect('/admin?err=Course%20has%20users');
    }
    db.get('SELECT COUNT(*) AS cnt FROM subjects WHERE course_id = ?', [courseId], (subErr, subRow) => {
      if (subErr) {
        return res.redirect('/admin?err=Database%20error');
      }
      if (Number(subRow.cnt) > 0) {
        return res.redirect('/admin?err=Course%20has%20subjects');
      }
      db.get('SELECT COUNT(*) AS cnt FROM semesters WHERE course_id = ?', [courseId], (semErr, semRow) => {
        if (semErr) {
          return res.redirect('/admin?err=Database%20error');
        }
        if (Number(semRow.cnt) > 0) {
          return res.redirect('/admin?err=Course%20has%20semesters');
        }
        db.run('DELETE FROM courses WHERE id = ?', [courseId], (err) => {
          if (err) {
            return res.redirect('/admin?err=Database%20error');
          }
          logAction(db, req, 'course_delete', { id: courseId });
          invalidateCoursesCache();
          invalidateSubjectsCache(courseId);
          invalidateSemestersCache(courseId);
          invalidateStudyDaysCache(courseId);
          return res.redirect('/admin?ok=Course%20deleted');
        });
      });
    });
  });
});

app.post('/admin/teacher-requests/:userId/approve', requireAdmin, async (req, res) => {
  const userId = Number(req.params.userId);
  if (Number.isNaN(userId)) {
    return res.redirect('/admin?err=Invalid%20user');
  }
  try {
    await ensureDbReady();
    await db.run('UPDATE teacher_requests SET status = ?, updated_at = NOW() WHERE user_id = ?', ['approved', userId]);
    await db.run('UPDATE users SET role = ? WHERE id = ?', ['teacher', userId]);
    logAction(db, req, 'teacher_request_approve', { user_id: userId });
    broadcast('users_updated');
    return res.redirect('/admin?ok=Teacher%20approved');
  } catch (err) {
    console.error('Approve teacher failed', err);
    return res.redirect('/admin?err=Database%20error');
  }
});

app.post('/admin/teacher-requests/:userId/reject', requireAdmin, async (req, res) => {
  const userId = Number(req.params.userId);
  if (Number.isNaN(userId)) {
    return res.redirect('/admin?err=Invalid%20user');
  }
  try {
    await ensureDbReady();
    await db.run('UPDATE teacher_requests SET status = ?, updated_at = NOW() WHERE user_id = ?', ['rejected', userId]);
    await db.run('UPDATE users SET role = ? WHERE id = ?', ['student', userId]);
    logAction(db, req, 'teacher_request_reject', { user_id: userId });
    broadcast('users_updated');
    return res.redirect('/admin?ok=Teacher%20rejected');
  } catch (err) {
    console.error('Reject teacher failed', err);
    return res.redirect('/admin?err=Database%20error');
  }
});

app.get('/admin/api/courses/:courseId/study-days', requireAdminOrDeanery, async (req, res) => {
  const courseId = Number(req.params.courseId);
  if (Number.isNaN(courseId) || courseId < 1) {
    return res.status(400).json({ error: 'Invalid course' });
  }
  if (req.session.role === 'deanery' && Number(req.session.user.course_id) !== courseId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const course = await db.get('SELECT id FROM courses WHERE id = ?', [courseId]);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    const studyDays = await getCourseStudyDays(courseId);
    const subjects = await getSubjectsCached(courseId);
    const subjectRows = (subjects || []).map((s) => ({ id: s.id, name: s.name }));
    return res.json({ days: studyDays, subjects: subjectRows });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/admin/api/courses/:courseId/study-days/:weekday', requireAdminOrDeanery, async (req, res) => {
  const courseId = Number(req.params.courseId);
  const weekday = Number(req.params.weekday);
  const { is_active } = req.body || {};
  if (Number.isNaN(courseId) || courseId < 1 || Number.isNaN(weekday) || weekday < 1 || weekday > 7) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  if (req.session.role === 'deanery' && Number(req.session.user.course_id) !== courseId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const course = await db.get('SELECT id FROM courses WHERE id = ?', [courseId]);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    await ensureCourseStudyDays(courseId);
    const updatedAt = new Date().toISOString();
    await db.run(
      'UPDATE course_study_days SET is_active = ?, updated_at = ? WHERE course_id = ? AND weekday = ?',
      [is_active ? 1 : 0, updatedAt, courseId, weekday]
    );
    invalidateStudyDaysCache(courseId);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/admin/api/courses/:courseId/study-days/:weekday/subjects', requireAdminOrDeanery, async (req, res) => {
  const courseId = Number(req.params.courseId);
  const weekday = Number(req.params.weekday);
  const subjectId = Number(req.body?.subject_id);
  if (Number.isNaN(courseId) || Number.isNaN(weekday) || Number.isNaN(subjectId) || weekday < 1 || weekday > 7) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  if (req.session.role === 'deanery' && Number(req.session.user.course_id) !== courseId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const course = await db.get('SELECT id FROM courses WHERE id = ?', [courseId]);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    const subject = await db.get('SELECT id, course_id FROM subjects WHERE id = ?', [subjectId]);
    if (!subject || Number(subject.course_id) !== courseId) {
      return res.status(400).json({ error: 'Invalid subject' });
    }
    await ensureCourseStudyDays(courseId);
    const dayRow = await db.get(
      'SELECT id FROM course_study_days WHERE course_id = ? AND weekday = ?',
      [courseId, weekday]
    );
    if (!dayRow) return res.status(404).json({ error: 'Day not found' });
    await db.run(
      'INSERT INTO course_day_subjects (course_study_day_id, subject_id) VALUES (?, ?) ON CONFLICT DO NOTHING',
      [dayRow.id, subjectId]
    );
    invalidateStudyDaysCache(courseId);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/admin/api/courses/:courseId/study-days/:weekday/subjects/:subjectId', requireAdminOrDeanery, async (req, res) => {
  const courseId = Number(req.params.courseId);
  const weekday = Number(req.params.weekday);
  const subjectId = Number(req.params.subjectId);
  if (Number.isNaN(courseId) || Number.isNaN(weekday) || Number.isNaN(subjectId) || weekday < 1 || weekday > 7) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  if (req.session.role === 'deanery' && Number(req.session.user.course_id) !== courseId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const dayRow = await db.get(
      'SELECT id FROM course_study_days WHERE course_id = ? AND weekday = ?',
      [courseId, weekday]
    );
    if (!dayRow) return res.status(404).json({ error: 'Day not found' });
    await db.run(
      'DELETE FROM course_day_subjects WHERE course_study_day_id = ? AND subject_id = ?',
      [dayRow.id, subjectId]
    );
    invalidateStudyDaysCache(courseId);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/admin/api/courses/:courseId/week-time', requireAdminOrDeanery, async (req, res) => {
  const courseId = Number(req.params.courseId);
  if (Number.isNaN(courseId) || courseId < 1) {
    return res.status(400).json({ error: 'Invalid course' });
  }
  if (req.session.role === 'deanery' && Number(req.session.user.course_id) !== courseId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const course = await db.get('SELECT id FROM courses WHERE id = ?', [courseId]);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    const semester = await getActiveSemester(courseId);
    if (!semester) {
      return res.json({ weeks: [], semester: null });
    }
    const weeks = await getCourseWeekTimeList(courseId, semester);
    return res.json({
      weeks,
      semester: { id: semester.id, weeks_count: semester.weeks_count },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.patch('/admin/api/courses/:courseId/week-time/:weekNumber', requireAdminOrDeanery, async (req, res) => {
  const courseId = Number(req.params.courseId);
  const weekNumber = Number(req.params.weekNumber);
  const { use_local_time } = req.body || {};
  if (Number.isNaN(courseId) || courseId < 1 || Number.isNaN(weekNumber) || weekNumber < 1) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  if (req.session.role === 'deanery' && Number(req.session.user.course_id) !== courseId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const course = await db.get('SELECT id FROM courses WHERE id = ?', [courseId]);
    if (!course) return res.status(404).json({ error: 'Course not found' });
    const semester = await getActiveSemester(courseId);
    if (!semester || !semester.id) {
      return res.status(400).json({ error: 'No active semester' });
    }
    const totalWeeks = Number(semester.weeks_count || 0);
    if (!totalWeeks || weekNumber > totalWeeks) {
      return res.status(400).json({ error: 'Invalid week' });
    }
    const now = new Date().toISOString();
    await db.run(
      `INSERT INTO course_week_time_modes (course_id, semester_id, week_number, use_local_time, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (course_id, semester_id, week_number)
       DO UPDATE SET use_local_time = EXCLUDED.use_local_time, updated_at = EXCLUDED.updated_at`,
      [courseId, semester.id, weekNumber, use_local_time ? 1 : 0, now, now]
    );
    invalidateWeekTimeCache();
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/admin/api/homework/bulk', requireHomeworkBulkAccess, writeLimiter, async (req, res) => {
  const { ids, action, payload } = req.body || {};
  const list = Array.isArray(ids) ? ids.map((id) => Number(id)).filter((id) => Number.isFinite(id)) : [];
  if (!list.length || !action) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const role = req.session.role;
  const courseId = role === 'admin' ? getAdminCourse(req) : (req.session.user.course_id || 1);
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return res.status(500).json({ error: 'Semester error' });
  }
  const placeholders = list.map(() => '?').join(',');
  const scoped = await db.all(
    `SELECT id, day_of_week, class_date, custom_due_date, week_number FROM homework
     WHERE id IN (${placeholders}) AND course_id = ? AND semester_id = ?`,
    [...list, courseId, activeSemester ? activeSemester.id : null]
  );
  const scopedIds = scoped.map((row) => row.id);
  if (!scopedIds.length) {
    return res.status(404).json({ error: 'No items found' });
  }
  const scopedPlaceholders = scopedIds.map(() => '?').join(',');

  try {
    if (action === 'add_tags' || action === 'remove_tags') {
      const tagNames = Array.isArray(payload?.tags) ? payload.tags.map((t) => String(t).trim()).filter(Boolean) : [];
      if (!tagNames.length) return res.status(400).json({ error: 'No tags' });
      const tagIds = [];
      for (const name of tagNames) {
        const row = await db.get(
          'INSERT INTO homework_tags (name) VALUES (?) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id',
          [name]
        );
        if (row && row.id) tagIds.push(row.id);
      }
      if (action === 'add_tags') {
        for (const hwId of scopedIds) {
          for (const tagId of tagIds) {
            await db.run(
              'INSERT INTO homework_tag_map (homework_id, tag_id) VALUES (?, ?) ON CONFLICT DO NOTHING',
              [hwId, tagId]
            );
          }
        }
      } else {
        const tagPlaceholders = tagIds.map(() => '?').join(',');
        await db.run(
          `DELETE FROM homework_tag_map WHERE homework_id IN (${scopedPlaceholders}) AND tag_id IN (${tagPlaceholders})`,
          [...scopedIds, ...tagIds]
        );
      }
      return res.json({ ok: true });
    }

    if (action === 'set_deadline') {
      const deadline = payload?.deadline ? String(payload.deadline).slice(0, 10) : '';
      if (!deadline) return res.status(400).json({ error: 'Invalid deadline' });
      await db.run(
        `UPDATE homework SET custom_due_date = ?, is_custom_deadline = 1 WHERE id IN (${scopedPlaceholders})`,
        [deadline, ...scopedIds]
      );
      return res.json({ ok: true });
    }

    if (action === 'shift_deadline') {
      const daysShift = Number(payload?.days || 0);
      if (!Number.isFinite(daysShift) || daysShift === 0) {
        return res.status(400).json({ error: 'Invalid shift' });
      }
      for (const row of scoped) {
        const base = row.custom_due_date || row.class_date;
        if (!base) continue;
        const d = new Date(`${base}T00:00:00Z`);
        d.setUTCDate(d.getUTCDate() + daysShift);
        const newDate = d.toISOString().slice(0, 10);
        await db.run('UPDATE homework SET custom_due_date = ?, is_custom_deadline = 1 WHERE id = ?', [newDate, row.id]);
      }
      return res.json({ ok: true });
    }

    if (action === 'move_to_week') {
      const targetWeek = Number(payload?.week || 0);
      if (!Number.isFinite(targetWeek) || targetWeek < 1) {
        return res.status(400).json({ error: 'Invalid week' });
      }
      for (const row of scoped) {
        if (!row.day_of_week) continue;
        const newDate = getDateForWeekDay(targetWeek, row.day_of_week, activeSemester ? activeSemester.start_date : null);
        await db.run(
          'UPDATE homework SET class_date = ?, week_number = ?, custom_due_date = NULL, is_custom_deadline = 0 WHERE id = ?',
          [newDate, targetWeek, row.id]
        );
      }
      return res.json({ ok: true });
    }

    if (action === 'delete') {
      await db.run(`DELETE FROM homework WHERE id IN (${scopedPlaceholders})`, scopedIds);
      return res.json({ ok: true });
    }

    if (action === 'export_csv') {
      const rows = await db.all(
        `SELECT h.id, h.description, h.group_number, h.custom_due_date, h.class_date, h.created_by, h.created_at,
                s.name AS subject_name
         FROM homework h
         LEFT JOIN subjects s ON s.id = h.subject_id
         WHERE h.id IN (${scopedPlaceholders})
         ORDER BY h.id`,
        scopedIds
      );
      const header = ['id','title','subject','group','deadline','is_weird','created_by','created_at'];
      const csv = [header.join(',')];
      rows.forEach((r) => {
        const deadline = r.custom_due_date || r.class_date || '';
        const isWeird = r.custom_due_date && r.custom_due_date !== r.class_date ? '1' : '0';
        const line = [
          r.id,
          JSON.stringify(r.description || '').slice(1, -1),
          JSON.stringify(r.subject_name || '').slice(1, -1),
          r.group_number || '',
          deadline,
          isWeird,
          JSON.stringify(r.created_by || '').slice(1, -1),
          r.created_at || '',
        ].join(',');
        csv.push(line);
      });
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename=\"homework_export.csv\"');
      return res.send(csv.join('\n'));
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/admin/api/schedule/validate', requireAdminOrDeanery, async (req, res) => {
  const role = req.session.role;
  const courseId = role === 'admin' ? getAdminCourse(req) : (req.session.user.course_id || 1);
  let activeSemester = null;
  try {
    activeSemester = await getActiveSemester(courseId);
  } catch (err) {
    return res.status(500).json({ error: 'Semester error' });
  }
  const week = req.query.week ? Number(req.query.week) : null;
  if (req.query.week && (Number.isNaN(week) || week < 1)) {
    return res.status(400).json({ error: 'Invalid week' });
  }
  const filters = ['se.course_id = ?', 'se.semester_id = ?'];
  const params = [courseId, activeSemester ? activeSemester.id : null];
  if (week) {
    filters.push('se.week_number = ?');
    params.push(week);
  }
  const where = `WHERE ${filters.join(' AND ')}`;
  try {
    const studyDays = await getCourseStudyDays(courseId);
    const activeDaySet = new Set(
      (studyDays || []).filter((d) => d.is_active).map((d) => d.day_name)
    );
    const subjects = await getSubjectsCached(courseId);
    const subjectMap = new Map((subjects || []).map((s) => [s.id, { id: s.id, name: s.name, group_count: s.group_count }]));
    const rows = await db.all(
      `SELECT se.*
       FROM schedule_entries se
       ${where}`,
      params
    );

    const issues = [];
    const collisionMap = new Map();
    (rows || []).forEach((row) => {
      const key = `${row.week_number}|${row.day_of_week}|${row.class_number}|${row.group_number}`;
      if (!collisionMap.has(key)) collisionMap.set(key, []);
      collisionMap.get(key).push(row);

      if (!Number.isFinite(Number(row.class_number)) || row.class_number < 1 || row.class_number > 7) {
        issues.push({
          type: 'invalid_class_number',
          severity: 'error',
          message: 'Невірний номер пари',
          context: {
            week: row.week_number,
            day_of_week: row.day_of_week,
            class_number: row.class_number,
            group: row.group_number,
            schedule_ids: [row.id],
          },
          fix_url: `/admin?course=${courseId}&day=${encodeURIComponent(row.day_of_week)}&group_number=${row.group_number}`,
        });
      }

      if (activeDaySet.size && !activeDaySet.has(row.day_of_week)) {
        issues.push({
          type: 'day_disabled',
          severity: 'warning',
          message: 'Пара на вимкнений день',
          context: {
            week: row.week_number,
            day_of_week: row.day_of_week,
            class_number: row.class_number,
            group: row.group_number,
            schedule_ids: [row.id],
          },
          fix_url: `/admin?course=${courseId}&day=${encodeURIComponent(row.day_of_week)}&group_number=${row.group_number}`,
        });
      }

      const subject = subjectMap.get(row.subject_id);
      if (subject && subject.group_count && row.group_number > subject.group_count) {
        issues.push({
          type: 'subject_group_missing',
          severity: 'warning',
          message: 'Група не відповідає предмету',
          context: {
            week: row.week_number,
            day_of_week: row.day_of_week,
            class_number: row.class_number,
            group: row.group_number,
            schedule_ids: [row.id],
          },
          fix_url: `/admin?course=${courseId}&day=${encodeURIComponent(row.day_of_week)}&group_number=${row.group_number}`,
        });
      }
    });

    collisionMap.forEach((list, key) => {
      if (list.length > 1) {
        const sample = list[0];
        issues.push({
          type: 'collision',
          severity: 'error',
          message: 'Конфлікт пар в одному слоті',
          context: {
            week: sample.week_number,
            day_of_week: sample.day_of_week,
            class_number: sample.class_number,
            group: sample.group_number,
            schedule_ids: list.map((r) => r.id),
          },
          fix_url: `/admin?course=${courseId}&day=${encodeURIComponent(sample.day_of_week)}&group_number=${sample.group_number}`,
        });
      }
    });

    const summary = {
      errors: issues.filter((i) => i.severity === 'error').length,
      warnings: issues.filter((i) => i.severity === 'warning').length,
    };
    return res.json({ issues, summary });
  } catch (err) {
    return res.status(500).json({ error: 'Database error' });
  }
});

app.post('/admin/semesters/add', requireAdmin, (req, res) => {
  const { title, start_date, weeks_count, is_active } = req.body;
  const courseId = getAdminCourse(req);
  const weeks = Number(weeks_count);
  const active = String(is_active) === '1' ? 1 : 0;
  if (!title || !start_date || Number.isNaN(weeks) || weeks < 1 || weeks > 30) {
    return res.redirect('/admin?err=Invalid%20semester');
  }
  const create = () => {
    db.run(
      'INSERT INTO semesters (course_id, title, start_date, weeks_count, is_active, is_archived) VALUES (?, ?, ?, ?, ?, 0)',
      [courseId, title.trim(), start_date, weeks, active],
      (err) => {
        if (err) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'semester_add', { title, start_date, weeks_count: weeks, is_active: active });
        invalidateSemestersCache(courseId);
        return res.redirect('/admin?ok=Semester%20created');
      }
    );
  };
  if (active) {
    db.run('UPDATE semesters SET is_active = 0 WHERE course_id = ?', [courseId], (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      create();
    });
  } else {
    create();
  }
});

app.post('/admin/semesters/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { title, start_date, weeks_count } = req.body;
  const courseId = getAdminCourse(req);
  const weeks = Number(weeks_count);
  if (!title || !start_date || Number.isNaN(weeks) || weeks < 1 || weeks > 30) {
    return res.redirect('/admin?err=Invalid%20semester');
  }
  db.run(
    'UPDATE semesters SET title = ?, start_date = ?, weeks_count = ? WHERE id = ? AND course_id = ?',
    [title.trim(), start_date, weeks, id, courseId],
    (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'semester_edit', { id, title, start_date, weeks_count: weeks });
    invalidateSemestersCache(courseId);
    return res.redirect('/admin?ok=Semester%20updated');
  }
);
});

app.post('/admin/semesters/set-active/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = getAdminCourse(req);
  db.run('UPDATE semesters SET is_active = 0 WHERE course_id = ?', [courseId], (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    db.run('UPDATE semesters SET is_active = 1, is_archived = 0 WHERE id = ? AND course_id = ?', [id, courseId], (err2) => {
      if (err2) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'semester_set_active', { id });
      invalidateSemestersCache(courseId);
      return res.redirect('/admin?ok=Semester%20activated');
    });
  });
});

app.post('/admin/semesters/archive/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = getAdminCourse(req);
  db.run('UPDATE semesters SET is_archived = 1, is_active = 0 WHERE id = ? AND course_id = ?', [id, courseId], (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'semester_archive', { id });
    invalidateSemestersCache(courseId);
    return res.redirect('/admin?ok=Semester%20archived');
  });
});

app.post('/admin/semesters/restore/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = getAdminCourse(req);
  db.run('UPDATE semesters SET is_archived = 0 WHERE id = ? AND course_id = ?', [id, courseId], (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'semester_restore', { id });
    invalidateSemestersCache(courseId);
    return res.redirect('/admin?ok=Semester%20restored');
  });
});

app.post('/admin/semesters/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const courseId = getAdminCourse(req);
  db.get('SELECT is_active FROM semesters WHERE id = ? AND course_id = ?', [id, courseId], (semErr, semRow) => {
    if (semErr || !semRow) {
      return res.redirect('/admin?err=Semester%20not%20found');
    }
    if (semRow.is_active === 1) {
      return res.redirect('/admin?err=Cannot%20delete%20active%20semester');
    }
    db.get('SELECT COUNT(*) AS cnt FROM schedule_entries WHERE semester_id = ?', [id], (cntErr, cntRow) => {
      if (cntErr) {
        return res.redirect('/admin?err=Database%20error');
      }
      if (Number(cntRow.cnt) > 0) {
        return res.redirect('/admin?err=Semester%20in%20use');
      }
      db.run('DELETE FROM semesters WHERE id = ? AND course_id = ?', [id, courseId], (err) => {
        if (err) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'semester_delete', { id });
        invalidateSemestersCache(courseId);
        return res.redirect('/admin?ok=Semester%20deleted');
      });
    });
  });
});

app.post('/admin/student-groups/set', requireAdmin, (req, res) => {
  const { student_id, subject_id, group_number } = req.body;
  const groupNum = Number(group_number);
  const courseId = getAdminCourse(req);
  if (!student_id || !subject_id || Number.isNaN(groupNum)) {
    return res.redirect('/admin?err=Invalid%20group%20assignment');
  }
  db.get('SELECT group_count FROM subjects WHERE id = ? AND course_id = ?', [subject_id, courseId], (err, subject) => {
    if (err || !subject) {
      return res.redirect('/admin?err=Database%20error');
    }
    if (groupNum < 1 || groupNum > subject.group_count) {
      return res.redirect('/admin?err=Group%20out%20of%20range');
    }
    db.run(
      `
        INSERT INTO student_groups (student_id, subject_id, group_number)
        VALUES (?, ?, ?)
        ON CONFLICT(student_id, subject_id)
        DO UPDATE SET group_number = excluded.group_number
      `,
      [student_id, subject_id, groupNum],
      (setErr) => {
        if (setErr) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'student_group_set', { student_id, subject_id, group_number: groupNum });
        logActivity(db, req, 'group_set', 'student_group', null, { student_id, subject_id, group_number: groupNum }, courseId);
        broadcast('users_updated');
        return res.redirect('/admin?ok=Group%20updated');
      }
    );
  });
});

app.post('/admin/group/remove', requireAdmin, (req, res) => {
  const { student_id, subject_id } = req.body;
  if (!student_id || !subject_id) {
    return res.redirect('/admin?err=Invalid%20remove%20request');
  }
  db.run(
    'DELETE FROM student_groups WHERE student_id = ? AND subject_id = ?',
    [student_id, subject_id],
    (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'student_group_remove', { student_id, subject_id });
    logActivity(db, req, 'group_remove', 'student_group', null, { student_id, subject_id }, getAdminCourse(req));
    broadcast('users_updated');
    return res.redirect('/admin?ok=Subject%20removed');
  }
  );
});

app.post('/admin/users/role', requireAdmin, (req, res) => {
  const { user_id, role } = req.body;
  const courseId = getAdminCourse(req);
  if (!user_id || !role || !['student', 'admin', 'starosta', 'deanery', 'teacher'].includes(role)) {
    return res.redirect('/admin?err=Invalid%20role');
  }
  const currentId = req.session.user.id;
  if (Number(user_id) === Number(currentId)) {
    return res.redirect('/admin?err=Cannot%20change%20your%20own%20role');
  }
  db.get('SELECT role FROM users WHERE id = ? AND course_id = ?', [user_id, courseId], (err, user) => {
    if (err || !user) {
      return res.redirect('/admin?err=User%20not%20found');
    }
    if (user.role === 'admin' && role !== 'admin') {
      db.get('SELECT COUNT(*) AS count FROM users WHERE role = ?', ['admin'], (countErr, row) => {
        if (countErr) {
          return res.redirect('/admin?err=Database%20error');
        }
        if (Number(row.count) <= 1) {
          return res.redirect('/admin?err=At%20least%20one%20admin%20required');
        }
        db.run('UPDATE users SET role = ? WHERE id = ?', [role, user_id], (updErr) => {
          if (updErr) {
            return res.redirect('/admin?err=Database%20error');
          }
          logAction(db, req, 'user_role_change', { user_id, role });
          broadcast('users_updated');
          return res.redirect('/admin?ok=Role%20updated');
        });
      });
      return;
    }
    db.run('UPDATE users SET role = ? WHERE id = ?', [role, user_id], (updErr) => {
      if (updErr) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'user_role_change', { user_id, role });
      broadcast('users_updated');
      return res.redirect('/admin?ok=Role%20updated');
    });
  });
});

app.post('/admin/users/course', requireAdmin, (req, res) => {
  const { user_id, course_id } = req.body;
  const userId = Number(user_id);
  const courseId = Number(course_id);
  const currentCourse = getAdminCourse(req);
  if (Number.isNaN(userId) || Number.isNaN(courseId)) {
    return res.redirect('/admin?err=Invalid%20course');
  }
  db.get('SELECT id FROM courses WHERE id = ?', [courseId], (courseErr, courseRow) => {
    if (courseErr || !courseRow) {
      return res.redirect('/admin?err=Invalid%20course');
    }
    db.get('SELECT role FROM users WHERE id = ? AND course_id = ?', [userId, currentCourse], (err, user) => {
      if (err || !user) {
        return res.redirect('/admin?err=User%20not%20found');
      }
      if (user.role === 'admin') {
        return res.redirect('/admin?err=Cannot%20change%20admin%20course');
      }
      db.run('UPDATE users SET course_id = ? WHERE id = ?', [courseId, userId], (updErr) => {
        if (updErr) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'user_course_change', { user_id: userId, course_id: courseId });
        broadcast('users_updated');
        return res.redirect(`/admin?course=${currentCourse}&ok=Course%20updated`);
      });
    });
  });
});

app.post('/admin/users/reset-password', requireAdmin, (req, res) => {
  const { user_id, new_password } = req.body;
  if (!user_id || !new_password) {
    return res.redirect('/admin?err=Password%20required');
  }
  if (new_password.length < 4) {
    return res.redirect('/admin?err=Password%20too%20short');
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.run(
    'UPDATE users SET password_hash = ? WHERE id = ?',
    [hash, user_id],
    (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'user_password_reset', { user_id });
      broadcast('users_updated');
      return res.redirect('/admin?ok=Password%20updated');
    }
  );
});

app.post('/admin/homework/migrate', requireAdmin, (req, res) => {
  const timeToClass = (time) => {
    if (!time) return null;
    const start = time.split('-')[0].trim();
    const match = Object.entries(bellSchedule).find(([, slot]) => slot.start === start);
    return match ? Number(match[0]) : null;
  };

  db.all(
    `
      SELECT id, subject, day, time, subject_id, group_number, day_of_week, class_number
      FROM homework
      WHERE subject_id IS NULL OR group_number IS NULL OR day_of_week IS NULL OR class_number IS NULL
    `,
    (err, rows) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      if (!rows.length) {
        return res.redirect('/admin?ok=Nothing%20to%20migrate');
      }
      db.all('SELECT id, name FROM subjects', (sErr, subjects) => {
        if (sErr) {
          return res.redirect('/admin?err=Database%20error');
        }
        const subjectMap = new Map(subjects.map((s) => [s.name, s.id]));
        const stmt = db.prepare(
          `
            UPDATE homework
            SET subject_id = COALESCE(subject_id, ?),
                group_number = COALESCE(group_number, ?),
                day_of_week = COALESCE(day_of_week, ?),
                class_number = COALESCE(class_number, ?)
            WHERE id = ?
          `
        );
        rows.forEach((row) => {
          const subjectId = subjectMap.get(row.subject) || row.subject_id;
          const classNum = row.class_number || timeToClass(row.time);
          const day = row.day_of_week || row.day;
          stmt.run(subjectId || null, 1, day || null, classNum || null, row.id);
        });
        stmt.finalize(() => {
          logAction(db, req, 'homework_migrate', { count: rows.length });
          return res.redirect('/admin?ok=Homework%20migrated');
        });
      });
    }
  );
});

app.post('/admin/users/delete-multiple', requireAdmin, (req, res) => {
  const ids = req.body.delete_user_ids;
  const courseId = getAdminCourse(req);
  if (!ids) {
    return res.redirect('/admin?err=No%20users%20selected');
  }
  const list = Array.isArray(ids) ? ids : [ids];
  const placeholders = list.map(() => '?').join(',');
  db.all(
    `SELECT id, role FROM users WHERE course_id = ? AND id IN (${placeholders})`,
    [courseId, ...list],
    (err, rows) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      const deleteIds = rows.filter((u) => u.role !== 'admin').map((u) => u.id);
      if (!deleteIds.length) {
        return res.redirect('/admin?err=No%20students%20to%20delete');
      }
      const delPlaceholders = deleteIds.map(() => '?').join(',');
      db.run(`UPDATE users SET is_active = 0 WHERE id IN (${delPlaceholders})`, deleteIds, (delErr) => {
        if (delErr) {
          return res.redirect('/admin?err=Database%20error');
        }
        logAction(db, req, 'users_deactivate_multiple', { ids: deleteIds });
        broadcast('users_updated');
        return res.redirect('/admin?ok=Users%20deactivated');
      });
    }
  );
});

app.post('/admin/users/clear-all', requireAdmin, (req, res) => {
  const courseId = getAdminCourse(req);
  db.all('SELECT id FROM users WHERE role != ? AND course_id = ?', ['admin', courseId], (err, rows) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    const ids = rows.map((r) => r.id);
    if (!ids.length) {
      return res.redirect('/admin?err=No%20students%20to%20delete');
    }
    const placeholders = ids.map(() => '?').join(',');
    db.run(`UPDATE users SET is_active = 0 WHERE id IN (${placeholders})`, ids, (delErr) => {
      if (delErr) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'users_deactivate_all', { ids });
      broadcast('users_updated');
      return res.redirect('/admin?ok=All%20students%20deactivated');
    });
  });
});

app.post('/admin/users/deactivate', requireAdmin, (req, res) => {
  const { user_id } = req.body;
  const courseId = getAdminCourse(req);
  if (!user_id) {
    return res.status(400).json({ error: 'Missing user_id' });
  }
  db.get('SELECT role, full_name FROM users WHERE id = ? AND course_id = ?', [user_id, courseId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.role === 'admin') {
      return res.status(400).json({ error: 'Cannot deactivate admin' });
    }
    db.run('UPDATE users SET is_active = 0 WHERE id = ?', [user_id], (updErr) => {
      if (updErr) {
        return res.status(500).json({ error: 'Database error' });
      }
      logAction(db, req, 'user_deactivate', { user_id, full_name: user.full_name });
      broadcast('users_updated');
      return res.json({ ok: true });
    });
  });
});

app.post('/admin/users/activate', requireAdmin, (req, res) => {
  const { user_id } = req.body;
  const courseId = getAdminCourse(req);
  if (!user_id) {
    return res.status(400).json({ error: 'Missing user_id' });
  }
  db.run('UPDATE users SET is_active = 1 WHERE id = ? AND course_id = ?', [user_id, courseId], (updErr) => {
    if (updErr) {
      return res.status(500).json({ error: 'Database error' });
    }
    logAction(db, req, 'user_activate', { user_id });
    broadcast('users_updated');
    return res.json({ ok: true });
  });
});

app.post('/admin/users/delete-permanent', requireAdmin, async (req, res) => {
  const { user_id } = req.body;
  const userId = Number(user_id);
  const courseId = getAdminCourse(req);
  if (Number.isNaN(userId)) {
    return res.redirect('/admin?err=Invalid%20user');
  }
  try {
    const user = await db.get('SELECT role FROM users WHERE id = ? AND course_id = ?', [userId, courseId]);
    if (!user) {
      return res.redirect('/admin?err=User%20not%20found');
    }
    if (user.role === 'admin') {
      return res.redirect('/admin?err=Cannot%20delete%20admin');
    }
    await db.run('DELETE FROM student_groups WHERE student_id = ?', [userId]);
    await db.run('DELETE FROM login_history WHERE user_id = ?', [userId]);
    await db.run('DELETE FROM message_reads WHERE user_id = ?', [userId]);
    await db.run('DELETE FROM message_targets WHERE user_id = ?', [userId]);
    await db.run('DELETE FROM teamwork_members WHERE user_id = ?', [userId]);
    await db.run('UPDATE homework SET created_by_id = NULL WHERE created_by_id = ?', [userId]);
    await db.run('UPDATE messages SET created_by_id = ? WHERE created_by_id = ?', [req.session.user.id, userId]);
    await db.run('UPDATE teamwork_tasks SET created_by = ? WHERE created_by = ?', [req.session.user.id, userId]);
    await db.run('UPDATE teamwork_groups SET leader_id = ? WHERE leader_id = ?', [req.session.user.id, userId]);
    await db.run('DELETE FROM users WHERE id = ?', [userId]);
    logAction(db, req, 'user_delete_permanent', { user_id: userId });
    broadcast('users_updated');
    return res.redirect('/admin?ok=User%20deleted');
  } catch (err) {
    return res.redirect('/admin?err=Database%20error');
  }
});

app.post('/admin/switch-to-student', requireAdmin, (req, res) => {
  req.session.viewAs = 'student';
  return res.redirect('/schedule');
});

app.post('/admin/switch-to-admin', requireAdmin, (req, res) => {
  req.session.viewAs = null;
  return res.redirect('/admin');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

const startScheduler = () => {
  const intervalMs = Number(process.env.SCHEDULER_INTERVAL_MS || 60000);
  if (!Number.isFinite(intervalMs) || intervalMs < 10000) {
    return;
  }
  setInterval(() => {
    publishScheduledItems().catch((err) => {
      console.error('Scheduler error', err);
    });
  }, intervalMs);
};

const startServer = () => {
  console.log('Starting server', {
    port: PORT,
    node: process.version,
    env: process.env.NODE_ENV || 'unknown',
  });
  server.listen(PORT, '0.0.0.0', () => console.log(`Listening on ${PORT}`));
  ensureDbReady().catch((err) => {
    console.error('Failed to initialize database', err);
  });
  startScheduler();
};

app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  if (process.env.DB_DEBUG === 'true') {
    return res.status(500).send(err && err.stack ? err.stack : String(err));
  }
  return res.status(500).send('Internal Server Error');
});

startServer();
