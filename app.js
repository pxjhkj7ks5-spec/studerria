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
const buildStamp = new Date().toISOString();

const app = express();
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const adminSeed = {
  full_name: process.env.ADMIN_NAME || 'Марченко Андрій Юрійович',
  role: 'admin',
  password: process.env.ADMIN_PASS || 'admadm',
};

const userSeed = [
  adminSeed,
  { full_name: 'Test', role: 'student', password: 'kma' },
];

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

app.use((req, res, next) => {
  res.locals.messages = {
    error: req.query && req.query.err ? req.query.err : '',
    success: req.query && req.query.ok ? req.query.ok : '',
  };
  res.locals.appVersion = appVersion;
  res.locals.buildStamp = buildStamp;
  res.locals.authorName = 'Andrii Marchenko';
  next();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
  })
);

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

const ensureUser = async (fullName, role, password, options = {}) => {
  const { forcePassword = false, forceRole = false } = options;
  const existing = await db.get('SELECT id, password_hash, role FROM users WHERE full_name = ?', [fullName]);
  const hash = await bcrypt.hash(password, 10);
  if (!existing) {
    await db.run(
      'INSERT INTO users (full_name, role, password_hash, password, is_active, schedule_group) VALUES (?, ?, ?, ?, ?, ?)',
      [fullName, role, hash, password, 1, 'A']
    );
    return;
  }
  if (forcePassword || !existing.password_hash) {
    await db.run('UPDATE users SET password_hash = ?, password = ?, is_active = 1 WHERE id = ?', [
      hash,
      password,
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
  const ddl = [
    `
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        password_hash TEXT,
        password TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_login_ip TEXT,
        last_user_agent TEXT,
        last_login_at TEXT,
        schedule_group TEXT NOT NULL DEFAULT 'A'
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS subjects (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        group_count INTEGER NOT NULL DEFAULT 1,
        default_group INTEGER NOT NULL DEFAULT 1,
        show_in_teamwork INTEGER NOT NULL DEFAULT 1
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS student_groups (
        id SERIAL PRIMARY KEY,
        student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        group_number INTEGER NOT NULL,
        UNIQUE(student_id, subject_id)
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS schedule_entries (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        group_number INTEGER NOT NULL,
        day_of_week TEXT NOT NULL,
        class_number INTEGER NOT NULL,
        week_number INTEGER NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS homework (
        id SERIAL PRIMARY KEY,
        group_name TEXT NOT NULL,
        subject TEXT NOT NULL,
        day TEXT NOT NULL,
        time TEXT NOT NULL,
        week_number INTEGER,
        class_number INTEGER,
        subject_id INTEGER,
        group_number INTEGER,
        day_of_week TEXT,
        created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        description TEXT NOT NULL,
        class_date TEXT,
        meeting_url TEXT,
        link_url TEXT,
        file_path TEXT,
        file_name TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS history_log (
        id SERIAL PRIMARY KEY,
        actor_id INTEGER,
        actor_name TEXT,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        full_name TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS teamwork_tasks (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS teamwork_groups (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES teamwork_tasks(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        leader_id INTEGER NOT NULL REFERENCES users(id),
        max_members INTEGER,
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS teamwork_members (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES teamwork_tasks(id) ON DELETE CASCADE,
        group_id INTEGER NOT NULL REFERENCES teamwork_groups(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        joined_at TEXT NOT NULL,
        UNIQUE(task_id, user_id)
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
        group_number INTEGER,
        target_all INTEGER NOT NULL DEFAULT 0,
        body TEXT NOT NULL,
        created_by_id INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS message_targets (
        id SERIAL PRIMARY KEY,
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS message_reads (
        id SERIAL PRIMARY KEY,
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        read_at TEXT NOT NULL,
        UNIQUE(message_id, user_id)
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS subgroups (
        id SERIAL PRIMARY KEY,
        homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `,
    `
      CREATE TABLE IF NOT EXISTS subgroup_members (
        id SERIAL PRIMARY KEY,
        subgroup_id INTEGER NOT NULL REFERENCES subgroups(id) ON DELETE CASCADE,
        member_username TEXT NOT NULL,
        joined_at TEXT NOT NULL,
        UNIQUE(subgroup_id, member_username)
      )
    `,
  ];

  for (const statement of ddl) {
    await pool.query(statement);
  }

  for (const user of userSeed) {
    const isAdmin = user.role === 'admin';
    await ensureUser(user.full_name, user.role, user.password, {
      forcePassword: isAdmin,
      forceRole: isAdmin,
    });
  }
};

let initPromise;
const ensureDbReady = async () => {
  if (initPromise) {
    return initPromise;
  }
  initPromise = (async () => {
    const maxAttempts = 8;
    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        await initDb();
        return true;
      } catch (err) {
        lastError = err;
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

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'uploads'));
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
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!allowedTypes.has(file.mimetype)) {
      return cb(new Error('Invalid file type'));
    }
    return cb(null, true);
  },
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  return next();
}

function requireStaff(req, res, next) {
  if (!req.session.user || !['admin', 'starosta'].includes(req.session.role)) {
    return res.status(403).send('Forbidden');
  }
  return next();
}

const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];

function getAcademicWeek(date) {
  const startUTC = Date.UTC(2026, 0, 19);
  const currentUTC = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
  const diffDays = Math.floor((currentUTC - startUTC) / (1000 * 60 * 60 * 24));
  let week = Math.floor(diffDays / 7) + 1;
  if (diffDays < 0) week = 1;
  if (week < 1) week = 1;
  if (week > 15) week = 15;
  return week;
}

function getDateForWeekDay(weekNumber, dayName) {
  const dayIndex = daysOfWeek.indexOf(dayName);
  if (dayIndex === -1) return null;
  const startUTC = Date.UTC(2026, 0, 19);
  const dateUTC =
    startUTC + (Number(weekNumber) - 1) * 7 * 24 * 60 * 60 * 1000 + dayIndex * 24 * 60 * 60 * 1000;
  return new Date(dateUTC).toISOString().slice(0, 10);
}

function logAction(dbRef, req, action, details) {
  const actorId = req.session.user ? req.session.user.id : null;
  const actorName = req.session.user ? req.session.user.username : null;
  const createdAt = new Date().toISOString();
  dbRef.run(
    'INSERT INTO history_log (actor_id, actor_name, action, details, created_at) VALUES (?, ?, ?, ?, ?)',
    [actorId, actorName, action, details ? JSON.stringify(details) : null, createdAt]
  );
  broadcast('history_updated');
}

function ensureUsersSchema(cb) {
  usersHasIsActive = true;
  return cb(true);
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

app.post('/login', async (req, res) => {
  const { full_name, password } = req.body;
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
    db.get(
      `SELECT id, full_name, role, password_hash, password, schedule_group FROM users WHERE LOWER(full_name) = LOWER(?)${activeClause}`,
      [normalizedName],
      (err, user) => {
        const validHash = user && user.password_hash ? bcrypt.compareSync(password, user.password_hash) : false;
        const validPlain = user && user.password && user.password === password;
        if (err || !user || (!validHash && !validPlain)) {
          return res.redirect('/login?error=1');
        }
        const loginAt = new Date().toISOString();
        db.run(
          'UPDATE users SET last_login_ip = ?, last_user_agent = ?, last_login_at = ? WHERE id = ?',
          [req.ip, req.headers['user-agent'] || null, loginAt, user.id]
        );
        db.run(
          'INSERT INTO login_history (user_id, full_name, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?)',
          [user.id, user.full_name, req.ip, req.headers['user-agent'] || null, loginAt]
        );
        req.session.user = {
          id: user.id,
          username: user.full_name,
          schedule_group: user.schedule_group,
        };
        req.session.role = user.role;

        if (user.role === 'admin') {
          return res.redirect('/admin');
        }
        return res.redirect('/schedule');
      }
    );
  });
});

app.get('/register', (req, res) => {
  res.render('register', { error: req.query.error || '' });
});

app.post('/register', async (req, res) => {
  const { full_name, password, confirm_password, agree } = req.body;
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
    const row = await db.get(
      'INSERT INTO users (full_name, role, password_hash, password, is_active, schedule_group) VALUES (?, ?, ?, ?, ?, ?) RETURNING id',
      [normalizedName, 'student', hash, password, 1, 'A']
    );
    if (!row || !row.id) {
      return res.redirect('/register?error=Database%20error');
    }
    req.session.pendingUserId = row.id;
    logAction(db, req, 'register_user', { user_id: row.id, full_name: normalizedName });
    broadcast('users_updated');
    return res.redirect('/register/subjects');
  } catch (err) {
    console.error('Register failed', err);
    return res.redirect('/register?error=Database%20error');
  }
});

app.get('/register/subjects', (req, res) => {
  if (!req.session.pendingUserId) {
    return res.redirect('/register');
  }
  ensureDbReady().catch((err) => {
    console.error('DB init failed', err);
  });
  db.all('SELECT * FROM subjects ORDER BY name', (err, subjects) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    res.render('register-subjects', { subjects });
  });
});

app.post('/register/subjects', (req, res) => {
  const userId = req.session.pendingUserId;
  if (!userId) {
    return res.redirect('/register');
  }

  db.all('SELECT id, group_count, default_group FROM subjects', (err, subjects) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    const stmt = db.prepare(
      `
        INSERT INTO student_groups (student_id, subject_id, group_number)
        VALUES (?, ?, ?)
        ON CONFLICT(student_id, subject_id)
        DO UPDATE SET group_number = excluded.group_number
      `
    );
    subjects.forEach((s) => {
      const value = req.body[`subject_${s.id}`];
      if (!value) {
        if (s.group_count === 1) {
          stmt.run(userId, s.id, 1);
        }
        return;
      }
      const groupNum = Number(value);
      if (groupNum >= 1 && groupNum <= s.group_count) {
        stmt.run(userId, s.id, groupNum);
      }
    });
    stmt.finalize(() => {
      db.get('SELECT id, full_name, role, schedule_group FROM users WHERE id = ?', [userId], (uErr, user) => {
        if (uErr || !user) {
          return res.redirect('/login');
        }
        req.session.user = {
          id: user.id,
          username: user.full_name,
          schedule_group: user.schedule_group,
        };
        req.session.role = user.role;
        req.session.pendingUserId = null;
        logAction(db, req, 'register_subjects', { user_id: user.id });
        broadcast('users_updated');
        return res.redirect('/schedule');
      });
    });
  });
});

app.get('/profile', requireLogin, (req, res) => {
  const { id } = req.session.user;
  db.get('SELECT id, full_name FROM users WHERE id = ?', [id], (err, user) => {
    if (err || !user) {
      return res.status(500).send('Database error');
    }
    res.render('profile', { user, error: req.query.error || '', success: req.query.ok || '' });
  });
});

app.post('/profile', requireLogin, (req, res) => {
  const { full_name, password, confirm_password } = req.body;
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

  params.push(id);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, (err) => {
    if (err) {
      return res.redirect('/profile?error=Name%20already%20exists');
    }
    req.session.user.username = full_name.trim();
    logAction(db, req, 'update_profile', { user_id: id });
    broadcast('users_updated');
    return res.redirect('/profile?ok=Profile%20updated');
  });
});

app.get('/schedule', requireLogin, (req, res) => {
  const { id: userId, schedule_group: group, username } = req.session.user;
  let selectedWeek = parseInt(req.query.week, 10);
  if (Number.isNaN(selectedWeek)) {
    selectedWeek = getAcademicWeek(new Date());
  }
  if (selectedWeek < 1) selectedWeek = 1;
  if (selectedWeek > 15) selectedWeek = 15;

  db.all(
    `
      SELECT sg.subject_id, sg.group_number, s.name AS subject_name
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      WHERE sg.student_id = ?
    `,
    [userId],
    (groupErr, studentGroups) => {
      if (groupErr) {
        return res.status(500).send('Database error');
      }

      const scheduleByDay = {};
      daysOfWeek.forEach((day) => {
        scheduleByDay[day] = [];
      });

      const loadHomework = () => {
        if (!studentGroups.length) {
          return res.render('schedule', {
            scheduleByDay,
            daysOfWeek,
            currentWeek: selectedWeek,
            bellSchedule,
            group: group || 'A',
            username,
            homework: [],
            subgroupError: req.query.sg || null,
            role: req.session.role,
            viewAs: req.session.viewAs || null,
            messageSubjects: studentGroups || [],
          });
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
            WHERE ${hwConditions}
            ORDER BY h.created_at DESC
          `,
          hwParams,
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

            res.render('schedule', {
              scheduleByDay,
              daysOfWeek,
              currentWeek: selectedWeek,
              bellSchedule,
              group: group || 'A',
              username,
              homework,
              subgroupError: req.query.sg || null,
              role: req.session.role,
              viewAs: req.session.viewAs || null,
              messageSubjects: studentGroups || [],
            });
          }
        );
      };

      if (!studentGroups.length) {
        return loadHomework();
      }

      const conditions = studentGroups
        .map(() => '(se.subject_id = ? AND se.group_number = ?)')
        .join(' OR ');
      const params = [selectedWeek];
      studentGroups.forEach((sg) => {
        params.push(sg.subject_id, sg.group_number);
      });

      const sql = `
        SELECT se.*, s.name AS subject_name
        FROM schedule_entries se
        JOIN subjects s ON s.id = se.subject_id
        WHERE se.week_number = ? AND (${conditions})
      `;

      db.all(sql, params, (scheduleErr, rows) => {
        if (scheduleErr) {
          return res.status(500).send('Database error');
        }
        rows.forEach((row) => {
          row.class_date = getDateForWeekDay(selectedWeek, row.day_of_week);
          if (scheduleByDay[row.day_of_week]) {
            scheduleByDay[row.day_of_week].push(row);
          }
        });
        daysOfWeek.forEach((day) => {
          scheduleByDay[day].sort((a, b) => a.class_number - b.class_number);
        });
        return loadHomework();
      });
    }
  );
});

app.get('/teamwork', requireLogin, (req, res) => {
  const { id: userId, username } = req.session.user;
  const selectedSubjectId = req.query.subject_id ? Number(req.query.subject_id) : null;
  db.all(
    `
      SELECT sg.subject_id, s.name AS subject_name
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      WHERE sg.student_id = ? AND s.show_in_teamwork = 1
      ORDER BY s.name ASC
    `,
    [userId],
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
        });
      }

      db.all(
        `
          SELECT t.*, s.name AS subject_name
          FROM teamwork_tasks t
          JOIN subjects s ON s.id = t.subject_id
          WHERE t.subject_id = ?
          ORDER BY t.created_at DESC
        `,
        [selectedSubjectId],
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
                      SELECT u.id, u.full_name
                      FROM users u
                      JOIN student_groups sg ON sg.student_id = u.id
                      WHERE sg.subject_id = ?
                      ORDER BY u.full_name ASC
                    `,
                    [selectedSubjectId],
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
});

app.post('/teamwork/task/create', requireLogin, async (req, res) => {
  const { title, subject_id } = req.body;
  const subjectId = Number(subject_id);
  if (!title || Number.isNaN(subjectId)) {
    return res.redirect('/teamwork?err=Missing%20fields');
  }
  const { id: userId } = req.session.user;
  const createdAt = new Date().toISOString();
  try {
    const taskRow = await db.get(
      'INSERT INTO teamwork_tasks (subject_id, title, created_by, created_at) VALUES (?, ?, ?, ?) RETURNING id',
      [subjectId, title.trim(), userId, createdAt]
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
    await db.run(
      'INSERT INTO teamwork_members (task_id, group_id, user_id, joined_at) VALUES (?, ?, ?, ?)',
      [taskRow.id, groupRow.id, userId, createdAt]
    );
    return res.redirect(`/teamwork?subject_id=${subjectId}`);
  } catch (err) {
    return res.redirect('/teamwork?err=Database%20error');
  }
});

app.post('/teamwork/group/create', requireLogin, async (req, res) => {
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

app.post('/teamwork/group/join', requireLogin, (req, res) => {
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

app.post('/teamwork/group/leave', requireLogin, (req, res) => {
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

app.post('/teamwork/group/disband', requireLogin, (req, res) => {
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

app.post('/teamwork/group/update', requireLogin, (req, res) => {
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

app.post('/admin/messages/send', requireStaff, async (req, res) => {
  const { target_type, target_all, subject_id, group_number, body, user_ids } = req.body;
  if (!body || !body.trim()) {
    return res.redirect('/admin?err=Message%20is%20empty');
  }
  const createdAt = new Date().toISOString();
  const createdBy = req.session.user.id;
  const target = target_type || (String(target_all) === '1' ? 'all' : 'subject');
  const isAll = target === 'all';
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
        INSERT INTO messages (subject_id, group_number, target_all, body, created_by_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?) RETURNING id
      `,
      [
        isAll || target === 'users' ? null : subjectId,
        isAll || target === 'users' ? null : groupNum,
        isAll ? 1 : 0,
        body.trim(),
        createdBy,
        createdAt,
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

app.post('/admin/messages/delete/:id', requireStaff, (req, res) => {
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

app.get('/messages.json', requireLogin, (req, res) => {
  const { id: userId } = req.session.user;
  const filterSubjectId = req.query.subject_id ? Number(req.query.subject_id) : null;
  db.all(
    `
      SELECT sg.subject_id, sg.group_number
      FROM student_groups sg
      WHERE sg.student_id = ?
    `,
    [userId],
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
      const subjectFilter = !Number.isNaN(filterSubjectId) ? ' AND m.subject_id = ?' : '';
      if (!Number.isNaN(filterSubjectId)) {
        params.push(filterSubjectId);
      }
      db.all(
        `
          SELECT m.*, s.name AS subject_name, u.full_name AS created_by, mr.id AS read_id
          FROM messages m
          LEFT JOIN subjects s ON s.id = m.subject_id
          LEFT JOIN users u ON u.id = m.created_by_id
          LEFT JOIN message_reads mr ON mr.message_id = m.id AND mr.user_id = ?
          LEFT JOIN message_targets mt ON mt.message_id = m.id
          ${baseWhere}${subjectFilter}
          ORDER BY m.created_at DESC
          LIMIT 50
        `,
        [userId, ...params],
        (msgErr, rows) => {
          if (msgErr) {
            return res.status(500).json({ error: 'Database error' });
          }
          const unreadCount = rows.filter((r) => !r.read_id).length;
          return res.json({ messages: rows, unread_count: unreadCount });
        }
      );
    }
  );
});

app.post('/messages/read', requireLogin, (req, res) => {
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

app.get('/admin', requireAdmin, (req, res) => {
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
  } = req.query;
  const scheduleFilters = [];
  const scheduleParams = [];

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

  const scheduleWhere = scheduleFilters.length ? `WHERE ${scheduleFilters.join(' AND ')}` : '';
  const scheduleSql = `
    SELECT se.*, s.name AS subject_name
    FROM schedule_entries se
    JOIN subjects s ON s.id = se.subject_id
    ${scheduleWhere}
    ORDER BY se.week_number, se.day_of_week, se.class_number
  `;

  db.all(scheduleSql, scheduleParams, (scheduleErr, scheduleRows) => {
    if (scheduleErr) {
      return res.status(500).send('Database error');
    }
    const schedule = sortSchedule(scheduleRows, sort_schedule);

    const homeworkFilters = [];
    const homeworkParams = [];
    if (group_number) {
      homeworkFilters.push('group_number = ?');
      homeworkParams.push(group_number);
    }
    if (subject) {
      homeworkFilters.push('subject LIKE ?');
      homeworkParams.push(`%${subject}%`);
    }
    if (q) {
      homeworkFilters.push('(description LIKE ? OR created_by LIKE ?)');
      homeworkParams.push(`%${q}%`, `%${q}%`);
    }

    const homeworkWhere = homeworkFilters.length ? `WHERE ${homeworkFilters.join(' AND ')}` : '';
    const homeworkSql = `
      SELECT h.*, subj.name AS subject_name
      FROM homework h
      JOIN subjects subj ON subj.id = h.subject_id
      ${homeworkWhere}
      ORDER BY h.created_at DESC
    `;

    db.all(homeworkSql, homeworkParams, (homeworkErr, homeworkRows) => {
      if (homeworkErr) {
        return res.status(500).send('Database error');
      }
      const homework = sortHomework(homeworkRows, sort_homework);
      ensureUsersSchema(() => {
        const userFilter =
          users_status === 'inactive'
            ? 'WHERE is_active = 0'
            : users_status === 'all'
            ? ''
            : usersHasIsActive
            ? 'WHERE is_active = 1'
            : '';
        db.all(
          `SELECT id, full_name, role, schedule_group, ${usersHasIsActive ? 'is_active,' : ''} last_login_ip, last_user_agent, last_login_at FROM users ${userFilter} ORDER BY full_name`,
          (userErr, users) => {
            if (userErr) {
              return res.status(500).send('Database error');
            }
            db.all('SELECT * FROM subjects ORDER BY name', (subjectErr, subjects) => {
              if (subjectErr) {
                return res.status(500).send('Database error');
              }
              db.all(
                `
                  SELECT sg.student_id, sg.subject_id, sg.group_number, s.name AS subject_name
                  FROM student_groups sg
                  JOIN subjects s ON s.id = sg.subject_id
                `,
                (sgErr, studentGroups) => {
                  if (sgErr) {
                    return res.status(500).send('Database error');
                  }
                  const historyFilters = [];
                  const historyParams = [];
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
                        return res.status(500).send('Database error');
                      }
                      db.all(
                        `
                          SELECT t.id, t.title, t.created_at, s.name AS subject_name,
                                 COUNT(DISTINCT g.id) AS group_count,
                                 COUNT(DISTINCT m.user_id) AS member_count
                          FROM teamwork_tasks t
                          JOIN subjects s ON s.id = t.subject_id
                          LEFT JOIN teamwork_groups g ON g.task_id = t.id
                          LEFT JOIN teamwork_members m ON m.task_id = t.id
                          GROUP BY t.id
                          ORDER BY t.created_at DESC
                        `,
                        [],
                        (taskErr, teamworkTasks) => {
                          if (taskErr) {
                            return res.status(500).send('Database error');
                          }
                          db.all(
                            `
                              SELECT m.*, s.name AS subject_name, u.full_name AS created_by
                              FROM messages m
                              LEFT JOIN subjects s ON s.id = m.subject_id
                              LEFT JOIN users u ON u.id = m.created_by_id
                              ORDER BY m.created_at DESC
                              LIMIT 200
                            `,
                            [],
                            (msgErr, messages) => {
                              if (msgErr) {
                                return res.status(500).send('Database error');
                              }
                              res.render('admin', {
                                username: req.session.user.username,
                                userId: req.session.user.id,
                                schedule,
                                homework,
                                users,
                                subjects,
                                studentGroups,
                                logs,
                                teamworkTasks,
                                adminMessages: messages,
                                filters: {
                                  group_number: group_number || '',
                                  day: day || '',
                                  subject: subject || '',
                                  q: q || '',
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
                                messages: {
                                  error: req.query.err || '',
                                  success: req.query.ok || '',
                                },
                              });
                            }
                          );
                        }
                      );
                    }
                  );
                }
              );
            });
          }
        );
      });
    });
  });
});

app.get('/admin/users.json', requireAdmin, (req, res) => {
  const status = req.query.status;
  ensureUsersSchema(() => {
    const userFilter =
      status === 'inactive'
        ? 'WHERE is_active = 0'
        : status === 'all'
        ? ''
        : usersHasIsActive
        ? 'WHERE is_active = 1'
        : '';
    const cols = usersHasIsActive ? 'id, full_name, role, schedule_group, is_active, last_login_ip, last_user_agent, last_login_at'
      : 'id, full_name, role, schedule_group, last_login_ip, last_user_agent, last_login_at';
    db.all(
      `SELECT ${cols} FROM users ${userFilter} ORDER BY full_name`,
      (userErr, users) => {
        if (userErr) {
          return res.status(500).json({ error: 'Database error' });
        }
        db.all('SELECT * FROM subjects ORDER BY name', (subjectErr, subjects) => {
          if (subjectErr) {
            return res.status(500).json({ error: 'Database error' });
          }
          db.all(
            'SELECT student_id, subject_id, group_number FROM student_groups',
            (sgErr, studentGroups) => {
              if (sgErr) {
                return res.status(500).json({ error: 'Database error' });
              }
              res.json({ users, subjects, studentGroups });
            }
          );
        });
      }
    );
  });
});

app.get('/admin/export/schedule.csv', requireAdmin, (req, res) => {
  db.all(
    `
      SELECT se.id, s.name AS subject, se.group_number, se.day_of_week, se.class_number, se.week_number
      FROM schedule_entries se
      JOIN subjects s ON s.id = se.subject_id
      ORDER BY se.week_number, se.day_of_week, se.class_number
    `,
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

app.get('/admin/export/users.csv', requireAdmin, (req, res) => {
  db.all('SELECT id, full_name, role, schedule_group, is_active FROM users ORDER BY full_name', (err, rows) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    const header = 'id,full_name,role,schedule_group,is_active';
    const lines = rows.map((r) =>
      [r.id, r.full_name, r.role, r.schedule_group, r.is_active]
        .map((v) => `"${String(v ?? '').replace(/\"/g, '""')}"`)
        .join(',')
    );
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
    res.send([header, ...lines].join('\n'));
  });
});

app.get('/admin/export/subjects.csv', requireAdmin, (req, res) => {
  db.all('SELECT id, name, group_count, default_group FROM subjects ORDER BY name', (err, rows) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    const header = 'id,name,group_count,default_group';
    const lines = rows.map((r) =>
      [r.id, r.name, r.group_count, r.default_group]
        .map((v) => `"${String(v ?? '').replace(/\"/g, '""')}"`)
        .join(',')
    );
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="subjects.csv"');
    res.send([header, ...lines].join('\n'));
  });
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

app.post('/homework/add', requireLogin, upload.single('attachment'), (req, res) => {
  const {
    description,
    link_url,
    meeting_url,
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
  if (!daysOfWeek.includes(day_of_week) || classNum < 1 || classNum > 7 || groupNum < 1 || groupNum > 3) {
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(400).send('Invalid data');
  }

  const { schedule_group: group, username, id: userId } = req.session.user;
  const createdAt = new Date().toISOString();

  db.get('SELECT name FROM subjects WHERE id = ?', [subjectId], (subErr, subjectRow) => {
    if (subErr || !subjectRow) {
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }
      return res.status(400).send('Invalid subject');
    }

    db.run(
      `
        INSERT INTO homework
        (group_name, subject, day, time, class_number, subject_id, group_number, day_of_week, created_by_id, description, class_date, meeting_url, link_url, file_path, file_name, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        group,
        subjectRow.name,
        day_of_week,
        time,
        classNum,
        subjectId,
        groupNum,
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
      ],
      (err) => {
        if (err) {
          if (req.file) {
            fs.unlink(req.file.path, () => {});
          }
          return res.status(500).send('Database error');
        }
        return res.redirect('/schedule');
      }
    );
  });
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

app.post('/admin/schedule/add', requireAdmin, (req, res) => {
  const { subject_id, group_number, day_of_week, class_number, week_numbers } = req.body;
  const groupNum = Number(group_number);
  const classNum = Number(class_number);

  if (!subject_id || !day_of_week || !week_numbers || Number.isNaN(groupNum) || Number.isNaN(classNum)) {
    return res.redirect('/admin?err=Missing%20fields');
  }
  if (!daysOfWeek.includes(day_of_week)) {
    return res.redirect('/admin?err=Invalid%20day');
  }
  if (classNum < 1 || classNum > 7) {
    return res.redirect('/admin?err=Invalid%20class%20number');
  }

  const weeks = week_numbers
    .split(',')
    .map((w) => Number(w.trim()))
    .filter((w) => !Number.isNaN(w) && w >= 1 && w <= 15);
  const uniqueWeeks = Array.from(new Set(weeks));
  if (!uniqueWeeks.length) {
    return res.redirect('/admin?err=Invalid%20weeks');
  }

  const stmt = db.prepare(
    'INSERT INTO schedule_entries (subject_id, group_number, day_of_week, class_number, week_number) VALUES (?, ?, ?, ?, ?)'
  );
  uniqueWeeks.forEach((week) => {
    stmt.run(subject_id, groupNum, day_of_week, classNum, week);
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
    });
    return res.redirect('/admin?ok=Class%20added');
  });
});

app.post('/admin/schedule/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { subject_id, group_number, day_of_week, class_number, week_number } = req.body;
  const groupNum = Number(group_number);
  const classNum = Number(class_number);
  const weekNum = Number(week_number);

  if (!subject_id || !day_of_week || Number.isNaN(groupNum) || Number.isNaN(classNum) || Number.isNaN(weekNum)) {
    return res.redirect('/admin?err=Missing%20fields');
  }
  if (!daysOfWeek.includes(day_of_week)) {
    return res.redirect('/admin?err=Invalid%20day');
  }
  if (classNum < 1 || classNum > 7 || weekNum < 1 || weekNum > 15) {
    return res.redirect('/admin?err=Invalid%20class%20or%20week');
  }

  db.run(
    `
      UPDATE schedule_entries
      SET subject_id = ?, group_number = ?, day_of_week = ?, class_number = ?, week_number = ?
      WHERE id = ?
    `,
    [subject_id, groupNum, day_of_week, classNum, weekNum, id],
    (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'schedule_edit', { id, subject_id, group_number: groupNum, day_of_week, class_number: classNum, week_number: weekNum });
      return res.redirect('/admin?ok=Class%20updated');
    }
  );
});

app.post('/admin/schedule/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM schedule_entries WHERE id = ?', [id], (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'schedule_delete', { id });
    return res.redirect('/admin?ok=Class%20deleted');
  });
});

app.post('/admin/schedule/delete-multiple', requireAdmin, (req, res) => {
  const ids = req.body.delete_ids;
  if (!ids) {
    return res.redirect('/admin?err=No%20items%20selected');
  }
  const list = Array.isArray(ids) ? ids : [ids];
  const placeholders = list.map(() => '?').join(',');
  db.run(`DELETE FROM schedule_entries WHERE id IN (${placeholders})`, list, (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'schedule_delete_multiple', { ids: list });
    return res.redirect('/admin?ok=Selected%20classes%20deleted');
  });
});

app.post('/admin/schedule/clear-all', requireAdmin, (req, res) => {
  db.run('DELETE FROM schedule_entries', (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'schedule_clear_all');
    return res.redirect('/admin?ok=Schedule%20cleared');
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
  const { name, group_count, default_group, show_in_teamwork } = req.body;
  const count = Number(group_count);
  const def = Number(default_group);
  const teamworkFlag = String(show_in_teamwork) === '1' ? 1 : 0;
  if (!name || Number.isNaN(count) || count < 1 || count > 3) {
    return res.redirect('/admin?err=Invalid%20subject%20data');
  }
  if (Number.isNaN(def) || def < 1 || def > count) {
    return res.redirect('/admin?err=Invalid%20default%20group');
  }
  db.run(
    'INSERT INTO subjects (name, group_count, default_group, show_in_teamwork) VALUES (?, ?, ?, ?)',
    [name, count, def, teamworkFlag],
    (err) => {
    if (err) {
      return res.redirect('/admin?err=Database%20error');
    }
    logAction(db, req, 'subject_add', { name, group_count: count, default_group: def, show_in_teamwork: teamworkFlag });
    return res.redirect('/admin?ok=Subject%20added');
    }
  );
});

app.post('/admin/subjects/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, group_count, default_group, show_in_teamwork } = req.body;
  const count = Number(group_count);
  const def = Number(default_group);
  const teamworkFlag = String(show_in_teamwork) === '1' ? 1 : 0;
  if (!name || Number.isNaN(count) || count < 1 || count > 3) {
    return res.redirect('/admin?err=Invalid%20subject%20data');
  }
  if (Number.isNaN(def) || def < 1 || def > count) {
    return res.redirect('/admin?err=Invalid%20default%20group');
  }
  db.run(
    'UPDATE subjects SET name = ?, group_count = ?, default_group = ?, show_in_teamwork = ? WHERE id = ?',
    [name, count, def, teamworkFlag, id],
    (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'subject_edit', { id, name, group_count: count, default_group: def, show_in_teamwork: teamworkFlag });
      return res.redirect('/admin?ok=Subject%20updated');
    }
  );
});

app.post('/admin/subjects/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM student_groups WHERE subject_id = ?', [id], (delErr) => {
    if (delErr) {
      return res.redirect('/admin?err=Database%20error');
    }
    db.run('DELETE FROM subjects WHERE id = ?', [id], (err) => {
      if (err) {
        return res.redirect('/admin?err=Database%20error');
      }
      logAction(db, req, 'subject_delete', { id });
      return res.redirect('/admin?ok=Subject%20deleted');
    });
  });
});

app.post('/admin/student-groups/set', requireAdmin, (req, res) => {
  const { student_id, subject_id, group_number } = req.body;
  const groupNum = Number(group_number);
  if (!student_id || !subject_id || Number.isNaN(groupNum)) {
    return res.redirect('/admin?err=Invalid%20group%20assignment');
  }
  db.get('SELECT group_count FROM subjects WHERE id = ?', [subject_id], (err, subject) => {
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
    broadcast('users_updated');
    return res.redirect('/admin?ok=Subject%20removed');
  }
  );
});

app.post('/admin/users/role', requireAdmin, (req, res) => {
  const { user_id, role } = req.body;
  if (!user_id || !role || !['student', 'admin', 'starosta'].includes(role)) {
    return res.redirect('/admin?err=Invalid%20role');
  }
  const currentId = req.session.user.id;
  if (Number(user_id) === Number(currentId)) {
    return res.redirect('/admin?err=Cannot%20change%20your%20own%20role');
  }
  db.get('SELECT role FROM users WHERE id = ?', [user_id], (err, user) => {
    if (err || !user) {
      return res.redirect('/admin?err=User%20not%20found');
    }
    if (user.role === 'admin' && role === 'student') {
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
    'UPDATE users SET password_hash = ?, password = ? WHERE id = ?',
    [hash, new_password, user_id],
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
  if (!ids) {
    return res.redirect('/admin?err=No%20users%20selected');
  }
  const list = Array.isArray(ids) ? ids : [ids];
  const placeholders = list.map(() => '?').join(',');
  db.all(
    `SELECT id, role FROM users WHERE id IN (${placeholders})`,
    list,
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
  db.all('SELECT id FROM users WHERE role != ?', ['admin'], (err, rows) => {
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
  if (!user_id) {
    return res.status(400).json({ error: 'Missing user_id' });
  }
  db.get('SELECT role, full_name FROM users WHERE id = ?', [user_id], (err, user) => {
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
  if (!user_id) {
    return res.status(400).json({ error: 'Missing user_id' });
  }
  db.run('UPDATE users SET is_active = 1 WHERE id = ?', [user_id], (updErr) => {
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
  if (Number.isNaN(userId)) {
    return res.redirect('/admin?err=Invalid%20user');
  }
  try {
    const user = await db.get('SELECT role FROM users WHERE id = ?', [userId]);
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

const startServer = () => {
  server.listen(PORT, () => console.log(`Listening on ${PORT}`));
  ensureDbReady().catch((err) => {
    console.error('Failed to initialize database', err);
  });
};

startServer();
