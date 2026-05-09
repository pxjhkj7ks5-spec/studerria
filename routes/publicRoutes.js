function registerPublicRoutes(app, deps) {
  const {
    getPreferredLang,
    buildLoginErrorMessage,
    publicLegalPages,
    pool,
    createRateLimiter,
    getClientIp,
    readLimiter,
    writeLimiter,
  } = deps;

  const MB_USERS = {
    chatma: { id: 'userA', displayName: 'Person A' },
    chatmb: { id: 'userB', displayName: 'Person B' },
  };
  const MB_USER_IDS = ['userA', 'userB'];
  const MB_ANIMATION_TYPES = new Set(['soft-glow', 'clouds', 'sparkles', 'tiny-faces']);
  const passThrough = (_req, _res, next) => next();
  const mbReadLimiter = typeof readLimiter === 'function' ? readLimiter : passThrough;
  const mbWriteLimiter = typeof writeLimiter === 'function' ? writeLimiter : passThrough;
  const mbLoginLimiter = typeof createRateLimiter === 'function' && pool
    ? createRateLimiter({
      pool,
      windowMs: 60 * 1000,
      max: 12,
      keyFn: (req) => `mb-auth:${typeof getClientIp === 'function' ? getClientIp(req) : req.ip}`,
      onLimit: (_req, res) => res.status(429).json({ ok: false, error: 'too_many_requests' }),
    })
    : passThrough;

  function getOtherMbUserId(userId) {
    return userId === 'userA' ? 'userB' : 'userA';
  }

  function normalizeMbUserId(value) {
    const normalized = String(value || '').trim();
    return MB_USER_IDS.includes(normalized) ? normalized : '';
  }

  function normalizeMbMessage(value) {
    return String(value || '').replace(/\r\n/g, '\n').trim().slice(0, 800);
  }

  function normalizeMbAnimation(value) {
    const normalized = String(value || '').trim();
    return MB_ANIMATION_TYPES.has(normalized) ? normalized : 'soft-glow';
  }

  function normalizeMbAvatarUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    if (raw.length > 1000) {
      throw new Error('invalid_avatar_url');
    }
    let parsed;
    try {
      parsed = new URL(raw);
    } catch (_error) {
      throw new Error('invalid_avatar_url');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('invalid_avatar_url');
    }
    return parsed.toString();
  }

  async function ensureMbProfiles() {
    await pool.query(
      `
        INSERT INTO mb_profiles (key_name, display_name, avatar_url, message_for_me, animation_type, updated_by)
        VALUES
          ('userA', $1, NULL, '', 'soft-glow', NULL),
          ('userB', $2, NULL, '', 'soft-glow', NULL)
        ON CONFLICT (key_name) DO NOTHING
      `,
      [MB_USERS.chatma.displayName, MB_USERS.chatmb.displayName]
    );
  }

  async function loadMbProfiles() {
    await ensureMbProfiles();
    const result = await pool.query(
      `
        SELECT key_name, display_name, avatar_url, message_for_me, animation_type, updated_by, updated_at
        FROM mb_profiles
        WHERE key_name = ANY($1::text[])
      `,
      [MB_USER_IDS]
    );
    return new Map(result.rows.map((row) => [row.key_name, row]));
  }

  function serializeMbProfile(row) {
    return {
      displayName: row.display_name,
      avatarUrl: row.avatar_url || '',
    };
  }

  function formatMbDate(value) {
    const date = value ? new Date(value) : new Date();
    if (Number.isNaN(date.getTime())) return 'сьогодні';
    try {
      return new Intl.DateTimeFormat('uk-UA', {
        timeZone: 'Europe/Kyiv',
        day: 'numeric',
        month: 'long',
      }).format(date);
    } catch (_error) {
      return 'сьогодні';
    }
  }

  async function buildMbState(req) {
    const currentUserId = normalizeMbUserId(req.session?.mbUser);
    if (!currentUserId) {
      return { ok: true, authenticated: false };
    }

    const profiles = await loadMbProfiles();
    const current = profiles.get(currentUserId);
    const other = profiles.get(getOtherMbUserId(currentUserId));
    if (!current || !other) {
      if (req.session) delete req.session.mbUser;
      return { ok: true, authenticated: false };
    }

    return {
      ok: true,
      authenticated: true,
      currentUser: serializeMbProfile(current),
      otherUser: serializeMbProfile(other),
      receivedMessage: {
        text: current.message_for_me || '',
        animationType: normalizeMbAnimation(current.animation_type),
        updatedAt: current.updated_at || null,
        updatedAtLabel: formatMbDate(current.updated_at),
      },
      draftForOther: {
        text: other.message_for_me || '',
        animationType: normalizeMbAnimation(other.animation_type),
      },
    };
  }

  function requireMbSession(req, res, next) {
    if (!normalizeMbUserId(req.session?.mbUser)) {
      return res.status(401).json({ ok: false, error: 'not_authenticated' });
    }
    return next();
  }

  function sendMbError(res, err) {
    if (err && err.message === 'invalid_avatar_url') {
      return res.status(400).json({ ok: false, error: 'invalid_avatar_url' });
    }
    return res.status(500).json({ ok: false, error: 'mb_unavailable' });
  }

  app.get('/', (req, res) => {
    if (req.session && req.session.user) {
      return res.redirect('/home');
    }
    const lang = getPreferredLang(req);
    const loginErrorText = buildLoginErrorMessage(lang, req.query.error);
    res.render('login', {
      error: Boolean(loginErrorText),
      loginErrorText,
      layout: false,
    });
  });

  app.get('/login', (req, res) => {
    if (req.session && req.session.user) {
      return res.redirect('/home');
    }
    const lang = getPreferredLang(req);
    const loginErrorText = buildLoginErrorMessage(lang, req.query.error);
    res.render('login', {
      error: Boolean(loginErrorText),
      loginErrorText,
      layout: false,
    });
  });

  app.get(['/terms', '/privacy'], (req, res) => {
    const lang = getPreferredLang(req);
    const legalLang = lang === 'en' ? 'en' : 'uk';
    const key = req.path === '/privacy' ? 'privacy' : 'terms';
    return res.render('legal', {
      ...publicLegalPages[legalLang][key],
      layout: false,
    });
  });

  app.get('/changelog', (req, res) => res.render('changelog', { layout: false }));

  app.get('/mb', (_req, res) => res.render('mb', { layout: false }));

  app.post('/mb/login', mbLoginLimiter, async (req, res) => {
    const password = String(req.body?.password || '');
    const profile = Object.prototype.hasOwnProperty.call(MB_USERS, password)
      ? MB_USERS[password]
      : null;

    if (!profile) {
      return res.status(401).json({ ok: false, error: 'invalid_key' });
    }

    try {
      req.session.mbUser = profile.id;
      await ensureMbProfiles();
      return res.json(await buildMbState(req));
    } catch (err) {
      return sendMbError(res, err);
    }
  });

  app.post('/mb/logout', mbWriteLimiter, (req, res) => {
    if (req.session) {
      delete req.session.mbUser;
    }
    return res.json({ ok: true, authenticated: false });
  });

  app.get('/mb/api/state', mbReadLimiter, async (req, res) => {
    try {
      return res.json(await buildMbState(req));
    } catch (err) {
      return sendMbError(res, err);
    }
  });

  app.post('/mb/api/message', mbWriteLimiter, requireMbSession, async (req, res) => {
    const currentUserId = normalizeMbUserId(req.session?.mbUser);
    const targetUserId = getOtherMbUserId(currentUserId);
    const text = normalizeMbMessage(req.body?.text);
    const animationType = normalizeMbAnimation(req.body?.animationType);

    try {
      await ensureMbProfiles();
      await pool.query(
        `
          UPDATE mb_profiles
          SET message_for_me = $1,
              animation_type = $2,
              updated_by = $3,
              updated_at = NOW()
          WHERE key_name = $4
        `,
        [text, animationType, currentUserId, targetUserId]
      );
      return res.json(await buildMbState(req));
    } catch (err) {
      return sendMbError(res, err);
    }
  });

  app.post('/mb/api/avatar', mbWriteLimiter, requireMbSession, async (req, res) => {
    const currentUserId = normalizeMbUserId(req.session?.mbUser);
    let avatarUrl = '';
    try {
      avatarUrl = normalizeMbAvatarUrl(req.body?.avatarUrl);
      await ensureMbProfiles();
      await pool.query(
        `
          UPDATE mb_profiles
          SET avatar_url = $1,
              updated_at = NOW()
          WHERE key_name = $2
        `,
        [avatarUrl || null, currentUserId]
      );
      return res.json(await buildMbState(req));
    } catch (err) {
      return sendMbError(res, err);
    }
  });
}

module.exports = {
  registerPublicRoutes,
};
