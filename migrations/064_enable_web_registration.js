async function up(pool) {
  await pool.query(
    `
      INSERT INTO settings (key, value)
      VALUES ('web_registration_enabled', 'true')
      ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
    `
  );
}

module.exports = {
  id: '064_enable_web_registration',
  up,
};
