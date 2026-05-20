const statements = [
  `
    ALTER TABLE user_registration_events
    DROP CONSTRAINT IF EXISTS user_registration_events_source_check
  `,
  `
    ALTER TABLE user_registration_events
    ADD CONSTRAINT user_registration_events_source_check
    CHECK (source IN ('register_form', 'import', 'admin_create', 'telegram_mini_auto_register'))
  `,
];

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '061_telegram_registration_event_source',
  up,
};
