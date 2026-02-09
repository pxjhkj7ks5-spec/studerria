const ddl = [
  'ALTER TABLE schedule_generator_entries ADD COLUMN IF NOT EXISTS item_id INTEGER REFERENCES schedule_generator_items(id) ON DELETE SET NULL',
  'CREATE INDEX IF NOT EXISTS schedule_generator_entries_item_idx ON schedule_generator_entries(item_id)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '008_schedule_generator_entry_item',
  up,
};
