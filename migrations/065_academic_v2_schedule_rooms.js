const ddl = [
  `
    ALTER TABLE academic_v2_schedule_entries
    ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL
  `,
  `
    CREATE INDEX IF NOT EXISTS academic_v2_schedule_entries_room_idx
    ON academic_v2_schedule_entries (room_id, term_id, week_number)
  `,
  `
    UPDATE academic_v2_schedule_entries current_entry
    SET room_id = legacy_entry.room_id
    FROM schedule_entries legacy_entry
    WHERE current_entry.legacy_schedule_entry_id = legacy_entry.id
      AND current_entry.room_id IS NULL
      AND legacy_entry.room_id IS NOT NULL
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '065_academic_v2_schedule_rooms',
  up,
};
