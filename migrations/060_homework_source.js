const statements = [
  "ALTER TABLE homework ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'web'",
  "UPDATE homework SET source = 'web' WHERE source IS NULL OR source = ''",
  'CREATE INDEX IF NOT EXISTS idx_homework_source ON homework (source)',
];

module.exports = {
  id: '060_homework_source',
  statements,
};
