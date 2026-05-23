const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  normalizeScheduleGeneratorOperationId,
  resolveScheduleGeneratorBackupPath,
} = require('../lib/scheduleGeneratorBackups');

test('normalizes UUID-shaped schedule generator operation ids', () => {
  assert.equal(
    normalizeScheduleGeneratorOperationId('  7D444840-9DC0-11D1-B245-5FFDCE74FAD2  '),
    '7d444840-9dc0-11d1-b245-5ffdce74fad2'
  );
  assert.equal(normalizeScheduleGeneratorOperationId(''), '');
});

test('rejects non-UUID and traversal operation ids', () => {
  for (const value of [
    'abc',
    '../version',
    '../../tmp/pwn',
    '..\\..\\tmp\\pwn',
    '/tmp/pwn',
    '7d444840-9dc0-11d1-b245-5ffdce74fad2/../../pwn',
    '7d444840-9dc0-11d1-b245-5ffdce74fad2.csv',
  ]) {
    assert.equal(normalizeScheduleGeneratorOperationId(value), null);
  }
});

test('resolves backup CSV path inside the generator backup directory', () => {
  const uploadsDir = path.join('/tmp', 'kma-uploads');
  const backup = resolveScheduleGeneratorBackupPath({
    uploadsDir,
    operationId: '7d444840-9dc0-11d1-b245-5ffdce74fad2',
  });

  assert.equal(backup.filename, 'schedule-backup-7d444840-9dc0-11d1-b245-5ffdce74fad2.csv');
  assert.equal(backup.backupDir, path.resolve(uploadsDir, 'generator-backups'));
  assert.equal(
    backup.path,
    path.resolve(uploadsDir, 'generator-backups', 'schedule-backup-7d444840-9dc0-11d1-b245-5ffdce74fad2.csv')
  );
  assert.equal(backup.path.startsWith(`${backup.backupDir}${path.sep}`), true);
});

test('does not resolve invalid backup CSV paths', () => {
  assert.equal(
    resolveScheduleGeneratorBackupPath({
      uploadsDir: path.join('/tmp', 'kma-uploads'),
      operationId: '../../../version',
    }),
    null
  );
});
