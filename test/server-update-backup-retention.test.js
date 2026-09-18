const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = process.cwd();
const source = fs.readFileSync('scripts/server-update.sh', 'utf8');
const functions = source.slice(source.indexOf('timestamp()'), source.indexOf('wait_for_service_ready()'));

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'backup-retention-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function backup(dir, day, label = 'postgres', managed = true, extension = 'dump') {
  const file = path.join(dir, `${label}-202609${String(day).padStart(2, '0')}T120000Z.${extension}`);
  fs.writeFileSync(file, 'backup data');
  if (managed) fs.writeFileSync(`${file}.complete`, '');
  return file;
}
function rotate(file, keep = 5) {
  return spawnSync('python3', ['scripts/rotate-update-backups.py', file, '--keep', String(keep)], { encoding: 'utf8' });
}

test('keeps newest five of same label; preserves historical, other services and pins', (t) => {
  const dir = fixture(t);
  const files = Array.from({ length: 8 }, (_, i) => backup(dir, i + 1));
  fs.writeFileSync(`${files[0]}.keep`, '');
  const historical = backup(dir, 9, 'postgres', false);
  const other = backup(dir, 1, 'osint-postgres');
  assert.equal(rotate(files[7]).status, 0);
  assert.ok(fs.existsSync(files[0]));
  assert.ok(!fs.existsSync(files[1]));
  assert.ok(!fs.existsSync(`${files[1]}.complete`));
  assert.ok(!fs.existsSync(files[2]));
  for (const file of [...files.slice(3), historical, other]) assert.ok(fs.existsSync(file));
});

test('custom limit rotates volume archives without touching partial files or directories', (t) => {
  const dir = fixture(t);
  const old = backup(dir, 1, 'osix-data', true, 'tgz');
  const latest = backup(dir, 2, 'osix-data', false, 'tgz');
  fs.writeFileSync(path.join(dir, '.osix.partial'), 'partial');
  fs.mkdirSync(path.join(dir, 'recovery'));
  assert.equal(rotate(latest, 1).status, 0);
  assert.ok(!fs.existsSync(old));
  assert.ok(fs.existsSync(`${latest}.complete`));
  assert.ok(fs.existsSync(path.join(dir, '.osix.partial')));
  assert.ok(fs.existsSync(path.join(dir, 'recovery')));
});

test('empty backups, symlinks and invalid limits cannot trigger deletion', (t) => {
  const dir = fixture(t);
  const old = backup(dir, 1);
  const empty = backup(dir, 2, 'postgres', false);
  fs.truncateSync(empty);
  assert.notEqual(rotate(empty, 1).status, 0);
  fs.unlinkSync(empty);
  fs.symlinkSync(old, empty);
  assert.notEqual(rotate(empty, 1).status, 0);
  assert.notEqual(rotate(old, 0).status, 0);
  assert.ok(fs.existsSync(old));
  assert.ok(!fs.existsSync(`${empty}.complete`));
});

function runBackup(dir, failure = false, skip = false) {
  return spawnSync('bash', ['-c', `
    set -euo pipefail
    SERVICE=osint
    BACKUP_DATA=${skip ? 0 : 1}
    BACKUP_KEEP_COUNT=1
    docker() {
      if [ "$3" = ps ]; then echo container; return; fi
      printf 'new dump'
      return ${failure ? 1 : 0}
    }
    ${functions}
    backup_stateful_data
  `], { encoding: 'utf8', env: { ...process.env, ROOT_DIR: root, BACKUP_DIR: dir } });
}

test('failed and skipped dumps preserve all old backups and remove failed partial', (t) => {
  const dir = fixture(t);
  const old = backup(dir, 1, 'osint-postgres');
  assert.notEqual(runBackup(dir, true).status, 0);
  assert.equal(runBackup(dir, false, true).status, 0);
  assert.deepEqual(fs.readdirSync(dir).sort(), [path.basename(old), `${path.basename(old)}.complete`].sort());
});

test('successful dump publishes complete archive before rotation', (t) => {
  const dir = fixture(t);
  const old = backup(dir, 1, 'osint-postgres');
  const result = runBackup(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!fs.existsSync(old));
  const dumps = fs.readdirSync(dir).filter(name => name.endsWith('.dump'));
  assert.equal(dumps.length, 1);
  assert.equal(fs.readFileSync(path.join(dir, dumps[0]), 'utf8'), 'new dump');
  assert.ok(fs.existsSync(path.join(dir, `${dumps[0]}.complete`)));
  assert.ok(!fs.readdirSync(dir).some(name => name.endsWith('.partial')));
});

test('volume failure preserves old archives; success publishes and rotates', (t) => {
  const dir = fixture(t);
  const old = backup(dir, 1, 'osix-data', true, 'tgz');
  function run(fail) {
    return spawnSync('bash', ['-c', `
      set -euo pipefail
      BACKUP_KEEP_COUNT=1
      docker() {
        if [ "$1" = compose ]; then echo container; return; fi
        if [ "$1" = inspect ]; then echo test-volume; return; fi
        for file in "$BACKUP_DIR"/*.partial "$BACKUP_DIR"/.*.partial; do
          [ -f "$file" ] || continue
          printf 'archive' > "$file"
        done
        return ${fail ? 1 : 0}
      }
      ${functions}
      backup_compose_volume_mount osix /data osix-data
    `], { encoding: 'utf8', env: { ...process.env, ROOT_DIR: root, BACKUP_DIR: dir } });
  }
  assert.equal(run(true).status, 0);
  assert.ok(fs.existsSync(old));
  assert.ok(!fs.readdirSync(dir).some(name => name.endsWith('.partial')));
  const result = run(false);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!fs.existsSync(old));
  assert.equal(fs.readdirSync(dir).filter(name => name.endsWith('.tgz')).length, 1);
});

test('timestamp collisions never overwrite a previous backup', (t) => {
  const dir = fixture(t);
  const file = backup(dir, 1);
  const partial = path.join(dir, '.new.partial');
  fs.writeFileSync(partial, 'replacement');
  const result = spawnSync('bash', ['-c', `set -euo pipefail\n${functions}\nfinish_backup "$PARTIAL" "$FINAL"`], {
    encoding: 'utf8', env: { ...process.env, PARTIAL: partial, FINAL: file },
  });
  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(file, 'utf8'), 'backup data');
});
