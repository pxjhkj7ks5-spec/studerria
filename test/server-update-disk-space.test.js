const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const source = fs.readFileSync('scripts/server-update.sh', 'utf8');
const check = source.slice(source.indexOf('minimum_free_kb='), source.indexOf('compose_up='));

function run(freeBefore, freeAfter, minimum = '5242880') {
  return spawnSync('bash', ['-c', `
    set -euo pipefail
    BACKUP_DIR=/tmp
    MIN_FREE_DISK_KB=${minimum}
    backed_up=0
    ensure_backup_dir() { :; }
    docker() { echo /tmp; }
    df() { if [ "$backed_up" = 0 ]; then echo 'disk 1 1 ${freeBefore} 1% /tmp'; else echo 'disk 1 1 ${freeAfter} 1% /tmp'; fi; }
    backup_stateful_data() { echo BACKUP; backed_up=1; }
    ${check}
    echo BUILD_ALLOWED
  `], { encoding: 'utf8' });
}

test('low disk fails before creating another backup', () => {
  const result = run(100, 100);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Insufficient free disk space/);
  assert.doesNotMatch(result.stdout, /BACKUP|BUILD_ALLOWED/);
});
test('backup consuming remaining headroom prevents image build', () => {
  const result = run(9000000, 100);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /BACKUP/);
  assert.doesNotMatch(result.stdout, /BUILD_ALLOWED/);
});
test('adequate disk allows backup and build', () => {
  const result = run(9000000, 8000000);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /BUILD_ALLOWED/);
});
test('invalid threshold fails clearly', () => {
  assert.equal(run(9000000, 8000000, 'invalid').status, 2);
});
