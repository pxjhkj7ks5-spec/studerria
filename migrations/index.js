const fs = require('fs');
const path = require('path');

const migrationFilePattern = /^\d{3}_[a-z0-9_]+\.js$/;

const migrations = fs.readdirSync(__dirname)
  .filter((fileName) => migrationFilePattern.test(fileName))
  .sort((left, right) => left.localeCompare(right, 'en'))
  .map((fileName) => require(path.join(__dirname, fileName)));

const migrationIds = migrations.map((migration) => String(migration?.id || '').trim());
const duplicateIds = migrationIds.filter((id, index) => !id || migrationIds.indexOf(id) !== index);

if (duplicateIds.length) {
  throw new Error(`Invalid migration catalog: ${[...new Set(duplicateIds)].join(', ')}`);
}

module.exports = migrations;
