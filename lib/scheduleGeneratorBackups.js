const path = require('path');

const SCHEDULE_GENERATOR_OPERATION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const normalizeScheduleGeneratorOperationId = (value) => {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) return '';
  return SCHEDULE_GENERATOR_OPERATION_ID_PATTERN.test(normalized) ? normalized : null;
};

const resolveScheduleGeneratorBackupPath = ({ uploadsDir, operationId }) => {
  const normalizedOperationId = normalizeScheduleGeneratorOperationId(operationId);
  if (!normalizedOperationId) return null;

  const backupDir = path.resolve(uploadsDir, 'generator-backups');
  const filename = `schedule-backup-${normalizedOperationId}.csv`;
  const filePath = path.resolve(backupDir, filename);
  const isInsideBackupDir = filePath === backupDir || filePath.startsWith(`${backupDir}${path.sep}`);
  if (!isInsideBackupDir) return null;

  return {
    operationId: normalizedOperationId,
    backupDir,
    filename,
    path: filePath,
  };
};

module.exports = {
  normalizeScheduleGeneratorOperationId,
  resolveScheduleGeneratorBackupPath,
};
