async function getStudentSubjectChoiceSummary(store) {
  const row = await store.get(`
    SELECT
      (SELECT COUNT(*)::int FROM student_groups) AS selections,
      (SELECT COUNT(*)::int FROM user_subject_optouts) AS optouts,
      (SELECT COUNT(*)::int FROM (
        SELECT student_id AS user_id FROM student_groups
        UNION
        SELECT user_id FROM user_subject_optouts
      ) affected) AS users
  `);
  return {
    users: Number(row && row.users || 0),
    selections: Number(row && row.selections || 0),
    optouts: Number(row && row.optouts || 0),
  };
}

async function resetAllStudentSubjectChoices(store, { actorTelegramId } = {}) {
  const actorId = String(actorTelegramId || '').trim();
  if (!/^[1-9]\d*$/.test(actorId)) throw new Error('RESET_ACTOR_REQUIRED');
  if (!store || typeof store.withTransaction !== 'function') throw new Error('RESET_TRANSACTION_REQUIRED');

  return store.withTransaction(async (tx) => {
    await tx.run("SET LOCAL lock_timeout = '5s'");
    await tx.run("SET LOCAL statement_timeout = '30s'");
    // Prevent selection writes between the recovery snapshot and deletion.
    await tx.run('LOCK TABLE student_groups, user_subject_optouts IN SHARE ROW EXCLUSIVE MODE');
    const selections = await tx.all('SELECT id, student_id, subject_id, group_number FROM student_groups ORDER BY id');
    const optouts = await tx.all('SELECT id, user_id, subject_id, created_at FROM user_subject_optouts ORDER BY id');
    const summary = {
      users: new Set([...selections.map((row) => row.student_id), ...optouts.map((row) => row.user_id)]).size,
      selections: selections.length,
      optouts: optouts.length,
    };
    const actor = await tx.get('SELECT id, full_name FROM users WHERE telegram_id = ? LIMIT 1', [actorId]);
    // The audit and complete recovery snapshot must commit together with the reset.
    const audit = await tx.get(`
      INSERT INTO history_log (actor_id, actor_name, action, details, created_at, course_id)
      VALUES (?, ?, ?, ?, ?, NULL)
      RETURNING id
    `, [
      actor ? actor.id : null,
      actor ? actor.full_name : 'Telegram dev',
      'telegram_dev_reset_subjects_all',
      JSON.stringify({ actor_telegram_id: actorId, ...summary, backup: { student_groups: selections, user_subject_optouts: optouts } }),
      new Date().toISOString(),
    ]);
    if (selections.length) {
      await tx.run('DELETE FROM student_groups WHERE id = ANY(?::int[])', [selections.map((row) => row.id)]);
    }
    if (optouts.length) {
      await tx.run('DELETE FROM user_subject_optouts WHERE id = ANY(?::int[])', [optouts.map((row) => row.id)]);
    }
    return { ...summary, auditId: Number(audit.id) };
  });
}

module.exports = { getStudentSubjectChoiceSummary, resetAllStudentSubjectChoices };
