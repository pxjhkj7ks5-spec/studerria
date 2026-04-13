const ddl = [
  `
    ALTER TABLE admin_change_audit
    DROP CONSTRAINT IF EXISTS admin_change_audit_course_id_fkey
  `,
  `
    ALTER TABLE admin_change_audit
    DROP CONSTRAINT IF EXISTS admin_change_audit_created_by_fkey
  `,
  `
    ALTER TABLE admin_change_audit
    DROP CONSTRAINT IF EXISTS admin_change_audit_rolled_back_by_fkey
  `,
  `
    ALTER TABLE admin_change_audit
    DROP CONSTRAINT IF EXISTS admin_change_audit_actor_user_id_fkey
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '050_admin_change_audit_append_only_fk_cleanup',
  up,
};
