'use strict';

async function up(pool) {
  await pool.query(`
    INSERT INTO access_permissions (key, label, category)
    VALUES ('osint-access', 'Social Graph: доступ', 'internal_service')
    ON CONFLICT (key) DO UPDATE SET label=EXCLUDED.label, category=EXCLUDED.category
  `);
  await pool.query(`
    INSERT INTO access_role_permissions (role_id, permission_id, allowed, created_at, updated_at)
    SELECT r.id, p.id, true, NOW(), NOW()
    FROM access_roles r JOIN access_permissions p ON p.key='osint-access'
    WHERE r.key='admin'
    ON CONFLICT (role_id,permission_id) DO NOTHING
  `);
}

module.exports = { id: '075_osint_access_permission', up };
