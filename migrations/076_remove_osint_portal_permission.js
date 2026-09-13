'use strict';

async function up(pool) {
  await pool.query(`
    DELETE FROM access_role_permissions
    WHERE permission_id IN (SELECT id FROM access_permissions WHERE key = 'osint-access')
  `);
  await pool.query("DELETE FROM access_permissions WHERE key = 'osint-access'");
}

module.exports = { id: '076_remove_osint_portal_permission', up };
