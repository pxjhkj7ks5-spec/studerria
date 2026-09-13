'use strict';

// Historical migration id retained so existing migration histories remain
// compatible. Social Graph authentication is owned by the isolated service.
async function up() {}

module.exports = { id: '075_osint_access_permission', up };
