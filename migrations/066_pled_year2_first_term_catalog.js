const { alignPledYear2FirstTermCatalog } = require('../lib/academicV2');

async function up(pool) {
  await alignPledYear2FirstTermCatalog({
    withTransaction: async (work) => {
      const client = await pool.connect();
      const query = (sql, params = []) => {
        let index = 0;
        return client.query(sql.replace(/\?/g, () => `$${++index}`), params);
      };
      try {
        await client.query('BEGIN');
        const result = await work({
          all: async (sql, params) => (await query(sql, params)).rows,
          get: async (sql, params) => (await query(sql, params)).rows[0] || null,
          run: async (sql, params) => query(sql, params),
        });
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },
  });
}

module.exports = { id: '066_pled_year2_first_term_catalog', up };
