const LEGACY_BROADCAST_BODIES = [
  'Будуть глобальні оновлення найближчим часом, очікуйте подробиць після релізу.',
  'Фікс був успішно зроблен, дані збережені. Також були зроблені апдейти для вашої зручності, візуальні та технічні зміни. По будь-яким питанням або багам - звертайтесь.',
  'Добрий вечір Були зроблені великі зміни і на жаль через це розклад частково зник. Очікуваний час фіксу 2-3 години.',
];

function normalizeBody(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim();
}

async function up(pool) {
  const normalizedBodies = LEGACY_BROADCAST_BODIES.map(normalizeBody).filter(Boolean);
  if (!normalizedBodies.length) {
    return;
  }

  await pool.query(
    `
      DELETE FROM messages
      WHERE target_all = 1
        AND subject_id IS NULL
        AND group_number IS NULL
        AND regexp_replace(BTRIM(COALESCE(body, '')), '\s+', ' ', 'g') = ANY($1::text[])
    `,
    [normalizedBodies]
  );
}

module.exports = {
  id: '038_message_archive_cleanup',
  up,
};
