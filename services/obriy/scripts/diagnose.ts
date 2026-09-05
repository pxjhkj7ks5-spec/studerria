import { loadConfig } from "../src/config.js";
import { Store } from "../src/store.js";
import type { RiskAssessment } from "../src/engine/types.js";

// Operator-only aggregate diagnostics: never print keys, chat IDs, names or coordinates.
const config = loadConfig(),
  store = new Store(config);
try {
  const [users, zones, outbox, tracks, assessments] = await Promise.all([
    store.pool.query(
      "SELECT count(*)::int total,count(*) FILTER(WHERE chat_enc IS NOT NULL)::int linked,count(*) FILTER(WHERE paused_until>now())::int paused FROM obriy.users",
    ),
    store.pool.query(
      "SELECT count(*)::int total,count(*) FILTER(WHERE enabled)::int enabled FROM obriy.zones",
    ),
    store.pool.query(
      "SELECT category,status,last_error_code,count(*)::int count,max(created_at) AS latest FROM obriy.notification_outbox WHERE created_at>now()-interval '24 hours' GROUP BY category,status,last_error_code ORDER BY category,status",
    ),
    store.pool.query(
      "SELECT count(*)::int active,count(*) FILTER(WHERE data#>>'{motion,speedKmh}' IS NOT NULL)::int with_motion,count(*) FILTER(WHERE data->>'advisory'='true')::int advisory FROM obriy.tracks WHERE status='active'",
    ),
    store.pool.query("SELECT zone_id,assessment_enc FROM obriy.alert_state"),
  ]);
  const levels: Record<string, number> = {},
    reasons: Record<string, number> = {};
  let eligible = 0;
  for (const row of assessments.rows) {
    const a = store.vault.decrypt<RiskAssessment>(
      row.assessment_enc,
      `assessment:${row.zone_id}`,
    );
    levels[a.level] = (levels[a.level] ?? 0) + 1;
    if (a.escalationAllowed) eligible++;
    for (const reason of a.explanationCodes)
      reasons[reason] = (reasons[reason] ?? 0) + 1;
  }
  console.log(
    "OBRIY_DIAG=" +
      JSON.stringify({
        telegramConfigured: Boolean(config.OBRIY_TELEGRAM_BOT_TOKEN),
        telegramMode: config.OBRIY_TELEGRAM_MODE,
        users: users.rows[0],
        zones: zones.rows[0],
        tracks: tracks.rows[0],
        outbox: outbox.rows,
        assessmentLevels: levels,
        escalationAllowed: eligible,
        assessmentReasons: reasons,
      }),
  );
} catch {
  console.log(
    "OBRIY_DIAG=" +
      JSON.stringify({
        error: "Diagnostic query failed; no private details emitted.",
      }),
  );
  process.exitCode = 1;
} finally {
  await store.close();
}
