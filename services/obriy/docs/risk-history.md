# Risk history storage

Current assessments remain in `obriy.alert_state` and continue to update on every evaluation.
Historical risk snapshots are sampled at most once per five minutes per zone/track.
`OBRIY_RISK_RETENTION_HOURS` defaults to 24 (range 1–72), independently of notification/audit retention.

Startup and hourly cleanup delete expired history in up to 20 batches of 5000 rows,
outside the transaction that locks users. A larger backlog takes multiple runs.
Existing snapshots older than the configured window are permanently removed after deployment.
Normal PostgreSQL vacuum makes deleted space reusable; it does not guarantee an immediate
drop in filesystem usage. Do not run VACUUM FULL automatically on the shared production database.
