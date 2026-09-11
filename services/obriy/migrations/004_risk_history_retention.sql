CREATE INDEX IF NOT EXISTS risk_assessments_created_idx
  ON obriy.risk_assessments(created_at);
CREATE INDEX IF NOT EXISTS risk_assessments_zone_track_created_idx
  ON obriy.risk_assessments(zone_id, track_id, created_at DESC);
