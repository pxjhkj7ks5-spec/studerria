DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = 'cloudsqlsuperuser'
  ) THEN
    CREATE ROLE cloudsqlsuperuser;
  END IF;
END
$$;
