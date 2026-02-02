# studerria
Student portal (Node.js + Express + EJS + Postgres on Cloud Run).

## CI/CD (GitHub Actions → Cloud Run)
Secrets to add in GitHub:
- `GCP_PROJECT_ID`
- `GCP_SA_KEY`
- `GCP_REGION`
- `SERVICE_NAME`
- `INSTANCE_CONNECTION_NAME`

Workflow lives at `.github/workflows/deploy.yml`.

## Cloud SQL backup to GCS
Example (Postgres):
```bash
gcloud sql export sql student-portal-db gs://YOUR_BUCKET/backups/student_portal_$(date +%F).sql \
  --database=student_portal \
  --project=project-25b725c0-e6f6-4253-afa
```

## Group Context (Kyiv / Munich)
- `groups` table is the top-level context; users have `users.group_id`.
- Content is scoped by `group_id + course_id + semester_id` where applicable (schedule, subjects, homework, teamwork, messages, logs).
- Onboarding flow: register → course → group → subjects.
- Admin UI: group selector sits next to course selector; admin context stored in session (`adminGroup`).
- If a user has no `group_id`, they are redirected to `/onboarding/group`.
