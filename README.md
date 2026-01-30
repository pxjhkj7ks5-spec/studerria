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
