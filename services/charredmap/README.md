# charredmap

When this project is vendored inside the Studerria repository, the primary runtime is the root `docker/local` stack, where Studerria proxies `/charredmap` to this service. The standalone `docker/studerria` files below remain as service-level reference.

`charredmap` is a Next.js fullstack MVP for a public memorial map of stories from occupied or deoccupied Ukrainian cities. The public side is registration-free, while moderators work through a separate admin path protected by a password and signed cookie session.

## Stack

- `Next.js 16` with App Router and Server Actions
- `Tailwind CSS 4`
- `Prisma + SQLite`
- `MapLibre GL JS`
- local upload adapter writing into a dedicated uploads directory that is served through a route handler

## Local Setup

1. Install dependencies:

```bash
npm install
```

2. Copy environment defaults if needed:

```bash
cp .env.example .env
```

3. Initialize SQLite schema and seed demo content:

```bash
npm run db:setup
```

4. Start the local server when you actually want to run it:

```bash
npm run dev
```

The default build assumes the app is mounted under `/charredmap`. If you need to run it from the root locally, override `NEXT_PUBLIC_BASE_PATH=""` before `npm run dev`.

## Studerria VPS deployment

This repository is now prepared for a path-based deployment on the main Studerria domain:

- public app: `https://studerria.com/charredmap`
- admin: `https://studerria.com/charredmap/admin`

The safest setup is to keep `charredmap` in its own container, expose it only on `127.0.0.1`, and proxy only the `/charredmap` prefix from the main nginx virtual host.

### 1. Prepare the compose env

```bash
cp docker/studerria/.env.example docker/studerria/.env
```

Set long random values for:

- `ADMIN_PASSWORD`
- `SESSION_SECRET` with at least 32 random characters

### 2. Start the container

```bash
cd docker/studerria
docker compose up -d --build
```

The compose file:

- builds the app with `NEXT_PUBLIC_BASE_PATH=/charredmap`
- binds the app only to `127.0.0.1:${APP_PORT}`
- keeps SQLite and uploads in a dedicated Docker volume
- runs the container read-only except for `/tmp` and `/data`
- drops Linux capabilities and enables `no-new-privileges`

### 3. Add the nginx location block on Studerria

Use the snippet in `docker/studerria/nginx.charredmap.conf` inside the existing `server {}` block for `studerria.com`.

Only the `/charredmap` prefix is proxied to this app, so the rest of Studerria stays isolated from `charredmap`.

### 4. Persisted content

- SQLite database: `/data/charredmap.db`
- uploaded images: `/data/uploads`

Uploads are served by the app through `/uploads/:fileName`, so production storage no longer needs to live in `public/`.

## Docker image

You can still build the production image directly:

```bash
docker build \
  --build-arg NEXT_PUBLIC_BASE_PATH=/charredmap \
  -t charredmap .

docker run --rm -p 8080:8080 \
  -e DATABASE_URL="file:./dev.db" \
  -e NEXT_PUBLIC_BASE_PATH="/charredmap" \
  -e ADMIN_PATH="admin" \
  -e ADMIN_PASSWORD="replace-with-a-long-random-password" \
  -e SESSION_SECRET="replace-with-at-least-32-random-characters" \
  charredmap
```

## Environment

Tracked defaults live in `.env.example`.

- `NEXT_PUBLIC_BASE_PATH` is the build-time URL prefix, defaulting to `/charredmap`
- `DATABASE_URL` points to the local SQLite file
- `ADMIN_PATH` is the admin path segment and defaults to `admin`
- `ADMIN_PASSWORD` is the shared moderator password and must be strong in production
- `SESSION_SECRET` signs the admin cookie and must be at least 32 characters in production
- `UPLOAD_DIR` is the writable storage path for uploaded images

## Versioning And Changelog

- Bump app version with `node version.js patch`
- Regenerate `changelog.json` from git history with `npm run changelog:update`
- The footer reads `changelog.json` and opens it in a modal via the `Changelog` button

## Important Notes

- The orange occupation layer is an editorial placeholder GeoJSON for MVP. Replace `src/data/occupied-territories-editorial.geojson` with verified newsroom data before deployment.
- Admin cookies are scoped only to the admin prefix, not the whole domain.
- SVG uploads are intentionally rejected to avoid same-origin script injection through moderator content.
