# Narada Druk subdomain cutover

Target hostname: `naradadruk.studerria.com`.

The production defaults keep the current storefront at
`https://studerria.com/naradadruk`. Do not set the cutover variables until DNS
is ready and the migration is starting.

## Before the cutover

1. Create a proxied DNS record for `naradadruk.studerria.com` that points to the
   same public endpoint as `studerria.com`.
2. Confirm that TLS is active for the new hostname.
3. Keep a copy of the current server `.env` values.

## Cutover values

Set these values in `docker/local/.env` on the server:

```dotenv
NARADADRUK_BASE_PATH=/
NARADADRUK_PUBLIC_URL=https://naradadruk.studerria.com
NARADADRUK_PUBLIC_HOST=naradadruk.studerria.com
```

`NARADADRUK_BASE_PATH=/` builds the Next.js storefront for the hostname root.
`NARADADRUK_PUBLIC_URL` updates canonical URLs, structured data, robots and the
sitemap. `NARADADRUK_PUBLIC_HOST` activates host routing and permanent redirects
from the old `/naradadruk` URLs.

## Service-scoped update

Run the two standard service-scoped updates one immediately after the other.
The Narada Druk update creates a data-volume backup before rebuilding:

```bash
bash scripts/server-update.sh naradadruk
bash scripts/server-update.sh app
cd docker/local && docker compose ps naradadruk app
```

## Verification

```bash
curl -sSI https://naradadruk.studerria.com/
curl -sS https://naradadruk.studerria.com/robots.txt
curl -sS https://naradadruk.studerria.com/sitemap.xml | head
curl -sSI https://studerria.com/naradadruk/catalog
```

Expected results:

- the new homepage responds with `200`;
- canonical URLs and the sitemap use `naradadruk.studerria.com`;
- the old `/naradadruk` URL responds with `308` to the matching path on the
  subdomain;
- the admin path, catalog, product images and checkout APIs remain available.

After verification, add the new URL-prefix property to Google Search Console,
submit `https://naradadruk.studerria.com/sitemap.xml`, and request indexing for
the homepage. Keep the permanent redirects in place.
