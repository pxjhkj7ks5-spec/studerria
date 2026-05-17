# china-map

Interactive educational atlas for the Studerria domain, mounted at `/china-map`.

The app is intentionally static: no database, no admin surface, and no external map tiles. MapLibre renders a warm-paper atlas canvas from versioned GeoJSON-like data in `src/lib/atlas-data.ts`.

## Local Development

```bash
npm install
npm run dev
```

By default, the app expects `NEXT_PUBLIC_BASE_PATH=/china-map`. To run at the root locally:

```bash
NEXT_PUBLIC_BASE_PATH="" npm run dev
```

## Studerria Deployment

The root Studerria app proxies `/china-map` to this service through `middleware/serviceProxies.js`.

```bash
cd ../../docker/local
docker compose up --build -d app china-map
```

Production URL:

- `https://studerria.com/china-map`
- `https://studerria.com/china-map/print`

## Content Notes

The map uses a de facto + claims stance: controlled territories are shown as the base layer, while disputes and claims are shown separately with dashed or translucent overlays. It is a classroom presentation aid, not an authoritative legal map.
