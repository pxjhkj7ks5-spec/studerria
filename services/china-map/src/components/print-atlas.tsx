import type { Geometry, Position } from "geojson";
import type { ReactNode } from "react";
import { PrintButton } from "@/components/print-button";
import { atlasPeriods, atlasSources, type AtlasArea } from "@/lib/atlas-data";
import { realBoundaries } from "@/lib/real-boundaries";

const mapFrame = {
  width: 760,
  height: 560,
  minLng: 72,
  maxLng: 134,
  minLat: 3,
  maxLat: 54,
  padding: 34,
};

function projectPoint(position: Position) {
  const [lng, lat] = position;
  const innerWidth = mapFrame.width - mapFrame.padding * 2;
  const innerHeight = mapFrame.height - mapFrame.padding * 2;
  const x = mapFrame.padding + ((lng - mapFrame.minLng) / (mapFrame.maxLng - mapFrame.minLng)) * innerWidth;
  const y = mapFrame.padding + ((mapFrame.maxLat - lat) / (mapFrame.maxLat - mapFrame.minLat)) * innerHeight;
  return [x, y] as const;
}

function svgPoint(position: Position) {
  const [x, y] = projectPoint(position);
  return `${x.toFixed(1)},${y.toFixed(1)}`;
}

function ringToPath(ring: Position[]) {
  if (ring.length === 0) return "";
  const [firstPoint, ...rest] = ring;
  return `M ${svgPoint(firstPoint)} ${rest.map((point) => `L ${svgPoint(point)}`).join(" ")} Z`;
}

function geometryToPath(geometry: Geometry) {
  if (geometry.type === "Polygon") {
    return geometry.coordinates.map((ring) => ringToPath(ring)).join(" ");
  }

  if (geometry.type === "MultiPolygon") {
    return geometry.coordinates.flatMap((polygon) => polygon.map((ring) => ringToPath(ring))).join(" ");
  }

  return "";
}

function areaGeometry(area: AtlasArea): Geometry {
  return area.geometry ?? {
    type: "Polygon",
    coordinates: area.coordinates ?? [],
  };
}

function Label({
  at,
  children,
  size = 16,
}: {
  at: Position;
  children: ReactNode;
  size?: number;
}) {
  const [x, y] = projectPoint(at);
  return (
    <text x={x} y={y} fill="#1f497d" fontSize={size} fontWeight="800">
      {children}
    </text>
  );
}

export function PrintAtlas() {
  const currentPeriod = atlasPeriods.find((period) => period.id === "2026");
  const currentClaims = currentPeriod?.claims.filter((area) => area.id !== "taiwan") ?? [];

  return (
    <main className="print-page">
      <article className="print-sheet">
        <header className="print-head">
          <div>
            <p className="atlas-eyebrow">Studerria атлас · Китай</p>
            <h1 className="print-title">Трансформації кордонів Китаю</h1>
            <p className="print-subtitle">
              Навчальна мапа у чотирьох зрізах: 1920-ті, 1950-ті, 1990-ті і 2026.
              Підхід: фактичний контроль як основа, спірні території як окремі прозорі шари.
            </p>
          </div>
          <PrintButton />
        </header>

        <div className="print-grid">
          <section className="print-map-card" aria-label="Друкована мапа кордонів Китаю">
            <svg viewBox="0 0 760 560" role="img" aria-labelledby="print-map-title">
              <title id="print-map-title">Друкована мапа кордонів Китаю на основі реальних GeoJSON-геометрій</title>
              <defs>
                <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">
                  <path d="M 32 0 L 0 0 0 32" fill="none" stroke="rgba(31,73,125,.12)" strokeWidth="1" />
                </pattern>
                <filter id="softShadow" x="-10%" y="-10%" width="120%" height="120%">
                  <feDropShadow dx="0" dy="14" stdDeviation="16" floodColor="#1f497d" floodOpacity=".14" />
                </filter>
              </defs>
              <rect width="760" height="560" rx="28" fill="#eeece1" />
              <rect width="760" height="560" rx="28" fill="url(#grid)" />
              <path
                d={geometryToPath(realBoundaries.mongolia)}
                fill="rgba(155,187,89,.22)"
                stroke="#9bbb59"
                strokeWidth="1.8"
                strokeDasharray="7 7"
              />
              <path
                d={geometryToPath(realBoundaries.china)}
                fill="rgba(79,129,189,.42)"
                stroke="#1f497d"
                strokeWidth="1.8"
                filter="url(#softShadow)"
              />
              <path
                d={geometryToPath(realBoundaries.xinjiang)}
                fill="rgba(79,129,189,.16)"
                stroke="#1f497d"
                strokeWidth=".8"
                strokeOpacity=".42"
              />
              <path
                d={geometryToPath(realBoundaries.tibet)}
                fill="rgba(192,80,77,.14)"
                stroke="#c0504d"
                strokeWidth="1"
                strokeOpacity=".58"
              />
              <path
                d={geometryToPath(realBoundaries.taiwan)}
                fill="rgba(155,187,89,.4)"
                stroke="#1f497d"
                strokeWidth="1.4"
              />
              <path
                d={`${geometryToPath(realBoundaries.hongKong)} ${geometryToPath(realBoundaries.macau)}`}
                fill="#c0504d"
                stroke="#1f497d"
                strokeWidth=".8"
              />
              {currentClaims.map((area) => (
                <path
                  key={area.id}
                  d={geometryToPath(areaGeometry(area))}
                  fill="rgba(192,80,77,.17)"
                  stroke="#c0504d"
                  strokeWidth="1.4"
                  strokeDasharray="6 6"
                />
              ))}
              <Label at={[78.4, 34.2]}>Аксай-Чин</Label>
              <Label at={[87.2, 31.2]} size={18}>Тибет</Label>
              <Label at={[103.5, 36.2]} size={24}>Материковий Китай</Label>
              <Label at={[99.5, 46.8]}>Монголія</Label>
              <Label at={[112.4, 12.8]}>Південнокитайське море</Label>
              <Label at={[121.7, 23.9]}>Тайвань</Label>
            </svg>
          </section>

          <section className="print-section">
            <h2>Підсумок часових зрізів</h2>
            <div className="print-timeline">
              {atlasPeriods.map((period) => (
                <div className="print-era" key={period.id}>
                  <h3>{period.label} · {period.title}</h3>
                  <p>{period.summary}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <section className="print-section">
          <h2>Ключові договори, рішення і норми</h2>
          <div className="print-timeline">
            {atlasPeriods.map((period) => (
              <div className="print-era" key={period.id}>
                <h3>{period.label}</h3>
                {period.legalActs.map((act) => (
                  <p key={act}>{act}</p>
                ))}
              </div>
            ))}
          </div>
        </section>

        <section className="print-section">
          <h2>Джерела</h2>
          <ol className="print-sources">
            {atlasSources.map((source) => (
              <li key={source.url}>
                {source.title}. {source.url}
              </li>
            ))}
          </ol>
        </section>
      </article>
    </main>
  );
}
