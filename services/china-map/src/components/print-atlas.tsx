import { atlasPeriods, atlasSources } from "@/lib/atlas-data";
import { PrintButton } from "@/components/print-button";

export function PrintAtlas() {
  return (
    <main className="print-page">
      <article className="print-sheet">
        <header className="print-head">
          <div>
            <p className="atlas-eyebrow">Studerria atlas · China</p>
            <h1 className="print-title">China border transformations</h1>
            <p className="print-subtitle">
              Контурна навчальна мапа у чотирьох зрізах: 1920-ті, 1950-ті, 1990-ті і 2026.
              Підхід: фактичний контроль як основа, спірні території як окремі approximate layers.
            </p>
          </div>
          <PrintButton />
        </header>

        <div className="print-grid">
          <section className="print-map-card" aria-label="Compact China border map">
            <svg viewBox="0 0 760 560" role="img" aria-labelledby="print-map-title">
              <title id="print-map-title">Compact China border classroom map</title>
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
                d="M90 242 L128 294 L175 332 L241 348 L298 388 L378 394 L430 356 L502 340 L570 302 L636 252 L654 190 L614 136 L538 92 L438 104 L356 90 L286 114 L210 112 L142 148 Z"
                fill="rgba(79,129,189,.42)"
                stroke="#1f497d"
                strokeWidth="3"
                filter="url(#softShadow)"
              />
              <path
                d="M150 96 L248 58 L376 62 L500 84 L598 70 L654 110 L594 144 L482 132 L390 126 L286 132 L196 120 Z"
                fill="rgba(155,187,89,.28)"
                stroke="#9bbb59"
                strokeWidth="2"
                strokeDasharray="8 8"
              />
              <path
                d="M118 244 L190 228 L274 242 L330 288 L292 330 L198 318 L130 284 Z"
                fill="rgba(192,80,77,.22)"
                stroke="#c0504d"
                strokeWidth="2"
                strokeDasharray="7 7"
              />
              <path
                d="M575 360 C650 384 686 438 650 502 C594 488 552 450 548 398 Z"
                fill="rgba(192,80,77,.18)"
                stroke="#c0504d"
                strokeWidth="2"
                strokeDasharray="7 7"
              />
              <ellipse cx="640" cy="332" rx="14" ry="30" fill="rgba(155,187,89,.42)" stroke="#1f497d" strokeWidth="2" />
              <circle cx="602" cy="302" r="5" fill="#c0504d" />
              <circle cx="594" cy="306" r="4" fill="#c0504d" />
              <circle cx="626" cy="154" r="5" fill="#c0504d" />
              <text x="108" y="224" fill="#1f497d" fontSize="18" fontWeight="700">Aksai Chin</text>
              <text x="252" y="304" fill="#1f497d" fontSize="20" fontWeight="800">Tibet</text>
              <text x="340" y="232" fill="#1f497d" fontSize="28" fontWeight="800">Mainland China</text>
              <text x="418" y="84" fill="#1f497d" fontSize="18" fontWeight="700">Mongolia</text>
              <text x="590" y="404" fill="#1f497d" fontSize="18" fontWeight="700">South China Sea</text>
              <text x="662" y="337" fill="#1f497d" fontSize="16" fontWeight="700">Taiwan</text>
            </svg>
          </section>

          <section className="print-section">
            <h2>Timeline summary</h2>
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
          <h2>Key legal acts and decisions</h2>
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
          <h2>Sources</h2>
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
