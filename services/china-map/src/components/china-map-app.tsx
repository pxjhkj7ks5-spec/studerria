"use client";

import { useState } from "react";
import clsx from "clsx";
import { MapCanvas } from "@/components/map-canvas";
import { atlasPeriods, atlasSources, initialPeriod, type PeriodId } from "@/lib/atlas-data";
import { getBasePath } from "@/lib/base-path";

const layerToggles = [
  {
    key: "control",
    title: "De facto control",
    body: "Базовий шар фактичного або адміністративного контролю.",
  },
  {
    key: "claims",
    title: "Claims / disputes",
    body: "Пунктирні або прозорі шари для спірних територій.",
  },
  {
    key: "events",
    title: "Treaties / events",
    body: "Маркери ключових договорів, рішень і статусних змін.",
  },
] as const;

export function ChinaMapApp() {
  const [activePeriodId, setActivePeriodId] = useState<PeriodId>(initialPeriod.id);
  const [showControl, setShowControl] = useState(true);
  const [showClaims, setShowClaims] = useState(true);
  const [showEvents, setShowEvents] = useState(true);
  const [sourcesOpen, setSourcesOpen] = useState(false);

  const activePeriod = atlasPeriods.find((period) => period.id === activePeriodId) ?? initialPeriod;
  const basePath = getBasePath();

  const toggleLayer = (key: (typeof layerToggles)[number]["key"]) => {
    if (key === "control") setShowControl((value) => !value);
    if (key === "claims") setShowClaims((value) => !value);
    if (key === "events") setShowEvents((value) => !value);
  };

  return (
    <main className="china-atlas-shell">
      <div className="atlas-workspace">
        <section className="atlas-panel atlas-copy-panel" aria-label="China border atlas controls">
          <div className="atlas-eyebrow">Studerria atlas</div>
          <div>
            <h1 className="atlas-title">China border atlas</h1>
            <p className="atlas-lead">
              Інтерактивна мапа для завдання: чотири часові зрізи показують, як змінювалася
              державна територія, фактичний контроль і спірні простори Китаю.
            </p>
          </div>

          <div className="atlas-period-card">
            <div className="atlas-period-kicker">{activePeriod.label} · {activePeriod.range}</div>
            <h2 className="atlas-period-title">{activePeriod.title}</h2>
            <p className="atlas-period-summary">{activePeriod.summary}</p>
            <p className="atlas-period-summary">{activePeriod.note}</p>
          </div>

          <nav className="atlas-timeline" aria-label="Timeline periods">
            <div className="timeline-track">
              {atlasPeriods.map((period) => (
                <button
                  key={period.id}
                  type="button"
                  className="timeline-button"
                  aria-pressed={period.id === activePeriod.id}
                  onClick={() => setActivePeriodId(period.id)}
                >
                  <span className="timeline-dot" aria-hidden="true" />
                  <span className="timeline-label">{period.label}</span>
                </button>
              ))}
            </div>
          </nav>

          <div className="atlas-toggle-grid" aria-label="Map layer toggles">
            {layerToggles.map((toggle) => {
              const active =
                (toggle.key === "control" && showControl)
                || (toggle.key === "claims" && showClaims)
                || (toggle.key === "events" && showEvents);
              return (
                <button
                  key={toggle.key}
                  type="button"
                  className="layer-toggle"
                  data-active={active ? "true" : "false"}
                  onClick={() => toggleLayer(toggle.key)}
                >
                  <span className="layer-toggle__switch" aria-hidden="true" />
                  <span>
                    <strong>{toggle.title}</strong>
                    <span>{toggle.body}</span>
                  </span>
                </button>
              );
            })}
          </div>

          <div className="atlas-period-card">
            <div className="atlas-period-kicker">Key events</div>
            <ul className="source-list" style={{ padding: 0 }}>
              {activePeriod.keyEvents.map((event) => (
                <li key={event}>
                  <span>{event}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="atlas-actions">
            <a className="atlas-action atlas-action--primary" href={`${basePath}/print`}>
              Print / Save PDF
            </a>
            <button type="button" className="atlas-action" onClick={() => setSourcesOpen(true)}>
              Sources
            </button>
          </div>
        </section>

        <section className="atlas-panel atlas-map-panel" aria-label="Interactive map">
          <MapCanvas
            period={activePeriod}
            showControl={showControl}
            showClaims={showClaims}
            showEvents={showEvents}
          />
        </section>
      </div>

      <aside className="source-drawer" data-open={sourcesOpen ? "true" : "false"} aria-hidden={!sourcesOpen}>
        <div className="source-drawer__head">
          <h2>Sources and map stance</h2>
          <button type="button" className="source-drawer__close" onClick={() => setSourcesOpen(false)}>
            Close
          </button>
        </div>
        <ul className="source-list">
          <li>
            <span>
              Map stance: <strong>de facto + claims</strong>. Solid layers show control or administration;
              translucent dashed layers show disputes, claims or approximate zones.
            </span>
          </li>
          {atlasSources.map((source) => (
            <li key={source.url}>
              <a href={source.url} target="_blank" rel="noreferrer">
                {source.title}
              </a>
              <span>{source.note}</span>
            </li>
          ))}
        </ul>
      </aside>

      <div
        className={clsx("source-drawer-backdrop", sourcesOpen && "is-open")}
        onClick={() => setSourcesOpen(false)}
      />
    </main>
  );
}
