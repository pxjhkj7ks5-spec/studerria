"use client";

import { useEffect, useMemo, useState } from "react";

type WithlforlExperienceProps = {
  initialDenied: boolean;
  initialUnlocked: boolean;
};

const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

function ReplyIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7.8 7.4h6.6a4.9 4.9 0 0 1 0 9.8H8.7l-3.5 2.5v-7.4a4.9 4.9 0 0 1 2.6-4.9Z" />
    </svg>
  );
}

function HeartIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 20.1s-7.1-4.3-8.7-9.4C2.5 8 4.1 5.6 6.8 5.3c1.8-.2 3.3.8 4.2 2.2.9-1.4 2.4-2.4 4.2-2.2 2.7.3 4.3 2.7 3.5 5.4C17.1 15.8 12 20.1 12 20.1Z" />
    </svg>
  );
}

function ShareIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 4.4 6.9 9.5l1.3 1.3 2.9-2.9v8.2h1.8V7.9l2.9 2.9 1.3-1.3L12 4.4Z" />
      <path d="M5.5 15.3v3.8h13v-3.8h1.8v5.6H3.7v-5.6h1.8Z" />
    </svg>
  );
}

function AccessGate({ initialDenied }: { initialDenied: boolean }) {
  return (
    <section className="gate-screen" aria-label="Private access">
      <div className="gate-glass" aria-hidden="true" />
      <form action={`${basePath}/api/access`} className="gate-panel" method="post">
        <span className="gate-mark">L</span>
        <label className="gate-label" htmlFor="withlforl-password">
          код
        </label>
        <input
          autoCapitalize="none"
          autoComplete="off"
          autoCorrect="off"
          autoFocus
          className="gate-input"
          id="withlforl-password"
          inputMode="text"
          lang="uk"
          name="password"
          placeholder="••••"
          spellCheck={false}
          type="text"
        />
        <button className="gate-button" type="submit">
          відкрити
        </button>
        <p className="gate-error" aria-live="polite">
          {initialDenied ? "ще раз" : " "}
        </p>
      </form>
    </section>
  );
}

function PrivatePost({ revealed }: { revealed: boolean }) {
  const reactions = useMemo(
    () => [
      { icon: <ReplyIcon />, label: "12" },
      { icon: <HeartIcon />, label: "∞" },
      { icon: <ShareIcon />, label: "1" },
    ],
    [],
  );

  return (
    <section className={revealed ? "feed-screen is-revealed" : "feed-screen"} aria-label="Private greeting">
      <div className="phone-topline" aria-hidden="true">
        <span />
      </div>
      <article className="post-shell">
        <header className="post-header">
          <div className="avatar" aria-hidden="true">
            L
          </div>
          <div>
            <p className="display-name">для тебе</p>
            <p className="handle">@withlforl · сьогодні</p>
          </div>
        </header>

        <div className="post-copy">
          <p>ти знаєш.</p>
          <p className="post-muted">тут буде кілька слів.</p>
        </div>

        <div className="silk-frame" aria-hidden="true">
          <span className="silk-line silk-line-a" />
          <span className="silk-line silk-line-b" />
          <span className="wine-drop" />
          <span className="milk-shine" />
        </div>

        <footer className="post-actions" aria-label="Post actions">
          {reactions.map((reaction) => (
            <span className="action" key={reaction.label}>
              {reaction.icon}
              <span>{reaction.label}</span>
            </span>
          ))}
        </footer>
      </article>
      <p className="under-note">поки що тихо.</p>
    </section>
  );
}

export function WithlforlExperience({ initialDenied, initialUnlocked }: WithlforlExperienceProps) {
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    if (!initialUnlocked) {
      return;
    }

    const timeout = window.setTimeout(() => setRevealed(true), 80);
    return () => window.clearTimeout(timeout);
  }, [initialUnlocked]);

  return (
    <main className={initialUnlocked ? "experience-shell unlocked" : "experience-shell"}>
      <div className="ambient-layer" aria-hidden="true" />
      {initialUnlocked ? (
        <form action={`${basePath}/api/logout`} className="logout-control" method="post">
          <button type="submit">вийти</button>
        </form>
      ) : null}
      {initialUnlocked ? <PrivatePost revealed={revealed} /> : <AccessGate initialDenied={initialDenied} />}
    </main>
  );
}
