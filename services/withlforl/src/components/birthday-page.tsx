"use client";

import { useMemo, useState } from "react";
import { birthdayContent } from "@/lib/content";

const floaters = ["серце", "іскра", "лист", "сонце", "подих", "мрія"];

function HeartIcon({ className = "" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 20.6c-.3 0-.6-.1-.8-.3-3.2-2.3-5.5-4.5-7-6.6C2.8 11.7 2 9.9 2 8.2 2 5.5 4 3.4 6.6 3.4c1.6 0 3.1.8 4 2.1.3.4.5.8.7 1.2.2-.4.4-.8.7-1.2.9-1.3 2.4-2.1 4-2.1 2.6 0 4.6 2.1 4.6 4.8 0 1.7-.8 3.5-2.2 5.5-1.5 2.1-3.8 4.3-7 6.6-.2.2-.5.3-.8.3Z" />
    </svg>
  );
}

export function BirthdayPage() {
  const [isOpen, setIsOpen] = useState(false);
  const sparkles = useMemo(() => floaters, []);

  const reveal = () => {
    setIsOpen(true);
    window.setTimeout(() => {
      document.getElementById("letter")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 520);
  };

  return (
    <main className={isOpen ? "birthday-shell is-open" : "birthday-shell"}>
      <section className="hero-section" aria-label="Birthday greeting">
        <div className="hero-media" aria-hidden="true" />
        <div className="ambient-glass glass-a" aria-hidden="true" />
        <div className="ambient-glass glass-b" aria-hidden="true" />
        <div className="floating-layer" aria-hidden="true">
          {sparkles.map((item, index) => (
            <span className={`floater floater-${index + 1}`} key={item}>
              <HeartIcon />
            </span>
          ))}
        </div>

        <div className="hero-copy">
          <div className="hero-note" aria-hidden="true">
            для тебе
            <span>сьогодні</span>
          </div>
          <h1>{birthdayContent.hero.title}</h1>
          <p>{birthdayContent.hero.lead}</p>
          <div className="hero-actions">
            <button className="reveal-button" type="button" onClick={reveal} aria-pressed={isOpen}>
              <span>{birthdayContent.hero.primaryAction}</span>
              <HeartIcon />
            </button>
            <a className="letter-link" href="#letter">
              {birthdayContent.hero.secondaryAction}
            </a>
          </div>
          <p className="revealed-line" aria-live="polite">
            {isOpen ? birthdayContent.hero.revealedLine : " "}
          </p>
        </div>
      </section>

      <section className="letter-section" id="letter">
        <div className="section-heart" aria-hidden="true">
          <HeartIcon />
        </div>
        <div className="section-heading">
          <h2>{birthdayContent.letter.title}</h2>
        </div>
        <article className="letter-paper">
          {birthdayContent.letter.paragraphs.map((paragraph) => (
            <p key={paragraph}>{paragraph}</p>
          ))}
          <p className="signature">{birthdayContent.letter.signature}</p>
        </article>
      </section>

      <section className="memory-section" aria-labelledby="moments-title">
        <div className="star-field" aria-hidden="true" />
        <h2 id="moments-title">{birthdayContent.memories.title}</h2>
        <div className="memory-track" aria-label="Memory moments">
          {birthdayContent.memories.items.map((item, index) => (
            <article className="memory-card" key={`${item.date}-${item.title}`}>
              <span className="memory-orbit" aria-hidden="true" />
              <span className="memory-date">{item.date}</span>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
              <span className="memory-count">0{index + 1}</span>
            </article>
          ))}
        </div>
      </section>

      <section className="final-section" aria-labelledby="wish-title">
        <div className="final-media" aria-hidden="true" />
        <div className="final-copy">
          <h2 id="wish-title">{birthdayContent.finalWish.title}</h2>
          <p>{birthdayContent.finalWish.body}</p>
          <div className="final-note">
            <span>{birthdayContent.finalWish.note}</span>
            <HeartIcon />
          </div>
        </div>
      </section>
    </main>
  );
}
