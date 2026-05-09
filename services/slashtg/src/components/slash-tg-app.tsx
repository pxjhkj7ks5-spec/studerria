"use client";

/* eslint-disable @next/next/no-img-element -- Telegram/custom avatars use arbitrary remote URLs. */

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { withBasePath } from "@/lib/base-path";

type TelegramWebApp = {
  initData?: string;
  colorScheme?: "light" | "dark";
  ready?: () => void;
  expand?: () => void;
  HapticFeedback?: {
    impactOccurred?: (style: "light" | "medium" | "heavy" | "rigid" | "soft") => void;
    notificationOccurred?: (type: "error" | "success" | "warning") => void;
    selectionChanged?: () => void;
  };
};

declare global {
  interface Window {
    Telegram?: {
      WebApp?: TelegramWebApp;
    };
  }
}

type SlashProfile = {
  displayName: string;
  avatarUrl: string;
  telegramUsername?: string;
};

type SlashState = {
  ok: boolean;
  authenticated: boolean;
  currentUser?: SlashProfile;
  otherUser?: SlashProfile;
  receivedMessage?: {
    text: string;
    animationType: string;
    updatedAt: string | null;
    updatedAtLabel: string;
  };
  draftForOther?: {
    text: string;
    animationType: string;
  };
  history?: {
    sent: SlashWish[];
    received: SlashWish[];
  };
};

type SlashWish = {
  id: number;
  text: string;
  animationType: string;
  createdAt: string;
  createdAtLabel: string;
};

const vibes = ["soft-glow", "clouds", "sparkles", "tiny-faces"];
const reactionOptions = ["🥹", "🥰", "✨", "🫶", "🌙", "☁️", "💫"];
const emptyMessage =
  "сьогодні тут ще тихо... але, здається, скоро щось з'явиться";

function todayLabel() {
  try {
    return new Intl.DateTimeFormat("uk-UA", {
      day: "numeric",
      month: "long",
    }).format(new Date());
  } catch {
    return "сьогодні";
  }
}

function initialsFor(profile?: SlashProfile) {
  const raw = String(profile?.displayName || "").trim();
  if (!raw) return "ST";
  return (
    raw
      .split(/\s+/)
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() || "ST"
  );
}

async function requestJson<T>(path: string, options: RequestInit = {}) {
  const response = await fetch(withBasePath(path), {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  let payload = {} as T & { ok?: boolean; error?: string };
  try {
    payload = (await response.json()) as T & { ok?: boolean; error?: string };
  } catch {
    payload = {} as T & { ok?: boolean; error?: string };
  }

  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.error || "request_failed");
    throw error;
  }

  return payload as T;
}

function haptic(type: "select" | "save" | "error") {
  const feedback = window.Telegram?.WebApp?.HapticFeedback;
  if (type === "select") {
    feedback?.selectionChanged?.();
    return;
  }
  if (type === "save") {
    feedback?.notificationOccurred?.("success");
    return;
  }
  feedback?.notificationOccurred?.("error");
}

function readStoredReaction(key: string) {
  try {
    return window.localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function Avatar({ profile, className = "" }: { profile?: SlashProfile; className?: string }) {
  const avatarUrl = String(profile?.avatarUrl || "").trim();

  return (
    <div className={`slash-avatar ${className}`} aria-hidden="true">
      {avatarUrl ? <img src={avatarUrl} alt="" referrerPolicy="no-referrer" /> : initialsFor(profile)}
    </div>
  );
}

function WishHistoryList({ items, emptyText }: { items: SlashWish[]; emptyText: string }) {
  if (!items.length) {
    return <p className="slash-history-empty">{emptyText}</p>;
  }

  return (
    <div className="slash-history-list">
      {items.map((item) => (
        <article className="slash-history-item" data-vibe={item.animationType} key={item.id}>
          <p>{item.text}</p>
          <span>{item.createdAtLabel}</span>
        </article>
      ))}
    </div>
  );
}

export function SlashTgApp() {
  const [state, setState] = useState<SlashState | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "locked">("loading");
  const [message, setMessage] = useState("");
  const [avatarUrl, setAvatarUrl] = useState("");
  const [vibe, setVibe] = useState("soft-glow");
  const [toast, setToast] = useState("");
  const [activeReaction, setActiveReaction] = useState("");

  const authenticated = Boolean(state?.authenticated);
  const currentUser = state?.currentUser;
  const otherUser = state?.otherUser;
  const received = state?.receivedMessage;
  const history = state?.history;

  const reactionKey = useMemo(
    () => `slashtg:reaction:${currentUser?.displayName || "anonymous"}`,
    [currentUser?.displayName],
  );

  const showToast = useCallback((text: string) => {
    setToast(text);
    window.setTimeout(() => setToast(""), 2200);
  }, []);

  const renderState = useCallback((nextState: SlashState) => {
    setState(nextState);
    if (!nextState.authenticated) {
      setStatus("locked");
      return;
    }

    setStatus("ready");
    setMessage(nextState.draftForOther?.text || "");
    setAvatarUrl(nextState.currentUser?.avatarUrl || "");
    setVibe(nextState.draftForOther?.animationType || nextState.receivedMessage?.animationType || "soft-glow");
    setActiveReaction(readStoredReaction(`slashtg:reaction:${nextState.currentUser?.displayName || "anonymous"}`));
  }, []);

  useEffect(() => {
    const webApp = window.Telegram?.WebApp;
    webApp?.ready?.();
    webApp?.expand?.();
    document.documentElement.dataset.tgScheme = webApp?.colorScheme || "light";

    let cancelled = false;
    async function bootstrap() {
      try {
        const existing = await requestJson<SlashState>("/api/session");
        if (cancelled) return;
        if (existing.authenticated) {
          renderState(existing);
          return;
        }

        const initData = String(webApp?.initData || "").trim();
        const created = await requestJson<SlashState>("/api/session", {
          method: "POST",
          body: JSON.stringify({ initData }),
        });
        if (!cancelled) renderState(created);
      } catch {
        if (!cancelled) {
          setState({ ok: true, authenticated: false });
          setStatus("locked");
        }
      }
    }

    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [renderState]);

  async function saveMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const payload = await requestJson<SlashState>("/api/message", {
        method: "POST",
        body: JSON.stringify({ text: message, animationType: vibe }),
      });
      renderState(payload);
      haptic("save");
      showToast("відправлено");
    } catch {
      haptic("error");
      showToast("не вийшло зберегти");
    }
  }

  async function saveAvatar(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const payload = await requestJson<SlashState>("/api/avatar", {
        method: "POST",
        body: JSON.stringify({ avatarUrl }),
      });
      renderState(payload);
      haptic("save");
      showToast("аватар збережено");
    } catch {
      haptic("error");
      showToast("цей URL не схожий на картинку");
    }
  }

  async function logout() {
    try {
      await requestJson<SlashState>("/api/session", { method: "DELETE" });
    } catch {}
    setState({ ok: true, authenticated: false });
    setStatus("locked");
  }

  function selectVibe(nextVibe: string) {
    setVibe(vibes.includes(nextVibe) ? nextVibe : "soft-glow");
    haptic("select");
  }

  function saveReaction(reaction: string) {
    try {
      window.localStorage.setItem(reactionKey, reaction);
    } catch {}
    setActiveReaction(reaction);
    haptic("select");
    showToast(`${reaction} збережено`);
  }

  return (
    <main className="slash-shell" data-status={status}>
      <div className="slash-bg" aria-hidden="true">
        <span className="slash-blob slash-blob--peach" />
        <span className="slash-blob slash-blob--lilac" />
        <span className="slash-blob slash-blob--sky" />
        <span className="slash-blob slash-blob--butter" />
      </div>

      {!authenticated ? (
        <section className="slash-login" aria-label="Slash TG">
          <div className="slash-login-card">
            <div className="slash-mini-mark" aria-hidden="true">
              /
            </div>
            <p className="slash-overline">Telegram MiniApp</p>
            <h1>Slash TG</h1>
            {status === "loading" ? (
              <p className="slash-login-copy">підключаємо приватний простір</p>
            ) : (
              <p className="slash-login-copy">
                відкрий Slash TG через Telegram, щоб увійти без пароля
              </p>
            )}
          </div>
        </section>
      ) : (
        <section className="slash-app" aria-label="Slash TG private note">
          <header className="slash-topbar">
            <Avatar profile={otherUser} className="slash-avatar--small" />
            <div className="slash-topbar-title">
              <span>побажання від</span>
              <strong>{otherUser?.displayName || "другого учасника"}</strong>
            </div>
            <button className="slash-icon-button" type="button" onClick={logout} aria-label="Вийти">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M10 6H6.9A2.9 2.9 0 0 0 4 8.9v6.2A2.9 2.9 0 0 0 6.9 18H10" />
                <path d="M14.2 8.2 18 12l-3.8 3.8" />
                <path d="M17.6 12H9.8" />
              </svg>
            </button>
          </header>

          <section className="slash-note-card" data-vibe={received?.animationType || vibe}>
            <div className="slash-card-motion" aria-hidden="true">
              <span />
              <span />
              <span />
              <b>✨</b>
              <b>☁️</b>
              <b>💫</b>
            </div>
            <div className="slash-note-meta">
              <span>{received?.updatedAtLabel || todayLabel()}</span>
            </div>
            <div className="slash-author-row">
              <Avatar profile={otherUser} className="slash-avatar--author" />
              <span>від {otherUser?.displayName || "другого учасника"}</span>
            </div>
            <p className="slash-note-text">{received?.text || emptyMessage}</p>
            <div className="slash-reactions" aria-label="Реакції">
              {reactionOptions.map((reaction) => (
                <button
                  key={reaction}
                  type="button"
                  className={activeReaction === reaction ? "is-active" : ""}
                  onClick={() => saveReaction(reaction)}
                >
                  {reaction}
                </button>
              ))}
            </div>
          </section>

          <section className="slash-panel slash-editor">
            <div className="slash-section-head">
              <div>
                <span>little sender</span>
                <h2>написати побажання</h2>
              </div>
              <button
                className="slash-vibe-random"
                type="button"
                onClick={() => selectVibe(vibes[(vibes.indexOf(vibe) + 1 + vibes.length) % vibes.length])}
              >
                змінити вайб
              </button>
            </div>

            <form onSubmit={saveMessage}>
              <label htmlFor="slashMessage">для {otherUser?.displayName || "другого учасника"}</label>
              <textarea
                id="slashMessage"
                name="text"
                maxLength={800}
                rows={6}
                placeholder="напиши щось тепле, смішне або просто дуже своє..."
                value={message}
                onChange={(event) => setMessage(event.target.value)}
              />

              <div className="slash-vibes" aria-label="Анімація картки">
                {vibes.map((item) => (
                  <button
                    key={item}
                    type="button"
                    className={vibe === item ? "is-active" : ""}
                    onClick={() => selectVibe(item)}
                  >
                    {item.replace("-", " ")}
                  </button>
                ))}
              </div>

              <button className="slash-primary" type="submit">
                зберегти
              </button>
            </form>
          </section>

          <section className="slash-panel slash-avatar-editor">
            <div className="slash-section-head">
              <div>
                <span>profile glow</span>
                <h2>змінити аватар</h2>
              </div>
              <Avatar profile={{ displayName: currentUser?.displayName || "", avatarUrl }} className="slash-avatar--preview" />
            </div>
            <form onSubmit={saveAvatar}>
              <label htmlFor="slashAvatarUrl">URL картинки</label>
              <input
                id="slashAvatarUrl"
                name="avatarUrl"
                type="url"
                inputMode="url"
                placeholder="https://..."
                value={avatarUrl}
                onChange={(event) => setAvatarUrl(event.target.value)}
              />
              <button className="slash-secondary" type="submit">
                зберегти аватар
              </button>
            </form>
          </section>

          <section className="slash-panel slash-history">
            <div className="slash-section-head">
              <div>
                <span>archive</span>
                <h2>історія побажань</h2>
              </div>
            </div>

            <div className="slash-history-grid">
              <section>
                <h3>ти кидав</h3>
                <WishHistoryList
                  items={history?.sent || []}
                  emptyText="Тут зʼявляться побажання, які ти надсилаєш."
                />
              </section>
              <section>
                <h3>тобі</h3>
                <WishHistoryList
                  items={history?.received || []}
                  emptyText="Тут буде історія побажань для тебе."
                />
              </section>
            </div>
          </section>
        </section>
      )}

      <div className={`slash-toast${toast ? " is-visible" : ""}`} role="status" aria-live="polite">
        {toast}
      </div>
    </main>
  );
}
