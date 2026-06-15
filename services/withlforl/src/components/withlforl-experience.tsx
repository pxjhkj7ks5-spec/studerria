"use client";

import { useEffect, useMemo, useState } from "react";

type WithlforlExperienceProps = {
  initialDenied: boolean;
  initialUnlocked: boolean;
};

const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

type ThreadPost = {
  id: number;
  title: string;
  body: string;
  fullBody: string[];
  muted: string;
  replyCount: string;
  replies: ThreadReply[];
  likeCount: string;
  mediaAlt?: string;
  mediaSrc?: string;
  shareCount: string;
};

type ThreadReply = {
  author: string;
  handle: string;
  text: string;
};

const threadPosts: ThreadPost[] = [
  {
    id: 1,
    title: "Ти - золото",
    body: "чому? а тицяй і поясню тобі",
    fullBody: [],
    muted: "і почну з простого",
    replyCount: "12",
    replies: [
      {
        author: "ти",
        handle: "@thread",
        text: "Золото - це та дорогоцінність що стає дорожчою з кожним днем, кожен день ти стаєш кращою. Але зберігаєш свої ідеї і ізначальну цінність.",
      },
      {
        author: "ще думка",
        handle: "@quiet",
        text: "Твоє волося немов покрито золотом, а твоя посмішка сяє яскравіше за нього. Можеш повертатись назад і відкривати наступний.",
      },
    ],
    likeCount: "∞",
    mediaAlt: "дзеркальне фото пари",
    mediaSrc: `${basePath}/images/first-post-gold.png`,
    shareCount: "1",
  },
  {
    id: 2,
    title: "Особливість",
    body: "маленькі речі, які дійсно роблять тебе не такою як інші.",
    fullBody: [],
    muted: "Характер, звички, відношення до інших.",
    replyCount: "7",
    replies: [
      {
        author: "пауза",
        handle: "@between",
        text: "хочу і бажаю тобі лишатись собою.",
      },
      {
        author: "деталь",
        handle: "@soft",
        text: "Бо ти супер крута вумен.",
      },
    ],
    likeCount: "24",
    mediaAlt: "селфі з аудиторії",
    mediaSrc: `${basePath}/images/second-post-special.png`,
    shareCount: "2",
  },
  {
    id: 3,
    title: "Людачка",
    body: "вітаю з твоїм днем і твоїми 18.",
    fullBody: [],
    muted: "офіційно доросла, але все така ж цікава, тепла і справжня.",
    replyCount: "3",
    replies: [
      {
        author: "баланс",
        handle: "@bright",
        text: "Ти можеш бути веселою, можеш бути серйозною, і в тобі точно є баланс. З тобою можна дискутувати, сперечатись і все одно відчувати, що поруч дуже розумна дівчинка.",
      },
      {
        author: "вдячність",
        handle: "@warm",
        text: "Ти глибока людина, з якою теми не закінчуються. З тобою навіть мовчки поруч тепло, і за цей рік ти зробила мене набагато щасливішим.",
      },
    ],
    likeCount: "18",
    mediaAlt: "селфі в аудиторії",
    mediaSrc: `${basePath}/images/third-post-birthday.png`,
    shareCount: "1",
  },
];

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
          код - те як тебе називаю
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

function PostHeader() {
  return (
    <header className="post-header">
      <div className="avatar" aria-hidden="true">
        L
      </div>
      <div>
        <p className="display-name">для тебе</p>
        <p className="handle">@andriimrch · сьогодні</p>
      </div>
    </header>
  );
}

function PostActions({ post }: { post: ThreadPost }) {
  const reactions = useMemo(
    () => [
      { icon: <ReplyIcon />, label: post.replyCount },
      { icon: <HeartIcon />, label: post.likeCount },
      { icon: <ShareIcon />, label: post.shareCount },
    ],
    [post],
  );

  return (
    <footer className="post-actions" aria-label="Post actions">
      {reactions.map((reaction) => (
        <span className="action" key={`${post.id}-${reaction.label}`}>
          {reaction.icon}
          <span>{reaction.label}</span>
        </span>
      ))}
    </footer>
  );
}

function PostMedia({ alt, src }: { alt?: string; src?: string }) {
  if (src) {
    return (
      <div className="silk-frame has-photo">
        <img alt={alt ?? ""} className="post-photo" src={src} />
      </div>
    );
  }

  return (
    <div className="silk-frame" aria-hidden="true">
      <span className="silk-line silk-line-a" />
      <span className="silk-line silk-line-b" />
      <span className="wine-drop" />
      <span className="milk-shine" />
    </div>
  );
}

function PostBody({ post }: { post: ThreadPost }) {
  return (
    <>
      <div className="post-copy">
        <p>{post.title}</p>
        <p className="post-muted">{post.body}</p>
        <p className="post-soft">{post.muted}</p>
      </div>
      <PostMedia alt={post.mediaAlt} src={post.mediaSrc} />
    </>
  );
}

function FeedPostCard({
  isLocked,
  onOpen,
  post,
}: {
  isLocked: boolean;
  onOpen: () => void;
  post: ThreadPost;
}) {
  return (
    <article className={isLocked ? "post-shell feed-post is-locked" : "post-shell feed-post"}>
      <button
        aria-label={isLocked ? "Пост заблоковано" : `Відкрити пост ${post.id}`}
        className="post-hit-target"
        disabled={isLocked}
        onClick={onOpen}
        type="button"
      />
      <span className="post-index">пост {post.id}</span>
      <div className="post-content">
        <PostHeader />
        <PostBody post={post} />
        <PostActions post={post} />
      </div>
      {isLocked ? <p className="locked-note">прочитай попередній щоб відкрити цей</p> : null}
    </article>
  );
}

function ThreadView({
  onBack,
  post,
}: {
  onBack: () => void;
  post: ThreadPost;
}) {
  return (
    <section className="thread-view" aria-label="Thread">
      <div className="thread-topbar">
        <button className="thread-back" onClick={onBack} type="button">
          назад
        </button>
        <p>сабтред</p>
      </div>
      <div className="thread-stack">
        <article className="post-shell thread-post">
          <PostHeader />
          <PostBody post={post} />
          {post.fullBody.length > 0 ? (
            <div className="thread-full-copy">
              {post.fullBody.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </div>
          ) : null}
          <PostActions post={post} />
        </article>
        <section className="thread-replies" aria-label="Replies">
          {post.replies.map((reply) => (
            <article className="reply-shell" key={`${reply.handle}-${reply.text}`}>
              <div className="reply-avatar" aria-hidden="true">
                {reply.author.charAt(0)}
              </div>
              <div className="reply-copy">
                <p className="reply-meta">
                  <span>{reply.author}</span>
                  <span>{reply.handle}</span>
                </p>
                <p>{reply.text}</p>
              </div>
            </article>
          ))}
        </section>
      </div>
    </section>
  );
}

function PrivatePost({ revealed }: { revealed: boolean }) {
  const [unlockedCount, setUnlockedCount] = useState(1);
  const [activePostId, setActivePostId] = useState<number | null>(null);
  const activePost = threadPosts.find((post) => post.id === activePostId) ?? null;

  function openPost(post: ThreadPost) {
    setActivePostId(post.id);
    setUnlockedCount((current) => Math.min(threadPosts.length, Math.max(current, post.id + 1)));
  }

  return (
    <section className={revealed ? "feed-screen is-revealed" : "feed-screen"} aria-label="Private greeting">
      <div className="phone-topline" aria-hidden="true">
        <span />
      </div>
      {activePost ? (
        <ThreadView onBack={() => setActivePostId(null)} post={activePost} />
      ) : (
        <>
          <div className="feed-list">
            {threadPosts.map((post) => (
              <FeedPostCard
                isLocked={post.id > unlockedCount}
                key={post.id}
                onOpen={() => openPost(post)}
                post={post}
              />
            ))}
          </div>
        </>
      )}
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
