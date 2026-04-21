import Link from "next/link";
import { MapStoryExperience } from "@/components/map/map-story-experience";
import { siteDescription } from "@/lib/constants";
import { getPublishedStories } from "@/lib/data";
import { getOccupationOverlay } from "@/lib/occupation-overlay";

export const dynamic = "force-dynamic";

export default async function Home() {
  const [stories, occupationOverlay] = await Promise.all([
    getPublishedStories(),
    getOccupationOverlay(),
  ]);

  return (
    <main className="relative pb-20">
      <section className="relative isolate overflow-hidden border-b border-white/8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.16),_transparent_24%),radial-gradient(circle_at_85%_12%,_rgba(255,255,255,0.08),_transparent_18%),linear-gradient(180deg,rgba(255,255,255,0.03),transparent_32%)]" />
        <div className="mx-auto grid w-full max-w-[1720px] gap-8 px-4 py-6 md:px-6 md:py-8 xl:gap-10 xl:grid-cols-[minmax(380px,0.64fr)_minmax(0,1.36fr)] xl:items-stretch 2xl:gap-12 2xl:grid-cols-[minmax(420px,0.72fr)_minmax(0,1.28fr)] 2xl:px-8">
          <div className="relative z-10 flex min-h-[calc(100svh-7rem)] flex-col justify-center gap-8 py-4 md:min-h-[44rem] md:py-8 xl:pr-4 2xl:pr-6">
            <div className="space-y-8">
              <div className="hero-reveal flex items-center gap-3 whitespace-nowrap text-[10px] uppercase tracking-[0.3em] text-[--muted] sm:text-[11px]">
                <span className="text-[--accent-orange]">charredmap</span>
                <span className="h-px w-10 bg-white/14" />
                <span>Атлас пам&apos;яті</span>
              </div>

              <div className="hero-reveal space-y-6 [animation-delay:120ms]">
                <h1 className="font-display max-w-[10.5ch] text-[clamp(3.1rem,6vw,6rem)] leading-[0.9] tracking-[-0.05em] text-white">
                  Мапа міст, де пам&apos;ять досі говорить голосніше за тишу.
                </h1>
                <p className="max-w-[32rem] text-[15px] leading-6 text-[#d5d8de] md:text-base md:leading-7">
                  {siteDescription} Мітка, місто і людська історія збираються тут в один темний
                  простір, де ніщо не відволікає від читання.
                </p>
              </div>
            </div>
          </div>

          <div className="relative z-10 hero-reveal w-full xl:flex xl:items-stretch xl:justify-end [animation-delay:180ms]">
            <div className="w-full xl:max-w-[1020px] 2xl:max-w-[1100px]">
              <MapStoryExperience
                stories={stories}
                occupationOverlay={occupationOverlay}
              />
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-[1720px] gap-10 px-4 py-14 md:px-6 md:py-16 lg:grid-cols-[minmax(0,0.7fr)_minmax(0,1.3fr)]">
        <div className="space-y-4">
          <p className="text-[11px] uppercase tracking-[0.32em] text-[--accent-orange]">
            Принцип публічної частини
          </p>
          <h2 className="font-display max-w-3xl text-4xl leading-[0.94] text-white md:text-5xl xl:text-6xl">
            Один екран тримає всю драматургію: мапа, індекс матеріалів і історія у фокусі.
          </h2>
          <p className="max-w-xl text-sm leading-7 text-white/70">
            Публічна поверхня лишається стриманою, але вже має окремий канал для нових подань від
            читачів без прямого доступу в редакторський шар.
          </p>
          <Link
            href="/submit"
            className="inline-flex rounded-full border border-white/10 bg-white/[0.04] px-5 py-3 text-sm text-white transition hover:border-[--accent-orange]/40 hover:bg-[rgba(255,132,56,0.08)]"
          >
            Надіслати історію на модерацію
          </Link>
        </div>
        <div className="grid gap-8 md:grid-cols-3">
          <div className="border-t border-white/10 pt-4">
            <p className="text-[11px] uppercase tracking-[0.28em] text-[--muted]">01</p>
            <h3 className="mt-4 font-display text-2xl text-white">Мапа як сцена</h3>
            <p className="mt-3 text-sm leading-7 text-[#d0d3da]">
              Публічна частина не розсипається на картки та дашборди. Головна площина лишається
              темною картою з кількома точними редакційними жестами.
            </p>
          </div>

          <div className="border-t border-white/10 pt-4">
            <p className="text-[11px] uppercase tracking-[0.28em] text-[--muted]">02</p>
            <h3 className="mt-4 font-display text-2xl text-white">Історія як читання</h3>
            <p className="mt-3 text-sm leading-7 text-[#d0d3da]">
              Кожна мітка відкриває окремий меморіальний sheet, а не перенасичений detail-view.
              Увага тримається на тексті, місці та даті публікації.
            </p>
          </div>

          <div className="border-t border-white/10 pt-4">
            <p className="text-[11px] uppercase tracking-[0.28em] text-[--muted]">03</p>
            <h3 className="mt-4 font-display text-2xl text-white">Публічне подання</h3>
            <p className="mt-3 text-sm leading-7 text-[#d0d3da]">
              Будь-хто може надіслати матеріал через окрему форму, але він потрапляє в чергу
              модерації. Публічний шар лишається чистим і не змішується з адмінською логікою.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
