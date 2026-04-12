import { MapStoryExperience } from "@/components/map/map-story-experience";
import { siteDescription } from "@/lib/constants";
import { getPublishedStats, getPublishedStories } from "@/lib/data";
import { getOccupationOverlay } from "@/lib/occupation-overlay";

export const dynamic = "force-dynamic";

export default async function Home() {
  const [stories, stats, occupationOverlay] = await Promise.all([
    getPublishedStories(),
    getPublishedStats(),
    getOccupationOverlay(),
  ]);
  const overviewItems = [
    {
      label: "Опубліковано",
      value: String(stories.length).padStart(2, "0"),
      note: "Історії, які вже відкриваються просто з мапи.",
    },
    {
      label: "Міста в архіві",
      value: String(stats.cities).padStart(2, "0"),
      note: "Точки пам'яті, прив'язані до редакційної бази.",
    },
    {
      label: "Публічний доступ",
      value: "Вільно",
      note: "Читання відкрите, а модерація винесена в окремий префікс.",
    },
  ];

  return (
    <main className="relative pb-20">
      <section className="relative isolate overflow-hidden border-b border-white/8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.16),_transparent_24%),radial-gradient(circle_at_85%_12%,_rgba(255,255,255,0.08),_transparent_18%),linear-gradient(180deg,rgba(255,255,255,0.03),transparent_32%)]" />
        <div className="mx-auto grid w-full max-w-[1720px] gap-10 px-4 py-6 md:px-6 md:py-8 xl:grid-cols-[minmax(0,0.72fr)_minmax(0,1.28fr)] xl:items-end">
          <div className="relative z-10 flex min-h-[calc(100svh-7rem)] flex-col justify-between gap-10 py-4 md:min-h-[48rem] md:py-8">
            <div className="space-y-8">
              <div className="hero-reveal flex flex-wrap items-center gap-3 text-[11px] uppercase tracking-[0.34em] text-[--muted]">
                <span className="text-[--accent-orange]">charredmap</span>
                <span className="h-px w-10 bg-white/14" />
                <span>Редакційний атлас пам&apos;яті</span>
              </div>

              <div className="hero-reveal space-y-6 [animation-delay:120ms]">
                <h1 className="font-display max-w-4xl text-[clamp(3.8rem,9vw,8rem)] leading-[0.88] tracking-[-0.045em] text-white">
                  Мапа міст, у яких пам&apos;ять досі говорить голосніше за тишу.
                </h1>
                <p className="max-w-2xl text-base leading-7 text-[#d5d8de] md:text-lg">
                  {siteDescription} Тут публікація починається не зі стрічки, а з географії болю:
                  мітка, місто, людська історія і нічний простір, у якому все інше відступає.
                </p>
              </div>
            </div>

            <div className="grid gap-8 xl:grid-cols-[minmax(0,0.88fr)_minmax(0,1.12fr)]">
              <div className="glass-panel hero-reveal rounded-[32px] p-5 md:p-6 [animation-delay:220ms]">
                <p className="text-[11px] uppercase tracking-[0.3em] text-[--accent-orange]">
                  Editorial note
                </p>
                <p className="mt-4 max-w-xl text-sm leading-7 text-[#f0d9c7] md:text-[15px]">
                  Помаранчевий контур залишається редакційним статичним overlay для MVP. Він
                  задає меморіальну рамку, а не імітує live-дані.
                </p>
              </div>

              <dl className="hero-reveal divide-y divide-white/10 border-y border-white/10 [animation-delay:280ms]">
                {overviewItems.map((item) => (
                  <div
                    key={item.label}
                    className="grid gap-2 py-4 md:grid-cols-[148px_minmax(0,1fr)] md:gap-6"
                  >
                    <dt className="text-[11px] uppercase tracking-[0.28em] text-[--muted]">
                      {item.label}
                    </dt>
                    <div className="space-y-1">
                      <dd className="font-display text-3xl leading-none text-white md:text-4xl">
                        {item.value}
                      </dd>
                      <p className="max-w-xl text-sm leading-6 text-[#d0d3da]">{item.note}</p>
                    </div>
                  </div>
                ))}
              </dl>
            </div>
          </div>

          <div className="relative z-10 hero-reveal xl:pb-8 [animation-delay:180ms]">
            <MapStoryExperience
              stories={stories}
              occupationOverlay={occupationOverlay}
            />
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
            <h3 className="mt-4 font-display text-2xl text-white">Окремий редактор</h3>
            <p className="mt-3 text-sm leading-7 text-[#d0d3da]">
              Адмінка ізольована окремим префіксом. Публічний шар залишається камерним і чистим,
              без будь-якого адміністративного шуму на поверхні сайту.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
