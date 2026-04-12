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

  return (
    <main className="pb-16">
      <section className="relative overflow-hidden border-b border-white/6">
        <div className="mx-auto grid w-full max-w-[1600px] gap-10 px-4 py-8 md:px-6 md:py-10 xl:grid-cols-[minmax(0,0.78fr)_minmax(0,1.22fr)] xl:items-stretch">
          <div className="flex flex-col justify-between gap-12">
            <div className="hero-reveal space-y-6">
              <p className="text-xs uppercase tracking-[0.34em] text-[--accent-orange]">
                charredmap
              </p>
              <div className="space-y-5">
                <h1 className="font-display max-w-3xl text-5xl leading-[0.95] text-white md:text-7xl xl:text-[5.3rem]">
                  Карта пам&apos;яті міст, які пережили окупацію або живуть у ній досі.
                </h1>
                <p className="max-w-2xl text-base leading-7 text-[#d3d6dc] md:text-lg">
                  {siteDescription} Кожна мітка відкриває людську історію, а помаранчевий шар на темній мапі нагадує, що ця географія досі болить.
                </p>
              </div>
            </div>

            <div className="grid gap-5 md:grid-cols-3">
              <div className="glass-panel hero-reveal rounded-[28px] p-5 [animation-delay:120ms]">
                <p className="text-xs uppercase tracking-[0.22em] text-[--muted]">Опубліковано</p>
                <p className="mt-3 font-display text-4xl text-white">{stories.length}</p>
              </div>
              <div className="glass-panel hero-reveal rounded-[28px] p-5 [animation-delay:180ms]">
                <p className="text-xs uppercase tracking-[0.22em] text-[--muted]">Міста у БД</p>
                <p className="mt-3 font-display text-4xl text-white">{stats.cities}</p>
              </div>
              <div className="glass-panel hero-reveal rounded-[28px] p-5 [animation-delay:240ms]">
                <p className="text-xs uppercase tracking-[0.22em] text-[--muted]">Формат</p>
                <p className="mt-3 font-display text-3xl text-white">Без реєстрації</p>
              </div>
            </div>

            <div className="hero-reveal max-w-xl rounded-[28px] border border-[--accent-orange]/20 bg-[rgba(255,132,56,0.08)] p-5 text-sm leading-6 text-[#f5d7c2] [animation-delay:300ms]">
              Помаранчевий контур є редакційним статичним overlay для MVP. Перед хостингом його треба замінити на перевірений newsroom GeoJSON.
            </div>
          </div>

          <div className="hero-reveal [animation-delay:180ms]">
            <MapStoryExperience
              stories={stories}
              occupationOverlay={occupationOverlay}
            />
          </div>
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-12 md:px-6 lg:grid-cols-[minmax(0,0.65fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <p className="text-xs uppercase tracking-[0.3em] text-[--accent-orange]">
            Про MVP
          </p>
          <h2 className="font-display text-4xl text-white md:text-5xl">
            Перший реліз зібраний навколо самої мапи, історії та редакторського контролю.
          </h2>
        </div>
        <div className="space-y-4 text-sm leading-7 text-[#d3d6dc] md:text-base">
          <p>
            У першій версії сайт не вимагає публічної авторизації. Вся редакторська логіка винесена в окрему закриту адмінку з паролем, де модератор створює місто, додає історію, фото і вирішує, залишати матеріал у draft чи показувати його на мапі.
          </p>
          <p>
            На публічній стороні головним екраном є нічна векторна карта. Внизу не дублюємо dashboard-картки, а тримаємо один сильний жест: карту як меморіальний простір і історію як модальне читання.
          </p>
        </div>
      </section>
    </main>
  );
}
