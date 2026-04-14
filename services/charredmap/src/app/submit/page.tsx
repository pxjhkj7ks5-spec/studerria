import type { Metadata } from "next";
import { PublicStoryForm } from "@/components/site/public-story-form";
import { getAdminCities } from "@/lib/data";

export const metadata: Metadata = {
  title: "Надіслати історію — charredmap",
  robots: {
    index: false,
    follow: false,
    nocache: true,
  },
};

export const dynamic = "force-dynamic";

type SubmitPageProps = {
  searchParams: Promise<{
    submitted?: string;
  }>;
};

export default async function SubmitPage({ searchParams }: SubmitPageProps) {
  const { submitted } = await searchParams;
  const cities = await getAdminCities();

  return (
    <main className="mx-auto w-full max-w-[1720px] px-4 py-8 md:px-6 md:py-10">
      <div className="mb-6 max-w-4xl space-y-3">
        <p className="text-[11px] uppercase tracking-[0.34em] text-[--accent-orange]">
          charredmap / public submit
        </p>
        <h1 className="font-display text-[clamp(2.7rem,5.5vw,5.3rem)] leading-[0.9] tracking-[-0.05em] text-white">
          Відкрита подача історій для карти пам&apos;яті.
        </h1>
      </div>

      {submitted ? (
        <div className="mb-6 rounded-[28px] border border-[--accent-orange]/25 bg-[rgba(255,132,56,0.08)] px-5 py-4 text-sm leading-6 text-[#f7d8c2]">
          Матеріал надіслано. Він не з&apos;явиться на мапі одразу: спершу піде в модерацію.
        </div>
      ) : null}

      <PublicStoryForm cities={cities} />
    </main>
  );
}
