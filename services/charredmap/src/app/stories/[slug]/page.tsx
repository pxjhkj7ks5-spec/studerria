import { notFound } from "next/navigation";
import { StorySheet } from "@/components/story/story-sheet";
import { getPublishedStoryBySlug } from "@/lib/data";

export const dynamic = "force-dynamic";

type StoryPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export default async function StoryPage({ params }: StoryPageProps) {
  const { slug } = await params;
  const story = await getPublishedStoryBySlug(slug);

  if (!story) {
    notFound();
  }

  return (
    <main className="mx-auto w-full max-w-5xl px-4 py-8 md:px-6 md:py-10">
      <div className="glass-panel overflow-hidden rounded-[32px]">
        <StorySheet story={story} />
      </div>
    </main>
  );
}
