import { notFound } from "next/navigation";
import { StoryEditorForm } from "@/components/admin/story-editor-form";
import { getAdminCities, getAdminStoryById } from "@/lib/data";

export const dynamic = "force-dynamic";

type EditStoryPageProps = {
  params: Promise<{
    adminPath: string;
    id: string;
  }>;
};

export default async function EditStoryPage({ params }: EditStoryPageProps) {
  const { adminPath, id } = await params;
  const [cities, story] = await Promise.all([getAdminCities(), getAdminStoryById(id)]);

  if (!story) {
    notFound();
  }

  return <StoryEditorForm adminPath={adminPath} cities={cities} story={story} />;
}
