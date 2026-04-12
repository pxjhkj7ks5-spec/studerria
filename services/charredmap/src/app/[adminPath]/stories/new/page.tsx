import { StoryEditorForm } from "@/components/admin/story-editor-form";
import { getAdminCities } from "@/lib/data";

export const dynamic = "force-dynamic";

type NewStoryPageProps = {
  params: Promise<{
    adminPath: string;
  }>;
};

export default async function NewStoryPage({ params }: NewStoryPageProps) {
  const { adminPath } = await params;
  const cities = await getAdminCities();

  return <StoryEditorForm adminPath={adminPath} cities={cities} />;
}
