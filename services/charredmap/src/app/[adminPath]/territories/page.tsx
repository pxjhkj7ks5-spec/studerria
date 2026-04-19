import { AdminShell } from "@/components/admin/admin-shell";
import { OccupationOverlayEditor } from "@/components/admin/occupation-overlay-editor";
import { assertAdminPath, requireAdminSession } from "@/lib/auth";
import { getOccupationOverlay } from "@/lib/occupation-overlay";

export const dynamic = "force-dynamic";

type AdminTerritoriesPageProps = {
  params: Promise<{
    adminPath: string;
  }>;
  searchParams: Promise<{
    saved?: string;
  }>;
};

export default async function AdminTerritoriesPage({
  params,
  searchParams,
}: AdminTerritoriesPageProps) {
  const [{ adminPath }, { saved }, overlay] = await Promise.all([
    params,
    searchParams,
    getOccupationOverlay(),
  ]);

  assertAdminPath(adminPath);
  await requireAdminSession();

  return (
    <AdminShell adminPath={adminPath}>
      <section className="space-y-5">
        {saved === "1" ? (
          <div className="rounded-[24px] border border-[--accent-orange]/25 bg-[rgba(255,132,56,0.08)] px-5 py-4 text-sm text-[#f7d8c2]">
            Overlay збережено.
          </div>
        ) : null}

        {saved === "0" ? (
          <div className="rounded-[24px] border border-[--accent-red]/28 bg-[rgba(218,59,59,0.12)] px-5 py-4 text-sm text-[#ffd2d2]">
            Не вдалося зберегти overlay.
          </div>
        ) : null}

        <OccupationOverlayEditor overlay={overlay} />
      </section>
    </AdminShell>
  );
}
