import { AdminShell } from "@/components/admin/admin-shell";
import { assertAdminPath, requireAdminSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

type AdminStoriesLayoutProps = {
  children: React.ReactNode;
  params: Promise<{
    adminPath: string;
  }>;
};

export default async function AdminStoriesLayout({
  children,
  params,
}: AdminStoriesLayoutProps) {
  const { adminPath } = await params;

  assertAdminPath(adminPath);
  await requireAdminSession();

  return <AdminShell adminPath={adminPath}>{children}</AdminShell>;
}
