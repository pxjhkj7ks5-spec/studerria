import { redirect } from "next/navigation";
import { LoginForm } from "@/components/admin/login-form";
import {
  assertAdminPath,
  getAdminStoriesRoute,
  isAdminAuthenticated,
} from "@/lib/auth";

export const dynamic = "force-dynamic";

type AdminLoginPageProps = {
  params: Promise<{
    adminPath: string;
  }>;
};

export default async function AdminLoginPage({ params }: AdminLoginPageProps) {
  const { adminPath } = await params;

  assertAdminPath(adminPath);

  if (await isAdminAuthenticated()) {
    redirect(getAdminStoriesRoute(adminPath));
  }

  return (
    <main className="mx-auto flex min-h-[72vh] w-full max-w-7xl items-center px-4 py-10 md:px-6">
      <LoginForm />
    </main>
  );
}
