import { cookies } from "next/headers";
import { WithlforlExperience } from "@/components/withlforl-experience";
import { ACCESS_COOKIE_NAME, isValidAccessToken } from "@/lib/access";

type HomeProps = {
  searchParams?: Promise<{ denied?: string }>;
};

export default async function Home({ searchParams }: HomeProps) {
  const cookieStore = await cookies();
  const initialUnlocked = isValidAccessToken(cookieStore.get(ACCESS_COOKIE_NAME)?.value);
  const params = await searchParams;
  const initialDenied = params?.denied === "1";

  return <WithlforlExperience initialDenied={initialDenied} initialUnlocked={initialUnlocked} />;
}
