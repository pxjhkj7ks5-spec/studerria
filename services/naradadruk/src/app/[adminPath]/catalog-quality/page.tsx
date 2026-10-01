import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { withBasePath } from "@/lib/base-path";

export const dynamic = "force-dynamic";
export default async function Page({ params }: { params: Promise<{ adminPath: string }> }) {
  await requireAdminSession();
  assertAdminPath((await params).adminPath);
  const products = await prisma.product.findMany({ where: { status: "published" }, include: { category: true }, orderBy: { title: "asc" } });
  const fields = ["compatibilityNote", "packageContentsNote", "specificationsNote", "materialNote", "leadTime"] as const;
  const labels = ["Сумісність", "Комплектація", "Розміри / характеристики", "Матеріал", "Термін"];
  return <main className="mx-auto max-w-[1200px] px-4 py-8"><a className="ghost-pill" href={withBasePath(getAdminRoute())}>До огляду</a><h1 className="my-6 text-3xl">Наповнення каталогу</h1><p>Перевірено {products.length} опублікованих товарів. Відсутні дані потрібно підтвердити; загальні описи не замінюють точних розмірів.</p><div className="mt-6 grid gap-4">{products.map((product) => <article key={product.id} className="glass-panel rounded-2xl p-5"><a className="underline" href={withBasePath(`${getAdminRoute()}/products/${product.id}`)}>{product.title}</a><p>{product.category.name}</p><ul>{fields.map((field, index) => <li key={field}>{labels[index]}: {product[field].trim() ? "Є — перевірити точність" : "Потрібно уточнити"}</li>)}</ul></article>)}</div></main>;
}
