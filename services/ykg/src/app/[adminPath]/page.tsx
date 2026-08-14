import Image from "next/image";
import { headers } from "next/headers";
import { assertAdminPath, getAdminRoute, getStaffSession } from "@/lib/auth";
import { getAdminDashboardData } from "@/lib/data";
import { prisma } from "@/lib/prisma";
import { withBasePath } from "@/lib/base-path";
import {
  addAnalyticsIpExclusionAction,
  createProductAction,
  deleteAnalyticsIpExclusionAction,
  deleteCategoryAction,
  logoutAction,
  saveCategoryAction,
  saveSettingsAction,
  saveStaffUserAction,
} from "@/app/actions/admin";
import { LoginForm } from "@/components/admin/login-form";
import { SubmitButton } from "@/components/admin/submit-button";
import { AnalyticsDashboard } from "@/components/admin/analytics-dashboard";
import { OrderDashboard } from "@/components/admin/order-dashboard";
import { parseAnalyticsRange } from "@/lib/analytics-report";
import { normalizeIpAddress, trustedClientIpHeader, trustedClientIpSourceHeader } from "@/lib/analytics-ip";

export const dynamic = "force-dynamic";

type AdminPageProps = {
  params: Promise<{ adminPath: string }>;
  searchParams: Promise<{ ok?: string; error?: string; range?: string }>;
};

function Message({ ok, error }: { ok?: string; error?: string }) {
  if (!ok && !error) return null;
  return <div className={`status-message ${ok ? "status-message--ok" : "status-message--error"}`}>{ok || error}</div>;
}

export default async function AdminPage({ params, searchParams }: AdminPageProps) {
  const [{ adminPath }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);
  const staff = await getStaffSession();
  if (!staff) {
    const bootstrap = (await prisma.staffUser.count()) === 0;
    return <main className="mx-auto flex min-h-[80dvh] w-full max-w-[1400px] items-center px-4 py-12 md:px-6"><LoginForm bootstrap={bootstrap} /></main>;
  }

  const analyticsRange = parseAnalyticsRange(query.range);
  const { categories, products, settings, telegramOperations, analytics, analyticsIpExclusions, orders, staffUsers, recentAudit } = await getAdminDashboardData({ analyticsRange });
  const requestHeaders = await headers();
  const currentAnalyticsIp = normalizeIpAddress(requestHeaders.get(trustedClientIpHeader) ?? "");
  const currentAnalyticsIpSource = requestHeaders.get(trustedClientIpSourceHeader);
  const productTitles = Object.fromEntries(products.map((product) => [product.slug, product.title]));

  return <main className="admin-main mx-auto w-full max-w-[1440px] px-4 py-4 md:px-6 md:py-6">
    <header className="admin-topbar">
      <div className="admin-brand"><span className="admin-brand__mark" aria-hidden>Y</span><span><strong>YKG</strong><small>{staff.displayName} · {staff.role}</small></span></div>
      <nav className="admin-nav" aria-label="Розділи адмінки"><a href="#orders">Замовлення</a><a href="#products">Товари</a><a href="#team">Команда</a><a href="#analytics">Аналітика</a><a href="#storefront">Вітрина</a></nav>
      <div className="admin-topbar__actions"><a className="ghost-pill" href={withBasePath("/catalog")}>Магазин</a><form action={logoutAction}><button className="ghost-pill" type="submit">Вийти</button></form></div>
    </header>

    <div className="admin-intro"><p className="admin-kicker">YKG operations</p><h1>Замовлення, склад і команда</h1><p>Точні залишки видно тільки персоналу. Відʼємні значення означають позиції під замовлення.</p></div>
    <div className="mt-6"><Message ok={query.ok} error={query.error} /></div>

    <OrderDashboard summary={orders} />

    <section className="glass-panel mt-6 rounded-[2rem] p-6" id="products">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="admin-kicker">Каталог і склад</p><h2 className="admin-section-title">Товари</h2></div><form action={createProductAction} className="flex flex-wrap gap-2"><input name="title" required minLength={3} placeholder="Назва нової чернетки" /><select name="categoryId" required defaultValue=""><option value="" disabled>Категорія</option>{categories.map((category) => <option value={category.id} key={category.id}>{category.name}</option>)}</select><SubmitButton>Створити</SubmitButton></form></div>
      <div className="mt-6 grid gap-3">
        {products.map((product) => {
          const usesVariants = product.variants.length > 0;
          const stock = usesVariants ? product.variants.reduce((sum, variant) => sum + variant.stockQuantity, 0) : product.stockQuantity;
          return <a className="admin-product-row" href={withBasePath(`${getAdminRoute()}/products/${product.id}`)} key={product.id}>
            <span className="admin-product-row__image">{product.coverImage ? <Image src={withBasePath(product.coverImage.urlPath)} alt={product.coverImage.alt || product.title} width={96} height={72} unoptimized /> : <span>YKG</span>}</span>
            <span className="min-w-0 flex-1"><strong>{product.title}</strong><small>{product.category.name} · {product.status === "published" ? "Опубліковано" : "Чернетка"} · {product.priceLabel}</small></span>
            <span className={stock < 0 ? "stock-count stock-count--warning" : "stock-count"}><small>{usesVariants ? "Сума варіантів" : "На складі"}</small><strong>{stock}</strong></span>
          </a>;
        })}
      </div>
    </section>

    <section className="glass-panel mt-6 rounded-[2rem] p-6" id="categories">
      <p className="admin-kicker">Структура каталогу</p><h2 className="admin-section-title">Категорії</h2>
      <div className="mt-5 grid gap-4 lg:grid-cols-2">{categories.map((category) => <form action={saveCategoryAction} className="admin-form-panel" key={category.id}><input type="hidden" name="categoryId" value={category.id} /><label className="field-shell"><span>Назва</span><input name="name" defaultValue={category.name} required /></label><label className="field-shell"><span>Slug</span><input name="slug" defaultValue={category.slug} /></label><label className="field-shell"><span>Опис</span><textarea name="description" defaultValue={category.description} /></label><label className="field-shell"><span>Порядок</span><input name="sortOrder" type="number" defaultValue={category.sortOrder} /></label><label className="check-row"><input name="isVisible" type="checkbox" defaultChecked={category.isVisible} /> Видима</label><div className="flex gap-2"><SubmitButton>Зберегти</SubmitButton>{staff.role === "owner" && category._count.products === 0 ? <button className="ghost-pill" formAction={deleteCategoryAction}>Видалити</button> : null}</div></form>)}</div>
    </section>

    <section className="glass-panel mt-6 rounded-[2rem] p-6" id="team">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><p className="admin-kicker">Доступ</p><h2 className="admin-section-title">Команда</h2></div><span className={`status-chip ${telegramOperations.configured ? "status-chip--ok" : ""}`}>Telegram bot: {telegramOperations.configured ? "налаштований" : "не налаштований"}{telegramOperations.topicConfigured ? " · topic" : ""}</span></div>
      <div className="mt-5 grid gap-3">{staffUsers.map((user) => <form action={saveStaffUserAction} className="admin-form-panel grid gap-3 md:grid-cols-6 md:items-end" key={user.id}><input type="hidden" name="userId" value={user.id} /><label className="field-shell"><span>Імʼя</span><input name="displayName" defaultValue={user.displayName} disabled={staff.role !== "owner"} /></label><label className="field-shell"><span>Логін</span><input name="username" defaultValue={user.username} disabled={staff.role !== "owner"} /></label><label className="field-shell"><span>Роль</span><select name="role" defaultValue={user.role} disabled={staff.role !== "owner"}><option value="owner">owner</option><option value="manager">manager</option></select></label><label className="field-shell"><span>Telegram user ID</span><input name="telegramUserId" defaultValue={user.telegramUserId ?? ""} disabled={staff.role !== "owner"} /></label><label className="field-shell"><span>Новий пароль</span><input name="password" type="password" disabled={staff.role !== "owner"} /></label><label className="check-row"><input name="isActive" type="checkbox" defaultChecked={user.isActive} disabled={staff.role !== "owner"} /> Активний</label>{staff.role === "owner" ? <SubmitButton>Зберегти</SubmitButton> : null}</form>)}</div>
      {staff.role === "owner" ? <form action={saveStaffUserAction} className="admin-form-panel mt-5 grid gap-3 md:grid-cols-6 md:items-end"><label className="field-shell"><span>Імʼя</span><input name="displayName" required /></label><label className="field-shell"><span>Логін</span><input name="username" required /></label><label className="field-shell"><span>Роль</span><select name="role" defaultValue="manager"><option value="manager">manager</option><option value="owner">owner</option></select></label><label className="field-shell"><span>Telegram user ID</span><input name="telegramUserId" /></label><label className="field-shell"><span>Пароль від 12 символів</span><input name="password" type="password" required minLength={12} /></label><label className="check-row"><input name="isActive" type="checkbox" defaultChecked /> Активний</label><SubmitButton>Додати</SubmitButton></form> : null}
      <div className="mt-6"><h3 className="text-lg text-white">Останні дії</h3><div className="mt-3 grid gap-2">{recentAudit.map((event) => <div className="audit-row" key={event.id}><span>{event.staffUser?.displayName || event.actorLabel}</span><code>{event.action}</code><small>{event.entityType} #{event.entityId} · {new Intl.DateTimeFormat("uk-UA", { dateStyle: "short", timeStyle: "short", timeZone: "Europe/Kyiv" }).format(event.createdAt)}</small></div>)}</div></div>
    </section>

    <AnalyticsDashboard report={analytics} productTitles={productTitles} />
    <section className="glass-panel mt-6 rounded-[2rem] p-6" id="analytics-exclusions"><p className="admin-kicker">Внутрішній трафік</p><h2 className="admin-section-title">IP без обліку</h2><form action={addAnalyticsIpExclusionAction} className="mt-5 grid gap-3 md:grid-cols-[1fr_1fr_auto] md:items-end"><label className="field-shell"><span>IPv4 або IPv6</span><input name="address" defaultValue={currentAnalyticsIp ?? ""} required /></label><label className="field-shell"><span>Позначка</span><input name="label" maxLength={80} /></label><button className="accent-pill">Не враховувати</button></form><p className="mt-2 text-xs text-[--muted]">Джерело поточної адреси: {currentAnalyticsIpSource || "невідоме"}.</p><div className="mt-4 grid gap-2">{analyticsIpExclusions.map((exclusion) => <div className="audit-row" key={exclusion.id}><span>{exclusion.label || "Без позначки"}</span><code>{exclusion.addressHint}</code><form action={deleteAnalyticsIpExclusionAction}><input type="hidden" name="exclusionId" value={exclusion.id} /><button className="ghost-pill">Прибрати</button></form></div>)}</div></section>

    <section className="glass-panel mt-6 rounded-[2rem] p-6" id="storefront"><p className="admin-kicker">Вітрина</p><h2 className="admin-section-title">Тексти й контакти</h2><form action={saveSettingsAction} className="mt-5 grid gap-4 lg:grid-cols-2">{[["heroTitle","Hero title",settings.heroTitle],["heroSubtitle","Hero subtitle",settings.heroSubtitle],["supportTitle","Support title",settings.supportTitle],["supportBody","Support body",settings.supportBody],["materialsNote","Матеріали",settings.materialsNote],["leadTimeNote","Термін",settings.leadTimeNote],["deliveryNote","Доставка",settings.deliveryNote],["paymentNote","Оплата",settings.paymentNote],["telegramUrl","Instagram / contact URL",settings.telegramUrl],["contactNote","Контактний текст",settings.contactNote]].map(([name,label,value]) => <label className="field-shell" key={name}><span>{label}</span><textarea name={name} defaultValue={value} required /></label>)}<div><SubmitButton>Зберегти storefront</SubmitButton></div></form></section>
  </main>;
}
