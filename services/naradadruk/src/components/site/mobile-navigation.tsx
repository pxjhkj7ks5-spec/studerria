"use client";

import { usePathname } from "next/navigation";
import { Cube, DotsThree, ShoppingBag, SquaresFour } from "@phosphor-icons/react";
import { withBasePath } from "@/lib/base-path";
import { useCart } from "@/components/site/cart-provider";

export function MobileNavigation() {
  const pathname = usePathname();
  const { itemCount } = useCart();
  const path = pathname.replace(withBasePath("/").replace(/\/$/, ""), "") || "/";
  if (/^\/(product|cart|custom|order)(\/|$)/.test(path)) return null;
  const items = [
    { href: "/catalog", label: "Каталог", Icon: SquaresFour, active: /^\/(catalog|category)/.test(path) },
    { href: "/custom", label: "Свій виріб", Icon: Cube, active: false },
    { href: "/cart", label: itemCount ? `Кошик (${itemCount})` : "Кошик", Icon: ShoppingBag, active: false },
    { href: "/more", label: "Ще", Icon: DotsThree, active: path === "/more" },
  ];
  return <nav className="mobile-navigation" aria-label="Мобільна навігація">{items.map(({ href, label, Icon, active }) => <a href={withBasePath(href)} key={href} aria-current={active ? "page" : undefined}><Icon size={22} aria-hidden /><span>{label}</span></a>)}</nav>;
}
