"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  clampCartQuantity,
  getCartItemKey,
  type CartItem,
  type CartProductInput,
} from "@/lib/cart";

const storageKey = "naradadruk-cart-v1";

type CartContextValue = {
  items: CartItem[];
  itemCount: number;
  total: number;
  hydrated: boolean;
  addItem: (item: CartProductInput, quantity?: number) => void;
  updateQuantity: (key: string, quantity: number) => void;
  removeItem: (key: string) => void;
  clearCart: () => void;
};

const CartContext = createContext<CartContextValue | null>(null);

function isStoredCartItem(value: unknown): value is CartItem {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<CartItem>;
  return (
    typeof item.key === "string" &&
    typeof item.productId === "number" &&
    typeof item.productSlug === "string" &&
    typeof item.productTitle === "string" &&
    (typeof item.variantId === "number" || item.variantId === null) &&
    typeof item.variantLabel === "string" &&
    typeof item.unitPrice === "number" &&
    (typeof item.regularUnitPrice === "number" || typeof item.regularUnitPrice === "undefined") &&
    typeof item.quantity === "number" &&
    typeof item.imageUrl === "string"
  );
}

export function CartProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<CartItem[]>([]);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      const stored = JSON.parse(window.localStorage.getItem(storageKey) || "[]");
      if (Array.isArray(stored)) {
        setItems(
          stored.filter(isStoredCartItem).map((item) => ({
            ...item,
            regularUnitPrice: item.regularUnitPrice ?? item.unitPrice,
            quantity: clampCartQuantity(item.quantity),
          })),
        );
      }
    } catch {
      window.localStorage.removeItem(storageKey);
    } finally {
      setHydrated(true);
    }
  }, []);

  useEffect(() => {
    if (hydrated) {
      window.localStorage.setItem(storageKey, JSON.stringify(items));
    }
  }, [hydrated, items]);

  const addItem = useCallback((input: CartProductInput, quantity = 1) => {
    const key = getCartItemKey(input.productId, input.variantId);
    setItems((current) => {
      const existing = current.find((item) => item.key === key);
      if (existing) {
        return current.map((item) =>
          item.key === key
            ? { ...item, quantity: clampCartQuantity(item.quantity + quantity) }
            : item,
        );
      }
      return [...current, { ...input, key, quantity: clampCartQuantity(quantity) }];
    });
  }, []);

  const updateQuantity = useCallback((key: string, quantity: number) => {
    setItems((current) =>
      current.map((item) =>
        item.key === key ? { ...item, quantity: clampCartQuantity(quantity) } : item,
      ),
    );
  }, []);

  const removeItem = useCallback((key: string) => {
    setItems((current) => current.filter((item) => item.key !== key));
  }, []);

  const clearCart = useCallback(() => {
    setItems([]);
    window.localStorage.removeItem(storageKey);
  }, []);
  const value = useMemo(
    () => ({
      items,
      itemCount: items.reduce((sum, item) => sum + item.quantity, 0),
      total: items.reduce((sum, item) => sum + item.unitPrice * item.quantity, 0),
      hydrated,
      addItem,
      updateQuantity,
      removeItem,
      clearCart,
    }),
    [addItem, clearCart, hydrated, items, removeItem, updateQuantity],
  );

  return <CartContext.Provider value={value}>{children}</CartContext.Provider>;
}

export function useCart() {
  const value = useContext(CartContext);
  if (!value) throw new Error("useCart must be used inside CartProvider");
  return value;
}
