type ProductReadinessInput = {
  title: string;
  shortDescription: string;
  fullDescription: string;
  basePrice: number | null;
  leadTime: string;
  materialNote: string;
  deliveryNote: string;
  paymentNote: string;
  variants: Array<{ price: number }>;
  images: Array<{ alt: string; isCover: boolean }>;
};

export type ProductReadinessCheck = {
  key: string;
  label: string;
  passed: boolean;
};

function usefulDescription(value: string, minimumLength: number) {
  const normalized = value.replace(/\s+/g, " ").trim();
  const priceOnly = /^(?:від\s+)?\d[\d\s]*\s*(?:грн|₴)?[.!]?$/iu.test(normalized);
  return normalized.length >= minimumLength && !priceOnly;
}

export function assessProductReadiness(product: ProductReadinessInput) {
  const checks: ProductReadinessCheck[] = [
    { key: "title", label: "Зрозуміла назва", passed: product.title.trim().length >= 3 },
    { key: "price", label: "Є базова ціна або варіанти", passed: product.basePrice !== null || product.variants.some((variant) => variant.price >= 0) },
    { key: "image", label: "Є хоча б одне фото", passed: product.images.length > 0 },
    { key: "cover", label: "Обрано обкладинку", passed: product.images.some((image) => image.isCover) },
    { key: "alt", label: "Фото мають описи", passed: product.images.length > 0 && product.images.every((image) => image.alt.trim().length >= 3) },
    { key: "short", label: "Короткий опис пояснює товар", passed: usefulDescription(product.shortDescription, 20) },
    { key: "full", label: "Повний опис достатньо змістовний", passed: usefulDescription(product.fullDescription, 40) },
    { key: "material", label: "Вказано матеріал", passed: product.materialNote.trim().length >= 4 },
    { key: "lead-time", label: "Вказано термін виготовлення", passed: product.leadTime.trim().length >= 4 },
    { key: "delivery", label: "Вказано доставку", passed: product.deliveryNote.trim().length >= 4 },
    { key: "payment", label: "Вказано оплату", passed: product.paymentNote.trim().length >= 4 },
  ];
  const passedCount = checks.filter((check) => check.passed).length;

  return {
    checks,
    passedCount,
    totalCount: checks.length,
    score: Math.round((passedCount / checks.length) * 100),
    ready: passedCount === checks.length,
  };
}
