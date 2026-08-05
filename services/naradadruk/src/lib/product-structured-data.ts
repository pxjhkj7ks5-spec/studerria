type ProductOfferInput = {
  name: string;
  price: number;
};

type ProductOfferOptions = {
  productUrl: string;
  sellerId: string;
  saleEndsAt: Date | null;
  isOnSale: boolean;
};

export function buildProductOffers(
  offers: ProductOfferInput[],
  { productUrl, sellerId, saleEndsAt, isOnSale }: ProductOfferOptions,
) {
  const priceValidUntil = isOnSale && saleEndsAt
    ? saleEndsAt.toISOString().slice(0, 10)
    : undefined;

  return offers.map((offer) => ({
    "@type": "Offer",
    url: productUrl,
    name: offer.name,
    priceCurrency: "UAH",
    price: String(offer.price),
    seller: { "@id": sellerId },
    ...(priceValidUntil ? { priceValidUntil } : {}),
  }));
}
