export function resolveReviewProductIds(
  orderItems: Array<{ productId: number | null }> | null,
  requestedProductId: number | null,
) {
  if (orderItems) {
    return [...new Set(orderItems.flatMap((item) => item.productId ? [item.productId] : []))];
  }
  return requestedProductId && Number.isInteger(requestedProductId) && requestedProductId > 0
    ? [requestedProductId]
    : [];
}
