export function getTransferPaymentDetails() {
  return (
    process.env.NARADADRUK_TRANSFER_PAYMENT_DETAILS?.trim() ||
    "Реквізити для переказу надішлемо в Telegram після підтвердження замовлення."
  );
}

