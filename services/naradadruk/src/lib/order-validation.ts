import { z } from "zod";

const trimmedText = (min: number, max: number) => z.string().trim().min(min).max(max);

export const orderInputSchema = z.object({
  firstName: trimmedText(2, 60),
  lastName: trimmedText(2, 60),
  comment: z.string().trim().max(1200).default(""),
  phone: z
    .string()
    .trim()
    .regex(/^\+?[\d\s()\-]{9,22}$/, "Вкажіть коректний номер телефону."),
  telegramContact: z
    .string()
    .trim()
    .min(3)
    .max(80)
    .regex(/^@?[a-zA-Z0-9_+().\-\s]+$/, "Вкажіть Telegram username або номер телефону."),
  cityName: trimmedText(2, 120),
  cityRef: z.string().trim().max(80).default(""),
  deliveryMethod: z.enum(["branch", "parcel_locker", "courier"]),
  deliveryDestination: trimmedText(3, 240),
  destinationRef: z.string().trim().max(80).default(""),
  courierAddress: z.string().trim().max(240).default(""),
  paymentMethod: z.enum(["cash_on_delivery", "transfer"]),
  items: z
    .array(
      z.object({
        productId: z.number().int().positive(),
        variantId: z.number().int().positive().nullable(),
        quantity: z.number().int().min(1).max(20),
      }),
    )
    .min(1)
    .max(50),
}).superRefine((value, context) => {
  if (value.deliveryMethod === "courier" && value.courierAddress.length < 5) {
    context.addIssue({
      code: "custom",
      path: ["courierAddress"],
      message: "Вкажіть адресу для курʼєрської доставки.",
    });
  }
});

export type OrderInput = z.infer<typeof orderInputSchema>;

