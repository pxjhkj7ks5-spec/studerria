import { z } from "zod";

const trimmedText = (label: string, min: number, max: number) =>
  z
    .string()
    .trim()
    .min(
      min,
      min === 1
        ? `Поле «${label}»: заповніть це поле.`
        : `Поле «${label}»: введіть щонайменше ${min} символи.`,
    )
    .max(max, `Поле «${label}»: максимально допустимо ${max} символів.`);

export const orderInputSchema = z.object({
  firstName: trimmedText("Імʼя", 2, 60),
  lastName: trimmedText("Прізвище", 2, 60),
  comment: z
    .string()
    .trim()
    .max(1200, "Поле «Коментар»: максимально допустимо 1200 символів.")
    .optional()
    .default(""),
  phone: z
    .string()
    .trim()
    .regex(/^\+?[\d\s()\-]{9,22}$/, "Поле «Телефон»: вкажіть коректний номер."),
  telegramContact: z
    .string()
    .trim()
    .min(3, "Поле «Telegram для звʼязку»: вкажіть username або номер телефону.")
    .max(80, "Поле «Telegram для звʼязку»: максимально допустимо 80 символів.")
    .regex(/^@?[a-zA-Z0-9_+().\-\s]+$/, "Поле «Telegram для звʼязку»: використайте username або номер телефону."),
  cityName: trimmedText("Місто", 2, 120),
  cityRef: z.string().trim().max(80, "Поле «Місто»: некоректний ідентифікатор.").default(""),
  deliveryMethod: z.enum(["branch", "parcel_locker", "courier"]),
  deliveryDestination: trimmedText("Відділення, поштомат або адреса", 1, 240),
  destinationRef: z.string().trim().max(80, "Поле «Точка доставки»: некоректний ідентифікатор.").default(""),
  courierAddress: z.string().trim().max(240, "Поле «Адреса доставки»: максимально допустимо 240 символів.").default(""),
  paymentMethod: z.enum(["cash_on_delivery", "transfer"]),
  promoCode: z.string().trim().max(32, "Промокод занадто довгий.").optional().default(""),
  items: z
    .array(
      z.object({
        productId: z.number().int().positive(),
        variantId: z.number().int().positive().nullable(),
        quantity: z.number().int().min(1).max(20),
      }),
    )
    .min(1, "Кошик порожній. Додайте хоча б один товар.")
    .max(50, "У кошику забагато різних позицій."),
}).superRefine((value, context) => {
  if (value.deliveryMethod === "courier" && value.courierAddress.length < 5) {
    context.addIssue({
      code: "custom",
      path: ["courierAddress"],
      message: "Поле «Адреса доставки»: вкажіть вулицю, будинок та, за потреби, квартиру.",
    });
  }
});

const fieldLabels: Record<string, string> = {
  firstName: "Імʼя",
  lastName: "Прізвище",
  comment: "Коментар",
  phone: "Телефон",
  telegramContact: "Telegram для звʼязку",
  cityName: "Місто",
  deliveryMethod: "Спосіб доставки",
  deliveryDestination: "Точка доставки",
  courierAddress: "Адреса доставки",
  paymentMethod: "Спосіб оплати",
  items: "Кошик",
};

export function getOrderValidationMessage(error: z.ZodError) {
  const issue = error.issues[0];
  if (!issue) return "Перевірте поля замовлення.";
  if (/[а-яіїєґ]/i.test(issue.message)) return issue.message;

  if (issue.path.includes("quantity")) {
    return "Поле «Кошик»: кількість кожної позиції має бути від 1 до 20.";
  }
  const field = String(issue.path[0] ?? "");
  const label = fieldLabels[field];
  return label ? `Поле «${label}»: перевірте введене значення.` : "Перевірте поля замовлення.";
}

export type OrderInput = z.infer<typeof orderInputSchema>;
