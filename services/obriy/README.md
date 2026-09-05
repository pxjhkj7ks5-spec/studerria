# Обрій / Obriy

Приватний сервіс контекстного моніторингу повітряних загроз для зон користувача. NEPTUN → сервер → оцінка → стійка Telegram-черга; alerts.in.ua додає адміністративний контекст. Це не радар, не офіційна система оповіщення й не прогноз влучання.

Працює у KMA як окремий Docker Compose сервіс `obriy`, адреса `/obriy`. Власний TypeScript/Fastify пакет, PostgreSQL schema `obriy`, незалежний dependency lock. Не перебудовує workspace/package-manager інших сайтів. Вебкабінет українською: захищений вхід, кілька зон, пояснення оцінок, стан джерел, пауза й видалення даних. Фонові повідомлення — через Telegram після явного підключення.

Перед кабінетом відкривається окремий екран зі спільним ключем `OBRIY_ADMIN_TOKEN`. Він дозволяє перейти до реєстрації/входу, але не відкриває жодного профілю. Після цього кожен користувач створює власні логін і пароль, додає свої зони та підключає свій Telegram. Доступ на пристрої зберігається на 30 днів, особиста сесія — 12 годин. Сервер віддає HTML кабінету лише чинній особистій сесії, включно з прямими шляхами до HTML. Чинна стара сесія дозволяє створити акаунт зі збереженням свого попереднього профілю; спільний ключ не дозволяє забрати його іншій людині.

## Локальний запуск

Node 24 LTS, PostgreSQL 16+ (у KMA PostgreSQL 18). Створіть окрему локальну базу та задайте її реквізити у `.env`.

```sh
npm ci
npm run secrets
# Відредагуйте приватний .env: DB connection та OBRIY_PUBLIC_URL=http://localhost:8080/obriy
npm run build
node --env-file=.env dist/src/main.js
```

`npm run secrets` не перезаписує файл; приклад без секретів — `.env.example`. Реальний NEPTUN доступний без API-ключа. Без бот-токена Telegram позначено неналаштованим; без alerts.in.ua токена незалежний другий канал вимкнений. Сторонні API-ключі не можна згенерувати самостійно.

## Перевірки

```sh
npm run typecheck
npm test
OBRIY_TEST_DATABASE_URL=postgres://USER@127.0.0.1:PORT/obriy_test npm run test:integration
npm run test:simulation
npm audit --omit=dev
npm run build
```

Integration suite потребує окремої тестової DB: очищає тільки власні obriy-таблиці. Без `OBRIY_TEST_DATABASE_URL` suite явно skipped. Синтетичні сценарії не використовують поточні координати загроз або користувача. CI запускає реальну PostgreSQL, збірку й smoke Docker image. UI не завантажує сторонні ресурси.

## Документація

- [Архітектура](docs/architecture.md)
- [Приватність](docs/privacy.md)
- [Логіка оцінювання](docs/threat-engine.md)
- [Перевірені API-контракти](docs/source-contracts.md)
- [Запуск, env та аварійні процедури](docs/operations.md)
- [Backup і відновлення](docs/disaster-recovery.md)

Джерела: [NEPTUN](https://neptun.in.ua/developers), [alerts.in.ua](https://devs.alerts.in.ua/), [Telegram Bot API](https://core.telegram.org/bots/api). Початкова модель ризику потребує окремої калібровки; проходження тестів не є доказом гарантованого попередження.

## Перевірено для першого релізу

2026-09-05: Node 24.20.0, 84 unit/contract/real-PostgreSQL integration тести; 12 синтетичних сценаріїв; 13 KMA proxy tests; production TypeScript build; npm audit без знайдених production вразливостей. Справжній NEPTUN stream приймав snapshot/alerts/heartbeat. Browser QA: 320/390/1440px, CRUD/pause/privacy, без console errors і без сторонніх запитів. Перевірено authenticated encrypted backup/restore у порожню PostgreSQL та відхилення пошкодженого архіву. Примусове закриття реального PG leader connection завершило процес із кодом 1. Live Telegram та alerts.in.ua не перевірено без персональних токенів; це окрема activation-перевірка власника.


Оновлення 0.2: 117 перевірок, включно з реальними PostgreSQL-сценаріями особистих акаунтів, розділенням зон/Telegram, перенесенням старої сесії, зміною пароля, обмеженням підбору та закриттям сторінки до входу. Паролі хешуються scrypt; спільний ключ не дозволяє читати чужі профілі.
