# YKG Store

Самостійний Next.js-магазин Young Killers Group. Перший маршрут — `/ykg`, але storefront, SEO URL і внутрішні посилання працюють також із порожнім `NEXT_PUBLIC_BASE_PATH` для майбутнього окремого домену.

## Локальний запуск

1. Скопіювати `.env.example` у `.env` та задати окремі YKG-секрети.
2. Запустити `npm install`, `npm run db:push`, `npm run db:seed`, `npm run dev`.
3. Відкрити `/ykg/admin`, ввести `YKG_BOOTSTRAP_TOKEN` і створити першого owner. Після цього bootstrap автоматично блокується.

У production `YKG_SESSION_SECRET` є обов’язковим (щонайменше 32 символи, без placeholder-значень); контейнер навмисно не стартує без нього. `YKG_BOOTSTRAP_TOKEN` потрібен для першого входу і більше не створює owner після завершеного bootstrap.

Чернетки з Instagram не публікуються автоматично. Перед публікацією потрібні підтверджені назва, ціна, варіанти, залишок та дозволені оригінальні фото.

## Дані й Telegram

- SQLite: `DATABASE_URL` (у Docker — `/data/ykg.db`).
- Файли: `UPLOAD_DIR` (у Docker — `/data/uploads`).
- Staff-бот працює тільки в `YKG_TELEGRAM_CHAT_ID`, опційно в `YKG_TELEGRAM_TOPIC_ID`, і допускає лише активних StaffUser з відповідним Telegram user ID.
- `/orders` показує активні замовлення; `/manual` створює каталогове або унікальне ручне замовлення.

## Backup, restore, update

`bash scripts/server-update.sh ykg` перед scoped update автоматично архівує named volume `ykg_data` у `backups/server-update/`. Архів містить SQLite та uploads разом.

Для відновлення потрібно зупинити тільки `ykg`, розпакувати обраний архів у його named volume та знову підняти тільки `ykg`. Перед відновленням перевірити точну назву volume через `docker inspect`; не використовувати `docker compose down -v`.

Проксі активується окремим update сервісу `app` після update `ykg`.
