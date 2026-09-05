# Експлуатація

## Перший запуск KMA

Потрібні чинна KMA PostgreSQL, HTTPS на `studerria.com` та активна SSH-сесія власника. Інтеграція додає лише Compose `obriy`, schema `obriy` та маршрут `/obriy` через `app`. Main Compose вже містить потрібну мережу й PostgreSQL; окремий Caddy на 443 не запускається.

На першому релізі спочатку оновити `app`, щоб підтягнути новий selector і маршрут, потім `obriy`:

```sh
bash scripts/server-update.sh app
bash scripts/server-update.sh obriy
```

Скрипт `setup-obriy-env.sh` автоматично генерує відсутні локальні security keys у `docker/local/.env`, не виводить їх і не замінює чинні значення. Порожні раніше оголошені ключі доповнюються новим значенням наприкінці dotenv. Перед видаленням/зміною encryption key потрібен експорт і контрольована міграція: його втрата робить захищені поля нечитабельними. Ключ входу — `OBRIY_ADMIN_TOKEN`; власник читає його у своєму приватному env-редакторі.

## Зовнішні ключі

1. Створіть окремого бота через [BotFather](https://t.me/BotFather), display name «Обрій». Username має закінчуватися `bot` і бути вільним; це перевіряє BotFather. Запишіть `OBRIY_TELEGRAM_BOT_TOKEN` та `OBRIY_TELEGRAM_BOT_USERNAME` (без @).
2. Отримайте персональний `OBRIY_ALERTS_TOKEN` через [офіційну форму](https://alerts.in.ua/api-request). Без токена другий канал позначається вимкненим; NEPTUN працює без ключа.
3. Оновіть лише `obriy`: `bash scripts/server-update.sh obriy --no-build` після суто env-змін.
4. Увійдіть на `/obriy` своїм ключем. Додайте зону вручну або через явну кнопку геопозиції, задайте радіус і за потреби адміністративну область/UID. Радіус 10 км — змінюваний початковий параметр, не рекомендація безпеки.
5. Натисніть підключення Telegram, надішліть боту `/start CODE`. Код живе 10 хвилин, одноразовий. Не надсилайте боту координати. Тільки приватний чат від його власника приймається.

Polling — типовий режим, не потребує публічного webhook. Не використовуйте токен бота, який уже обслуговує інший процес. `409` зазвичай означає конфлікт getUpdates/webhook: перевірте чинну інтеграцію, не видаляйте її навмання. Webhook підтримується як альтернативний режим; Telegram `setWebhook` власник виконує із секретом і HTTPS URL `/obriy/telegram/webhook`, лише після переведення `OBRIY_TELEGRAM_MODE=webhook`. Не активуйте обидва режими.

## Здоров'я та аварії

- `/obriy/healthz`: живий HTTP-процес (Docker healthcheck).
- `/obriy/readyz`: HTTP 200 лише за наявності DB, локальних ключів, ingestion owner та свіжого NEPTUN. Незалежно перевіряйте, чи налаштовані Telegram і alerts.in.ua, та їхній стан.
- `/obriy/api/v1/status`: публічний стан джерел без секретів/зон.
- `/obriy/metrics`: лише `Authorization: Bearer OBRIY_METRICS_TOKEN`; значення не мають user/zone labels. Власний Prometheus може читати внутрішню Compose-мережу. Жоден окремий публічний порт не відкривається.

Для втрати NEPTUN: залишити reconnect і REST fallback працювати; не підвищувати частоту REST понад обмеження. При 401/403 alerts.in.ua перевірити токен; при 429 зачекати retry. При втраті PG leader connection процес завершується після закриття сервера; Docker перезапускає його. Звичайні DB запити провалюються без виводу credentials. Якщо інший leader займає lock, другий instance не починає ingestion.

Пауза в UI або `/pause` зупиняє персональну доставку, а не збір даних. Глобально `OBRIY_TELEGRAM_MODE=disabled` відключає polling/delivery. Прості pending/expired/dead лічильники доступні в metrics. Outbox не гарантує exactly-once у зовнішньому Telegram: після timeout уже прийняте повідомлення може повторитись. Повідомлення, яке вже почало HTTP-відправку, неможливо гарантовано відкликати одночасним видаленням/паузою.

## Обмеження v0.1

Немає фонової GPS-слідкування, Web Push, native Critical Alerts, AirSigma/MTProto, multi-source fusion або карти. Інтерфейс працює в мобільному браузері, але не обіцяє фонові PWA-сповіщення. Підтримується один приватний власник із кількома зонами; multi-user registration не відкрито. TLS і off-site backups налаштовує власник на своїй інфраструктурі.
