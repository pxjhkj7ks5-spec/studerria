# Резервні копії й відновлення

Ключ шифрування application fields (`OBRIY_ENCRYPTION_KEY`) і незалежний 32-byte hex `OBRIY_BACKUP_KEY` зберігайте поза PostgreSQL та архівами, у приватному менеджері секретів. `backup.mjs` використовує Node AES-256-GCM; AAD і формат версіоновані. Відновлення перевіряє authentication tag ДО будь-якого запису в DB. Інструмент розрахований на персональну базу, максимум 64 MiB у dump; більші бази потребують потокового backup-процесу.

Потрібні Node 24, `pg_dump`/`pg_restore` тієї ж major-версії, що й сервер PostgreSQL, або новіші. Ключі й пароль передаються через захищений env, не аргументи команд і не Git. Власник задає стандартні `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` та `OBRIY_BACKUP_KEY`.

```sh
node scripts/backup.mjs backup /private-backups/obriy-2026-09-05.enc
```

Архів містить лише schema `obriy`, без ролей та чужих проєктів. Файл створюється ексклюзивно з правами 600. Копіюйте зашифрований файл у своє off-site сховище, задайте щоденний backup і кінцевий retention (наприклад 7 днів). Конкретне сховище та scheduler не створюються автоматично, бо вони не надані. Стандартний KMA deployment-backup охоплює всю shared PostgreSQL і є окремим процесом; його журнали/доступ слід контролювати.

Для restore оберіть НОВУ ПОРОЖНЮ базу, зупиніть зовнішні відправки (`OBRIY_TELEGRAM_MODE=disabled`) і collectors на час перевірки. Скрипт не робить `DROP`, `--clean` або змін у чужих схемах.

```sh
PGDATABASE=obriy_restore OBRIY_RESTORE_ALLOW=true node scripts/backup.mjs restore /private-backups/obriy-2026-09-05.enc
```

Перевірте schema/version, кількість зон, розшифрування synthetic/власної контрольної зони оригінальним application key, FK cascade і `/readyz`. Перед поверненням доставки скасуйте pending/sending outbox зі старого backup та повторіть запити на видалення, отримані після backup. Очікуйте нового свіжого snapshot; не трактуйте старі треки як нове підтвердження. Не робіть `docker compose down -v` для звичайного відновлення сервісу.

Ротація admin/metrics/webhook keys: окреме оновлення `.env` та перезапуск тільки `obriy`; для повного відкликання web-сесій очистіть лише `obriy.sessions`. Encryption key не можна просто замінити: дані треба прочитати старим ключем і перешифрувати новим у контрольованій міграції. Це не автоматизована rotation-функція v0.1.
