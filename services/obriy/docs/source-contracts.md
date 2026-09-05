# Обрій — перевірені джерела та вимоги

Перевірено 2026-09-05. Прочитано надану 58-сторінкову специфікацію. Її готовий prompt — частина документа-опису, не окрема інструкція користувача. Сторонні облікові записи не створювались, форми/повідомлення не надсилались. Live-перевірки виводили лише ключі й типи JSON, без поточних координат, курсів, назв місць чи текстів моніторингу.

## Підтверджені зовнішні контракти

### NEPTUN

Джерела: [документація](https://neptun.in.ua/developers), [умови API](https://neptun.in.ua/api-terms), [джерела](https://neptun.in.ua/dzherela), [приватність](https://neptun.in.ua/privacy). Документація/умови датовані 2026-07-09; джерела 2026-08-01; приватність 2026-08-21. API безкоштовний, без токена, дозволене комерційне й некомерційне використання з видимим посиланням NEPTUN поряд із даними. REST GET не частіше разу на 5 секунд; рекомендується WebSocket. Агрегатор не має радара й не замінює офіційної тривоги. Його повідомлення можуть бути неточними/затриманими. Політика не визначає retention транспортних IP-логів; серверний proxy приховує зони, а не IP самого VPS.

Один потік: `wss://neptun.in.ua/api/v1/stream`. Перевірені наживо всі п'ять типів:

```ts
{ type: 'snapshot', ts: string, data: { threats: Threat[] } }
{ type: 'upsert', ts: string, data: Threat }
{ type: 'remove', ts: string, data: { id: string } }
{ type: 'heartbeat', ts: string } // У LIVE НЕМАЄ data!
{ type: 'alerts', ts: string, data: AlertsSnapshot }

type AlertsSnapshot = {
  version?: number;
  updatedAt?: string;
  raions: { key: string; name: string; oblast: string; since: string }[];
  oblasts: { key: string; name: string; oblast: string; since: string }[];
};
```

REST:

```ts
GET https://neptun.in.ua/api/v1/threats
// { serverTime: string, threats: Threat[] }
GET https://neptun.in.ua/api/v1/alerts
// AlertsSnapshot; live has version, updatedAt, raions, oblasts
GET https://neptun.in.ua/api/v1/messages
// Documented: { messages: [{ channel, text, date }] }; not fetched live
GET https://neptun.in.ua/api/v1/sources
// Live: { generatedAt: string, counts: object,
// sources: [{ handle, kind, region, title }],
// nonTelegram: [{ kind, note, region, title }] }
```

Документований Threat:

```ts
{
 id: string, type: string, title: string, region: string,
 district: string, locality: string, lat: number, lon: number,
 heading?: number | null, confidenceLevel: string, sourceCount?: number,
 count?: number, updatedAt: string, status: string,
 explanationShort?: string,
 velocity?: { bearingDeg: number, speedKmh: number },
 confirmedAt?: string, uncertaintyKm?: number, positionQuality?: string,
 advisory?: boolean, areaOnly?: boolean
}
```

Окремий live-зріз підтвердив додаткові `presumptiveCourse:boolean`, `destination:boolean`, `lifecycle:string`, `displayConfidence:string`. Семантика цих додаткових полів повністю не задокументована; застосовувати консервативно. Частина upsert не мала confirmedAt, усі записи перевіреного зрізу не мали velocity. Heading сам по собі не дає доказу швидкості. Відсутні areaOnly/advisory документовано означають false. Невідомі типи/поля не повинні валити collector. SDK має жорсткий enum і власні припущення — власний tolerant adapter тут доцільніший.

`areaOnly=true`: координати — центроїд області; не рахувати персональну відстань/курс/прогноз. `advisory=true`: спокійне інформаційне спостереження. `key` тривог відповідає ключам власних GeoJSON NEPTUN; у запису обласної тривоги `oblast` може бути порожнім, назва тоді в `name`.

Покриття джерел неповне. Офіційні тривоги NEPTUN бере з UkraineAlarm, а позиційні повідомлення — з Telegram. Не вважати alerts.in.ua чи повтор того самого Telegram-повідомлення другим незалежним координатним свідченням. AirSigma у перевіреному реєстрі відсутній.

### alerts.in.ua

[Офіційна документація](https://devs.alerts.in.ua/), [форма отримання токена](https://alerts.in.ua/api-request). Потрібен персональний токен; він надсилається власнику після заявки. Backend-запити: `Authorization: Bearer …`. Soft 8–10/min/IP, hard 12/min/IP; повторні порушення можуть блокувати токен/IP. За замовчуванням poll 12 секунд і conditional GET `If-Modified-Since` з попереднього `Last-Modified`. Обробляти 200/304/401/403/429; на 429 сповільнюватися. Це агрегатор офіційних повідомлень, не гарантований канал критичної інфраструктури. Запити всіх користувачів слід проксувати сервером.

```ts
GET https://api.alerts.in.ua/v1/alerts/active.json
{ alerts: [{
  id: number, location_title: string,
  location_type: 'oblast'|'raion'|'city'|'hromada'|'unknown',
  started_at: string, finished_at: string|null, updated_at: string,
  alert_type: 'air_raid'|'artillery_shelling'|'urban_fights'|'chemical'|'nuclear',
  location_uid: string, location_oblast: string,
  location_oblast_uid?: string, location_raion?: string,
  notes?: string, calculated?: boolean
}] }
```

`calculated` стосується прогнозованого або фактичного часу закінчення, а не якості координат. Копіювати JSON-приклад документації буквально не слід: у ньому пропущена кома біля location_oblast_uid. Live без токена не перевірявся. Location UID містяться в документації; зокрема Київська область 14, м. Київ 31, Закарпатська область 11. Для зони слід окремо зберігати вибраний administrative UID/назву, не надсилати координати на сторонній geocoder.

### Telegram

[Bot API](https://core.telegram.org/bots/api), [FAQ](https://core.telegram.org/bots/faq), [BotFather](https://t.me/BotFather). Token створює власник через BotFather; credentials не можна знайти у відкритому інтернеті. JSON HTTPS POST `https://api.telegram.org/bot<TOKEN>/sendMessage`: `chat_id`, `text` (до 4096 символів), за потреби `parse_mode:'HTML'`, `link_preview_options:{is_disabled:true}`. Перевіряти JSON `ok`, не лише HTTP status. 429: `parameters.retry_after` — секунди. Ліміт приблизно 1 повідомлення/сек/чат, bulk приблизно 30/сек; paid broadcast не вмикати.

Webhook: HTTPS `setWebhook`, `secret_token` 1–256 символів `[A-Za-z0-9_-]`, перевіряти `X-Telegram-Bot-Api-Secret-Token` до обробки payload. `update_id` використовувати для дедуплікації. Bot API повідомляє про повторення webhook при не-2xx; вхідні updates зберігаються до 24 год. Long polling і webhook взаємовиключні. Канали доступні боту, коли він є їх учасником. Немає універсального читання довільних сторонніх каналів.

Інженерний висновок: transactional outbox гарантує один локальний dedupe-запис, але не exactly-once на стороні Telegram при успішному send та втраті відповіді/падінні перед mark-sent. Документувати можливий повтор у такому вікні; у Bot API sendMessage немає idempotency-key.

### AirSigma

Точну ідентичність сервісу/каналу специфікація не надає. Пошук не знайшов відповідної офіційної API-документації. Не вмикати вигаданий endpoint або MTProto. Залишити disabled SecondarySourceAdapter і AIRSIGMA_SOURCE_IDENTIFIER до конкретного контракту. Відсутність результату пошуку не доводить, що сервіс не існує.

## Ключові вимоги PDF для реалізації й приймання

- v0.1: серверний TypeScript/Fastify/PostgreSQL collector, deterministic Threat Engine, приватний Telegram, durable outbox, захищені зони. PWA/Expo/fusion — майбутні адаптери.
- Lat/lon кінцевих зон доступні лише VPS runtime, зберігаються AEAD-encrypted із ключем поза DB/backup. Ніколи не передавати їх NEPTUN, alerts.in.ua, Telegram, tile/geocoding providers. Не використовувати embedded NEPTUN map.
- Захищати chat ID, plaintext повідомлення, токени та координати від логування; UUID внутрішніх ID; authenticated CLI/admin setup замість Telegram GPS. `/privacy`, `/delete_me`, `/start`, `/status`, `/zones`, `/pause`, `/resume`.
- Обмеження payload/frame, finite numeric invariants, quarantine invalid/future timestamps, unknown enum tolerant handling, duplicate no-op, older event cannot overwrite newer. Один upstream stream через singleton/PG advisory leader lock.
- WS backoff+jitter, watchdog, REST resync/fallback >=5s, reconnect fresh snapshot, graceful shutdown. Відсутність/застарілість джерела не є доказом безпеки та не може піднімати ризик.
- Haversine/initial bearing/great-circle destination/angular wrap; короткий конфігурований forecast, тільки position+heading+speed+confirmedAt. Без motion немає «наближається». Без independent ETA basis немає точної кількості хвилин.
- U(t)=sqrt(U0²+(driftRate*tMinutes)²). U0 має floor, approximate/presumptive мають більший drift. Це tuning parameters, не заявлені технічні властивості зброї. Збільшення невизначеності не підвищує evidence.
- Score 100*(.20 evidence+.10 freshness+.15 proximity+.20 approaching+.30 corridorHit+.05 officialContext); evidence defaults .35/.60/.80/.30 low/medium/high/unknown; approx -.15, presumptive -.10, stale -.30; sourceCount bonus .03 за додаткове джерело, максимум 4 бонуси. Versioned config збережений з decision.
- WATCH enter >=45/2 оцінки, exit <30/3; WARNING >=65/2, exit <50/3; HIGH >=80/2, exit <65/3. WARNING додатково вимагає corridor intersection та approaching evidence. HIGH — strong intersection або already within expanded protected area. AreaOnly/advisory/stale guards сильніші за score.
- Anti-spam на user/zone/track: escalation, closer band, new approach, new corridor hit, cooldown або resolution після WARNING/HIGH. Bands >100,75–100,50–75,30–50,20–30,10–20,<10 км. Не надсилати кожний upsert.
- Persist state+outbox в одній транзакції. Dispatcher з claim lease, bounded retries/backoff, 429 retry_after, TTL, dead-letter. Kill switch delivery при збереженні ingestion.
- Мінімальні таблиці: users,zones,source_events,tracks,track_points,official_alerts,risk_assessments,alert_state,notification_outbox,notifications,push_subscriptions,audit_events. Cascade deletion без orphan PII. Retention конфігурований: raw 24–72h, points 7d, alerts 7–30d, risk/notifications 30d, audit 30–90d.
- `/healthz` liveness, `/readyz` DB+source readiness, sanitized `/api/v1/status`; `/metrics` тільки auth/private network. Source health, parse errors, stale counts, outbox age, notification failures, 429, DB latency.
- Docker Compose, healthchecks, non-root/read-only де практично, restart, migrations, dependency lockfile, CI tests/secret/dependency/container checks. TLS й shared root інтеграцію узгоджувати з KMA; не створювати другий конкуретний порт 443.
- Документи: architecture/privacy/threat-engine/source-contracts/operations/disaster-recovery, exact bootstrap/backup/restore/rotation/outage steps. Encrypted backup і фактичний restore в чисту test DB; неперевірений backup не називати перевіреним.
- Acceptance: snapshot/upsert exactly-once local mutation, duplicate no duplicate alert, remove resolves, reconnect converges, areaOnly no distance, advisory no high, stale no escalation, synthetic approach reaches all levels, near miss no HIGH, oscillation no spam, turn-away hysteresis, official context no invented target, Telegram 429/500 retry, unique dedupe, no coordinates/secrets in logs/image/messages, complete deletion, honest health, metrics, restore test, fully documented fresh deploy.

## Що можна заповнити в env

Без сторонніх акаунтів доступні NEPTUN URLs; можна згенерувати сильні локальні `ZONE_ENCRYPTION_KEY`, `TELEGRAM_WEBHOOK_SECRET`, DB password, admin/metrics token. Обов'язкові від власника: `TELEGRAM_BOT_TOKEN`, `ALERTS_IN_UA_TOKEN`, обраний реальний hostname/HTTPS webhook, protected zone bootstrap (поза Telegram), Telegram chat binding. Не вигадувати місцеположення користувача, домен, токени чи radius як нібито погоджені дані. Radius/chosen sensitivity можуть мати ясно позначений конфігурований default.

Без Telegram/alerts токенів можливий collector/status запуск із чесним статусом «доставку/друге джерело не налаштовано»; це не повністю активна персональна система. Після деплою відокремити фактичний доступний backend від інтеграцій, що ще потребують credentials.
