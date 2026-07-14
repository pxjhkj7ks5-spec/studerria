export type ShieldlineLocale = "uk" | "ru" | "en";

const en = {
  "brand.tagline": "One city. One night. Your command.",
  "catalog.eyebrow": "Campaign command simulation",
  "catalog.title": "Hold the line.",
  "catalog.lead": "Place real defenses, follow live launches, and hold the city through one operation.",
  "catalog.open": "Open Campaign",
  "catalog.campaign": "Campaign", "catalog.campaignDesc": "A sequence of night operations where each result carries into the next mission.", "catalog.resources": "Resources", "catalog.risk": "Main risk", "catalog.victory": "Victory",
  "mission.1": "Random Threat Night",
  "catalog.paused": "Training, Sandbox, Ranked, Co-op, Rapid Response and Daily Defense are paused while Campaign reaches production quality.",
  "panel.layers": "Layers", "panel.units": "Defense units", "panel.planning": "Planning", "panel.intel": "Live intelligence", "panel.report": "After-action", "panel.settings": "Settings",
  "layer.live": "Live", "layer.threats": "Threats", "layer.coverage": "Coverage", "layer.logistics": "Logistics",
  "operation.planning": "planning", "operation.countdown": "countdown", "operation.running": "running", "operation.paused": "paused", "operation.completed": "completed",
  "operation.syncing": "Synchronizing operation…", "operation.launchIn": "Launch in {seconds}s", "operation.start": "Start operation", "operation.pause": "Pause", "operation.resume": "Resume", "operation.new": "New operation",
  "readiness.radar": "Place at least one radar.", "readiness.kinetic": "Place at least one combat air-defense unit.", "readiness.ready": "Defense plan ready.",
  "stats.cycle": "Cycle", "stats.revealed": "Revealed", "stats.interceptions": "Interceptions", "stats.impacts": "Impacts", "stats.pressure": "Pressure", "stats.supply": "Supply delay",
  "stream.title": "Authoritative stream", "stream.waiting": "Awaiting launch", "stream.sequence": "Sequence {sequence}",
  "aar.title": "After-action report", "aar.pending": "Pending first completed cycle", "aar.server": "Authoritative server result", "aar.intercepts": "Intercepts", "aar.impacts": "Impacts", "aar.ammo": "Ammo spent", "aar.version": "Sim version", "aar.damage": "damage",
  "event.started": "Campaign operation started.", "event.warning": "Launch warning in the {sector} sector.", "event.launched": "{count} targets launched toward the city.", "event.detected": "Radar confirmed {count} inbound targets.", "event.fired": "Air defense fired at {count} targets.", "event.intercepted": "{count} targets intercepted.", "event.impact": "{count} targets reached the defended sector.", "event.completed": "Campaign operation completed.",
  "action.close": "Close", "action.back": "Back", "action.cancelPlacement": "Cancel placement", "action.reset": "Reset Campaign",
} as const;

type TranslationKey = keyof typeof en;

const uk: Record<TranslationKey, string> = {
  "brand.tagline": "Одне місто. Одна ніч. Ваше командування.",
  "catalog.eyebrow": "Симуляція командування кампанією",
  "catalog.title": "Утримайте рубіж.",
  "catalog.lead": "Розмістіть реальне ППО, стежте за живими пусками та втримайте місто протягом однієї операції.",
  "catalog.open": "Відкрити кампанію",
  "catalog.campaign": "Кампанія", "catalog.campaignDesc": "Послідовність нічних операцій, де кожен результат переходить у наступну місію.", "catalog.resources": "Ресурси", "catalog.risk": "Головний ризик", "catalog.victory": "Перемога",
  "mission.1": "Ніч випадкових загроз",
  "catalog.paused": "Навчання, Пісочниця, Рейтинг, Co-op, Швидке реагування та Daily Defense призупинені, доки Кампанія не досягне production-якості.",
  "panel.layers": "Шари", "panel.units": "Підрозділи ППО", "panel.planning": "Планування", "panel.intel": "Бойова розвідка", "panel.report": "Післяопераційний звіт", "panel.settings": "Налаштування",
  "layer.live": "Бій", "layer.threats": "Загрози", "layer.coverage": "Покриття", "layer.logistics": "Логістика",
  "operation.planning": "планування", "operation.countdown": "відлік", "operation.running": "операція", "operation.paused": "пауза", "operation.completed": "завершено",
  "operation.syncing": "Синхронізація операції…", "operation.launchIn": "Пуск через {seconds} с", "operation.start": "Почати операцію", "operation.pause": "Пауза", "operation.resume": "Продовжити", "operation.new": "Нова операція",
  "readiness.radar": "Розмістіть щонайменше один радар.", "readiness.kinetic": "Розмістіть щонайменше одну бойову установку ППО.", "readiness.ready": "План оборони готовий.",
  "stats.cycle": "Цикл", "stats.revealed": "Виявлено", "stats.interceptions": "Перехоплено", "stats.impacts": "Влучання", "stats.pressure": "Тиск", "stats.supply": "Затримка постачання",
  "stream.title": "Авторитетний потік", "stream.waiting": "Очікування пуску", "stream.sequence": "Подія {sequence}",
  "aar.title": "Післяопераційний звіт", "aar.pending": "Очікується завершення першої операції", "aar.server": "Авторитетний результат сервера", "aar.intercepts": "Перехоплення", "aar.impacts": "Влучання", "aar.ammo": "Витрачено БК", "aar.version": "Версія симуляції", "aar.damage": "пошкоджень",
  "event.started": "Операцію кампанії розпочато.", "event.warning": "Попередження про пуск у секторі {sector}.", "event.launched": "Запущено цілей: {count}.", "event.detected": "Радар підтвердив вхідні цілі: {count}.", "event.fired": "ППО відкрила вогонь по цілях: {count}.", "event.intercepted": "Перехоплено цілей: {count}.", "event.impact": "До захищеного сектора дісталися цілі: {count}.", "event.completed": "Операцію кампанії завершено.",
  "action.close": "Закрити", "action.back": "Назад", "action.cancelPlacement": "Скасувати розміщення", "action.reset": "Скинути кампанію",
};

const ru: Record<TranslationKey, string> = {
  "brand.tagline": "Один город. Одна ночь. Ваше командование.",
  "catalog.eyebrow": "Симуляция командования кампанией",
  "catalog.title": "Удержите рубеж.",
  "catalog.lead": "Разместите реальную ПВО, следите за живыми пусками и удержите город в течение одной операции.",
  "catalog.open": "Открыть кампанию",
  "catalog.campaign": "Кампания", "catalog.campaignDesc": "Последовательность ночных операций, где каждый результат переходит в следующую миссию.", "catalog.resources": "Ресурсы", "catalog.risk": "Главный риск", "catalog.victory": "Победа",
  "mission.1": "Ночь случайных угроз",
  "catalog.paused": "Обучение, Песочница, Рейтинг, Co-op, Быстрое реагирование и Daily Defense приостановлены до завершения Кампании.",
  "panel.layers": "Слои", "panel.units": "Подразделения ПВО", "panel.planning": "Планирование", "panel.intel": "Боевая разведка", "panel.report": "Отчёт об операции", "panel.settings": "Настройки",
  "layer.live": "Бой", "layer.threats": "Угрозы", "layer.coverage": "Покрытие", "layer.logistics": "Логистика",
  "operation.planning": "планирование", "operation.countdown": "отсчёт", "operation.running": "операция", "operation.paused": "пауза", "operation.completed": "завершено",
  "operation.syncing": "Синхронизация операции…", "operation.launchIn": "Пуск через {seconds} с", "operation.start": "Начать операцию", "operation.pause": "Пауза", "operation.resume": "Продолжить", "operation.new": "Новая операция",
  "readiness.radar": "Разместите хотя бы один радар.", "readiness.kinetic": "Разместите хотя бы одну боевую установку ПВО.", "readiness.ready": "План обороны готов.",
  "stats.cycle": "Цикл", "stats.revealed": "Обнаружено", "stats.interceptions": "Перехвачено", "stats.impacts": "Попадания", "stats.pressure": "Давление", "stats.supply": "Задержка снабжения",
  "stream.title": "Авторитетный поток", "stream.waiting": "Ожидание пуска", "stream.sequence": "Событие {sequence}",
  "aar.title": "Отчёт об операции", "aar.pending": "Ожидается завершение первой операции", "aar.server": "Авторитетный результат сервера", "aar.intercepts": "Перехваты", "aar.impacts": "Попадания", "aar.ammo": "Израсходовано БК", "aar.version": "Версия симуляции", "aar.damage": "повреждений",
  "event.started": "Операция кампании начата.", "event.warning": "Предупреждение о пуске в секторе {sector}.", "event.launched": "Запущено целей: {count}.", "event.detected": "Радар подтвердил входящие цели: {count}.", "event.fired": "ПВО открыла огонь по целям: {count}.", "event.intercepted": "Перехвачено целей: {count}.", "event.impact": "До защищаемого сектора дошли цели: {count}.", "event.completed": "Операция кампании завершена.",
  "action.close": "Закрыть", "action.back": "Назад", "action.cancelPlacement": "Отменить размещение", "action.reset": "Сбросить кампанию",
};

export function resolveLocale(): ShieldlineLocale {
  return "uk";
}

export const shieldlineLocale = resolveLocale();
const active = shieldlineLocale === "ru" ? ru : shieldlineLocale === "en" ? en : uk;

export function t(key: TranslationKey, values: Record<string, string | number> = {}) {
  return Object.entries(values).reduce((text, [name, value]) => text.replaceAll(`{${name}}`, String(value)), active[key] || en[key]);
}

export function formatNumber(value: number, options?: Intl.NumberFormatOptions) {
  return new Intl.NumberFormat(shieldlineLocale === "uk" ? "uk-UA" : shieldlineLocale === "ru" ? "ru-RU" : "en-US", options).format(value);
}

export function formatSimulationEvent(event: SimulationEvent) {
  const count = formatNumber(Number(event.payload.count || event.payload.tracks || 0));
  const values = { count, sector: String(event.payload.launchSectorName || event.sectorId || event.targetId || "—") };
  if (event.type === "mission.started") return t("event.started", values);
  if (event.type === "launch.warning") return t("event.warning", values);
  if (event.type === "threat.launched") return t("event.launched", values);
  if (event.type === "track.detected" || event.type === "wave.detected") return t("event.detected", values);
  if (event.type === "battery.fired") return t("event.fired", values);
  if (event.type === "interception") return t("event.intercepted", values);
  if (event.type === "impact") return t("event.impact", values);
  if (event.type === "mission.completed") return t("event.completed", values);
  return event.message;
}
import type { SimulationEvent } from "../domain/contracts";
