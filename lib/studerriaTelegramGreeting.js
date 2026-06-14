const TRUE_ENV_VALUES = new Set(['1', 'true', 'yes', 'on']);

function sanitizeGreetingName(value = '') {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 40);
}

function parseStuderriaTelegramGreetingCommand(text = '') {
  const raw = String(text || '').trim();
  const match = raw.match(/^привітай\s*[:：]\s*(.+)$/iu);
  if (!match) return null;
  const names = String(match[1] || '')
    .split(/[,;\n]+/)
    .map(sanitizeGreetingName)
    .filter(Boolean)
    .slice(0, 8);
  if (!names.length) return null;
  return { names };
}

function formatGreetingNameList(names = []) {
  const cleanNames = names.map(sanitizeGreetingName).filter(Boolean);
  if (cleanNames.length <= 1) return cleanNames[0] || '';
  if (cleanNames.length === 2) return `${cleanNames[0]} і ${cleanNames[1]}`;
  return `${cleanNames.slice(0, -1).join(', ')} і ${cleanNames[cleanNames.length - 1]}`;
}

const STUDERRIA_TG_GREETING_TEMPLATES = [
  ({ names }) =>
    `${names}, з днем народження легенди!!! 🎉🎂\nвід Марченка: мінімум стресу, максимум смішних історій і щоб цей рік був реально сильний, а не просто "ну норм".`,
  ({ names }) =>
    `чат, хвилина уваги: сьогодні ${names} приймають вітання 🥳\nМарченко передає, що ви круті, живіть красиво, не губіться в дедлайнах і лишайтесь тими самими людьми, за яких не соромно поставити ❤️.`,
  ({ names }) =>
    `${names}, happy birthday по-нашому 🎊\nвід мене через бота: хай буде більше моментів "оце тусня", менше моментів "а що дедлайн сьогодні?", і щоб усе важливе складалось як треба.`,
  ({ names, plural }) =>
    `${names}, вітаю з др!!! 🫡🎂\nМарченко бажає ${plural ? 'вам' : 'тобі'} здоров'я, нормального сну, людей поруч і таких історій, які потім ще довго переказують у чаті.`,
  ({ names, plural }) =>
    `${names}, з днем народження!!! 🥳🥳🥳\nце не офіційний пресреліз Studerria, це Марченко каже: ${plural ? 'тримайте' : 'тримай'} щастя, меми, спокій і перемоги при собі.`,
  ({ names }) =>
    `сьогодні святкують: ${names} 🎉\nвід Марченка коротко: ви легенди, не втрачайте вайб, ловіть свої можливості і хай життя частіше підкидає "оце було сильно".`,
  ({ names, plural }) =>
    `${names}, з днем народження, легенд${plural ? 'и' : 'о'} 💪🥳\nМарченко передає: хай ${plural ? 'ваші' : 'твої'} дні народження будуть відоміші, ніж дедлайн за 10 хвилин, а рік буде без зайвої драми і з нормальними перемогами.`,
];

function buildStuderriaTelegramGreeting(names = [], random = Math.random) {
  const cleanNames = names.map(sanitizeGreetingName).filter(Boolean);
  if (!cleanNames.length) return '';
  const indexRaw = Math.floor(Number(random()) * STUDERRIA_TG_GREETING_TEMPLATES.length);
  const index = Number.isInteger(indexRaw)
    ? Math.max(0, Math.min(STUDERRIA_TG_GREETING_TEMPLATES.length - 1, indexRaw))
    : 0;
  const formatter = STUDERRIA_TG_GREETING_TEMPLATES[index] || STUDERRIA_TG_GREETING_TEMPLATES[0];
  return formatter({
    names: formatGreetingNameList(cleanNames),
    plural: cleanNames.length > 1,
  });
}

function isStuderriaTelegramGreetingEnabled(env = process.env) {
  return TRUE_ENV_VALUES.has(String(env.STUDERRIA_TG_DEV_GREETING_ENABLED || '').trim().toLowerCase());
}

function getStuderriaTelegramGreetingTarget(env = process.env) {
  const chatId = String(env.STUDERRIA_TG_DEV_GREETING_TARGET_CHAT_ID || '').trim();
  const threadIdRaw = Number(env.STUDERRIA_TG_DEV_GREETING_TARGET_THREAD_ID || 0);
  const threadId = Number.isInteger(threadIdRaw) && threadIdRaw > 0 ? threadIdRaw : null;
  return {
    enabled: isStuderriaTelegramGreetingEnabled(env),
    chatId,
    threadId,
  };
}

module.exports = {
  STUDERRIA_TG_GREETING_TEMPLATES,
  buildStuderriaTelegramGreeting,
  formatGreetingNameList,
  getStuderriaTelegramGreetingTarget,
  isStuderriaTelegramGreetingEnabled,
  parseStuderriaTelegramGreetingCommand,
  sanitizeGreetingName,
};
