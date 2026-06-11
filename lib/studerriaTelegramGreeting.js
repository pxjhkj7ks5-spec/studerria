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
    `${names}, з днем народження! Бажаємо, щоб дедлайни обходили стороною, пари закінчувались раніше, а настрій тримався на рівні "я все встигаю".`,
  ({ names }) =>
    `Сьогодні офіційно вітаємо ${names}. Нехай буде більше нормальної кави, хороших новин і людей, які скидають конспекти без нагадувань.`,
  ({ names }) =>
    `${names}, happy birthday по-студентськи: мінімум стресу, максимум смішних історій і щоб усі "потім дороблю" реально дороблялись.`,
  ({ names, plural }) =>
    `Великий день для ${names}. ${plural ? 'Нехай у вас' : 'Нехай у тебе'} буде стільки удачі, скільки вкладок відкрито перед дедлайном, але без такого ж хаосу.`,
  ({ names, plural }) =>
    `${names}, вітаємо! ${plural ? 'Ловіть' : 'Лови'} побажання: менше рандомних переносів, більше вільних вечорів і стабільний вайб "я це вивезу".`,
  ({ names }) =>
    `Аплодисменти в чат для ${names}. Бажаємо року без зайвих нервів, з класними людьми поруч і з оцінками, за які не треба торгуватись з долею.`,
  ({ names, plural }) =>
    `${names}, з днем народження! ${plural ? 'Хай ваші' : 'Хай твої'} плани збуваються швидше, ніж староста пише "пара буде", і приємніше, ніж раптовий вихідний.`,
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
