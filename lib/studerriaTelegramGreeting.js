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
    `${names}, з днем народження легенди!!! 🎉🎂\nСтудерія передає: хай цей рік буде сильний і без зайвого стресу.`,
  ({ names }) =>
    `чат, хвилина уваги: сьогодні ${names} приймають вітання 🥳\nСтудерія передає: живіть красиво і не губіть свій вайб.`,
  ({ names }) =>
    `${names}, happy birthday по-нашому 🎊\nСтудерія передає: більше моментів "оце тусня" і менше "а дедлайн сьогодні?".`,
  ({ names, plural }) =>
    `${names}, вітаємо з др!!! 🫡🎂\nСтудерія бажає ${plural ? 'вам' : 'тобі'} нормального сну і людей поруч.`,
  ({ names, plural }) =>
    `${names}, з днем народження!!! 🥳🥳🥳\nце не офіційний пресреліз, це Студерія каже: ${plural ? 'тримайте' : 'тримай'} щастя і спокій при собі.`,
  ({ names }) =>
    `сьогодні святкують: ${names} 🎉\nСтудерія коротко передає: ви легенди, не втрачайте вайб.`,
  ({ names, plural }) =>
    `${names}, з днем народження, легенд${plural ? 'и' : 'о'} 💪🥳\nСтудерія передає: хай рік буде без зайвої драми і з нормальними перемогами.`,
  ({ names }) =>
    `${names}, з днем народження!!! 🎂\nСтудерія передає: хай усе важливе складається як треба.`,
  ({ names }) =>
    `${names}, вітаємооо 🎉\nСтудерія передає: більше крутих новин і менше дивних днів.`,
  ({ names, plural }) =>
    `${names}, з др 🥳\nСтудерія бажає ${plural ? 'вам' : 'тобі'} спокійного року і красивих перемог.`,
  ({ names }) =>
    `${names}, happy birthday!!! 🎊\nСтудерія передає: хай буде легко там, де зазвичай душно.`,
  ({ names }) =>
    `сьогодні день ${names} 🎂\nСтудерія передає: нехай цей день буде гучний, а рік - добрий.`,
  ({ names, plural }) =>
    `${names}, з днем народження 🫶\nСтудерія каже: ${plural ? 'бережіть' : 'бережи'} себе і не зникайте з радарів.`,
  ({ names }) =>
    `${names}, вітаємо з новим особистим роком 🎉\nСтудерія передає: хай буде більше "я це вивіз" і менше хаосу.`,
  ({ names }) =>
    `${names}, з днем народження!!! 🥳\nСтудерія передає: хай сьогодні буде красиво, а далі ще краще.`,
  ({ names, plural }) =>
    `${names}, приймай${plural ? 'те' : ''} вітання 🎂\nСтудерія бажає ${plural ? 'вам' : 'тобі'} нормального темпу і хороших людей поруч.`,
  ({ names }) =>
    `${names}, birthday alert 🎉\nСтудерія передає: хай рік буде без зайвих нервів.`,
  ({ names }) =>
    `${names}, з днем народження!!!\nСтудерія передає: залишайтесь такими ж класними 🥳`,
  ({ names, plural }) =>
    `${names}, вітаємо з др 🎊\nСтудерія каже: ${plural ? 'ловіть' : 'лови'} удачу і не віддавайте її нікому.`,
  ({ names }) =>
    `${names}, сьогодні ваш день 🥳\nСтудерія передає: хай буде що згадати і з чого сміятись.`,
  ({ names, plural }) =>
    `${names}, з днем народження 🎂\nСтудерія бажає ${plural ? 'вам' : 'тобі'} менше дедлайнової паніки і більше нормальних вечорів.`,
  ({ names }) =>
    `${names}, вітаємо в чаті 🎉\nСтудерія передає: хай цей рік буде не просто норм, а прям хороший.`,
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
