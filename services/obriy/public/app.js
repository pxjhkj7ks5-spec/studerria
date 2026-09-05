const rawBase = document.querySelector('meta[name="app-base"]')?.content ?? '/obriy';
const base = /^\/[a-zA-Z0-9/_-]*$/.test(rawBase) ? rawBase.replace(/\/$/, '') : '/obriy';
const byId = (id) => document.getElementById(id);
const state = { status: null, me: null, refreshing: false, editingZone: null, loaded: false, notificationCodeExpires: null };
const dateFormat = new Intl.DateTimeFormat('uk-UA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const timeFormat = new Intl.DateTimeFormat('uk-UA', { hour: '2-digit', minute: '2-digit' });
let toastTimer;
let lastZoneSignature;

class RequestError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(`${base}${path}`, {
      ...options,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: controller.signal,
      headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    if (!response.ok) {
      const messages = {
        400: 'Перевірте введені дані й спробуйте ще раз.',
        401: 'Потрібно увійти з чинним ключем доступу.',
        403: 'Ця дія недоступна для вашої сесії. Спробуйте увійти знову.',
        404: 'Запис уже недоступний. Оновіть дані.',
        409: 'Запис змінився. Оновіть дані й повторіть дію.',
        422: 'Перевірте формат і допустимі значення полів.',
        429: 'Забагато запитів. Зачекайте хвилину перед повторною спробою.',
        503: 'Сервіс ще не налаштований або тимчасово недоступний.',
      };
      throw new RequestError(response.status, messages[response.status] ?? 'Не вдалося виконати запит. Спробуйте пізніше.');
    }
    if (response.status === 204) return null;
    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes('application/json')) throw new RequestError(0, 'Сервер повернув неочікувану відповідь. Спробуйте оновити сторінку.');
    return await response.json();
  } catch (error) {
    if (error instanceof RequestError) throw error;
    if (error.name === 'AbortError') throw new RequestError(0, 'Сервер не відповідає вчасно. Перевірте з’єднання й повторіть спробу.');
    throw new RequestError(0, 'Немає з’єднання із сервером. Дані можуть бути неактуальними.');
  } finally { clearTimeout(timer); }
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function icon(paths, className = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  if (className) svg.setAttribute('class', className);
  for (const d of paths) { const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', d); svg.append(path); }
  return svg;
}

function showMessage(id, message = '') { const target = byId(id); target.textContent = message; target.hidden = !message; }
function toast(message) { clearTimeout(toastTimer); showMessage('toast', message); toastTimer = setTimeout(() => showMessage('toast'), 5000); }
function openDialog(id) { const dialog = byId(id); if (!dialog.open) dialog.showModal(); }
function authenticatedAction(action) { if (!state.me) { openDialog('login-dialog'); return; } action(); }
function dateValue(value) { if (value === null || value === undefined || value === '') return null; const stamp = typeof value === 'number' ? value : Date.parse(value); return Number.isFinite(stamp) ? stamp : null; }
function clockNow() { return dateValue(state.status?.serverTime) ?? Date.now(); }
function relativeTime(value) {
  const stamp = dateValue(value);
  if (stamp === null) return 'Ще немає даних';
  const seconds = Math.max(0, Math.floor((clockNow() - stamp) / 1000));
  if (seconds < 60) return 'Щойно';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} хв тому`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} год тому`;
  return dateFormat.format(stamp);
}
function sourceInfo(source, type) {
  if (!source) return { label: 'Недоступно', color: 'offline', fresh: false, at: null };
  const sourceState = String(source.state ?? '').toLowerCase();
  const at = type === 'neptun' ? source.lastEventAt ?? source.lastSnapshotAt : source.lastSuccessAt;
  const stamp = dateValue(at);
  const age = stamp === null ? Infinity : clockNow() - stamp;
  const disabled = ['disabled', 'unconfigured', 'not_configured', 'setup_required', 'missing_token'].includes(sourceState);
  const unhealthy = ['error', 'offline', 'disconnected', 'stopped', 'unavailable', 'failed', 'unauthorized'].includes(sourceState);
  const waiting = ['starting', 'connecting', 'reconnecting', 'backoff', 'waiting'].includes(sourceState);
  const degraded = sourceState === 'degraded';
  const fresh = !disabled && !unhealthy && !waiting && !degraded && sourceState !== 'stale' && age >= -60000 && age <= 90000;
  if (disabled) return { label: 'Не налаштовано', color: 'pending', fresh: false, at };
  if (unhealthy) return { label: 'Немає з’єднання', color: 'offline', fresh: false, at };
  if (waiting) return { label: 'З’єднуємося', color: 'pending', fresh: false, at };
  if (degraded) return { label: 'Джерело працює з перебоями', color: 'pending', fresh: false, at };
  if (fresh) return { label: 'Дані актуальні', color: 'healthy', fresh: true, at };
  return { label: stamp === null ? 'Очікуємо дані' : 'Дані застаріли', color: 'pending', fresh: false, at };
}

function renderSource(id, info) {
  const label = byId(`${id}-state`);
  label.className = `source-state ${info.color}`;
  label.textContent = info.label;
  const time = byId(`${id}-time`);
  time.textContent = relativeTime(info.at);
  const stamp = dateValue(info.at);
  time.title = stamp === null ? '' : dateFormat.format(stamp);
}

function renderStatus() {
  const status = state.status;
  const neptun = sourceInfo(status?.sources?.neptun, 'neptun');
  const alerts = sourceInfo(status?.sources?.alerts, 'alerts');
  renderSource('neptun', neptun);
  renderSource('alerts', alerts);
  const complete = neptun.fresh && alerts.fresh;
  const connected = Boolean(status);
  const configured = status?.configured !== false;
  const connection = byId('connection-label');
  connection.replaceChildren(element('i', `status-dot ${!connected ? 'offline' : complete ? 'healthy' : 'pending'}`), document.createTextNode(!connected ? 'Немає з’єднання' : !configured ? 'Потрібне налаштування' : complete ? 'Джерела актуальні' : 'Дані обмежені'));
  let title;
  let description;
  if (!connected) {
    title = 'Немає з’єднання із сервером';
    description = 'Поточний стан загроз невідомий. Перевірте офіційні повідомлення та спробуйте оновити дані.';
  } else if (!configured) {
    title = 'Потрібне налаштування сервісу';
    description = 'Власник сервера має додати ключі доступу та налаштувати зберігання. До цього персональний моніторинг недоступний.';
  } else if (!neptun.fresh) {
    title = 'Очікуємо актуальні дані';
    description = 'Джерело моніторингу ще не під’єдналося або дані застаріли. Ситуацію для ваших зон наразі не можна оцінити.';
  } else if (!alerts.fresh) {
    title = 'Моніторинг із неповними даними';
    description = 'Дані NEPTUN надходять. Незалежне джерело офіційних тривог зараз недоступне або ще не налаштоване.';
  } else {
    title = 'Джерела даних працюють';
    description = 'Сервер отримує дані моніторингу та офіційних тривог. Це стан джерел, а не підтвердження безпеки.';
  }
  byId('overview-title').textContent = title;
  byId('overview-description').textContent = description;
  byId('overview-updated').textContent = status?.serverTime ? `Перевірено о ${timeFormat.format(dateValue(status.serverTime) ?? Date.now())}` : 'Поточний стан невідомий';
  byId('version-label').textContent = status?.version ? `Обрій · v${String(status.version).slice(0, 24)}` : 'Обрій';
  const account = byId('account-button');
  account.firstChild.textContent = state.me ? 'Мій профіль' : 'Увійти';
  byId('delete-account-button').hidden = !state.me;
  renderDelivery();
}

function renderEmptyZone(title, description, buttonLabel, action) {
  const wrapper = element('div', 'empty-state');
  const graphic = element('div', 'empty-illustration');
  const svg = icon(['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z', 'M12 1v4m11 7h-4M12 23v-4M1 12h4']);
  svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '1.2');
  graphic.append(svg);
  wrapper.append(graphic, element('h3', '', title), element('p', '', description));
  if (buttonLabel) { const button = element('button', 'button button-secondary', buttonLabel); button.type = 'button'; button.addEventListener('click', action); wrapper.append(button); }
  byId('zones-list').replaceChildren(wrapper);
}

function rowButton(label, paths, onClick, destructive = false) {
  const button = element('button', `row-action${destructive ? ' destructive' : ''}`);
  button.type = 'button'; button.title = label; button.setAttribute('aria-label', label); button.append(icon(paths));
  button.addEventListener('click', () => onClick(button));
  return button;
}

function renderZones() {
  const zones = Array.isArray(state.me?.zones) ? state.me.zones : [];
  const signature = JSON.stringify({ authenticated: Boolean(state.me), zones });
  if (signature === lastZoneSignature) return;
  lastZoneSignature = signature;
  byId('zones-list').classList.toggle('has-zones', Boolean(state.me && zones.length));
  byId('zone-count').textContent = state.me ? String(zones.length) : '—';
  byId('nav-zone-count').textContent = state.me ? String(zones.length) : '—';
  if (!state.me) {
    renderEmptyZone('Увійдіть, щоб додати свої зони', 'Ваші місця доступні лише після входу. Додайте зони та налаштуйте персональні повідомлення.', 'Увійти в особистий простір', () => openDialog('login-dialog'));
    return;
  }
  if (!zones.length) {
    renderEmptyZone('У вас поки немає зон', 'Додайте місце та радіус спостереження. Точні координати залишаться на вашому сервері.', 'Додати першу зону', () => openZone());
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const zone of zones) {
    const row = element('article', 'zone-row');
    const graphic = element('div', 'zone-icon');
    graphic.append(icon(['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z']));
    const content = element('div', 'zone-main');
    const heading = element('div', 'zone-heading');
    heading.append(element('h3', '', String(zone.label ?? 'Зона')), element('span', `zone-state${zone.enabled === false ? ' paused' : ''}`, zone.enabled === false ? 'Вимкнено' : 'Активна'));
    const region = zone.oblast ? ` · ${String(zone.oblast)}` : '';
    content.append(heading, element('p', 'zone-detail', `Радіус ${Number.isFinite(Number(zone.radiusKm)) ? Number(zone.radiusKm) : '—'} км${region}`));
    const controls = element('div', 'zone-controls');
    controls.append(
      rowButton(`Редагувати зону ${zone.label}`, ['m16 3 5 5-12 12-6 1 1-6L16 3Z', 'm13 6 5 5'], () => openZone(zone)),
      rowButton(`${zone.enabled === false ? 'Увімкнути' : 'Призупинити'} зону ${zone.label}`, zone.enabled === false ? ['m9 5 11 7-11 7V5Z'] : ['M8 5v14M16 5v14'], (button) => mutate(button, () => request(`/api/v1/zones/${encodeURIComponent(zone.id)}`, { method: 'PATCH', body: { enabled: zone.enabled === false } }), 'Зону оновлено')),
      rowButton(`Видалити зону ${zone.label}`, ['M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7'], (button) => { if (window.confirm(`Видалити зону «${zone.label}»? Вона перестане брати участь у моніторингу.`)) mutate(button, () => request(`/api/v1/zones/${encodeURIComponent(zone.id)}`, { method: 'DELETE' }), 'Зону видалено'); }, true),
    );
    row.append(graphic, content, controls); fragment.append(row);
  }
  byId('zones-list').replaceChildren(fragment);
}

const levelLabels = { NONE: 'Без оцінки', INFO: 'Інформація', WATCH: 'Спостереження', WARNING: 'Увага', HIGH: 'Потенційна загроза', UNKNOWN: 'Недостатньо даних' };
const threatLabels = { uav: 'БпЛА', fpv: 'FPV-дрон', recon: 'Розвідувальний БпЛА', missile: 'Ракета', ballistic: 'Балістична загроза', kab: 'Керована авіабомба', mig31k: 'Активність МіГ-31К', unknown: 'Повідомлення моніторингу', other: 'Повідомлення моніторингу' };
const explanationLabels = {
  AREA_ONLY: 'Відомо лише область. Персональна відстань і траєкторія не визначаються.',
  AREA_ONLY_NO_GEOMETRY: 'Відомо лише область. Персональна відстань і траєкторія не визначаються.',
  ADVISORY_ONLY: 'Інформаційне спостереження без окремого сигналу негайної загрози.',
  ADVISORY: 'Інформаційне спостереження без окремого сигналу негайної загрози.',
  STALE_TRACK: 'Дані треку застаріли. Вони не є підставою для посилення сигналу.',
  STALE_DATA: 'Дані треку застаріли. Вони не є підставою для посилення сигналу.',
  STALE: 'Дані треку застаріли. Вони не є підставою для посилення сигналу.',
  SOURCE_STALE: 'Джерело не має достатньо свіжих даних.',
  CORRIDOR_INTERSECTS: 'Оцінений коридор руху може перетнути вашу зону.',
  CORRIDOR_INTERSECTION: 'Оцінений коридор руху може перетнути вашу зону.',
  CORRIDOR_MISSES: 'За наявними даними перетин коридору із зоною не визначено.',
  APPROACHING: 'Є ознаки можливого наближення до вашої зони.',
  NOT_APPROACHING: 'У наявних даних немає підтвердження наближення.',
  LOW_CONFIDENCE: 'Достовірність даних обмежена.',
  HIGH_UNCERTAINTY: 'Позиція має значну невизначеність.',
  OFFICIAL_ALERT_ACTIVE: 'Для регіону зафіксовано офіційну тривогу.',
  INSUFFICIENT_EVIDENCE: 'Недостатньо узгоджених даних для персонального попередження.',
  MISSING_POSITION: 'Немає позиції для персональної оцінки.',
  NO_POSITION: 'Немає позиції для персональної оцінки.',
  MISSING_MOTION: 'Напрямок руху невідомий.',
  ZONE_DISABLED: 'Моніторинг зони вимкнено.',
  HIGH_UPSTREAM_CONFIDENCE: 'Джерело позначає високу впевненість у повідомленні.',
  LOW_POSITION_QUALITY: 'Позиція приблизна або не підтверджена.',
  INSUFFICIENT_MOTION: 'Недостатньо даних про напрямок і рух.',
  POSITION_UNAVAILABLE: 'Немає позиції для персональної оцінки.',
  SOURCE_RESOLVED: 'Джерело завершило спостереження за цим треком.',
  SOURCE_STATUS_UNKNOWN: 'Поточний стан треку невідомий.',
  PREDICTION_HORIZON_EXHAUSTED: 'Дані вже не дозволяють оцінювати подальший рух.',
  UNCERTAINTY_DOMINATES: 'Невизначеність надто значна для впевненої оцінки коридору.',
  TURNING_AWAY: 'У наявних даних є ознаки віддалення від зони.',
  NEAR_MISS: 'Оцінений коридор наразі не перетинає зону. Напрямок може змінитися.',
};

function distanceLabel(band) {
  if (typeof band === 'string' && band.length < 50 && /^[\d\s–—\-+<>≤≥.,кмkm]+$/iu.test(band)) return `Приблизна відстань: ${band}${/км|km/i.test(band) ? '' : ' км'}.`;
  return '';
}

function renderAssessments() {
  const container = byId('assessments-list');
  const assessments = Array.isArray(state.me?.assessments) ? state.me.assessments : [];
  const visible = assessments.filter((assessment) => !['NONE', 'RESOLVED'].includes(String(assessment.level).toUpperCase()));
  byId('assessment-count').textContent = state.me ? String(visible.length) : '—';
  if (!state.me) { container.replaceChildren(element('p', 'empty-line', 'Оцінки з’являться після входу.')); return; }
  if (!visible.length) {
    const activeZones = state.me.zones?.some((zone) => zone.enabled !== false);
    const fresh = sourceInfo(state.status?.sources?.neptun, 'neptun').fresh;
    const text = !activeZones ? 'Додайте або увімкніть зону, щоб бачити персональні оцінки.' : fresh ? 'Для ваших зон зараз немає оцінок, що потребують відображення. Це не означає відсутності загрози.' : 'Актуальних оцінок немає. Дочекайтеся відновлення джерел і стежте за офіційними повідомленнями.';
    container.replaceChildren(element('p', 'empty-line', text)); return;
  }
  const ranks = { HIGH: 4, WARNING: 3, WATCH: 2, INFO: 1 };
  visible.sort((a, b) => (ranks[String(b.level).toUpperCase()] ?? 0) - (ranks[String(a.level).toUpperCase()] ?? 0));
  const fragment = document.createDocumentFragment();
  for (const assessment of visible) {
    const zone = state.me.zones?.find((item) => item.id === assessment.zoneId);
    const level = String(assessment.level ?? 'UNKNOWN').toUpperCase();
    const row = element('article', 'assessment-row');
    const content = element('div', 'assessment-content');
    content.append(element('h3', '', `${zone?.label ?? 'Зона'} · ${threatLabels[assessment.threatType] ?? 'Повідомлення моніторингу'}`));
    const codes = Array.isArray(assessment.explanationCodes) ? assessment.explanationCodes : [];
    const texts = [...new Set(codes.map((code) => explanationLabels[String(code).toUpperCase()]).filter(Boolean))].slice(0, 3);
    const distance = distanceLabel(assessment.geometry?.distanceBand);
    if (distance) texts.unshift(distance);
    if (!texts.length) texts.push('Оцінка базується на приблизних даних NEPTUN. Вона не визначає точне місце чи час прибуття загрози.');
    content.append(element('p', '', texts.join(' ')));
    const dataStamp = dateValue(assessment.upstreamUpdatedAt ?? assessment.sourceUpdatedAt);
    const stale = !sourceInfo(state.status?.sources?.neptun, 'neptun').fresh || (dataStamp !== null && clockNow() - dataStamp > 90000);
    if (stale) content.append(element('p', 'assessment-stale', 'Дані можуть бути застарілими. Ця оцінка не описує поточну ситуацію.'));
    const time = element('time', 'assessment-time', relativeTime(assessment.evaluatedAt));
    if (dateValue(assessment.evaluatedAt) !== null) { time.dateTime = new Date(dateValue(assessment.evaluatedAt)).toISOString(); time.title = dateFormat.format(dateValue(assessment.evaluatedAt)); }
    row.append(element('span', `assessment-level ${Object.hasOwn(levelLabels, level) ? level.toLowerCase() : ''}`, levelLabels[level] ?? 'Недостатньо даних'), content, time); fragment.append(row);
  }
  container.replaceChildren(fragment);
}

function isPaused() { const stamp = dateValue(state.me?.user?.pausedUntil); return stamp !== null && stamp > clockNow(); }
function renderDelivery() {
  const linked = state.me?.user?.telegramLinked === true;
  const configured = state.status?.delivery?.configured === true;
  const degraded = state.status?.delivery?.state === 'degraded';
  const paused = isPaused();
  byId('delivery-title').textContent = !configured ? 'Бот ще не налаштований' : degraded ? 'Доставка з перебоями' : linked ? paused ? 'Доставку призупинено' : 'Telegram під’єднано' : 'У ваш Telegram';
  byId('delivery-description').textContent = !configured ? 'Власник сервера має додати налаштування Telegram. Після цього ви зможете під’єднати свій чат.' : degraded ? 'Сервер зафіксував помилку Telegram. Повідомлення можуть затримуватися або не доставлятися.' : linked ? paused ? `Пауза до ${timeFormat.format(dateValue(state.me.user.pausedUntil))}. Моніторинг зон продовжується.` : 'Сигнали для активних зон надсилаються у ваш приватний чат із ботом.' : 'Під’єднайте приватного бота, щоб отримувати повідомлення для обраних зон.';
  byId('notification-status').textContent = byId('delivery-description').textContent;
  byId('generate-link-button').textContent = linked ? 'Під’єднати інший чат' : 'Під’єднати Telegram';
  byId('generate-link-button').disabled = !configured || !state.me;
  byId('pause-title').textContent = paused ? 'Сповіщення на паузі' : 'Доставка повідомлень';
  byId('pause-description').textContent = paused ? `Автоматично відновиться о ${timeFormat.format(dateValue(state.me.user.pausedUntil))}.` : 'Можна призупинити на одну годину.';
  byId('pause-button').textContent = paused ? 'Відновити' : 'Пауза на 1 год';
  byId('pause-button').disabled = !state.me;
}

async function refresh() {
  if (state.refreshing || document.hidden) return;
  state.refreshing = true;
  byId('refresh-button').disabled = true;
  try {
    const status = await request('/api/v1/status');
    if (!status || typeof status !== 'object' || !status.sources) throw new RequestError(0, 'Не вдалося прочитати стан сервісу. Повторіть спробу пізніше.');
    state.status = status;
    state.me = status.authenticated ? await request('/api/v1/me') : null;
    showMessage('page-error');
  } catch (error) {
    state.status = null;
    state.me = null;
    showMessage('page-error', error.message);
  } finally {
    state.loaded = true;
    state.refreshing = false;
    byId('refresh-button').disabled = false;
    renderStatus(); renderZones(); renderAssessments();
  }
}

async function mutate(button, action, message, errorTarget = 'page-error') {
  button.disabled = true;
  showMessage(errorTarget);
  try { await action(); await refresh(); if (message) toast(message); return true; }
  catch (error) { showMessage(errorTarget, error.message); if (error.status === 401) { state.me = null; renderZones(); renderAssessments(); renderStatus(); } return false; }
  finally { button.disabled = false; }
}

function openZone(zone = null) {
  state.editingZone = zone?.id ?? null;
  byId('zone-form').reset();
  byId('zone-dialog-title').textContent = zone ? 'Редагувати зону' : 'Додати зону';
  byId('zone-label').value = zone?.label ?? '';
  byId('zone-lat').value = zone?.lat ?? '';
  byId('zone-lon').value = zone?.lon ?? '';
  const defaultRadius = Number(state.status?.defaults?.radiusKm);
  byId('zone-radius').value = zone?.radiusKm ?? (Number.isFinite(defaultRadius) && defaultRadius >= 1 && defaultRadius <= 100 ? String(defaultRadius) : '');
  byId('zone-oblast').value = zone?.oblast ?? '';
  byId('zone-region').value = zone?.regionUid ?? '';
  byId('zone-enabled').checked = zone?.enabled !== false;
  showMessage('zone-error');
  openDialog('zone-dialog');
}

function openNotifications() { showMessage('notification-error'); byId('telegram-link-result').replaceChildren(); byId('telegram-link-result').hidden = true; renderDelivery(); openDialog('notification-dialog'); }

for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click', () => button.closest('dialog').close());
for (const dialog of document.querySelectorAll('dialog')) {
  dialog.addEventListener('click', (event) => { if (event.target !== dialog) return; const box = dialog.getBoundingClientRect(); if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) dialog.close(); });
}
byId('login-dialog').addEventListener('close', () => { byId('access-token').value = ''; showMessage('login-error'); });
byId('zone-dialog').addEventListener('close', () => { byId('zone-form').reset(); state.editingZone = null; });
byId('notification-dialog').addEventListener('close', () => { byId('telegram-link-result').replaceChildren(); byId('telegram-link-result').hidden = true; });
byId('account-button').addEventListener('click', () => { showMessage('account-error'); openDialog(state.me ? 'account-dialog' : 'login-dialog'); });
byId('refresh-button').addEventListener('click', refresh);
byId('privacy-button').addEventListener('click', () => { showMessage('privacy-error'); openDialog('privacy-dialog'); });
byId('footer-privacy-button').addEventListener('click', () => { showMessage('privacy-error'); openDialog('privacy-dialog'); });
byId('add-zone-button').addEventListener('click', () => authenticatedAction(() => openZone()));
byId('notifications-button').addEventListener('click', () => authenticatedAction(openNotifications));
byId('connect-telegram-button').addEventListener('click', () => authenticatedAction(openNotifications));

byId('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('[type=submit]');
  button.disabled = true; showMessage('login-error');
  try {
    await request('/api/v1/session', { method: 'POST', body: { token: byId('access-token').value.trim() } });
    byId('access-token').value = '';
    byId('login-dialog').close();
    await refresh();
    if (state.me) toast('Ви увійшли у свій простір');
  } catch (error) { showMessage('login-error', error.message); }
  finally { button.disabled = false; }
});

byId('zone-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('[type=submit]');
  const body = {
    label: byId('zone-label').value.trim(),
    lat: Number(byId('zone-lat').value), lon: Number(byId('zone-lon').value), radiusKm: Number(byId('zone-radius').value),
    oblast: byId('zone-oblast').value.trim() || (state.editingZone ? null : undefined), regionUid: byId('zone-region').value.trim() || (state.editingZone ? null : undefined), enabled: byId('zone-enabled').checked,
  };
  if (!body.label || ![body.lat, body.lon, body.radiusKm].every(Number.isFinite) || Math.abs(body.lat) > 90 || Math.abs(body.lon) > 180 || body.radiusKm < 1 || body.radiusKm > 100) { showMessage('zone-error', 'Вкажіть назву, допустимі координати та радіус від 1 до 100 км.'); return; }
  const path = state.editingZone ? `/api/v1/zones/${encodeURIComponent(state.editingZone)}` : '/api/v1/zones';
  const method = state.editingZone ? 'PATCH' : 'POST';
  const success = await mutate(button, () => request(path, { method, body }), 'Зону збережено', 'zone-error');
  if (success) byId('zone-dialog').close();
});

byId('location-button').addEventListener('click', () => {
  if (!navigator.geolocation) { showMessage('zone-error', 'Геопозиція недоступна в цьому браузері. Введіть координати вручну.'); return; }
  const button = byId('location-button'); button.disabled = true; showMessage('zone-error');
  navigator.geolocation.getCurrentPosition((position) => {
    button.disabled = false;
    if (!byId('zone-dialog').open) return;
    byId('zone-lat').value = position.coords.latitude.toFixed(5);
    byId('zone-lon').value = position.coords.longitude.toFixed(5);
    toast('Геопозицію підставлено. Збережіть зону, щоб застосувати її.');
  }, (error) => {
    button.disabled = false;
    if (!byId('zone-dialog').open) return;
    showMessage('zone-error', error.code === 1 ? 'Доступ до геопозиції не надано. Введіть координати вручну.' : 'Не вдалося визначити геопозицію. Введіть координати вручну.');
  }, { enableHighAccuracy: false, timeout: 12000, maximumAge: 0 });
});

byId('generate-link-button').addEventListener('click', async () => {
  const button = byId('generate-link-button'); button.disabled = true; showMessage('notification-error');
  try {
    const result = await request('/api/v1/telegram/link', { method: 'POST', body: {} });
    if (typeof result?.code !== 'string' || !/^[a-zA-Z0-9_-]{4,200}$/.test(result.code)) throw new RequestError(0, 'Не вдалося отримати код під’єднання. Повторіть спробу.');
    const target = byId('telegram-link-result');
    target.replaceChildren(element('p', '', 'Надішліть цю команду своєму боту в Telegram:'), element('code', '', `/start ${result.code}`));
    if (result.botUsername && /^[A-Za-z0-9_]{5,32}$/.test(result.botUsername)) {
      const link = element('a', '', `Відкрити @${result.botUsername}`);
      link.href = `https://t.me/${result.botUsername}?start=${encodeURIComponent(result.code)}`; link.target = '_blank'; link.rel = 'noopener noreferrer'; target.append(link);
    }
    const expiration = dateValue(result.expiresAt);
    if (expiration !== null) target.append(element('p', 'field-note', `Код дійсний до ${timeFormat.format(expiration)}. Не передавайте його іншим.`));
    target.hidden = false;
  } catch (error) { showMessage('notification-error', error.message); }
  finally { button.disabled = false; }
});

byId('pause-button').addEventListener('click', async () => {
  const pausedMinutes = isPaused() ? 0 : 60;
  await mutate(byId('pause-button'), () => request('/api/v1/preferences', { method: 'POST', body: { pausedMinutes } }), pausedMinutes ? 'Сповіщення призупинено на годину' : 'Сповіщення відновлено', 'notification-error');
  renderDelivery();
});

byId('logout-button').addEventListener('click', async () => {
  const success = await mutate(byId('logout-button'), () => request('/api/v1/session', { method: 'DELETE' }), 'Ви вийшли з особистого простору', 'account-error');
  if (success) { state.me = null; byId('account-dialog').close(); renderZones(); renderAssessments(); renderStatus(); }
});

byId('delete-account-button').addEventListener('click', async () => {
  if (!window.confirm('Видалити профіль, усі зони, налаштування та зв’язок із Telegram? Цю дію неможливо скасувати.')) return;
  const success = await mutate(byId('delete-account-button'), () => request('/api/v1/me', { method: 'DELETE' }), 'Профіль і зони видалено', 'privacy-error');
  if (success) { state.me = null; byId('privacy-dialog').close(); renderZones(); renderAssessments(); renderStatus(); }
});

async function openChangelog() {
  const target = byId('changelog-content'); target.replaceChildren(element('p', 'muted', 'Завантажуємо оновлення…')); openDialog('changelog-dialog');
  try {
    const result = await request('/changelog.json');
    const entries = Array.isArray(result?.items) ? result.items : Array.isArray(result) ? result : [];
    if (!entries.length) { target.replaceChildren(element('p', 'muted', 'Опис оновлень поки відсутній.')); return; }
    const fragment = document.createDocumentFragment();
    for (const entry of entries.slice(0, 8)) {
      const section = element('section', 'changelog-entry');
      section.append(element('h3', '', `Версія ${String(entry.version ?? '—')}`));
      if (entry.date) section.append(element('time', '', String(entry.date)));
      for (const item of Array.isArray(entry.items) ? entry.items : []) if (typeof item === 'string') section.append(element('p', '', item));
      fragment.append(section);
    }
    target.replaceChildren(fragment);
  } catch (error) { target.replaceChildren(element('p', 'muted', error.message)); }
}
byId('changelog-button').addEventListener('click', openChangelog);
byId('footer-changelog-button').addEventListener('click', openChangelog);

document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
window.addEventListener('online', refresh);
window.addEventListener('offline', () => { state.status = null; state.me = null; renderStatus(); renderZones(); renderAssessments(); showMessage('page-error', 'Немає з’єднання з мережею. Поточний стан загроз невідомий.'); });
setInterval(refresh, 15000);
refresh();
