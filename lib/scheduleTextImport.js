const DAY_ALIASES = new Map([
  ['monday', 'Monday'], ['mon', 'Monday'], ['понеділок', 'Monday'], ['понедельник', 'Monday'],
  ['tuesday', 'Tuesday'], ['tue', 'Tuesday'], ['вівторок', 'Tuesday'], ['вторник', 'Tuesday'],
  ['wednesday', 'Wednesday'], ['wed', 'Wednesday'], ['середа', 'Wednesday'], ['среда', 'Wednesday'],
  ['thursday', 'Thursday'], ['thu', 'Thursday'], ['четвер', 'Thursday'],
  ['friday', 'Friday'], ['fri', 'Friday'], ['пʼятниця', 'Friday'], ['п’ятниця', 'Friday'], ['пятниця', 'Friday'], ['пятница', 'Friday'],
  ['saturday', 'Saturday'], ['sat', 'Saturday'], ['субота', 'Saturday'], ['суббота', 'Saturday'],
  ['sunday', 'Sunday'], ['sun', 'Sunday'], ['неділя', 'Sunday'], ['воскресенье', 'Sunday'],
]);

const ACTIVITY_ALIASES = new Map([
  ['lecture', 'lecture'], ['лекція', 'lecture'], ['лекция', 'lecture'], ['лк', 'lecture'], ['л', 'lecture'],
  ['seminar', 'seminar'], ['семінар', 'seminar'], ['семинар', 'seminar'], ['сем', 'seminar'], ['с', 'seminar'],
  ['practice', 'practice'], ['практика', 'practice'], ['практичне', 'practice'], ['пр', 'practice'],
  ['lab', 'lab'], ['laboratory', 'lab'], ['лабораторна', 'lab'], ['лабораторная', 'lab'], ['лаб', 'lab'],
]);

const ALL_GROUP_ALIASES = new Set(['all', 'all groups', 'усі', 'всі', 'все', '*', '-']);

function normalizeToken(value) {
  return String(value || '')
    .replace(/[’`]/g, 'ʼ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function parsePositiveNumberSet(rawValue, { min = 1, max = 40 } = {}) {
  const normalized = String(rawValue || '').replace(/[–—]/g, '-').trim();
  if (!normalized) return [];
  const values = new Set();
  normalized.split(/[;,\s]+/).filter(Boolean).forEach((part) => {
    const rangeMatch = part.match(/^(\d+)-(\d+)$/);
    if (rangeMatch) {
      const start = Number(rangeMatch[1]);
      const end = Number(rangeMatch[2]);
      if (start > end || start < min || end > max) {
        throw new Error('invalid range');
      }
      for (let value = start; value <= end; value += 1) values.add(value);
      return;
    }
    if (!/^\d+$/.test(part)) throw new Error('invalid number');
    const value = Number(part);
    if (value < min || value > max) throw new Error('number out of range');
    values.add(value);
  });
  return Array.from(values).sort((left, right) => left - right);
}

function splitColumns(line) {
  if (line.includes('\t')) return line.split('\t').map((item) => item.trim());
  return line.split('|').map((item) => item.trim());
}

function parseScheduleImportText(rawText, options = {}) {
  const maxEntries = Math.max(1, Math.min(500, Number(options.maxEntries || 300)));
  const lines = String(rawText || '').replace(/^\uFEFF/, '').split(/\r?\n/);
  const entries = [];
  const errors = [];

  lines.forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const line = String(rawLine || '').trim();
    if (!line || line.startsWith('#') || /^STUDERRIA_SCHEDULE_V[12]$/i.test(line)) return;
    if (entries.length >= maxEntries) {
      errors.push({ lineNumber, message: `дозволено не більше ${maxEntries} рядків` });
      return;
    }

    const columns = splitColumns(line);
    if (columns.length < 6 || columns.length > 7) {
      errors.push({ lineNumber, message: 'потрібно 6 або 7 колонок: предмет, тип, день, пара, тижні, групи, аудиторія' });
      return;
    }

    const [subject, rawActivity, rawDay, rawClassNumber, rawWeeks, rawGroups, rawRoom = ''] = columns;
    const activityType = ACTIVITY_ALIASES.get(normalizeToken(rawActivity));
    const dayOfWeek = DAY_ALIASES.get(normalizeToken(rawDay));
    const classNumber = Number(rawClassNumber);
    if (!subject) errors.push({ lineNumber, message: 'не вказано предмет' });
    if (!activityType) errors.push({ lineNumber, message: `невідомий тип заняття «${rawActivity}»` });
    if (!dayOfWeek) errors.push({ lineNumber, message: `невідомий день «${rawDay}»` });
    if (!Number.isInteger(classNumber) || classNumber < 1 || classNumber > 12) {
      errors.push({ lineNumber, message: 'номер пари має бути від 1 до 12' });
    }

    let weekNumbers = [];
    try {
      weekNumbers = parsePositiveNumberSet(rawWeeks, { min: 1, max: 40 });
      if (!weekNumbers.length) throw new Error('empty');
    } catch (_error) {
      errors.push({ lineNumber, message: `некоректні тижні «${rawWeeks}»` });
    }

    const allGroups = ALL_GROUP_ALIASES.has(normalizeToken(rawGroups));
    let targetGroupNumbers = [];
    if (!allGroups) {
      try {
        targetGroupNumbers = parsePositiveNumberSet(rawGroups, { min: 1, max: 12 });
        if (!targetGroupNumbers.length) throw new Error('empty');
      } catch (_error) {
        errors.push({ lineNumber, message: `некоректні групи «${rawGroups}»` });
      }
    }
    if (activityType === 'lecture' && !allGroups) {
      errors.push({ lineNumber, message: 'лекція завжди має групи «усі»' });
    }

    if (!errors.some((error) => error.lineNumber === lineNumber)) {
      entries.push({
        lineNumber,
        subject: subject.trim(),
        activityType,
        dayOfWeek,
        classNumber,
        weekNumbers,
        allGroups,
        targetGroupNumbers,
        roomLabel: String(rawRoom || '').trim(),
      });
    }
  });

  if (!entries.length && !errors.length) {
    errors.push({ lineNumber: 0, message: 'текст не містить рядків розкладу' });
  }

  return { entries, errors };
}

module.exports = {
  parseScheduleImportText,
  parsePositiveNumberSet,
};
