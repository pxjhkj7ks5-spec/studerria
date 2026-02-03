const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
const fullWeekDays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const studyDayLabels = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Нд'];

function parseDateUTC(dateStr) {
  if (!dateStr) return null;
  const [y, m, d] = dateStr.split('-').map((n) => Number(n));
  if (!y || !m || !d) return null;
  return Date.UTC(y, m - 1, d);
}

function isValidDateString(dateStr) {
  if (!dateStr || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  return parseDateUTC(dateStr) !== null;
}

function isValidTimeString(timeStr) {
  if (!timeStr) return false;
  if (!/^\d{2}:\d{2}$/.test(timeStr)) return false;
  const [hours, minutes] = timeStr.split(':').map((n) => Number(n));
  return hours >= 0 && hours <= 23 && minutes >= 0 && minutes <= 59;
}

function parseCsvText(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (inQuotes) {
      if (ch === '"' && next === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      field = '';
      if (row.some((cell) => String(cell).trim().length)) {
        rows.push(row);
      }
      row = [];
    } else if (ch !== '\r') {
      field += ch;
    }
  }
  row.push(field);
  if (row.some((cell) => String(cell).trim().length)) {
    rows.push(row);
  }
  if (!rows.length) return [];
  const headers = rows
    .shift()
    .map((h) => String(h || '').replace(/^\uFEFF/, '').trim().toLowerCase());
  return rows.map((r) => {
    const obj = {};
    headers.forEach((h, idx) => {
      if (!h) return;
      obj[h] = r[idx] !== undefined ? String(r[idx]).trim() : '';
    });
    return obj;
  });
}

function getWeekDayForDate(dateStr, semesterStart) {
  if (!dateStr || !semesterStart) return null;
  const targetUTC = parseDateUTC(dateStr);
  const startUTC = parseDateUTC(semesterStart);
  if (targetUTC === null || startUTC === null) return null;
  const diffDays = Math.floor((targetUTC - startUTC) / (1000 * 60 * 60 * 24));
  if (diffDays < 0) return null;
  const weekNumber = Math.floor(diffDays / 7) + 1;
  const dayIndex = diffDays % 7;
  const dayName = daysOfWeek[dayIndex];
  if (!dayName) return null;
  return { weekNumber, dayName };
}

function getAcademicWeekForSemester(date, semester) {
  if (!semester || !semester.start_date) return 1;
  const startUTC = parseDateUTC(semester.start_date);
  if (!startUTC) return 1;
  const currentUTC = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
  const diffDays = Math.floor((currentUTC - startUTC) / (1000 * 60 * 60 * 24));
  let week = Math.floor(diffDays / 7) + 1;
  if (diffDays < 0) week = 1;
  if (week < 1) week = 1;
  if (semester.weeks_count && week > Number(semester.weeks_count)) {
    week = Number(semester.weeks_count);
  }
  return week;
}

function getDateForWeekDay(weekNumber, dayName, semesterStart) {
  const dayIndex = daysOfWeek.indexOf(dayName);
  if (dayIndex === -1) return null;
  const startUTC = parseDateUTC(semesterStart) ?? Date.UTC(2026, 0, 19);
  const dateUTC =
    startUTC + (Number(weekNumber) - 1) * 7 * 24 * 60 * 60 * 1000 + dayIndex * 24 * 60 * 60 * 1000;
  return new Date(dateUTC).toISOString().slice(0, 10);
}

function getDateForWeekIndex(weekNumber, dayIndex, semesterStart) {
  if (dayIndex < 0 || dayIndex > 6) return null;
  const startUTC = parseDateUTC(semesterStart) ?? Date.UTC(2026, 0, 19);
  const dateUTC =
    startUTC + (Number(weekNumber) - 1) * 7 * 24 * 60 * 60 * 1000 + dayIndex * 24 * 60 * 60 * 1000;
  return new Date(dateUTC).toISOString().slice(0, 10);
}

function getDayNameFromDate(dateStr) {
  if (!dateStr) return null;
  const d = new Date(`${dateStr}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return null;
  const idx = d.getUTCDay();
  const map = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  return map[idx] || null;
}

function formatLocalDate(date) {
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 10);
}

function addDays(date, days) {
  const copy = new Date(date);
  copy.setDate(copy.getDate() + days);
  return copy;
}

module.exports = {
  daysOfWeek,
  fullWeekDays,
  studyDayLabels,
  parseDateUTC,
  isValidDateString,
  isValidTimeString,
  parseCsvText,
  getWeekDayForDate,
  getAcademicWeekForSemester,
  getDateForWeekDay,
  getDateForWeekIndex,
  getDayNameFromDate,
  formatLocalDate,
  addDays,
};
