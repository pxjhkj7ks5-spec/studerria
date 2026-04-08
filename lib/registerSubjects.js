function normalizePositiveInt(value) {
  const normalized = Number(value || 0);
  return Number.isInteger(normalized) && normalized > 0 ? normalized : null;
}

function normalizeBoolean(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  const normalized = String(value || '').trim().toLowerCase();
  if (['1', 'true', 'on', 'yes'].includes(normalized)) return true;
  if (['0', 'false', 'off', 'no'].includes(normalized)) return false;
  return fallback === true;
}

function cleanText(value, maxLength = 200) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeGroupCount(value) {
  const normalized = normalizePositiveInt(value);
  if (normalized === 1 || normalized === 2 || normalized === 3) {
    return normalized;
  }
  return 1;
}

function isRequiredRegisterSubject(subject) {
  return normalizeBoolean(subject && subject.is_required, true);
}

function normalizeSelectedGroup(value, groupCount) {
  const normalized = normalizePositiveInt(value);
  return normalized && normalized <= normalizeGroupCount(groupCount) ? normalized : null;
}

function buildRegisterSubjectCard(subject = {}) {
  const groupCount = normalizeGroupCount(subject.group_count);
  const requiredFlag = isRequiredRegisterSubject(subject);
  const autoAssigned = requiredFlag && groupCount === 1;
  const selectedGroup = normalizeSelectedGroup(subject.selected_group, groupCount);
  const optedOut = !requiredFlag && normalizeBoolean(subject.opted_out, false);
  const effectiveSelectedGroup = autoAssigned ? (selectedGroup || 1) : (optedOut ? null : selectedGroup);
  const interactive = !autoAssigned;

  return {
    id: normalizePositiveInt(subject.id || subject.subject_id),
    name: cleanText(subject.name || subject.subject_name || subject.subject_title, 200),
    groupCount,
    requiredFlag,
    allowNotTaught: !requiredFlag,
    autoAssigned,
    interactive,
    optedOut,
    selectedGroup: effectiveSelectedGroup,
    pending: interactive && !optedOut && !effectiveSelectedGroup,
    ready: autoAssigned || optedOut || Boolean(effectiveSelectedGroup),
  };
}

function buildRegisterSubjectCards(subjects = []) {
  return (Array.isArray(subjects) ? subjects : [])
    .map((subject) => buildRegisterSubjectCard(subject))
    .filter((subject) => subject.id && subject.name);
}

function isOptoutValue(value) {
  return ['1', 'true', 'on', 'yes'].includes(String(value || '').trim().toLowerCase());
}

function readRegisterSubjectChoice(subject = {}, body = {}) {
  const card = buildRegisterSubjectCard(subject);
  const payload = body && typeof body === 'object' ? body : {};
  const selectedGroup = normalizeSelectedGroup(payload[`subject_${card.id}`], card.groupCount);
  const optedOut = card.allowNotTaught && isOptoutValue(payload[`optout_${card.id}`]);
  const ready = card.autoAssigned || optedOut || Boolean(selectedGroup);

  return {
    ...card,
    selectedGroup: card.autoAssigned ? 1 : (optedOut ? null : selectedGroup),
    optedOut,
    ready,
    missingChoice: card.interactive && !ready,
    invalidGroup: !card.autoAssigned && Boolean(payload[`subject_${card.id}`]) && !selectedGroup,
  };
}

module.exports = {
  buildRegisterSubjectCard,
  buildRegisterSubjectCards,
  isRequiredRegisterSubject,
  readRegisterSubjectChoice,
};
