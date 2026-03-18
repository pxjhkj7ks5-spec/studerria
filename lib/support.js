const SUPPORT_REQUEST_CATEGORIES = ['account', 'schedule', 'journal', 'subjects', 'teamwork', 'other'];
const SUPPORT_REQUEST_STATUSES = ['new', 'in_progress', 'resolved'];
const SUPPORT_REQUEST_MESSAGE_ROLES = ['user', 'admin'];

function normalizeSupportRequestCategory(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return SUPPORT_REQUEST_CATEGORIES.includes(normalized) ? normalized : 'other';
}

function normalizeSupportRequestStatus(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return SUPPORT_REQUEST_STATUSES.includes(normalized) ? normalized : 'new';
}

function normalizeSupportRequestMessageRole(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return SUPPORT_REQUEST_MESSAGE_ROLES.includes(normalized) ? normalized : 'user';
}

function buildSupportRequestFallbackMessages(requestRow = {}) {
  const messages = [];
  const requestId = Number(requestRow.id || 0);
  const userBody = String(requestRow.body || '').trim();
  if (userBody) {
    messages.push({
      id: requestId ? `request-${requestId}-user` : 'request-user',
      request_id: requestId || null,
      author_role: 'user',
      author_user_id: Number.isFinite(Number(requestRow.user_id)) ? Number(requestRow.user_id) : null,
      author_name: String(requestRow.user_name || '').trim() || 'User',
      body: userBody,
      created_at: requestRow.created_at || null,
    });
  }
  const adminBody = String(requestRow.admin_note || '').trim();
  if (adminBody) {
    messages.push({
      id: requestId ? `request-${requestId}-admin` : 'request-admin',
      request_id: requestId || null,
      author_role: 'admin',
      author_user_id: Number.isFinite(Number(requestRow.resolved_by)) ? Number(requestRow.resolved_by) : null,
      author_name: String(requestRow.resolved_by_name || '').trim() || 'Admin',
      body: adminBody,
      created_at: requestRow.resolved_at || requestRow.updated_at || requestRow.created_at || null,
    });
  }
  return messages;
}

function ensureSupportRequestThread(requestRow = {}, messages = []) {
  const normalizedMessages = Array.isArray(messages) ? messages.filter(Boolean) : [];
  const thread = normalizedMessages.length ? normalizedMessages : buildSupportRequestFallbackMessages(requestRow);
  return thread
    .map((message) => ({
      ...message,
      author_role: normalizeSupportRequestMessageRole(message.author_role),
      author_name: String(message.author_name || '').trim()
        || (normalizeSupportRequestMessageRole(message.author_role) === 'admin' ? 'Admin' : 'User'),
      body: String(message.body || '').trim(),
    }))
    .filter((message) => message.body)
    .sort((a, b) => {
      const aTime = new Date(a.created_at || 0).getTime();
      const bTime = new Date(b.created_at || 0).getTime();
      if (Number.isFinite(aTime) && Number.isFinite(bTime) && aTime !== bTime) {
        return aTime - bTime;
      }
      return String(a.id || '').localeCompare(String(b.id || ''));
    });
}

function buildSupportRequestPreview(requestRow = {}, messages = []) {
  const thread = ensureSupportRequestThread(requestRow, messages);
  const lastMessage = thread.length ? thread[thread.length - 1] : null;
  return {
    ...requestRow,
    messages: thread,
    messages_count: thread.length,
    last_message_preview: lastMessage ? String(lastMessage.body || '').slice(0, 180) : '',
    last_message_at: lastMessage ? (lastMessage.created_at || requestRow.updated_at || requestRow.created_at || null) : null,
    needs_reply: normalizeSupportRequestStatus(requestRow.status) !== 'resolved',
  };
}

function summarizeSupportRequests(requestRows = [], options = {}) {
  const rows = Array.isArray(requestRows) ? requestRows : [];
  const responseLabel = String(options.responseLabel || '').trim();
  const open = rows.filter((row) => normalizeSupportRequestStatus(row.status) !== 'resolved').length;
  const resolved = rows.filter((row) => normalizeSupportRequestStatus(row.status) === 'resolved').length;
  const latest = rows
    .map((row) => row.last_message_at || row.updated_at || row.created_at || null)
    .filter(Boolean)
    .sort()
    .pop() || null;
  return {
    open,
    resolved,
    total: rows.length,
    latest_activity_at: latest,
    response: responseLabel,
  };
}

function buildHelpPageExperienceContent(lang) {
  const isUk = lang === 'uk';
  return {
    hero: {
      kicker: isUk ? 'FAQ / Підтримка' : 'FAQ / Support',
      title: 'FAQ & Help',
      subtitle: isUk
        ? 'Пояснення по реальних щоденних сценаріях Studerria плюс жива історія ваших звернень.'
        : 'Answers around real Studerria journeys plus the live history of your requests.',
      lead: isUk
        ? 'Сторінка зібрана навколо того, що користувач робить щодня: входить у профіль, завершує реєстрацію, перевіряє розклад і сесії, відкриває журнал, матеріали, teamwork, Teacher Workspace та support threads.'
        : 'This page follows what people actually do every day: sign in, finish registration, check schedule and sessions, open the journal, find materials, use teamwork, Teacher Workspace, and support threads.',
      note: isUk
        ? 'Якщо тема не змінилася, відповідайте прямо в наявному support thread. Так контекст, вкладення й SLA не розриваються.'
        : 'If the topic did not change, reply inside the existing support thread so the context, files, and SLA stay intact.',
    },
    faqTitle: isUk ? 'Питання по реальних user journeys' : 'Answers by real user journey',
    faqSubtitle: isUk
      ? 'Менше довідки про модулі, більше відповідей про те, де люди реально губляться в Studerria.'
      : 'Less module theory, more answers about where people actually get stuck in Studerria.',
    faqGroups: [
      {
        kicker: isUk ? 'Доступ' : 'Access',
        title: isUk ? 'Login, профіль і базовий доступ' : 'Login, profile, and core access',
        items: [
          {
            question: isUk ? 'Не вдається увійти або профіль виглядає порожнім.' : 'I cannot sign in or the profile looks empty.',
            answer: isUk
              ? 'Спершу перевірте ПІБ і пароль. Якщо вхід спрацьовує, але зникли курс, роль, групи або журнал, створіть звернення з темою "Акаунт" і вкажіть, який саме блок доступу пропав.'
              : 'Check your full name and password first. If sign-in works but the course, role, groups, or journal disappeared, open an "Account" request and specify which access layer is missing.',
          },
          {
            question: isUk ? 'Де змінити ПІБ, пароль або мову?' : 'Where do I change my name, password, or language?',
            answer: isUk
              ? 'У "Профілі". Це єдина точка, де варто оновлювати персональні дані, щоб вони однаково відображались у My Day, повідомленнях і support history.'
              : 'Use "Profile". It is the single place for personal data changes so My Day, messages, and support history stay consistent.',
          },
        ],
      },
      {
        kicker: 'Pathways',
        title: isUk ? 'Реєстрація, pathways і база предметів' : 'Registration, pathways, and subject base',
        items: [
          {
            question: isUk ? 'На реєстрації порожній шлях або не зʼявляються предмети.' : 'Registration hits an empty path or no subjects appear.',
            answer: isUk
              ? 'Це зазвичай означає, що для вашої програми, року вступу або кампусу ще не завершений mapping. Якщо список предметів порожній або обрізаний, вкажіть програму, рік вступу, кампус і курс у зверненні з темою "Предмети" або "Реєстрація".'
              : 'This usually means the mapping for your program, admission year, or campus is incomplete. If the subject list is empty or truncated, include the program, admission year, campus, and course in a "Subjects" or "Registration" request.',
          },
          {
            question: isUk ? 'Можна повторно пройти вибір груп без нового акаунта?' : 'Can I reopen group selection without a new account?',
            answer: isUk
              ? 'Так. У профілі є дія для повторного входу у вибір предметів. Це безпечніше за дубль акаунта, бо Studerria збереже одну історію журналу, повідомлень і підтримки.'
              : 'Yes. Profile includes an action that reopens subject selection. It is safer than creating a duplicate account because Studerria keeps one journal, message, and support history.',
          },
        ],
      },
      {
        kicker: isUk ? 'Розклад' : 'Schedule',
        title: isUk ? 'Розклад, сесії та аудиторії' : 'Schedule, sessions, and rooms',
        items: [
          {
            question: isUk ? 'У розкладі немає пари, дедлайну або кабінету.' : 'A class, deadline, or room is missing in the schedule.',
            answer: isUk
              ? 'Перевірте правильний тиждень і курс. Якщо елемент усе одно не видно, напишіть день, слот, предмет, групу й очікуваний кабінет. Для session issues окремо вкажіть room conflict або teacher conflict, якщо він помітний.'
              : 'Check the correct week and course first. If it is still missing, include the day, slot, subject, group, and expected room. For session issues, mention whether it looks like a room conflict or a teacher clash.',
          },
          {
            question: isUk ? 'Сесія опублікована, але виглядає конфліктною.' : 'The published session still looks conflicted.',
            answer: isUk
              ? 'Укажіть дату, слот, предмет, викладача й аудиторію. Для сесій це найкоротший шлях перевірити два шари одразу: зайнятість викладача і зайнятість кімнати.'
              : 'Include the date, slot, subject, teacher, and room. That lets the team verify both layers immediately: teacher availability and room occupancy.',
          },
        ],
      },
      {
        kicker: isUk ? 'Журнал' : 'Journal',
        title: isUk ? 'Журнал, attendance і рейтинги' : 'Journal, attendance, and ratings',
        items: [
          {
            question: isUk ? 'Журнал порожній або не відкривається по предмету.' : 'The journal is empty or does not open for a subject.',
            answer: isUk
              ? 'Найчастіше бракує звʼязки між викладачем, предметом і курсом. У зверненні вкажіть предмет, курс і що саме зламалось: оцінки, attendance, insights або доступ до subject journal.'
              : 'Most often the teacher-subject-course mapping is incomplete. Include the subject, course, and the broken layer: grades, attendance, insights, or journal access.',
          },
          {
            question: isUk ? 'Де шукати published rating або attendance signal?' : 'Where do I find the published rating or attendance signal?',
            answer: isUk
              ? 'Останній published rating залишається в Journal Insights, але той самий snapshot дублюється на My Day і в message surfaces. Attendance редагується в журналі, а на головній показується стислий health signal.'
              : 'The latest published rating stays in Journal Insights, but the same snapshot is echoed in My Day and message surfaces. Attendance stays editable in the journal while the homepage shows a compact health signal.',
          },
        ],
      },
      {
        kicker: isUk ? 'Матеріали' : 'Materials',
        title: isUk ? 'Subject materials і вкладення' : 'Subject materials and attachments',
        items: [
          {
            question: isUk ? 'Не відкривається файл або зник матеріал по предмету.' : 'A file does not open or subject material is missing.',
            answer: isUk
              ? 'Вкажіть предмет, курс, назву матеріалу або дедлайну. Якщо зламався лише один файл, не потрібно перевантажувати весь пакет заново: достатньо назви проблемного asset або посилання.'
              : 'Include the subject, course, and the material or deadline title. If only one file failed, do not reupload the whole package; the missing asset or link title is enough.',
          },
        ],
      },
      {
        kicker: 'Teamwork',
        title: isUk ? 'Команди і спільна робота' : 'Teams and collaborative work',
        items: [
          {
            question: isUk ? 'Не вдається створити або приєднатися до teamwork-команди.' : 'I cannot create or join a teamwork team.',
            answer: isUk
              ? 'Опишіть точний крок, на якому процес зупинився, і до якого предмета або завдання це привʼязано. Це допомагає швидко відрізнити проблему ролей від проблеми дедлайну або subject scope.'
              : 'Describe the exact step where the flow stopped and which subject or task it belongs to. That helps separate a role issue from a deadline or subject-scope issue.',
          },
        ],
      },
      {
        kicker: isUk ? 'Teacher Workspace' : 'Teacher Workspace',
        title: isUk ? 'Teacher Hub, шаблони й assets' : 'Teacher Hub, templates, and assets',
        items: [
          {
            question: isUk ? 'Шаблон викладача або asset-library працює не так, як очікувалось.' : 'A teacher template or the asset library does not behave as expected.',
            answer: isUk
              ? 'Укажіть назву шаблону, курс, предмет і що саме зламалось: scope, файли, clone, bulk action або видимість asset. Так команда швидше перевірить правильний рівень Teacher Workspace.'
              : 'Include the template title, course, subject, and the failing layer: scope, files, clone, bulk action, or asset visibility. That points the team to the right Teacher Workspace layer immediately.',
          },
        ],
      },
      {
        kicker: 'Support',
        title: isUk ? 'Support threads і SLA' : 'Support threads and SLA',
        items: [
          {
            question: isUk ? 'Коли відповідати в існуючий thread, а коли створювати новий?' : 'When should I reply in a thread instead of creating a new one?',
            answer: isUk
              ? 'Якщо це та сама проблема, відповідайте в наявний thread. Нове звернення варто створювати лише тоді, коли змінюється тема: наприклад login issue окремо, session room conflict окремо.'
              : 'Reply in the existing thread if it is the same issue. Open a new request only when the topic changes, for example a login issue versus a session room conflict.',
          },
          {
            question: isUk ? 'Який SLA у підтримки?' : 'What is the support SLA?',
            answer: isUk
              ? 'Базовий орієнтир: до одного робочого дня на першу відповідь. Якщо проблема блокує реєстрацію, розклад, журнал або рейтинг, скажіть це прямо в темі першого повідомлення.'
              : 'The default target is within one business day for the first reply. If the issue blocks registration, schedule, journal, or rating publication, say that in the subject of the first message.',
          },
        ],
      },
    ],
  };
}

module.exports = {
  SUPPORT_REQUEST_CATEGORIES,
  SUPPORT_REQUEST_STATUSES,
  SUPPORT_REQUEST_MESSAGE_ROLES,
  normalizeSupportRequestCategory,
  normalizeSupportRequestStatus,
  normalizeSupportRequestMessageRole,
  buildSupportRequestFallbackMessages,
  buildHelpPageExperienceContent,
  ensureSupportRequestThread,
  buildSupportRequestPreview,
  summarizeSupportRequests,
};
