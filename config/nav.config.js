const APP_ROLES = ['admin', 'deanery', 'starosta', 'teacher', 'student'];
const PERSONAL_LABEL = 'Особисте';
const PERSONAL_LABEL_KEY = 'nav.personal';
const ADMIN_PANEL_ROLES = ['admin', 'deanery', 'starosta', 'teacher'];
const DEADLINE_ROLES = ['student', 'starosta', 'teacher'];
const JOURNAL_ROLES = ['admin', 'deanery', 'starosta', 'teacher', 'student'];
const JOURNAL_INSIGHT_ROLES = ['admin', 'deanery', 'starosta', 'teacher'];

const navConfig = {
  personalLabel: PERSONAL_LABEL,
  personalLabelKey: PERSONAL_LABEL_KEY,
  items: [
    // TODO: replace this temporary role/flag blend with the final centralized RBAC policy once it is exported outside app.js.
    {
      id: 'admin',
      label: 'Адмінка',
      labelKey: 'nav.admin',
      href: '/admin',
      section: 'main',
      rolesAllowed: ADMIN_PANEL_ROLES,
      requiredFlags: ['canAccessAdminPanel'],
      matchMode: 'prefix',
    },
    {
      id: 'home',
      label: 'Головна',
      labelKey: 'nav.home',
      href: '/home',
      section: 'main',
      rolesAllowed: APP_ROLES,
      matchPaths: ['/home', '/my-day'],
    },
    {
      id: 'schedule',
      label: 'Розклад',
      labelKey: 'nav.schedule',
      href: '/schedule',
      section: 'main',
      rolesAllowed: APP_ROLES,
      matchPaths: ['/schedule'],
      children: [
        {
          id: 'homework',
          label: 'Завдання',
          labelKey: 'nav.homework',
          href: '/schedule#homework',
          section: 'main',
          rolesAllowed: APP_ROLES,
        },
        {
          id: 'custom-deadlines',
          label: 'Особисті дедлайни',
          labelKey: 'nav.customDeadlines',
          href: '/schedule?panel=deadlines',
          section: 'main',
          rolesAllowed: DEADLINE_ROLES,
          requiredFlags: ['canUseCustomDeadlines'],
          navAction: 'custom-deadlines',
          matchPaths: ['/schedule/custom-deadlines'],
        },
        {
          id: 'messages',
          label: 'Повідомлення',
          labelKey: 'nav.messages',
          href: '/schedule?panel=messages',
          section: 'main',
          rolesAllowed: APP_ROLES,
          requiredFlags: ['allowMessages'],
          navAction: 'messages',
          matchPaths: ['/messages'],
        },
      ],
    },
    {
      id: 'subjects',
      label: 'Предмети',
      labelKey: 'nav.subjects',
      href: '/subjects',
      section: 'main',
      rolesAllowed: APP_ROLES,
      matchPaths: ['/subjects'],
    },
    {
      id: 'teamwork',
      label: 'Команди',
      labelKey: 'nav.teamwork',
      href: '/teamwork',
      section: 'main',
      rolesAllowed: APP_ROLES,
      matchPaths: ['/teamwork'],
    },
    {
      id: 'journal',
      label: 'Журнал',
      labelKey: 'nav.journal',
      href: '/journal',
      section: 'main',
      rolesAllowed: JOURNAL_ROLES,
      matchPaths: ['/journal'],
      children: [
        {
          id: 'journal-insights',
          label: 'Рейтинг',
          labelKey: 'nav.insights',
          href: '/journal/insights',
          section: 'main',
          rolesAllowed: JOURNAL_INSIGHT_ROLES,
          matchPaths: ['/journal/insights'],
        },
      ],
    },
    {
      id: 'personal',
      label: PERSONAL_LABEL,
      labelKey: 'nav.personal',
      href: '/profile',
      section: 'main',
      rolesAllowed: APP_ROLES,
      children: [
        { id: 'help', label: 'Допомога', labelKey: 'nav.help', href: '/help', section: 'main', rolesAllowed: APP_ROLES, matchPaths: ['/help'] },
        { id: 'about', label: 'Про Studerria', labelKey: 'nav.about', href: '/about', section: 'main', rolesAllowed: APP_ROLES, matchPaths: ['/about'] },
        {
          id: 'theme',
          label: 'Зміна теми',
          labelKey: 'nav.theme',
          href: '#theme-toggle',
          section: 'main',
          rolesAllowed: APP_ROLES,
          navAction: 'theme-toggle',
        },
      ],
    },
    {
      id: 'teacher-hub',
      label: 'Викладання',
      labelKey: 'nav.teacherHub',
      href: '/teacher',
      section: 'main',
      rolesAllowed: ['teacher'],
      matchMode: 'prefix',
      matchPaths: ['/teacher'],
      children: [
        { id: 'teacher-workspace', label: 'Завдання', labelKey: 'nav.teacherWorkspace', href: '/teacher/workspace', section: 'main', rolesAllowed: ['teacher'], matchPaths: ['/teacher/workspace'] },
        { id: 'teacher-subjects', label: 'Предмети', labelKey: 'nav.teacherSubjects', href: '/teacher/subjects', section: 'main', rolesAllowed: ['teacher'], matchPaths: ['/teacher/subjects'] },
      ],
    },
    {
      id: 'admin-pathways',
      label: 'Pathways',
      labelKey: 'nav.pathways',
      href: '/admin/pathways',
      section: 'main',
      rolesAllowed: ADMIN_PANEL_ROLES,
      requiredFlags: ['canManagePathways'],
      hidden: true,
      matchMode: 'prefix',
    },
    {
      id: 'deanery',
      label: 'Deanery',
      labelKey: 'nav.deanery',
      href: '/deanery',
      section: 'main',
      rolesAllowed: ['deanery'],
      hidden: true,
      matchPaths: ['/deanery'],
    },
  ],
};

module.exports = {
  APP_ROLES,
  navConfig,
};
