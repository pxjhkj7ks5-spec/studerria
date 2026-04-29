const changelogTextEnMap = new Map([
  ['Мінорні оновлення сайту для покращення роботи.', 'Minor site updates to improve overall experience.'],
  ['Локальні покращення стабільності та зручності використання.', 'Local stability and usability improvements.'],
  ['Поточні доопрацювання для кращого щоденного досвіду.', 'Ongoing refinements for a better daily experience.'],
  ['Оновлено візуальні деталі для ціліснішого досвіду.', 'Visual details updated for a more cohesive experience.'],
  ['Оновлено візуальні деталі для зручнішої щоденної роботи.', 'Visual details updated for smoother daily use.'],
  ['Поточні доопрацювання для ціліснішого щоденного досвіду.', 'Ongoing refinements for a more cohesive daily experience.'],
  ['Оновлено візуальні деталі для більш цілісного досвіду.', 'Visual details updated for a more unified experience.'],
  ['Оновлено візуальну узгодженість сторінок для комфортнішої роботи.', 'Visual consistency across pages has been improved for more comfortable use.'],
  ['Оновлено візуальні деталі для більш цілісного вигляду сайту.', 'Visual details updated for a more cohesive site appearance.'],
  ['Оновлено відображення навчальних даних для зручнішої роботи з семестром.', 'Academic data display updated for easier semester workflow.'],
  ['Оновлено поведінку генератора розкладу для стабільного попереднього перегляду.', 'Schedule generator behavior updated for a more stable preview flow.'],
  ['Локальні покращення зручності роботи зі сторінкою генерації.', 'Local usability improvements for the generation page.'],
  ['Оновлено правила релізного процесу та перевірок для стабільнішого серверного оновлення.', 'Release process and checks were updated for more stable server updates.'],
  ['Мінорні оновлення робочих сторінок сайту для кращої зручності та актуальності даних.', 'Minor updates to core pages for better usability and fresher data.'],
  ['Оновлено правила ведення changelog і уніфіковано стиль записів по всій історії версій.', 'Changelog rules were updated and entry style was unified across version history.'],
  ['Мінорні оновлення сайту для покращення стабільності та щоденної роботи.', 'Minor site updates to improve stability and daily use.'],
  ['Локальні покращення продуктивності та дрібні виправлення інтерфейсу.', 'Local performance improvements and minor UI fixes.'],
  ['Поточні доопрацювання для комфортнішого щоденного користування сайтом.', 'Ongoing refinements for more comfortable daily use of the platform.'],
  ['Невеликий пакет покращень якості роботи й узгодженості сторінок.', 'A small package of quality and page-consistency improvements.'],
  ['Планове сервісне оновлення для кращої зручності та надійності.', 'Planned service update for better usability and reliability.'],
  ['Мінорне оновлення платформи з фокусом на стабільність і UX.', 'Minor platform update focused on stability and UX.'],
  ['Регулярне покращення якості: швидкість, читабельність і плавність взаємодії.', 'Regular quality improvements: speed, readability, and smoother interaction.'],
  ['Сервісні доопрацювання без зміни базових сценаріїв використання.', 'Service refinements without changes to core usage flows.'],
  ['Невеликі покращення для більш передбачуваної роботи основних сторінок.', 'Small improvements for more predictable behavior across core pages.'],
  ['Технічне полірування інтерфейсу та локальні покращення користувацького досвіду.', 'Technical UI polish and local user-experience improvements.'],
  ['Реліз 1.6.00 зосереджений на відчутному покращенні щоденного користувацького досвіду.', 'Release 1.6.00 is focused on a noticeable improvement in the daily user experience.'],
  ['Покращено поведінку ключових навчальних сценаріїв: розклад, дедлайни, журнал і teamwork.', 'Behavior of key academic flows was improved: schedule, deadlines, journal, and teamwork.'],
  ['Інтерфейс став стабільнішим і прогнозованішим на регулярних щоденних діях.', 'The interface became more stable and predictable in routine daily actions.'],
  ['Реліз 1.5.00 оновив взаємодію з основними сторінками та щоденним маршрутом користувача.', 'Release 1.5.00 updated interaction with core pages and the daily user journey.'],
  ['Покращено візуальну узгодженість, читабельність і зручність переходів між ключовими модулями.', 'Visual consistency, readability, and transition comfort between key modules were improved.'],
  ['Фокус оновлення: менше тертя у щоденних задачах студентів і викладачів.', 'Update focus: less friction in daily tasks for students and teachers.'],
  ['Реліз 1.4.00 сфокусований на покращенні якості користування навчальними сторінками.', 'Release 1.4.00 is focused on improving usability of academic pages.'],
  ['Оновлено подачу інформації у щоденних сценаріях, щоб швидше знаходити потрібний контекст.', 'Information presentation in daily scenarios was updated to find needed context faster.'],
  ['Стабілізовано базові UX-потоки для регулярної роботи з платформою.', 'Core UX flows were stabilized for regular platform use.'],
  ['Реліз 1.3.00 розширив і вирівняв досвід взаємодії з навчальними модулями.', 'Release 1.3.00 expanded and aligned the interaction experience across academic modules.'],
  ['Покращено ключові користувацькі сценарії навколо матеріалів, дедлайнів і командної взаємодії.', 'Key user scenarios around materials, deadlines, and team collaboration were improved.'],
  ['Інтерфейсні потоки стали простішими та більш передбачуваними для щоденного використання.', 'Interface flows became simpler and more predictable for daily use.'],
  ['Реліз 1.2.00 покращив стартові та базові сценарії роботи користувача з системою.', 'Release 1.2.00 improved onboarding and core user scenarios in the system.'],
  ['Оновлено зручність взаємодії з профілем і щоденними навчальними сторінками.', 'Interaction with profile and daily study pages was made more convenient.'],
  ['Зменшено кількість дрібних UX-барєрів у регулярному користуванні платформою.', 'The number of small UX barriers in regular platform use was reduced.'],
  ['Реліз 1.1.00 присвячений стабілізації та покращенню щоденного користувацького шляху.', 'Release 1.1.00 is dedicated to stabilizing and improving the daily user journey.'],
  ['Посилено надійність базових навчальних сценаріїв і читабельність інтерфейсу.', 'Reliability of core academic scenarios and interface readability were improved.'],
  ['Платформа стала більш послідовною в типових щоденних діях.', 'The platform became more consistent in typical daily actions.'],
  ['Реліз 1.0.00 зафіксував стабільний користувацький досвід для основних сценаріїв платформи.', 'Release 1.0.00 established a stable user experience for core platform scenarios.'],
  ['Базові модулі навчання та персонального простору приведено до цілісної й зрозумілої взаємодії.', 'Core learning and personal-space modules were aligned into a cohesive and clear interaction model.'],
  ['Оновлення орієнтоване на передбачуваність, зручність і готовність до щоденного використання.', 'The update is focused on predictability, usability, and readiness for daily use.'],
  ['Реліз 0.9.00 суттєво покращив щоденний UX і загальну цілісність інтерфейсу.', 'Release 0.9.00 significantly improved daily UX and overall interface cohesion.'],
  ['Оновлено ключові користувацькі потоки для більш плавної та зрозумілої взаємодії.', 'Key user flows were updated for smoother and clearer interaction.'],
  ['Підвищено зручність роботи з основними навчальними сценаріями.', 'Usability of core academic scenarios was improved.'],
  ['Реліз 0.8.00 посилив базовий користувацький досвід і узгодженість сторінок.', 'Release 0.8.00 strengthened core user experience and page consistency.'],
  ['Покращено щоденні сценарії навігації та взаємодії з навчальним контентом.', 'Daily navigation and learning-content interaction scenarios were improved.'],
  ['Фокус оновлення: стабільніша робота і простіше сприйняття основних функцій.', 'Update focus: more stable behavior and simpler perception of core features.'],
  ['Реліз 0.7.00 заклав основу для зручного щоденного користування платформою.', 'Release 0.7.00 laid the foundation for convenient daily platform use.'],
  ['Оновлено ключові сценарії навчальної взаємодії для більш цілісного користувацького досвіду.', 'Key academic interaction scenarios were updated for a more cohesive user experience.'],
  ['Підвищено загальну якість інтерфейсу та передбачуваність роботи основних сторінок.', 'Overall interface quality and predictability of core pages were improved.'],
]);

function localizeChangelogItems(items, lang) {
  if (!Array.isArray(items) || lang !== 'en') return Array.isArray(items) ? items : [];
  return items.map((entry) => {
    if (!entry || typeof entry !== 'object') return entry;
    const sourceItems = Array.isArray(entry.items) ? entry.items : [];
    const localizedItems = sourceItems.map((text) => {
      const normalized = String(text || '').trim();
      return changelogTextEnMap.get(normalized) || normalized;
    });
    return {
      ...entry,
      items: localizedItems,
    };
  });
}

module.exports = {
  localizeChangelogItems,
};
