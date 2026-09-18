/* Shared UI vocabulary. Wire values and user-authored text are never translated. */
(function (root) {
  "use strict";
  const entities = {
    PERSON: "Людина",
    ORGANIZATION: "Організація",
    SOCIAL_ACCOUNT: "Соціальний акаунт",
    USERNAME: "Ім’я користувача",
    EMAIL: "Електронна пошта",
    PHONE: "Телефон",
    WEBSITE: "Сайт",
    DOMAIN: "Домен",
    LOCATION: "Місце",
    POST: "Публікація",
    DOCUMENT: "Документ",
    IMAGE: "Зображення",
    EVENT: "Подія",
    PUBLIC_CHANNEL: "Публічний канал",
    OTHER: "Інше",
  };
  const relationships = {
    OWNS: "Володіє",
    USES: "Використовує",
    WORKS_AT: "Працює в",
    FOUNDED: "Заснував / заснувала",
    MEMBER_OF: "Входить до",
    FOLLOWS: "Стежить за",
    FOLLOWED_BY: "Має підписника",
    MUTUAL_FOLLOW: "Взаємна підписка",
    MENTIONS: "Згадує",
    TAGGED: "Позначає",
    COMMENTED: "Коментує",
    COMMENTED_ON: "Коментує",
    COLLABORATED_WITH: "Співпрацює з",
    LINKED_TO: "Посилається на",
    LOCATED_AT: "Розташовано в",
    PARTICIPATED_IN: "Бере участь у",
    SAME_PERSON_AS: "Та сама особа",
    POSSIBLY_SAME_PERSON_AS: "Можливо, та сама особа",
    ASSOCIATED_WITH: "Пов’язано з",
    RELATED_TO: "Має зв’язок із",
    SAME_USERNAME: "Однакове ім’я користувача",
    SAME_DOMAIN: "Спільний домен",
    COMMON_CONNECTION: "Спільний зв’язок",
    OTHER: "Інший зв’язок",
  };
  const statuses = {
    FACT: "Факт · FACT",
    INFERENCE: "Аналітичний висновок · INFERENCE",
    HYPOTHESIS: "Гіпотеза · HYPOTHESIS",
  };
  const hints = {
    FACT: "Є конкретне джерело або опис безпосереднього спостереження.",
    INFERENCE:
      "Аналітичний висновок на основі відомостей, а не підтверджений факт.",
    HYPOTHESIS: "Припущення, яке ще потрібно перевірити.",
  };
  const leads = {
    NEW: "Нова",
    TO_CHECK: "До перевірки",
    INVESTIGATING: "У роботі",
    CONFIRMED: "Підтверджена",
    DISMISSED: "Відхилена",
  };
  const priorities = { LOW: "Низький", MEDIUM: "Середній", HIGH: "Високий" };
  const views = {
    Graph: "Граф",
    Table: "Таблиця",
    Timeline: "Хронологія",
    Evidence: "Докази",
    Leads: "Зачіпки",
    Notes: "Нотатки",
    Analysis: "Аналіз",
  };
  const dates = {
    event_date: "Дата події",
    valid_from: "Дійсне від",
    valid_to: "Дійсне до",
    observed_at: "Спостереження",
    created_at: "Створено",
  };
  const kinds = {
    entity: "Сутність",
    relationship: "Зв’язок",
    source: "Джерело",
    lead: "Зачіпка",
    note: "Нотатка",
    layer: "Шар",
    group: "Група",
  };
  const errors = {
    duplicate_record:
      "Такий запис уже існує. Відредагуйте його або змініть тип чи назву.",
    fact_requires_evidence_or_direct_observation:
      "Для факту додайте джерело або опишіть безпосереднє спостереження.",
    self_relationship: "Оберіть дві різні сутності.",
    required_text_missing: "Заповніть обов’язкові поля.",
    invalid_url:
      "Вкажіть повне посилання, що починається з https:// або http://.",
    invalid_confidence: "Впевненість має бути від 0 до 100%.",
    text_too_long: "Текст перевищує дозволену довжину. Скоротіть його.",
    invalid_date: "Перевірте дату та час.",
    invalid_record: "Перевірте заповнені поля й пов’язані об’єкти.",
    invalid_layout:
      "Координати не вдалося зберегти. Спробуйте впорядкувати граф знову.",
    reference_not_found:
      "Пов’язаний об’єкт уже недоступний. Оновіть розслідування.",
    investigation_not_found: "Розслідування вже недоступне. Оберіть інше.",
    entity_not_found: "Сутність уже недоступна. Оновіть розслідування.",
    record_not_found: "Запис уже недоступний. Оновіть розслідування.",
    source_not_found: "Джерело вже недоступне. Оберіть інше.",
    relationship_not_found: "Зв’язок уже недоступний. Оновіть розслідування.",
    file_not_found: "Файл не знайдено. Завантажте його повторно.",
    file_required: "Оберіть файл для завантаження.",
    limit_file_size: "Файл завеликий. Для доказу дозволено до 10 МіБ.",
    file_too_large: "Файл перевищує дозволений розмір.",
    rate_limited: "Забагато запитів. Зачекайте хвилину й повторіть дію.",
    csrf_invalid: "Сеанс застарів. Оновіть сторінку та увійдіть знову.",
    authentication_required: "Увійдіть, щоб продовжити.",
    invalid_credentials: "Неправильний логін або пароль.",
    login_rate_limited: "Забагато спроб входу. Спробуйте пізніше.",
    invalid_json: "Не вдалося прочитати JSON. Перевірте формат файла.",
    invalid_csv:
      "Не вдалося прочитати CSV. Перевірте заголовки та роздільники.",
    invalid_dataset_shape: "Файл не містить потрібних сутностей і зв’язків.",
    unknown_csv_shape: "Не розпізнано колонки CSV. Перевірте приклад формату.",
    unsupported_import_type: "Оберіть файл JSON або CSV.",
    import_file_required: "Оберіть файл для імпорту.",
    too_many_records: "У файлі забагато записів. Розділіть його на частини.",
    graph_node_limit_exceeded: "Досягнуто ліміту сутностей у розслідуванні.",
    graph_relationship_limit_exceeded:
      "Досягнуто ліміту зв’язків у розслідуванні.",
    restore_requires_empty_investigation:
      "Для відновлення повного JSON створіть порожнє розслідування.",
    file_checksum_mismatch:
      "Вкладення пошкоджене. Використайте іншу копію експорту.",
    relationship_reference_missing:
      "Зв’язок посилається на відсутню сутність. Імпортуйте обидва CSV разом.",
    preview_not_supported: "Для цього формату доступне лише завантаження.",
    invalid_entity_type: "Вкажіть тип сутності.",
    invalid_relationship_type: "Вкажіть тип зв’язку.",
    invalid_merge: "Оберіть дві різні сутності для об’єднання.",
    internal_error: "Не вдалося виконати дію. Спробуйте ще раз.",
  };
  function error(value) {
    const s = String(value?.message || value || "");
    return (
      errors[s] ||
      (/[А-Яа-яІіЇїЄєҐґ]/.test(s)
        ? s
        : "Не вдалося виконати дію. Перевірте з’єднання й повторіть спробу.")
    );
  }
  function count(n, forms) {
    const k = new Intl.PluralRules("uk").select(n);
    return `${new Intl.NumberFormat("uk-UA").format(n)} ${forms[{ one: 0, few: 1, many: 2, other: 2 }[k]]}`;
  }
  const dictionary = {
    entities,
    relationships,
    statuses,
    hints,
    leads,
    priorities,
    views,
    dates,
    kinds,
    errors,
    error,
    count,
  };
  if (typeof module === "object" && module.exports) module.exports = dictionary;
  else root.OsintUk = dictionary;
})(typeof window === "object" ? window : globalThis);
