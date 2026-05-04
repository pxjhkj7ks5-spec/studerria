const publicLegalPages = {
  uk: {
    terms: {
      legalTitle: 'Умови використання',
      legalLead: 'Ці умови описують базові правила користування Studerria: навчальним простором для розкладу, завдань, повідомлень, матеріалів і командної роботи.',
      legalSections: [
        {
          title: '1. Призначення сервісу',
          body: 'Studerria допомагає організовувати навчальний процес і щоденну взаємодію між студентами, викладачами та адміністрацією. Сервіс не замінює офіційні документи закладу освіти, якщо інше прямо не визначено адміністрацією.',
        },
        {
          title: '2. Обліковий запис',
          items: [
            'Користувач відповідає за коректність даних, які вводить під час реєстрації та використання сайту.',
            'Пароль потрібно зберігати конфіденційно й не передавати іншим людям.',
            'Адміністрація може обмежити доступ, якщо акаунт використовується для порушення правил або втручання в роботу сервісу.',
          ],
        },
        {
          title: '3. Навчальні дані та дії',
          body: 'Розклад, домашні завдання, повідомлення, матеріали, оцінки та інші навчальні дані показуються відповідно до ролі користувача й наданих прав доступу.',
          items: [
            'Не змінюйте й не публікуйте дані, якщо у вас немає на це дозволу.',
            'Не завантажуйте файли, що порушують права інших людей або можуть пошкодити сервіс.',
            'Не використовуйте автоматизовані запити, скрипти або інші дії, які створюють зайве навантаження.',
          ],
        },
        {
          title: '4. Доступність і зміни',
          body: 'Ми можемо оновлювати інтерфейс, функції та правила роботи Studerria, щоб покращувати стабільність, безпеку й зручність. Окремі функції можуть тимчасово бути недоступними під час технічних робіт.',
        },
        {
          title: '5. Зворотний звʼязок',
          body: 'Якщо ви помітили помилку, маєте питання щодо доступу або хочете уточнити правила користування, зверніться через сторінку підтримки або до відповідальної особи у вашій навчальній групі.',
        },
      ],
    },
    privacy: {
      legalTitle: 'Політика конфіденційності',
      legalLead: 'Ця політика пояснює, які дані Studerria обробляє, для чого вони потрібні та як ми зберігаємо приватність користувачів.',
      legalSections: [
        {
          title: '1. Які дані обробляються',
          items: [
            'Профільні дані: імʼя, роль, курс, група та повʼязані навчальні налаштування.',
            'Навчальні дані: розклад, завдання, матеріали, повідомлення, teamwork-активність і повʼязані статуси.',
            'Технічні дані: сесії входу, час активності, IP-адреса, user agent і події безпеки, потрібні для захисту акаунтів.',
          ],
        },
        {
          title: '2. Для чого використовуються дані',
          body: 'Дані потрібні, щоб показувати персональний навчальний простір, керувати доступами, доставляти повідомлення, підтримувати роботу розкладу та захищати сервіс від зловживань.',
        },
        {
          title: '3. Доступ до даних',
          items: [
            'Користувач бачить дані відповідно до своєї ролі та навчальної групи.',
            'Викладачі, старости, деканат і адміністратори можуть бачити лише ті розділи, які потрібні для їхніх робочих сценаріїв.',
            'Ми не продаємо персональні дані та не передаємо їх стороннім рекламним сервісам.',
          ],
        },
        {
          title: '4. Зберігання та безпека',
          body: 'Studerria використовує сесії, рольові перевірки та технічні журнали для безпечної роботи. Дані зберігаються стільки, скільки потрібно для навчального процесу, адміністрування, підтримки й захисту сервісу.',
        },
        {
          title: '5. Ваші запити',
          body: 'Щоб уточнити дані профілю, повідомити про помилку або поставити питання щодо приватності, зверніться через підтримку. Ми опрацюємо запит у межах доступних технічних і організаційних процедур.',
        },
      ],
    },
  },
  en: {
    terms: {
      legalTitle: 'Terms of Use',
      legalLead: 'These terms describe the core rules for using Studerria as a learning space for schedule, assignments, messaging, materials, and teamwork.',
      legalSections: [
        {
          title: '1. Service purpose',
          body: 'Studerria helps organize the learning process and day-to-day interaction between students, teachers, and administration. The service does not replace official institutional documents unless explicitly stated by administration.',
        },
        {
          title: '2. Account responsibility',
          items: [
            'The user is responsible for the accuracy of data provided during registration and platform usage.',
            'Passwords must be kept confidential and not shared with other people.',
            'Administration may restrict access if an account is used to violate rules or interfere with service operation.',
          ],
        },
        {
          title: '3. Learning data and actions',
          body: 'Schedule, assignments, messages, materials, grades, and other study data are shown according to user role and granted permissions.',
          items: [
            'Do not modify or publish data without proper permission.',
            'Do not upload files that violate rights of others or can damage the service.',
            'Do not use automated requests, scripts, or other actions that create excessive load.',
          ],
        },
        {
          title: '4. Availability and updates',
          body: 'We may update Studerria interfaces, features, and operational rules to improve stability, security, and usability. Some features may be temporarily unavailable during maintenance.',
        },
        {
          title: '5. Feedback',
          body: 'If you notice an issue, have access questions, or need rule clarification, contact support or the responsible person in your study group.',
        },
      ],
    },
    privacy: {
      legalTitle: 'Privacy Policy',
      legalLead: 'This policy explains what data Studerria processes, why it is needed, and how user privacy is protected.',
      legalSections: [
        {
          title: '1. Data we process',
          items: [
            'Profile data: name, role, course, group, and related academic settings.',
            'Learning data: schedule, assignments, materials, messages, teamwork activity, and related statuses.',
            'Technical data: login sessions, activity timestamps, IP address, user agent, and security events required to protect accounts.',
          ],
        },
        {
          title: '2. Why data is used',
          body: 'Data is used to provide a personalized learning workspace, manage permissions, deliver messages, support schedule flows, and protect the service from abuse.',
        },
        {
          title: '3. Access to data',
          items: [
            'Each user sees data according to role and academic group.',
            'Teachers, group leaders, deanery, and administrators can access only sections needed for their workflows.',
            'We do not sell personal data and do not transfer it to third-party advertising services.',
          ],
        },
        {
          title: '4. Storage and security',
          body: 'Studerria uses session controls, role checks, and technical logs for secure operation. Data is stored only as long as needed for the learning process, administration, support, and service protection.',
        },
        {
          title: '5. Your requests',
          body: 'To update profile data, report an issue, or ask a privacy question, contact support. Requests are processed within available technical and organizational procedures.',
        },
      ],
    },
  },
};

module.exports = {
  publicLegalPages,
};
