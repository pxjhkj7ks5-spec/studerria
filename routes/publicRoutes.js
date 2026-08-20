const LANDING_PRODUCTS = Object.freeze([
  {
    id: 'naradadruk',
    href: '/naradadruk',
    secondaryHref: 'https://t.me/naradaprint',
  },
  {
    id: 'studerria',
    href: '/login',
  },
  {
    id: 'telegram',
    href: 'https://t.me/studerria_bot',
  },
  {
    id: 'charredmap',
    href: '/charredmap',
  },
  {
    id: 'shieldline',
    href: '/shieldline',
    secondaryHref: 'https://t.me/ShieldLinebot',
  },
  {
    id: 'ykg',
    href: '',
    status: 'soon',
  },
]);

const LANDING_COPY = Object.freeze({
  uk: {
    seo: {
      title: 'Studerria — цифрові продукти однієї команди',
      description: 'Studerria обʼєднує навчальну платформу, Telegram-продукти, NaradaDruk, Charredmap, Shieldline та нові проєкти команди.',
    },
    nav: {
      products: 'Продукти',
      team: 'Команда',
      open: 'Увійти',
      menu: 'Відкрити меню',
      closeMenu: 'Закрити меню',
      language: 'Мова',
    },
    hero: {
      eyebrow: 'Studerria / digital products',
      titleLead: 'Одна команда.',
      titleAccent: 'Різні продукти.',
      description: 'Створюємо й розвиваємо цифрові продукти для навчання, творчості, торгівлі та взаємодії.',
      productsCta: 'Дивитися продукти',
      platformCta: 'Увійти в Studerria',
      imageAlt: '3D-друкований виріб NaradaDruk у робочому середовищі',
      scroll: 'Гортайте далі',
    },
    intro: {
      eyebrow: 'Не концепти',
      title: 'Продукти, які вже працюють.',
      description: 'Кожен напрям має власний характер і задачу. За ними — одна команда, спільний підхід і постійна робота після запуску.',
    },
    productsLabel: 'Продукти Studerria',
    products: {
      naradadruk: {
        eyebrow: 'Головний фокус зараз / 3D-друк',
        title: 'NaradaDruk',
        description: '3D-друк, корисні речі та індивідуальні замовлення — від ідеї до готового виробу.',
        primaryCta: 'Відкрити магазин',
        secondaryCta: 'Telegram',
        imageAlt: 'Добірка 3D-друкованих виробів NaradaDruk',
      },
      studerria: {
        eyebrow: 'Навчальна платформа',
        title: 'Studerria',
        description: 'Розклад, журнал, дедлайни, My Day і teamwork в одному навчальному просторі.',
        primaryCta: 'Відкрити платформу',
      },
      telegram: {
        eyebrow: 'Навчання в Telegram',
        title: 'Studerria bot',
        description: 'Розклад, предмети, My Day і teamwork у звичному Telegram-середовищі.',
        primaryCta: 'Відкрити бота',
        visualTitle: 'Твій день',
        visualLine1: 'Розклад і предмети',
        visualLine2: 'My Day і Teamwork',
      },
      charredmap: {
        eyebrow: 'Інтерактивна мапа історій',
        title: 'Charredmap',
        description: 'Публічна мапа історій українських міст, де памʼять говорить через місця й людські свідчення.',
        primaryCta: 'Відкрити мапу',
      },
      shieldline: {
        eyebrow: 'Стратегічна браузерна гра',
        title: 'Shieldline',
        description: 'Вигадана стратегічна гра про захист міст, планування оборони та рішення під тиском.',
        primaryCta: 'Відкрити гру',
        secondaryCta: 'Telegram bot',
        imageAlt: 'Знак стратегічної гри Shieldline',
      },
      ykg: {
        eyebrow: 'Окремий магазин',
        title: 'YKG',
        description: 'Самостійний storefront Young Killers Group. Перший публічний запуск ще готується.',
        status: 'Незабаром',
      },
    },
    manifesto: {
      eyebrow: 'Одна команда',
      titleLead: 'Різні напрями.',
      titleAccent: 'Спільна відповідальність.',
      description: 'Ці продукти створюються й підтримуються однією командою — від першого рішення до щоденної роботи після запуску.',
      cta: 'Почати зі Studerria',
    },
    footer: {
      line: 'Digital products by one team.',
      privacy: 'Конфіденційність',
      terms: 'Умови',
      changelog: 'Оновлення',
      copyright: '© Studerria 2026',
    },
  },
  en: {
    seo: {
      title: 'Studerria — digital products by one team',
      description: 'Studerria brings together a learning platform, Telegram products, NaradaDruk, Charredmap, Shieldline, and the teamʼs new projects.',
    },
    nav: {
      products: 'Products',
      team: 'Team',
      open: 'Sign in',
      menu: 'Open menu',
      closeMenu: 'Close menu',
      language: 'Language',
    },
    hero: {
      eyebrow: 'Studerria / digital products',
      titleLead: 'One team.',
      titleAccent: 'Different products.',
      description: 'We create and grow digital products for learning, making, commerce, and interaction.',
      productsCta: 'Explore products',
      platformCta: 'Open Studerria',
      imageAlt: 'A NaradaDruk 3D-printed object in a working environment',
      scroll: 'Scroll to explore',
    },
    intro: {
      eyebrow: 'Built, not imagined',
      title: 'Products that already work.',
      description: 'Every direction has its own character and purpose. Behind them is one team, a shared approach, and continuous work after launch.',
    },
    productsLabel: 'Studerria products',
    products: {
      naradadruk: {
        eyebrow: 'Current main focus / 3D printing',
        title: 'NaradaDruk',
        description: '3D printing, useful objects, and custom orders — from an idea to a finished piece.',
        primaryCta: 'Open the store',
        secondaryCta: 'Telegram',
        imageAlt: 'A selection of NaradaDruk 3D-printed products',
      },
      studerria: {
        eyebrow: 'Learning platform',
        title: 'Studerria',
        description: 'Schedule, journal, deadlines, My Day, and teamwork in one learning space.',
        primaryCta: 'Open the platform',
      },
      telegram: {
        eyebrow: 'Learning in Telegram',
        title: 'Studerria bot',
        description: 'Schedule, subjects, My Day, and teamwork in the familiar Telegram environment.',
        primaryCta: 'Open the bot',
        visualTitle: 'Your day',
        visualLine1: 'Schedule and subjects',
        visualLine2: 'My Day and Teamwork',
      },
      charredmap: {
        eyebrow: 'Interactive story map',
        title: 'Charredmap',
        description: 'A public map of stories from Ukrainian cities, where memory speaks through places and personal accounts.',
        primaryCta: 'Open the map',
      },
      shieldline: {
        eyebrow: 'Strategic browser game',
        title: 'Shieldline',
        description: 'A fictional strategy game about protecting cities, planning defenses, and making decisions under pressure.',
        primaryCta: 'Open the game',
        secondaryCta: 'Telegram bot',
        imageAlt: 'The mark of the Shieldline strategy game',
      },
      ykg: {
        eyebrow: 'Independent store',
        title: 'YKG',
        description: 'A standalone Young Killers Group storefront. Its first public release is still in preparation.',
        status: 'Coming soon',
      },
    },
    manifesto: {
      eyebrow: 'One team',
      titleLead: 'Different directions.',
      titleAccent: 'Shared responsibility.',
      description: 'These products are created and maintained by one team — from the first decision to the daily work after launch.',
      cta: 'Start with Studerria',
    },
    footer: {
      line: 'Digital products by one team.',
      privacy: 'Privacy',
      terms: 'Terms',
      changelog: 'Changelog',
      copyright: '© Studerria 2026',
    },
  },
});

function buildLandingStructuredData(copy, platformUrl) {
  const productUrls = {
    naradadruk: 'https://studerria.com/naradadruk',
    studerria: new URL(platformUrl, 'https://studerria.com').toString(),
    telegram: 'https://t.me/studerria_bot',
    charredmap: 'https://studerria.com/charredmap',
    shieldline: 'https://studerria.com/shieldline',
  };

  return {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'WebSite',
        name: 'Studerria',
        url: 'https://studerria.com/',
        description: copy.seo.description,
        inLanguage: copy === LANDING_COPY.en ? 'en' : 'uk',
      },
      {
        '@type': 'ItemList',
        name: copy.productsLabel,
        itemListElement: LANDING_PRODUCTS.map((product, index) => ({
          '@type': 'ListItem',
          position: index + 1,
          item: {
            '@type': 'CreativeWork',
            name: copy.products[product.id].title,
            description: copy.products[product.id].description,
            ...(productUrls[product.id] ? { url: productUrls[product.id] } : {}),
          },
        })),
      },
    ],
  };
}

function registerPublicRoutes(app, deps) {
  const {
    getPreferredLang,
    buildLoginErrorMessage,
    publicLegalPages,
  } = deps;

  app.get('/', (req, res) => {
    const landingLang = getPreferredLang(req) === 'en' ? 'en' : 'uk';
    const copy = LANDING_COPY[landingLang];
    const platformUrl = req.session && req.session.user ? '/home' : '/login';
    return res.render('landing', {
      layout: false,
      landingLang,
      copy,
      products: LANDING_PRODUCTS,
      platformUrl,
      structuredData: buildLandingStructuredData(copy, platformUrl),
    });
  });

  app.get('/login', (req, res) => {
    if (req.session && req.session.user) {
      return res.redirect('/home');
    }
    const lang = getPreferredLang(req);
    const loginErrorText = buildLoginErrorMessage(lang, req.query.error);
    res.render('login', {
      error: Boolean(loginErrorText),
      loginErrorText,
      layout: false,
    });
  });

  app.get(['/terms', '/privacy'], (req, res) => {
    const lang = getPreferredLang(req);
    const legalLang = lang === 'en' ? 'en' : 'uk';
    const key = req.path === '/privacy' ? 'privacy' : 'terms';
    return res.render('legal', {
      ...publicLegalPages[legalLang][key],
      layout: false,
    });
  });

  app.get('/changelog', (req, res) => res.render('changelog', { layout: false }));

  app.get('/preview', (req, res) => res.render('preview', { layout: false }));
}

module.exports = {
  LANDING_COPY,
  LANDING_PRODUCTS,
  buildLandingStructuredData,
  registerPublicRoutes,
};
