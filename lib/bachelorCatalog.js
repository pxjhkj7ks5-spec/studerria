const DEFAULT_BACHELOR_CATALOG_SOURCE_KEY = 'bachelor_bp_pled_2025';
const DEFAULT_BACHELOR_CATALOG_GROUP_COUNT = 2;

const DEFAULT_BACHELOR_CATALOG_FLAGS = Object.freeze({
  is_visible: true,
  is_required: true,
  is_general: true,
  show_in_teamwork: true,
});

const BACHELOR_SEMESTER_COLUMN_MAP = Object.freeze({
  10: Object.freeze({ stage_number: 1, term_number: 1 }),
  11: Object.freeze({ stage_number: 1, term_number: 2 }),
  12: Object.freeze({ stage_number: 1, term_number: 3 }),
  13: Object.freeze({ stage_number: 2, term_number: 1 }),
  14: Object.freeze({ stage_number: 2, term_number: 2 }),
  15: Object.freeze({ stage_number: 2, term_number: 3 }),
  16: Object.freeze({ stage_number: 3, term_number: 1 }),
  17: Object.freeze({ stage_number: 3, term_number: 2 }),
  18: Object.freeze({ stage_number: 3, term_number: 3 }),
  19: Object.freeze({ stage_number: 4, term_number: 1 }),
  20: Object.freeze({ stage_number: 4, term_number: 2 }),
  21: Object.freeze({ stage_number: 4, term_number: 3 }),
});

const ENTRY_KIND_SET = new Set([
  'subject',
  'practice',
  'coursework',
  'elective',
  'qualification_work',
  'final_exam',
]);

const BACHELOR_CATALOG_PLACEMENT_OVERRIDES = Object.freeze({
  '1.1.11.': Object.freeze({ suggested_stage_number: 1, suggested_term_numbers: [3] }),
  '1.1.13.': Object.freeze({ suggested_stage_number: 1, suggested_term_numbers: [3] }),
  '1.1.14.': Object.freeze({ suggested_stage_number: 1, suggested_term_numbers: [3] }),
  '1.1.15.': Object.freeze({ suggested_stage_number: 1, suggested_term_numbers: [3] }),
  '1.2.1.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [2, 3] }),
  '2.1.1.7.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [2, 3] }),
  '2.1.2.7.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [2, 3] }),
  '2.1.3.7.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [2, 3] }),
  '2.1.4.7.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [2, 3] }),
  '2.2.1.': Object.freeze({ suggested_stage_number: 3, suggested_term_numbers: [3] }),
  '2.2.4.': Object.freeze({ suggested_stage_number: 2, suggested_term_numbers: [3] }),
  '2.2.7.': Object.freeze({ suggested_stage_number: 2, suggested_term_numbers: [3] }),
  '3.1.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [1, 2, 3] }),
  '3.2.': Object.freeze({ suggested_stage_number: 4, suggested_term_numbers: [3] }),
});

const RAW_BACHELOR_CATALOG_SOURCES = [
  {
    key: DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
    track_key: 'bachelor',
    label: 'БП 2025-2026',
    title: 'Політичне лідерство та економічна дипломатія',
    description: 'Sheet 2 "БП" from 0601НП_ПЛЕД Бакалавр_2025-2026н.р..xlsx',
    entries: [
      { source_code: '1.1.1.', template_name: 'Українська мова за професійним спрямуванням. Академічне письмо і публічні виступи', display_title: 'Українська мова за професійним спрямуванням. Академічне письмо і публічні виступи', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.2.', template_name: 'Академічна іноземна мова', display_title: 'Академічна іноземна мова', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1, 2], entry_kind: 'subject' },
      { source_code: '1.1.3.', template_name: 'Прикладна математика для ухвалення рішень', display_title: 'Прикладна математика для ухвалення рішень', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1, 2], entry_kind: 'subject' },
      { source_code: '1.1.4.', template_name: 'Публічна історія України та українська ідентичність', display_title: 'Публічна історія України та українська ідентичність', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.5.', template_name: 'Вступ до політології. Загальна теорія політики.', display_title: 'Вступ до політології. Загальна теорія політики.', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1, 2], entry_kind: 'subject' },
      { source_code: '1.1.6.', template_name: 'Міжнародні відносини і світова політика', display_title: 'Міжнародні відносини і світова політика', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1, 2], entry_kind: 'subject' },
      { source_code: '1.1.7.', template_name: 'Історія великих ідей (формат дискусійного клубу)', display_title: 'Історія великих ідей (формат дискусійного клубу)', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.8.', template_name: 'Права людини та конституціоналізм', display_title: 'Права людини та конституціоналізм', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.9.', template_name: 'Публічна політика та публічна дипломатія', display_title: 'Публічна політика та публічна дипломатія', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.10.', template_name: 'Філософія', display_title: 'Філософія', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.11.', template_name: 'Дипломатичний протокол та етикет', display_title: 'Дипломатичний протокол та етикет', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'subject' },
      { source_code: '1.1.12.', template_name: 'Глобалістика і регіоналістика', display_title: 'Глобалістика і регіоналістика', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 1, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.13.', template_name: 'Політологічні студії', display_title: 'Політологічні студії', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'subject' },
      { source_code: '1.1.14.', template_name: 'Мовна практика (формат тематичної мовної школи)', display_title: 'Мовна практика (формат тематичної мовної школи)', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'practice' },
      { source_code: '1.1.15.', template_name: 'Лідери світу і основи країнознавства (практикуми)', display_title: 'Лідери світу і основи країнознавства (практикуми)', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'practice' },
      { source_code: '1.1.16.', template_name: 'Іноземна  мова (за професійним спрямуванням)', display_title: 'Іноземна  мова (за професійним спрямуванням)', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [1, 2], entry_kind: 'subject' },
      { source_code: '1.1.17.', template_name: 'Міжнародні організації та глобальне управління (дипломатичні симуляції)', display_title: 'Міжнародні організації та глобальне управління (дипломатичні симуляції)', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.18.', template_name: 'Мікроекономіка', display_title: 'Мікроекономіка', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.19.', template_name: 'Макроекономіка', display_title: 'Макроекономіка', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.20.', template_name: 'Міжнародні економічні відносини', display_title: 'Міжнародні економічні відносини', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.21.', template_name: 'Національна безпека. Національні інтереси держави', display_title: 'Національна безпека. Національні інтереси держави', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.22.', template_name: 'Політичні системи сучасності. Політична компаративістика', display_title: 'Політичні системи сучасності. Політична компаративістика', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.23.', template_name: 'Стратегічні комунікації та GR - технології', display_title: 'Стратегічні комунікації та GR - технології', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.24.', template_name: 'Міжнародна торгівля. Міжнародні фінанси', display_title: 'Міжнародна торгівля. Міжнародні фінанси', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.25.', template_name: 'Саморозвиток Лідера та практики командотворення', display_title: 'Саморозвиток Лідера та практики командотворення', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.26.', template_name: 'Міжнародне публічне право. Міжнародне економічне право', display_title: 'Міжнародне публічне право. Міжнародне економічне право', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.27.', template_name: 'Статистика. Кількісні та якісні методи дослідження у соціальних науках', display_title: 'Статистика. Кількісні та якісні методи дослідження у соціальних науках', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.28.', template_name: 'Науково-практичні дослідження в соціальних науках', display_title: 'Науково-практичні дослідження в соціальних науках', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [1, 2], entry_kind: 'subject' },
      { source_code: '1.1.29.', template_name: 'Економічна дипломатія', display_title: 'Економічна дипломатія', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.30.', template_name: 'Міжнародні конфлікти. Міжнародна безпека', display_title: 'Міжнародні конфлікти. Міжнародна безпека', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.31.', template_name: 'Аналіз відкритих даних. Моделювання і прогнозування сучасних процесів', display_title: 'Аналіз відкритих даних. Моделювання і прогнозування сучасних процесів', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.32.', template_name: 'Політична культура і міжкультурний діалог', display_title: 'Політична культура і міжкультурний діалог', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.33.', template_name: 'Прикладана політологія', display_title: 'Прикладана політологія', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.34.', template_name: 'Політична аналітика: методи та підходи', display_title: 'Політична аналітика: методи та підходи', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.35.', template_name: 'Світові ринки. Кон\'юнктурний аналіз світових ринків', display_title: 'Світові ринки. Кон\'юнктурний аналіз світових ринків', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '1.1.36.', template_name: 'Політичні технології. Псефологія.', display_title: 'Політичні технології. Псефологія.', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.1.37.', template_name: 'Зовнішня політика України. Дипломатична служба', display_title: 'Зовнішня політика України. Дипломатична служба', source_section: '1.1. Обов\'язкові освітні компоненти', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '1.2.1.', template_name: 'Практика переддипломна', display_title: 'Практика переддипломна', source_section: '1.2. Практика', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'practice' },
      { source_code: '2.1.1.1.', template_name: 'Політична географія та регіоналістика Африки', display_title: 'Політична географія та регіоналістика Африки', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.1.2.', template_name: 'Соціокультурний розвиток та релігійна різноманітність в Африці', display_title: 'Соціокультурний розвиток та релігійна різноманітність в Африці', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.1.3.', template_name: 'Політичні системи країн Африки', display_title: 'Політичні системи країн Африки', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.1.4.', template_name: 'Економіка країн Африки', display_title: 'Економіка країн Африки', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.1.5.', template_name: 'Збройні конфлікти в Африці', display_title: 'Збройні конфлікти в Африці', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.1.6.', template_name: 'Багатостороння дипломатія африканських країн', display_title: 'Багатостороння дипломатія африканських країн', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.1.7.', template_name: 'Міждисциплінарна курсова робота за Minor (Африканістика)', display_title: 'Міждисциплінарна курсова робота за Minor', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'coursework', minor_name: 'Африканістика' },
      { source_code: '2.1.2.1.', template_name: 'Політична географія та регіоналістика  Латинської Америки і Карибського басейну', display_title: 'Політична географія та регіоналістика  Латинської Америки і Карибського басейну', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.2.2.', template_name: 'Соціокультурний розвиток і релігійні особливості регіону Латинської Америки і Карибського басейну', display_title: 'Соціокультурний розвиток і релігійні особливості регіону Латинської Америки і Карибського басейну', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.2.3.', template_name: 'Політичні системи країн Латинської Америки і Карибського басейну', display_title: 'Політичні системи країн Латинської Америки і Карибського басейну', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.2.4.', template_name: 'Особливості економічного розвитку та інвестиційного клімату країн Латинської Америки і Карибського басейну', display_title: 'Особливості економічного розвитку та інвестиційного клімату країн Латинської Америки і Карибського басейну', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.2.5.', template_name: 'Збройні конфлікти в в регіоні Латинської Америки і Карибського басейну', display_title: 'Збройні конфлікти в в регіоні Латинської Америки і Карибського басейну', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.2.6.', template_name: 'Зовнішня політика і дипломатія України в країнах Латинської Америки і Карибського басейну', display_title: 'Зовнішня політика і дипломатія України в країнах Латинської Америки і Карибського басейну', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.2.7.', template_name: 'Міждисциплінарна курсова робота за Minor (Латиноамериканські студії)', display_title: 'Міждисциплінарна курсова робота за Minor', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'coursework', minor_name: 'Латиноамериканські студії' },
      { source_code: '2.1.3.1.', template_name: 'Історія євроропейської цивілізації. Культурна спадщина Європи', display_title: 'Історія євроропейської цивілізації. Культурна спадщина Європи', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.3.2.', template_name: 'Право ЄС', display_title: 'Право ЄС', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.3.3.', template_name: 'Інституції ЄС і ухвалення політичних рішень', display_title: 'Інституції ЄС і ухвалення політичних рішень', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.3.4.', template_name: 'Європейська економічна інтеграція. Економічна політика та економічна дипломатія ЄС', display_title: 'Європейська економічна інтеграція. Економічна політика та економічна дипломатія ЄС', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.3.5.', template_name: 'Європейський мультикультуралізм. Публічна дипломатія і міжкультурний діалог в ЄС', display_title: 'Європейський мультикультуралізм. Публічна дипломатія і міжкультурний діалог в ЄС', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.3.6.', template_name: 'Зелена економіка і кліматична дипломатія ЄС', display_title: 'Зелена економіка і кліматична дипломатія ЄС', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.3.7.', template_name: 'Міждисциплінарна курсова робота за Minor (Європейські міждисциплінарні студії)', display_title: 'Міждисциплінарна курсова робота за Minor', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'coursework', minor_name: 'Європейські міждисциплінарні студії' },
      { source_code: '2.1.4.1.', template_name: 'Дисципліна 1', display_title: 'Дисципліна 1', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.4.2.', template_name: 'Дисципліна 2', display_title: 'Дисципліна 2', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.4.3.', template_name: 'Дисципліна 3', display_title: 'Дисципліна 3', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.4.4.', template_name: 'Дисципліна 4', display_title: 'Дисципліна 4', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.1.4.5.', template_name: 'Дисципліна 5', display_title: 'Дисципліна 5', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.4.6.', template_name: 'Дисципліна 6', display_title: 'Дисципліна 6', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1], entry_kind: 'subject' },
      { source_code: '2.1.4.7.', template_name: 'Дисципліна 7', display_title: 'Дисципліна 7', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.2.1.', template_name: 'Друга іноземна мова', display_title: 'Друга іноземна мова', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'subject' },
      { source_code: '2.2.1.1.', template_name: 'Іспанська мова', display_title: 'Іспанська мова', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject', default_group_count: 2, default_flags: { is_general: true } },
      { source_code: '2.2.1.2.', template_name: 'Німецька мова', display_title: 'Німецька мова', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject', default_group_count: 1, default_flags: { is_general: true } },
      { source_code: '2.2.2.', template_name: 'Базова загальна військова підготовка громадян України, які здобувають вищу освіту (теоретична підготовка)*', display_title: 'Базова загальна військова підготовка громадян України, які здобувають вищу освіту (теоретична підготовка)*', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.2.3.', template_name: 'Комунікації в публічній сфері', display_title: 'Комунікації в публічній сфері', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'subject' },
      { source_code: '2.2.4.', template_name: 'Базова загальна військова підготовка громадян України, які здобувають вищу освіту (практична підготовка)**', display_title: 'Базова загальна військова підготовка громадян України, які здобувають вищу освіту (практична підготовка)**', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'practice' },
      { source_code: '2.2.5.', template_name: 'Дисципліна вільного вибору 1', display_title: 'Дисципліна вільного вибору 1', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [1], entry_kind: 'elective' },
      { source_code: '2.2.6.', template_name: 'Дисципліна вільного вибору 2', display_title: 'Дисципліна вільного вибору 2', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 2, suggested_term_numbers: [2], entry_kind: 'elective' },
      { source_code: '2.2.7.', template_name: 'Дисципліна вільного вибору 3', display_title: 'Дисципліна вільного вибору 3', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'elective' },
      { source_code: '2.2.8.', template_name: 'Дисципліна вільного вибору 4', display_title: 'Дисципліна вільного вибору 4', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [1], entry_kind: 'elective' },
      { source_code: '2.2.9.', template_name: 'Дисципліна вільного вибору 5', display_title: 'Дисципліна вільного вибору 5', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 3, suggested_term_numbers: [2], entry_kind: 'elective' },
      { source_code: '3.1.', template_name: 'Кваліфікаційна робота', display_title: 'Кваліфікаційна робота', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: 4, suggested_term_numbers: [1, 2], entry_kind: 'qualification_work' },
      { source_code: '3.2.', template_name: 'Комплексний фаховий екзамен', display_title: 'Комплексний фаховий екзамен', source_section: '2.1. Дисципліни професійної  та практичної підготовки', suggested_stage_number: null, suggested_term_numbers: [], entry_kind: 'final_exam' },
    ],
  },
];

function cleanText(value, maxLength = 200) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizePositiveInt(value, fallback = null) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  const normalizedFallback = Number(fallback || 0);
  return Number.isInteger(normalizedFallback) && normalizedFallback > 0 ? normalizedFallback : null;
}

function normalizeSourceKey(value, fallback = DEFAULT_BACHELOR_CATALOG_SOURCE_KEY) {
  const normalized = cleanText(value, 80).toLowerCase();
  if (RAW_BACHELOR_CATALOG_SOURCES.some((source) => source.key === normalized)) {
    return normalized;
  }
  return RAW_BACHELOR_CATALOG_SOURCES.some((source) => source.key === fallback)
    ? fallback
    : DEFAULT_BACHELOR_CATALOG_SOURCE_KEY;
}

function normalizeEntryKind(value) {
  const normalized = cleanText(value, 40).toLowerCase();
  return ENTRY_KIND_SET.has(normalized) ? normalized : 'subject';
}

function normalizeTermNumbers(values = []) {
  return Array.from(new Set(
    (Array.isArray(values) ? values : [values])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => value === 1 || value === 2 || value === 3)
  )).sort((a, b) => a - b);
}

function normalizeBachelorCatalogGroupCount(value, fallback = DEFAULT_BACHELOR_CATALOG_GROUP_COUNT) {
  const normalized = normalizePositiveInt(value, fallback);
  if (normalized === 1 || normalized === 2 || normalized === 3) {
    return normalized;
  }
  const fallbackValue = normalizePositiveInt(fallback, DEFAULT_BACHELOR_CATALOG_GROUP_COUNT);
  return fallbackValue === 1 || fallbackValue === 2 || fallbackValue === 3
    ? fallbackValue
    : DEFAULT_BACHELOR_CATALOG_GROUP_COUNT;
}

function mapBachelorSemesterColumnToStageTerm(columnNumber) {
  const normalized = normalizePositiveInt(columnNumber);
  const row = normalized ? BACHELOR_SEMESTER_COLUMN_MAP[normalized] : null;
  return row ? { ...row } : null;
}

function isBachelorCatalogContainerTitle(title) {
  const normalized = cleanText(title, 200);
  if (!normalized) {
    return true;
  }
  return (
    /^Minor\s+"/u.test(normalized)
    || normalized === 'Навчальні дисципліни професійної та практичної підготовки'
    || normalized === 'Навчальні дисципліни вільного вибору'
  );
}

function buildMinorCourseworkTemplateName(title, minorName) {
  const normalizedTitle = cleanText(title, 200);
  const normalizedMinorName = cleanText(minorName, 120);
  if (
    normalizedTitle !== 'Міждисциплінарна курсова робота за Minor'
    || !normalizedMinorName
  ) {
    return normalizedTitle;
  }
  return `${normalizedTitle} (${normalizedMinorName})`;
}

function normalizeBachelorCatalogEntry(rawEntry = {}, sourceKey = DEFAULT_BACHELOR_CATALOG_SOURCE_KEY) {
  const normalizedTemplateName = buildMinorCourseworkTemplateName(
    rawEntry.template_name || rawEntry.display_title,
    rawEntry.minor_name
  );
  const sourceCode = cleanText(rawEntry.source_code, 80);
  const placementOverride = BACHELOR_CATALOG_PLACEMENT_OVERRIDES[sourceCode] || null;
  return {
    source_key: normalizeSourceKey(sourceKey),
    source_code: sourceCode,
    template_name: cleanText(normalizedTemplateName, 200),
    display_title: cleanText(rawEntry.display_title || rawEntry.template_name, 200),
    source_section: cleanText(rawEntry.source_section, 160),
    suggested_stage_number: normalizePositiveInt(
      placementOverride ? placementOverride.suggested_stage_number : rawEntry.suggested_stage_number
    ),
    suggested_term_numbers: normalizeTermNumbers(
      placementOverride ? placementOverride.suggested_term_numbers : (rawEntry.suggested_term_numbers || [])
    ),
    entry_kind: normalizeEntryKind(rawEntry.entry_kind),
    default_group_count: normalizeBachelorCatalogGroupCount(rawEntry.default_group_count),
    default_flags: {
      ...DEFAULT_BACHELOR_CATALOG_FLAGS,
      ...(rawEntry.default_flags && typeof rawEntry.default_flags === 'object' ? rawEntry.default_flags : {}),
    },
    default_activity_preset: cleanText(rawEntry.default_activity_preset || 'lecture_seminar', 40).toLowerCase() || 'lecture_seminar',
    minor_name: cleanText(rawEntry.minor_name, 120),
  };
}

function cloneCatalogSource(rawSource = {}) {
  const sourceKey = normalizeSourceKey(rawSource.key);
  const entries = (Array.isArray(rawSource.entries) ? rawSource.entries : [])
    .map((entry) => normalizeBachelorCatalogEntry(entry, sourceKey))
    .filter((entry) => entry.source_code && entry.template_name && entry.display_title);
  return {
    key: sourceKey,
    track_key: cleanText(rawSource.track_key, 40).toLowerCase() || 'bachelor',
    label: cleanText(rawSource.label, 120),
    title: cleanText(rawSource.title, 200),
    description: cleanText(rawSource.description, 200),
    entries,
  };
}

function listBachelorCatalogSources() {
  return RAW_BACHELOR_CATALOG_SOURCES
    .map((source) => cloneCatalogSource(source))
    .map((source) => ({
      key: source.key,
      track_key: source.track_key,
      label: source.label,
      title: source.title,
      description: source.description,
      entry_count: source.entries.length,
    }));
}

function getBachelorCatalogSource(sourceKey) {
  const normalizedSourceKey = normalizeSourceKey(sourceKey);
  const rawSource = RAW_BACHELOR_CATALOG_SOURCES.find((source) => source.key === normalizedSourceKey)
    || RAW_BACHELOR_CATALOG_SOURCES[0]
    || null;
  return rawSource ? cloneCatalogSource(rawSource) : null;
}

function listBachelorCatalogEntries(sourceKey) {
  const source = getBachelorCatalogSource(sourceKey);
  return source ? source.entries.map((entry) => ({ ...entry, suggested_term_numbers: [...entry.suggested_term_numbers] })) : [];
}

function findBachelorCatalogEntry(sourceKey, sourceCode) {
  const normalizedSourceCode = cleanText(sourceCode, 80);
  return listBachelorCatalogEntries(sourceKey).find((entry) => entry.source_code === normalizedSourceCode) || null;
}

module.exports = {
  DEFAULT_BACHELOR_CATALOG_SOURCE_KEY,
  DEFAULT_BACHELOR_CATALOG_GROUP_COUNT,
  DEFAULT_BACHELOR_CATALOG_FLAGS,
  buildMinorCourseworkTemplateName,
  findBachelorCatalogEntry,
  getBachelorCatalogSource,
  isBachelorCatalogContainerTitle,
  listBachelorCatalogEntries,
  listBachelorCatalogSources,
  mapBachelorSemesterColumnToStageTerm,
  normalizeBachelorCatalogEntry,
  normalizeBachelorCatalogGroupCount,
  normalizeBachelorCatalogSourceKey: normalizeSourceKey,
};
