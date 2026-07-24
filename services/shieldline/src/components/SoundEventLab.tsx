import { useMemo, useState } from "react";
import { ArrowLeft, Headphones, Pause, Play, RotateCcw, Volume2, VolumeX } from "lucide-react";
import { previewSound, shieldlineAudio } from "../audio/audioEngine";
import { soundCueDefinitions, type SoundCue } from "../audio/soundCues";
import { createScenarioState } from "../game/initialState";
import { getUnitDefinition } from "../data/units";
import { readAudioPreferences, writeAudioPreferences } from "../platform/audioPreferences";
import type {
  CityAlertState,
  DefenseBattery,
  EngagementEvent,
  EngagementResult,
  GameState,
  ImpactMarker,
  LiveThreat,
  MapMode,
  ShotStyle,
  ThreatKind,
  UnitKind,
} from "../types/game";
import { TacticalMap } from "./TacticalMap";

interface SoundLabItem {
  cue: SoundCue;
  label: string;
  context: string;
}

interface SoundLabGroup {
  title: string;
  summary: string;
  items: SoundLabItem[];
}

export const soundEventLabGroups: SoundLabGroup[] = [
  {
    title: "Інтерфейс",
    summary: "Базові дії в меню й панелях.",
    items: [
      { cue: "ui.open", label: "Відкрити панель", context: "Відкриття меню, профілю або налаштувань." },
      { cue: "ui.close", label: "Закрити панель", context: "Закриття модалки або бічної панелі." },
      { cue: "ui.select", label: "Звичайний клік", context: "Вибір кнопки чи вкладки без окремого cue." },
      { cue: "ui.confirm", label: "Підтвердження", context: "Успішне підтвердження важливої UI-дії." },
      { cue: "ui.cancel", label: "Скасування", context: "Скасування режиму або повернення назад." },
      { cue: "ui.error", label: "Помилка", context: "Команда відхилена або недоступна." },
    ],
  },
  {
    title: "Розміщення та план",
    summary: "ППО, передислокація, сервіс і доктрина.",
    items: [
      { cue: "placement.select", label: "Вибір ППО", context: "Одиницю вибрано для розміщення." },
      { cue: "placement.success", label: "ППО розміщено", context: "Успішне встановлення системи на карту." },
      { cue: "placement.failure", label: "Розміщення відхилено", context: "Точка заборонена або ресурсів недостатньо." },
      { cue: "placement.redeploy", label: "Передислокація", context: "Зняття зі позиції або повернення зі складу." },
      { cue: "placement.service", label: "Сервіс ППО", context: "Поповнення БК або ремонт між місіями." },
      { cue: "planning.toggle", label: "Зміна плану", context: "Перемикач доктрини чи планувальної дії." },
    ],
  },
  {
    title: "Хід операції",
    summary: "Старт, пауза, відновлення й завершення.",
    items: [
      { cue: "operation.countdown", label: "Відлік", context: "Перед запуском бойової симуляції." },
      { cue: "operation.start", label: "Операція почалась", context: "Перехід від відліку до активної фази." },
      { cue: "operation.pause", label: "Пауза", context: "Симуляцію призупинено." },
      { cue: "operation.resume", label: "Продовжити", context: "Симуляцію відновлено після паузи." },
      { cue: "operation.complete", label: "Операція завершена", context: "Бойовий цикл закінчився перед звітом." },
    ],
  },
  {
    title: "Пуски та тривога",
    summary: "Усі production-варіанти попереджень і запусків.",
    items: [
      { cue: "alert.prelaunch", label: "Підготовка пуску", context: "Активність у секторі до появи цілі." },
      { cue: "alert.launch.drone", label: "Пуск БПЛА", context: "Поява ударного дрона на маршруті." },
      { cue: "alert.launch.cruise", label: "Пуск крилатої ракети", context: "Крилата ціль входить у повітряний простір." },
      { cue: "alert.launch.ballistic", label: "Балістичний пуск", context: "Критичне попередження про балістичну ціль." },
      { cue: "alert.air-raid", label: "Повітряна тривога", context: "Глобальна ескалація для міст під загрозою." },
      { cue: "alert.clear", label: "Відбій тривоги", context: "Міста повертаються до спокійного стану." },
    ],
  },
  {
    title: "Контакти та бій",
    summary: "Супровід цілей і всі способи відпрацювання.",
    items: [
      { cue: "contact.detected", label: "Контакт виявлено", context: "Низька достовірність, ціль ще не класифікована." },
      { cue: "contact.classified", label: "Ціль класифіковано", context: "Підтверджено тип і маршрут цілі." },
      { cue: "contact.lost", label: "Супровід втрачено", context: "Маршрут стає непевним." },
      { cue: "engagement.radar", label: "Радарний супровід", context: "Сенсор бере контакт у роботу." },
      { cue: "engagement.gun", label: "Гарматна черга", context: "Мобільна вогнева група стріляє по дрону." },
      { cue: "engagement.missile", label: "Пуск перехоплювача", context: "Ракетна система відпрацьовує по цілі." },
      { cue: "engagement.ew", label: "РЕБ", context: "Радіоелектронне придушення каналу наведення." },
      { cue: "engagement.drone", label: "Дрон-перехоплювач", context: "Операторський підрозділ запускає перехоплювач." },
      { cue: "engagement.reload", label: "Перезарядження", context: "Магазин поповнюється із запасу місії." },
    ],
  },
  {
    title: "Результати",
    summary: "Успіхи, промахи, влучання та фінали місій.",
    items: [
      { cue: "result.intercept", label: "Ціль збито", context: "Кінетичне перехоплення успішне." },
      { cue: "result.soft-kill", label: "М'яке придушення", context: "РЕБ відвела або зірвала ціль без збиття." },
      { cue: "result.miss", label: "Промах", context: "Перехоплювач не вразив ціль." },
      { cue: "result.impact", label: "Влучання", context: "Неперехоплена ціль уразила місто." },
      { cue: "result.mission-success", label: "Місію виконано", context: "Позитивний підсумок окремої місії." },
      { cue: "result.mission-failure", label: "Місію провалено", context: "Критичний негативний підсумок." },
      { cue: "result.campaign-complete", label: "Кампанію завершено", context: "Фінальне успішне завершення кампанії." },
    ],
  },
];

const threatLabels: Record<ThreatKind, string> = {
  drone: "БПЛА",
  ballistic: "Балістична ціль",
  cruise: "Крилата ракета",
  decoy: "Хибна ціль",
  combined: "Комбінована ціль",
  saturation: "Група БПЛА",
  geran2: "Geran-2",
  gerbera: "Gerbera",
  parodiya: "Parodiya",
  kh101: "X-101",
  kalibr: "Kalibr",
  iskander: "Iskander-M",
  recon: "Розвідувальний БПЛА",
  "low-signature-cruise": "Малопомітна крилата ціль",
  jammer: "Постановник перешкод",
};

const batteryPositions: Partial<Record<UnitKind, { lat: number; lng: number }>> = {
  radar: { lat: 49.35, lng: 30.15 },
  mvg: { lat: 48.8, lng: 32.7 },
  patriot: { lat: 49.15, lng: 31.05 },
  ew: { lat: 49.05, lng: 29.55 },
  "drone-operators": { lat: 49.4, lng: 32.25 },
};

function battery(kind: UnitKind, sequence: number, overrides: Partial<DefenseBattery> = {}): DefenseBattery {
  const definition = getUnitDefinition(kind);
  const position = batteryPositions[kind] || { lat: 49, lng: 31 };
  return {
    id: `lab-battery-${kind}-${sequence}`,
    kind,
    coverageTier: definition.outerRangeKm >= 75 ? "III" : definition.outerRangeKm >= 35 ? "II" : "I",
    coverageRadius: Math.max(.1, definition.outerRangeKm / 85),
    readiness: definition.readiness,
    fatigue: 8,
    daysSinceMaintenance: 0,
    lastAction: "sound lab",
    lastEngagementResult: "готова до тесту",
    status: "ready",
    supplyStatus: "well-supplied",
    cooldownMs: 0,
    reloadRemainingMs: 0,
    currentAmmo: definition.ammoCapacity,
    missionReserve: definition.missionReserveCapacity,
    manualOverrideTargets: [],
    assignedCityId: "kyiv",
    health: 100,
    experienceLevel: 1,
    createdAtMission: 1,
    lastMovedMission: 1,
    ...overrides,
    position: overrides.position || position,
  };
}

function threat(kind: ThreatKind, sequence: number, overrides: Partial<LiveThreat> = {}): LiveThreat {
  const ballistic = kind === "ballistic" || kind === "iskander";
  const drone = ["drone", "saturation", "geran2", "gerbera", "parodiya", "recon"].includes(kind);
  return {
    id: `lab-threat-${sequence}`,
    kind,
    status: "inbound",
    origin: { lat: 49.35, lng: 37.75 },
    target: { lat: 50.4501, lng: 30.5234 },
    targetCityId: "kyiv",
    launchSectorId: `lab-sector-${sequence}`,
    launchSectorName: "Східний тестовий сектор",
    progress: .14,
    speed: 1 / 11_000,
    speedKph: ballistic ? 3_200 : drone ? 185 : 780,
    altitudeM: ballistic ? 28_000 : drone ? 160 : 120,
    difficulty: ballistic ? 70 : 38,
    damage: ballistic ? 18 : 7,
    confidence: 92,
    classification: "confirmed-type",
    displayLabel: threatLabels[kind],
    saturation: kind === "saturation" ? 5 : 1,
    headingDeg: 276,
    revealed: true,
    trackQuality: 88,
    fireControlQuality: 82,
    speedModifier: 1,
    damageModifier: 1,
    reward: ballistic ? 12 : 4,
    routeWaypoints: [
      { lat: 49.35, lng: 37.75 },
      { lat: 49.1, lng: 34.9 },
      { lat: 49.65, lng: 32.55 },
      { lat: 50.4501, lng: 30.5234 },
    ],
    ...overrides,
  };
}

function impact(sequence: number, tone: ImpactMarker["tone"], position = { lat: 50.2, lng: 31.25 }): ImpactMarker {
  return { id: `lab-impact-${tone}-${sequence}`, position, tone, ttlMs: 12_000 };
}

function engagement(
  style: ShotStyle | "radar",
  result: EngagementResult,
  targetId: string,
  sequence: number,
): EngagementEvent {
  const unitType: UnitKind = style === "radar" ? "radar" : style === "gun" ? "mvg" : style === "ew" ? "ew" : style === "drone" ? "drone-operators" : "patriot";
  const startPosition = batteryPositions[unitType] || { lat: 49.15, lng: 31.05 };
  return {
    id: `lab-engagement-${style}-${sequence}`,
    unitId: `lab-battery-${unitType}-${sequence}`,
    targetId,
    unitType,
    startPosition,
    targetStartPosition: { lat: 49.5, lng: 33.6 },
    targetPredictedPosition: { lat: 49.72, lng: 32.3 },
    result,
    startedAtMs: 0,
    durationMs: style === "radar" ? 1_300 : 2_400,
    progress: 0,
    resolved: false,
    style,
  };
}

function baseScene(sequence: number) {
  const game = createScenarioState(() => .42, "sandbox", "decoy-storm");
  game.elapsedMs = sequence;
  game.log = [];
  game.liveThreats = [];
  game.engagementEvents = [];
  game.impactMarkers = [];
  game.carriers = [];
  game.launchSectors = [];
  game.batteries = [
    battery("radar", sequence),
    battery("mvg", sequence),
    battery("patriot", sequence),
    battery("ew", sequence),
    battery("drone-operators", sequence),
  ];
  game.cities = game.cities.map((city) => ({ ...city, alertState: "calm" }));
  return game;
}

function setCityAlert(game: GameState, alertState: CityAlertState, infrastructure = 88) {
  game.cities = game.cities.map((city) => city.id === "kyiv" ? { ...city, alertState, infrastructure } : city);
}

function setLaunchScene(game: GameState, kind: ThreatKind, sequence: number, state: "warning" | "launching" | "cooldown" = "launching") {
  const activeThreat = threat(kind, sequence);
  game.launchSectors = [{
    id: activeThreat.launchSectorId,
    name: activeThreat.launchSectorName,
    lat: 49.35,
    lng: 37.75,
    radiusKm: 18,
    weight: 1,
    threats: kind === "iskander" || kind === "ballistic" ? ["iskander_m"] : kind === "kh101" || kind === "cruise" ? ["kh101"] : ["shahed"],
    role: "тест production-пуску",
    state,
    activeThreatKind: kind,
    lastLaunchCoordinates: state === "warning" ? undefined : activeThreat.origin,
  }];
  if (state === "launching") game.liveThreats = [activeThreat];
  return activeThreat;
}

function setEngagementScene(game: GameState, style: ShotStyle | "radar", result: EngagementResult, sequence: number) {
  const kind: ThreatKind = style === "gun" || style === "drone" || style === "ew" ? "geran2" : "kh101";
  const activeThreat = threat(kind, sequence, { progress: .58, speed: 0, status: "engaged" });
  game.liveThreats = [activeThreat];
  game.engagementEvents = [engagement(style, result, activeThreat.id, sequence)];
  game.batteries = [battery(style === "radar" ? "radar" : style === "gun" ? "mvg" : style === "ew" ? "ew" : style === "drone" ? "drone-operators" : "patriot", sequence, { status: "engaging" })];
  return activeThreat;
}

function sceneForCue(cue: SoundCue, sequence: number): { game: GameState; mapMode: MapMode; note: string } {
  const game = baseScene(sequence);
  let mapMode: MapMode = "live";
  let note = "Оновлено бойову карту й контекст події.";

  if (cue === "ui.open") {
    mapMode = "coverage";
    note = "Відкрито шар покриття ППО.";
  } else if (cue === "ui.close") {
    game.batteries = [];
    note = "Панель і тактичні шари закрито.";
  } else if (cue === "ui.select") {
    mapMode = "threats";
    game.liveThreats = [threat("recon", sequence, { confidence: 38, classification: "probable-class", displayLabel: "Непевний контакт" })];
    note = "Вибрано шар загроз.";
  } else if (cue === "ui.confirm") {
    game.impactMarkers = [impact(sequence, "intercept")];
    note = "Команду підтверджено на карті.";
  } else if (cue === "ui.cancel") {
    setLaunchScene(game, "geran2", sequence, "cooldown");
    note = "Поточну карту дії скасовано.";
  } else if (cue === "ui.error") {
    mapMode = "coverage";
    game.batteries = [battery("patriot", sequence, { currentAmmo: 0, lastEngagementResult: "команда недоступна" })];
    note = "На карті показано недоступну систему.";
  } else if (cue === "placement.select") {
    mapMode = "coverage";
    game.batteries = [battery("nasams", sequence, { position: { lat: 49.25, lng: 31.6 } })];
    note = "NASAMS вибрано для розміщення.";
  } else if (cue === "placement.success") {
    mapMode = "coverage";
    game.batteries = [battery("patriot", sequence, { position: { lat: 49.4, lng: 31.55 }, lastAction: "щойно розміщено" })];
    note = "Нову позицію ППО додано на карту.";
  } else if (cue === "placement.failure") {
    mapMode = "coverage";
    game.batteries = [battery("patriot", sequence, { currentAmmo: 0, position: { lat: 50.38, lng: 30.5 }, lastEngagementResult: "розміщення відхилено" })];
    note = "Відхилену позицію позначено недоступним станом.";
  } else if (cue === "placement.redeploy") {
    mapMode = "coverage";
    game.batteries = [battery("iris-t", sequence, { status: "redeploying", position: { lat: 48.95, lng: 33.25 }, lastAction: "передислокація" })];
    note = "Одиницю перенесено до нової позиції.";
  } else if (cue === "placement.service") {
    mapMode = "coverage";
    game.batteries = [battery("s300", sequence, { status: "maintenance", readiness: 62, health: 74, lastAction: "сервіс" })];
    note = "Система перейшла в технічне обслуговування.";
  } else if (cue === "planning.toggle") {
    mapMode = "logistics";
    note = "Увімкнено логістичний шар планування.";
  } else if (cue === "operation.countdown" || cue === "alert.prelaunch") {
    setLaunchScene(game, "geran2", sequence, "warning");
    note = "Пусковий сектор перейшов у попередження.";
  } else if (cue === "operation.start") {
    setLaunchScene(game, "cruise", sequence);
    note = "Операція стартувала з активним маршрутом.";
  } else if (cue === "operation.pause") {
    game.liveThreats = [threat("kh101", sequence, { progress: .48, speed: 0 })];
    note = "Рух контакту поставлено на паузу.";
  } else if (cue === "operation.resume") {
    setEngagementScene(game, "missile", "success", sequence);
    note = "Рух і бойове відпрацювання відновлено.";
  } else if (cue === "operation.complete") {
    game.impactMarkers = [impact(sequence, "intercept"), impact(sequence + 1, "impact", { lat: 48.9, lng: 33.2 })];
    note = "На карті залишено підсумкові бойові маркери.";
  } else if (cue === "alert.launch.drone") {
    setLaunchScene(game, "geran2", sequence);
    note = "На маршруті з'явився Geran-2.";
  } else if (cue === "alert.launch.cruise") {
    setLaunchScene(game, "kh101", sequence);
    note = "На маршруті з'явилась крилата ракета.";
  } else if (cue === "alert.launch.ballistic") {
    setLaunchScene(game, "iskander", sequence);
    note = "На карті показано балістичний пуск.";
  } else if (cue === "alert.air-raid") {
    setCityAlert(game, "air-raid");
    setLaunchScene(game, "iskander", sequence);
    note = "Київ переведено у стан повітряної тривоги.";
  } else if (cue === "alert.clear") {
    setCityAlert(game, "calm");
    game.impactMarkers = [impact(sequence, "intercept")];
    note = "Місто повернуто до спокійного стану.";
  } else if (cue === "contact.detected") {
    mapMode = "threats";
    game.liveThreats = [threat("geran2", sequence, { confidence: 28, classification: "unknown", displayLabel: "Невідомий контакт", trackQuality: 34 })];
    note = "Показано первинний невідомий контакт.";
  } else if (cue === "contact.classified") {
    mapMode = "threats";
    game.liveThreats = [threat("geran2", sequence)];
    note = "Контакт підтверджено як Geran-2.";
  } else if (cue === "contact.lost") {
    mapMode = "threats";
    game.liveThreats = [threat("kh101", sequence, { confidence: 42, classification: "probable-class", displayLabel: "Супровід втрачено", trackQuality: 18 })];
    note = "Маршрут контакту став прогнозованим.";
  } else if (cue === "engagement.radar") {
    setEngagementScene(game, "radar", "detected", sequence);
    note = "Радар виконує production-анімацію супроводу.";
  } else if (cue === "engagement.gun") {
    setEngagementScene(game, "gun", "success", sequence);
    note = "МВГ веде гарматний вогонь по дрону.";
  } else if (cue === "engagement.missile") {
    setEngagementScene(game, "missile", "success", sequence);
    note = "Ракетний перехоплювач рухається до цілі.";
  } else if (cue === "engagement.ew") {
    setEngagementScene(game, "ew", "soft-kill", sequence);
    note = "РЕБ виконує придушення цілі.";
  } else if (cue === "engagement.drone") {
    setEngagementScene(game, "drone", "success", sequence);
    note = "Дрон-перехоплювач рухається до цілі.";
  } else if (cue === "engagement.reload") {
    mapMode = "coverage";
    game.batteries = [battery("mvg", sequence, { status: "reloading", currentAmmo: 0, reloadRemainingMs: 5_000, lastAction: "перезарядження" })];
    note = "МВГ показано у стані перезарядження.";
  } else if (cue === "result.intercept") {
    const activeThreat = setEngagementScene(game, "missile", "success", sequence);
    activeThreat.status = "intercepted";
    game.impactMarkers = [impact(sequence, "intercept", { lat: 49.72, lng: 32.3 })];
    note = "Ціль збито, на карті з'явився маркер перехоплення.";
  } else if (cue === "result.soft-kill") {
    const activeThreat = setEngagementScene(game, "ew", "soft-kill", sequence);
    activeThreat.status = "intercepted";
    activeThreat.softKillEffect = "guidance-lost";
    note = "Ціль нейтралізовано м'яким придушенням.";
  } else if (cue === "result.miss") {
    setEngagementScene(game, "missile", "miss", sequence);
    note = "Анімація завершується позначкою MISS.";
  } else if (cue === "result.impact") {
    const activeThreat = threat("iskander", sequence, { progress: .96, speed: 0, status: "impact" });
    game.liveThreats = [activeThreat];
    game.impactMarkers = [impact(sequence, "impact", { lat: 50.4501, lng: 30.5234 })];
    setCityAlert(game, "air-raid", 72);
    note = "На Києві показано production-маркер влучання.";
  } else if (cue === "result.mission-success") {
    game.impactMarkers = [impact(sequence, "intercept"), impact(sequence + 1, "intercept", { lat: 49.15, lng: 33.25 })];
    note = "Карта показує успішно завершену місію.";
  } else if (cue === "result.mission-failure") {
    setCityAlert(game, "air-raid", 58);
    game.impactMarkers = [impact(sequence, "impact", { lat: 50.4501, lng: 30.5234 }), impact(sequence + 1, "impact", { lat: 48.4647, lng: 35.0462 })];
    note = "Карта показує критичний підсумок місії.";
  } else if (cue === "result.campaign-complete") {
    game.impactMarkers = [
      impact(sequence, "intercept"),
      impact(sequence + 1, "intercept", { lat: 49.15, lng: 33.25 }),
      impact(sequence + 2, "intercept", { lat: 48.2, lng: 30.45 }),
    ];
    note = "На карті показано фінальний успіх кампанії.";
  }

  return { game, mapMode, note };
}

function sourceNames(cue: SoundCue) {
  return [...new Set(soundCueDefinitions[cue].variants.map((variant) => variant.file.replace("audio/sfx/", "").replace(".mp3", "")))].join(" · ");
}

export function SoundEventLab() {
  const [sequence, setSequence] = useState(1);
  const [activeCue, setActiveCue] = useState<SoundCue>("alert.launch.drone");
  const [scene, setScene] = useState(() => sceneForCue("alert.launch.drone", 1));
  const [audioPreferences, setAudioPreferences] = useState(readAudioPreferences);
  const [playState, setPlayState] = useState<"idle" | "playing" | "muted" | "failed">("idle");
  const allCueCount = useMemo(() => soundEventLabGroups.reduce((total, group) => total + group.items.length, 0), []);

  const trigger = async (cue: SoundCue) => {
    const nextSequence = sequence + 1;
    setSequence(nextSequence);
    setActiveCue(cue);
    setScene(sceneForCue(cue, nextSequence));
    setPlayState("playing");
    const played = await previewSound(cue);
    setPlayState(played ? "playing" : audioPreferences.enabled ? "failed" : "muted");
  };

  const toggleAudio = async () => {
    const next = { ...audioPreferences, enabled: !audioPreferences.enabled };
    setAudioPreferences(next);
    writeAudioPreferences(next);
    shieldlineAudio.setPreferences(next);
    if (next.enabled) await shieldlineAudio.unlock();
    else shieldlineAudio.stopAll();
    setPlayState(next.enabled ? "idle" : "muted");
  };

  const reset = () => {
    const nextSequence = sequence + 1;
    setSequence(nextSequence);
    setActiveCue("alert.launch.drone");
    setScene(sceneForCue("alert.launch.drone", nextSequence));
    setPlayState("idle");
    shieldlineAudio.stopAll();
  };

  const leave = () => {
    shieldlineAudio.stopAll();
    const url = new URL(window.location.href);
    url.searchParams.delete("soundLab");
    window.location.assign(url.toString());
  };

  const definition = soundCueDefinitions[activeCue];
  return (
    <main className="sound-event-lab" data-audio-scope="player" aria-label="Полігон звуку та бойових подій Shieldline">
      <header className="sound-event-lab__header">
        <button type="button" className="icon-action" data-sound="none" onClick={leave} aria-label="Повернутися до Shieldline"><ArrowLeft size={19} /></button>
        <div>
          <span><Headphones size={15} /> Службовий тестовий режим</span>
          <strong>Звук + подія</strong>
          <small>{allCueCount} production-cue · реальна тактична карта</small>
        </div>
        <button type="button" className={`sound-lab-audio-toggle ${audioPreferences.enabled ? "is-on" : ""}`} data-sound="none" onClick={toggleAudio}>
          {audioPreferences.enabled ? <Volume2 size={17} /> : <VolumeX size={17} />}
          <span>{audioPreferences.enabled ? "Звук увімкнено" : "Увімкнути звук"}</span>
        </button>
        <button type="button" className="icon-action" data-sound="none" onClick={reset} aria-label="Скинути полігон"><RotateCcw size={18} /></button>
      </header>

      <section className="sound-event-lab__workspace">
        <aside className="sound-event-lab__menu" aria-label="Каталог звуків і подій">
          <div className="sound-event-lab__intro">
            <h1>Усі звукові ситуації</h1>
            <p>Кожна кнопка запускає поточний production-cue та відповідну сцену на карті. Повторний клік перезапускає звук без очікування cooldown.</p>
          </div>
          {soundEventLabGroups.map((group) => (
            <section className="sound-lab-group" key={group.title}>
              <header><strong>{group.title}</strong><span>{group.items.length}</span><small>{group.summary}</small></header>
              <div>
                {group.items.map((item) => {
                  const cueDefinition = soundCueDefinitions[item.cue];
                  return (
                    <button
                      type="button"
                      className={activeCue === item.cue ? "is-active" : ""}
                      data-sound="none"
                      key={item.cue}
                      onClick={() => void trigger(item.cue)}
                      aria-pressed={activeCue === item.cue}
                    >
                      <span className={`sound-lab-priority sound-lab-priority--${cueDefinition.priority}`}>{activeCue === item.cue ? <Pause size={12} /> : <Play size={12} />}</span>
                      <span><strong>{item.label}</strong><small>{item.context}</small><code>{item.cue}</code></span>
                      <em>{cueDefinition.variants.length}×</em>
                    </button>
                  );
                })}
              </div>
            </section>
          ))}
        </aside>

        <section className="sound-event-lab__stage" aria-label="Тактична візуалізація звукової події">
          <TacticalMap gameOverride={scene.game} mapModeOverride={scene.mapMode} readOnly />
          <div className={`sound-lab-event-card sound-lab-event-card--${definition.priority}`} key={`${activeCue}-${sequence}`}>
            <span>{definition.category === "critical" ? "КРИТИЧНИЙ CUE" : definition.category === "combat" ? "БОЙОВИЙ CUE" : "UI CUE"}</span>
            <strong>{soundEventLabGroups.flatMap((group) => group.items).find((item) => item.cue === activeCue)?.label}</strong>
            <code>{activeCue}</code>
            <p>{scene.note}</p>
            <small>Джерело: {sourceNames(activeCue)} · {definition.variants.length} вар. · cooldown {definition.cooldownMs} мс</small>
          </div>
          <div className={`sound-lab-playback sound-lab-playback--${playState}`}>
            {playState === "muted" ? <VolumeX size={14} /> : playState === "failed" ? <VolumeX size={14} /> : <Volume2 size={14} />}
            {playState === "muted" ? "Карта оновлена · звук вимкнений" : playState === "failed" ? "Карта оновлена · аудіо не запустилось" : playState === "idle" ? "Готово до відтворення" : "Відтворено й показано на карті"}
          </div>
        </section>
      </section>
    </main>
  );
}
