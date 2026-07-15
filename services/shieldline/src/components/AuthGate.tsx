import { createContext, useCallback, useContext, useEffect, useRef, useState, type ClipboardEvent, type KeyboardEvent, type ReactNode } from "react";
import { AlertTriangle, Check, ChevronRight, FileText, LoaderCircle, LockKeyhole, Radio, RotateCcw, ShieldCheck, UserRound } from "lucide-react";
import { authApi, type AuthBootstrap, type AuthProfile } from "../data/authApi";

type AuthContextValue = {
  profile: AuthProfile;
  bootstrap: AuthBootstrap;
  refresh: () => Promise<void>;
  setProfile: (profile: AuthProfile) => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthGate.");
  return value;
}

export function AuthGate({ children }: { children: ReactNode }) {
  const isAdminRoute = window.location.pathname.replace(/\/+$/, "").endsWith("/admin");
  const [bootstrap, setBootstrap] = useState<AuthBootstrap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(!isAdminRoute);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try { setBootstrap(await authApi.bootstrap()); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "ShieldLine зараз недоступний."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { if (!isAdminRoute) void refresh(); }, [isAdminRoute, refresh]);
  if (isAdminRoute) return children;
  if (loading) return <AuthLoading />;
  if (error || !bootstrap) return <AuthOffline message={error || "Не вдалося завантажити профіль."} onRetry={refresh} />;

  const forcePreview = !bootstrap.authRequired && new URLSearchParams(window.location.search).get("onboarding") === "1";
  if (bootstrap.status === "onboarding_required" || forcePreview) {
    return <Onboarding bootstrap={bootstrap} onAuthenticated={(profile) => {
      const url = new URL(window.location.href);
      url.searchParams.delete("onboarding");
      window.history.replaceState({}, "", url);
      setBootstrap((current) => current ? { ...current, status: "authenticated", user: profile } : current);
    }} />;
  }

  return <AuthContext.Provider value={{ profile: bootstrap.user, bootstrap, refresh, setProfile: (profile) => setBootstrap((current) => current ? { ...current, user: profile } : current) }}>{children}</AuthContext.Provider>;
}

function AuthLoading() {
  return <main className="auth-shell auth-shell--center"><section className="auth-loading" aria-live="polite"><span className="auth-orbit"><Radio size={28} /></span><strong>Встановлюємо захищений зв’язок</strong><small>Перевіряємо цей пристрій…</small></section></main>;
}

function AuthOffline({ message, onRetry }: { message: string; onRetry: () => Promise<void> }) {
  return <main className="auth-shell auth-shell--center"><section className="auth-card auth-offline"><AlertTriangle size={28} /><h1>Немає зв’язку</h1><p>{message}</p><button className="auth-primary" type="button" onClick={() => void onRetry()}><RotateCcw size={17} /> Спробувати ще раз</button></section></main>;
}

function Onboarding({ bootstrap, onAuthenticated }: { bootstrap: AuthBootstrap; onAuthenticated: (profile: AuthProfile) => void }) {
  const suggestedNickname = bootstrap.telegramPrefill?.username || [bootstrap.telegramPrefill?.firstName, bootstrap.telegramPrefill?.lastName].filter(Boolean).join(" ") || "";
  const [tab, setTab] = useState<"register" | "code">(bootstrap.telegramConflict ? "code" : "register");
  const [nickname, setNickname] = useState(suggestedNickname);
  const [available, setAvailable] = useState<boolean | null>(null);
  const [checking, setChecking] = useState(false);
  const [consent, setConsent] = useState(false);
  const [legalOpen, setLegalOpen] = useState(false);
  const [code, setCode] = useState<string[]>(() => Array(6).fill(""));
  const codeRefs = useRef<Array<HTMLInputElement | null>>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const clean = nickname.trim();
    setAvailable(null);
    if (clean.length < 3 || clean.length > 24) return undefined;
    setChecking(true);
    const timer = window.setTimeout(() => {
      void authApi.nicknameAvailability(clean).then((result) => setAvailable(result.available)).catch(() => setAvailable(null)).finally(() => setChecking(false));
    }, 350);
    return () => { window.clearTimeout(timer); setChecking(false); };
  }, [nickname]);

  const submitRegistration = async () => {
    if (!consent || available !== true) return;
    setBusy(true); setError(null);
    try { onAuthenticated((await authApi.register(nickname.trim(), bootstrap.consentVersion)).user); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Не вдалося завершити реєстрацію."); }
    finally { setBusy(false); }
  };

  const submitCode = async () => {
    if (code.some((digit) => !digit)) return;
    setBusy(true); setError(null);
    try { onAuthenticated((await authApi.redeemTransferCode(code.join(""))).user); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Не вдалося виконати вхід."); }
    finally { setBusy(false); }
  };

  const setCodeDigit = (index: number, value: string) => {
    const digit = value.replace(/\D/g, "").slice(-1);
    setCode((current) => current.map((entry, position) => position === index ? digit : entry));
    if (digit && index < 5) codeRefs.current[index + 1]?.focus();
  };

  const handleCodeKey = (index: number, event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Backspace" && !code[index] && index > 0) codeRefs.current[index - 1]?.focus();
    if (event.key === "ArrowLeft" && index > 0) codeRefs.current[index - 1]?.focus();
    if (event.key === "ArrowRight" && index < 5) codeRefs.current[index + 1]?.focus();
  };

  const pasteCode = (event: ClipboardEvent<HTMLDivElement>) => {
    const digits = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6).split("");
    if (!digits.length) return;
    event.preventDefault();
    setCode(Array.from({ length: 6 }, (_, index) => digits[index] || ""));
    codeRefs.current[Math.min(digits.length, 6) - 1]?.focus();
  };

  return <main className="auth-shell">
    <section className="auth-card auth-onboarding" aria-label="Реєстрація ShieldLine">
      <header className="auth-brand"><span><ShieldCheck size={26} /></span><div><strong>ShieldLine</strong><small>COMMAND NETWORK</small></div></header>
      <div className="auth-intro"><span className="auth-kicker"><Radio size={14} /> ПЕРШИЙ ВИХІД НА ЗВ’ЯЗОК</span><h1>Створіть позивний</h1><p>Один унікальний нікнейм працюватиме на всіх ваших пристроях і показуватиметься в рейтингах.</p></div>
      <div className="auth-tabs" role="tablist"><button type="button" role="tab" aria-selected={tab === "register"} onClick={() => { setTab("register"); setError(null); }}>Реєстрація</button><button type="button" role="tab" aria-selected={tab === "code"} onClick={() => { setTab("code"); setError(null); }}>Вхід за кодом</button></div>
      {tab === "register" ? <div className="auth-form">
        <label className="auth-field"><span>Нікнейм</span><div><UserRound size={17} /><input autoFocus value={nickname} maxLength={24} onChange={(event) => setNickname(event.target.value)} placeholder="Наприклад, Sokil_01" autoComplete="nickname" /></div><small className={available === false ? "auth-field__error" : available ? "auth-field__ok" : ""}>{checking ? "Перевіряємо доступність…" : available === true ? "Нікнейм вільний" : available === false ? "Цей нікнейм уже зайнятий" : "3–24 символи: літери, цифри, пробіл, . _ -"}</small></label>
        {bootstrap.telegramPrefill ? <div className="auth-telegram-hint"><Radio size={17} /><span><strong>Telegram розпізнано</strong><small>{bootstrap.telegramPrefill.username ? `@${bootstrap.telegramPrefill.username}` : suggestedNickname}</small></span><Check size={16} /></div> : null}
        <label className="auth-consent"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><i><Check size={13} /></i><span>Я приймаю <button type="button" onClick={(event) => { event.preventDefault(); setLegalOpen(true); }}>умови використання ShieldLine та погоджуюся на обробку персональних даних</button>.</span></label>
        {error ? <p className="auth-error" role="alert">{error}</p> : null}
        <button className="auth-primary" type="button" disabled={!consent || available !== true || busy} onClick={() => void submitRegistration()}>{busy ? <LoaderCircle className="auth-spin" size={18} /> : <LockKeyhole size={18} />} Створити профіль <ChevronRight size={17} /></button>
      </div> : <div className="auth-form auth-code-form">
        <div className="auth-code-icon"><LockKeyhole size={24} /></div><h2>Введіть код з іншого пристрою</h2><p>У відкритому профілі натисніть «Додати інший пристрій». Код діє 5 хвилин і лише один раз.</p>
        <div className="auth-code-input" role="group" aria-label="Шестизначний код" onPaste={pasteCode}>{code.map((digit, index) => <input key={index} ref={(element) => { codeRefs.current[index] = element; }} autoFocus={index === 0} aria-label={`Цифра ${index + 1}`} inputMode="numeric" autoComplete={index === 0 ? "one-time-code" : "off"} value={digit} maxLength={1} onChange={(event) => setCodeDigit(index, event.target.value)} onKeyDown={(event) => handleCodeKey(index, event)} />)}</div>
        {error ? <p className="auth-error" role="alert">{error}</p> : null}
        <button className="auth-primary" type="button" disabled={code.some((digit) => !digit) || busy} onClick={() => void submitCode()}>{busy ? <LoaderCircle className="auth-spin" size={18} /> : <LockKeyhole size={18} />} Увійти на цьому пристрої</button>
      </div>}
      <footer className="auth-security"><LockKeyhole size={13} /> Прив’язка зберігається локально на цьому пристрої</footer>
    </section>
    {legalOpen ? <LegalDialog version={bootstrap.consentVersion} onClose={() => setLegalOpen(false)} /> : null}
  </main>;
}

function LegalDialog({ version, onClose }: { version: string; onClose: () => void }) {
  return <div className="auth-modal" role="dialog" aria-modal="true" aria-label="Умови використання"><section className="auth-legal"><header><FileText size={21} /><div><strong>Умови ShieldLine</strong><small>Редакція {version}</small></div></header><div><h2>Використання сервісу</h2><p>ShieldLine є ігровою симуляцією. Дані, події та підказки не є джерелом реальної оперативної інформації.</p><h2>Дані профілю</h2><p>Ми зберігаємо нікнейм, технічний ідентифікатор пристрою у вигляді захищеного хешу, час прийняття умов та, після вашої явної дії, ідентифікатор і публічні дані Telegram.</p><h2>Мета і строк зберігання</h2><p>Дані потрібні для входу, синхронізації прогресу, рейтингу й безпеки акаунта та зберігаються, доки профіль використовується або цього вимагають обґрунтовані технічні й правові потреби.</p><h2>Безпека й відповідальність</h2><p>Не передавайте коди входу стороннім особам. Один код діє п’ять хвилин і може бути використаний лише один раз.</p><h2>Ваші права</h2><p>Ви можете просити уточнити, виправити або видалити свої дані та отримати пояснення щодо їх обробки.</p><h2>Звернення щодо даних</h2><p>Зверніться до адміністрації ShieldLine через офіційний канал, у якому ви отримали доступ до гри. Активний контакт на цьому екрані поки не публікується.</p></div><button className="auth-primary" type="button" onClick={onClose}>Зрозуміло</button></section></div>;
}
