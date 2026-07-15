import { useEffect, useState } from "react";
import { Check, Copy, Link2, LoaderCircle, Radio, ShieldCheck, Smartphone, UserRound, X } from "lucide-react";
import { authApi } from "../data/authApi";
import { useAuth } from "./AuthGate";

export function AccountSettings({ modal = false, onClose }: { modal?: boolean; onClose?: () => void }) {
  const { profile, bootstrap, setProfile } = useAuth();
  const [transfer, setTransfer] = useState<{ code: string; expiresAt: string } | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!transfer) return undefined;
    const update = () => setRemaining(Math.max(0, Math.ceil((new Date(transfer.expiresAt).getTime() - Date.now()) / 1000)));
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [transfer]);

  const generate = async () => {
    setBusy(true); setMessage(null); setCopied(false);
    try { setTransfer(await authApi.generateTransferCode()); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Не вдалося створити код."); }
    finally { setBusy(false); }
  };

  const copy = async () => {
    if (!transfer) return;
    await navigator.clipboard.writeText(transfer.code);
    setCopied(true);
  };

  const linkTelegram = async () => {
    setBusy(true); setMessage(null);
    try { setProfile((await authApi.linkTelegram()).user); setMessage("Telegram успішно прив’язано."); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Не вдалося прив’язати Telegram."); }
    finally { setBusy(false); }
  };

  const content = <section className={`account-card${modal ? " account-card--modal" : ""}`} aria-label="Профіль ShieldLine">
    <header className="account-header"><div><span><ShieldCheck size={20} /></span><div><small>ПРОФІЛЬ КОМАНДИРА</small><strong>{profile.nickname}</strong></div></div>{modal ? <button type="button" onClick={onClose} aria-label="Закрити профіль"><X size={19} /></button> : null}</header>
    <div className="account-summary"><span><UserRound size={21} /></span><div><strong>{profile.nickname}</strong><small>Унікальний нікнейм · активний</small></div><Check size={17} /></div>
    <div className="account-meta"><div><span>Telegram</span><strong>{profile.telegram ? (profile.telegram.username ? `@${profile.telegram.username}` : "Прив’язано") : "Не прив’язано"}</strong></div><div><span>Пристрої</span><strong>{profile.deviceCount}</strong></div></div>
    {!profile.telegram && bootstrap.telegramLinkOffer ? <button className="account-secondary" type="button" disabled={busy} onClick={() => void linkTelegram()}><Radio size={17} /> Прив’язати цей Telegram</button> : null}
    <section className="account-device"><div className="account-device__title"><Smartphone size={19} /><div><strong>Додати інший пристрій</strong><small>Поточний пристрій залишиться в системі</small></div></div>
      {transfer && remaining > 0 ? <div className="account-transfer"><button type="button" onClick={() => void copy()} aria-label="Копіювати код"><span>{transfer.code.slice(0, 3)}</span><span>{transfer.code.slice(3)}</span><Copy size={17} /></button><small>{copied ? "Код скопійовано" : `Діє ще ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`}</small></div> : <button className="account-secondary" type="button" disabled={busy} onClick={() => void generate()}>{busy ? <LoaderCircle className="auth-spin" size={17} /> : <Link2 size={17} />} Створити код входу</button>}
      {transfer && remaining > 0 ? <button className="account-link-button" type="button" disabled={busy} onClick={() => void generate()}>Створити новий код</button> : null}
    </section>
    {message ? <p className="account-message" role="status">{message}</p> : null}
    <footer><ShieldCheck size={13} /> Умови прийнято {profile.consentAcceptedAt ? new Date(profile.consentAcceptedAt).toLocaleDateString("uk-UA") : ""}</footer>
  </section>;

  return modal ? <div className="account-modal" role="dialog" aria-modal="true" aria-label="Налаштування профілю" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose?.(); }}>{content}</div> : content;
}
