import { Crosshair, Eye, Map, RadioTower, X } from "lucide-react";

interface TutorialOverlayProps {
  onDismiss: () => void;
}

export function TutorialOverlay({ onDismiss }: TutorialOverlayProps) {
  return (
    <div className="tutorial-overlay" role="dialog" aria-modal="true" aria-label="Швидкий старт Shieldline">
      <section className="tutorial-card">
        <button className="tutorial-close" type="button" onClick={onDismiss} aria-label="Закрити навчання">
          <X size={18} />
        </button>
        <div className="tutorial-heading">
          <RadioTower size={24} />
          <div>
            <strong>Перше бойове зведення</strong>
            <span>Оцінюйте непевні контакти, розміщуйте прикриття та захищайте міста.</span>
          </div>
        </div>
        <div className="tutorial-steps">
          <article>
            <Map size={20} />
            <strong>Ресурси</strong>
            <p>Бюджет купує установки, БК потрібен для перехоплень, а енергія й мораль підтримують стійкість.</p>
          </article>
          <article>
            <Crosshair size={20} />
            <strong>Розміщення</strong>
            <p>Оберіть установку, поверніться на мапу й торкніться дозволеної ділянки. Катери розміщуються на воді.</p>
          </article>
          <article>
            <Eye size={20} />
            <strong>Туман війни</strong>
            <p>Непевні контакти можуть бути хибними цілями, доки радар не уточнить інформацію.</p>
          </article>
        </div>
        <button className="tutorial-primary" type="button" onClick={onDismiss}>Почати спостереження</button>
      </section>
    </div>
  );
}
