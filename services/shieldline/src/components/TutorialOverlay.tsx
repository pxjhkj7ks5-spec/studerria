import { Crosshair, Eye, Map, RadioTower, X } from "lucide-react";

interface TutorialOverlayProps {
  onDismiss: () => void;
}

export function TutorialOverlay({ onDismiss }: TutorialOverlayProps) {
  return (
    <div className="tutorial-overlay" role="dialog" aria-modal="true" aria-label="Shieldline quick start">
      <section className="tutorial-card">
        <button className="tutorial-close" type="button" onClick={onDismiss} aria-label="Close tutorial">
          <X size={18} />
        </button>
        <div className="tutorial-heading">
          <RadioTower size={24} />
          <div>
            <strong>First run briefing</strong>
            <span>Survive by reading uncertainty, placing coverage, and protecting infrastructure.</span>
          </div>
        </div>
        <div className="tutorial-steps">
          <article>
            <Map size={20} />
            <strong>Resources</strong>
            <p>Budget buys units, ammo fuels engagements, energy and morale are national stability.</p>
          </article>
          <article>
            <Crosshair size={20} />
            <strong>Placement</strong>
            <p>Pick a unit card, then click the map. Placement uses the exact cursor point inside allowed zones.</p>
          </article>
          <article>
            <Eye size={20} />
            <strong>Fog of war</strong>
            <p>Low confidence tracks can be decoys or misclassified until radar contact improves certainty.</p>
          </article>
        </div>
        <button className="tutorial-primary" type="button" onClick={onDismiss}>Begin watch</button>
      </section>
    </div>
  );
}
