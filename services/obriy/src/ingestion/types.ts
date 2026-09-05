export interface SourceHealth {
  state: "disabled" | "connecting" | "live" | "degraded" | "error";
  lastEventAt?: string;
  lastSnapshotAt?: string;
  lastSuccessAt?: string;
  transport?: string;
}

export interface SecondaryObservation {
  source: string;
  externalId: string;
  observedAt: string;
  provenance: "unknown" | "dependent" | "independent";
  relationship: "unlinked" | "corroboration_unknown" | "contradiction";
}

export interface SecondarySourceAdapter {
  readonly id: string;
  start(signal: AbortSignal): Promise<void>;
  health(): SourceHealth;
}

/** No channel identity or access contract was supplied; never silently enable a userbot. */
export class DisabledSecondarySource implements SecondarySourceAdapter {
  readonly id = "airsigma";
  async start(_signal: AbortSignal): Promise<void> {}
  health(): SourceHealth {
    return { state: "disabled" };
  }
}
