export type ReviewModerationAction = "approve" | "reject";
export type ReviewModerationStatus = "pending" | "approved" | "rejected";
export type ReviewModerationOutcome =
  | "published"
  | "confirmed"
  | "already_confirmed"
  | "hidden"
  | "already_hidden"
  | "rejection_locked"
  | "missing"
  | "conflict";

export type ReviewModerationState = {
  status: ReviewModerationStatus;
  moderatedAt: Date | null;
};

export type ReviewModerationStore = {
  getState(id: number): Promise<ReviewModerationState | null>;
  transition(
    id: number,
    from: ReviewModerationStatus,
    to: ReviewModerationStatus,
    moderatedAt: Date,
    requireUnmoderated: boolean,
  ): Promise<boolean>;
};

export async function moderateReview(
  store: ReviewModerationStore,
  id: number,
  action: ReviewModerationAction,
): Promise<ReviewModerationOutcome> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const state = await store.getState(id);
    if (!state) return "missing";

    if (action === "approve") {
      if (state.status === "rejected") return "already_hidden";
      if (state.status === "approved" && state.moderatedAt) return "already_confirmed";
      if (state.status === "approved") {
        if (await store.transition(id, "approved", "approved", new Date(), true)) return "confirmed";
        continue;
      }
      if (await store.transition(id, "pending", "approved", new Date(), false)) return "published";
      continue;
    }

    if (state.status === "rejected") return "already_hidden";
    if (state.moderatedAt) return "rejection_locked";
    if (await store.transition(id, state.status, "rejected", new Date(), true)) return "hidden";
  }

  return "conflict";
}
