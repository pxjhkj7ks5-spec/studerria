export type ReviewModerationAction = "approve" | "reject";
export type ReviewModerationStatus = "pending" | "approved" | "rejected";
export type ReviewModerationOutcome =
  | "published"
  | "already_published"
  | "hidden"
  | "already_hidden"
  | "missing"
  | "conflict";

export type ReviewModerationStore = {
  getStatus(id: number): Promise<ReviewModerationStatus | null>;
  transition(
    id: number,
    from: ReviewModerationStatus,
    to: ReviewModerationStatus,
    moderatedAt: Date,
  ): Promise<boolean>;
};

export async function moderateReview(
  store: ReviewModerationStore,
  id: number,
  action: ReviewModerationAction,
): Promise<ReviewModerationOutcome> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const status = await store.getStatus(id);
    if (!status) return "missing";

    if (action === "approve") {
      if (status === "approved") return "already_published";
      if (status === "rejected") return "already_hidden";
      if (await store.transition(id, "pending", "approved", new Date())) return "published";
      continue;
    }

    if (status === "rejected") return "already_hidden";
    if (await store.transition(id, status, "rejected", new Date())) return "hidden";
  }

  return "conflict";
}
