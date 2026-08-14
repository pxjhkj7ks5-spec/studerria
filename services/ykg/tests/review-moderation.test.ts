import assert from "node:assert/strict";
import test from "node:test";
import {
  moderateReview,
  type ReviewModerationState,
  type ReviewModerationStore,
} from "../src/lib/review-moderation";

function createStore(initialState: ReviewModerationState | null) {
  let state = initialState;
  let transitionCount = 0;
  const store: ReviewModerationStore = {
    async getState() {
      return state;
    },
    async transition(_id, from, to, moderatedAt, requireUnmoderated) {
      transitionCount += 1;
      if (!state || state.status !== from || (requireUnmoderated && state.moderatedAt)) return false;
      state = { status: to, moderatedAt };
      return true;
    },
  };
  return {
    store,
    get state() {
      return state;
    },
    get transitionCount() {
      return transitionCount;
    },
  };
}

test("confirming an auto-published review persistently locks rejection", async () => {
  const state = createStore({ status: "approved", moderatedAt: null });

  const outcome = await moderateReview(state.store, 42, "approve");
  const rejectionOutcome = await moderateReview(state.store, 42, "reject");

  assert.equal(outcome, "confirmed");
  assert.equal(state.state?.status, "approved");
  assert.ok(state.state?.moderatedAt);
  assert.equal(rejectionOutcome, "rejection_locked");
  assert.equal(state.transitionCount, 1);
});

test("rejecting an unconfirmed published review hides it", async () => {
  const state = createStore({ status: "approved", moderatedAt: null });

  const outcome = await moderateReview(state.store, 42, "reject");

  assert.equal(outcome, "hidden");
  assert.equal(state.state?.status, "rejected");
  assert.equal(state.transitionCount, 1);
});

test("rejecting an already hidden review is idempotent", async () => {
  const state = createStore({ status: "rejected", moderatedAt: new Date() });

  const outcome = await moderateReview(state.store, 42, "reject");

  assert.equal(outcome, "already_hidden");
  assert.equal(state.transitionCount, 0);
});

test("legacy pending reviews can still be published", async () => {
  const state = createStore({ status: "pending", moderatedAt: null });

  const outcome = await moderateReview(state.store, 42, "approve");

  assert.equal(outcome, "published");
  assert.equal(state.state?.status, "approved");
  assert.ok(state.state?.moderatedAt);
});

test("an already confirmed review stays published without another transition", async () => {
  const confirmedAt = new Date("2026-08-04T12:00:00Z");
  const state = createStore({ status: "approved", moderatedAt: confirmedAt });

  const outcome = await moderateReview(state.store, 42, "approve");

  assert.equal(outcome, "already_confirmed");
  assert.equal(state.state?.moderatedAt, confirmedAt);
  assert.equal(state.transitionCount, 0);
});
