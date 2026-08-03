import assert from "node:assert/strict";
import test from "node:test";
import {
  moderateReview,
  type ReviewModerationStatus,
  type ReviewModerationStore,
} from "../src/lib/review-moderation";

function createStore(initialStatus: ReviewModerationStatus | null) {
  let status = initialStatus;
  let transitionCount = 0;
  const store: ReviewModerationStore = {
    async getStatus() {
      return status;
    },
    async transition(_id, from, to) {
      transitionCount += 1;
      if (status !== from) return false;
      status = to;
      return true;
    },
  };
  return {
    store,
    get status() {
      return status;
    },
    get transitionCount() {
      return transitionCount;
    },
  };
}

test("confirming an already published review is idempotent", async () => {
  const state = createStore("approved");

  const outcome = await moderateReview(state.store, 42, "approve");

  assert.equal(outcome, "already_published");
  assert.equal(state.status, "approved");
  assert.equal(state.transitionCount, 0);
});

test("rejecting a published review hides it", async () => {
  const state = createStore("approved");

  const outcome = await moderateReview(state.store, 42, "reject");

  assert.equal(outcome, "hidden");
  assert.equal(state.status, "rejected");
  assert.equal(state.transitionCount, 1);
});

test("rejecting an already hidden review is idempotent", async () => {
  const state = createStore("rejected");

  const outcome = await moderateReview(state.store, 42, "reject");

  assert.equal(outcome, "already_hidden");
  assert.equal(state.transitionCount, 0);
});

test("legacy pending reviews can still be published", async () => {
  const state = createStore("pending");

  const outcome = await moderateReview(state.store, 42, "approve");

  assert.equal(outcome, "published");
  assert.equal(state.status, "approved");
});
