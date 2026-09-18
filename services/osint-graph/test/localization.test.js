"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const uk = require("../public/uk");
const {
  ENTITY_TYPES,
  RELATIONSHIP_TYPES,
} = require("../src/security/validation");
const { summarizeAnalysis } = require("../src/analysis/summarizer");
test("every standard wire type has a Ukrainian label without changing custom values", () => {
  for (const [types, labels] of [
    [ENTITY_TYPES, uk.entities],
    [RELATIONSHIP_TYPES, uk.relationships],
  ])
    for (const type of types)
      assert.match(labels[type], /[А-Яа-яІіЇїЄєҐґ]/, type);
  const userType = "Власний тип";
  assert.equal(uk.entities[userType] || userType, userType);
  for (const status of ["FACT", "INFERENCE", "HYPOTHESIS"]) {
    assert.ok(uk.statuses[status].endsWith(status));
    assert.ok(uk.hints[status]);
  }
});
test("Ukrainian counters use correct singular few and many forms", () => {
  const forms = ["сутність", "сутності", "сутностей"];
  for (const [n, word] of [
    [1, "сутність"],
    [2, "сутності"],
    [5, "сутностей"],
    [11, "сутностей"],
    [21, "сутність"],
    [22, "сутності"],
    [500, "сутностей"],
  ])
    assert.ok(uk.count(n, forms).endsWith(" " + word));
});
test("raw server and network errors are not shown as technical codes", () => {
  for (const error of [
    "unknown_internal_code",
    "Failed to fetch",
    "fact_requires_evidence_or_direct_observation",
  ]) {
    const message = uk.error(new Error(error));
    assert.notEqual(message, error);
    assert.match(message, /[А-Яа-яІіЇїЄєҐґ]/);
  }
  assert.equal(
    uk.error(new Error("Оберіть дві сутності.")),
    "Оберіть дві сутності.",
  );
});
test("new analysis prose is Ukrainian while entity names stay unchanged", () => {
  const result = summarizeAnalysis({
    entities: [{ id: "1", display_name: "User supplied Name" }],
    analysis: {
      metrics: [{ entityId: "1" }],
      bridgeEntityIds: ["1"],
      connectedComponents: [["1"]],
    },
  });
  assert.match(result, /Найбільше зв’язків/);
  assert.match(result, /User supplied Name/);
  assert.match(result, /не висновки про наміри/);
});
