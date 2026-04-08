const test = require('node:test');
const assert = require('node:assert/strict');

const registerSubjectHelpers = require('../lib/registerSubjects');

function createSubject(overrides = {}) {
  return {
    id: 101,
    name: 'Соціокультурний розвиток',
    group_count: 2,
    is_required: true,
    selected_group: null,
    opted_out: false,
    ...overrides,
  };
}

test('required single-group subjects are auto-assigned and hidden from manual selection', () => {
  const [card] = registerSubjectHelpers.buildRegisterSubjectCards([
    createSubject({ group_count: 1, is_required: true }),
  ]);

  assert.equal(card.autoAssigned, true);
  assert.equal(card.interactive, false);
  assert.equal(card.selectedGroup, 1);
  assert.equal(card.ready, true);
});

test('optional single-group subjects require an explicit choice between group 1 and not taught', () => {
  const [card] = registerSubjectHelpers.buildRegisterSubjectCards([
    createSubject({ group_count: 1, is_required: false }),
  ]);

  assert.equal(card.autoAssigned, false);
  assert.equal(card.interactive, true);
  assert.equal(card.allowNotTaught, true);
  assert.equal(card.pending, true);
});

test('optional single-group subjects accept an explicit not-taught choice', () => {
  const choice = registerSubjectHelpers.readRegisterSubjectChoice(
    createSubject({ id: 102, group_count: 1, is_required: false }),
    { optout_102: '1' }
  );

  assert.equal(choice.optedOut, true);
  assert.equal(choice.ready, true);
  assert.equal(choice.missingChoice, false);
});

test('optional multi-group subjects accept either a group or not-taught', () => {
  const selectedChoice = registerSubjectHelpers.readRegisterSubjectChoice(
    createSubject({ id: 103, group_count: 3, is_required: false }),
    { subject_103: '2' }
  );
  const skippedChoice = registerSubjectHelpers.readRegisterSubjectChoice(
    createSubject({ id: 103, group_count: 3, is_required: false }),
    { optout_103: '1' }
  );

  assert.equal(selectedChoice.selectedGroup, 2);
  assert.equal(selectedChoice.ready, true);
  assert.equal(selectedChoice.missingChoice, false);
  assert.equal(skippedChoice.optedOut, true);
  assert.equal(skippedChoice.ready, true);
  assert.equal(skippedChoice.missingChoice, false);
});

test('interactive subjects stay invalid when neither a group nor not-taught is selected', () => {
  const optionalChoice = registerSubjectHelpers.readRegisterSubjectChoice(
    createSubject({ id: 104, group_count: 1, is_required: false }),
    {}
  );
  const requiredChoice = registerSubjectHelpers.readRegisterSubjectChoice(
    createSubject({ id: 105, group_count: 2, is_required: true }),
    {}
  );

  assert.equal(optionalChoice.missingChoice, true);
  assert.equal(requiredChoice.missingChoice, true);
});
