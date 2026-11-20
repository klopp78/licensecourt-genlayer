import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const resolve = ({ baseline, counterevidence, rationale }) => {
  const commitment = digest(JSON.stringify({ counterevidence, rationale }));
  const counterSnapshot = digest(counterevidence);
  const decision = /revoked|not licensed|prohibited/i.test(counterevidence + ' ' + rationale)
    ? 'denied' : baseline === 'licensed' ? 'approved' : 'inconclusive';
  return { decision, commitment, counterSnapshot, bundle: digest(commitment + counterSnapshot) };
};
const unchanged = resolve({ baseline: 'licensed', counterevidence: 'Original permission remains valid.', rationale: 'No material contradiction found.' });
const challenged = resolve({ baseline: 'licensed', counterevidence: 'License revoked; this use is prohibited.', rationale: 'The later notice supersedes the original grant.' });
assert.equal(unchanged.decision, 'approved');
assert.equal(challenged.decision, 'denied');
assert.notEqual(unchanged.commitment, challenged.commitment);
assert.notEqual(unchanged.counterSnapshot, challenged.counterSnapshot);
assert.notEqual(unchanged.bundle, challenged.bundle);
console.log('Challenge evidence changes the deterministic reassessment vector.');
