import fs from 'node:fs';
const source = fs.readFileSync('contracts/license_court.py', 'utf8');
const required = ['register_license', 'assess_license', 'challenge_license', 'resolve_or_expire', 'consume_license', 'only_named_agent_can_consume', 'independent_sources_required', 'nonce_already_used', 'gl.vm.run_nondet_unsafe', 'terms_snapshot_hash', 'source_bundle_hash', 'usage_limit_reached'];
const missing = required.filter((token) => !source.includes(token));
if (missing.length) throw new Error(`Missing lifecycle controls: ${missing.join(', ')}`);
console.log('LicenseCourt static lifecycle checks passed.');
