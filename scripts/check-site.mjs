import fs from 'node:fs';
const site = fs.readFileSync('docs/index.html', 'utf8');
const adapter = fs.readFileSync('docs/genlayer-adapter.js', 'utf8');
const required = ['GenLayerAdapter', 'preview_license_id', 'get_license', 'Finalized and re-read', 'does not use ethers', 'createClient', 'studionet', 'estimateTransactionFeesForWrite', 'writeContract', 'waitForFinalization', 'isSuccessful', 'TransactionHashVariant.LATEST_FINAL'];
const joined = site + adapter;
const missing = required.filter(x => !joined.includes(x));
if (missing.length || /ethers@|new ethers|BrowserProvider/.test(joined)) throw Error(`Missing GenLayer site controls: ${missing.join(', ')}`);
console.log('LicenseCourt GenLayer adapter and finality checks passed.');
