import { createClient, isSuccessful } from 'https://esm.sh/genlayer-js@1.1.8?bundle';
import { studionet } from 'https://esm.sh/genlayer-js@1.1.8/chains?bundle';
import { TransactionHashVariant } from 'https://esm.sh/genlayer-js@1.1.8/types?bundle';

// This adapter makes the browser workflow depend on GenLayer consensus, not EVM receipt status.
export class GenLayerAdapter {
  constructor(address, provider) { this.address = address; this.provider = provider; this.reader = createClient({ chain: studionet }); }
  async connect() { if (!this.provider) throw Error('A GenLayer-compatible wallet is required.'); const accounts = await this.provider.request({ method: 'eth_requestAccounts' }); this.account = accounts?.[0]; if (!this.account) throw Error('No wallet account was selected.'); this.writer = createClient({ chain: studionet, account: this.account, provider: this.provider }); await this.writer.connect('studionet'); return this.account; }
  async read(functionName, args = []) { return this.reader.readContract({ address: this.address, functionName, args, transactionHashVariant: TransactionHashVariant.LATEST_FINAL }); }
  async write(functionName, args) { if (!this.writer) throw Error('Connect a wallet first.'); const call = { address: this.address, functionName, args }; const quote = await this.writer.estimateTransactionFeesForWrite(call); const hash = await this.writer.writeContract({ ...call, fees: { distribution: quote.distribution, feeValue: quote.feeValue } }); const result = await this.writer.waitForFinalization({ hash }); if (!isSuccessful(result)) throw Error('GenLayer consensus did not finalize successfully.'); return hash; }
}
