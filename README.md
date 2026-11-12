# LicenseCourt for GenLayer

LicenseCourt is an on-chain admission gate for an AI agent that needs permission to use a licensed content, API, or model asset. It converts a mutable link-based claim into a consensus-reviewed license record with immutable source commitments, bounded usage and a named executor.

**Studio Dev deployment:** [`0x6d913f1366c5Eed81C39E587e9A3A2692C122Ceb`](https://explorer-studio-next.genlayer.com/address/0x6d913f1366c5Eed81C39E587e9A3A2692C122Ceb)

## Why it needs GenLayer

Normal contracts can count a token but cannot independently read and adjudicate whether a web-hosted license actually permits an agent's requested scope. LicenseCourt uses GenLayer validators to render the registered terms, asset, and two independent source pages. The agreed decision and every consequential snapshot hash are persisted with the license record.

## Lifecycle

1. **Register**: the owner binds consumer, named agent, asset URL, terms URL, use scope, positive maximum uses, expiry, and two distinct registrable-domain sources into a canonical SHA-256 license commitment.
2. **Assess**: validators independently retrieve the four bound sources and agree on a decision plus terms, asset, and source-bundle snapshot commitments.
3. **Challenge**: only either named party can submit counterevidence from an already committed source identity. This freezes use; resolution is delayed, deadline-bounded, and has a deterministic timeout revocation path.
4. **Consume**: only the named agent can use an approved, unexpired license. Each call creates one receipt and the contract enforces the use cap on-chain.
5. **Recover**: the owner can revoke an open license; any relevant active state becomes expired after its deadline so no record remains indefinitely actionable.

## Integrity controls

- Every ID derives from a canonical JSON representation and a one-use SHA-256 nonce.
- Source identity rejects user-info and port-bearing authorities, folds `www`, and requires different base host identities for the two evidence sources.
- Inconclusive retrieval is never silently approved.
- Validators compare the decision, license commitment, all source snapshot hashes, and derived assessment hash.
- The UI waits for transaction finality and re-reads the exact license ID, never a global latest record.

## Run checks

```bash
npm test
```

Deploy `contracts/license_court.py` in GenLayer Studio. Then set that address in `docs/index.html`; the app calls the deployed contract for registration, assessment, challenge, consumption, revocation and record reads.
