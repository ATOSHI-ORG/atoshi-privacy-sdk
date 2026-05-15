# Atoshi Privacy SDK — Frontend Integration Guide

`@atoshi/privacy-sdk` is the TypeScript SDK for **privacy transactions on Atoshi L2** — shielded deposits, transfers, and withdrawals using ZK-SNARK proofs.

This is the **companion SDK** to `@atoshi/chain-sdk` (which handles L1 queries and bridging). A complete wallet uses both.

---

## 0. What This SDK Does

The privacy system lives entirely on L2 and revolves around three core operations:

| Op | What happens | User-visible result |
|---|---|---|
| **Deposit (shield)** | Move tokens from a transparent L2 account into the Shield pool — your address is recorded, but the new "note" inside the pool is anonymous | "I put 10 ATOS into the privacy pool" |
| **Transfer** | Send a note to another user's public key inside the pool — no on-chain `from`/`to`/`amount` visible | "I sent 5 ATOS privately to Alice" |
| **Withdraw (unshield)** | Pop a note out of the pool to a fresh L2 address — breaks the link to your original identity | "I cashed out 5 ATOS to a new address" |

The cryptographic core: each "note" is a Poseidon hash commitment. Spending a note reveals a **nullifier** (proves the spender owns the note without revealing which note). All bookkeeping is verified on-chain by ZK proofs generated locally by this SDK.

---

## 1. Installation

```bash
npm install git+ssh://git@github.com/ATOSHI-ORG/atoshi-privacy-sdk.git
npm install ethers@^6 circomlibjs@^0.1 snarkjs@^0.7
```

These are heavy: snarkjs alone is ~500 KB. Plan your bundling accordingly (code-split the privacy flows so users hitting your landing page don't pay the cost).

After NPM publish:

```bash
npm install @atoshi/privacy-sdk ethers circomlibjs snarkjs
```

---

## 2. Conceptual Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  L2 (Atoshi 67890)                                                  │
│                                                                     │
│  ┌─ Transparent ─────┐         ┌─ Shield Pool ──────────────────┐   │
│  │                   │         │                                │   │
│  │  User L2 EOA      │ deposit │  Note merkle tree              │   │
│  │  has 10 ATOS  ───────────►  │   leaves: Poseidon(amount,     │   │
│  │                   │         │           tokenId, ownerPubKey,│   │
│  │  ┌──────────┐     │         │           blinding)            │   │
│  │  │ withdraw │  ◄──┼────────│                                │   │
│  │  │ to fresh │     │         │  spent set: nullifiers         │   │
│  │  │ EOA      │     │         │                                │   │
│  │  └──────────┘     │         └────────────────────────────────┘   │
│  └───────────────────┘                                              │
└─────────────────────────────────────────────────────────────────────┘
```

**Key types** the SDK exposes:

- `Keypair`: `{ privateKey, publicKey }` — both `bigint`, used for note ownership
- `NoteData`: `{ amount, tokenId, owner, blinding, commitment, leafIndex }` — one private balance unit
- `NoteRecord`: `NoteData` + status (pending/committed/spent) + tx hashes — stored client-side
- `MerkleProof`: 32-level path needed for ZK proof of inclusion
- `ZkProof`: `{ pA, pB, pC }` — Groth16 proof submitted on-chain

---

## 3. Initialize the Wallet

```typescript
import { PrivacyWallet } from '@atoshi/privacy-sdk';

const wallet = new PrivacyWallet({
  storagePrefix: 'atoshi_privacy_',   // localStorage key prefix (default)
  autoSync: true,
});

await wallet.init();   // loads circomlibjs Poseidon hasher (~200ms)
```

Then **derive the keypair**. The privacy keypair is **separate** from the user's EVM wallet — but you can deterministically derive it from one of these sources:

### 3.1 EIP-712 signature (recommended for non-custodial wallets)

The user signs a fixed message with MetaMask → we hash that signature → deterministic privacy key. The user does **not** manage a second mnemonic.

```typescript
// Step 1: ask MetaMask to sign a fixed EIP-712 message
const eip712Sig = await window.ethereum.request({
  method: 'eth_signTypedData_v4',
  params: [evmAddr, JSON.stringify({
    domain: { name: 'Atoshi Privacy', version: '1' },
    primaryType: 'PrivacyAuth',
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
      ],
      PrivacyAuth: [{ name: 'purpose', type: 'string' }],
    },
    message: { purpose: 'derive-privacy-key' },
  })],
});

// Step 2: derive the privacy keypair from that signature
const keypair = await wallet.initFromEIP712Signature(eip712Sig);
console.log('privacy pubkey:', keypair.publicKey.toString(16));
```

The user always recovers the same keypair from the same MetaMask account.

### 3.2 Mnemonic (BIP-39)

For users comfortable with managing a seed phrase:

```typescript
import { generateMnemonic } from '@atoshi/privacy-sdk';

const phrase = generateMnemonic();   // 12 words
// Show to user, ask them to back it up
await wallet.initFromMnemonic(phrase);
```

To restore:

```typescript
await wallet.initFromMnemonic(savedPhrase);
```

### 3.3 Encrypted backup (browser persistence)

After initial setup, save an encrypted blob:

```typescript
const blob = await wallet.exportEncrypted();
localStorage.setItem('atoshi_privacy_backup', JSON.stringify(blob));
```

On next session:

```typescript
const blob = JSON.parse(localStorage.getItem('atoshi_privacy_backup'));
await wallet.importEncrypted(blob);
// wallet is now initialized; no MetaMask signature needed again
```

---

## 4. Building the Transaction Layer

The `PrivacyWallet` holds keys and notes. To actually submit on-chain, use `TransactionBuilder`:

```typescript
import { TransactionBuilder, PrivacyRpcClient } from '@atoshi/privacy-sdk';
import { ethers } from 'ethers';

// L2 EVM provider + signer
const l2Provider = new ethers.JsonRpcProvider('http://localhost:8123', {
  chainId: 67890, name: 'atoshi-l2',
}, { batchMaxCount: 1, staticNetwork: true });

const ethSigner = await new ethers.BrowserProvider(window.ethereum).getSigner();

const tx = new TransactionBuilder({
  shieldContract: '0x81fAA0D0579c82d6b77FD759C198B507180E59E9',
  l1RpcUrl: '...',         // for cross-checks; usually optional
  nodeUrl: 'https://privacy-rpc.atoshi.xyz',   // privacy node RPC (the Shield index/prover service)
  circuitsPath: '/circuits',                    // path served by your web app
  keysPath: '/circuits/keys',
}, wallet);

await tx.init(ethSigner);   // connects to L2, compiles WASM
```

> **`circuitsPath` / `keysPath`** must point to a place where your web app serves the compiled circuit files (`*.wasm`, `*.zkey`). Standard setup: copy these from the `atoshi-privacy-contracts/circuits/build/` directory into your `public/` dir.

You'll also want a read-only `PrivacyRpcClient` for queries:

```typescript
const rpc = new PrivacyRpcClient('https://privacy-rpc.atoshi.xyz');

const state = await rpc.getState();
// { merkleRoot: "0x...", nextIndex: 42, nullifiersCount: 17 }

const isSpent = await rpc.isNullifierSpent(yourNullifier);
```

---

## 5. Core Flows (Copy-Paste Ready)

### 5.1 Deposit: shield 10 ATOS

```typescript
async function shieldDeposit(amountAtos: string) {
  // Ensure wallet is initialized (keypair exists)
  if (!wallet.isInitialized()) throw new Error('wallet not initialized');

  const result = await tx.deposit({
    amount: ethers.parseEther(amountAtos),     // bigint
    tokenAddress: ethers.ZeroAddress,          // native ATOS (or ERC20 address)
  });

  if (!result.success) {
    throw new Error(`Deposit failed: ${result.error}`);
  }

  console.log('deposit tx:', result.txHash, 'leaf index:', result.leafIndex);
  return result;
}
```

Internally:
1. Creates a new `NoteData` with random `blinding`
2. Computes the commitment = Poseidon(amount, tokenId, ownerPubKey, blinding)
3. Calls `Shield.deposit(commitment)` on L2 with `value: amount`
4. Saves note to wallet's local store as `Pending`
5. When the deposit log lands, marks note `Committed` with `leafIndex`

### 5.2 Private Transfer

```typescript
async function privateTransfer(recipientPubKey: bigint, amountAtos: string) {
  // Find a suitable note to spend
  const notes = wallet.getAvailableNotes();
  const suitable = notes.find(n => n.note.amount >= ethers.parseEther(amountAtos));
  if (!suitable) throw new Error('no note with enough balance');

  const result = await tx.transfer({
    noteIndex: suitable.note.leafIndex!,
    recipientPublicKey: recipientPubKey,
    amount: ethers.parseEther(amountAtos),    // optional: split note if smaller than the full note
  });

  if (!result.success) throw new Error(result.error);
  return result;
}
```

Internally:
1. Computes the nullifier for the old note (proves you own it without revealing which one)
2. Builds two new note commitments: one for recipient, one for change-back to self
3. Generates a Groth16 ZK proof: "I know an unspent note that hashes to commitment C; here are the nullifier and two new commitments"
4. Submits to `Shield.transfer(proof, nullifier, newC1, newC2)`

ZK proof generation takes **3-8 seconds** on a typical laptop. Show a progress UI.

### 5.3 Withdraw: unshield to a fresh address

```typescript
async function unshield(toAddress: string, amountAtos: string, relayerAddress?: string) {
  const notes = wallet.getAvailableNotes();
  const suitable = notes.find(n => n.note.amount === ethers.parseEther(amountAtos));
  if (!suitable) throw new Error('exact amount note required for withdraw');

  const result = await tx.withdraw({
    noteIndex: suitable.note.leafIndex!,
    recipient: toAddress,             // L2 address that receives the unshielded ATOS
    relayer: relayerAddress,          // optional: Relayer that will pay gas on behalf of user
    fee: relayerAddress ? ethers.parseEther('0.001') : 0n,   // fee paid to relayer
  });

  if (!result.success) throw new Error(result.error);
  return result;
}
```

**Why the relayer matters for privacy**: if the user pays gas themselves, the L2 EOA paying gas is linked to the withdrawal — defeating anonymity. The relayer pattern keeps the user's identity decoupled.

Relayer fee is paid in shielded ATOS (deducted from the withdrawn note).

---

## 6. Querying Privacy State

```typescript
// Total deposits / commits in the pool
const state = await rpc.getState();
// { merkleRoot: "0x1a3f...", nextIndex: 42, nullifiersCount: 17 }

// Check if a specific nullifier has been spent
const spent = await rpc.isNullifierSpent(myNoteNullifier);

// Get a merkle proof for any leaf (needed for spending notes)
const proof = await rpc.getMerkleProof(leafIndex);
// { leaf: bigint, leafIndex: number, pathElements: bigint[], pathIndices: number[], root: bigint }
```

The `PrivacyRpcClient` talks to your privacy node's JSON-RPC. Without a privacy node deployed yet, the wallet falls back to direct contract reads (slower).

---

## 7. Wallet's Own Note Manager

The `PrivacyWallet` instance maintains a local index of notes:

```typescript
// All notes the wallet owns (any status)
wallet.getAllNotes();

// Only spendable
wallet.getAvailableNotes();    // status === Committed && !spent

// Lookup
wallet.getNote(leafIndex);

// Total balance across unspent notes
const total = wallet.getAvailableNotes().reduce(
  (sum, r) => sum + r.note.amount,
  0n
);
console.log('private balance:', ethers.formatEther(total));
```

Notes are persisted to localStorage (or whatever backend you configure via `storagePrefix`).

---

## 8. Cross-SDK Integration (Real Wallet Flow)

A typical wallet shows balances and lets the user move funds end-to-end. This requires both SDKs:

```typescript
import { AtoshiClient } from '@atoshi/chain-sdk';
import { PrivacyWallet, TransactionBuilder, PrivacyRpcClient } from '@atoshi/privacy-sdk';

// (1) Init read clients
const chainRead = new AtoshiClient(sharedCfg);

// (2) Init signers (browser)
const evmChain = new AtoshiClient({ ...sharedCfg, signer: { type: 'metamask' } });
const cosmosChain = new AtoshiClient({
  ...sharedCfg,
  signer: { type: 'keplr', tendermintRpcUrl: '...' },
});

// (3) Init privacy
const privacy = new PrivacyWallet();
await privacy.init();
await privacy.initFromEIP712Signature(eip712Sig);

const tx = new TransactionBuilder({...}, privacy);
await tx.init(await new ethers.BrowserProvider(window.ethereum).getSigner());

// (4) Render unified dashboard
const data = {
  // L1
  atosPrice:   (await chainRead.oracle.currentPrice()).price,
  energy:      (await chainRead.energy.balance(cosmosAddr)).txEnergyAccrued,
  l1AtosBal:   (await chainRead.bank.balance(cosmosAddr)).amount,
  // L2 transparent
  l2AtosBal:   await l2Provider.getBalance(evmAddr),
  // L2 private (note balance)
  privBal:     privacy.getAvailableNotes().reduce((s, r) => s + r.note.amount, 0n),
};
```

---

## 9. Error Handling

### 9.1 Common ZK proof errors

```typescript
try {
  await tx.transfer({ noteIndex, recipientPublicKey, amount });
} catch (e) {
  const msg = (e as Error).message;
  if (msg.includes('snarkjs') && msg.includes('Assert')) {
    // Most common: constraint violation in the circuit
    // → likely a wrong nullifier or merkle proof; check note's leafIndex is fresh
    showToast('Proof generation failed; please refresh notes and retry');
  } else if (msg.includes('insufficient note balance')) {
    showToast('Not enough in this note; pick a larger one');
  } else if (msg.includes('NullifierAlreadySpent')) {
    showToast('This note has already been spent');
  } else {
    showToast('Transfer failed: ' + msg);
  }
}
```

### 9.2 Circuit files missing

If the user sees `Cannot find module circuit.wasm`, your `circuitsPath` is misconfigured. Make sure the circuit files are deployed to a public path:

```bash
# in your web app
mkdir -p public/circuits
cp -r ../atoshi-privacy-contracts/circuits/build/* public/circuits/
```

---

## 10. Performance Notes

| Operation | Typical time |
|---|---|
| `wallet.init()` (Poseidon load) | ~200ms |
| `tx.deposit()` (no ZK proof) | ~1s + L2 tx mining (~3s) |
| `tx.transfer()` (Groth16 proof) | **3-8s** on laptop |
| `tx.withdraw()` (Groth16 proof) | **3-8s** |
| `rpc.getMerkleProof()` | <100ms |

For mobile or low-end devices, withdraw/transfer proofs can take 15+ seconds. Always show a progress indicator and warn users not to navigate away.

---

## 11. Known Limitations / FAQ

### Q: Why is private transfer so slow?

A: Generating a Groth16 ZK proof is computationally heavy (the circuit has ~20k constraints). This is fundamental to all ZK-based privacy systems. Snarkjs is single-threaded JS; native or WebGPU provers exist but require an extra dep.

### Q: Can I generate the proof on a server and the user just submits?

A: Technically yes — implement `proverUrl` in your SDK config. But sending circuit witnesses (which contain note private data) to a server breaks anonymity unless that server is **fully trustless**. Don't do this casually.

### Q: How do users back up notes?

A: `wallet.exportEncrypted()` returns a small JSON blob (encrypted with the user's derived secret). Store in localStorage + optionally backup to user's email / GitHub gist. On restore, re-init wallet with the same source (EIP-712 sig or mnemonic) → import the blob.

### Q: What happens if a user loses their keypair?

A: Funds in their notes are **permanently lost** — no recovery is possible without the private key. Make this very clear in UX: "back up your privacy key" is more critical than backing up an EVM mnemonic, because there's no chain to "rescue" you from.

### Q: Does this SDK depend on the Atoshi L1?

A: Only loosely. Privacy operations happen entirely on L2. But:
- To get funds **into** Shield, users typically bridge from L1 first (use `chain-sdk` for that)
- The Relayer system that pays gas anonymously is registered on L1's `x/energy` module (use `chain-sdk.energy.delegate()`)

The two SDKs together cover the full user journey.

---

## 12. Contact

- Repo: https://github.com/ATOSHI-ORG/atoshi-privacy-sdk
- Companion: https://github.com/ATOSHI-ORG/atoshi-chain-sdk
- Issues / PRs welcome
