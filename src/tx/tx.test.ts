// Integration-ish tests for TransactionBuilder.transfer's encryptedNote key
// selection (audit Issue 6 follow-up). Uses a fake RPC client so no chain is
// needed. The key property under test: a transfer to an EXTERNAL recipient
// without their viewing pubkey must FAIL LOUD rather than silently produce a
// note the recipient can never recover.

import { describe, it, expect, beforeEach } from 'vitest';
import { TransactionBuilder } from './index';
import { PrivacyWallet } from '../wallet';
import { TESTNET_CONFIG } from '../config';
import { InvalidParamsError, ProofError } from '../errors';

const MNEMONIC =
  'test test test test test test test test test test test junk';

async function makeCommittedWallet(): Promise<PrivacyWallet> {
  const w = new PrivacyWallet({ chainId: TESTNET_CONFIG.l2ChainId });
  await w.init();
  await w.initFromMnemonic(MNEMONIC);
  const note = await w.createNote(1000n, 0n); // owner = self
  w.addNote(note);
  w.markNoteCommitted(note.getCommitment()!, 0, '0xhash', 1);
  return w;
}

// Fake privacy-node RPC: leaf matches so the reorg guard passes, nullifier is
// unspent, and submitTransfer "succeeds".
function fakeRpc(leaf: bigint) {
  return {
    getMerkleProof: async (leafIndex: number) => ({
      leaf,
      leafIndex,
      pathElements: [],
      pathIndices: [],
      root: 0n,
    }),
    isNullifierSpent: async () => false,
    submitTransfer: async () => ({ success: true, txHash: '0xtx', leafIndex: 1 }),
  };
}

describe('transfer encryptedNote key selection (audit Issue 6)', () => {
  let builder: TransactionBuilder;
  let wallet: PrivacyWallet;
  let commitment: bigint;

  beforeEach(async () => {
    wallet = await makeCommittedWallet();
    commitment = wallet.getAllNotes()[0].note.commitment!;
    builder = new TransactionBuilder(wallet, {
      ...TESTNET_CONFIG,
      nodeUrl: 'http://localhost:0',
    });
    await builder.init(); // no signer needed for the node-submitted transfer path
    // Inject the fake node so no real network is used.
    (builder as unknown as { rpcClient: unknown }).rpcClient = fakeRpc(commitment);
  });

  it('throws when transferring to another recipient without a viewing pubkey', async () => {
    await expect(
      builder.transfer({ noteIndex: 0, recipientPublicKey: 999n })
    ).rejects.toBeInstanceOf(InvalidParamsError);

    // The input note must NOT have been marked spent (we failed before submit).
    expect(wallet.getUnspentNotes()).toHaveLength(1);
  });

  it('accepts a self-transfer without a viewing pubkey (defaults to own key)', async () => {
    // A self-transfer must NOT be rejected by key selection. It gets past
    // buildEncryptedNote and only fails later at real proof generation (no
    // circuit .wasm in the unit-test env) — i.e. a ProofError, never an
    // InvalidParamsError. That proves the own-key default applies to self.
    const self = wallet.getPublicKey()!;
    await expect(
      builder.transfer({ noteIndex: 0, recipientPublicKey: self })
    ).rejects.toBeInstanceOf(ProofError);
  });
});
