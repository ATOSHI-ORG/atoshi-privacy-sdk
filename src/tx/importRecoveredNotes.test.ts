// Unit test for TransactionBuilder.importRecoveredNotes (audit Issue 11 / Q6):
// merging ChainScanner results back into the wallet's note store.
//
// What we protect:
//   - deposit / resolved-leafIndex notes become Committed (spendable);
//   - a recovered note already spent ON-CHAIN becomes Spent, not spendable
//     (the fresh-wallet scenario: no local state, so we must ask the contract);
//   - transfer notes with leafIndex -1 (unresolved) become Pending, NOT spendable;
//   - an already-Spent (locally) note is never resurrected by a re-scan;
//   - the merge is idempotent.
// The on-chain isSpent() check is stubbed so no network runs.

import { describe, it, expect } from 'vitest';
import { PrivacyWallet } from '../wallet';
import { TransactionBuilder } from './index';
import { Note } from '../note';
import { NoteStatus } from '../types';
import { TESTNET_CONFIG } from '../config';
import type { RecoveredNote } from '../scanner';

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function makeBuilder(isSpent: (n: bigint) => Promise<boolean> = async () => false) {
  const wallet = new PrivacyWallet();
  await wallet.init();
  await wallet.initFromMnemonic(PHRASE);
  const tb = new TransactionBuilder(wallet, { ...TESTNET_CONFIG });
  await tb.init();
  // Stub the on-chain nullifier check so the test needs no network.
  (tb as any).shieldRead = { isSpent };
  return { wallet, tb, owner: wallet.getPublicKey()! };
}

function rec(overrides: Partial<RecoveredNote> & { commitment: bigint }): RecoveredNote {
  return {
    leafIndex: 0,
    blockNumber: 1,
    txHash: '0xtx',
    source: 'deposit',
    amount: 1000n,
    tokenId: 0n,
    blinding: 12345n,
    ...overrides,
  };
}

describe('TransactionBuilder.importRecoveredNotes', () => {
  it('marks an unspent deposit / resolved-leafIndex note Committed and spendable', async () => {
    const { wallet, tb } = await makeBuilder(async () => false);
    const c = 111n;

    const out = await tb.importRecoveredNotes([
      rec({ commitment: c, leafIndex: 5, source: 'deposit' }),
    ]);

    expect(out.committed).toContain(c);
    expect(out.pending).toHaveLength(0);
    const unspent = wallet.getUnspentNotes();
    expect(unspent.map((r) => r.note.commitment)).toContain(c);
    const record = unspent.find((r) => r.note.commitment === c)!;
    expect(record.status).toEqual(NoteStatus.Committed);
    expect(record.note.leafIndex).toEqual(5);
  });

  it('marks a recovered note Spent when its nullifier is already spent on-chain', async () => {
    // Fresh-wallet scenario the auditor flagged: no local state, chain says spent.
    const { wallet, tb } = await makeBuilder(async () => true);
    const c = 555n;

    const out = await tb.importRecoveredNotes([
      rec({ commitment: c, leafIndex: 8, source: 'deposit' }),
    ]);

    expect(out.spent).toContain(c);
    expect(out.committed).not.toContain(c);
    // The whole point: a spent note must NOT appear as spendable.
    expect(wallet.getUnspentNotes().map((r) => r.note.commitment)).not.toContain(c);
    const record = wallet.getAllNotes().find((r) => r.note.commitment === c)!;
    expect(record.status).toEqual(NoteStatus.Spent);
  });

  it('keeps transfer notes with leafIndex -1 Pending (not spendable)', async () => {
    const { wallet, tb } = await makeBuilder();
    const c = 222n;

    const out = await tb.importRecoveredNotes([
      rec({ commitment: c, leafIndex: -1, source: 'transfer' }),
    ]);

    expect(out.pending).toContain(c);
    expect(out.committed).toHaveLength(0);
    expect(wallet.getUnspentNotes().map((r) => r.note.commitment)).not.toContain(c);
  });

  it('never resurrects a locally already-spent note', async () => {
    const { wallet, tb, owner } = await makeBuilder();
    const c = 333n;

    // Pre-seed a spent note with this commitment.
    const spent = new Note({ amount: 500n, tokenId: 0n, owner, blinding: 9n, commitment: c });
    wallet.addNote(spent);
    wallet.markNoteSpent(c, '0xspend');

    const out = await tb.importRecoveredNotes([
      rec({ commitment: c, leafIndex: 7, source: 'transfer' }),
    ]);

    expect(out.skipped).toContain(c);
    expect(out.committed).not.toContain(c);
    const record = wallet.getAllNotes().find((r) => r.note.commitment === c)!;
    expect(record.status).toEqual(NoteStatus.Spent);
  });

  it('is idempotent across repeated imports', async () => {
    const { wallet, tb } = await makeBuilder(async () => false);
    const c = 444n;
    const note = rec({ commitment: c, leafIndex: 3, source: 'deposit' });

    await tb.importRecoveredNotes([note]);
    await tb.importRecoveredNotes([note]);

    const matches = wallet.getAllNotes().filter((r) => r.note.commitment === c);
    expect(matches).toHaveLength(1);
    expect(matches[0].status).toEqual(NoteStatus.Committed);
  });
});
