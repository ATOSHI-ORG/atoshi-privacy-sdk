// Unit test for TransactionBuilder.importRecoveredNotes (audit Issue 11 / Q6):
// merging ChainScanner results back into the wallet's note store.
//
// What we protect:
//   - deposit / resolved-leafIndex notes become Committed (spendable);
//   - transfer notes with leafIndex -1 (unresolved) become Pending, NOT spendable;
//   - an already-Spent note is never resurrected by a re-scan;
//   - the merge is idempotent.
// No chain access: init() only builds Poseidon + a lazy provider.

import { describe, it, expect } from 'vitest';
import { PrivacyWallet } from '../wallet';
import { TransactionBuilder } from './index';
import { Note } from '../note';
import { NoteStatus } from '../types';
import { TESTNET_CONFIG } from '../config';
import type { RecoveredNote } from '../scanner';

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function makeBuilder() {
  const wallet = new PrivacyWallet();
  await wallet.init();
  await wallet.initFromMnemonic(PHRASE);
  const tb = new TransactionBuilder(wallet, {
    ...TESTNET_CONFIG,
    nodeUrl: 'http://localhost:0',
  });
  await tb.init();
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
  it('marks deposit / resolved-leafIndex notes Committed and spendable', async () => {
    const { wallet, tb } = await makeBuilder();
    const c = 111n;

    const out = tb.importRecoveredNotes([
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

  it('keeps transfer notes with leafIndex -1 Pending (not spendable)', async () => {
    const { wallet, tb } = await makeBuilder();
    const c = 222n;

    const out = tb.importRecoveredNotes([
      rec({ commitment: c, leafIndex: -1, source: 'transfer' }),
    ]);

    expect(out.pending).toContain(c);
    expect(out.committed).toHaveLength(0);
    // Pending notes are tracked but excluded from the spendable set.
    expect(wallet.getUnspentNotes().map((r) => r.note.commitment)).not.toContain(c);
  });

  it('never resurrects an already-spent note', async () => {
    const { wallet, tb, owner } = await makeBuilder();
    const c = 333n;

    // Pre-seed a spent note with this commitment.
    const spent = new Note({ amount: 500n, tokenId: 0n, owner, blinding: 9n, commitment: c });
    wallet.addNote(spent);
    wallet.markNoteSpent(c, '0xspend');

    const out = tb.importRecoveredNotes([
      rec({ commitment: c, leafIndex: 7, source: 'transfer' }),
    ]);

    expect(out.skipped).toContain(c);
    expect(out.committed).not.toContain(c);
    const record = wallet.getAllNotes().find((r) => r.note.commitment === c)!;
    expect(record.status).toEqual(NoteStatus.Spent);
  });

  it('is idempotent across repeated imports', async () => {
    const { wallet, tb } = await makeBuilder();
    const c = 444n;
    const note = rec({ commitment: c, leafIndex: 3, source: 'deposit' });

    tb.importRecoveredNotes([note]);
    tb.importRecoveredNotes([note]);

    const matches = wallet.getAllNotes().filter((r) => r.note.commitment === c);
    expect(matches).toHaveLength(1);
    expect(matches[0].status).toEqual(NoteStatus.Committed);
  });
});
