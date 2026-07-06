// Unit tests for PrivacyWallet state handling introduced by the audit fixes.
// Pure (no chain / RPC): exercises note dedup (Issue 10), getters returning
// copies (Issue 16), and chainId-namespaced backups (Q5).

import { describe, it, expect } from 'vitest';
import { PrivacyWallet } from './index';
import { NoteStatus } from '../types';

// Standard test mnemonic (valid BIP-39) — derives a full key set.
const MNEMONIC =
  'test test test test test test test test test test test junk';

async function makeWallet(chainId?: number): Promise<PrivacyWallet> {
  const w = new PrivacyWallet(chainId === undefined ? {} : { chainId });
  await w.init();
  await w.initFromMnemonic(MNEMONIC);
  return w;
}

describe('PrivacyWallet.addNote dedup (audit Issue 10)', () => {
  it('does not silently overwrite a note with the same commitment', async () => {
    const w = await makeWallet();
    const note = await w.createNote(1000n, 0n);
    const commitment = note.getCommitment()!;

    w.addNote(note);
    w.markNoteCommitted(commitment, 7, '0xhash', 100);
    expect(w.getAllNotes()).toHaveLength(1);
    expect(w.getAllNotes()[0].status).toBe(NoteStatus.Committed);

    // Re-adding the same note must NOT reset it to Pending or duplicate it.
    w.addNote(note);
    expect(w.getAllNotes()).toHaveLength(1);
    expect(w.getAllNotes()[0].status).toBe(NoteStatus.Committed);
    expect(w.getAllNotes()[0].note.leafIndex).toBe(7);
  });
});

describe('PrivacyWallet getters return copies (audit Issue 16)', () => {
  it('mutating a returned NoteRecord does not change wallet state', async () => {
    const w = await makeWallet();
    const note = await w.createNote(500n, 0n);
    w.addNote(note);

    const records = w.getAllNotes();
    records[0].status = NoteStatus.Spent;
    records[0].note.leafIndex = 999;

    // Internal state is untouched.
    expect(w.getAllNotes()[0].status).toBe(NoteStatus.Pending);
    expect(w.getAllNotes()[0].note.leafIndex).toBeUndefined();
  });

  it('mutating the returned keypair does not change wallet state', async () => {
    const w = await makeWallet();
    const kp = w.getKeypair()!;
    const original = kp.privateKey;
    kp.privateKey = 12345n;
    expect(w.getKeypair()!.privateKey).toBe(original);
  });

  it('mutating returned derived keys does not change wallet state', async () => {
    const w = await makeWallet();
    const dk = w.getDerivedKeys()!;
    dk.encryptionKey[0] = (dk.encryptionKey[0] ^ 0xff) & 0xff;
    // Fresh copy is unaffected by the mutation above.
    expect(w.getDerivedKeys()!.encryptionKey[0]).not.toBe(dk.encryptionKey[0]);
  });
});

describe('PrivacyWallet chainId-namespaced backups (audit Q5)', () => {
  it('rejects importing a backup from a different chainId', async () => {
    const w1 = await makeWallet(67890);
    const backup = w1.export();

    const w2 = new PrivacyWallet({ chainId: 12345 });
    await w2.init();
    await expect(w2.import(backup)).rejects.toThrow(/chainId/);
  });

  it('accepts importing a backup from the same chainId', async () => {
    const w1 = await makeWallet(67890);
    const note = await w1.createNote(1n, 0n);
    w1.addNote(note);
    const backup = w1.export();

    const w2 = new PrivacyWallet({ chainId: 67890 });
    await w2.init();
    await expect(w2.import(backup)).resolves.toBeUndefined();
    expect(w2.getAllNotes()).toHaveLength(1);
  });

  it('legacy backup with no chainId still imports (backward compatible)', async () => {
    const w1 = await makeWallet(); // no chainId
    const backup = w1.export();

    const w2 = new PrivacyWallet({ chainId: 67890 });
    await w2.init();
    await expect(w2.import(backup)).resolves.toBeUndefined();
  });
});
