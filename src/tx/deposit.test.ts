// Deposit note-tracking + receipt handling (audit Issue 11 follow-up).
// Chain I/O is stubbed (proof gen, contract call, receipt) so no network runs.

import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import { TransactionBuilder } from './index';
import { PrivacyWallet } from '../wallet';
import { TESTNET_CONFIG } from '../config';
import { NoteStatus } from '../types';
import { viewingPubKey } from '../crypto/ecies';

const MNEMONIC = 'test test test test test test test test test test test junk';
const PROOF = { pA: ['0', '0'], pB: [['0', '0'], ['0', '0']], pC: ['0', '0'] };
const RECEIPT_NO_LEAF = { hash: '0xdep', blockNumber: 1, logs: [] };

async function makeBuilder(receipt: any) {
  const w = new PrivacyWallet({ chainId: TESTNET_CONFIG.l2ChainId });
  await w.init();
  await w.initFromMnemonic(MNEMONIC);
  const tb = new TransactionBuilder(w, { ...TESTNET_CONFIG });
  await tb.init();
  // Stub the on-chain bits so deposit() reaches its note-tracking logic.
  (tb as any).generateProof = async () => PROOF;
  (tb as any).signer = {};
  (tb as any).shieldContract = {
    deposit: async () => ({ hash: '0xdep', wait: async () => receipt }),
  };
  return { w, tb };
}

describe('deposit note tracking (audit Issue 11 follow-up)', () => {
  it('does NOT track a deposit made to another recipient', async () => {
    const { w, tb } = await makeBuilder(RECEIPT_NO_LEAF);
    await tb.deposit({
      amount: 1000n,
      tokenAddress: ethers.ZeroAddress,
      recipient: 999n, // external owner pubkey
      recipientViewingPubKey: viewingPubKey(555n),
    });
    // The note belongs to 999n, not us — must not pollute our wallet.
    expect(w.getAllNotes()).toHaveLength(0);
  });

  it('tracks a self-deposit as Pending until a leafIndex is known', async () => {
    const { w, tb } = await makeBuilder(RECEIPT_NO_LEAF);
    await tb.deposit({ amount: 1000n, tokenAddress: ethers.ZeroAddress });
    const notes = w.getAllNotes();
    expect(notes).toHaveLength(1);
    expect(notes[0].status).toEqual(NoteStatus.Pending);
  });

  it('returns tx.hash (not a dropped receipt) when tx.wait() yields null', async () => {
    const { tb } = await makeBuilder(null); // provider dropped the receipt
    const r = await tb.deposit({ amount: 1000n, tokenAddress: ethers.ZeroAddress });
    expect(r.success).toBe(false);
    expect(r.txHash).toBe('0xdep'); // caller can still poll status
  });
});
