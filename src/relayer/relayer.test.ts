// Verify RelayerClient emits exactly the wire format atoshi-privacy-relayer's
// server.js expects (POST /relay/withdraw, /relay/transfer). If these drift the
// relayer rejects the request, so the shapes are pinned here.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RelayerClient } from './index';
import { RpcError } from '../errors';

const PROOF = { pA: ['1', '2'], pB: [['3', '4'], ['5', '6']], pC: ['7', '8'] } as any;

describe('RelayerClient', () => {
  let calls: Array<{ url: string; body: any }>;

  beforeEach(() => {
    calls = [];
    global.fetch = (async (url: string, opts: any) => {
      calls.push({ url, body: JSON.parse(opts.body) });
      return { ok: true, json: async () => ({ txHash: '0xabc' }) } as any;
    }) as any;
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('submitWithdraw posts the exact /relay/withdraw wire format', async () => {
    const c = new RelayerClient('https://relayer.example/'); // trailing slash trimmed
    const r = await c.submitWithdraw({
      proof: PROOF,
      root: 10n,
      nullifierHash: 20n,
      recipient: '0xRecipient',
      relayer: '0xRelayer',
      amount: 1000n,
      fee: 5n,
      token: '0xToken',
    });
    expect(r).toEqual({ success: true, txHash: '0xabc', error: undefined });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://relayer.example/relay/withdraw');
    expect(calls[0].body).toEqual({
      proof: { pA: ['1', '2'], pB: [['3', '4'], ['5', '6']], pC: ['7', '8'] },
      publicSignals: {
        root: '10',
        nullifierHash: '20',
        recipient: '0xRecipient',
        relayer: '0xRelayer',
        amount: '1000',
        fee: '5',
      },
      token: '0xToken',
    });
  });

  it('submitTransfer posts the exact /relay/transfer wire format', async () => {
    const c = new RelayerClient('https://relayer.example');
    await c.submitTransfer({
      proof: PROOF,
      root: 1n,
      nullifierHash: 2n,
      newCommitment: 3n,
      encryptedNote: '0xdead',
    });
    expect(calls[0].url).toBe('https://relayer.example/relay/transfer');
    expect(calls[0].body).toEqual({
      proof: { pA: ['1', '2'], pB: [['3', '4'], ['5', '6']], pC: ['7', '8'] },
      publicSignals: { root: '1', nullifierHash: '2', newCommitment: '3' },
      encryptedNote: '0xdead',
    });
  });

  it('throws RpcError on a non-2xx response (surfacing the relayer error)', async () => {
    global.fetch = (async () => ({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({ error: 'relayer field mismatch' }),
    })) as any;
    const c = new RelayerClient('https://relayer.example');
    await expect(
      c.submitWithdraw({
        proof: PROOF,
        root: 1n,
        nullifierHash: 2n,
        recipient: '0xr',
        relayer: '0xrl',
        amount: 1n,
        fee: 0n,
        token: '0xt',
      })
    ).rejects.toBeInstanceOf(RpcError);
  });
});
