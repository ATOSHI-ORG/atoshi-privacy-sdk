// Unit test for low-s signature normalization in seed derivation (audit
// Issue 15). ECDSA is malleable: (r, s) and (r, n - s) are both valid, and
// different wallets may return either. Without normalization the same EOA +
// typed data could derive two different seeds -> unrecoverable wallet. We
// assert the two malleated forms derive the SAME seed, and that a genuinely
// different s derives a DIFFERENT seed (so the test can actually fail).

import { describe, it, expect } from 'vitest';
import { seedFromEIP712Signature } from './derivation';

// secp256k1 group order.
const N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function hex32(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}

// Build a 65-byte r||s||v hex signature.
function sig(r: bigint, s: bigint, v = '1b'): string {
  return '0x' + hex32(r) + hex32(s) + v;
}

const R = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

describe('seedFromEIP712Signature low-s normalization', () => {
  it('high-s and low-s equivalent signatures derive the same seed', async () => {
    const sLow = 42n;
    const sHigh = N - sLow; // the malleated (high-s) equivalent

    const seedFromLow = await seedFromEIP712Signature(sig(R, sLow));
    const seedFromHigh = await seedFromEIP712Signature(sig(R, sHigh));

    expect(Array.from(seedFromLow)).toEqual(Array.from(seedFromHigh));
  });

  it('is independent of the v byte parity', async () => {
    const a = await seedFromEIP712Signature(sig(R, 42n, '1b'));
    const b = await seedFromEIP712Signature(sig(R, 42n, '00'));
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it('a genuinely different s derives a different seed', async () => {
    const seedA = await seedFromEIP712Signature(sig(R, 42n));
    const seedB = await seedFromEIP712Signature(sig(R, 43n));
    expect(Array.from(seedA)).not.toEqual(Array.from(seedB));
  });

  it('rejects a signature that is not 65 bytes', async () => {
    await expect(seedFromEIP712Signature('0x1234')).rejects.toThrow();
  });
});
