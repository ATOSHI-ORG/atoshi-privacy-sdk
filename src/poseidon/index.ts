/**
 * Poseidon hash primitives for Atoshi privacy.
 *
 * Uses circomlibjs internally. All inputs/outputs are BN254 field elements
 * (bigint < FIELD_SIZE). This module is the canonical source of truth — both
 * the H5 frontend (shield/) and the SDK consumers should use these helpers
 * instead of re-implementing Poseidon.
 */

import { buildPoseidon } from 'circomlibjs';

export const BN254_FIELD_SIZE = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

let _poseidon: any = null;
let _F: any = null;

async function ensurePoseidon() {
  if (!_poseidon) {
    _poseidon = await buildPoseidon();
    _F = _poseidon.F;
  }
  return { poseidon: _poseidon, F: _F };
}

/** Poseidon hash: N field elements → 1 field element */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const { poseidon, F } = await ensurePoseidon();
  return F.toObject(poseidon(inputs));
}

/** Compute Note commitment = Poseidon(amount, tokenId, owner, blinding) */
export async function computeCommitment(
  amount: bigint,
  tokenId: bigint,
  owner: bigint,
  blinding: bigint
): Promise<bigint> {
  return poseidonHash([amount, tokenId, owner, blinding]);
}

/** Compute nullifier = Poseidon(commitment, spendingKey, leafIndex) */
export async function computeNullifier(
  commitment: bigint,
  spendingKey: bigint,
  leafIndex: bigint | number
): Promise<bigint> {
  return poseidonHash([commitment, spendingKey, BigInt(leafIndex)]);
}

/** Derive owner pubkey = Poseidon(spendingKey). Share this with senders. */
export async function deriveOwnerPubkey(spendingKey: bigint): Promise<bigint> {
  return poseidonHash([spendingKey]);
}

/** Generate a random blinding factor (31 bytes, safe < FIELD_SIZE) */
export function randomBlinding(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

/**
 * Build empty-subtree "zeros" array used by Tornado-style Merkle trees.
 * zeros[0] = 0, zeros[i] = Poseidon(zeros[i-1], zeros[i-1])
 *
 * @param levels  Tree depth (Atoshi uses 20)
 */
export async function buildZeros(levels: number): Promise<bigint[]> {
  const zeros: bigint[] = [0n];
  for (let i = 1; i < levels; i++) {
    zeros.push(await poseidonHash([zeros[i - 1], zeros[i - 1]]));
  }
  return zeros;
}
