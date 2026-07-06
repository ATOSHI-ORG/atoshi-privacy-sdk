/**
 * Utility functions
 */

import { FIELD_SIZE } from '../types';

/**
 * Generate a random field element.
 *
 * Uses the Web Crypto API (globalThis.crypto) so it runs unchanged in the
 * browser / H5 environment as well as Node 18+, avoiding the Node-only
 * `crypto.randomBytes` + `Buffer` that break under Vite / Webpack 5.
 */
export function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  // Clear top bits to ensure < 2^253
  bytes[0] &= 0x1f;
  return fromBytes(bytes) % FIELD_SIZE;
}

/**
 * Poseidon hash function wrapper
 */
export async function poseidonHash(
  inputs: bigint[],
  poseidon?: any,
  F?: any
): Promise<bigint> {
  if (!poseidon || !F) {
    const { buildPoseidon } = await import('circomlibjs');
    poseidon = await buildPoseidon();
    F = poseidon.F;
  }

  const hash = poseidon(inputs.map((x) => F.e(x)));
  return BigInt(F.toObject(hash));
}

/**
 * Convert bigint to hex string
 */
export function toHex(value: bigint, padLength = 64): string {
  return '0x' + value.toString(16).padStart(padLength, '0');
}

/**
 * Convert hex string to bigint
 */
export function fromHex(hex: string): bigint {
  return BigInt(hex.startsWith('0x') ? hex : '0x' + hex);
}

/**
 * Convert bigint to bytes
 */
export function toBytes(value: bigint, length = 32): Uint8Array {
  const hex = value.toString(16).padStart(length * 2, '0');
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to bigint
 */
export function fromBytes(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

/**
 * Check if value is valid field element
 */
export function isValidFieldElement(value: bigint): boolean {
  return value >= 0n && value < FIELD_SIZE;
}

/**
 * Validate Ethereum address
 */
export function isValidAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wrap a promise with a timeout (audit Issue 12).
 *
 * The underlying work may keep running — snarkjs proof generation cannot be
 * truly aborted — but the returned promise rejects after `ms` so callers are
 * not blocked indefinitely on a slow prover / RPC.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label = 'operation'
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms
    );
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}

/**
 * Retry function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  maxRetries = 3,
  baseDelay = 1000
): Promise<T> {
  let lastError: Error | undefined;

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (i < maxRetries - 1) {
        await sleep(baseDelay * Math.pow(2, i));
      }
    }
  }

  throw lastError;
}

