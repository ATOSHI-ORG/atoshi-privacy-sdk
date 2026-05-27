/**
 * ECIES (Elliptic Curve Integrated Encryption Scheme) using X25519 + AES-256-GCM.
 *
 * Use case: encrypt Note data so only the recipient (who holds the corresponding
 * viewingKey) can decrypt it. The encrypted blob goes on-chain in Deposit /
 * Transfer events; the recipient scans these and tries decrypting each one.
 *
 * Scheme:
 *   - recipient holds a 32-byte viewingKey, derived from EIP-712 + HKDF
 *   - viewingKey is interpreted as a X25519 private key (clamped per RFC 7748)
 *   - recipient's viewingPubKey = X25519.getPublicKey(viewingKey)
 *   - sender generates ephemeral X25519 keypair (e, E)
 *   - shared = X25519(e, viewingPubKey)
 *   - aesKey = SHA-256(shared || E)
 *   - iv = 12 random bytes
 *   - ciphertext = AES-256-GCM(plaintext, aesKey, iv)   (16-byte tag appended)
 *
 * Wire format (concatenated bytes):
 *   [0..32)    ephemeral public key E    (32 bytes)
 *   [32..44)   iv                        (12 bytes)
 *   [44..]     ciphertext || gcm_tag     (variable)
 *
 * Decryption (recipient side):
 *   shared = X25519(viewingKey, E)
 *   aesKey = SHA-256(shared || E)
 *   plaintext = AES-256-GCM-decrypt(ciphertext, aesKey, iv)
 *
 * Note: this is a standard scheme used by Zcash sapling and many ZK projects.
 * Uses @noble/curves for portability (works in Node + browser + RN).
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Convert a viewingKey (BigInt from HKDF) into a 32-byte X25519 private key.
 * X25519 clamps the scalar internally so any 32 bytes work as input.
 */
export function viewingKeyToBytes(viewingKey: bigint): Uint8Array {
  const hex = viewingKey.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Derive the public key for a given viewingKey.
 * The pubkey is what gets shared with senders so they can encrypt Notes to you.
 */
export function viewingPubKey(viewingKey: bigint): Uint8Array {
  const priv = viewingKeyToBytes(viewingKey);
  return x25519.getPublicKey(priv);
}

/**
 * Encrypt arbitrary bytes for a recipient identified by their X25519 pubkey.
 * Returns the wire-format blob (ephemeralPub || iv || ciphertextWithTag).
 *
 * @param plaintext   Bytes to encrypt (e.g. JSON-serialized Note)
 * @param recipientPubKey  32-byte X25519 public key (recipient.viewingPubKey)
 * @returns           Encrypted blob (>= 60 bytes for any payload)
 */
export async function eciesEncrypt(
  plaintext: Uint8Array,
  recipientPubKey: Uint8Array
): Promise<Uint8Array> {
  if (recipientPubKey.length !== 32) {
    throw new Error('recipientPubKey must be 32 bytes (X25519)');
  }

  // 1. Ephemeral X25519 keypair (one-time per message)
  const ephemeralPriv = crypto.getRandomValues(new Uint8Array(32));
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv);

  // 2. ECDH shared secret
  const shared = x25519.getSharedSecret(ephemeralPriv, recipientPubKey);

  // 3. Derive AES key: SHA-256(shared || ephemeralPub)
  //    (Binding ephemeralPub into the KDF prevents key reuse if someone reuses
  //    a shared secret across messages.)
  const kdfInput = new Uint8Array(shared.length + ephemeralPub.length);
  kdfInput.set(shared, 0);
  kdfInput.set(ephemeralPub, shared.length);
  const aesKey = sha256(kdfInput);

  // 4. Random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // 5. AES-256-GCM encrypt
  const key = await crypto.subtle.importKey(
    'raw',
    aesKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  const ctWithTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  );

  // 6. Concatenate: ephemeralPub (32) || iv (12) || ciphertext+tag
  const out = new Uint8Array(32 + 12 + ctWithTag.length);
  out.set(ephemeralPub, 0);
  out.set(iv, 32);
  out.set(ctWithTag, 44);
  return out;
}

/**
 * Try to decrypt an ECIES blob with the given viewingKey.
 * Returns the plaintext on success, or null on failure (not addressed to you,
 * corrupted blob, etc).
 *
 * IMPORTANT: this function is ALWAYS expected to be called speculatively
 * against every Deposit/Transfer event (scanner pattern). The "is this mine?"
 * question is answered by "did decryption succeed?" — so it MUST not throw
 * on cryptographic failure, only return null.
 */
export async function eciesDecrypt(
  blob: Uint8Array,
  viewingKey: bigint
): Promise<Uint8Array | null> {
  if (blob.length < 32 + 12 + 16) {
    // 32 (ephemeral pub) + 12 (iv) + 16 (gcm tag minimum)
    return null;
  }

  try {
    const ephemeralPub = blob.subarray(0, 32);
    const iv = blob.subarray(32, 44);
    const ctWithTag = blob.subarray(44);

    const priv = viewingKeyToBytes(viewingKey);
    const shared = x25519.getSharedSecret(priv, ephemeralPub);

    const kdfInput = new Uint8Array(shared.length + ephemeralPub.length);
    kdfInput.set(shared, 0);
    kdfInput.set(ephemeralPub, shared.length);
    const aesKey = sha256(kdfInput);

    const key = await crypto.subtle.importKey(
      'raw',
      aesKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ctWithTag)
    );
    return plaintext;
  } catch {
    // GCM tag mismatch (= not encrypted for me, or tampered blob).
    // Standard library throws OperationError; we suppress and return null.
    return null;
  }
}

/**
 * High-level helper: encrypt a Note's recoverable data as JSON.
 *
 * Recoverable fields (what the receiver needs to spend or recover the Note):
 *   - amount    (BigInt, decimal string)
 *   - tokenId   (BigInt, decimal string)
 *   - blinding  (BigInt, decimal string)
 *   - The receiver computes owner = Poseidon(spendingKey) themselves.
 *   - leafIndex is read from the chain event, not encrypted here.
 */
export interface NotePlaintext {
  amount: string;     // decimal
  tokenId: string;    // decimal
  blinding: string;   // decimal
}

export async function encryptNote(
  plaintext: NotePlaintext,
  recipientViewingPubKey: Uint8Array
): Promise<Uint8Array> {
  const json = JSON.stringify(plaintext);
  const bytes = new TextEncoder().encode(json);
  return eciesEncrypt(bytes, recipientViewingPubKey);
}

export async function decryptNote(
  blob: Uint8Array,
  viewingKey: bigint
): Promise<NotePlaintext | null> {
  const plaintext = await eciesDecrypt(blob, viewingKey);
  if (!plaintext) return null;
  try {
    const text = new TextDecoder().decode(plaintext);
    const obj = JSON.parse(text);
    if (
      typeof obj === 'object' &&
      obj !== null &&
      typeof obj.amount === 'string' &&
      typeof obj.tokenId === 'string' &&
      typeof obj.blinding === 'string'
    ) {
      return obj as NotePlaintext;
    }
    return null; // Decrypted to something, but not a Note plaintext.
  } catch {
    return null;
  }
}
