// Key derivation + encrypted backup primitives for the Atoshi privacy
// wallet. The flows in this file solve the recovery problem:
//
//   "User installs the DApp on a new device. They have only their
//    Ethereum wallet (MetaMask) or a 12-word mnemonic. How do they get
//    back their notes?"
//
// We support two equivalent paths to a master seed:
//
//   1. EIP-712 signature path (recommended for normal users)
//      User signs a deterministic typed-data message with their EOA
//      key. The signature is hashed to a 32-byte master_seed. As long
//      as the user has the same MetaMask account, signing again
//      reproduces the same seed — no extra phrase to remember.
//
//   2. Mnemonic path (power users / cross-wallet portability)
//      Standard BIP-39 12/24-word phrase -> seed via PBKDF2.
//
// From the master_seed we derive three subkeys via HKDF-SHA256, each
// with a distinct "info" string so they are domain-separated:
//
//   spending_key   - used to compute Note nullifiers (must stay secret)
//   viewing_key    - decrypts EncryptedNote events (read-only sharable)
//   encryption_key - AES-GCM key for local Note backups
//
// Note encrypted backups use AES-256-GCM with a random 12-byte IV.
// Output blob is { v: 1, iv, ct } JSON; a passphrase variant is
// available too for users who prefer not to involve a wallet at all.

import {
  Mnemonic,
  Wallet,
  computeHmac,
  getBytes,
  hexlify,
  TypedDataEncoder,
} from "ethers";

const TEXT_ENC = new TextEncoder();
const TEXT_DEC = new TextDecoder();

const FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

// EIP-712 domain + message used to derive the master seed. Hard-coded
// so re-signing on any device produces the same signature -> seed.
export const DOMAIN_NAME = "Atoshi Privacy";
export const DOMAIN_VERSION = "1";

// Empty chainId means the signature is portable across L1 / L2 — the
// note-decrypt key is the SAME no matter which chain the user is on.
export const SEED_DERIVATION_TYPED_DATA = {
  domain: {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
  },
  types: {
    AtoshiPrivacyKeyDerivation: [
      { name: "purpose", type: "string" },
      { name: "version", type: "uint256" },
    ],
  },
  primaryType: "AtoshiPrivacyKeyDerivation",
  message: {
    purpose:
      "Sign this message ONLY on the official Atoshi DApp to derive your privacy keys. " +
      "DO NOT sign this on any other site — the signer can decrypt your notes.",
    version: 1n,
  },
};

/** A 32-byte master seed used to derive viewing/spending/encryption keys. */
export type Seed = Uint8Array;

export interface DerivedKeys {
  /** Used to generate Note nullifiers (Poseidon-domain field element). */
  spendingKey: bigint;
  /** Used to decrypt EncryptedNote events for incoming Notes. */
  viewingKey: bigint;
  /** Raw 32-byte AES-256-GCM key for local backups. */
  encryptionKey: Uint8Array;
}

// ============================================================
// 1. EIP-712 path
// ============================================================

/**
 * Compute the typed-data hash that a user signs with their EOA wallet
 * (MetaMask, etc) to prove they want to derive privacy keys for THIS
 * domain + version. Two devices using the same EOA produce the same
 * hash, hence the same signature, hence the same seed.
 */
export function getSeedDerivationDigest(): string {
  return TypedDataEncoder.hash(
    SEED_DERIVATION_TYPED_DATA.domain,
    SEED_DERIVATION_TYPED_DATA.types,
    SEED_DERIVATION_TYPED_DATA.message,
  );
}

/**
 * Convenience helper for tests / Node-side automation: signs the
 * derivation typed data with a given private key and returns the seed.
 *
 * In a browser, the signing happens via MetaMask's
 * `signer.signTypedData(...)` and you pass the resulting signature
 * into `seedFromEIP712Signature` directly.
 */
export async function signSeedDerivation(privateKey: string): Promise<string> {
  const wallet = new Wallet(privateKey);
  return wallet.signTypedData(
    SEED_DERIVATION_TYPED_DATA.domain,
    SEED_DERIVATION_TYPED_DATA.types,
    SEED_DERIVATION_TYPED_DATA.message,
  );
}

/**
 * Convert a hex EIP-712 signature into a 32-byte master seed via
 * SHA-256 (computeHmac with empty key collapses to HMAC(sig, "") which
 * is unsuitable here — use SHA-256 of the signature bytes instead).
 *
 * The signature is 65 bytes (r || s || v). SHA-256 collapses to 32
 * bytes deterministically regardless of v parity, so the seed is the
 * same whether the wallet returns 27/28 or 0/1 for v.
 */
export async function seedFromEIP712Signature(signature: string): Promise<Seed> {
  const sig = getBytes(signature);
  if (sig.length !== 65) {
    throw new Error(
      `expected 65-byte EIP-712 signature, got ${sig.length} bytes`,
    );
  }
  // Drop v byte so seed is independent of the recovery-id encoding the
  // wallet picks (some return 27/28, some 0/1).
  const sigNoV = sig.slice(0, 64);
  const hash = await crypto.subtle.digest("SHA-256", sigNoV);
  return new Uint8Array(hash);
}

// ============================================================
// 2. Mnemonic path
// ============================================================

/**
 * BIP-39 mnemonic -> 64-byte seed (PBKDF2 with the standard
 * "mnemonic" + passphrase salt). We hash the result down to 32 bytes
 * so callers always work with a consistent Seed length.
 */
export async function seedFromMnemonic(
  phrase: string,
  passphrase = "",
): Promise<Seed> {
  const m = Mnemonic.fromPhrase(phrase.trim(), passphrase);
  const longSeed = getBytes(m.computeSeed()); // 64 bytes
  const hash = await crypto.subtle.digest("SHA-256", longSeed);
  return new Uint8Array(hash);
}

/**
 * Generate a fresh BIP-39 mnemonic suitable for showing to the user
 * during onboarding. Default 12 words = 128 bits of entropy.
 */
export function generateMnemonic(strengthBits: 128 | 256 = 128): string {
  // ethers' fromEntropy expects a hex string of the entropy bytes.
  const entropy = crypto.getRandomValues(new Uint8Array(strengthBits / 8));
  return Mnemonic.fromEntropy(hexlify(entropy)).phrase;
}

// ============================================================
// 3. HKDF -> three derived keys
// ============================================================

/**
 * RFC 5869 HKDF-SHA256. We expose only `extract+expand` combined for
 * the call-sites we actually use, and pull a domain-separated 32-byte
 * key per `info` label.
 */
async function hkdfSha256(
  ikm: Uint8Array,
  info: string,
  length = 32,
): Promise<Uint8Array> {
  const salt = TEXT_ENC.encode("atoshi-privacy-hkdf-v1");
  // computeHmac is HMAC-SHA256: HKDF-Extract = HMAC(salt, IKM)
  const prk = getBytes(computeHmac("sha256", salt, ikm));
  // HKDF-Expand: T(1) = HMAC(prk, info || 0x01); we only need length<=32
  // so a single-block expansion is enough.
  if (length > 32) {
    throw new Error("hkdfSha256 implementation only supports length <= 32");
  }
  const infoBytes = TEXT_ENC.encode(info);
  const expandInput = new Uint8Array(infoBytes.length + 1);
  expandInput.set(infoBytes, 0);
  expandInput[infoBytes.length] = 0x01;
  const out = getBytes(computeHmac("sha256", prk, expandInput));
  return out.slice(0, length);
}

/**
 * Reduce a 32-byte HKDF output into a BN254 scalar field element.
 * Standard "reduce mod q" approach; the bias from rejection-free
 * truncation is negligible (~2^-128) given the field size.
 */
function bytesToFieldElement(bytes: Uint8Array): bigint {
  const hex = "0x" + Buffer.from(bytes).toString("hex");
  return BigInt(hex) % FIELD_SIZE;
}

/**
 * Derive the three privacy keys from a master seed. The labels MUST
 * stay stable for the lifetime of the protocol — changing them would
 * silently break recovery for every existing user.
 */
export async function deriveKeysFromSeed(seed: Seed): Promise<DerivedKeys> {
  const [spendBytes, viewBytes, encBytes] = await Promise.all([
    hkdfSha256(seed, "atoshi-privacy/spending"),
    hkdfSha256(seed, "atoshi-privacy/viewing"),
    hkdfSha256(seed, "atoshi-privacy/encryption"),
  ]);
  return {
    spendingKey: bytesToFieldElement(spendBytes),
    viewingKey: bytesToFieldElement(viewBytes),
    encryptionKey: encBytes,
  };
}

// ============================================================
// 4. AES-256-GCM encrypted Note backup
// ============================================================

export interface EncryptedBackup {
  v: 1;
  iv: string; // hex
  ct: string; // hex (ciphertext + auth tag, as returned by SubtleCrypto)
}

// `any` for the return type and string[] for usages because this file
// targets both Node (test runtime) and browsers; pulling in `lib: "dom"`
// from tsconfig just for these two names brings in thousands of unused
// global types that pollute IntelliSense in the rest of the package.
async function importAesKey(
  key: Uint8Array,
  usage: ('encrypt' | 'decrypt')[],
): Promise<any> {
  return crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM", length: 256 },
    false,
    usage,
  );
}

/**
 * Encrypt a JSON-serializable wallet snapshot with the user's
 * encryption key. Output is a small JSON blob safe to store anywhere
 * (localStorage, IPFS, or as an EncryptedNote event on chain).
 */
export async function encryptBackup(
  data: string,
  encryptionKey: Uint8Array,
): Promise<EncryptedBackup> {
  const key = await importAesKey(encryptionKey, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    TEXT_ENC.encode(data),
  );
  return {
    v: 1,
    iv: hexlify(iv),
    ct: hexlify(new Uint8Array(ct)),
  };
}

/**
 * Decrypt a backup produced by `encryptBackup`. Throws if the
 * encryption key is wrong (AES-GCM auth tag rejects on mismatch).
 */
export async function decryptBackup(
  blob: EncryptedBackup,
  encryptionKey: Uint8Array,
): Promise<string> {
  if (blob.v !== 1) {
    throw new Error(`unsupported backup version: ${blob.v}`);
  }
  const key = await importAesKey(encryptionKey, ["decrypt"]);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: getBytes(blob.iv) },
    key,
    getBytes(blob.ct),
  );
  return TEXT_DEC.decode(pt);
}

// ============================================================
// 5. Optional: passphrase-only path (no wallet, no mnemonic)
// ============================================================

/**
 * Derive a seed from a user-chosen passphrase via Argon2id-equivalent
 * stretching. Web Crypto only ships PBKDF2, so we use 600k iterations
 * of PBKDF2-SHA256 — the same setting OWASP recommends for password
 * vaults. Slower than Argon2id (no memory-hardness) but available
 * everywhere without a polyfill.
 */
export async function seedFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
): Promise<Seed> {
  if (salt.length < 16) {
    throw new Error("passphrase salt must be >= 16 bytes");
  }
  const baseKey = await crypto.subtle.importKey(
    "raw",
    TEXT_ENC.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 600_000, hash: "SHA-256" },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}
