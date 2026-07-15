/**
 * Atoshi Privacy SDK
 * 
 * TypeScript SDK for privacy transactions on Atoshi Chain.
 */

// Core exports
export { PrivacyWallet } from './wallet';
export { Note, NoteManager } from './note';
export { TransactionBuilder } from './tx';
export { PrivacyRpcClient } from './rpc';

// EncryptedNote (Zcash/Aztec pattern: encrypt to recipient.viewingPubKey,
// emit on-chain, receiver scans and decrypts with viewingKey).
export {
  eciesEncrypt,
  eciesDecrypt,
  encryptNote,
  decryptNote,
  viewingPubKey,
  viewingKeyToBytes,
} from './crypto/ecies';
export type { NotePlaintext } from './crypto/ecies';

// EIP-712 seed derivation: users sign SEED_DERIVATION_TYPED_DATA with their
// EOA (MetaMask) and pass the signature to PrivacyWallet.initFromEIP712Signature
// to derive the full privacy key set (spending/viewing/encryption).
export {
  SEED_DERIVATION_TYPED_DATA,
  getSeedDerivationDigest,
  seedFromEIP712Signature,
  // Pure derivation / backup helpers. These are stateless functions (they hold
  // no key material), so exposing them does not reopen audit Issue 8 (which hid
  // stateful key-material getters). H5 integrators need them to derive the key
  // set and to align with the SDK's canonical derivation instead of hand-rolling
  // seed→key math. Referenced by H5_INTEGRATION.md §2/§6.
  seedFromMnemonic,
  generateMnemonic,
  deriveKeysFromSeed,
  encryptBackup,
  decryptBackup,
} from './wallet/derivation';
export type { DerivedKeys, EncryptedBackup } from './wallet/derivation';

// Chain scanner: 增量扫 Shield 事件,自动恢复属于本人的 Note (跨设备恢复用).
export { ChainScanner } from './scanner';
export type { ScannerConfig, RecoveredNote } from './scanner';

// Poseidon helpers (commitment / nullifier / owner pubkey / blinding).
export {
  poseidonHash,
  computeCommitment,
  computeNullifier,
  deriveOwnerPubkey,
  randomBlinding,
  buildZeros,
  BN254_FIELD_SIZE,
} from './poseidon';

// Off-chain Merkle tree reconstruction (Unshield / Transfer 生成 proof 必须).
export { rebuildMerkleTree } from './merkle';
export type { MerklePath, MerkleTreeData } from './merkle';

// Typed errors: consumers can `instanceof AtoshiSdkError` / branch on `.code`
// instead of string-matching messages (audit Q8).
export * from './errors';

// Types
export * from './types';

// Utilities
export * from './utils';

// Network configuration (multi-network: testnet + mainnet).
// Consumers pick a network with:
//   import { MAINNET_CONFIG, getConfigByChainId } from '@atoshi/privacy-sdk';
export {
  TESTNET_CONFIG,
  MAINNET_CONFIG,
  NETWORKS,
  getConfigByChainId,
  DEFAULT_CONFIG,
  validateConfig,
} from './config';
// SdkConfig (canonical, defined in ./config) is surfaced via `export * from
// './types'`, which re-exports it — single source of truth (audit Q7).

// Version
export const VERSION = '0.4.1';

