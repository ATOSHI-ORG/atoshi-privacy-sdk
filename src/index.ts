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

// Chain scanner: 增量扫 Shield 事件,自动恢复属于本人的 Note (跨设备恢复用).
export { ChainScanner } from './scanner';
export type { ScannerConfig, RecoveredNote } from './scanner';

// Types
export * from './types';

// Utilities
export * from './utils';

// Version
export const VERSION = '0.1.0';

