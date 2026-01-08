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

// Types
export * from './types';

// Utilities
export * from './utils';

// Version
export const VERSION = '0.1.0';

