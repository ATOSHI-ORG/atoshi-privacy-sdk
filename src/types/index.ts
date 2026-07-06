/**
 * Type definitions for Atoshi Privacy SDK
 */

import { BigNumberish } from 'ethers';

/**
 * Field size for BN254 curve
 */
export const FIELD_SIZE = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

/**
 * Keypair for privacy transactions
 */
export interface Keypair {
  privateKey: bigint;
  publicKey: bigint;
}

/**
 * Note structure representing a private asset
 */
export interface NoteData {
  amount: bigint;
  tokenId: bigint;
  owner: bigint;
  blinding: bigint;
  commitment?: bigint;
  leafIndex?: number;
}

/**
 * Serialized note for storage
 */
export interface SerializedNote {
  amount: string;
  tokenId: string;
  owner: string;
  blinding: string;
  commitment?: string;
  leafIndex?: number;
}

/**
 * Note status
 */
export enum NoteStatus {
  Pending = 'pending',
  Committed = 'committed',
  Spent = 'spent',
}

/**
 * Note record with metadata
 */
export interface NoteRecord {
  note: NoteData;
  status: NoteStatus;
  createdAt: Date;
  spentAt?: Date;
  depositTxHash?: string;
  spendTxHash?: string;
}

/**
 * Merkle proof for membership verification
 */
export interface MerkleProof {
  leaf: bigint;
  leafIndex: number;
  pathElements: bigint[];
  pathIndices: number[];
  root: bigint;
}

/**
 * ZK proof data
 */
export interface ZkProof {
  pA: [string, string];
  pB: [[string, string], [string, string]];
  pC: [string, string];
}

/**
 * Deposit transaction parameters
 */
export interface DepositParams {
  amount: BigNumberish;
  tokenAddress: string;
  recipient?: bigint; // Recipient public key (default: self)
  /**
   * Recipient's 32-byte X25519 viewing public key. The note's
   * {amount,tokenId,blinding} is encrypted to this and emitted on-chain so the
   * recipient can recover the note by scanning (audit Issue 6). Defaults to the
   * depositor's own viewing pubkey (deposit-to-self).
   */
  recipientViewingPubKey?: Uint8Array;
}

/**
 * Withdraw transaction parameters
 */
export interface WithdrawParams {
  noteIndex: number;
  recipient: string;
  relayer?: string;
  fee?: BigNumberish;
}

/**
 * Transfer transaction parameters
 */
export interface TransferParams {
  noteIndex: number;
  recipientPublicKey: bigint;
  /**
   * Recipient's 32-byte X25519 viewing public key. The output note's
   * {amount,tokenId,blinding} is encrypted to this and emitted on-chain so the
   * recipient can recover the note by scanning (audit Issue 6). Required for a
   * real recipient; may be omitted only for a self-transfer (defaults to the
   * sender's own viewing pubkey).
   */
  recipientViewingPubKey?: Uint8Array;
  // NOTE: V1 transfers move the FULL input note only. The transfer circuit
  // enforces inAmount === outAmount (no change/split output), so a partial
  // amount cannot produce a verifiable proof. A split-note `amount` field
  // was removed here (audit Issue 9); change-note support is a V2 item that
  // requires coordinated circuit + contract + SDK changes.
}

/**
 * Transaction result
 */
export interface TransactionResult {
  success: boolean;
  txHash?: string;
  leafIndex?: number;
  newRoot?: string;
  error?: string;
}

/**
 * Node state
 */
export interface NodeState {
  merkleRoot: string;
  nextIndex: number;
  nullifiersCount: number;
}

/**
 * SDK configuration.
 *
 * There is a single canonical SdkConfig defined in ../config (the rich,
 * multi-network shape used by the built-in TESTNET_CONFIG / MAINNET_CONFIG).
 * It is re-exported here so `import { SdkConfig } from '../types'` and the
 * package-root export resolve to the SAME type — the previous duplicate
 * definition (missing nodeUrl) caused a real type mismatch (audit Q7).
 */
export type { SdkConfig } from '../config';

/**
 * Wallet configuration
 */
export interface WalletConfig {
  /** Storage key prefix */
  storagePrefix?: string;

  /** Auto-sync notes on init */
  autoSync?: boolean;

  /**
   * Chain id of the network whose Shield this wallet's notes belong to.
   * Notes / leafIndex are chain-specific (a leaf position in one chain's
   * Shield tree is meaningless on another), so backups are stamped with this
   * and a restore onto a different chainId is rejected (audit Q5). The derived
   * keys themselves are chain-independent by design.
   */
  chainId?: number;
}

