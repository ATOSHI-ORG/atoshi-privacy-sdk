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
  amount?: BigNumberish; // Optional: split note
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
 * SDK configuration
 */
export interface SdkConfig {
  /** Privacy node RPC URL */
  nodeUrl: string;
  
  /** L1 chain RPC URL */
  l1RpcUrl: string;
  
  /** Shield contract address */
  shieldContract: string;
  
  /** Path to circuit WASM files */
  circuitsPath?: string;
  
  /** Path to proving keys */
  keysPath?: string;
}

/**
 * Wallet configuration
 */
export interface WalletConfig {
  /** Storage key prefix */
  storagePrefix?: string;
  
  /** Auto-sync notes on init */
  autoSync?: boolean;
}

