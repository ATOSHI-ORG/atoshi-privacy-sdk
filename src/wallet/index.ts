/**
 * Privacy Wallet
 * 
 * Manages keypairs, notes, and privacy transactions.
 */

import { buildPoseidon } from 'circomlibjs';
import { Keypair, NoteData, NoteRecord, NoteStatus, WalletConfig, FIELD_SIZE } from '../types';
import { Note } from '../note';
import { randomFieldElement, poseidonHash } from '../utils';

/**
 * Privacy wallet for managing private assets
 */
export class PrivacyWallet {
  private poseidon: any;
  private F: any;
  private keypair: Keypair | null = null;
  private notes: Map<string, NoteRecord> = new Map();
  private config: WalletConfig;
  private initialized = false;

  constructor(config: WalletConfig = {}) {
    this.config = {
      storagePrefix: 'atoshi_privacy_',
      autoSync: true,
      ...config,
    };
  }

  /**
   * Initialize the wallet
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    this.poseidon = await buildPoseidon();
    this.F = this.poseidon.F;
    this.initialized = true;
  }

  /**
   * Ensure wallet is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('Wallet not initialized. Call init() first.');
    }
  }

  /**
   * Generate a new keypair
   */
  async generateKeypair(): Promise<Keypair> {
    this.ensureInitialized();

    const privateKey = randomFieldElement();
    const publicKey = await this.derivePublicKey(privateKey);

    this.keypair = { privateKey, publicKey };
    return this.keypair;
  }

  /**
   * Import keypair from private key
   */
  async importKeypair(privateKey: bigint): Promise<Keypair> {
    this.ensureInitialized();

    if (privateKey >= FIELD_SIZE) {
      throw new Error('Private key exceeds field size');
    }

    const publicKey = await this.derivePublicKey(privateKey);
    this.keypair = { privateKey, publicKey };
    return this.keypair;
  }

  /**
   * Derive public key from private key
   */
  async derivePublicKey(privateKey: bigint): Promise<bigint> {
    this.ensureInitialized();
    return poseidonHash([privateKey], this.poseidon, this.F);
  }

  /**
   * Get current keypair
   */
  getKeypair(): Keypair | null {
    return this.keypair;
  }

  /**
   * Get public key
   */
  getPublicKey(): bigint | null {
    return this.keypair?.publicKey ?? null;
  }

  /**
   * Create a new note
   */
  async createNote(
    amount: bigint,
    tokenId: bigint,
    recipient?: bigint
  ): Promise<Note> {
    this.ensureInitialized();

    const owner = recipient ?? this.keypair?.publicKey;
    if (!owner) {
      throw new Error('No recipient specified and no keypair loaded');
    }

    const note = new Note({
      amount,
      tokenId,
      owner,
      blinding: randomFieldElement(),
    });

    await note.computeCommitment(this.poseidon, this.F);
    return note;
  }

  /**
   * Add a note to the wallet
   */
  addNote(note: Note): void {
    const commitment = note.getCommitment();
    if (!commitment) {
      throw new Error('Note commitment not computed');
    }

    const key = commitment.toString();
    this.notes.set(key, {
      note: note.toData(),
      status: NoteStatus.Pending,
      createdAt: new Date(),
    });
  }

  /**
   * Mark note as committed (in Merkle tree)
   */
  markNoteCommitted(commitment: bigint, leafIndex: number, txHash: string): void {
    const key = commitment.toString();
    const record = this.notes.get(key);
    
    if (record) {
      record.status = NoteStatus.Committed;
      record.note.leafIndex = leafIndex;
      record.depositTxHash = txHash;
    }
  }

  /**
   * Mark note as spent
   */
  markNoteSpent(commitment: bigint, txHash: string): void {
    const key = commitment.toString();
    const record = this.notes.get(key);
    
    if (record) {
      record.status = NoteStatus.Spent;
      record.spentAt = new Date();
      record.spendTxHash = txHash;
    }
  }

  /**
   * Get all notes
   */
  getAllNotes(): NoteRecord[] {
    return Array.from(this.notes.values());
  }

  /**
   * Get unspent notes
   */
  getUnspentNotes(): NoteRecord[] {
    return this.getAllNotes().filter(
      (record) => record.status === NoteStatus.Committed
    );
  }

  /**
   * Get note by index
   */
  getNoteByIndex(leafIndex: number): NoteRecord | undefined {
    return this.getAllNotes().find(
      (record) => record.note.leafIndex === leafIndex
    );
  }

  /**
   * Get total balance for a token
   */
  getBalance(tokenId: bigint): bigint {
    return this.getUnspentNotes()
      .filter((record) => record.note.tokenId === tokenId)
      .reduce((sum, record) => sum + record.note.amount, 0n);
  }

  /**
   * Compute nullifier for a note
   */
  async computeNullifier(note: NoteData): Promise<bigint> {
    this.ensureInitialized();

    if (!this.keypair) {
      throw new Error('No keypair loaded');
    }

    if (note.leafIndex === undefined) {
      throw new Error('Note not committed (no leaf index)');
    }

    const commitment = note.commitment ?? await poseidonHash(
      [note.amount, note.tokenId, note.owner, note.blinding],
      this.poseidon,
      this.F
    );

    return poseidonHash(
      [commitment, this.keypair.privateKey, BigInt(note.leafIndex)],
      this.poseidon,
      this.F
    );
  }

  /**
   * Export wallet data for backup
   */
  export(): string {
    if (!this.keypair) {
      throw new Error('No keypair to export');
    }

    const data = {
      privateKey: this.keypair.privateKey.toString(),
      notes: Array.from(this.notes.entries()).map(([key, record]) => ({
        key,
        note: {
          amount: record.note.amount.toString(),
          tokenId: record.note.tokenId.toString(),
          owner: record.note.owner.toString(),
          blinding: record.note.blinding.toString(),
          commitment: record.note.commitment?.toString(),
          leafIndex: record.note.leafIndex,
        },
        status: record.status,
        createdAt: record.createdAt.toISOString(),
        spentAt: record.spentAt?.toISOString(),
        depositTxHash: record.depositTxHash,
        spendTxHash: record.spendTxHash,
      })),
    };

    return JSON.stringify(data);
  }

  /**
   * Import wallet data from backup
   */
  async import(data: string): Promise<void> {
    this.ensureInitialized();

    const parsed = JSON.parse(data);
    
    // Import keypair
    await this.importKeypair(BigInt(parsed.privateKey));

    // Import notes
    this.notes.clear();
    for (const item of parsed.notes) {
      this.notes.set(item.key, {
        note: {
          amount: BigInt(item.note.amount),
          tokenId: BigInt(item.note.tokenId),
          owner: BigInt(item.note.owner),
          blinding: BigInt(item.note.blinding),
          commitment: item.note.commitment ? BigInt(item.note.commitment) : undefined,
          leafIndex: item.note.leafIndex,
        },
        status: item.status,
        createdAt: new Date(item.createdAt),
        spentAt: item.spentAt ? new Date(item.spentAt) : undefined,
        depositTxHash: item.depositTxHash,
        spendTxHash: item.spendTxHash,
      });
    }
  }
}

export default PrivacyWallet;

