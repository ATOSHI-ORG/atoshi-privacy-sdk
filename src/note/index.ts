/**
 * Note module
 * 
 * Note structure and management for privacy transactions.
 */

import { NoteData, SerializedNote, FIELD_SIZE } from '../types';
import { poseidonHash, randomFieldElement } from '../utils';

/**
 * Note class representing a private asset
 */
export class Note {
  private data: NoteData;

  constructor(data: Partial<NoteData> & { amount: bigint; tokenId: bigint; owner: bigint }) {
    this.data = {
      amount: data.amount,
      tokenId: data.tokenId,
      owner: data.owner,
      blinding: data.blinding ?? randomFieldElement(),
      commitment: data.commitment,
      leafIndex: data.leafIndex,
    };
  }

  /**
   * Create note from serialized data
   */
  static fromSerialized(data: SerializedNote): Note {
    return new Note({
      amount: BigInt(data.amount),
      tokenId: BigInt(data.tokenId),
      owner: BigInt(data.owner),
      blinding: BigInt(data.blinding),
      commitment: data.commitment ? BigInt(data.commitment) : undefined,
      leafIndex: data.leafIndex,
    });
  }

  /**
   * Compute commitment
   * commitment = Poseidon(amount, tokenId, owner, blinding)
   */
  async computeCommitment(poseidon: any, F: any): Promise<bigint> {
    if (this.data.commitment) {
      return this.data.commitment;
    }

    this.data.commitment = await poseidonHash(
      [this.data.amount, this.data.tokenId, this.data.owner, this.data.blinding],
      poseidon,
      F
    );

    return this.data.commitment;
  }

  /**
   * Get commitment (must be computed first)
   */
  getCommitment(): bigint | undefined {
    return this.data.commitment;
  }

  /**
   * Compute nullifier
   * nullifier = Poseidon(commitment, privateKey, leafIndex)
   */
  async computeNullifier(
    privateKey: bigint,
    poseidon: any,
    F: any
  ): Promise<bigint> {
    if (!this.data.commitment) {
      throw new Error('Commitment not computed');
    }
    if (this.data.leafIndex === undefined) {
      throw new Error('Leaf index not set');
    }

    return poseidonHash(
      [this.data.commitment, privateKey, BigInt(this.data.leafIndex)],
      poseidon,
      F
    );
  }

  /**
   * Set leaf index
   */
  setLeafIndex(index: number): void {
    this.data.leafIndex = index;
  }

  /**
   * Get leaf index
   */
  getLeafIndex(): number | undefined {
    return this.data.leafIndex;
  }

  /**
   * Get note data
   */
  toData(): NoteData {
    return { ...this.data };
  }

  /**
   * Serialize note
   */
  serialize(): SerializedNote {
    return {
      amount: this.data.amount.toString(),
      tokenId: this.data.tokenId.toString(),
      owner: this.data.owner.toString(),
      blinding: this.data.blinding.toString(),
      commitment: this.data.commitment?.toString(),
      leafIndex: this.data.leafIndex,
    };
  }

  /**
   * Get amount
   */
  get amount(): bigint {
    return this.data.amount;
  }

  /**
   * Get token ID
   */
  get tokenId(): bigint {
    return this.data.tokenId;
  }

  /**
   * Get owner
   */
  get owner(): bigint {
    return this.data.owner;
  }

  /**
   * Get blinding
   */
  get blinding(): bigint {
    return this.data.blinding;
  }
}

/**
 * Note manager for handling multiple notes
 */
export class NoteManager {
  private notes: Map<string, Note> = new Map();

  /**
   * Add a note
   */
  add(note: Note): void {
    const commitment = note.getCommitment();
    if (!commitment) {
      throw new Error('Note commitment not computed');
    }
    this.notes.set(commitment.toString(), note);
  }

  /**
   * Get note by commitment
   */
  get(commitment: bigint): Note | undefined {
    return this.notes.get(commitment.toString());
  }

  /**
   * Get all notes
   */
  getAll(): Note[] {
    return Array.from(this.notes.values());
  }

  /**
   * Remove a note
   */
  remove(commitment: bigint): boolean {
    return this.notes.delete(commitment.toString());
  }

  /**
   * Get notes by token
   */
  getByToken(tokenId: bigint): Note[] {
    return this.getAll().filter((note) => note.tokenId === tokenId);
  }

  /**
   * Get total balance for a token
   */
  getBalance(tokenId: bigint): bigint {
    return this.getByToken(tokenId).reduce(
      (sum, note) => sum + note.amount,
      0n
    );
  }

  /**
   * Clear all notes
   */
  clear(): void {
    this.notes.clear();
  }

  /**
   * Get count
   */
  get count(): number {
    return this.notes.size;
  }
}

export default Note;

