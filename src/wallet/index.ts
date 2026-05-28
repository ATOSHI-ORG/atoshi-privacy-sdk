/**
 * Privacy Wallet
 * 
 * Manages keypairs, notes, and privacy transactions.
 */

import { buildPoseidon } from 'circomlibjs';
import { Keypair, NoteData, NoteRecord, NoteStatus, WalletConfig, FIELD_SIZE } from '../types';
import { Note } from '../note';
import { randomFieldElement, poseidonHash } from '../utils';
import {
  DerivedKeys,
  EncryptedBackup,
  decryptBackup,
  deriveKeysFromSeed,
  encryptBackup,
  seedFromEIP712Signature,
  seedFromMnemonic,
  seedFromPassphrase,
} from './derivation';

export {
  generateMnemonic,
  seedFromEIP712Signature,
  seedFromMnemonic,
  seedFromPassphrase,
  encryptBackup,
  decryptBackup,
} from './derivation';
export type { EncryptedBackup, DerivedKeys } from './derivation';

/**
 * Privacy wallet for managing private assets
 */
export class PrivacyWallet {
  private poseidon: any;
  private F: any;
  private keypair: Keypair | null = null;
  private notes: Map<string, NoteRecord> = new Map();
  private initialized = false;
  // Held in memory for exportEncrypted / EncryptedNote decoding flows.
  // Lost on page refresh; the user re-derives via the same EIP-712
  // signature or mnemonic on next login.
  private derivedKeys: DerivedKeys | null = null;

  constructor(_config: WalletConfig = {}) {
    // config 当前没被消费,接收参数仅为 API 兼容性
    // 字段被消费时再恢复 this.config = { storagePrefix: 'atoshi_privacy_', autoSync: true, ..._config };
    void _config;
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

  // ==========================================================
  // Recoverable key derivation (Phase 1: cross-device recovery)
  // ==========================================================

  /**
   * Initialize the wallet from a 65-byte EIP-712 signature obtained by
   * the user from MetaMask (or another EOA wallet). Two devices using
   * the same EOA produce the same signature -> same seed -> same
   * privacy keys, so notes are recoverable without managing extra
   * secrets.
   *
   * Flow:
   *   1. Browser: signer.signTypedData(domain, types, message) where
   *      domain/types/message come from
   *      `SEED_DERIVATION_TYPED_DATA` in derivation.ts.
   *   2. Pass the resulting hex signature here.
   *
   * The wallet's main keypair adopts `derivedKeys.spendingKey` as its
   * private key (Poseidon nullifier domain). The viewing key and AES
   * encryption key are stashed for later use by EncryptedNote
   * decoding and exportEncrypted.
   */
  async initFromEIP712Signature(signature: string): Promise<Keypair> {
    this.ensureInitialized();
    const seed = await seedFromEIP712Signature(signature);
    return this.applyDerivedKeys(await deriveKeysFromSeed(seed));
  }

  /**
   * Initialize the wallet from a BIP-39 mnemonic (12 or 24 words).
   * Optional passphrase is the BIP-39 "25th word".
   */
  async initFromMnemonic(phrase: string, passphrase = ''): Promise<Keypair> {
    this.ensureInitialized();
    const seed = await seedFromMnemonic(phrase, passphrase);
    return this.applyDerivedKeys(await deriveKeysFromSeed(seed));
  }

  /**
   * Initialize the wallet from a user-chosen passphrase + a stored salt.
   * The salt MUST be at least 16 bytes and stored alongside the
   * encrypted backup so subsequent logins can re-derive the same key.
   */
  async initFromPassphrase(passphrase: string, salt: Uint8Array): Promise<Keypair> {
    this.ensureInitialized();
    const seed = await seedFromPassphrase(passphrase, salt);
    return this.applyDerivedKeys(await deriveKeysFromSeed(seed));
  }

  /**
   * Read-only access to the viewing/encryption keys derived in
   * initFrom*. The spending key is always exposed via getKeypair().
   * Returns null if the wallet was initialized via generateKeypair()
   * (random key path), which intentionally has no recoverable seed.
   */
  getDerivedKeys(): DerivedKeys | null {
    return this.derivedKeys;
  }

  /** Internal: shared completion path for the three initFrom* methods. */
  private async applyDerivedKeys(keys: DerivedKeys): Promise<Keypair> {
    this.derivedKeys = keys;
    // The Note nullifier circuit treats the spending key as a Poseidon
    // field element. Use it as the wallet's main private key so the
    // existing keypair-based code paths (createNote, computeNullifier,
    // etc.) keep working unchanged.
    return this.importKeypair(keys.spendingKey);
  }

  // ==========================================================
  // Encrypted backup / restore
  // ==========================================================

  /**
   * Encrypt the wallet's full state (keypair + notes) with the
   * derived AES-256-GCM key. The output blob is a small JSON object
   * safe to store in localStorage, IPFS, or as on-chain
   * EncryptedNote events.
   *
   * Requires the wallet was initialized via one of the initFrom*
   * methods so an encryption key is available.
   */
  async exportEncrypted(): Promise<EncryptedBackup> {
    if (!this.derivedKeys) {
      throw new Error(
        'exportEncrypted requires a wallet initialized via initFromEIP712Signature/Mnemonic/Passphrase',
      );
    }
    const json = this.export();
    return encryptBackup(json, this.derivedKeys.encryptionKey);
  }

  /**
   * Decrypt a backup blob produced by `exportEncrypted` and load its
   * keypair + notes into this wallet instance. The encryption key
   * must be the same one the backup was sealed with — typically the
   * caller has already run initFrom* and is now restoring saved
   * notes.
   */
  async importEncrypted(blob: EncryptedBackup): Promise<void> {
    if (!this.derivedKeys) {
      throw new Error(
        'importEncrypted requires the wallet was first initialized via initFrom* so an encryption key is available',
      );
    }
    const json = await decryptBackup(blob, this.derivedKeys.encryptionKey);
    await this.import(json);
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

