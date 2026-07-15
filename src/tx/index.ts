/**
 * Transaction Builder
 * 
 * Build and submit privacy transactions.
 */

import { ethers } from 'ethers';
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';

import {
  DepositParams,
  WithdrawParams,
  TransferParams,
  TransactionResult,
  ZkProof,
  MerkleProof,
  SdkConfig,
  NoteStatus,
} from '../types';
import { PrivacyWallet } from '../wallet';
import { Note } from '../note';
import type { RecoveredNote } from '../scanner';
import { PrivacyRpcClient } from '../rpc';
import { encryptNote } from '../crypto/ecies';
import { toHex, fromHex, withTimeout } from '../utils';
import {
  NotInitializedError,
  InvalidParamsError,
  NoteNotFoundError,
  NoteNotCommittedError,
  NoteAlreadySpentError,
  ProofError,
  StaleLeafIndexError,
  AtoshiSdkError,
} from '../errors';

// Upper bound on a single ZK proof generation. snarkjs cannot be truly
// aborted, but this releases the caller if the prover stalls (audit Issue 12).
const PROOF_TIMEOUT_MS = 120_000;

// Shield contract ABI (minimal).
// Signatures updated for audit 2026-06:
//   - deposit() now takes a Groth16 proof tuple (pA, pB, pC) plus
//     encryptedNote, binding amount + tokenId into the proof (Issue 2).
//   - withdraw() public-input shape is unchanged at the function level,
//     but the underlying Verifier circuit grew from 6 to 7 public signals
//     (added relayer) — see audit Issue 4 and the unshield prover
//     input changes in generateWithdrawProof().
//   - transfer() unchanged at the function level.
const SHIELD_ABI = [
  'function deposit(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256 commitment, address token, uint256 amount, bytes encryptedNote) payable',
  'function withdraw(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256 root, uint256 nullifierHash, address recipient, address relayer, uint256 fee, address token, uint256 amount)',
  'function transfer(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256 root, uint256 nullifierHash, uint256 newCommitment, bytes encryptedNote)',
  'function isKnownRoot(uint256 root) view returns (bool)',
  'function isSpent(uint256 nullifierHash) view returns (bool)',
  'function getLastRoot() view returns (uint256)',
];

/**
 * Transaction builder for privacy operations
 */
export class TransactionBuilder {
  private wallet: PrivacyWallet;
  private rpcClient: PrivacyRpcClient;
  private config: SdkConfig;
  // _provider / _F 是给后续 Unshield + Transfer 流程预留的字段,目前未启用
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _provider: ethers.Provider | null = null;
  private signer: ethers.Signer | null = null;
  private shieldContract: ethers.Contract | null = null;
  private poseidon: any;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _F: any;
  private initialized = false;

  constructor(wallet: PrivacyWallet, config: SdkConfig) {
    if (!config.nodeUrl) {
      // nodeUrl is optional on the shared SdkConfig (built-in network configs
      // don't hardcode a privacy-node URL), but TransactionBuilder must have it
      // to submit transfers/withdraws (audit Q7).
      throw new InvalidParamsError(
        'SdkConfig.nodeUrl is required for TransactionBuilder — set it, e.g. ' +
          "{ ...TESTNET_CONFIG, nodeUrl: 'https://<privacy-node>' }"
      );
    }
    this.wallet = wallet;
    this.config = config;
    this.rpcClient = new PrivacyRpcClient(config.nodeUrl);
  }

  /**
   * Initialize the transaction builder
   */
  async init(signer?: ethers.Signer): Promise<void> {
    if (this.initialized) return;

    // Initialize Poseidon
    this.poseidon = await buildPoseidon();
    this._F = this.poseidon.F;

    // Setup provider and signer
    if (signer) {
      this.signer = signer;
      this._provider = signer.provider ?? null;
    } else {
      this._provider = new ethers.JsonRpcProvider(this.config.l1RpcUrl);
    }

    // Setup Shield contract
    if (this.signer) {
      this.shieldContract = new ethers.Contract(
        this.config.shieldContract,
        SHIELD_ABI,
        this.signer
      );
    }

    this.initialized = true;
  }

  /**
   * Ensure builder is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new NotInitializedError('TransactionBuilder not initialized. Call init() first.');
    }
  }

  /**
   * Build and submit a deposit transaction
   */
  async deposit(params: DepositParams): Promise<TransactionResult> {
    this.ensureInitialized();

    if (!this.signer || !this.shieldContract) {
      throw new InvalidParamsError('Signer required for deposit');
    }

    const publicKey = params.recipient ?? this.wallet.getPublicKey();
    if (!publicKey) {
      throw new InvalidParamsError('No recipient specified');
    }

    // Create note
    const amount = BigInt(params.amount.toString());
    const tokenId = params.tokenAddress === ethers.ZeroAddress ? 0n : fromHex(params.tokenAddress);

    const note = await this.wallet.createNote(amount, tokenId, publicKey);
    const commitment = note.getCommitment()!;

    // Generate the deposit ZK proof binding (commitment, amount, tokenId)
    // together. After audit Issue 2 the Shield contract requires this —
    // without it deposit() reverts with "Shield: invalid deposit proof".
    const shieldProof = await this.generateProof('shield', {
      commitment: commitment.toString(),
      amount: amount.toString(),
      tokenId: tokenId.toString(),
      owner: publicKey.toString(),
      blinding: note.blinding.toString(),
    });
    // Encrypt {amount,tokenId,blinding} to the recipient's viewing key and
    // emit it on-chain so the recipient can recover the note by scanning
    // (audit Issue 6). Defaults to the depositor's own viewing pubkey.
    const encryptedNote = await this.buildEncryptedNote(
      note,
      params.recipientViewingPubKey
    );

    // Submit to the Shield contract (deployed on L2). deposit() requires an
    // L2-connected signer; the earlier "Submit to L1" note was wrong — Shield
    // lives on L2 (audit Q5).
    let tx: ethers.TransactionResponse;

    if (params.tokenAddress === ethers.ZeroAddress) {
      // Native token deposit
      tx = await this.shieldContract.deposit(
        shieldProof.pA,
        shieldProof.pB,
        shieldProof.pC,
        commitment,
        ethers.ZeroAddress,
        amount,
        encryptedNote,
        { value: amount }
      );
    } else {
      // ERC20 deposit (requires approval first)
      tx = await this.shieldContract.deposit(
        shieldProof.pA,
        shieldProof.pB,
        shieldProof.pC,
        commitment,
        params.tokenAddress,
        amount,
        encryptedNote
      );
    }

    const receipt = await tx.wait();
    
    if (!receipt) {
      return {
        success: false,
        error: 'Transaction failed',
      };
    }

    // Notify privacy node
    const nodeResult = await this.rpcClient.submitDeposit(
      commitment,
      params.tokenAddress,
      amount,
      receipt.hash
    );

    // The deposit is already on-chain, so always track the note — otherwise a
    // node that hasn't returned a leafIndex yet would drop it from the wallet
    // entirely (audit Issue 11 scenario 1). It stays Pending until the leafIndex
    // is known (from the node here, or later via a chain scan), then upgrades
    // to Committed.
    this.wallet.addNote(note);
    if (nodeResult.success && nodeResult.leafIndex !== undefined) {
      note.setLeafIndex(nodeResult.leafIndex);
      this.wallet.markNoteCommitted(
        commitment,
        nodeResult.leafIndex,
        receipt.hash,
        receipt.blockNumber
      );
    }

    return {
      success: nodeResult.success,
      txHash: receipt.hash,
      leafIndex: nodeResult.leafIndex,
      newRoot: nodeResult.newRoot,
      error: nodeResult.error,
    };
  }

  /**
   * Build and submit a withdraw transaction
   */
  async withdraw(params: WithdrawParams): Promise<TransactionResult> {
    this.ensureInitialized();

    // Get note
    const noteRecord = this.wallet.getNoteByIndex(params.noteIndex);
    if (!noteRecord) {
      throw new NoteNotFoundError();
    }

    const note = noteRecord.note;
    if (note.leafIndex === undefined) {
      throw new NoteNotCommittedError('Note not committed');
    }

    // Get Merkle proof
    const merkleProof = await this.rpcClient.getMerkleProof(note.leafIndex);

    // Reorg guard: the on-chain leaf at our cached index must still equal this
    // note's commitment. If a reorg shifted the position, the cached leafIndex
    // is stale and would produce an invalid proof / wrong nullifier — revert
    // the note to Pending and fail loud instead (audit Issue 14).
    if (note.commitment !== undefined && merkleProof.leaf !== note.commitment) {
      this.wallet.invalidateCommittedNote(note.commitment);
      throw new StaleLeafIndexError();
    }

    // Compute nullifier
    const nullifier = await this.wallet.computeNullifier(note);

    // Check nullifier not spent. If it is (e.g. already spent from another
    // device), reconcile local state so this note stops being offered as
    // spendable (audit Issue 11 scenario 3) before surfacing the error.
    if (await this.rpcClient.isNullifierSpent(nullifier)) {
      // commitment may be undefined on a note restored without it — guard so we
      // surface NoteAlreadySpentError, not an opaque TypeError (audit Q8).
      if (note.commitment !== undefined) {
        this.wallet.markNoteSpent(note.commitment);
      }
      throw new NoteAlreadySpentError();
    }

    // Generate ZK proof. The unshield circuit now binds `relayer` into
    // the public-input vector (audit Issue 3 / contract Issue 4), so
    // callers must specify which relayer will broadcast the tx. When
    // unset, default to address(0) and force fee=0 (the contract
    // requires _relayer != 0 whenever _fee > 0).
    const relayer = params.relayer ?? '0x0000000000000000000000000000000000000000';
    const fee = params.fee ? BigInt(params.fee.toString()) : 0n;
    if (fee > 0n && relayer === '0x0000000000000000000000000000000000000000') {
      throw new InvalidParamsError('A non-zero relayer address is required when fee > 0');
    }
    const proof = await this.generateWithdrawProof(
      note,
      merkleProof,
      params.recipient,
      relayer,
      fee
    );

    // Submit to privacy node
    const result = await this.rpcClient.submitWithdraw(
      proof,
      merkleProof.root,
      nullifier,
      params.recipient,
      note.tokenId === 0n ? ethers.ZeroAddress : toHex(note.tokenId, 40),
      note.amount,
      params.fee ? BigInt(params.fee.toString()) : 0n
    );

    // Once the node accepts the proof the nullifier is spent on-chain
    // regardless of whether a txHash made it back (relayer async / dropped
    // response), so mark spent on success — not only when txHash is present
    // (audit Issue 11 scenario 2).
    if (result.success && note.commitment !== undefined) {
      this.wallet.markNoteSpent(note.commitment, result.txHash);
    }

    return result;
  }

  /**
   * Build and submit a transfer transaction
   */
  async transfer(params: TransferParams): Promise<TransactionResult> {
    this.ensureInitialized();

    // Get input note
    const noteRecord = this.wallet.getNoteByIndex(params.noteIndex);
    if (!noteRecord) {
      throw new NoteNotFoundError();
    }

    const inNote = noteRecord.note;
    if (inNote.leafIndex === undefined) {
      throw new NoteNotCommittedError('Note not committed');
    }

    // Get Merkle proof
    const merkleProof = await this.rpcClient.getMerkleProof(inNote.leafIndex);

    // Reorg guard (audit Issue 14): the leaf at our cached index must still be
    // this note's commitment, else the leafIndex is stale (reorg) and would
    // yield an invalid proof — revert to Pending and fail loud.
    if (inNote.commitment !== undefined && merkleProof.leaf !== inNote.commitment) {
      this.wallet.invalidateCommittedNote(inNote.commitment);
      throw new StaleLeafIndexError();
    }

    // Compute nullifier
    const nullifier = await this.wallet.computeNullifier(inNote);

    // Check nullifier not spent. Reconcile local state before throwing so a
    // note spent elsewhere stops being offered as spendable (audit Issue 11
    // scenario 3).
    if (await this.rpcClient.isNullifierSpent(nullifier)) {
      // Guard commitment (may be undefined on a restored note) so we throw
      // NoteAlreadySpentError rather than an opaque TypeError (audit Q8).
      if (inNote.commitment !== undefined) {
        this.wallet.markNoteSpent(inNote.commitment);
      }
      throw new NoteAlreadySpentError();
    }

    // Create output note. V1 moves the FULL input amount only: the transfer
    // circuit enforces inAmount === outAmount (no change note), so we never
    // split (audit Issue 9).
    const outNote = await this.wallet.createNote(
      inNote.amount,
      inNote.tokenId,
      params.recipientPublicKey
    );
    const outCommitment = outNote.getCommitment()!;

    // Encrypt the output note to the recipient's viewing key so they can
    // recover it by scanning the on-chain Transfer event (audit Issue 6).
    const encryptedNote = await this.buildEncryptedNote(
      outNote,
      params.recipientViewingPubKey
    );

    // Generate ZK proof
    const proof = await this.generateTransferProof(
      inNote,
      merkleProof,
      outNote.toData()
    );

    // Submit to privacy node
    const result = await this.rpcClient.submitTransfer(
      proof,
      merkleProof.root,
      nullifier,
      outCommitment,
      encryptedNote
    );

    // The input nullifier is spent on-chain as soon as the node accepts the
    // proof, so mark the input note spent on success even if no txHash came
    // back (audit Issue 11 scenario 2).
    if (result.success) {
      if (inNote.commitment !== undefined) {
        this.wallet.markNoteSpent(inNote.commitment, result.txHash);
      }

      // If transferring to self, track the new output note. Upgrade it to
      // Committed only once we actually have a leafIndex.
      if (params.recipientPublicKey === this.wallet.getPublicKey()) {
        this.wallet.addNote(outNote);
        if (result.leafIndex !== undefined) {
          outNote.setLeafIndex(result.leafIndex);
          this.wallet.markNoteCommitted(outCommitment, result.leafIndex, result.txHash ?? '');
        }
      }
    }

    return result;
  }

  /**
   * Generate withdraw proof.
   *
   * @param relayer EVM address of the relayer that will submit this
   *                withdraw on-chain. Bound into the proof via audit
   *                Issue 3 (circuit) / Issue 4 (contract) so an MEV
   *                attacker cannot swap _relayer in calldata and steal
   *                the fee. Pass address(0) when self-broadcasting (fee
   *                must be 0 in that case; the contract enforces it).
   */
  private async generateWithdrawProof(
    note: any,
    merkleProof: MerkleProof,
    recipient: string,
    relayer: string,
    fee: bigint
  ): Promise<ZkProof> {
    const keypair = this.wallet.getKeypair();
    if (!keypair) {
      throw new InvalidParamsError('No keypair loaded');
    }

    const input = {
      // Public inputs (7 total — order must match unshield.circom's
      // `component main {public [...]}` declaration).
      root: merkleProof.root.toString(),
      nullifierHash: (await this.wallet.computeNullifier(note)).toString(),
      recipient: BigInt(recipient).toString(),
      relayer: BigInt(relayer).toString(),
      tokenId: note.tokenId.toString(),
      amount: note.amount.toString(),
      fee: fee.toString(),

      // Private inputs
      privateKey: keypair.privateKey.toString(),
      blinding: note.blinding.toString(),
      leafIndex: note.leafIndex!.toString(),
      pathElements: merkleProof.pathElements.map((e) => e.toString()),
      pathIndices: merkleProof.pathIndices.map((i) => i.toString()),
    };

    return this.generateProof('unshield', input);
  }

  /**
   * Generate transfer proof
   */
  private async generateTransferProof(
    inNote: any,
    merkleProof: MerkleProof,
    outNote: any
  ): Promise<ZkProof> {
    const keypair = this.wallet.getKeypair();
    if (!keypair) {
      throw new InvalidParamsError('No keypair loaded');
    }

    const input = {
      // Public inputs
      root: merkleProof.root.toString(),
      nullifierHash: (await this.wallet.computeNullifier(inNote)).toString(),
      newCommitment: outNote.commitment!.toString(),

      // Private inputs - Input Note
      inAmount: inNote.amount.toString(),
      inTokenId: inNote.tokenId.toString(),
      inPrivateKey: keypair.privateKey.toString(),
      inBlinding: inNote.blinding.toString(),
      inLeafIndex: inNote.leafIndex!.toString(),
      pathElements: merkleProof.pathElements.map((e) => e.toString()),
      pathIndices: merkleProof.pathIndices.map((i) => i.toString()),

      // Private inputs - Output Note
      outAmount: outNote.amount.toString(),
      outTokenId: outNote.tokenId.toString(),
      outOwner: outNote.owner.toString(),
      outBlinding: outNote.blinding.toString(),
    };

    return this.generateProof('transfer', input);
  }

  /**
   * Encrypt a note's {amount,tokenId,blinding} to the recipient's viewing key
   * and return it as a hex `bytes` string for the on-chain encryptedNote
   * argument / event (audit Issue 6). Falls back to '0x' when no viewing key is
   * available (e.g. the deprecated generateKeypair path) — the recipient then
   * cannot recover the note by scanning and must already hold it locally.
   */
  private async buildEncryptedNote(
    note: Note,
    recipientViewingPubKey?: Uint8Array
  ): Promise<string> {
    let pubKey = recipientViewingPubKey;
    if (!pubKey) {
      const ownPub = this.wallet.getPublicKey();
      const isSelf = ownPub !== null && note.owner === ownPub;
      if (isSelf) {
        // Self-note: default to our own viewing key. If we don't even have one
        // (deprecated generateKeypair path), emit '0x' — we already hold the
        // note locally, so on-chain recovery isn't needed.
        pubKey = this.wallet.getViewingPubKey() ?? undefined;
        if (!pubKey) {
          console.warn(
            '[atoshi-sdk] no viewing key for self-note; emitting empty ' +
              'encryptedNote (note is already held locally).'
          );
          return '0x';
        }
      } else {
        // External recipient without a viewing key: emitting an empty or
        // own-key note would make the funds UNRECOVERABLE for the recipient
        // (they own the note but can't learn its blinding). Fail loud instead
        // of silently losing it (audit Issue 6).
        throw new InvalidParamsError(
          'recipientViewingPubKey is required when sending to another recipient: ' +
            'without it the recipient cannot recover the note from chain events.'
        );
      }
    }
    const blob = await encryptNote(
      {
        amount: note.amount.toString(),
        tokenId: note.tokenId.toString(),
        blinding: note.blinding.toString(),
      },
      pubKey
    );
    return ethers.hexlify(blob);
  }

  /**
   * Re-validate every committed note's cached leafIndex against the current
   * chain (audit Issue 14). If a reorg shifted a note's leaf position, the
   * on-chain leaf at that index no longer equals the note's commitment; such
   * notes are reverted to Pending (leafIndex cleared) so they are not spent
   * with a stale index, and their commitments are returned so the caller can
   * trigger a re-scan (ChainScanner) to recover a fresh leafIndex.
   *
   * Transient RPC failures are skipped (note left as-is) so a flaky node does
   * not wrongly invalidate good notes.
   */
  async reconcileNotes(): Promise<bigint[]> {
    this.ensureInitialized();
    const invalidated: bigint[] = [];
    for (const record of this.wallet.getAllNotes()) {
      if (record.status !== NoteStatus.Committed) continue;
      const { commitment, leafIndex } = record.note;
      if (commitment === undefined || leafIndex === undefined) continue;
      let proof: MerkleProof;
      try {
        proof = await this.rpcClient.getMerkleProof(leafIndex);
      } catch {
        continue; // transient RPC error — retry on a later reconcile
      }
      if (proof.leaf !== commitment) {
        this.wallet.invalidateCommittedNote(commitment);
        invalidated.push(commitment);
      }
    }
    return invalidated;
  }

  /**
   * Merge notes recovered by ChainScanner into the wallet's note store (audit
   * Issue 11 / Q6). The scanner only returns RecoveredNote[]; before this there
   * was no supported path to get them into the wallet (addNote is @internal), so
   * cross-device recovery could not rebuild the user's spendable note set.
   *
   * For each recovered note:
   *  - already tracked & Spent  → skipped (never resurrect a spent note);
   *  - leafIndex >= 0           → added and marked Committed (spendable);
   *  - leafIndex < 0            → added as Pending (a transfer output whose
   *                               leafIndex the scanner could not yet derive on
   *                               an incremental scan — not spendable until a
   *                               full scan resolves it).
   *
   * The scanner has already cryptographically validated every RecoveredNote
   * against this wallet's owner pubkey (re-hashed commitment match), so all
   * inputs here belong to this wallet. Idempotent: re-importing is a no-op for
   * already-tracked notes (addNote skips existing keys; re-committing is stable).
   *
   * @returns commitments grouped by outcome, so the caller can surface
   *          not-yet-spendable notes and trigger a full re-scan if needed.
   */
  importRecoveredNotes(notes: RecoveredNote[]): {
    committed: bigint[];
    pending: bigint[];
    skipped: bigint[];
  } {
    this.ensureInitialized();
    const owner = this.wallet.getPublicKey();
    if (owner === null) {
      throw new NotInitializedError(
        'wallet has no keypair; initialize it (initFrom*) before importing recovered notes'
      );
    }

    // Snapshot existing statuses so we never re-commit an already-spent note.
    const statusByCommitment = new Map<string, NoteStatus>();
    for (const record of this.wallet.getAllNotes()) {
      if (record.note.commitment !== undefined) {
        statusByCommitment.set(record.note.commitment.toString(), record.status);
      }
    }

    const committed: bigint[] = [];
    const pending: bigint[] = [];
    const skipped: bigint[] = [];

    for (const rec of notes) {
      if (statusByCommitment.get(rec.commitment.toString()) === NoteStatus.Spent) {
        skipped.push(rec.commitment);
        continue;
      }

      const note = new Note({
        amount: rec.amount,
        tokenId: rec.tokenId,
        owner,
        blinding: rec.blinding,
        commitment: rec.commitment,
      });
      this.wallet.addNote(note); // adds as Pending; no-op if already tracked

      if (rec.leafIndex >= 0) {
        this.wallet.markNoteCommitted(
          rec.commitment,
          rec.leafIndex,
          rec.txHash,
          rec.blockNumber
        );
        committed.push(rec.commitment);
      } else {
        pending.push(rec.commitment);
      }
    }

    return { committed, pending, skipped };
  }

  /**
   * Generate ZK proof using snarkjs
   */
  private async generateProof(circuit: string, input: any): Promise<ZkProof> {
    const wasmPath = `${this.config.circuitsPath}/${circuit}/${circuit}_js/${circuit}.wasm`;
    const zkeyPath = `${this.config.keysPath}/${circuit}_final.zkey`;

    let proof;
    try {
      ({ proof } = await withTimeout(
        snarkjs.groth16.fullProve(input, wasmPath, zkeyPath),
        PROOF_TIMEOUT_MS,
        `${circuit} proof generation`
      ));
    } catch (err) {
      // Preserve typed SDK errors (e.g. TimeoutError from withTimeout); wrap
      // any other snarkjs failure as a typed ProofError (audit Q8).
      if (err instanceof AtoshiSdkError) throw err;
      throw new ProofError(
        `${circuit} proof generation failed: ${(err as Error).message}`
      );
    }

    return {
      pA: [proof.pi_a[0], proof.pi_a[1]],
      pB: [
        [proof.pi_b[0][1], proof.pi_b[0][0]],
        [proof.pi_b[1][1], proof.pi_b[1][0]],
      ],
      pC: [proof.pi_c[0], proof.pi_c[1]],
    };
  }
}

export default TransactionBuilder;

