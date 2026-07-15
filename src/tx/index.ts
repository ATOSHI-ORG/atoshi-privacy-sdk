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
import { RelayerClient } from '../relayer';
import { rebuildMerkleTree, MerkleTreeData } from '../merkle';
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

// Must match Shield.sol's TREE_LEVELS (bumped to 32 in audit Issue 7) and the
// levels compiled into the unshield / transfer circuits.
const TREE_LEVELS = 32;

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
  private relayerClient: RelayerClient;
  private config: SdkConfig;
  // L2 provider used to read chain state (rebuild the Merkle tree from events,
  // check isSpent) on the withdraw/transfer paths.
  private _provider: ethers.JsonRpcProvider | null = null;
  private signer: ethers.Signer | null = null;
  // Signer-connected contract for deposit() (user-signed on-chain).
  private shieldContract: ethers.Contract | null = null;
  // Provider-connected read-only contract for isSpent() on the relayer paths.
  private shieldRead: ethers.Contract | null = null;
  private poseidon: any;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _F: any;
  private initialized = false;

  constructor(wallet: PrivacyWallet, config: SdkConfig) {
    if (!config.relayerUrl) {
      // withdraw/transfer are broadcast by the Atoshi privacy relayer so that
      // msg.sender != note owner (audit Q8). The relayer URL is therefore
      // required; the built-in network configs already set it.
      throw new InvalidParamsError(
        'SdkConfig.relayerUrl is required for TransactionBuilder — use a built-in ' +
          "config (TESTNET_CONFIG / MAINNET_CONFIG) or set it explicitly"
      );
    }
    this.wallet = wallet;
    this.config = config;
    this.relayerClient = new RelayerClient(config.relayerUrl);
  }

  /**
   * Initialize the transaction builder
   */
  async init(signer?: ethers.Signer): Promise<void> {
    if (this.initialized) return;

    // Initialize Poseidon
    this.poseidon = await buildPoseidon();
    this._F = this.poseidon.F;

    // Shield + the commitment tree live on L2 (audit Q5). Always read through a
    // dedicated L2 JSON-RPC provider — the earlier code used l1RpcUrl, which is
    // the wrong chain. batchMaxCount:1 mirrors the H5 / relayer wiring for the
    // fork11 sequencer, which rejects batched requests.
    this._provider = new ethers.JsonRpcProvider(
      this.config.l2RpcUrl,
      { chainId: this.config.l2ChainId, name: this.config.name },
      { batchMaxCount: 1, staticNetwork: true }
    );
    this.shieldRead = new ethers.Contract(
      this.config.shieldContract,
      SHIELD_ABI,
      this._provider
    );

    // A signer is only needed for deposit() (user-signed). withdraw/transfer are
    // broadcast by the relayer, so they work without one.
    if (signer) {
      this.signer = signer;
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

    // deposit() emits Deposit(commitment, leafIndex, ...); read the leafIndex
    // straight from the receipt (the on-chain tree assigned it). No privacy node
    // is involved — deposit is a direct, user-signed L2 tx.
    let leafIndex: number | undefined;
    const depositIface = new ethers.Interface([
      'event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 timestamp, address indexed token, uint256 amount, bytes encryptedNote)',
    ]);
    for (const log of receipt.logs) {
      try {
        const parsed = depositIface.parseLog({
          topics: log.topics as string[],
          data: log.data,
        });
        if (parsed && BigInt(parsed.args.commitment) === commitment) {
          leafIndex = Number(parsed.args.leafIndex);
          break;
        }
      } catch {
        /* not the Deposit event */
      }
    }

    // The deposit is already on-chain, so always track the note (audit Issue 11
    // scenario 1). Upgrade to Committed once we have the leafIndex from the event.
    this.wallet.addNote(note);
    if (leafIndex !== undefined) {
      note.setLeafIndex(leafIndex);
      this.wallet.markNoteCommitted(
        commitment,
        leafIndex,
        receipt.hash,
        receipt.blockNumber
      );
    }

    return {
      success: true,
      txHash: receipt.hash,
      leafIndex,
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

    // Rebuild the Merkle tree from chain events and derive this note's path.
    // Shield + the tree live on L2; there is no privacy-node merkle endpoint, so
    // we reconstruct it the same way the H5 proof path does.
    const merkleProof = await this.buildMerkleProof(note.leafIndex);

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

    // Check nullifier not spent — read the Shield contract directly on L2. If it
    // is (e.g. spent from another device), reconcile local state so this note
    // stops being offered as spendable (audit Issue 11 scenario 3).
    if (await this.shieldRead!.isSpent(nullifier)) {
      // commitment may be undefined on a note restored without it — guard so we
      // surface NoteAlreadySpentError, not an opaque TypeError (audit Q8).
      if (note.commitment !== undefined) {
        this.wallet.markNoteSpent(note.commitment);
      }
      throw new NoteAlreadySpentError();
    }

    // The unshield circuit binds `relayer` into the public-input vector (audit
    // Issue 3 / contract Issue 4). Default to the configured relayer (which will
    // broadcast the tx); callers may override. address(0) => self-broadcast,
    // which requires fee == 0 (the contract enforces it).
    const relayer =
      params.relayer ?? this.config.relayerAddress ?? ethers.ZeroAddress;
    const fee = params.fee ? BigInt(params.fee.toString()) : 0n;
    if (fee > 0n && relayer === ethers.ZeroAddress) {
      throw new InvalidParamsError('A non-zero relayer address is required when fee > 0');
    }
    const proof = await this.generateWithdrawProof(
      note,
      merkleProof,
      params.recipient,
      relayer,
      fee
    );

    // Submit to the relayer: it validates publicSignals.relayer == its own
    // address and broadcasts Shield.withdraw with itself as msg.sender (audit
    // Q8); the contract also enforces msg.sender == _relayer.
    const result = await this.relayerClient.submitWithdraw({
      proof,
      root: merkleProof.root,
      nullifierHash: nullifier,
      recipient: params.recipient,
      relayer,
      amount: note.amount,
      fee,
      token: note.tokenId === 0n ? ethers.ZeroAddress : toHex(note.tokenId, 40),
    });

    // Once the relayer broadcasts, the nullifier is spent on-chain, so mark the
    // note spent on success even if no txHash came back (audit Issue 11
    // scenario 2).
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

    // Rebuild the Merkle tree from chain and derive the input note's path
    // (same reconstruction as the H5 proof path — no privacy-node endpoint).
    const merkleProof = await this.buildMerkleProof(inNote.leafIndex);

    // Reorg guard (audit Issue 14): the leaf at our cached index must still be
    // this note's commitment, else the leafIndex is stale (reorg) and would
    // yield an invalid proof — revert to Pending and fail loud.
    if (inNote.commitment !== undefined && merkleProof.leaf !== inNote.commitment) {
      this.wallet.invalidateCommittedNote(inNote.commitment);
      throw new StaleLeafIndexError();
    }

    // Compute nullifier
    const nullifier = await this.wallet.computeNullifier(inNote);

    // Check nullifier not spent — read the Shield contract directly on L2.
    // Reconcile local state before throwing so a note spent elsewhere stops
    // being offered as spendable (audit Issue 11 scenario 3).
    if (await this.shieldRead!.isSpent(nullifier)) {
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

    // Submit to the relayer, which broadcasts Shield.transfer with itself as
    // msg.sender so the note owner's address never appears on-chain (audit Q8).
    const result = await this.relayerClient.submitTransfer({
      proof,
      root: merkleProof.root,
      nullifierHash: nullifier,
      newCommitment: outCommitment,
      encryptedNote,
    });

    // The input nullifier is spent on-chain as soon as the relayer broadcasts,
    // so mark the input note spent on success even if no txHash came back
    // (audit Issue 11 scenario 2).
    if (result.success) {
      if (inNote.commitment !== undefined) {
        this.wallet.markNoteSpent(inNote.commitment, result.txHash);
      }

      // If transferring to self, track the new output note. The Transfer event
      // carries no leafIndex (audit Q6), so it stays Pending until a ChainScanner
      // full scan resolves its position; importRecoveredNotes then commits it.
      if (params.recipientPublicKey === this.wallet.getPublicKey()) {
        this.wallet.addNote(outNote);
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

    // Rebuild the tree once from chain and check every committed note's leaf
    // against its cached index. A transient RPC failure aborts the whole pass
    // (notes left as-is) rather than wrongly invalidating good notes.
    let tree: MerkleTreeData;
    try {
      tree = await this.rebuildTree();
    } catch {
      return invalidated; // transient RPC error — retry on a later reconcile
    }

    for (const record of this.wallet.getAllNotes()) {
      if (record.status !== NoteStatus.Committed) continue;
      const { commitment, leafIndex } = record.note;
      if (commitment === undefined || leafIndex === undefined) continue;
      const leaf = leafIndex < tree.leaves.length ? tree.leaves[leafIndex] : undefined;
      if (leaf !== commitment) {
        this.wallet.invalidateCommittedNote(commitment);
        invalidated.push(commitment);
      }
    }
    return invalidated;
  }

  /** Rebuild the on-chain commitment tree from Shield events (L2). */
  private async rebuildTree(): Promise<MerkleTreeData> {
    return rebuildMerkleTree(this._provider!, this.config.shieldContract, {
      levels: TREE_LEVELS,
    });
  }

  /**
   * Rebuild the tree and assemble the MerkleProof for `leafIndex`. Throws
   * StaleLeafIndexError if the cached index is beyond the current on-chain tree
   * (a deep reorg / rollback); callers additionally compare merkleProof.leaf to
   * the note's commitment to catch a shifted leaf (audit Issue 14).
   */
  private async buildMerkleProof(leafIndex: number): Promise<MerkleProof> {
    const tree = await this.rebuildTree();
    if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
      throw new StaleLeafIndexError();
    }
    const path = tree.pathFor(leafIndex);
    return {
      leaf: tree.leaves[leafIndex],
      leafIndex,
      pathElements: path.pathElements.map((e) => BigInt(e)),
      pathIndices: path.pathIndices,
      root: path.root,
    };
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

