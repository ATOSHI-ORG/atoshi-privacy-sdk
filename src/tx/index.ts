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
} from '../types';
import { PrivacyWallet } from '../wallet';
import { PrivacyRpcClient } from '../rpc';
import { toHex, fromHex, withTimeout } from '../utils';

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
      throw new Error('TransactionBuilder not initialized. Call init() first.');
    }
  }

  /**
   * Build and submit a deposit transaction
   */
  async deposit(params: DepositParams): Promise<TransactionResult> {
    this.ensureInitialized();

    if (!this.signer || !this.shieldContract) {
      throw new Error('Signer required for deposit');
    }

    const publicKey = params.recipient ?? this.wallet.getPublicKey();
    if (!publicKey) {
      throw new Error('No recipient specified');
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
    const encryptedNote = '0x'; // SDK consumers can plumb a real encryptedNote later

    // Submit to L1
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

    if (nodeResult.success && nodeResult.leafIndex !== undefined) {
      // Update note with leaf index
      note.setLeafIndex(nodeResult.leafIndex);
      this.wallet.addNote(note);
      this.wallet.markNoteCommitted(commitment, nodeResult.leafIndex, receipt.hash);
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
      throw new Error('Note not found');
    }

    const note = noteRecord.note;
    if (note.leafIndex === undefined) {
      throw new Error('Note not committed');
    }

    // Get Merkle proof
    const merkleProof = await this.rpcClient.getMerkleProof(note.leafIndex);

    // Compute nullifier
    const nullifier = await this.wallet.computeNullifier(note);

    // Check nullifier not spent
    if (await this.rpcClient.isNullifierSpent(nullifier)) {
      throw new Error('Note already spent');
    }

    // Generate ZK proof. The unshield circuit now binds `relayer` into
    // the public-input vector (audit Issue 3 / contract Issue 4), so
    // callers must specify which relayer will broadcast the tx. When
    // unset, default to address(0) and force fee=0 (the contract
    // requires _relayer != 0 whenever _fee > 0).
    const relayer = params.relayer ?? '0x0000000000000000000000000000000000000000';
    const fee = params.fee ? BigInt(params.fee.toString()) : 0n;
    if (fee > 0n && relayer === '0x0000000000000000000000000000000000000000') {
      throw new Error('A non-zero relayer address is required when fee > 0');
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

    if (result.success && result.txHash) {
      this.wallet.markNoteSpent(note.commitment!, result.txHash);
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
      throw new Error('Note not found');
    }

    const inNote = noteRecord.note;
    if (inNote.leafIndex === undefined) {
      throw new Error('Note not committed');
    }

    // Get Merkle proof
    const merkleProof = await this.rpcClient.getMerkleProof(inNote.leafIndex);

    // Compute nullifier
    const nullifier = await this.wallet.computeNullifier(inNote);

    // Check nullifier not spent
    if (await this.rpcClient.isNullifierSpent(nullifier)) {
      throw new Error('Note already spent');
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
      outCommitment
    );

    if (result.success && result.txHash) {
      this.wallet.markNoteSpent(inNote.commitment!, result.txHash);
      
      // If transferring to self, add the new note
      if (params.recipientPublicKey === this.wallet.getPublicKey()) {
        outNote.setLeafIndex(result.leafIndex!);
        this.wallet.addNote(outNote);
        this.wallet.markNoteCommitted(outCommitment, result.leafIndex!, result.txHash);
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
      throw new Error('No keypair loaded');
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
      throw new Error('No keypair loaded');
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
   * Generate ZK proof using snarkjs
   */
  private async generateProof(circuit: string, input: any): Promise<ZkProof> {
    const wasmPath = `${this.config.circuitsPath}/${circuit}/${circuit}_js/${circuit}.wasm`;
    const zkeyPath = `${this.config.keysPath}/${circuit}_final.zkey`;

    const { proof } = await withTimeout(
      snarkjs.groth16.fullProve(input, wasmPath, zkeyPath),
      PROOF_TIMEOUT_MS,
      `${circuit} proof generation`
    );

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

