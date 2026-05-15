/**
 * Updated TransactionBuilder with L2 Bridge Support
 */

import { ethers } from 'ethers';
import { PrivacyWallet } from '../wallet';
import { BridgeClient } from '../bridge';
import { SdkConfig } from '../config';
import type { Note } from '../types';

export interface DepositParams {
  amount: bigint;
  tokenAddress: string;
  recipient?: bigint; // Optional: deposit for someone else
}

export interface WithdrawParams {
  noteIndex: number;
  recipient: string;
  relayer?: string;
  fee?: bigint;
}

export interface TransferParams {
  noteIndex: number;
  recipientPublicKey: bigint;
  amount?: bigint; // Optional: partial transfer
}

export interface TransactionResult {
  txHash: string;
  note?: Note;
  commitment?: bigint;
}

export class TransactionBuilder {
  private wallet: PrivacyWallet;
  private config: SdkConfig;
  private signer?: ethers.Signer;
  private l1Signer?: ethers.Signer;
  private l2Signer?: ethers.Signer;
  private shieldContract?: ethers.Contract;
  private bridge: BridgeClient;

  constructor(wallet: PrivacyWallet, config: SdkConfig) {
    this.wallet = wallet;
    this.config = config;
    this.bridge = new BridgeClient({
      l1RpcUrl: config.l1RpcUrl,
      l2RpcUrl: config.l2RpcUrl,
      l1BridgeAddress: config.l1BridgeContract,
      l2BridgeAddress: config.l2BridgeContract,
      l1ChainId: config.l1ChainId,
      l2ChainId: config.l2ChainId,
    });
  }

  /**
   * Initialize with signers
   * 
   * @param l1Signer Signer for L1 transactions
   * @param l2Signer Signer for L2 transactions (optional, will derive from L1 if not provided)
   */
  async init(l1Signer: ethers.Signer, l2Signer?: ethers.Signer): Promise<void> {
    this.l1Signer = l1Signer;
    
    if (l2Signer) {
      this.l2Signer = l2Signer;
    } else {
      // Use same private key for L2
      if ('privateKey' in l1Signer) {
        const l2Provider = new ethers.JsonRpcProvider(this.config.l2RpcUrl);
        this.l2Signer = new ethers.Wallet((l1Signer as any).privateKey, l2Provider);
      } else {
        throw new Error('Cannot derive L2 signer from L1 signer. Please provide L2 signer explicitly.');
      }
    }

    // Initialize Shield contract on L2
    const SHIELD_ABI = [
      'function deposit(uint256 commitment, address token, uint256 amount) external payable',
      'function withdraw(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256 root, uint256 nullifierHash, address recipient, address relayer, uint256 fee, address token, uint256 amount) external',
      'function transfer(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256 root, uint256 nullifierHash, uint256 newCommitment) external',
    ];

    this.shieldContract = new ethers.Contract(
      this.config.shieldContract,
      SHIELD_ABI,
      this.l2Signer
    );
  }

  /**
   * Deposit tokens into privacy pool
   * 
   * Flow:
   * 1. Bridge assets from L1 to L2
   * 2. Wait for bridge confirmation
   * 3. Deposit into Shield contract on L2
   * 
   * @param params Deposit parameters
   * @returns Transaction result with note
   */
  async deposit(params: DepositParams): Promise<TransactionResult> {
    if (!this.l1Signer || !this.l2Signer) {
      throw new Error('Signers not initialized. Call init() first.');
    }

    console.log('🔐 Starting privacy deposit...\n');

    // Step 1: Bridge from L1 to L2
    console.log('Step 1/3: Bridging assets from L1 to L2...');
    console.log(`  Amount: ${ethers.formatEther(params.amount)} tokens`);
    console.log(`  Token: ${params.tokenAddress}`);

    const bridgeResult = await this.bridge.bridgeToL2(
      params.tokenAddress,
      params.amount,
      this.l1Signer
    );

    console.log(`✅ Bridge transaction: ${bridgeResult.txHash}`);

    // Step 2: Wait for bridge confirmation
    console.log('\nStep 2/3: Waiting for bridge confirmation...');
    await this.bridge.waitForBridgeConfirmation(bridgeResult.txHash, true);

    // Step 3: Deposit into privacy pool on L2
    console.log('\nStep 3/3: Depositing into privacy pool on L2...');

    // Create note
    const recipientPubKey = params.recipient || this.wallet.getPublicKey();
    if (!recipientPubKey) {
      throw new Error('No recipient public key. Generate keypair first.');
    }

    const note = await this.wallet.createNote(
      params.amount,
      BigInt(params.tokenAddress),
      recipientPubKey
    );

    console.log(`  Commitment: ${note.commitment.toString(16)}`);

    // Call Shield.deposit on L2
    const tx = await this.shieldContract!.deposit(
      note.commitment,
      params.tokenAddress,
      params.amount,
      params.tokenAddress === ethers.ZeroAddress ? { value: params.amount } : {}
    );

    console.log(`  Transaction: ${tx.hash}`);
    
    const receipt = await tx.wait();
    console.log(`✅ Deposit confirmed in block ${receipt!.blockNumber}`);

    // Save note
    this.wallet.addNote(note);

    console.log('\n🎉 Privacy deposit complete!');
    console.log(`   Your funds are now private on L2`);

    return {
      txHash: tx.hash,
      note,
      commitment: note.commitment,
    };
  }

  /**
   * Withdraw tokens from privacy pool
   * 
   * This happens entirely on L2. If you want to move funds back to L1,
   * you need to call bridgeToL1() separately after withdrawal.
   * 
   * @param params Withdraw parameters
   * @returns Transaction result
   */
  async withdraw(params: WithdrawParams): Promise<TransactionResult> {
    if (!this.l2Signer) {
      throw new Error('L2 signer not initialized');
    }

    console.log('🔓 Starting privacy withdrawal...\n');

    // Get note
    const notes = this.wallet.getUnspentNotes();
    if (params.noteIndex >= notes.length) {
      throw new Error(`Note index ${params.noteIndex} out of range`);
    }

    const noteRecord = notes[params.noteIndex];
    const note = noteRecord.note;

    console.log(`  Amount: ${ethers.formatEther(note.amount)} tokens`);
    console.log(`  Recipient: ${params.recipient}`);

    // Generate ZK proof
    console.log('\n⏳ Generating ZK proof...');
    const proof = await this.generateWithdrawProof(note, params);
    console.log('✅ Proof generated');

    // Submit withdrawal
    console.log('\n📤 Submitting withdrawal to L2...');
    const tx = await this.shieldContract!.withdraw(
      proof.pA,
      proof.pB,
      proof.pC,
      proof.root,
      proof.nullifierHash,
      params.recipient,
      params.relayer || ethers.ZeroAddress,
      params.fee || 0n,
      note.tokenId.toString(), // Convert to address
      note.amount
    );

    console.log(`  Transaction: ${tx.hash}`);
    
    const receipt = await tx.wait();
    console.log(`✅ Withdrawal confirmed in block ${receipt!.blockNumber}`);

    // Mark note as spent
    this.wallet.markNoteAsSpent(params.noteIndex);

    console.log('\n🎉 Privacy withdrawal complete!');
    console.log(`   Funds sent to ${params.recipient} on L2`);

    return {
      txHash: tx.hash,
    };
  }

  /**
   * Private transfer within the pool
   * 
   * @param params Transfer parameters
   * @returns Transaction result with new note
   */
  async transfer(params: TransferParams): Promise<TransactionResult> {
    if (!this.l2Signer) {
      throw new Error('L2 signer not initialized');
    }

    console.log('🔄 Starting privacy transfer...\n');

    // Get old note
    const notes = this.wallet.getUnspentNotes();
    if (params.noteIndex >= notes.length) {
      throw new Error(`Note index ${params.noteIndex} out of range`);
    }

    const oldNote = notes[params.noteIndex].note;
    const transferAmount = params.amount || oldNote.amount;

    console.log(`  Amount: ${ethers.formatEther(transferAmount)} tokens`);
    console.log(`  Recipient: ${params.recipientPublicKey.toString(16).slice(0, 10)}...`);

    // Create new note for recipient
    const newNote = await this.wallet.createNote(
      transferAmount,
      oldNote.tokenId,
      params.recipientPublicKey
    );

    // Generate ZK proof
    console.log('\n⏳ Generating ZK proof...');
    const proof = await this.generateTransferProof(oldNote, newNote);
    console.log('✅ Proof generated');

    // Submit transfer
    console.log('\n📤 Submitting transfer to L2...');
    const tx = await this.shieldContract!.transfer(
      proof.pA,
      proof.pB,
      proof.pC,
      proof.root,
      proof.nullifierHash,
      newNote.commitment
    );

    console.log(`  Transaction: ${tx.hash}`);
    
    const receipt = await tx.wait();
    console.log(`✅ Transfer confirmed in block ${receipt!.blockNumber}`);

    // Mark old note as spent
    this.wallet.markNoteAsSpent(params.noteIndex);

    console.log('\n🎉 Privacy transfer complete!');

    return {
      txHash: tx.hash,
      note: newNote,
      commitment: newNote.commitment,
    };
  }

  /**
   * Bridge funds from L2 back to L1
   * 
   * Note: You must withdraw from privacy pool first!
   * 
   * @param token Token address
   * @param amount Amount to bridge
   * @returns Bridge transaction hash
   */
  async bridgeToL1(token: string, amount: bigint): Promise<string> {
    if (!this.l2Signer) {
      throw new Error('L2 signer not initialized');
    }

    console.log('🌉 Bridging funds from L2 to L1...');
    console.log(`  Amount: ${ethers.formatEther(amount)} tokens`);

    const result = await this.bridge.bridgeToL2(token, amount, this.l2Signer);
    
    console.log(`✅ Bridge transaction: ${result.txHash}`);
    console.log('⏳ Waiting for L2 batch verification on L1 (30-60 minutes)...');
    console.log('   You can claim assets on L1 after verification completes');

    return result.txHash;
  }

  // ============ Private Methods ============

  private async generateWithdrawProof(note: Note, params: WithdrawParams): Promise<any> {
    // TODO: Implement actual proof generation using snarkjs
    // This is a placeholder
    throw new Error('Proof generation not implemented yet');
  }

  private async generateTransferProof(oldNote: Note, newNote: Note): Promise<any> {
    // TODO: Implement actual proof generation
    throw new Error('Proof generation not implemented yet');
  }
}

export default TransactionBuilder;

