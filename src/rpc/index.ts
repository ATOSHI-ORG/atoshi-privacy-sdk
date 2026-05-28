/**
 * RPC Client for Privacy Node
 */

import { 
  NodeState, 
  MerkleProof, 
  TransactionResult,
  ZkProof 
} from '../types';
import { toHex, fromHex } from '../utils';

/**
 * Privacy RPC client
 */
export class PrivacyRpcClient {
  private baseUrl: string;

  constructor(nodeUrl: string) {
    this.baseUrl = nodeUrl.replace(/\/$/, '');
  }

  /**
   * Make HTTP request
   */
  private async request<T>(
    method: string,
    path: string,
    body?: any
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    
    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`RPC error: ${response.status} - ${error}`);
    }

    return (await response.json()) as T;
  }

  /**
   * Health check
   */
  async health(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get node state
   */
  async getState(): Promise<NodeState> {
    const result = await this.request<any>('GET', '/api/v1/state');
    return {
      merkleRoot: result.merkle_root,
      nextIndex: result.next_index,
      nullifiersCount: result.nullifiers_count,
    };
  }

  /**
   * Get current Merkle root
   */
  async getRoot(): Promise<{ root: bigint; nextIndex: number }> {
    const result = await this.request<any>('GET', '/api/v1/root');
    return {
      root: fromHex(result.root),
      nextIndex: result.next_index,
    };
  }

  /**
   * Check if nullifier is spent
   */
  async isNullifierSpent(nullifier: bigint): Promise<boolean> {
    const hash = toHex(nullifier);
    const result = await this.request<any>('GET', `/api/v1/nullifier/${hash}`);
    return result.is_spent;
  }

  /**
   * Get Merkle proof for a leaf
   */
  async getMerkleProof(leafIndex: number): Promise<MerkleProof> {
    const result = await this.request<any>('GET', `/api/v1/merkle/proof/${leafIndex}`);
    return {
      leaf: fromHex(result.leaf),
      leafIndex: result.leaf_index,
      pathElements: result.path_elements.map((e: string) => fromHex(e)),
      pathIndices: result.path_indices,
      root: fromHex(result.root),
    };
  }

  /**
   * Submit deposit transaction
   */
  async submitDeposit(
    commitment: bigint,
    token: string,
    amount: bigint,
    l1TxHash: string
  ): Promise<TransactionResult> {
    const result = await this.request<any>('POST', '/api/v1/tx/deposit', {
      commitment: toHex(commitment),
      token,
      amount: amount.toString(),
      l1_tx_hash: l1TxHash,
    });

    return {
      success: result.success,
      txHash: result.tx_hash,
      leafIndex: result.leaf_index,
      newRoot: result.new_root,
      error: result.error,
    };
  }

  /**
   * Submit withdraw transaction
   */
  async submitWithdraw(
    proof: ZkProof,
    root: bigint,
    nullifierHash: bigint,
    recipient: string,
    token: string,
    amount: bigint,
    fee: bigint
  ): Promise<TransactionResult> {
    const result = await this.request<any>('POST', '/api/v1/tx/withdraw', {
      proof: {
        pi_a: proof.pA,
        pi_b: proof.pB,
        pi_c: proof.pC,
      },
      root: toHex(root),
      nullifier_hash: toHex(nullifierHash),
      recipient,
      token,
      amount: amount.toString(),
      fee: fee.toString(),
    });

    return {
      success: result.success,
      txHash: result.tx_hash,
      error: result.error,
    };
  }

  /**
   * Submit transfer transaction
   */
  async submitTransfer(
    proof: ZkProof,
    root: bigint,
    nullifierHash: bigint,
    newCommitment: bigint
  ): Promise<TransactionResult> {
    const result = await this.request<any>('POST', '/api/v1/tx/transfer', {
      proof: {
        pi_a: proof.pA,
        pi_b: proof.pB,
        pi_c: proof.pC,
      },
      root: toHex(root),
      nullifier_hash: toHex(nullifierHash),
      new_commitment: toHex(newCommitment),
    });

    return {
      success: result.success,
      txHash: result.tx_hash,
      leafIndex: result.leaf_index,
      newRoot: result.new_root,
      error: result.error,
    };
  }

  /**
   * JSON-RPC call
   */
  async rpcCall<T>(method: string, params: any[] = []): Promise<T> {
    const result = await this.request<any>('POST', '/rpc', {
      jsonrpc: '2.0',
      method,
      params,
      id: Date.now(),
    });

    if (result.error) {
      throw new Error(`RPC error: ${result.error.message}`);
    }

    return result.result;
  }
}

export default PrivacyRpcClient;

