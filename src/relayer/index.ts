/**
 * Atoshi Privacy Relayer client.
 *
 * The relayer (atoshi-privacy-relayer) holds its own L2 EOA. The SDK sends it a
 * ZK proof + public signals; the relayer signs and broadcasts the corresponding
 * Shield.transfer / Shield.withdraw so the user's wallet never appears as
 * msg.sender on-chain (audit Q8 unlinkability). deposit() is NOT relayed — it
 * pulls tokens from the user's own wallet via msg.sender / msg.value, so it
 * stays user-signed.
 *
 * Wire format matches atoshi-privacy-relayer/src/server.js EXACTLY:
 *   POST /relay/transfer  { proof, publicSignals:{root,nullifierHash,newCommitment}, encryptedNote }
 *   POST /relay/withdraw  { proof, publicSignals:{root,nullifierHash,recipient,relayer,amount,fee}, token }
 *   GET  /health
 * The relayer rejects a withdraw whose publicSignals.relayer != its own address
 * (server.js), and the Shield contract additionally enforces msg.sender ==
 * _relayer, so the fee can only ever go to the relayer that broadcasts.
 */

import { ZkProof, TransactionResult } from '../types';
import { RpcError, TimeoutError } from '../errors';

/** snarkjs-format proof → the relayer's expected string tuple. */
function proofToWire(proof: ZkProof) {
  return {
    pA: [proof.pA[0].toString(), proof.pA[1].toString()],
    pB: [
      [proof.pB[0][0].toString(), proof.pB[0][1].toString()],
      [proof.pB[1][0].toString(), proof.pB[1][1].toString()],
    ],
    pC: [proof.pC[0].toString(), proof.pC[1].toString()],
  };
}

export class RelayerClient {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(relayerUrl: string, options: { timeoutMs?: number } = {}) {
    this.baseUrl = relayerUrl.replace(/\/$/, '');
    // Bound every request so an unresponsive relayer can't hang a
    // withdraw/transfer flow forever (audit Issue 12).
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  private async post<T>(path: string, body: any, signal?: AbortSignal): Promise<T> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);
    const onExternalAbort = () => controller.abort();
    if (signal) {
      if (signal.aborted) controller.abort();
      else signal.addEventListener('abort', onExternalAbort, { once: true });
    }

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!response.ok) {
        const text = await response.text();
        let msg = text;
        try {
          msg = JSON.parse(text).error ?? text;
        } catch {
          /* body is not JSON */
        }
        throw new RpcError(
          `relayer ${path} rejected (${response.status}): ${msg}`,
          response.status
        );
      }
      return (await response.json()) as T;
    } catch (err) {
      if (timedOut) {
        throw new TimeoutError(
          `relayer request timed out after ${this.timeoutMs}ms: POST ${path}`
        );
      }
      throw err;
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onExternalAbort);
    }
  }

  /** Liveness probe (GET /health). Returns false instead of throwing. */
  async health(): Promise<boolean> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const r = await fetch(`${this.baseUrl}/health`, { signal: controller.signal });
      return r.ok;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Submit a Shield.withdraw for the relayer to broadcast. */
  async submitWithdraw(
    args: {
      proof: ZkProof;
      root: bigint;
      nullifierHash: bigint;
      recipient: string;
      relayer: string;
      amount: bigint;
      fee: bigint;
      token: string;
    },
    signal?: AbortSignal
  ): Promise<TransactionResult> {
    const result = await this.post<any>(
      '/relay/withdraw',
      {
        proof: proofToWire(args.proof),
        publicSignals: {
          root: args.root.toString(),
          nullifierHash: args.nullifierHash.toString(),
          recipient: args.recipient,
          relayer: args.relayer,
          amount: args.amount.toString(),
          fee: args.fee.toString(),
        },
        token: args.token,
      },
      signal
    );
    return { success: !!result.txHash, txHash: result.txHash, error: result.error };
  }

  /** Submit a Shield.transfer for the relayer to broadcast. */
  async submitTransfer(
    args: {
      proof: ZkProof;
      root: bigint;
      nullifierHash: bigint;
      newCommitment: bigint;
      encryptedNote: string;
    },
    signal?: AbortSignal
  ): Promise<TransactionResult> {
    const result = await this.post<any>(
      '/relay/transfer',
      {
        proof: proofToWire(args.proof),
        publicSignals: {
          root: args.root.toString(),
          nullifierHash: args.nullifierHash.toString(),
          newCommitment: args.newCommitment.toString(),
        },
        encryptedNote: args.encryptedNote,
      },
      signal
    );
    // The Transfer event carries no leafIndex, so a self-transfer's output note
    // must be recovered later via ChainScanner (audit Q6); the relayer returns
    // only { txHash }.
    return { success: !!result.txHash, txHash: result.txHash, error: result.error };
  }
}

export default RelayerClient;
