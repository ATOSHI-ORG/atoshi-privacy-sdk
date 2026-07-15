/**
 * Chain Scanner — 扫 Shield 合约的 Deposit / Transfer 事件,
 * 用本地 viewingKey 尝试解密 encryptedNote, 自动恢复属于本人的 Note.
 *
 * 用法:
 *   const scanner = new ChainScanner({
 *     rpcUrl: 'http://52.76.210.218:8123',
 *     shieldAddress: '0x4A951a4B...',  // current Atoshi L2 Shield (redeployed 2026-06-03 with evmVersion=paris)
 *     fromBlock: 0,                           // 或上次扫到的位置
 *   });
 *   const notes = await scanner.scanForViewer(viewingKey, spendingKey);
 *   // 每个 note 是一个 RecoveredNote。deposit note 与(全量扫描 fromBlock=0 时)
 *   // transfer note 都带有可用于 spend 的 leafIndex;transfer 的 leafIndex 由扫描器
 *   // 按插入次序推算(合约不 emit,见 scanForViewer 内注释 / audit Issue 11)。
 *
 * 性能:
 *   - 单笔 try-decrypt < 1ms
 *   - 扫 10000 个事件约 1-2s (主要是 RPC 拉取)
 *   - 增量扫描: 钱包记录 lastScannedBlock, 下次只扫新区块
 */

import { ethers } from 'ethers';
import { decryptNote, viewingPubKey, NotePlaintext } from '../crypto/ecies';
import { computeCommitment, deriveOwnerPubkey } from '../poseidon';

/** Shield 合约的最小 ABI (只是扫描需要的事件) */
const SHIELD_EVENTS_ABI = [
  'event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 timestamp, address indexed token, uint256 amount, bytes encryptedNote)',
  'event Transfer(uint256 indexed nullifierHash, uint256 indexed newCommitment, bytes encryptedNote)',
];

export interface ScannerConfig {
  rpcUrl: string;
  shieldAddress: string;
  /** 起始扫描块,首次启动用 0,后续传 lastScannedBlock + 1 */
  fromBlock?: number;
  /** RPC 每次 getLogs 最多扫多少块,默认 9000 (符合大多数公网 RPC 限制) */
  chunkSize?: number;
}

/**
 * 从链上扫到 + 解密成功的 Note. 包含 spend 所需全部字段.
 *
 * NOTE: commitment 来自链上事件 (公开数据).
 *       leafIndex: deposit 直接来自事件;transfer 由扫描器按插入次序推算
 *       (合约不 emit)。全量扫描 (fromBlock=0) 下均为有效值;增量扫描中,
 *       首个 Deposit 锚点之前的 transfer 输出会是 -1 (尚不可 spend)。
 *       amount/blinding 来自 encryptedNote 的解密 plaintext (私密数据).
 *       owner 在本地用 spendingKey 重算 = Poseidon(spendingKey).
 */
export interface RecoveredNote {
  /** 来自事件 (公开) */
  commitment: bigint;
  /** deposit: 来自事件; transfer: 按插入次序推算 (-1 = 未锚定, 尚不可 spend) */
  leafIndex: number;
  blockNumber: number;
  txHash: string;
  /** 来自事件类型 (deposit 是自己存的, transfer 是别人转来的) */
  source: 'deposit' | 'transfer';
  /** 来自解密 plaintext (私密) */
  amount: bigint;
  tokenId: bigint;
  blinding: bigint;
}

export class ChainScanner {
  private provider: ethers.JsonRpcProvider;
  private iface: ethers.Interface;
  private shieldAddress: string;
  private fromBlock: number;
  private chunkSize: number;

  constructor(config: ScannerConfig) {
    // fork11 兼容: batchMaxCount: 1
    this.provider = new ethers.JsonRpcProvider(
      config.rpcUrl,
      undefined,
      { batchMaxCount: 1, staticNetwork: true }
    );
    this.iface = new ethers.Interface(SHIELD_EVENTS_ABI);
    this.shieldAddress = config.shieldAddress;
    this.fromBlock = config.fromBlock ?? 0;
    this.chunkSize = config.chunkSize ?? 9000;
  }

  /** 当前链高,用于增量扫描分页 */
  async getLatestBlock(): Promise<number> {
    return this.provider.getBlockNumber();
  }

  /**
   * 扫指定区块范围的所有 Deposit + Transfer 事件,挨个 try-decrypt.
   *
   * @param viewingKey       本地 viewingKey (从 EIP-712 派生)
   * @param spendingKey      本地 spendingKey (用于 sanity-check Note 是否真属于本人)
   * @param toBlock          扫到哪个块为止 (含)。默认 latest。
   * @returns 解密成功 + 属于本人的 Note 列表
   */
  async scanForViewer(
    viewingKey: bigint,
    spendingKey: bigint,
    toBlock?: number
  ): Promise<RecoveredNote[]> {
    const end = toBlock ?? (await this.getLatestBlock());
    const recovered: RecoveredNote[] = [];

    // Audit Q4 (contract audit 2026-06): the contract cannot validate
    // encryptedNote payload (it's encrypted; if the contract could read
    // it, every observer could, breaking confidentiality). So the
    // validation has to live here, client-side, where the spending key
    // is available.
    //
    // Threat model without this check: an attacker emits a Transfer/
    // Deposit event with an encryptedNote crafted for the victim's
    // viewingPubKey but claiming a much larger (amount, tokenId) than
    // the underlying on-chain commitment actually encodes. The victim's
    // wallet decrypts successfully, displays inflated balance, and the
    // victim may rely on it (OTC, collateralized lending, …) before
    // discovering at spend time that no proof will verify.
    //
    // Fix: derive the owner pubkey from the spendingKey and re-hash the
    // decrypted (amount, tokenId, ownerPubkey, blinding) into a fresh
    // commitment locally. If it doesn't match the on-chain commitment,
    // the encryptedNote was forged — drop it silently.
    const ownerPubkey = await deriveOwnerPubkey(spendingKey);

    // Derive the leafIndex of every note — including Transfer outputs, which
    // the contract does NOT emit a leafIndex for (audit Issue 11 / Q6).
    //
    // The Shield tree only ever inserts leaves in two places — deposit() and
    // transfer() — each inserts exactly one leaf, sequentially (+1), in on-chain
    // execution order (Shield.sol / MerkleTree.insert). Deposit events DO carry
    // their leafIndex. So by walking all Deposit + Transfer events in chain
    // order and counting insertions, we can assign the correct leafIndex to each
    // Transfer output too, anchoring/cross-checking against the leafIndex the
    // Deposit events emit.
    //
    // nextLeafIndex starts at 0 for a full scan (fromBlock === 0). For an
    // incremental scan starting mid-stream we don't know the tree size up front,
    // so it starts null (unanchored) and is anchored by the first Deposit we
    // see; Transfer outputs seen before that anchor get leafIndex -1 (caller
    // treats them as not-yet-spendable). Full recovery should scan from block 0.
    let nextLeafIndex: number | null = this.fromBlock === 0 ? 0 : null;

    for (let from = this.fromBlock; from <= end; from += this.chunkSize) {
      const to = Math.min(from + this.chunkSize - 1, end);
      const logs = await this.provider.getLogs({
        address: this.shieldAddress,
        fromBlock: from,
        toBlock: to,
        // 不过滤 topic[0], 一次拉 Deposit + Transfer 两种事件
      });

      // Leaf ordering must follow on-chain execution order. getLogs is normally
      // already ascending, but sort explicitly so the counter is never wrong.
      logs.sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index);

      for (const log of logs) {
        let parsed;
        try {
          parsed = this.iface.parseLog({ topics: log.topics as string[], data: log.data });
        } catch {
          continue;
        }
        if (!parsed) continue;

        let commitment: bigint;
        let leafIndex: number;
        let source: 'deposit' | 'transfer';
        let encryptedNoteHex: string;

        if (parsed.name === 'Deposit') {
          commitment = BigInt(parsed.args.commitment);
          // Deposit emits its own leafIndex — authoritative. Use it and
          // (re-)anchor the running counter so subsequent Transfer outputs are
          // numbered correctly even on an incremental scan.
          leafIndex = Number(parsed.args.leafIndex);
          nextLeafIndex = leafIndex + 1;
          source = 'deposit';
          encryptedNoteHex = parsed.args.encryptedNote as string;
        } else if (parsed.name === 'Transfer') {
          commitment = BigInt(parsed.args.newCommitment);
          // Transfer does NOT emit a leafIndex. Derive it from the running
          // insertion counter (audit Issue 11 / Q6). -1 only if we haven't
          // anchored yet (incremental scan started before the first Deposit).
          if (nextLeafIndex === null) {
            leafIndex = -1;
          } else {
            leafIndex = nextLeafIndex;
            nextLeafIndex++;
          }
          source = 'transfer';
          encryptedNoteHex = parsed.args.encryptedNote as string;
        } else {
          continue;
        }

        // encryptedNote 可能是空 (向后兼容用法), 跳过
        if (!encryptedNoteHex || encryptedNoteHex === '0x' || encryptedNoteHex.length <= 2) {
          continue;
        }

        const blob = hexToBytes(encryptedNoteHex);
        const plaintext = await decryptNote(blob, viewingKey);
        if (!plaintext) continue;

        // Audit Q4: re-derive commitment from the decrypted plaintext
        // and reject anything that doesn't match the on-chain value.
        // This is the only place "attacker-forged encryptedNote → fake
        // balance" can be blocked — the chain can't see through the
        // ciphertext.
        const amount = BigInt(plaintext.amount);
        const tokenId = BigInt(plaintext.tokenId);
        const blinding = BigInt(plaintext.blinding);
        const recomputed = await computeCommitment(amount, tokenId, ownerPubkey, blinding);
        if (recomputed !== commitment) continue;

        recovered.push({
          commitment,
          leafIndex,
          blockNumber: log.blockNumber,
          txHash: log.transactionHash,
          source,
          amount,
          tokenId,
          blinding,
        });
      }
    }

    return recovered;
  }
}

/** Helper: 0x-prefixed hex → Uint8Array */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** 导出 viewingPubKey 给外部 (sender 用来加密 Note 给 receiver) */
export { viewingPubKey } from '../crypto/ecies';
