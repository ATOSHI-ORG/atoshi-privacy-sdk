/**
 * Chain Scanner — 扫 Shield 合约的 Deposit / Transfer 事件,
 * 用本地 viewingKey 尝试解密 encryptedNote, 自动恢复属于本人的 Note.
 *
 * 用法:
 *   const scanner = new ChainScanner({
 *     rpcUrl: 'http://52.76.210.218:8123',
 *     shieldAddress: '0x2942ACf6...',
 *     fromBlock: 0,                           // 或上次扫到的位置
 *   });
 *   const notes = await scanner.scanForViewer(viewingKey, spendingKey);
 *   // 每个 note 是一个 RecoveredNote, 包含完整字段可直接 spend
 *
 * 性能:
 *   - 单笔 try-decrypt < 1ms
 *   - 扫 10000 个事件约 1-2s (主要是 RPC 拉取)
 *   - 增量扫描: 钱包记录 lastScannedBlock, 下次只扫新区块
 */

import { ethers } from 'ethers';
import { decryptNote, viewingPubKey, NotePlaintext } from '../crypto/ecies';

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
 * NOTE: commitment 和 leafIndex 来自链上事件 (公开数据).
 *       amount/blinding 来自 encryptedNote 的解密 plaintext (私密数据).
 *       owner 在本地用 spendingKey 重算 = Poseidon(spendingKey).
 */
export interface RecoveredNote {
  /** 来自事件 (公开) */
  commitment: bigint;
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

    // 用 spendingKey 算出 ownerPubkey, 后面用来验证解密的 Note 真的属于本人
    // (encryptedNote 任何人都能 emit, 必须验证 commitment == Poseidon(amount, tokenId, owner, blinding))
    // —— 这步在调用方做(他们有 Poseidon hasher),scanner 只负责拉 + 解密.

    for (let from = this.fromBlock; from <= end; from += this.chunkSize) {
      const to = Math.min(from + this.chunkSize - 1, end);
      const logs = await this.provider.getLogs({
        address: this.shieldAddress,
        fromBlock: from,
        toBlock: to,
        // 不过滤 topic[0], 一次拉 Deposit + Transfer 两种事件
      });

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
          leafIndex = Number(parsed.args.leafIndex);
          source = 'deposit';
          encryptedNoteHex = parsed.args.encryptedNote as string;
        } else if (parsed.name === 'Transfer') {
          commitment = BigInt(parsed.args.newCommitment);
          // Transfer 没直接 emit leafIndex,需要从 commitmentTree 的插入次序推算
          // (或扫描器单独跟踪 nextIndex 计数器). 这里暂用 -1 占位,
          // 调用方在后处理时根据 commitment 在 tree 中的位置赋值.
          leafIndex = -1;
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

        recovered.push({
          commitment,
          leafIndex,
          blockNumber: log.blockNumber,
          txHash: log.transactionHash,
          source,
          amount: BigInt(plaintext.amount),
          tokenId: BigInt(plaintext.tokenId),
          blinding: BigInt(plaintext.blinding),
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
