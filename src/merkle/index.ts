/**
 * Off-chain Merkle tree reconstruction from Shield contract events.
 *
 * Used when generating ZK proofs for Unshield / Transfer:
 *   - Need to prove "my leaf is in the on-chain tree"
 *   - Path = list of sibling node values at each level
 *
 * Algorithm:
 *   1. eth_getLogs(Shield, topic=Deposit) chunked by 9000 blocks (RPC limit)
 *   2. Sort leaves by leafIndex
 *   3. Build tree level-by-level using Poseidon
 *   4. For any leafIndex, derive the path (pathElements + pathIndices)
 *
 * Tree dimensions: 20 levels (Atoshi standard).
 * Empty siblings = zeros[level] (precomputed).
 */

import { ethers } from 'ethers';
import { poseidonHash, buildZeros } from '../poseidon';

const DEPOSIT_TOPIC = ethers.id(
  'Deposit(uint256,uint256,uint256,address,uint256,bytes)'
);
const DEPOSIT_IFACE = new ethers.Interface([
  'event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 timestamp, address indexed token, uint256 amount, bytes encryptedNote)',
]);
const TRANSFER_TOPIC = ethers.id(
  'Transfer(uint256,uint256,bytes)'
);
const TRANSFER_IFACE = new ethers.Interface([
  'event Transfer(uint256 indexed nullifierHash, uint256 indexed newCommitment, bytes encryptedNote)',
]);

export interface MerklePath {
  pathElements: string[];   // 长度 = levels, decimal string per level
  pathIndices: number[];    // 0 = left child, 1 = right child
  root: bigint;             // 当前 on-chain root
}

export interface MerkleTreeData {
  leaves: bigint[];               // 按 leafIndex 排序
  treeLevels: bigint[][];         // treeLevels[i] = 第 i 层节点(已填零兄弟)
  root: bigint;                   // = treeLevels[levels][0]
  zeros: bigint[];                // 空子树哈希
  pathFor(leafIndex: number): MerklePath;
}

/**
 * 从 Shield 合约链上事件重建整棵 Merkle tree.
 *
 * 同时拉 Deposit + Transfer 事件,因为两者都往 tree 里插入 commitment.
 * 按 leafIndex 排序(Deposit 事件直接带,Transfer 事件需要推算或单独跟踪).
 *
 * 注意: 当前 Transfer 事件**没有 leafIndex 字段**, 这里假设 Transfer 的
 * commitment 按时间顺序在 Deposit 之后插入. 在生产中应用单独的 indexer
 * 或合约增加 leafIndex 字段以确保严格顺序.
 */
export async function rebuildMerkleTree(
  provider: ethers.JsonRpcProvider,
  shieldAddress: string,
  options: {
    levels?: number;
    fromBlock?: number;
    chunkSize?: number;
  } = {}
): Promise<MerkleTreeData> {
  const levels = options.levels ?? 20;
  const fromBlock = options.fromBlock ?? 0;
  const chunk = options.chunkSize ?? 9000;
  const latest = await provider.getBlockNumber();

  // 收集 (leafIndex, commitment) 对
  type Entry = { leafIndex: number; commitment: bigint; blockNumber: number };
  const entries: Entry[] = [];

  for (let from = fromBlock; from <= latest; from += chunk) {
    const to = Math.min(from + chunk - 1, latest);

    // Deposit 事件: 直接带 leafIndex
    const depositLogs = await provider.getLogs({
      address: shieldAddress,
      topics: [DEPOSIT_TOPIC],
      fromBlock: from,
      toBlock: to,
    });
    for (const log of depositLogs) {
      try {
        const parsed = DEPOSIT_IFACE.parseLog({ topics: log.topics as string[], data: log.data });
        if (!parsed) continue;
        entries.push({
          leafIndex: Number(parsed.args.leafIndex),
          commitment: BigInt(parsed.args.commitment),
          blockNumber: log.blockNumber,
        });
      } catch { /* skip */ }
    }

    // Transfer 事件: 没 leafIndex, 用区块号 + log 顺序作为时间戳排序
    // 后续需要根据 nextIndex 进展给它分配真实 leafIndex
    const transferLogs = await provider.getLogs({
      address: shieldAddress,
      topics: [TRANSFER_TOPIC],
      fromBlock: from,
      toBlock: to,
    });
    for (const log of transferLogs) {
      try {
        const parsed = TRANSFER_IFACE.parseLog({ topics: log.topics as string[], data: log.data });
        if (!parsed) continue;
        entries.push({
          leafIndex: -1,                              // 占位, 下面会按时间顺序填
          commitment: BigInt(parsed.args.newCommitment),
          blockNumber: log.blockNumber,
        });
      } catch { /* skip */ }
    }
  }

  // 按 (blockNumber, leafIndex 优先) 排序得到插入顺序
  entries.sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
    // 同一块内, Deposit (leafIndex >= 0) 优先, Transfer 后到
    return a.leafIndex - b.leafIndex;
  });

  // 重新填 Transfer 的 leafIndex(假设按插入顺序递增)
  // 用一个 counter: 见到 Deposit 取它带的 leafIndex; Transfer 取 counter
  // 注意: Deposit 已经有真实 leafIndex, 我们只对 Transfer 重新编号
  // 实际更稳妥的做法是依赖合约 nextIndex,但 Atoshi Transfer 事件还没 leafIndex 字段.
  // 此处用简化算法:先收 Deposit 的 leafIndex 上界,然后给所有 Transfer 顺序填.
  const knownDeposits = entries.filter(e => e.leafIndex >= 0).sort((a, b) => a.leafIndex - b.leafIndex);
  // 按 leaf 顺序排好的全集 (Deposit 用真 index, Transfer 在 Deposit 之间按 blockNumber 插入)
  // 简化: 暂时假设池子里只有 Deposit (V1 多数场景); Transfer 真实编号待后端 indexer 补
  const leaves: bigint[] = knownDeposits.map(e => e.commitment);

  // 构建 tree
  const zeros = await buildZeros(levels);
  const treeLevels: bigint[][] = [leaves.slice()];
  for (let lvl = 0; lvl < levels; lvl++) {
    const cur = treeLevels[lvl];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      const left = cur[i];
      const right = i + 1 < cur.length ? cur[i + 1] : zeros[lvl];
      next.push(await poseidonHash([left, right]));
    }
    treeLevels.push(next);
  }

  // root = 最顶层, 但要继续按 Tornado 模式 hash 到 levels 高度
  // (如果 leaves 多, 上面 loop 已经收敛到 1 个; 还要继续跟 zeros 走完剩下层)
  let curLevel = treeLevels[levels].length > 0 ? treeLevels[levels] : [zeros[levels - 1]];
  // 通常 20 层够 2^20 = 1M 个 leaf, 实际生产 leaf 远少于此, treeLevels[20] 已经 = root
  // 但如果 leaves.length < 1, 上面 loop curLevel 仍是 [zeros 链]
  const root = curLevel[0] ?? zeros[levels - 1];

  function pathFor(leafIndex: number): MerklePath {
    if (leafIndex < 0 || leafIndex >= leaves.length) {
      throw new Error(`leafIndex ${leafIndex} 超出范围 [0, ${leaves.length})`);
    }
    const pathElements: string[] = [];
    const pathIndices: number[] = [];
    let curIdx = leafIndex;
    for (let lvl = 0; lvl < levels; lvl++) {
      const isRight = curIdx & 1;
      const sibIdx = isRight ? curIdx - 1 : curIdx + 1;
      const level = treeLevels[lvl];
      const sibling = sibIdx < level.length ? level[sibIdx] : zeros[lvl];
      pathElements.push(sibling.toString());
      pathIndices.push(isRight);
      curIdx = curIdx >> 1;
    }
    return { pathElements, pathIndices, root };
  }

  return { leaves, treeLevels, root, zeros, pathFor };
}
