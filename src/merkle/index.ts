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
  // Must match Shield.sol's TREE_LEVELS (bumped to 32 in audit Issue 7).
  const levels = options.levels ?? 32;
  const fromBlock = options.fromBlock ?? 0;
  const chunk = options.chunkSize ?? 9000;
  const latest = await provider.getBlockNumber();

  // The tree inserts a leaf for EVERY Deposit AND EVERY Transfer, one each, in
  // strict on-chain execution order (Shield.sol / MerkleTree.insert). Transfer
  // events do not emit a leafIndex, so we cannot rely on the emitted index for
  // ordering — instead we collect both event types with their (blockNumber,
  // logIndex) and reproduce the insertion order by sorting on those. This is the
  // same reconstruction the H5 proof path uses; the earlier version silently
  // dropped every Transfer leaf, producing a wrong root.
  type Entry = { blockNumber: number; logIndex: number; commitment: bigint };
  const entries: Entry[] = [];

  for (let from = fromBlock; from <= latest; from += chunk) {
    const to = Math.min(from + chunk - 1, latest);
    const logs = await provider.getLogs({
      address: shieldAddress,
      fromBlock: from,
      toBlock: to,
      // no topic filter — pull Deposit + Transfer in one pass
    });
    for (const log of logs) {
      try {
        if (log.topics[0] === DEPOSIT_TOPIC) {
          const parsed = DEPOSIT_IFACE.parseLog({ topics: log.topics as string[], data: log.data });
          if (!parsed) continue;
          entries.push({
            blockNumber: log.blockNumber,
            logIndex: log.index,
            commitment: BigInt(parsed.args.commitment),
          });
        } else if (log.topics[0] === TRANSFER_TOPIC) {
          const parsed = TRANSFER_IFACE.parseLog({ topics: log.topics as string[], data: log.data });
          if (!parsed) continue;
          entries.push({
            blockNumber: log.blockNumber,
            logIndex: log.index,
            commitment: BigInt(parsed.args.newCommitment),
          });
        }
      } catch { /* not a leaf-inserting event we recognize */ }
    }
  }

  // Sort by (blockNumber, logIndex) = the contract's leaf-insertion order, so
  // leaves[i] is the commitment at leafIndex i.
  entries.sort((a, b) => (a.blockNumber - b.blockNumber) || (a.logIndex - b.logIndex));
  const leaves: bigint[] = entries.map(e => e.commitment);

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
