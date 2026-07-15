// rebuildMerkleTree must reconstruct the tree from BOTH Deposit and Transfer
// events, ordered by (blockNumber, logIndex) = the contract's leaf-insertion
// order. The previous version silently dropped every Transfer leaf, producing a
// wrong root (that's why the H5 proof path had to reimplement it).

import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import { rebuildMerkleTree } from './index';

const depIface = new ethers.Interface([
  'event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 timestamp, address indexed token, uint256 amount, bytes encryptedNote)',
]);
const trIface = new ethers.Interface([
  'event Transfer(uint256 indexed nullifierHash, uint256 indexed newCommitment, bytes encryptedNote)',
]);

function depositLog(commitment: bigint, leafIndex: number, blockNumber: number, index: number) {
  const { data, topics } = depIface.encodeEventLog('Deposit', [
    commitment, leafIndex, 0, ethers.ZeroAddress, 0, '0x',
  ]);
  return { blockNumber, index, topics, data };
}
function transferLog(newCommitment: bigint, blockNumber: number, index: number) {
  const { data, topics } = trIface.encodeEventLog('Transfer', [0, newCommitment, '0x']);
  return { blockNumber, index, topics, data };
}

function fakeProvider(logs: any[]) {
  return {
    getBlockNumber: async () => 100, // < chunkSize, so a single getLogs pass
    getLogs: async () => logs,
  } as any;
}

describe('rebuildMerkleTree', () => {
  it('includes Deposit + Transfer leaves ordered by (block, logIndex)', async () => {
    // Supplied out of order on purpose; sorting must fix it.
    const logs = [
      transferLog(300n, 5, 1),   // block 5, idx 1  -> 4th leaf
      depositLog(100n, 0, 1, 0), // block 1, idx 0  -> 1st leaf
      depositLog(200n, 1, 1, 1), // block 1, idx 1  -> 2nd leaf
      transferLog(400n, 5, 0),   // block 5, idx 0  -> 3rd leaf
    ];
    const tree = await rebuildMerkleTree(fakeProvider(logs), '0xShield', { levels: 4 });
    // Transfer leaves (300, 400) are present, and order follows chain order,
    // NOT the deposit-emitted leafIndex.
    expect(tree.leaves).toEqual([100n, 200n, 400n, 300n]);
  });

  it('produces a path whose leaf matches the requested index', async () => {
    const logs = [
      depositLog(100n, 0, 1, 0),
      transferLog(400n, 2, 0),
    ];
    const tree = await rebuildMerkleTree(fakeProvider(logs), '0xShield', { levels: 4 });
    expect(tree.leaves[1]).toEqual(400n); // the transfer output is spendable at index 1
    const path = tree.pathFor(1);
    expect(path.pathElements).toHaveLength(4); // one sibling per level
    expect(path.pathIndices).toEqual([1, 0, 0, 0]); // index 1 = right child at level 0
  });
});
