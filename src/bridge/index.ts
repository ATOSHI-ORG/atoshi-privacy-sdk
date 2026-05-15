/**
 * Bridge Client for L1 <-> L2 asset transfers
 * 
 * Handles bridging assets between atoshi-chain (L1) and Polygon zkEVM (L2)
 */

import { ethers } from 'ethers';

// Polygon Bridge ABI (simplified)
const BRIDGE_ABI = [
  'function bridgeAsset(uint32 destinationNetwork, address destinationAddress, uint256 amount, address token, bool forceUpdateGlobalExitRoot, bytes permitData) external payable',
  'function claimAsset(bytes32[32] smtProof, uint32 index, bytes32 mainnetExitRoot, bytes32 rollupExitRoot, uint32 originNetwork, address originTokenAddress, uint32 destinationNetwork, address destinationAddress, uint256 amount, bytes metadata) external',
  'function getDepositRoot() external view returns (bytes32)',
  'event BridgeEvent(uint8 leafType, uint32 originNetwork, address originAddress, uint32 destinationNetwork, address destinationAddress, uint256 amount, bytes metadata, uint32 depositCount)',
];

export interface BridgeConfig {
  l1RpcUrl: string;
  l2RpcUrl: string;
  l1BridgeAddress: string;
  l2BridgeAddress: string;
  l1ChainId: number;
  l2ChainId: number;
}

export interface BridgeResult {
  txHash: string;
  depositCount: number;
  globalIndex: bigint;
}

export class BridgeClient {
  private l1Provider: ethers.Provider;
  private l2Provider: ethers.Provider;
  private l1Bridge: ethers.Contract;
  private l2Bridge: ethers.Contract;
  private config: BridgeConfig;

  constructor(config: BridgeConfig) {
    this.config = config;
    this.l1Provider = new ethers.JsonRpcProvider(config.l1RpcUrl);
    this.l2Provider = new ethers.JsonRpcProvider(config.l2RpcUrl);

    this.l1Bridge = new ethers.Contract(
      config.l1BridgeAddress,
      BRIDGE_ABI,
      this.l1Provider
    );

    this.l2Bridge = new ethers.Contract(
      config.l2BridgeAddress,
      BRIDGE_ABI,
      this.l2Provider
    );
  }

  /**
   * Bridge assets from L1 to L2
   * 
   * @param token Token address (ethers.ZeroAddress for native token)
   * @param amount Amount to bridge
   * @param signer L1 signer
   * @returns Bridge transaction result
   */
  async bridgeToL2(
    token: string,
    amount: bigint,
    signer: ethers.Signer
  ): Promise<BridgeResult> {
    const bridge = this.l1Bridge.connect(signer);
    const destinationAddress = await signer.getAddress();

    let tx: ethers.ContractTransaction;

    if (token === ethers.ZeroAddress) {
      // Bridge native token
      tx = await bridge.bridgeAsset(
        1, // destinationNetwork (L2)
        destinationAddress,
        amount,
        token,
        true, // forceUpdateGlobalExitRoot
        '0x', // permitData
        { value: amount }
      );
    } else {
      // Bridge ERC20 token
      // First approve
      const tokenContract = new ethers.Contract(
        token,
        ['function approve(address spender, uint256 amount) external returns (bool)'],
        signer
      );
      const approveTx = await tokenContract.approve(this.config.l1BridgeAddress, amount);
      await approveTx.wait();

      // Then bridge
      tx = await bridge.bridgeAsset(
        1,
        destinationAddress,
        amount,
        token,
        true,
        '0x'
      );
    }

    const receipt = await tx.wait();
    
    // Parse BridgeEvent to get deposit count
    const bridgeEvent = receipt?.logs
      .map(log => {
        try {
          return this.l1Bridge.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find(event => event?.name === 'BridgeEvent');

    if (!bridgeEvent) {
      throw new Error('BridgeEvent not found in transaction receipt');
    }

    const depositCount = bridgeEvent.args.depositCount;
    const globalIndex = this.computeGlobalIndex(depositCount, 0); // 0 = L1 network

    return {
      txHash: tx.hash,
      depositCount,
      globalIndex,
    };
  }

  /**
   * Bridge assets from L2 to L1
   * 
   * @param token Token address
   * @param amount Amount to bridge
   * @param signer L2 signer
   * @returns Bridge transaction result
   */
  async bridgeToL1(
    token: string,
    amount: bigint,
    signer: ethers.Signer
  ): Promise<BridgeResult> {
    const bridge = this.l2Bridge.connect(signer);
    const destinationAddress = await signer.getAddress();

    let tx: ethers.ContractTransaction;

    if (token === ethers.ZeroAddress) {
      tx = await bridge.bridgeAsset(
        0, // destinationNetwork (L1)
        destinationAddress,
        amount,
        token,
        true,
        '0x',
        { value: amount }
      );
    } else {
      // Approve ERC20
      const tokenContract = new ethers.Contract(
        token,
        ['function approve(address spender, uint256 amount) external returns (bool)'],
        signer
      );
      const approveTx = await tokenContract.approve(this.config.l2BridgeAddress, amount);
      await approveTx.wait();

      tx = await bridge.bridgeAsset(
        0,
        destinationAddress,
        amount,
        token,
        true,
        '0x'
      );
    }

    const receipt = await tx.wait();
    
    const bridgeEvent = receipt?.logs
      .map(log => {
        try {
          return this.l2Bridge.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find(event => event?.name === 'BridgeEvent');

    if (!bridgeEvent) {
      throw new Error('BridgeEvent not found in transaction receipt');
    }

    const depositCount = bridgeEvent.args.depositCount;
    const globalIndex = this.computeGlobalIndex(depositCount, 1); // 1 = L2 network

    return {
      txHash: tx.hash,
      depositCount,
      globalIndex,
    };
  }

  /**
   * Claim assets on L1 after bridging from L2
   * 
   * This requires waiting for the L2 batch to be verified on L1 (usually 30-60 minutes)
   * 
   * @param claimData Claim data from bridge service
   * @param signer L1 signer
   */
  async claimOnL1(
    claimData: {
      smtProof: string[];
      index: number;
      mainnetExitRoot: string;
      rollupExitRoot: string;
      originNetwork: number;
      originTokenAddress: string;
      destinationNetwork: number;
      destinationAddress: string;
      amount: bigint;
      metadata: string;
    },
    signer: ethers.Signer
  ): Promise<string> {
    const bridge = this.l1Bridge.connect(signer);

    const tx = await bridge.claimAsset(
      claimData.smtProof,
      claimData.index,
      claimData.mainnetExitRoot,
      claimData.rollupExitRoot,
      claimData.originNetwork,
      claimData.originTokenAddress,
      claimData.destinationNetwork,
      claimData.destinationAddress,
      claimData.amount,
      claimData.metadata
    );

    const receipt = await tx.wait();
    return receipt!.hash;
  }

  /**
   * Wait for bridge confirmation
   * 
   * L1 -> L2: Usually 1-2 minutes
   * L2 -> L1: Usually 30-60 minutes (need to wait for batch verification)
   * 
   * @param txHash Bridge transaction hash
   * @param fromL1 Whether bridging from L1 to L2
   */
  async waitForBridgeConfirmation(
    txHash: string,
    fromL1: boolean = true
  ): Promise<void> {
    const provider = fromL1 ? this.l1Provider : this.l2Provider;
    
    console.log(`⏳ Waiting for bridge confirmation...`);
    console.log(`   Transaction: ${txHash}`);
    
    // Wait for transaction confirmation
    const receipt = await provider.waitForTransaction(txHash, 1);
    
    if (!receipt) {
      throw new Error('Transaction not found');
    }

    console.log(`✅ Transaction confirmed on ${fromL1 ? 'L1' : 'L2'}`);

    if (fromL1) {
      // L1 -> L2: Wait for L2 to process the deposit
      console.log('⏳ Waiting for L2 to process deposit (1-2 minutes)...');
      await this.sleep(60000); // Wait 1 minute
      console.log('✅ Bridge to L2 should be complete');
    } else {
      // L2 -> L1: Need to wait for batch verification
      console.log('⏳ Waiting for L2 batch verification on L1 (30-60 minutes)...');
      console.log('   You can claim assets on L1 after verification completes');
      console.log('   Use the bridge service API to check claim status');
    }
  }

  /**
   * Get bridge status
   */
  async getBridgeStatus(): Promise<{
    l1DepositRoot: string;
    l2DepositRoot: string;
  }> {
    const [l1Root, l2Root] = await Promise.all([
      this.l1Bridge.getDepositRoot(),
      this.l2Bridge.getDepositRoot(),
    ]);

    return {
      l1DepositRoot: l1Root,
      l2DepositRoot: l2Root,
    };
  }

  /**
   * Compute global index for bridge event
   */
  private computeGlobalIndex(depositCount: number, networkId: number): bigint {
    return (BigInt(depositCount) + (BigInt(networkId) << BigInt(64)));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export default BridgeClient;

