/**
 * Updated SDK Configuration for Polygon L2
 */

export interface SdkConfig {
  // ============ L1 Configuration (atoshi-chain) ============
  l1RpcUrl: string;
  l1ChainId: number;
  l1BridgeContract: string;  // Polygon Bridge on L1

  // ============ L2 Configuration (Polygon zkEVM) ============
  l2RpcUrl: string;
  l2ChainId: number;
  l2BridgeContract: string;  // Polygon Bridge on L2 (fixed address)

  // ============ Privacy Contracts (deployed on L2) ============
  shieldContract: string;    // Shield.sol on L2
  verifierContract: string;  // Verifier.sol on L2

  // ============ Circuit Configuration ============
  circuitsPath?: string;     // Path to circuit WASM files
  keysPath?: string;         // Path to proving keys

  // ============ Optional ============
  proverUrl?: string;        // Optional remote prover service
  indexerUrl?: string;       // Optional indexer service for faster queries
}

/**
 * Default configuration for Atoshi testnet (2026-06 redeploy).
 *
 * L1 contracts (forkID=11, salt=0x...05, deployer A 0x73aF73D9...):
 *   - Bridge proxy:        0x8024430B...
 *   - GER:                 0xD19110E2...
 *   - RollupManager:       0xEF58A09e...
 *   - rollupAddress:       0xECe5D7e2...
 *
 * L2 privacy contracts (audit/2026-06-fixes, commit 9c6adaa):
 *   - Shield:              0xB515a4a4... (Merkle 32 + relayer-binding)
 *   - ShieldVerifier:      0x8409B3Fd...
 *   - TransferVerifier:    0x14B3743E...
 *   - UnshieldVerifier:    0xa7944803... (含 relayer binding)
 *   - Poseidon(2):         0xC1d3Bb5B...
 */
export const DEFAULT_CONFIG: Partial<SdkConfig> = {
  // L1 (atoshi-chain testnet)
  l1RpcUrl: 'https://rpc-testnet.atoshi.org',
  l1ChainId: 88288,
  l1BridgeContract: '0x8024430BC06A3BfFFDF65bE4a5f86833E61A1C63',

  // L2 (Atoshi privacy testnet)
  l2RpcUrl: 'http://localhost:8123',
  l2ChainId: 67890,
  // L2 Bridge proxy (在 L2 genesis 里固定地址, 跟 L1 Bridge 不同址)
  l2BridgeContract: '0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe',

  // Privacy contracts (audit/2026-06-fixes deployment)
  shieldContract: '0xB515a4a438c168cf34F1ABEEa40a835a39af5625',
  // verifierContract 字段历史遗留, SDK 不直接调; 填主 verifier 占位
  // (实际 3 个 verifier 都在 Shield 合约内部引用, 见 deployments/atoshi_l2.json)
  verifierContract: '0x8409B3Fd5b7F48678AA8D0Ffc97aDFa18612dA6A',

  // Circuits
  circuitsPath: './circuits/build',
  keysPath: './circuits/keys',
};

/**
 * Validate SDK configuration
 */
export function validateConfig(config: SdkConfig): void {
  const required = [
    'l1RpcUrl',
    'l1ChainId',
    'l1BridgeContract',
    'l2RpcUrl',
    'l2ChainId',
    'shieldContract',
    'verifierContract',
  ];

  for (const field of required) {
    if (!(field in config)) {
      throw new Error(`Missing required config field: ${field}`);
    }
  }

  // Validate addresses
  const addresses = [
    'l1BridgeContract',
    'l2BridgeContract',
    'shieldContract',
    'verifierContract',
  ];

  for (const field of addresses) {
    const addr = (config as any)[field];
    if (typeof addr === 'string' && !addr.match(/^0x[a-fA-F0-9]{40}$/)) {
      throw new Error(`Invalid address for ${field}: ${addr}`);
    }
  }

  // Validate chain IDs
  if (config.l1ChainId === config.l2ChainId) {
    throw new Error('L1 and L2 chain IDs must be different');
  }
}

/**
 * Example configuration for production
 */
export const PRODUCTION_CONFIG_EXAMPLE: SdkConfig = {
  // L1 (atoshi-chain mainnet)
  l1RpcUrl: 'https://rpc.atoshi.network',
  l1ChainId: 12345,
  l1BridgeContract: '0x...', // Deployed L1 bridge address

  // L2 (Polygon zkEVM)
  l2RpcUrl: 'https://l2-rpc.atoshi.network',
  l2ChainId: 67890,
  l2BridgeContract: '0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe',

  // Privacy contracts on L2
  shieldContract: '0x...', // Deployed Shield.sol address
  verifierContract: '0x...', // Deployed Verifier.sol address

  // Circuits
  circuitsPath: './circuits/build',
  keysPath: './circuits/keys',

  // Optional services
  proverUrl: 'https://prover.atoshi.network',
  indexerUrl: 'https://indexer.atoshi.network',
};

