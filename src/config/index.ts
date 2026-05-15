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
 * Default configuration for development
 */
export const DEFAULT_CONFIG: Partial<SdkConfig> = {
  // L1 (atoshi-chain)
  l1RpcUrl: 'http://localhost:8545',
  l1ChainId: 12345,

  // L2 (Polygon zkEVM)
  l2RpcUrl: 'http://localhost:8123',
  l2ChainId: 67890,
  
  // L2 Bridge is at a fixed address on Polygon zkEVM
  l2BridgeContract: '0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe',

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

