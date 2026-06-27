/**
 * Atoshi Privacy SDK — multi-network configuration.
 *
 * One SDK version supports both testnet and mainnet. The caller picks
 * the network via:
 *   import { AtoshiClient, MAINNET_CONFIG } from '@atoshi/privacy-sdk';
 *   const client = new AtoshiClient(MAINNET_CONFIG);
 *
 * Or by chainId lookup:
 *   const cfg = NETWORKS[await wallet.getChainId()];
 *   const client = new AtoshiClient(cfg);
 *
 * Or build a fully custom config (for local dev / private deployments).
 */

export interface SdkConfig {
  /** Human-readable network name, e.g. "atoshi-mainnet" */
  name: string;

  // ============ L1 (atoshi-chain) ============
  l1RpcUrl: string;
  l1ChainId: number;
  l1BridgeContract: string;  // Polygon Bridge on L1

  // ============ L2 (atoshi privacy L2) ============
  l2RpcUrl: string;
  l2ChainId: number;
  l2BridgeContract: string;  // Polygon Bridge on L2 (genesis-fixed)
  /** Polygon CDK rollup networkID, used as `destinationNetwork` in L1→L2
   *  bridgeAsset / bridgeMessage calls. L1 mainnet origin = 0, each rollup
   *  gets a sequential ID assigned at createRollup time.  Wrong value here
   *  → tx succeeds on L1 but funds are unclaimable (different network). */
  bridgeNetworkId: number;

  // ============ Privacy contracts (deployed on L2) ============
  shieldContract: string;    // Shield.sol on L2
  /** Kept for backwards-compat with older SDK consumers.  Filled with
   *  ShieldVerifier; the SDK itself does not call verifiers directly. */
  verifierContract: string;

  // ============ Services (Phase 3 — Bridge + Relayer) ============
  /** zkevm-bridge-service REST API (merkle proofs, deposit list). */
  bridgeServiceUrl?: string;
  /** Atoshi Privacy Relayer (sponsored transfer / unshield). */
  relayerUrl?: string;
  /** Relayer L2 EOA — bound into unshield ZK proof's `_relayer` field
   *  so a third party can't intercept and claim the fee. */
  relayerAddress?: string;

  // ============ Circuit Configuration ============
  circuitsPath?: string;     // Path to circuit WASM files
  keysPath?: string;         // Path to proving keys

  // ============ Optional ============
  proverUrl?: string;
  indexerUrl?: string;
}

// ============================================================================
// Built-in network configurations
// ============================================================================

/**
 * Atoshi testnet (chainID L1=88288, L2=67890).
 * Contracts deployed 2026-06-21 from audit/2026-06-fixes commit 9c6adaa.
 */
export const TESTNET_CONFIG: SdkConfig = {
  name: 'atoshi-testnet',

  l1RpcUrl: 'https://rpc-testnet.atoshi.org',
  l1ChainId: 88288,
  l1BridgeContract: '0x8024430BC06A3BfFFDF65bE4a5f86833E61A1C63',

  l2RpcUrl: 'https://l2-rpc1-testnet.atoshi.org',
  l2ChainId: 67890,
  l2BridgeContract: '0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe',
  bridgeNetworkId: 1,

  shieldContract: '0xB515a4a438c168cf34F1ABEEa40a835a39af5625',
  verifierContract: '0x8409B3Fd5b7F48678AA8D0Ffc97aDFa18612dA6A',

  bridgeServiceUrl: 'https://l2-rpc1-testnet.atoshi.org/bridger',
  relayerUrl: 'https://l2-rpc1-testnet.atoshi.org/relayer',
  relayerAddress: '0x06A5381541211Ed5676C8Fd08E0cAaDb8b2829f7',

  circuitsPath: './circuits/build',
  keysPath: './circuits/keys',
};

/**
 * Atoshi mainnet (chainID L1=88188, L2=67897).
 * Contracts deployed 2026-06-27 from audit/2026-06-fixes commit 4dfc671.
 */
export const MAINNET_CONFIG: SdkConfig = {
  name: 'atoshi-mainnet',

  l1RpcUrl: 'https://rpc.atoshi.org',
  l1ChainId: 88188,
  l1BridgeContract: '0x08cE2E12DdA5f5AD1f458a11eF1Bcb7A96498E05',

  l2RpcUrl: 'https://l2-public.rpc.atoshi.org',
  l2ChainId: 67897,
  l2BridgeContract: '0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe',
  bridgeNetworkId: 2,

  shieldContract: '0xf9639ac8869B514B50A5F5174B26EA94Fa558c99',
  verifierContract: '0xa6163377B79eCA32f76eA3F5d083637D5e90557D',

  bridgeServiceUrl: 'https://bridge.atoshi.org',
  relayerUrl: 'https://bridge.atoshi.org/relayer',
  relayerAddress: '0xF5F573c7A42BeA8C2bC7888AE011aB45fDD65326',

  circuitsPath: './circuits/build',
  keysPath: './circuits/keys',
};

/**
 * Lookup table keyed by L2 chainID so callers can do:
 *   const cfg = NETWORKS[await wallet.getChainId()];
 *   if (!cfg) throw new Error('Unsupported network: ' + chainId);
 */
export const NETWORKS: Record<number, SdkConfig> = {
  [TESTNET_CONFIG.l2ChainId]: TESTNET_CONFIG,
  [MAINNET_CONFIG.l2ChainId]: MAINNET_CONFIG,
};

/** Pick a built-in config by L2 chainID. */
export function getConfigByChainId(l2ChainId: number): SdkConfig {
  const cfg = NETWORKS[l2ChainId];
  if (!cfg) {
    throw new Error(
      `Unsupported L2 chainID ${l2ChainId}. ` +
      `Known networks: ${Object.keys(NETWORKS).join(', ')}. ` +
      `Pass a custom SdkConfig to AtoshiClient if you need a non-standard network.`
    );
  }
  return cfg;
}

/**
 * Default config kept for backwards compatibility with SDK 0.4.0 callers
 * that did `new AtoshiClient()` without args. Points to mainnet — new
 * code should pass a config explicitly via NETWORKS[chainId] or by name.
 */
export const DEFAULT_CONFIG: SdkConfig = MAINNET_CONFIG;

// ============================================================================
// Validation
// ============================================================================

/**
 * Throws if config is missing required fields or has malformed addresses.
 * Called by AtoshiClient at construction.
 */
export function validateConfig(config: SdkConfig): void {
  const required: (keyof SdkConfig)[] = [
    'l1RpcUrl',
    'l1ChainId',
    'l1BridgeContract',
    'l2RpcUrl',
    'l2ChainId',
    'l2BridgeContract',
    'bridgeNetworkId',
    'shieldContract',
    'verifierContract',
  ];

  for (const field of required) {
    if (config[field] === undefined || config[field] === null || config[field] === '') {
      throw new Error(`Missing required config field: ${field}`);
    }
  }

  const addressFields: (keyof SdkConfig)[] = [
    'l1BridgeContract',
    'l2BridgeContract',
    'shieldContract',
    'verifierContract',
  ];
  if (config.relayerAddress) addressFields.push('relayerAddress');

  for (const field of addressFields) {
    const addr = config[field] as string;
    if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) {
      throw new Error(`Invalid address for ${field}: ${addr}`);
    }
  }

  if (config.l1ChainId === config.l2ChainId) {
    throw new Error('L1 and L2 chain IDs must be different');
  }
}
