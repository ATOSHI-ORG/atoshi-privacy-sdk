# Atoshi Privacy SDK

TypeScript SDK for privacy transactions on Atoshi Chain.

## 🚀 Features

- 🔐 **Privacy Wallet**: Manage keypairs and private notes
- 💸 **Deposit**: Convert public tokens to private notes
- 🔓 **Withdraw**: Convert private notes back to public tokens
- 🔄 **Transfer**: Private transfers between users
- 🌐 **RPC Client**: Communicate with privacy node

## 📦 Installation

```bash
npm install @atoshi/privacy-sdk
# or
yarn add @atoshi/privacy-sdk
# or
pnpm add @atoshi/privacy-sdk
```

## 🏁 Quick Start

```typescript
import { PrivacyWallet, TransactionBuilder, PrivacyRpcClient } from '@atoshi/privacy-sdk';
import { ethers } from 'ethers';

// Initialize wallet
const wallet = new PrivacyWallet();
await wallet.init();

// Generate or import keypair
const keypair = await wallet.generateKeypair();
console.log('Public Key:', keypair.publicKey.toString());

// Or import existing keypair
// await wallet.importKeypair(BigInt('your_private_key'));

// Setup transaction builder
const config = {
  nodeUrl: 'http://localhost:8080',
  l1RpcUrl: 'http://localhost:8545',
  shieldContract: '0x...',
  circuitsPath: './circuits/build',
  keysPath: './circuits/keys',
};

const builder = new TransactionBuilder(wallet, config);

// Connect signer
const provider = new ethers.BrowserProvider(window.ethereum);
const signer = await provider.getSigner();
await builder.init(signer);

// Deposit 1 ETH
const depositResult = await builder.deposit({
  amount: ethers.parseEther('1'),
  tokenAddress: ethers.ZeroAddress,
});
console.log('Deposit:', depositResult);

// Check balance
const balance = wallet.getBalance(0n); // 0n = native token
console.log('Private Balance:', ethers.formatEther(balance));

// Withdraw
const withdrawResult = await builder.withdraw({
  noteIndex: 0,
  recipient: '0x...',
});
console.log('Withdraw:', withdrawResult);
```

## 📖 API Reference

### PrivacyWallet

```typescript
class PrivacyWallet {
  // Initialize wallet
  async init(): Promise<void>;
  
  // Generate new keypair
  async generateKeypair(): Promise<Keypair>;
  
  // Import existing keypair
  async importKeypair(privateKey: bigint): Promise<Keypair>;
  
  // Get current keypair
  getKeypair(): Keypair | null;
  
  // Get public key
  getPublicKey(): bigint | null;
  
  // Create a new note
  async createNote(amount: bigint, tokenId: bigint, recipient?: bigint): Promise<Note>;
  
  // Get all notes
  getAllNotes(): NoteRecord[];
  
  // Get unspent notes
  getUnspentNotes(): NoteRecord[];
  
  // Get balance for a token
  getBalance(tokenId: bigint): bigint;
  
  // Export wallet for backup
  export(): string;
  
  // Import wallet from backup
  async import(data: string): Promise<void>;
}
```

### TransactionBuilder

```typescript
class TransactionBuilder {
  // Initialize with signer
  async init(signer?: ethers.Signer): Promise<void>;
  
  // Deposit tokens
  async deposit(params: DepositParams): Promise<TransactionResult>;
  
  // Withdraw tokens
  async withdraw(params: WithdrawParams): Promise<TransactionResult>;
  
  // Private transfer
  async transfer(params: TransferParams): Promise<TransactionResult>;
}
```

### PrivacyRpcClient

```typescript
class PrivacyRpcClient {
  // Health check
  async health(): Promise<boolean>;
  
  // Get node state
  async getState(): Promise<NodeState>;
  
  // Get Merkle root
  async getRoot(): Promise<{ root: bigint; nextIndex: number }>;
  
  // Check if nullifier is spent
  async isNullifierSpent(nullifier: bigint): Promise<boolean>;
  
  // Get Merkle proof
  async getMerkleProof(leafIndex: number): Promise<MerkleProof>;
}
```

## 🔧 Configuration

```typescript
interface SdkConfig {
  // Privacy node RPC URL
  nodeUrl: string;
  
  // L1 chain RPC URL
  l1RpcUrl: string;
  
  // Shield contract address
  shieldContract: string;
  
  // Path to circuit WASM files
  circuitsPath?: string;
  
  // Path to proving keys
  keysPath?: string;
}
```

## 📝 Examples

### Deposit ERC20 Token

```typescript
import { ethers } from 'ethers';

// First approve the Shield contract
const token = new ethers.Contract(tokenAddress, ERC20_ABI, signer);
await token.approve(shieldContract, amount);

// Then deposit
const result = await builder.deposit({
  amount: ethers.parseUnits('100', 18),
  tokenAddress: tokenAddress,
});
```

### Private Transfer

```typescript
// Get recipient's public key (they share this publicly)
const recipientPubKey = BigInt('recipient_public_key');

// Transfer
const result = await builder.transfer({
  noteIndex: 0,
  recipientPublicKey: recipientPubKey,
});
```

### Backup and Restore

```typescript
// Export wallet
const backup = wallet.export();
localStorage.setItem('wallet_backup', backup);

// Restore wallet
const newWallet = new PrivacyWallet();
await newWallet.init();
await newWallet.import(localStorage.getItem('wallet_backup')!);
```

## 🔐 Security

- **Private keys** are never sent to any server
- **ZK proofs** are generated locally
- **Notes** are encrypted and stored locally
- Always backup your wallet data

## 📄 License

MIT License

