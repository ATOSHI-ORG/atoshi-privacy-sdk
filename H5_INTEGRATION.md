# @atoshi/privacy-sdk H5 集成文档

> 给 H5 前端团队的完整接入指南。
> 适用场景：网页 / 钱包内嵌 webview / 移动浏览器
> 最低要求：现代浏览器（Chrome 90+ / Safari 14+ / Edge 90+），需支持 Web Crypto API

---

## 0. 系统全景图（必读）

```
┌──────────────────────────────────────────────────────────────┐
│           隐私 H5 (本文档讲的部分)                            │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐                  │
│  │ 业务 UI 组件     │  │ @atoshi/         │                  │
│  │ (React/Vue/...)  │──│ privacy-sdk      │                  │
│  │                  │  │                  │                  │
│  │ - Shield 流程    │  │ - 密钥派生        │                  │
│  │ - Unshield 流程  │  │ - ECIES 加密      │                  │
│  │ - Transfer 流程  │  │ - 链上扫描        │                  │
│  │ - Note 列表      │  │ - Note 管理       │                  │
│  └────────┬─────────┘  └────────┬─────────┘                  │
│           │                     │                            │
│           ▼                     ▼                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           window.ethereum (EIP-1193)                   │ │
│  │  - eth_requestAccounts                                 │ │
│  │  - eth_signTypedData_v4   ← 派生 privacy keys 用       │ │
│  │  - eth_sendTransaction    ← Shield.deposit/transfer 等  │ │
│  └────────────────────────┬───────────────────────────────┘ │
└───────────────────────────┼──────────────────────────────────┘
                            │
                            ▼
       ┌────────────────────────────────────────┐
       │ 原生钱包 / MetaMask / 其他 EIP-1193 wallet │
       │ - 用户私钥保管在这里                    │
       │ - 显示签名/交易确认弹窗                │
       └────────────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │  Atoshi L2 (chain 67890)    │
              │  Shield 合约                │
              │  0x2942ACf67055...8CBa8C    │
              └─────────────────────────────┘
```

**关键认知**：
- H5 不能直接读用户私钥；私钥永远在原生钱包里
- H5 通过 `window.ethereum` 跟钱包要"签名"/"发交易"
- ECIES 加密 / Poseidon 哈希 / snarkjs proof 全部在 H5 本地完成
- 用户的隐私身份（spending/viewing key）从 EOA 签名派生 → 无需额外助记词

---

## 1. 安装

```bash
npm install @atoshi/privacy-sdk
# 或
yarn add @atoshi/privacy-sdk
```

依赖（已自动安装）：
- `ethers ^6.9.0` — EVM RPC
- `circomlibjs ^0.1.7` — Poseidon
- `snarkjs ^0.7.3` — ZK proof generation
- `@noble/curves ^2.x` — X25519 (ECIES)
- `@noble/hashes ^2.x` — SHA256

---

## 2. 完整接入流程（5 步）

### Step 1: 用户连接钱包（标准 EIP-1193）

```typescript
import { ethers } from 'ethers';

// 连接钱包（用户授权 + 拿到地址）
async function connectWallet(): Promise<string> {
  if (!window.ethereum) {
    throw new Error('No EVM wallet detected');
  }
  const accounts = await window.ethereum.request({
    method: 'eth_requestAccounts',
  });
  return accounts[0];
}

// 用 ethers 包装,后续签名 / 发交易都用 signer
function getSigner() {
  const provider = new ethers.BrowserProvider(window.ethereum);
  return provider.getSigner();
}
```

### Step 2: 派生隐私身份（首次进入隐私页面时做一次）

```typescript
import {
  SEED_DERIVATION_TYPED_DATA,
  seedFromEIP712Signature,
  deriveKeysFromSeed,
} from '@atoshi/privacy-sdk';

async function setupPrivacyKeys() {
  const signer = await getSigner();

  // 让用户用 EOA 签固定的 EIP-712 typed-data
  // 钱包 UI 会显示 "Atoshi Privacy v1" 域名 + 警示文案,用户能看懂
  const signature = await signer.signTypedData(
    SEED_DERIVATION_TYPED_DATA.domain,
    SEED_DERIVATION_TYPED_DATA.types,
    SEED_DERIVATION_TYPED_DATA.message,
  );

  // signature → masterSeed → 3 个 key
  const seed = await seedFromEIP712Signature(signature);
  const keys = await deriveKeysFromSeed(seed);

  // keys = {
  //   spendingKey: bigint,    // 算 nullifier 用,绝不能泄漏
  //   viewingKey:  bigint,    // 解密自己收到的 Note 用,可分享给会计 (只读)
  //   encryptionKey: Uint8Array, // 本地缓存加密用 (兜底)
  // }

  // 保存到 IndexedDB (用 encryptionKey 加密 spendingKey)
  await saveKeysToIndexedDB(keys);

  return keys;
}
```

**重要**：用户每次进 H5，**只需要签一次** EIP-712 即可恢复完整身份。同一个 EOA 签同一段 typed-data → 必然得到相同 key。

### Step 3: Shield（明文 → 隐私池）

```typescript
import {
  encryptNote,
  viewingPubKey,
} from '@atoshi/privacy-sdk';
import { buildPoseidon } from 'circomlibjs';

// SHIELD_ADDR 来自配置
const SHIELD_ADDR = '0x2942ACf67055b1520904227d13789cc03C8CBa8C';
const NATIVE_TOKEN = '0x0000000000000000000000000000000000000000';

async function shield(amountAatos: bigint, keys: DerivedKeys) {
  // 1. 生成随机 blinding
  const blindingBytes = crypto.getRandomValues(new Uint8Array(31));
  const blinding = BigInt('0x' + Buffer.from(blindingBytes).toString('hex'));

  // 2. 算 commitment = Poseidon(amount, tokenId=0, ownerPubkey, blinding)
  //    ownerPubkey = Poseidon(spendingKey)
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const ownerPubkey = F.toObject(poseidon([keys.spendingKey]));
  const commitment = F.toObject(
    poseidon([amountAatos, 0n, ownerPubkey, blinding])
  );

  // 3. 加密 Note 给自己(以便换设备时能扫回来)
  const encryptedNote = await encryptNote(
    {
      amount: amountAatos.toString(),
      tokenId: '0',
      blinding: blinding.toString(),
    },
    viewingPubKey(keys.viewingKey),
  );

  // 4. 调 Shield.deposit
  const signer = await getSigner();
  const shieldAbi = [
    'function deposit(uint256 commitment, address token, uint256 amount, bytes encryptedNote) external payable',
  ];
  const shield = new ethers.Contract(SHIELD_ADDR, shieldAbi, signer);
  const tx = await shield.deposit(
    commitment,
    NATIVE_TOKEN,
    amountAatos,
    '0x' + Buffer.from(encryptedNote).toString('hex'),
    { value: amountAatos, gasLimit: 1_500_000n },
  );
  const receipt = await tx.wait();

  // 5. 从事件解析 leafIndex
  const depositEvent = receipt.logs.find((log) =>
    log.topics[0] === ethers.id('Deposit(uint256,uint256,uint256,address,uint256,bytes)')
  );
  const leafIndex = Number(BigInt(depositEvent.data.slice(0, 66)));

  // 6. 本地保存 Note
  await saveNote({
    commitment, amount: amountAatos, tokenId: 0n, blinding,
    leafIndex, ownerPubkey, txHash: tx.hash,
  });

  return { txHash: tx.hash, leafIndex };
}
```

### Step 4: Unshield（隐私 → 明文）

```typescript
import * as snarkjs from 'snarkjs';

async function unshield(
  note: LocalNote,
  recipientAddr: string,
  keys: DerivedKeys,
) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  // 1. 算 nullifier
  const nullifierHash = F.toObject(
    poseidon([note.commitment, keys.spendingKey, BigInt(note.leafIndex)])
  );

  // 2. 重建 Merkle tree(从链上拉所有 Deposit + Transfer 事件)
  //    见 scanner 模块 + helper utils
  const { tree, root } = await rebuildMerkleTreeFromChain(SHIELD_ADDR);
  const merklePath = tree.pathFor(note.leafIndex);

  // 3. 构造 witness
  const input = {
    root: root.toString(),
    nullifierHash: nullifierHash.toString(),
    recipient: BigInt(recipientAddr).toString(),
    tokenId: '0',
    amount: note.amount.toString(),
    fee: '0',
    privateKey: keys.spendingKey.toString(),
    blinding: note.blinding.toString(),
    leafIndex: note.leafIndex.toString(),
    pathElements: merklePath.elements,
    pathIndices: merklePath.indices,
  };

  // 4. 生成 ZK proof (snarkjs.wasm, 浏览器里跑 ~15-30 秒)
  const { proof } = await snarkjs.groth16.fullProve(
    input,
    '/circuits/unshield.wasm',          // 部署到 CDN 或 public/ 目录
    '/circuits/unshield_final.zkey',
  );

  // 5. 格式化 proof (G2 内层 swap)
  const pA = [proof.pi_a[0], proof.pi_a[1]];
  const pB = [
    [proof.pi_b[0][1], proof.pi_b[0][0]],
    [proof.pi_b[1][1], proof.pi_b[1][0]],
  ];
  const pC = [proof.pi_c[0], proof.pi_c[1]];

  // 6. 调 Shield.withdraw
  const signer = await getSigner();
  const shieldAbi = [
    'function withdraw(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256 root, uint256 nullifierHash, address recipient, address relayer, uint256 fee, address token, uint256 amount) external',
  ];
  const shield = new ethers.Contract(SHIELD_ADDR, shieldAbi, signer);
  const tx = await shield.withdraw(
    pA, pB, pC, root, nullifierHash, recipientAddr,
    ethers.ZeroAddress, // relayer (自付)
    0n,                 // fee
    NATIVE_TOKEN,
    note.amount,
    { gasLimit: 500_000n },
  );
  await tx.wait();

  // 7. 标记本地 Note 为已花费
  await markNoteSpent(note.commitment);
}
```

### Step 5: Transfer（隐私 → 隐私，Alice 转给 Bob）

跟 Unshield 类似，区别：
- `pathElements/pathIndices` 给旧 Note 的位置
- 多算一个 `newCommitment = Poseidon(amount, tokenId, bob.ownerPubkey, newBlinding)`
- 多用一个 `encryptedNote = encryptNote(noteData, bob.viewingPubKey)` 给 Bob 解
- 调 `Shield.transfer(...)` 而不是 `withdraw`

```typescript
async function transfer(
  oldNote: LocalNote,
  bobViewingPubKey: Uint8Array,    // Bob 提前给的
  bobOwnerPubkey: bigint,          // 同上
  keys: DerivedKeys,
) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const nullifierHash = F.toObject(
    poseidon([oldNote.commitment, keys.spendingKey, BigInt(oldNote.leafIndex)])
  );

  // 给 Bob 的新 Note
  const newBlindingBytes = crypto.getRandomValues(new Uint8Array(31));
  const newBlinding = BigInt('0x' + Buffer.from(newBlindingBytes).toString('hex'));
  const newCommitment = F.toObject(
    poseidon([oldNote.amount, 0n, bobOwnerPubkey, newBlinding])
  );

  const encryptedNote = await encryptNote(
    {
      amount: oldNote.amount.toString(),
      tokenId: '0',
      blinding: newBlinding.toString(),
    },
    bobViewingPubKey,
  );

  // ... 重建 tree, 生成 transfer proof (用 transfer.wasm + transfer_final.zkey),
  //     调 Shield.transfer(pA, pB, pC, root, nullifierHash, newCommitment, encryptedNote)
  // ...
}
```

---

## 3. 跨设备 / 卸载后恢复

```typescript
import { ChainScanner } from '@atoshi/privacy-sdk';

async function restoreNotesFromChain(keys: DerivedKeys) {
  const scanner = new ChainScanner({
    rpcUrl: 'http://52.76.210.218:8123',
    shieldAddress: '0x2942ACf67055b1520904227d13789cc03C8CBa8C',
    fromBlock: 0,                  // 首次启动从 0 开始扫
    chunkSize: 9000,               // 单批最多扫 9000 块 (RPC 限制)
  });

  // 扫所有 Deposit + Transfer 事件, 挨个用 viewingKey 试解密
  // 解密成功的就是 "我的 Note", 自动入库
  const myNotes = await scanner.scanForViewer(
    keys.viewingKey,
    keys.spendingKey,
  );

  // myNotes: RecoveredNote[] 包含 spend 所需全字段
  for (const note of myNotes) {
    await saveNote(note);
  }

  // 也要从 nullifier mapping 排除掉已经花掉的 Note
  // (可以查 Shield.isSpent(nullifier))
}
```

**用户体验**：
```
用户换手机/换电脑/卸载重装 → 
    1. 装回钱包, 导回 EOA
    2. 打开隐私 H5, 签一次 EIP-712 (跟第一次一模一样)
    3. 钱包后台扫链, 几秒到几十秒完成
    4. 历史 Note 全部回来
```

**完全不需要**用户手动备份。

---

## 4. 关键文件 / 资源

```
项目目录/
├── public/
│   └── circuits/                    ← 部署时打包进 dist
│       ├── unshield.wasm            (2.9 MB)
│       ├── unshield_final.zkey      (5.3 MB)
│       ├── transfer.wasm            (2.9 MB)
│       └── transfer_final.zkey      (5.5 MB)
│
├── src/
│   ├── privacy/
│   │   ├── shield.ts                ← Step 3 代码
│   │   ├── unshield.ts              ← Step 4 代码
│   │   ├── transfer.ts              ← Step 5 代码
│   │   ├── scanner.ts               ← 跨设备恢复
│   │   └── merkle.ts                ← 从链事件重建 tree (参考 atoshi-privacy-contracts/scripts/l2-e2e-test.js)
│   └── storage/
│       └── indexed-db.ts            ← Note + keys 本地持久化
```

**电路文件来源**: `/Users/liudongqi/atoshi/atoshi-privacy-circuits/build/{transfer,unshield}/` 和 `/Users/liudongqi/atoshi/atoshi-privacy-circuits/keys/`

---

## 5. 错误处理 / 性能优化

### 常见错误

| 报错 | 原因 | 修法 |
|---|---|---|
| `Shield: invalid commitment` | commitment ≥ BN254 field size | blinding 控制在 248 位以内 |
| `Shield: amount too small` | amount < minDeposit | 查 `Shield.minDeposits(NATIVE_TOKEN)` |
| `Shield: invalid proof` | ZK proof 验证失败 | root/witness 不匹配,检查 Merkle tree 重建逻辑 |
| `Shield: already spent` | nullifier 已用过 | 本地 Note 状态没同步,触发一次 scanner 刷新 |
| ZK proof 生成 30+ 秒 | snarkjs 在低端机慢 | UI 上加进度条 + "正在生成隐私证明..." 文案,不能让用户切后台 |
| `eth_call` 返回 "from state" 错 | L2 RPC 临时挂 | 重试 / 切备用 RPC |

### 性能建议

1. **electric.wasm / zkey 文件加载**：首次加载 ~17 MB，加缓存 + service worker。后续直接走 cache。
2. **ZK proof 生成**：必须用 Web Worker，**不能阻塞主线程**。否则 UI 会卡死。
3. **链上扫描**：增量扫描（记录 lastScannedBlock），每次只扫新区块。
4. **Note 列表**：用 IndexedDB 而非 localStorage（10MB+ 数据 localStorage 撑不住）。

---

## 6. 完整 API 速查

```typescript
// === 密钥派生 ===
import {
  SEED_DERIVATION_TYPED_DATA,    // EIP-712 typed-data 常量
  seedFromEIP712Signature,        // signature → masterSeed
  seedFromMnemonic,                // 备选:从 12/24 词派生
  deriveKeysFromSeed,              // masterSeed → {spendingKey, viewingKey, encryptionKey}
  generateMnemonic,                // 生成新助记词 (备用)
  encryptBackup, decryptBackup,    // 本地 AES-GCM 加密备份
} from '@atoshi/privacy-sdk';

// === ECIES (Note 加密广播) ===
import {
  viewingPubKey,                   // viewingKey → X25519 pubkey
  encryptNote,                     // 加密 NotePlaintext 给接收方
  decryptNote,                     // 用 viewingKey 解密
} from '@atoshi/privacy-sdk';

// === 链上扫描 ===
import { ChainScanner } from '@atoshi/privacy-sdk';
// new ChainScanner({rpcUrl, shieldAddress, fromBlock, chunkSize})
// .scanForViewer(viewingKey, spendingKey) → RecoveredNote[]
```

---

## 7. 配置常量

```typescript
// L2 网络
export const L2_RPC_URL = 'http://52.76.210.218:8123';
export const L2_CHAIN_ID = 67890;

// 合约地址 (2026-05-28 部署,带 encryptedNote 支持)
export const SHIELD_ADDR = '0x2942ACf67055b1520904227d13789cc03C8CBa8C';
export const TRANSFER_VERIFIER = '0x14B3743E87d75786Ce350cAF26e1F719Ae5c0825';
export const UNSHIELD_VERIFIER = '0xa7944803e80B93952e9421622A4aBf75E77B5D17';
export const POSEIDON_CONTRACT = '0xC1d3Bb5B7b9f4f097e7cD0126608D498A2986DAe';

// 协议常量
export const NATIVE_TOKEN = '0x0000000000000000000000000000000000000000';
export const TREE_LEVELS = 20;
export const BN254_FIELD_SIZE = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);
export const PROTOCOL_FEE_BPS = 30; // 0.3% (在 Unshield 时扣)
```

---

## 8. 参考代码

最完整的参考实现：[`/Users/liudongqi/shield`](/Users/liudongqi/shield)
- React + Vite + wagmi + rainbowkit
- 完整 UI（Setup / PublicDashboard / PrivateDashboard / ActionModal）
- 已经接好新 Shield 0x2942ACf6 + encryptedNote ABI

跑起来：
```bash
cd /Users/liudongqi/shield
npm install
npm run dev   # 启动 http://localhost:5173
```

数据流参考：[`/Users/liudongqi/atoshi/atoshi-privacy-contracts/scripts/l2-e2e-test.js`](/Users/liudongqi/atoshi/atoshi-privacy-contracts/scripts/l2-e2e-test.js)
- 完整跑通 Shield → Merkle 重建 → ZK proof → Unshield → 双花保护
- 是 H5 端业务流程的"权威实现"，前端就照它的步骤写

---

## 9. 提问 / Issue

技术问题：项目根目录 `PLAN.md` 有完整设计文档 + 已知问题清单。
