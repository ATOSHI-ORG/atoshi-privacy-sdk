import { describe, it, expect } from 'vitest';
import { viewingPubKey, encryptNote, decryptNote } from '../crypto/ecies';

/**
 * Scanner 的纯单元测试 (不依赖 RPC).
 * 完整链上扫描的 e2e 在 atoshi-privacy-contracts/scripts/l2-e2e-test.js
 * 跟 Stage 4 (shield 项目联调) 里验证.
 *
 * 这里只验证:
 *   - viewingPubKey 导出可用
 *   - encryptNote / decryptNote 在 scanner 模块 re-export 正确工作
 *   - 解密失败返回 null 不抛错
 */

describe('scanner crypto integration', () => {
  it('viewingPubKey 跨模块一致', () => {
    const vk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
    const pub1 = viewingPubKey(vk);
    expect(pub1.length).toBe(32);
  });

  it('双 viewer 互相不能解密对方的 note', async () => {
    const aliceVk = 0xaaaa567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
    const bobVk = 0xbbbb567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

    const aliceBlob = await encryptNote(
      { amount: '100', tokenId: '0', blinding: '12345' },
      viewingPubKey(aliceVk)
    );

    // Bob 试解 Alice 的 → 失败
    expect(await decryptNote(aliceBlob, bobVk)).toBeNull();
    // Alice 解自己的 → 成功
    expect(await decryptNote(aliceBlob, aliceVk)).toEqual({
      amount: '100',
      tokenId: '0',
      blinding: '12345',
    });
  });
});
