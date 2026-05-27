import { describe, it, expect } from 'vitest';
import {
  viewingKeyToBytes,
  viewingPubKey,
  eciesEncrypt,
  eciesDecrypt,
  encryptNote,
  decryptNote,
} from './ecies';

describe('ecies', () => {
  // 模拟一个 viewingKey (来自 EIP-712 → HKDF, 这里随便取一个域内的 BigInt)
  const aliceViewingKey = BigInt(
    '0x12345678901234567890123456789012345678901234567890123456789012'
  );
  const bobViewingKey = BigInt(
    '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef01'
  );

  it('viewingKeyToBytes 输出固定 32 字节', () => {
    expect(viewingKeyToBytes(aliceViewingKey).length).toBe(32);
    expect(viewingKeyToBytes(1n).length).toBe(32);
    expect(viewingKeyToBytes(0n).length).toBe(32);
  });

  it('viewingPubKey 是 32 字节', () => {
    const pub = viewingPubKey(aliceViewingKey);
    expect(pub.length).toBe(32);
  });

  it('Bob 用 viewingKey 能解 Alice 加密给 Bob 的消息', async () => {
    const bobPub = viewingPubKey(bobViewingKey);
    const plaintext = new TextEncoder().encode('hello bob, this is alice');

    const blob = await eciesEncrypt(plaintext, bobPub);
    // 输出包含 32 (eph pub) + 12 (iv) + plaintext_len + 16 (gcm tag)
    expect(blob.length).toBe(32 + 12 + plaintext.length + 16);

    const decrypted = await eciesDecrypt(blob, bobViewingKey);
    expect(decrypted).not.toBeNull();
    expect(new TextDecoder().decode(decrypted!)).toBe(
      'hello bob, this is alice'
    );
  });

  it('错误的 viewingKey 不会解密成功(返回 null)', async () => {
    const bobPub = viewingPubKey(bobViewingKey);
    const blob = await eciesEncrypt(
      new TextEncoder().encode('secret for bob'),
      bobPub
    );
    // Alice 试解给 Bob 的消息 → 不是给她的
    const decrypted = await eciesDecrypt(blob, aliceViewingKey);
    expect(decrypted).toBeNull();
  });

  it('损坏的 blob 不会抛错(返回 null)', async () => {
    const bobPub = viewingPubKey(bobViewingKey);
    const blob = await eciesEncrypt(
      new TextEncoder().encode('msg'),
      bobPub
    );
    // 翻转一个字节(在 ciphertext 区域)模拟损坏
    const tampered = new Uint8Array(blob);
    tampered[blob.length - 1] ^= 0xff;

    const decrypted = await eciesDecrypt(tampered, bobViewingKey);
    expect(decrypted).toBeNull();
  });

  it('encryptNote / decryptNote 端到端', async () => {
    const note = {
      amount: '10000000000000000', // 0.01 ATOS in aatos
      tokenId: '0',
      blinding: '123456789012345678901234567890',
    };
    const bobPub = viewingPubKey(bobViewingKey);
    const blob = await encryptNote(note, bobPub);

    const decoded = await decryptNote(blob, bobViewingKey);
    expect(decoded).toEqual(note);
  });

  it('Note 字段缺失 → decryptNote 返回 null', async () => {
    const bobPub = viewingPubKey(bobViewingKey);
    // 编一个非 Note 的 JSON
    const blob = await eciesEncrypt(
      new TextEncoder().encode(JSON.stringify({ hello: 'world' })),
      bobPub
    );
    const decoded = await decryptNote(blob, bobViewingKey);
    expect(decoded).toBeNull();
  });
});
