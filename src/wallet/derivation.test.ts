// Unit tests for the wallet key-derivation primitives. These run via
// vitest (`npm test`) and do NOT require a chain — pure crypto.
//
// What we're protecting:
//   - Determinism: the same seed input always produces the same keys.
//     Recovery on a new device depends on this.
//   - Domain separation: changing the HKDF info label moves to a
//     different key, so spending/viewing/encryption keys never alias.
//   - Round-trip encryption: a backup encrypted with key K decrypts
//     with K and rejects every other key.
//   - EIP-712 path: signing the same typed-data with the same EOA
//     produces the same seed regardless of v-byte parity (some
//     wallets return 27/28, some return 0/1).

import { describe, it, expect } from "vitest";
import { Wallet } from "ethers";
import {
  decryptBackup,
  deriveKeysFromSeed,
  encryptBackup,
  generateMnemonic,
  seedFromEIP712Signature,
  seedFromMnemonic,
  seedFromPassphrase,
  signSeedDerivation,
} from "./derivation";

const FIELD_SIZE = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

describe("seedFromMnemonic", () => {
  it("is deterministic given the same phrase", async () => {
    const phrase =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const a = await seedFromMnemonic(phrase);
    const b = await seedFromMnemonic(phrase);
    expect(Buffer.from(a).toString("hex")).toEqual(
      Buffer.from(b).toString("hex"),
    );
    expect(a.length).toEqual(32);
  });

  it("produces a different seed when a passphrase is used", async () => {
    const phrase =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const a = await seedFromMnemonic(phrase, "");
    const b = await seedFromMnemonic(phrase, "withpass");
    expect(Buffer.from(a).toString("hex")).not.toEqual(
      Buffer.from(b).toString("hex"),
    );
  });

  it("rejects garbage", async () => {
    await expect(seedFromMnemonic("not a valid mnemonic")).rejects.toThrow();
  });
});

describe("generateMnemonic", () => {
  it("yields a 12-word phrase by default", () => {
    const phrase = generateMnemonic();
    expect(phrase.split(" ").length).toEqual(12);
  });

  it("yields a 24-word phrase at 256-bit strength", () => {
    const phrase = generateMnemonic(256);
    expect(phrase.split(" ").length).toEqual(24);
  });
});

describe("seedFromEIP712Signature", () => {
  it("re-signing with the same key yields the same seed", async () => {
    const wallet = Wallet.createRandom();
    const sig1 = await signSeedDerivation(wallet.privateKey);
    const sig2 = await signSeedDerivation(wallet.privateKey);
    expect(sig1).toEqual(sig2); // signatures themselves are deterministic for ECDSA-with-RFC6979
    const seed1 = await seedFromEIP712Signature(sig1);
    const seed2 = await seedFromEIP712Signature(sig2);
    expect(Buffer.from(seed1).toString("hex")).toEqual(
      Buffer.from(seed2).toString("hex"),
    );
  });

  it("different EOAs produce different seeds", async () => {
    const sigA = await signSeedDerivation(Wallet.createRandom().privateKey);
    const sigB = await signSeedDerivation(Wallet.createRandom().privateKey);
    const seedA = await seedFromEIP712Signature(sigA);
    const seedB = await seedFromEIP712Signature(sigB);
    expect(Buffer.from(seedA).toString("hex")).not.toEqual(
      Buffer.from(seedB).toString("hex"),
    );
  });

  it("rejects malformed signatures", async () => {
    await expect(seedFromEIP712Signature("0x1234")).rejects.toThrow(
      /65-byte EIP-712 signature/,
    );
  });
});

describe("deriveKeysFromSeed", () => {
  const SEED = new Uint8Array(32).fill(0x42);

  it("returns three distinct keys", async () => {
    const k = await deriveKeysFromSeed(SEED);
    expect(k.spendingKey).not.toEqual(k.viewingKey);
    expect(k.spendingKey).not.toEqual(BigInt(0));
    expect(k.viewingKey).not.toEqual(BigInt(0));
    expect(k.encryptionKey.length).toEqual(32);
    // Ensure encryptionKey is different from spendingKey bytes.
    const spendHex = k.spendingKey.toString(16).padStart(64, "0");
    const encHex = Buffer.from(k.encryptionKey).toString("hex");
    expect(spendHex).not.toEqual(encHex);
  });

  it("spending and viewing keys are valid field elements", async () => {
    const k = await deriveKeysFromSeed(SEED);
    expect(k.spendingKey < FIELD_SIZE).toBe(true);
    expect(k.viewingKey < FIELD_SIZE).toBe(true);
  });

  it("is deterministic", async () => {
    const a = await deriveKeysFromSeed(SEED);
    const b = await deriveKeysFromSeed(SEED);
    expect(a.spendingKey).toEqual(b.spendingKey);
    expect(a.viewingKey).toEqual(b.viewingKey);
    expect(Buffer.from(a.encryptionKey).toString("hex")).toEqual(
      Buffer.from(b.encryptionKey).toString("hex"),
    );
  });

  it("a 1-bit change in the seed scrambles every output key", async () => {
    const seed2 = new Uint8Array(SEED);
    seed2[0] ^= 0x01;
    const a = await deriveKeysFromSeed(SEED);
    const b = await deriveKeysFromSeed(seed2);
    expect(a.spendingKey).not.toEqual(b.spendingKey);
    expect(a.viewingKey).not.toEqual(b.viewingKey);
    expect(Buffer.from(a.encryptionKey).toString("hex")).not.toEqual(
      Buffer.from(b.encryptionKey).toString("hex"),
    );
  });
});

describe("encryptBackup / decryptBackup", () => {
  const KEY = new Uint8Array(32).fill(0x77);

  it("round-trips arbitrary JSON", async () => {
    const payload = JSON.stringify({ hello: "world", n: 42, list: [1, 2, 3] });
    const blob = await encryptBackup(payload, KEY);
    expect(blob.v).toEqual(1);
    const restored = await decryptBackup(blob, KEY);
    expect(restored).toEqual(payload);
  });

  it("rejects a wrong key", async () => {
    const blob = await encryptBackup("secret", KEY);
    const wrongKey = new Uint8Array(32).fill(0x88);
    await expect(decryptBackup(blob, wrongKey)).rejects.toThrow();
  });

  it("each encryption uses a fresh IV", async () => {
    const a = await encryptBackup("same data", KEY);
    const b = await encryptBackup("same data", KEY);
    expect(a.iv).not.toEqual(b.iv);
    expect(a.ct).not.toEqual(b.ct);
  });
});

describe("seedFromPassphrase", () => {
  it("is deterministic given the same passphrase + salt", async () => {
    const salt = new Uint8Array(16).fill(0x33);
    const a = await seedFromPassphrase("correct horse battery staple", salt);
    const b = await seedFromPassphrase("correct horse battery staple", salt);
    expect(Buffer.from(a).toString("hex")).toEqual(
      Buffer.from(b).toString("hex"),
    );
  });

  it("rejects salts shorter than 16 bytes", async () => {
    await expect(
      seedFromPassphrase("x", new Uint8Array(8)),
    ).rejects.toThrow(/>= 16 bytes/);
  });
});
