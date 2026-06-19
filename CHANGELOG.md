# Changelog

## 0.4.0 (audit 2026-06 response)

**Breaking changes.** All consumers must upgrade in lock-step with the
matching audit branch of `atoshi-privacy-contracts` (commit
`9c6adaa` or later) and a re-deployed Shield contract whose Verifier
contracts were regenerated against the new circuits.

### Breaking

- `TransactionBuilder.deposit()` now generates a `shield`-circuit
  Groth16 proof internally and passes the `(pA, pB, pC, encryptedNote)`
  tuple through to `Shield.deposit()`. The on-chain function gained
  these arguments to bind `amount` and `tokenId` into the proof (audit
  Issue 2). The SDK's external API is unchanged — `deposit({ amount,
  tokenAddress, recipient })` still works — but the SDK now reads
  `config.circuitsPath` and `config.keysPath` to find
  `shield_final.zkey` and `shield.wasm`.

- `TransactionBuilder.withdraw()` accepts an extra `relayer` field in
  `WithdrawParams`. The unshield circuit grew from 6 to 7 public
  signals (relayer slotted between recipient and tokenId) to prevent
  MEV / fee-stealing on the withdraw path (audit Issue 3 / contract
  Issue 4). When `fee > 0` a non-zero relayer is required; when self-
  broadcasting (`fee = 0`) the relayer defaults to `address(0)`.

- `SHIELD_ABI` strings in `tx/index.ts` updated for the new
  `deposit(uint256[2], uint256[2][2], uint256[2], uint256, address,
  uint256, bytes)` signature.

### New

- `ChainScanner.scanForViewer` now re-computes the commitment from each
  decrypted note plaintext and discards entries whose recomputed
  commitment does not match the on-chain commitment. Closes audit Q4 —
  the "phantom balance" attack where someone broadcasts a forged
  encryptedNote claiming an inflated `(amount, tokenId)` against the
  victim's viewing key.

### Notes for downstream

Atoshi-Private-h5 / the in-tree `sdk/zk-prover.ts` does NOT call
`TransactionBuilder` and is unaffected by the deposit/withdraw API
changes. It only consumes the primitives (`computeCommitment`,
`decryptNote`, `randomBlinding`, `viewingPubKey`, `ChainScanner`,
`computeNullifier`, etc.) — all of which keep their existing
signatures. The Q4 commitment-recheck inside ChainScanner is a
transparent improvement for that path.
