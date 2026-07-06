/**
 * Typed SDK errors (audit Q8).
 *
 * The SDK used to throw bare `Error` objects with ad-hoc messages, forcing
 * callers to string-match (fragile, and the documented strings did not even
 * match what was thrown). All SDK-originated failures now throw an
 * `AtoshiSdkError` subclass carrying a stable `code`, so integrators can do:
 *
 *   try { await tx.withdraw(params); }
 *   catch (e) {
 *     if (e instanceof NoteAlreadySpentError) { ... }
 *     // or branch on e.code
 *   }
 */

export type AtoshiErrorCode =
  | 'NOT_INITIALIZED'
  | 'INVALID_PARAMS'
  | 'NOTE_NOT_FOUND'
  | 'NOTE_NOT_COMMITTED'
  | 'NOTE_ALREADY_SPENT'
  | 'RPC_ERROR'
  | 'TIMEOUT'
  | 'PROOF_ERROR'
  | 'TX_FAILED'
  | 'STALE_LEAF_INDEX';

/** Base class for every error the SDK throws. */
export class AtoshiSdkError extends Error {
  readonly code: AtoshiErrorCode;

  constructor(code: AtoshiErrorCode, message: string) {
    super(message);
    this.name = 'AtoshiSdkError';
    this.code = code;
    // Keep `instanceof` reliable across transpilation targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** A method was called before init()/initFrom* completed. */
export class NotInitializedError extends AtoshiSdkError {
  constructor(message = 'SDK component not initialized. Call init() first.') {
    super('NOT_INITIALIZED', message);
    this.name = 'NotInitializedError';
  }
}

/** Caller-supplied parameters or configuration are invalid. */
export class InvalidParamsError extends AtoshiSdkError {
  constructor(message: string) {
    super('INVALID_PARAMS', message);
    this.name = 'InvalidParamsError';
  }
}

/** The referenced note does not exist in the wallet. */
export class NoteNotFoundError extends AtoshiSdkError {
  constructor(message = 'Note not found') {
    super('NOTE_NOT_FOUND', message);
    this.name = 'NoteNotFoundError';
  }
}

/** The note has no leafIndex yet (not committed to the Merkle tree). */
export class NoteNotCommittedError extends AtoshiSdkError {
  constructor(message = 'Note not committed (no leaf index)') {
    super('NOTE_NOT_COMMITTED', message);
    this.name = 'NoteNotCommittedError';
  }
}

/** The note's nullifier is already spent on-chain. */
export class NoteAlreadySpentError extends AtoshiSdkError {
  constructor(message = 'Note already spent') {
    super('NOTE_ALREADY_SPENT', message);
    this.name = 'NoteAlreadySpentError';
  }
}

/** A privacy-node RPC call failed. */
export class RpcError extends AtoshiSdkError {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super('RPC_ERROR', message);
    this.name = 'RpcError';
    this.status = status;
  }
}

/** An RPC request or proof generation exceeded its time budget. */
export class TimeoutError extends AtoshiSdkError {
  constructor(message: string) {
    super('TIMEOUT', message);
    this.name = 'TimeoutError';
  }
}

/** ZK proof generation failed. */
export class ProofError extends AtoshiSdkError {
  constructor(message: string) {
    super('PROOF_ERROR', message);
    this.name = 'ProofError';
  }
}

/**
 * A note's cached leafIndex no longer matches the on-chain leaf at that
 * position — typically caused by a block reorg (audit Issue 14). The note has
 * been reverted to Pending and must be re-recovered (rescan) before spending.
 */
export class StaleLeafIndexError extends AtoshiSdkError {
  constructor(
    message = 'Note leafIndex is stale (possible reorg); re-scan before spending'
  ) {
    super('STALE_LEAF_INDEX', message);
    this.name = 'StaleLeafIndexError';
  }
}
