// Unit tests for the typed error hierarchy (audit Q8). These guarantee that
// consumers can reliably branch on `instanceof` and on the stable `.code`,
// which is the whole point of replacing bare Error throws.

import { describe, it, expect } from 'vitest';
import {
  AtoshiSdkError,
  NotInitializedError,
  InvalidParamsError,
  NoteNotFoundError,
  NoteNotCommittedError,
  NoteAlreadySpentError,
  RpcError,
  TimeoutError,
  ProofError,
  StaleLeafIndexError,
} from './index';

describe('typed SDK errors', () => {
  it('every subclass is both an Error and an AtoshiSdkError', () => {
    const errors = [
      new NotInitializedError(),
      new InvalidParamsError('bad'),
      new NoteNotFoundError(),
      new NoteNotCommittedError(),
      new NoteAlreadySpentError(),
      new RpcError('boom'),
      new TimeoutError('slow'),
      new ProofError('nope'),
      new StaleLeafIndexError(),
    ];
    for (const e of errors) {
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(AtoshiSdkError);
    }
  });

  it('carries the expected stable code', () => {
    expect(new NotInitializedError().code).toBe('NOT_INITIALIZED');
    expect(new InvalidParamsError('x').code).toBe('INVALID_PARAMS');
    expect(new NoteNotFoundError().code).toBe('NOTE_NOT_FOUND');
    expect(new NoteNotCommittedError().code).toBe('NOTE_NOT_COMMITTED');
    expect(new NoteAlreadySpentError().code).toBe('NOTE_ALREADY_SPENT');
    expect(new RpcError('x').code).toBe('RPC_ERROR');
    expect(new TimeoutError('x').code).toBe('TIMEOUT');
    expect(new ProofError('x').code).toBe('PROOF_ERROR');
    expect(new StaleLeafIndexError().code).toBe('STALE_LEAF_INDEX');
  });

  it('RpcError preserves the HTTP status', () => {
    expect(new RpcError('server error', 503).status).toBe(503);
    expect(new RpcError('no status').status).toBeUndefined();
  });

  it('is catchable as its specific subclass (instanceof survives throw)', () => {
    try {
      throw new NoteAlreadySpentError();
    } catch (e) {
      expect(e instanceof NoteAlreadySpentError).toBe(true);
      expect(e instanceof AtoshiSdkError).toBe(true);
      expect((e as AtoshiSdkError).code).toBe('NOTE_ALREADY_SPENT');
    }
  });
});
