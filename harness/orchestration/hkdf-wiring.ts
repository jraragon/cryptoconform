// M2.4.7 -- operation-specific wiring for HKDF x Node-WebCrypto. This is
// where "how do I read a HkdfEvidenceRecord" lives -- the generic engine
// (harness/orchestration/engine.ts) never needs to know this.

import { hkdfWebCrypto } from '../../src/adapters/webcrypto/hkdf.js';
import type { HkdfRequest } from '../../src/contract/hkdf.js';
import type { HkdfEvidenceRecord } from '../../src/evidence/record.js';
import { NODE_WEBCRYPTO_OPENSSL } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';

export const HKDF_NODE_WEBCRYPTO_ADAPTER: ExecutionAdapter<HkdfRequest, HkdfEvidenceRecord> = {
  operation: 'hkdf',
  backend: NODE_WEBCRYPTO_OPENSSL,
  execute: (fixture) => hkdfWebCrypto(fixture), // the REAL M1 adapter -- never reimplemented
  toEvidenceFields: (fixture, record) => ({
    subject: { backend: NODE_WEBCRYPTO_OPENSSL, direction: 'derive', path: 'sdk' },
    input: { kind: 'hkdf-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'hkdf-okm', bytes: record.outcome.okmHex } : undefined,
    outcome: record.outcome.kind === 'accept'
      ? { kind: 'accept' }
      : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds,
    executionStatus: 'completed',
    nativeObservation: undefined,
  }),
};
