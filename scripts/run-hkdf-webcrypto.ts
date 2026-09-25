import { hkdfWebCrypto } from '../src/adapters/webcrypto/hkdf.js';
import { fromHex } from '../src/evidence/record.js';

/**
 * M1 vertical slice: HKDF x WebCrypto, no mutations.
 * See Experimental_Evidence_Base v0.1, sec:m1-slice.
 *
 * Proves: frozen contract -> common SDK request -> WebCrypto adapter
 *         -> normalized result -> evidence record, end to end,
 * and that the WebCrypto realization matches RFC 5869's own published KAT
 * (verified against the RFC 5869 Editor text and cross-checked against an
 * independent implementation's test vectors before use here).
 */

// RFC 5869 Appendix A.1 -- Test Case 1, Basic test case with SHA-256
const RFC5869_TEST_CASE_1 = {
  ikm: fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
  salt: fromHex('000102030405060708090a0b0c'),
  info: fromHex('f0f1f2f3f4f5f6f7f8f9'),
  length: 42,
  expectedOkmHex:
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
};

async function main(): Promise<void> {
  console.log('=== M1 vertical slice: HKDF x WebCrypto ===\n');

  // --- 1. RFC 5869 KAT: proves the pipeline AND correctness against the normative source ---
  console.log('--- RFC 5869 Test Case 1 (KAT) ---');
  const katRecord = await hkdfWebCrypto(RFC5869_TEST_CASE_1);
  console.log(JSON.stringify(katRecord, null, 2));

  if (katRecord.outcome.kind !== 'accept') {
    throw new Error(`Expected acceptance, got rejection: ${JSON.stringify(katRecord.outcome)}`);
  }
  if (katRecord.outcome.okmHex !== RFC5869_TEST_CASE_1.expectedOkmHex) {
    throw new Error(
      `KAT MISMATCH.\n  expected: ${RFC5869_TEST_CASE_1.expectedOkmHex}\n  actual:   ${katRecord.outcome.okmHex}`,
    );
  }
  console.log('\n✅ KAT PASS -- WebCrypto realization matches RFC 5869 Test Case 1 exactly.\n');

  // --- 2. D-068 boundary sanity check (contract validation of OUR implementation --
  //         NOT a Gamma_0 mutation; that is explicitly M2's job, not M1's) ---
  console.log('--- D-068 boundary sanity check (L=0, contract-level, not a mutation) ---');
  const zeroLengthRecord = await hkdfWebCrypto({ ...RFC5869_TEST_CASE_1, length: 0 });
  console.log(JSON.stringify(zeroLengthRecord, null, 2));
  if (zeroLengthRecord.outcome.kind !== 'reject' || zeroLengthRecord.outcome.errorClass !== 'invalid_parameter') {
    throw new Error('Expected L=0 to be rejected as invalid_parameter per D-068.');
  }
  console.log('\n✅ D-068 bound enforced correctly by the SDK adapter (invalid_parameter, not unsupported).\n');

  console.log('=== M1 slice complete: pipeline validated end to end for HKDF x WebCrypto ===');
}

main().catch((err) => {
  console.error('\n❌ M1 slice FAILED:', err);
  process.exitCode = 1;
});
