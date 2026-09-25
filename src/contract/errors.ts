import type { ClauseId } from './clause-ids.js';

/**
 * Contractual SDK error classes, union across all operations implemented so far.
 * HKDF (D-068's disambiguation rule) uses only 'invalid_parameter'. AES-GCM
 * (v0.6, sec:aesgcm) freezes the full four-class model E_GCM^SDK =
 * {invalid_parameter, malformed_artifact, unsupported, authentication_failure},
 * with a pre-registered adapter classification order (capability/portable
 * boundary -> artifact structure -> remaining parameters -> authentication_failure,
 * only reachable after 1-3 have excluded every structural/parametric cause).
 * RSA-OAEP (v0.6, sec:oaep-error-model) freezes its OWN four-class model
 * E_OAEP^SDK = {unsupported, invalid_key, invalid_parameter, decryption_error},
 * DELIBERATELY FLATTER than GCM's in the decryption-failure region -- this is
 * not a simplification of convenience but the literal reading of RFC 8017's
 * own anti-oracle error pseudocode (Bleichenbacher/Manger): once execution
 * enters RSAES-OAEP-DECRYPT, EVERY failure collapses to decryption_error,
 * including ciphertext length != k, which the adapter could in principle
 * detect in advance but must NOT reclassify as invalid_parameter.
 * EC-ser (v0.6, sec:ec-ser-errors, D-061) freezes FOUR content categories --
 * E_syntax, E_representation, E_key, E_membership -- plus the same
 * unsupported capability gate. E_membership is a GENUINELY NEW class
 * (`invalid_membership` below): RSA-ser has no analogue, since RSA has no
 * curve-membership structure. It is kept deliberately separate from
 * invalid_key (E_key, covering V_scalar and V_pair) -- collapsing
 * Membership into Key would undo the methodological effort invested in
 * keeping Membership != Key != Validation as three distinct layers
 * (obligation != validation mechanism != observable error), and would cost
 * R_err exactly the diagnostic value this separation exists to measure.
 */
export type SdkErrorClass =
  | 'invalid_parameter'
  | 'unsupported'
  | 'malformed_artifact'
  | 'authentication_failure'
  | 'invalid_key'
  | 'decryption_error'
  | 'invalid_membership';

export class SdkContractError extends Error {
  readonly errorClass: SdkErrorClass;
  readonly clauseIds: ClauseId[];

  constructor(errorClass: SdkErrorClass, clauseIds: ClauseId[], detail: string) {
    super(`[${errorClass}] ${detail} (clauses: ${clauseIds.join(', ')})`);
    this.errorClass = errorClass;
    this.clauseIds = clauseIds;
    this.name = 'SdkContractError';
  }
}
