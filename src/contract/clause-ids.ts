/**
 * Clause IDs, transcribed VERBATIM from the frozen v0.6 clause tables.
 * Do not edit these strings independently of v0.6 -- if v0.6 is ever
 * amended post-freeze (D-070 policy), the amendment is recorded in
 * this repository's own deviations log, not by silently changing an ID here.
 *
 * Source: Paper_4_Research_Design_and_Evidence_Base_v0.6.tex, HKDF clause table.
 */
export type HkdfClauseId =
  | 'hkdf.ikm'
  | 'hkdf.salt'
  | 'hkdf.info'
  | 'hkdf.hash'
  | 'hkdf.length'
  | 'hkdf.output'
  | 'hkdf.validation'
  | 'hkdf.error'
  | 'hkdf.cap';

/**
 * AES-GCM clause IDs, transcribed verbatim from v0.6's frozen AES-GCM clause
 * table (sec:aesgcm). Twelve clauses, independently re-verified against the
 * source .tex before transcription here, not recalled from memory:
 * gcm.key, gcm.plaintext, gcm.aad, gcm.iv, gcm.tagLength, gcm.ciphertext,
 * gcm.authentication, gcm.artifact, gcm.validation, gcm.error,
 * gcm.cap.provider, gcm.cap.portable.
 */
export type GcmClauseId =
  | 'gcm.key'
  | 'gcm.plaintext'
  | 'gcm.aad'
  | 'gcm.iv'
  | 'gcm.tagLength'
  | 'gcm.ciphertext'
  | 'gcm.authentication'
  | 'gcm.artifact'
  | 'gcm.validation'
  | 'gcm.error'
  | 'gcm.cap.provider'
  | 'gcm.cap.portable';

// Other operations' ClauseId unions are added here as their adapters are implemented
// (RSA-PSS, RSA-ser, EC-ser) -- not stubbed in advance.

/**
 * RSA-OAEP clause IDs, transcribed verbatim from v0.6's frozen RSA-OAEP
 * clause table (sec:oaep-clauses). Thirteen clauses, independently
 * re-verified against the source .tex before transcription here, not
 * recalled from memory: oaep.key, oaep.modulus, oaep.message,
 * oaep.ciphertext, oaep.ciphertextLength, oaep.hash, oaep.mgfCoupling,
 * oaep.label, oaep.randomness, oaep.validation, oaep.error,
 * oaep.cap.provider, oaep.cap.portable.
 */
export type OaepClauseId =
  | 'oaep.key'
  | 'oaep.modulus'
  | 'oaep.message'
  | 'oaep.ciphertext'
  | 'oaep.ciphertextLength'
  | 'oaep.hash'
  | 'oaep.mgfCoupling'
  | 'oaep.label'
  | 'oaep.randomness'
  | 'oaep.validation'
  | 'oaep.error'
  | 'oaep.cap.provider'
  | 'oaep.cap.portable';

export type ClauseId = HkdfClauseId | GcmClauseId | OaepClauseId | PssClauseId | RsaSerClauseId | EcSerClauseId;

/**
 * EC P-256 Key Serialization clause IDs, transcribed verbatim from the
 * frozen design's sec:ec-ser-clauses (D-062). Thirteen clauses.
 *
 * The most novel clause transversally: ec-ser.curveMembership
 * (Membership.CurveMembership) -- the first genuine K1=Membership
 * instantiation in this project (AES-GCM covered 9/10 K1 values with
 * Membership the one systematic absence). ec-ser.pairConsistency
 * (Key.PublicPrivateConsistency) is the second most novel, with no RSA-ser
 * analogue: EC carries a genuine public/private consistency obligation
 * (Q=dG) that RSA's key material has no equivalent of.
 *
 * curveMembership deliberately does NOT also appear inside
 * validation.semantic (obligation != validation mechanism != observable
 * error, D-061). private.scalar and pairConsistency remain separate
 * clauses even though both map to the single observable class E_key --
 * sharing an observable error never justifies merging distinct causal
 * obligations (same principle already applied to RSA-ser's V_domain/V_rel).
 */
export type EcSerClauseId =
  | 'ec-ser.key.role'
  | 'ec-ser.curve'
  | 'ec-ser.public.asn1'
  | 'ec-ser.public.point'
  | 'ec-ser.private.asn1'
  | 'ec-ser.private.scalar'
  | 'ec-ser.curveMembership'
  | 'ec-ser.pairConsistency'
  | 'ec-ser.export'
  | 'ec-ser.validation.syntax'
  | 'ec-ser.validation.semantic'
  | 'ec-ser.error'
  | 'ec-ser.cap';

/**
 * RSA Key Serialization clause IDs, transcribed verbatim from the frozen
 * design's sec:rsa-ser-clauses. Thirteen clauses (D-057), independently
 * re-verified against the source .tex before transcription here.
 *
 * Evaluability-dependency order (audited before freezing, D-057):
 * der-syntax -> exact-consumption -> container -> role-container ->
 * algorithm-id -> algorithm-params -> {public-validity | private-domain +
 * private-relations}. public-material/private-material are role-exclusive
 * (never co-applicable to the same artifact, D-053's role/container
 * coupling); exact-consumption has no export equivalent (import-only, D-055).
 */
export type RsaSerClauseId =
  | 'rsa-ser.public-material'
  | 'rsa-ser.private-material'
  | 'rsa-ser.der-syntax'
  | 'rsa-ser.container'
  | 'rsa-ser.exact-consumption'
  | 'rsa-ser.role-container'
  | 'rsa-ser.algorithm-id'
  | 'rsa-ser.algorithm-params'
  | 'rsa-ser.public-validity'
  | 'rsa-ser.private-domain'
  | 'rsa-ser.private-relations'
  | 'rsa-ser.error'
  | 'rsa-ser.cap';

/**
 * RSA-PSS clause IDs, transcribed verbatim from v0.6's frozen RSA-PSS
 * clause table (sec:pss-clauses). Fifteen clauses, independently
 * re-verified against the source .tex before transcription here, not
 * recalled from memory: pss.key, pss.modulus, pss.message, pss.hash,
 * pss.mgfCoupling, pss.saltLength, pss.rngControl, pss.saltBytes,
 * pss.signature, pss.signatureLength, pss.verification, pss.validation,
 * pss.error, pss.cap.provider, pss.cap.portable.
 *
 * Two structural decisions frozen jointly as D-048: (1) pss.rngControl and
 * pss.saltBytes stay separate despite both instantiating
 * Parameter.ExternalRandomnessControl at K2 -- genuinely distinct
 * capabilities; (2) pss.verification is the first real materialization of
 * Authentication.SignatureVerification in this project.
 */
export type PssClauseId =
  | 'pss.key'
  | 'pss.modulus'
  | 'pss.message'
  | 'pss.hash'
  | 'pss.mgfCoupling'
  | 'pss.saltLength'
  | 'pss.rngControl'
  | 'pss.saltBytes'
  | 'pss.signature'
  | 'pss.signatureLength'
  | 'pss.verification'
  | 'pss.validation'
  | 'pss.error'
  | 'pss.cap.provider'
  | 'pss.cap.portable';
