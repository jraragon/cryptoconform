import { checkClause } from './check-clause.js';

/**
 * RSA-PSS portable contract. Source: v0.6, sec:pss through sec:pss-clauses
 * ($C_{pre}^{PSS}$, $E_{PSS}^{SDK}$, and the 15 frozen pss.* clauses).
 *
 * Profile: RSA-3072, SHA-256, H_PSS = H_MGF1, sLen = hLen = 32 bytes.
 *   k = 384 bytes (modulus in octets). No portable message-length boundary
 *   exists (unlike OAEP's mLen<=318) -- EMSA-PSS bounds the ENCODED message
 *   via modulus/hash/salt, never the original message length itself.
 *
 * CRITICAL, non-obvious rule (v0.6 sec:pss-siglen, D-046 -- a correction to
 * an earlier, wrong draft decision): a signature presented at verify with
 * length != 384 bytes is NOT invalid_parameter. RFC 8017 Sec.8.1.2 Step 1
 * defines "if the length of the signature S is not k octets, output
 * 'invalid signature' and stop" as the FIRST STEP of Verify's own output
 * domain -- textually adjacent to, and folded into the same two-valued
 * {true,false} result as, RSAVP1's "representative out of range" and
 * EMSA-PSS's inconsistency outcome. This is a stronger, more fundamental
 * rule than OAEP's D-034 (decryption_error): here there is no SDK error
 * class to normalize to at all -- the wrong-length signature is simply a
 * `false` verification result, exactly as if the signature were
 * cryptographically invalid. validatePssVerifyRequest below deliberately
 * does NOT check signature length -- see that function's comment.
 *
 * E_PSS^SDK has only THREE classes (v0.6, D-047) -- there is no
 * decryption_error/false-equivalent SDK error: {unsupported, invalid_key,
 * invalid_parameter}. Once C_pre^PSS is satisfied, Verify is a clean total
 * boolean function over sigma in {0,1}*.
 */

export const MODULUS_BITS = 3072;
export const K_BYTES = MODULUS_BITS / 8; // 384
export const HASH_LEN_BYTES = 32; // SHA-256
export const SALT_LEN_BYTES = HASH_LEN_BYTES; // 32; sLen = hLen (D-041, intersection-forced by Crypto++'s audited surface)
export const PSS_HASH = 'SHA-256';
export const PSS_MGF_HASH = 'SHA-256'; // H_PSS = H_MGF1 (D-040)

export type PssKeyRole = 'public' | 'private';

/**
 * Backend-agnostic description of the key actually used for a request.
 * Each adapter translates its own native key representation into this
 * shape before calling Accept_C -- same pattern as OaepKeyRef.
 */
export interface PssKeyRef {
  readonly role: PssKeyRole;
  readonly modulusBits: number;
}

export interface PssSignRequest {
  readonly key: PssKeyRef; // Accept_C requires role === 'private'
  readonly message: Uint8Array;
  readonly hash: string;
  readonly mgfHash: string;
  readonly saltLengthBytes: number;
}

export interface PssVerifyRequest {
  readonly key: PssKeyRef; // Accept_C requires role === 'public'
  readonly message: Uint8Array;
  readonly signature: Uint8Array; // NOT length-checked here -- see file header, D-046
  readonly hash: string;
  readonly mgfHash: string;
  readonly saltLengthBytes: number;
}

/**
 * Accept_C(request) for PSS sign -- v0.6's frozen classification order:
 * C_manifest (not enforced here, no manifest infra yet, same limitation
 * already accepted for GCM/OAEP) -> C_key (role) -> C_profile-values
 * (modulus, hash, mgfCoupling, saltLength) -> C_request (message is an
 * opaque byte sequence, no length boundary).
 */
export function validatePssSignRequest(req: PssSignRequest): void {
  checkClause(
    'pss.key',
    req.key.role === 'private',
    'invalid_key',
    `sign requires a private key; got role="${req.key.role}"`,
  );
  checkClause(
    'pss.modulus',
    req.key.modulusBits === MODULUS_BITS,
    'invalid_parameter',
    `modulus ${req.key.modulusBits} bits, portable profile requires exactly ${MODULUS_BITS}`,
  );
  checkClause(
    'pss.hash',
    req.hash === PSS_HASH,
    'invalid_parameter',
    `hash "${req.hash}", portable profile requires exactly "${PSS_HASH}"`,
  );
  checkClause(
    'pss.mgfCoupling',
    req.mgfHash === req.hash,
    'invalid_parameter',
    `mgfHash "${req.mgfHash}" != hash "${req.hash}"; portable profile requires H_PSS=H_MGF1 (D-040)`,
  );
  checkClause(
    'pss.saltLength',
    req.saltLengthBytes === SALT_LEN_BYTES,
    'invalid_parameter',
    `saltLength=${req.saltLengthBytes} bytes, portable profile requires exactly ${SALT_LEN_BYTES} (=hLen, D-041)`,
  );
  checkClause('pss.message', req.message instanceof Uint8Array, 'invalid_parameter', 'message must be a byte sequence');
}

/**
 * Accept_C(request) for PSS verify -- same order as sign, but WITHOUT any
 * signature-length check. Per D-046, |signature| != K_BYTES must be left
 * to flow through to the actual Verify call and come back as a legitimate
 * `false` result, not intercepted here as invalid_parameter -- the same
 * discipline as OAEP's ciphertext-length omission, but grounded in an even
 * more direct normative rule: RFC 8017 defines the length check as part of
 * Verify's own result domain, not a request precondition.
 */
export function validatePssVerifyRequest(req: PssVerifyRequest): void {
  checkClause(
    'pss.key',
    req.key.role === 'public',
    'invalid_key',
    `verify requires a public key; got role="${req.key.role}"`,
  );
  checkClause(
    'pss.modulus',
    req.key.modulusBits === MODULUS_BITS,
    'invalid_parameter',
    `modulus ${req.key.modulusBits} bits, portable profile requires exactly ${MODULUS_BITS}`,
  );
  checkClause(
    'pss.hash',
    req.hash === PSS_HASH,
    'invalid_parameter',
    `hash "${req.hash}", portable profile requires exactly "${PSS_HASH}"`,
  );
  checkClause(
    'pss.mgfCoupling',
    req.mgfHash === req.hash,
    'invalid_parameter',
    `mgfHash "${req.mgfHash}" != hash "${req.hash}"; portable profile requires H_PSS=H_MGF1 (D-040)`,
  );
  checkClause(
    'pss.saltLength',
    req.saltLengthBytes === SALT_LEN_BYTES,
    'invalid_parameter',
    `saltLength=${req.saltLengthBytes} bytes, portable profile requires exactly ${SALT_LEN_BYTES} (=hLen, D-041)`,
  );
  checkClause('pss.message', req.message instanceof Uint8Array, 'invalid_parameter', 'message must be a byte sequence');
  // Deliberately NO check on req.signature.length here. See this function's
  // header comment and file header for why.
}
