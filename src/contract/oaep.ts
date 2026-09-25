import { checkClause } from './check-clause.js';

/**
 * RSA-OAEP portable contract. Source: v0.6, sec:oaep through sec:oaep-ciphertext
 * ($C_{pre}^{OAEP}$), and sec:oaep-clauses (the 13 frozen oaep.* clauses).
 *
 * Profile: RSA-3072, SHA-256, H_OAEP = H_MGF1, L = empty.
 *   k = 384 bytes (modulus in octets); hLen = 32 bytes (SHA-256).
 *   mLen_max = k - 2*hLen - 2 = 318 bytes.
 *   |C| = k = 384 bytes, always, for a successful encryption.
 *
 * CRITICAL, non-obvious rule (v0.6 sec:oaep-error-model, D-034): a
 * ciphertext presented at decrypt with length != 384 bytes is NOT
 * invalid_parameter, even though it is trivially checkable in advance --
 * it collapses to decryption_error, per RFC 8017 Sec.7.1.2's own
 * anti-oracle error pseudocode (Bleichenbacher/Manger). This is the
 * single most dangerous point of implementation divergence from the
 * AES-GCM adapters, where pre-backend structural checks were the norm.
 * validateOaepDecryptRequest below deliberately does NOT check ciphertext
 * length -- see that function's comment.
 */

export const MODULUS_BITS = 3072;
export const K_BYTES = MODULUS_BITS / 8; // 384
export const HASH_LEN_BYTES = 32; // SHA-256
export const MAX_MESSAGE_LEN_BYTES = K_BYTES - 2 * HASH_LEN_BYTES - 2; // 318, derived (D-032), not chosen
export const OAEP_HASH = 'SHA-256';
export const OAEP_MGF_HASH = 'SHA-256'; // H_OAEP = H_MGF1 (D-028); same value, kept as a separate named constant for clarity at call sites

export type OaepKeyRole = 'public' | 'private';

/**
 * Backend-agnostic description of the key actually used for a request.
 * Each adapter is responsible for translating its own native key
 * representation (WebCrypto CryptoKey, Crypto++ RSA::PublicKey/PrivateKey,
 * Bouncy Castle RSAKeyParameters) into this shape before calling Accept_C --
 * the contract layer itself never touches a native key object.
 */
export interface OaepKeyRef {
  readonly role: OaepKeyRole;
  readonly modulusBits: number;
}

export interface OaepEncryptRequest {
  readonly key: OaepKeyRef; // Accept_C requires role === 'public'
  readonly plaintext: Uint8Array;
  readonly label: Uint8Array | undefined; // undefined = absent; contractually === empty (L_absent === L_empty, all three backends)
  readonly hash: string; // requested OAEP digest
  readonly mgfHash: string; // requested MGF1 digest
}

export interface OaepDecryptRequest {
  readonly key: OaepKeyRef; // Accept_C requires role === 'private'
  readonly ciphertext: Uint8Array; // NOT length-checked here -- see file header
  readonly label: Uint8Array | undefined;
  readonly hash: string;
  readonly mgfHash: string;
}

/**
 * Accept_C(request) for OAEP encrypt -- v0.6's frozen steps 2 ("key
 * contract") and 3 ("portable parameter/input contract"). Step 1
 * (capability/manifest -> unsupported) is not enforced here: no capability
 * manifest infrastructure exists yet in M1 (same limitation already
 * accepted for AES-GCM's gcm.cap.provider/portable). Step 4 does not apply
 * to encrypt -- RSAES-OAEP-DECRYPT is never entered.
 */
export function validateOaepEncryptRequest(req: OaepEncryptRequest): void {
  // Step 2: key contract.
  checkClause(
    'oaep.key',
    req.key.role === 'public',
    'invalid_key',
    `encrypt requires a public key; got role="${req.key.role}"`,
  );
  // Step 3: portable parameter/input contract -- fully computable in advance,
  // without invoking the backend (v0.6, sec:oaep-error-model, verbatim).
  checkClause(
    'oaep.modulus',
    req.key.modulusBits === MODULUS_BITS,
    'invalid_parameter',
    `modulus ${req.key.modulusBits} bits, portable profile requires exactly ${MODULUS_BITS}`,
  );
  checkClause(
    'oaep.hash',
    req.hash === OAEP_HASH,
    'invalid_parameter',
    `hash "${req.hash}", portable profile requires exactly "${OAEP_HASH}"`,
  );
  checkClause(
    'oaep.mgfCoupling',
    req.mgfHash === req.hash,
    'invalid_parameter',
    `mgfHash "${req.mgfHash}" != hash "${req.hash}"; portable profile requires H_OAEP=H_MGF1 (D-028)`,
  );
  checkClause(
    'oaep.label',
    req.label === undefined || req.label.length === 0,
    'invalid_parameter',
    `label present with ${req.label?.length ?? 0} byte(s); portable profile requires L=empty (D-030)`,
  );
  checkClause(
    'oaep.message',
    req.plaintext instanceof Uint8Array && req.plaintext.length <= MAX_MESSAGE_LEN_BYTES,
    'invalid_parameter',
    `mLen=${req.plaintext.length} exceeds portable bound 0<=mLen<=${MAX_MESSAGE_LEN_BYTES} (D-032)`,
  );
}

/**
 * Accept_C(request) for OAEP decrypt -- steps 2 and 3, EXCLUDING ciphertext
 * length. Per v0.6's frozen decision (D-034, sec:oaep-error-model): a
 * ciphertext of length != K_BYTES presented at decrypt is NOT
 * invalid_parameter -- it is one of RFC 8017 Sec.7.1.2's own enumerated
 * causes of the generic decryption_error, and the adapter must not exploit
 * its ability to check this in advance to reclassify it. The caller (the
 * adapter) is responsible for letting a wrong-length ciphertext flow
 * through to step 4 and normalizing whatever the backend does there to
 * decryption_error -- exactly the same discipline as GCM's
 * authentication_failure catch, but for a DIFFERENT reason: GCM's
 * collapse is a design choice; OAEP's is mandated by RFC 8017 itself.
 */
export function validateOaepDecryptRequest(req: OaepDecryptRequest): void {
  // Step 2: key contract.
  checkClause(
    'oaep.key',
    req.key.role === 'private',
    'invalid_key',
    `decrypt requires a private key; got role="${req.key.role}"`,
  );
  // Step 3: portable parameter/input contract (ciphertext length deliberately excluded).
  checkClause(
    'oaep.modulus',
    req.key.modulusBits === MODULUS_BITS,
    'invalid_parameter',
    `modulus ${req.key.modulusBits} bits, portable profile requires exactly ${MODULUS_BITS}`,
  );
  checkClause(
    'oaep.hash',
    req.hash === OAEP_HASH,
    'invalid_parameter',
    `hash "${req.hash}", portable profile requires exactly "${OAEP_HASH}"`,
  );
  checkClause(
    'oaep.mgfCoupling',
    req.mgfHash === req.hash,
    'invalid_parameter',
    `mgfHash "${req.mgfHash}" != hash "${req.hash}"; portable profile requires H_OAEP=H_MGF1 (D-028)`,
  );
  checkClause(
    'oaep.label',
    req.label === undefined || req.label.length === 0,
    'invalid_parameter',
    `label present with ${req.label?.length ?? 0} byte(s); portable profile requires L=empty (D-030)`,
  );
}
