import type { ClauseId } from '../contract/clause-ids.js';

/**
 * One evidence record per executed request against one backend realization.
 * No mutations yet in M1 (mutationId always null here) -- see
 * Experimental_Evidence_Base v0.3, sec:m1-slice.
 *
 * Discriminated union on `operation` (and, for GCM, `direction`). HKDF's
 * shape is UNCHANGED from earlier sessions -- existing HKDF adapters/tests
 * are not touched by this generalization.
 */
export type BackendName = 'webcrypto' | 'cryptopp' | 'bouncycastle';

interface EvidenceRecordBase {
  readonly backend: {
    readonly name: BackendName;
    readonly realization: string; // exact pinned identity, not just the family name
  };
  readonly clauseIds: ClauseId[]; // clauses exercised by this request
  readonly mutationId: null; // reserved for M2; always null until the mutation harness exists
  readonly timestampIso: string;
}

export interface HkdfEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'HKDF-SHA-256';
  readonly input: {
    readonly ikmHex: string;
    readonly saltHex: string | null; // null = absent, per RFC 5869 default
    readonly infoHex: string;
    readonly length: number;
  };
  readonly outcome:
    | { readonly kind: 'accept'; readonly okmHex: string }
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
}

export interface GcmEncryptEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'AES-256-GCM';
  readonly direction: 'encrypt';
  readonly input: {
    readonly keyHex: string;
    readonly plaintextHex: string;
    readonly aadHex: string | null; // null = absent; contractually === empty for GCM (unlike HKDF's salt)
    readonly ivHex: string;
    readonly tagLengthBits: number;
  };
  readonly outcome:
    | { readonly kind: 'accept'; readonly artifactHex: string } // version || IV12 || C || T16
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
}

export interface GcmDecryptEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'AES-256-GCM';
  readonly direction: 'decrypt';
  readonly input: {
    readonly keyHex: string;
    readonly artifactHex: string;
    readonly aadHex: string | null;
  };
  readonly outcome:
    | { readonly kind: 'accept'; readonly plaintextHex: string }
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
}

export interface OaepEncryptEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'RSA-OAEP';
  readonly direction: 'encrypt';
  readonly input: {
    readonly keyRole: string;
    readonly modulusBits: number;
    readonly plaintextHex: string;
    readonly labelHex: string | null; // null = absent; contractually === empty (D-030)
    readonly hash: string;
    readonly mgfHash: string;
  };
  readonly outcome:
    | { readonly kind: 'accept'; readonly ciphertextHex: string } // raw RSAES-OAEP ciphertext, |C|=384 bytes -- no SDK wrapper (D-034)
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
}

export interface OaepDecryptEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'RSA-OAEP';
  readonly direction: 'decrypt';
  readonly input: {
    readonly keyRole: string;
    readonly modulusBits: number;
    readonly ciphertextHex: string;
    readonly labelHex: string | null;
    readonly hash: string;
    readonly mgfHash: string;
  };
  readonly outcome:
    | { readonly kind: 'accept'; readonly plaintextHex: string }
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
}

export interface PssSignEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'RSA-PSS';
  readonly direction: 'sign';
  readonly input: {
    readonly keyRole: string;
    readonly modulusBits: number;
    readonly messageHex: string;
    readonly hash: string;
    readonly mgfHash: string;
    readonly saltLengthBytes: number;
  };
  readonly outcome:
    | { readonly kind: 'accept'; readonly signatureHex: string } // |signature|=384 bytes
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
}

/**
 * PSS verify's outcome is NOT a simple accept/reject the way every other
 * operation's is: per v0.6 D-046/D-047, once Accept_C passes, Verify is a
 * clean TOTAL boolean function -- a `false` verdict is a correctly
 * functioning result, not an SDK-level rejection (E_PSS^SDK has no
 * decryption_error/false-equivalent class). `outcome.kind` therefore only
 * ever distinguishes "Accept_C admitted the request" (kind: 'verified',
 * carrying the boolean verdict in `valid`) from "Accept_C rejected the
 * request before verification was even attempted" (kind: 'reject', an
 * actual SdkErrorClass) -- these are NOT the same axis as `valid`.
 */
export interface PssVerifyEvidenceRecord extends EvidenceRecordBase {
  readonly operation: 'RSA-PSS';
  readonly direction: 'verify';
  readonly input: {
    readonly keyRole: string;
    readonly modulusBits: number;
    readonly messageHex: string;
    readonly signatureHex: string;
    readonly hash: string;
    readonly mgfHash: string;
    readonly saltLengthBytes: number;
  };
  readonly outcome:
    | { readonly kind: 'verified'; readonly valid: boolean } // valid=false includes |sigma|!=k, per D-046 -- NOT an SDK error
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string }; // Accept_C failure only (key/modulus/hash/mgfCoupling/saltLength)
}

export type EvidenceRecord =
  | HkdfEvidenceRecord
  | GcmEncryptEvidenceRecord
  | GcmDecryptEvidenceRecord
  | OaepEncryptEvidenceRecord
  | OaepDecryptEvidenceRecord
  | PssSignEvidenceRecord
  | PssVerifyEvidenceRecord;

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}
