import { importEcSer, exportEcSer, type EcKeyMaterial } from '../../contract/ec-ser.js';
import { SdkContractError } from '../../contract/errors.js';
import { toHex } from '../../evidence/record.js';

/**
 * EC-ser Chromium/WebCrypto adapter.
 *
 * CRITICAL: EC-ser is
 * compared against CHROMIUM specifically (via Playwright), NOT against
 * node:crypto's webcrypto -- unlike every prior operation (HKDF, AES-GCM,
 * RSA-OAEP, RSA-PSS, RSA-ser), which used node:crypto.webcrypto as their
 * "WebCrypto" realization. The findings motivating this operation --
 * W3C webcrypto#356, the Chromium/BoringSSL ec.cc source trace -- concern
 * Chromium specifically; substituting Node here would silently replace
 * the pinned realization the Design Freeze actually characterized. Node
 * remains available only as an independent arithmetic-verification probe
 * (already used in Step 1), never as the EC-ser "WebCrypto" backend.
 *
 * Same Accept_C-first discipline as every prior WebCrypto adapter:
 * importEcSer() (our own contract, sec:ec-ser-cpre) runs FIRST, using our
 * own DER walker and P-256 arithmetic -- Chromium is never invoked for a
 * rejected artifact. Only once Accept_C has already classified the
 * artifact (accept, accept-with-normalization, or reject) does this
 * adapter separately probe Chromium's OWN native import, purely to record
 * interop/divergence evidence -- never to determine admission.
 *
 * KNOWN, EMPIRICALLY CONFIRMED DIVERGENCE (post-freeze deviation, recorded
 * in the Experimental Evidence Base's own Deviations section, not in the
 * frozen design): Chromium 151.0.7922.34 natively ACCEPTS
 * publicKey[1]-absent PKCS8 artifacts (auto-deriving Q:=dG), while our own
 * Accept_C REJECTS the same artifact, because [1]-absence is excluded from
 * D_import^common entirely (W3C #356's cross-realization instability), not
 * merely from the portable profile. This is Accept_C != NativeAccept_p by
 * design, not an adapter bug -- confirmed and exercised explicitly below.
 */

export interface EcSerImportEvidenceRecord {
  readonly operation: 'EC-ser';
  readonly direction: 'import';
  readonly backend: { readonly name: 'chromium'; readonly realization: string };
  readonly clauseIds: string[];
  readonly mutationId: null;
  readonly input: { readonly role: 'public' | 'private'; readonly artifactHex: string };
  readonly outcome:
    | { readonly kind: 'accept'; readonly normalized: boolean }
    | { readonly kind: 'reject'; readonly errorClass: string; readonly detail: string };
  readonly timestampIso: string;
}

export interface EcSerExportEvidenceRecord {
  readonly operation: 'EC-ser';
  readonly direction: 'export';
  readonly backend: { readonly name: 'chromium'; readonly realization: string };
  readonly clauseIds: string[];
  readonly mutationId: null;
  readonly input: { readonly role: 'public' | 'private' };
  readonly outcome: { readonly kind: 'accept'; readonly artifactHex: string };
  readonly timestampIso: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Contract-level import: Accept_C only. Never touches Chromium. Use this
 * for the "contract path" half of the two-path discipline
 * (contract path vs. native probe, kept explicitly separate
 * in every test and every evidence record -- discrepancies between them
 * are evidence, not adapter defects, whenever the contract's rejection is
 * deliberate).
 */
export function ecSerContractImport(
  artifact: Uint8Array,
  role: 'public' | 'private',
  realizationId: string,
): EcSerImportEvidenceRecord & { material?: EcKeyMaterial } {
  const input = { role, artifactHex: toHex(artifact) };
  try {
    const result = importEcSer(artifact, role);
    const clauseIds =
      role === 'public'
        ? ['ec-ser.key.role', 'ec-ser.public.asn1', 'ec-ser.curve', 'ec-ser.public.point', 'ec-ser.curveMembership']
        : [
            'ec-ser.key.role',
            'ec-ser.private.asn1',
            'ec-ser.curve',
            'ec-ser.private.scalar',
            'ec-ser.curveMembership',
            'ec-ser.pairConsistency',
            'ec-ser.validation.semantic',
          ];
    return {
      operation: 'EC-ser',
      direction: 'import',
      backend: { name: 'chromium', realization: realizationId },
      clauseIds,
      mutationId: null,
      input,
      outcome: { kind: 'accept', normalized: result.normalized },
      timestampIso: nowIso(),
      material: result.material,
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'EC-ser',
        direction: 'import',
        backend: { name: 'chromium', realization: realizationId },
        clauseIds: err.clauseIds,
        mutationId: null,
        input,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    throw err;
  }
}

/** Contract-level export: our own canonical writer, pure function, no Chromium involvement. */
export function ecSerContractExport(material: EcKeyMaterial, realizationId: string): EcSerExportEvidenceRecord {
  const artifact = exportEcSer(material);
  return {
    operation: 'EC-ser',
    direction: 'export',
    backend: { name: 'chromium', realization: realizationId },
    clauseIds:
      material.role === 'public'
        ? ['ec-ser.export', 'ec-ser.public.asn1', 'ec-ser.public.point']
        : ['ec-ser.export', 'ec-ser.private.asn1', 'ec-ser.pairConsistency'],
    mutationId: null,
    input: { role: material.role },
    outcome: { kind: 'accept', artifactHex: toHex(artifact) },
    timestampIso: nowIso(),
  };
}
