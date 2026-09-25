// M3.7-D2 (provenance repair) -- the C-T-swap producer plaintext.
//
// gcm-sdk-artifact-ctlen-01 was generated with a SPECIFIC 16-byte plaintext so
// that |C| = |tag| and the C<->T swap intervention is meaningful at all. The
// artifact was frozen; the parameter that reconstructs its producer was not.
// The record stores only { ciphertext, sourceMaterialId }, and
// sourceMaterialId points at aes-phasec-primary-01 -- whose own plaintext is a
// DIFFERENT one, so producing A_0 from it would yield |C| != |tag| and the
// frozen mutation would not apply.
//
//     historically frozen generator parameter -> explicit frozen Phase-C material
//
// Nothing is invented: the value below is the literal the frozen generator
// used, and a test asserts it still equals that literal rather than trusting
// this copy. The runtime never reads the script.

export const CT_SWAP_PRODUCER_PLAINTEXT = Object.freeze({
  /** Verbatim from scripts/generate-gcm-sdk-artifacts.ts, line 130. */
  utf8: 'PhaseC-CTSwap-16',
  bytes: 16,
  appliesToMaterialId: 'gcm-sdk-artifact-ctlen-01',
  provenance: Object.freeze({
    origin: 'promoted-from-frozen-generator',
    generator: 'scripts/generate-gcm-sdk-artifacts.ts',
    generatorVersion: 'M3.2.4b-2.13',
    sourceMaterialIds: Object.freeze(['aes-phasec-primary-01', 'gcm-sdk-artifact-ctlen-01']),
    /** Why the value is what it is, and not a free choice. */
    rationale: 'AES-GCM is a stream cipher mode, so |C| = |PT|; a 16-byte plaintext makes |C| = |tag| = 16, '
      + 'without which the C<->T swap has nothing to swap.',
  }),
});

export function ctSwapPlaintextBytes(): Uint8Array {
  return new Uint8Array(Buffer.from(CT_SWAP_PRODUCER_PLAINTEXT.utf8, 'utf8'));
}
