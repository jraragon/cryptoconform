// EC-ser x Crypto++ adapter header.
//
// Mirrors src/contract/ec-ser.ts's and src/contract/p256.ts's architecture:
// our own byte-level DER TLV walker (extended with EXPLICIT context-tag
// support for RFC 5915's parameters[0]/publicKey[1]) for C_struct/C_profile,
// and our OWN P-256 point arithmetic (point add/double, scalar
// multiplication, on-curve check) using CryptoPP::Integer only as the
// bignum arithmetic PRIMITIVE -- NOT CryptoPP::ECP/DL_GroupParameters_EC's
// own VerifyPoint/ValidateElement/Multiply, which are the exact native
// operations this design keeps independent of (same principle already
// applied to RSA-ser's avoidance of RSA::PrivateKey::Validate()).
//
// CONFIRMED PRECISELY AGAINST THE PINNED COMMIT
// (782425901d36fe0944b16aae37801b8ec2fa9000), not "current master":
//   - DL_GroupParameters_EC::BERDecode dispatches on the first tag: OID ->
//     named curve; anything else -> attempts a full explicit ECParameters
//     SEQUENCE. Confirmed: explicit curves ARE an admitted Crypto++ import
//     source, a real divergence from RFC 5480/WebCrypto's namedCurve-only
//     profile.
//   - DL_PrivateKey_EC::BERDecodePrivateKey: if the OUTER AlgorithmIdentifier
//     carried no parameters, INNER [0] becomes MANDATORY (a stricter,
//     more precise finding than "either source admitted" -- confirmed via
//     the literal `if (!parametersPresent && seq.PeekByte() != ...)
//     BERDecodeError()` check). If [1] is present, it is decoded into a
//     LOCAL variable, never assigned to `this` -- confirmed parsed then
//     discarded, exactly as the frozen design states.
//   - DEREncodePrivateKey emits ONLY {version=1, privateKey} -- confirmed,
//     omits BOTH [0] and [1] entirely on native export.
//   - ECP::DecodePoint: compressed (type 2/3) computes y from x via the
//     curve equation and Jacobi tests it a quadratic residue -- curve
//     membership is an INHERENT byproduct of decompression. Uncompressed
//     (type 4) reads x,y directly with ZERO equation evaluation. The
//     identity point (type 0) is accepted UNCONDITIONALLY at this layer
//     with no rejection -- our own decoder never even attempts to parse
//     that point form, so this native permissiveness cannot leak through
//     our own Accept_C.
//   - ValidateElement(level, g, ...) is fully separate from Load(); Load()
//     never calls it automatically.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "integer.h"

namespace paper4 {

struct EcPoint {
  bool isInfinity = false;
  CryptoPP::Integer x, y;
};

struct EcKeyMaterial {
  std::string role;  // "public" | "private"
  EcPoint q;
  CryptoPP::Integer d;  // meaningful only when role == "private"
};

struct EcSerError {
  std::string clauseId;
  std::string errorClass;  // "malformed_artifact" | "invalid_parameter" | "invalid_key" | "invalid_membership"
  std::string detail;
};

struct EcSerImportResult {
  EcKeyMaterial material;
  bool normalized = false;  // true iff parameters[0] was absent (common-but-not-portable) and the artifact was accepted via normalization
};

/// Our own Accept_C classifier, five conjuncts (C_struct -> C_profile ->
/// V_scalar -> V_curve -> V_pair), three-way outcome captured via
/// EcSerImportResult.normalized. Throws EcSerError on rejection.
/// CryptoPP's own EC BERDecode/Load machinery is NEVER invoked by this
/// function -- classification is entirely ours.
EcSerImportResult ImportEcSerCryptoPP(const std::vector<uint8_t>& artifact, const std::string& requestedRole);

/// Our own canonical DER writer (pure function, no CryptoPP EC classes
/// involved) -- mirrors ec-ser.ts's exportEcSer(). Always emits
/// parameters[0] and publicKey[1] present (portable profile, D-059).
std::vector<uint8_t> ExportEcSerCryptoPP(const EcKeyMaterial& material);

/// GENUINE native Crypto++ SPKI/PKCS8 export, via actual
/// DL_PublicKey_EC<ECP>/DL_PrivateKey_EC<ECP> objects and Save() --
/// Crypto++'s own architecturally independent ASN.1 writer. For the
/// R_byte comparison ONLY. NOTE (confirmed above): the native PKCS8
/// writer omits BOTH parameters[0] and publicKey[1] -- this function
/// returns exactly that native (non-portable) artifact, unmodified.
std::vector<uint8_t> NativeCryptoPPSpkiExport(const EcKeyMaterial& material);
std::vector<uint8_t> NativeCryptoPPPkcs8Export(const EcKeyMaterial& material);

/// Attempts a GENUINE native Crypto++ import of the same raw artifact
/// bytes via DL_PublicKey_EC<ECP>/DL_PrivateKey_EC<ECP>::Load() -- called
/// ONLY after our own Accept_C has already admitted the artifact, purely
/// to test interop, never to determine admission. Returns the recovered
/// material (Q for public; d for private -- Q is deliberately NOT
/// recovered for private material, mirroring the confirmed
/// parse-then-discard finding above) or throws on native rejection.
EcKeyMaterial NativeCryptoPPImport(const std::vector<uint8_t>& artifact, const std::string& role);

/// Generates a fresh P-256 key pair via Crypto++'s own EC key-generation
/// machinery, returned as generic EcKeyMaterial. Shared fixture for this
/// adapter's tests.
EcKeyMaterial GenerateEcSerKeyMaterial();

}  // namespace paper4
