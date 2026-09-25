// RSA-ser x Crypto++ adapter.
//
// Mirrors src/contract/rsa-ser.ts's architecture exactly: our own byte-level
// DER TLV walker for C_struct/C_profile (NOT CryptoPP::BERSequenceDecoder,
// which would mean Crypto++'s own ASN.1 machinery decides structural
// admission before Accept_C gets a say), CryptoPP::Integer used ONLY as
// the bignum arithmetic primitive (Gcd, LCM, IsPrime, modular reduction),
// and V_domain/V_rel reimplemented independently -- NOT
// RSA::PrivateKey::Validate(), which this session's design review requires
// be checked precisely against our exact obligation, not assumed
// equivalent. See rsa-ser.cpp's header comment for the confirmed,
// itemized divergence between Validate() and V_domain^RSA,2 / V_rel^RSA,2.
//
// A SEPARATE pair of functions (NativeCryptoPPSpkiExport/PkcsExport) uses
// GENUINE CryptoPP::RSA::PublicKey/PrivateKey + X509PublicKey::Save()/
// PKCS8PrivateKey::Save() -- Crypto++'s own, architecturally independent
// SPKI/PKCS#8 writer -- exposed specifically for the R_byte comparison.
// This is NOT the same code path as ExportRsaSerCryptoPP (our own
// canonical writer); conflating the two would make an R_byte match
// meaningless (comparing our encoder against itself).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "integer.h"

namespace paper4 {

struct RsaKeyMaterial {
  std::string role;  // "public" | "private"
  CryptoPP::Integer n, e;
  CryptoPP::Integer d, p, q, dP, dQ, qInv;  // meaningful only when role == "private"
};

struct RsaSerError {
  std::string clauseId;
  std::string errorClass;  // "malformed_artifact" | "invalid_parameter" | "invalid_key"
  std::string detail;
};

/// Our own Accept_C classifier (C_struct -> C_profile -> C_math^role).
/// Throws RsaSerError on rejection; CryptoPP's own BERDecode/Load is NEVER
/// invoked by this function at all -- classification is entirely ours.
RsaKeyMaterial ImportRsaSerCryptoPP(const std::vector<uint8_t>& artifact, const std::string& requestedRole);

/// Our own canonical DER writer (pure function, no CryptoPP ASN.1 classes
/// involved) -- the SDK's own encoder, exactly mirroring rsa-ser.ts's
/// exportRsaSer().
std::vector<uint8_t> ExportRsaSerCryptoPP(const RsaKeyMaterial& material);

/// GENUINE native Crypto++ SPKI export, via RSA::PublicKey + X509PublicKey::Save() --
/// Crypto++'s own, architecturally independent ASN.1 writer. For the R_byte comparison ONLY.
std::vector<uint8_t> NativeCryptoPPSpkiExport(const RsaKeyMaterial& material);

/// GENUINE native Crypto++ PKCS8 export, via RSA::PrivateKey + PKCS8PrivateKey::Save().
std::vector<uint8_t> NativeCryptoPPPkcs8Export(const RsaKeyMaterial& material);

/// Attempts a GENUINE native Crypto++ import (RSA::PublicKey/PrivateKey::Load())
/// of the same raw artifact bytes -- called ONLY after our own Accept_C has
/// already admitted the artifact, purely to test interop, never to
/// determine admission. Returns false if Crypto++ natively rejects it.
bool NativeCryptoPPImportSucceeds(const std::vector<uint8_t>& artifact, const std::string& role);

/// GENUINE native Crypto++ import that returns the RECOVERED MATERIAL
/// itself (not just a success/failure boolean) -- via RSA::PublicKey/
/// PrivateKey::Load() and the class's own named accessors, with NO
/// contribution from this project's own Accept_C/DER walker at any point.
/// Throws std::exception on native failure. Used exclusively by the
/// native-only cross-provider interop matrix, kept structurally separate
/// from the contract-level (Accept_C-mediated) matrix.
RsaKeyMaterial NativeCryptoPPImport(const std::vector<uint8_t>& artifact, const std::string& role);

/// Generates a fresh RSA key pair via Crypto++'s own GenerateRandomWithKeySize,
/// returned as generic RsaKeyMaterial. Shared fixture for this adapter's tests.
RsaKeyMaterial GenerateRsaSerKeyMaterial(int modulusBits);

}  // namespace paper4
