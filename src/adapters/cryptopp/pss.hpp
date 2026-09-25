// RSA-PSS x Crypto++ adapter.
//
// Mirrors src/contract/pss.ts and src/adapters/webcrypto/pss.ts: same
// Accept_C checks (Design Freeze v0.6, sec:pss-error-model), same ClauseId
// set, same EvidenceRecord JSON shape -- independently reimplemented in C++.
//
// SAME declaredRole DESIGN AS OAEP, for the SAME reason: RSASS<PSS,H>::Signer
// only accepts RSA::PrivateKey; ::Verifier only accepts RSA::PublicKey
// (compile-time enforcement, confirmed in Design Freeze v0.6's PSS backend
// inventory -- "same type-system pattern as OAEP"). If this adapter's
// request types were themselves typed as CryptoPP::RSA::PublicKey/PrivateKey,
// a wrong-role request would be a COMPILE ERROR, not a runtime Accept_C
// rejection, making pss.key's invalid_key check untestable through this
// adapter's own API surface. Key material is therefore carried generically
// (modulus + exponent(s) + a caller-DECLARED role string); Accept_C checks
// the declared role BEFORE any typed CryptoPP key object is constructed.
//
// saltLength=32 invariant (this session's explicit requirement #2): the
// standard PSS type (PSSR_MEM<false>) defaults its salt length to hLen
// (=32 for SHA-256) -- confirmed by DIRECT SOURCE INSPECTION in this
// session (weidai11/cryptopp's pssr.h: `template <..., int SALT_LEN=-1,
// ...> class PSSR_MEM { virtual size_t SaltLen(size_t hashLen) const
// {return SALT_LEN < 0 ? hashLen : SALT_LEN;} ... };`), and additionally
// weidai11/cryptopp#1121 documents this is NOT runtime-configurable through
// this API at all.
//
// IMPORTANT CORRECTION, made during this session: an earlier version of
// this file attempted to confirm this by calling SaltLen() directly at
// runtime on a standalone PSSR_MEM<false> instance. That does not compile
// -- SaltLen() is declared with no access specifier inside PSSR_MEM's class
// body, which defaults to PRIVATE in C++ for `class` (confirmed by the
// resulting compiler error), and there is no public accessor or friend
// declaration exposing it. Rather than force this via a wrapper or by
// weakening access (which would mean testing modified library source, not
// the pinned one), PssSaltLenBytes() below takes a REAL, already-produced
// signature and a public key, and manually reverses RSAVP1 + EMSA-PSS's
// MGF1 unmasking (RFC 8017 Sec.9.1.2) to recover the ACTUAL salt length
// Crypto++ embedded in that concrete signature -- a genuine empirical
// measurement of what the library actually did, not a config-value query
// blocked by access control.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "integer.h"

namespace paper4 {

constexpr int PSS_MODULUS_BITS = 3072;
constexpr size_t PSS_K_BYTES = PSS_MODULUS_BITS / 8;  // 384
constexpr size_t PSS_HASH_LEN_BYTES = 32;              // SHA-256
constexpr size_t PSS_SALT_LEN_BYTES = PSS_HASH_LEN_BYTES;  // 32 = hLen; empirically confirmed -- see PssSaltLenBytes()

/// Generic RSA key material, decoupled from CryptoPP's own typed key
/// classes -- see this file's header comment.
struct PssKeyMaterial {
  std::string declaredRole;  // "public" | "private" -- caller's claim, checked by Accept_C
  CryptoPP::Integer modulus;
  CryptoPP::Integer publicExponent;
  CryptoPP::Integer privateExponent;  // meaningful only when declaredRole == "private"
  int modulusBits = 0;
};

struct PssSignRequest {
  PssKeyMaterial key;  // Accept_C requires key.declaredRole == "private"
  std::vector<uint8_t> message;  // no portable length boundary (unlike OAEP's plaintext)
  std::string hash;
  std::string mgfHash;
  size_t saltLengthBytes = 0;
};

struct PssVerifyRequest {
  PssKeyMaterial key;  // Accept_C requires key.declaredRole == "public"
  std::vector<uint8_t> message;
  std::vector<uint8_t> signature;  // NOT length-checked by Accept_C -- Design Freeze v0.6 D-046
  std::string hash;
  std::string mgfHash;
  size_t saltLengthBytes = 0;
};

/// Generates a fresh RSA-3072 key pair and returns it as generic
/// PssKeyMaterial (declaredRole == "private", carrying the full material).
/// Shared fixture for this adapter's test suite; not itself part of Accept_C.
PssKeyMaterial GeneratePssKeyMaterial();

/// Manually reverses RSAVP1 + EMSA-PSS's MGF1 unmasking (RFC 8017 Sec.9.1.2)
/// on a REAL signature already produced by this adapter's own
/// PssSignCryptoPP, to recover the ACTUAL salt length Crypto++ embedded in
/// it -- see this file's header comment for why this replaced a direct
/// (inaccessible, private) SaltLen() call. `publicKey` must carry the
/// modulus/publicExponent corresponding to the private key that produced
/// `signature`. Throws std::runtime_error if the trailer byte (0xbc) is
/// not found where EMSA-PSS-VERIFY expects it (i.e. the signature is not
/// well-formed EMSA-PSS output at all).
size_t PssSaltLenBytes(const PssKeyMaterial& publicKey, const std::vector<uint8_t>& signature);

std::string PssSignCryptoPP(const PssSignRequest& req);
std::string PssVerifyCryptoPP(const PssVerifyRequest& req);

}  // namespace paper4
