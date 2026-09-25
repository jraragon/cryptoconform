// RSA-OAEP x Crypto++ adapter.
//
// Mirrors src/contract/oaep.ts and src/adapters/webcrypto/oaep.ts: same
// Accept_C checks (v0.6, sec:oaep-error-model), same ClauseId set, same
// EvidenceRecord JSON shape -- independently reimplemented in C++.
//
// CRITICAL DESIGN NOTE: Crypto++'s own key-role enforcement is
// COMPILE-TIME (RSAES<OAEP<H>>::Encryptor only accepts RSA::PublicKey;
// ::Decryptor only accepts RSA::PrivateKey -- v0.6, sec:oaep-error-model:
// "role misuse does not compile under normal use, and consequently can
// never surface as a runtime-observable error from this backend at all").
// If this adapter's request types were themselves typed as
// CryptoPP::RSA::PublicKey/PrivateKey, a wrong-role request would be a
// COMPILE ERROR, not a runtime Accept_C rejection -- making oaep.key's
// invalid_key check untestable through this adapter's own API surface.
// Deliberately, requests here carry key material generically (modulus +
// exponent(s) + a caller-DECLARED role string), decoupled from CryptoPP's
// static types. Accept_C checks the declared role BEFORE any typed
// CryptoPP::RSA::PublicKey/PrivateKey object is ever constructed; only
// once that check passes does the adapter build the correctly-typed
// native object needed for the actual operation. This is the direct C++
// analogue of v0.6's own conclusion: "Where a provider does not enforce
// [the key-role obligation]..., the adapter must."
//
// Two invariants specific to this backend (this session's design review):
//   1. RNG-injection is used normally (Crypto++'s OAEP requires an
//      explicit RandomNumberGenerator&) but NEVER exposed as a portable
//      "OAEP seed" contractual field -- no request/EvidenceRecord field
//      here names or exposes randomness control. oaep.randomness never
//      appears in any accept outcome's clauseIds (v0.6, D-033).
//   2. Crypto++ distinguishes ciphertext-length mismatch (throws
//      InvalidArgument, from TF_DecryptorBase::Decrypt's structural
//      pre-check) from internal OAEP-decode failure (returns
//      DecodingResult.isValidCoding=false, no exception) -- two
//      DIFFERENT native mechanisms. The adapter must hide BOTH behind a
//      single decryption_error outcome; oaepDecryptCryptoPP's decrypt
//      path handles both explicitly, not just one of them.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "integer.h"

namespace paper4 {

constexpr int OAEP_MODULUS_BITS = 3072;
constexpr size_t OAEP_K_BYTES = OAEP_MODULUS_BITS / 8;                        // 384
constexpr size_t OAEP_HASH_LEN_BYTES = 32;                                    // SHA-256
constexpr size_t OAEP_MAX_MESSAGE_LEN_BYTES = OAEP_K_BYTES - 2 * OAEP_HASH_LEN_BYTES - 2;  // 318

/// Generic RSA key material, decoupled from CryptoPP's own typed key
/// classes -- see this file's header comment for why.
struct OaepKeyMaterial {
  std::string declaredRole;             // "public" | "private" -- caller's claim, checked by Accept_C
  CryptoPP::Integer modulus;
  CryptoPP::Integer publicExponent;
  CryptoPP::Integer privateExponent;    // meaningful only when declaredRole == "private"; ignored otherwise
  int modulusBits = 0;                  // caller-reported; independently re-derived from `modulus` for evidence purposes
};

struct OaepEncryptRequest {
  OaepKeyMaterial key;  // Accept_C requires key.declaredRole == "public"
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> label;
  bool labelPresent;
  std::string hash;
  std::string mgfHash;
};

struct OaepDecryptRequest {
  OaepKeyMaterial key;  // Accept_C requires key.declaredRole == "private"
  std::vector<uint8_t> ciphertext;  // NOT length-checked by Accept_C -- v0.6 D-034
  std::vector<uint8_t> label;
  bool labelPresent;
  std::string hash;
  std::string mgfHash;
};

/// Generates a fresh RSA-3072 key pair (via CryptoPP::AutoSeededRandomPool)
/// and returns it as generic OaepKeyMaterial (declaredRole == "private",
/// carrying the full material -- the public-only material is trivially
/// derivable by the caller from modulus+publicExponent). Not itself part
/// of Accept_C; a shared fixture for this adapter's test suite.
OaepKeyMaterial GenerateOaepKeyMaterial();

std::string OaepEncryptCryptoPP(const OaepEncryptRequest& req);
std::string OaepDecryptCryptoPP(const OaepDecryptRequest& req);

}  // namespace paper4
