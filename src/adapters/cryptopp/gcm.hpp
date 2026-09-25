// AES-256-GCM x Crypto++ adapter.
//
// Mirrors src/contract/gcm.ts and src/adapters/webcrypto/gcm.ts exactly:
// same Accept_C checks (v0.6, sec:aesgcm), same ClauseId set, same
// EvidenceRecord JSON shape -- independently reimplemented in C++, not
// shared code across languages, so a bug in one language's validation is
// not silently masked by the other's.
//
// Three non-negotiable adapter invariants (v0.6 sec:aesgcm-backends
// findings, confirmed against weidai11/cryptopp source):
//   1. Contractual tagLength is BITS; Crypto++'s truncatedDigestSize
//      parameter is BYTES. Conversion is centralized, not scattered.
//   2. AuthenticatedEncryptionFilter has NO MAC-position flag (unlike the
//      decryption filter) -- its C||T behavior is controlled entirely by
//      `macChannel`. This adapter passes DEFAULT_CHANNEL EXPLICITLY, not
//      relying on the parameter's default value, so the choice is a
//      documented decision, not an unexamined default.
//   3. Crypto++'s generic API path enforces NO lower bound on tag length
//      (only t<=16 bytes -- ThrowIfInvalidTruncatedSize checks only the
//      upper bound). t=128 (16 bytes) is enforced by THIS adapter's
//      Accept_C, before GCM<AES>::Encryption/Decryption is ever touched --
//      not delegated to the backend, which would accept t=0.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace paper4 {

constexpr size_t GCM_KEY_LEN_BYTES = 32;        // 256 bits
constexpr size_t GCM_IV_LEN_BYTES = 12;         // 96 bits
constexpr size_t GCM_TAG_LEN_BYTES = 16;        // 128 bits
constexpr size_t GCM_TAG_LEN_BITS = GCM_TAG_LEN_BYTES * 8;  // 128
constexpr uint8_t GCM_ARTIFACT_VERSION = 1;
constexpr size_t GCM_MIN_ARTIFACT_LEN_BYTES = 1 + GCM_IV_LEN_BYTES + GCM_TAG_LEN_BYTES;  // 29

struct GcmEncryptRequest {
  std::vector<uint8_t> key;
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> aad;
  bool aadPresent;  // false = absent (never written to AAD_CHANNEL at all)
  std::vector<uint8_t> iv;
  size_t tagLengthBits;  // contractual unit is BITS
};

struct GcmDecryptRequest {
  std::vector<uint8_t> key;
  std::vector<uint8_t> artifact;  // version || IV12 || C || T16
  std::vector<uint8_t> aad;
  bool aadPresent;
};

struct AeadArtifactParts {
  uint8_t version;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> tag;
};

// Encodes version(1) || IV || C || T. Pure encoder, mirrors
// src/contract/gcm.ts's buildAeadArtifact exactly. Exposed (not static) so
// the runner can independently verify the C/T split invariant.
std::vector<uint8_t> BuildAeadArtifact(const std::vector<uint8_t>& iv, const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& tag);

// Structurally validates and parses an artifact. Returns false (with
// errorDetail filled) on malformed input, rather than throwing -- mirrors
// this codebase's existing HKDF Crypto++ adapter convention of using
// return-value control flow for EXPECTED validation failures, reserving
// C++ exceptions for the one case where they are unavoidable: Crypto++'s
// own THROW_EXCEPTION-flagged authentication failure inside the decrypt
// call itself (see gcm.cpp).
bool ParseAeadArtifact(const std::vector<uint8_t>& artifact, AeadArtifactParts& out, std::string& errorDetail);

std::string GcmEncryptCryptoPP(const GcmEncryptRequest& req);
std::string GcmDecryptCryptoPP(const GcmDecryptRequest& req);

}  // namespace paper4
