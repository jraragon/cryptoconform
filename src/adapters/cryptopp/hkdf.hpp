// HKDF x Crypto++ adapter.
//
// STATUS: build-verified. Compiled and executed against the exact pinned
// weidai11/cryptopp commit 782425901d36fe0944b16aae37801b8ec2fa9000
// (master, NOT the CRYPTOPP_8_9_0 tag -- see Experimental_Evidence_Base
// v0.2, sec:environment for why). RFC 5869 Test Case 1 KAT confirmed exact,
// D-068 bounds (L=0, L=8160, L=8161) and the absent/empty/HashLen-zero-byte
// salt triple-equivalence confirmed empirically (scripts/run-hkdf-cryptopp.cpp).
//
// Written against the official Crypto++ HKDF<T> API
// (cryptopp.com/docs/ref/class_h_k_d_f.html, cryptopp.com/wiki/HKDF).
//
// Mirrors src/adapters/webcrypto/hkdf.ts exactly: same Accept_C checks
// (v0.6, D-068), same ClauseId set, same EvidenceRecord JSON shape, so
// cross-backend evidence records are structurally comparable without
// per-language translation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace paper4 {

struct HkdfRequest {
  std::vector<uint8_t> ikm;
  std::vector<uint8_t> salt;  // meaningful only if saltPresent
  bool saltPresent;           // false = absent (RFC 5869 default), distinct
                               // from an explicit zero-length salt
  std::vector<uint8_t> info;
  size_t length;  // requested OKM length L, in octets
};

// Returns a JSON-serialized EvidenceRecord, field-for-field identical in
// shape to the TypeScript EvidenceRecord (src/evidence/record.ts):
//   { operation, backend: {name, realization}, clauseIds, mutationId,
//     input: {ikmHex, saltHex, infoHex, length},
//     outcome: {kind:'accept', okmHex} | {kind:'reject', errorClass, detail},
//     timestampIso }
std::string HkdfCryptoPP(const HkdfRequest& req);

}  // namespace paper4
